﻿Set-StrictMode -Version Latest

class PartialScanManager
{
	hidden [string] $OrgName = $null;
	hidden [string] $ProjectName = $null;
	hidden [PSObject] $ScanPendingForResources = $null;
	hidden [string] $ResourceScanTrackerFileName=$null;
	hidden [PartialScanResourceMap] $ResourceScanTrackerObj = $null
	[PSObject] $ControlSettings;
	hidden [ActiveStatus] $ActiveStatus = [ActiveStatus]::NotStarted;
	hidden [string] $CAScanProgressSnapshotsContainerName = [Constants]::CAScanProgressSnapshotsContainerName
    hidden [string] $AzSKTempStatePath = (Join-Path $([Constants]::AzSKAppFolderPath) "TempState" | Join-Path -ChildPath "PartialScanData");
	hidden [bool] $StoreResTrackerLocally = $false;
	hidden [string] $ScanSource = $null;
	hidden [bool] $IsRTFAlreadyAvailable = $false;
	hidden [bool] $IsDurableStorageFound = $false;
	hidden [string] $MasterFilePath;
	$StorageContext = $null;
	$ControlStateBlob = $null;
	hidden static $IsCsvUpdatedAtCheckpoint = $false; 
	hidden static $CollatedSummaryCount = @(); # Matrix of counts for severity and control status
	hidden static $CollatedBugSummaryCount = @(); # Matrix of counts for severity and Bug status
	hidden static $ControlResultsWithBugSummary = @();
	hidden static $ControlResultsWithSARIFSummary= @();
	hidden static $ControlResultsWithClosedBugSummary= @();
	hidden static $duplicateClosedBugCount=0;
  hidden [string] $SummaryMarkerText = "------";
  hidden [string] $BackupControlStatePath = (Join-Path $([Constants]::AzSKAppFolderPath) "TempState" | Join-Path -ChildPath "BackupControlState");
	hidden [string] $BackupControlStateFilePath;
	hidden [PSObject] $StateOfControlsToBeFixed = $null;
	hidden [bool] $IsControlStateBackupFetched = $false;


	hidden static [PartialScanManager] $Instance = $null;
	
	static [PartialScanManager] GetInstance([PSObject] $StorageAccount, [string] $OrganizationName)
    {
        if ( $null -eq  [PartialScanManager]::Instance)
        {
			[PartialScanManager]::Instance = [PartialScanManager]::new($OrganizationName);
		}
		[PartialScanManager]::Instance.OrgName = $OrganizationName;
        return [PartialScanManager]::Instance
    }

	static [PartialScanManager] GetInstance()
    {
        if ( $null -eq  [PartialScanManager]::Instance)
        {
            [PartialScanManager]::Instance = [PartialScanManager]::new();
        }
        return [PartialScanManager]::Instance
    }
	static [void] ClearInstance()
    {
       [PartialScanManager]::Instance = $null
	   [PartialScanManager]::IsCsvUpdatedAtCheckpoint = $false
    }
	PartialScanManager([string] $OrganizationName)
	{
		$this.ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
		$this.OrgName = $OrganizationName;
		if ([string]::isnullorwhitespace($this.ResourceScanTrackerFileName))
        {
           if([ConfigurationManager]::GetAzSKSettings().IsCentralScanModeOn)
		   {
				$this.ResourceScanTrackerFileName = Join-Path $OrganizationName $([Constants]::ResourceScanTrackerCMBlobName)
		   }
		   else
		   {
				$this.ResourceScanTrackerFileName = Join-Path $OrganizationName $([Constants]::ResourceScanTrackerBlobName)
		   }
        }
		$this.GetResourceScanTrackerObject();
	}

	PartialScanManager()
	{
		$this.ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
		if ([string]::isnullorwhitespace($this.ResourceScanTrackerFileName))
        {
			$this.ResourceScanTrackerFileName =  [Constants]::ResourceScanTrackerBlobName
        }
		$this.GetResourceScanTrackerObject();
	}

     hidden [void] GetResourceTrackerFile($orgName, $isControlFixCmd)
    {
		$this.ScanSource = [AzSKSettings]::GetInstance().GetScanSource();
		$this.OrgName = $orgName

		#Validating the configuration of storing resource tracker file
        if($null -ne $this.ControlSettings.PartialScan)
		{
			$this.StoreResTrackerLocally = [Bool]::Parse($this.ControlSettings.PartialScan.StoreResourceTrackerLocally);
		}

		#Use local Resource Tracker files for partial scanning
        if ($this.StoreResTrackerLocally -and ($this.ScanSource -ne "CA" -and $this.ScanSource -ne "CICD") )
        {
            if($null -eq $this.ScanPendingForResources)
            {
                if($isControlFixCmd)
                {
                    $this.ResourceScanTrackerFileName = "ControlFix"+ $this.ResourceScanTrackerFileName
                }
                if(![string]::isnullorwhitespace($this.OrgName)){
                    if(Test-Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrgName) $this.ResourceScanTrackerFileName))	
                    {
                        $this.ScanPendingForResources = Get-Content (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrgName) $this.ResourceScanTrackerFileName) -Raw
                    }
                    $this.MasterFilePath = (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrgName) $this.ResourceScanTrackerFileName)
                }
                else {
                    $this.MasterFilePath = (Join-Path $this.AzSKTempStatePath $this.ResourceScanTrackerFileName)
                }
            }
        }

        if ($this.ScanSource -eq "CA") # use storage in ADOScannerRG in case of CA scan
        {
			$this.MasterFilePath = (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrgName) $this.ResourceScanTrackerFileName)

			try {
				#Validate if Storage is found 
				$keys = Get-AzStorageAccountKey -ResourceGroupName $env:StorageRG -Name $env:StorageName
				$this.StorageContext = New-AzStorageContext -StorageAccountName $env:StorageName -StorageAccountKey $keys[0].Value -Protocol Https
				$containerObject = Get-AzStorageContainer -Context $this.StorageContext -Name $this.CAScanProgressSnapshotsContainerName -ErrorAction SilentlyContinue
					
				#If checkpoint container is found then get ResourceTracker.json (if exists)
				if($null -ne $containerObject)
				{
					$this.ControlStateBlob = Get-AzStorageBlob -Container $this.CAScanProgressSnapshotsContainerName -Context $this.StorageContext -Blob (Join-Path $this.OrgName.ToLower() $this.ResourceScanTrackerFileName) -ErrorAction SilentlyContinue

					#If controlStateBlob is null then it will get created when we first write the resource tracker file to storage
					#If its not null this means Resource tracker file has been found in storage and will be used to continue pending scan
					if ($null -ne $this.ControlStateBlob)
					{
						if ($null -ne $this.MasterFilePath)
						{
							if (-not (Test-Path $this.MasterFilePath))
							{
								$filePath = $this.MasterFilePath.Replace($this.ResourceScanTrackerFileName, "")
								New-Item -ItemType Directory -Path $filePath
								New-Item -Path $filePath -Name $this.ResourceScanTrackerFileName -ItemType "file" 
							}
							#Copy existing RTF locally to handle any non ascii characters as ICloudBlob.DownloadText() was inserting non ascii charcaters
							Get-AzStorageBlobContent -CloudBlob $this.ControlStateBlob.ICloudBlob -Context $this.StorageContext -Destination $this.MasterFilePath -Force                
							$this.ScanPendingForResources  = Get-ChildItem -Path $this.MasterFilePath -Force | Get-Content | ConvertFrom-Json
							#Delete the local RTF file
							Remove-Item -Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrgName) $this.ResourceScanTrackerFileName)
						}
						$this.IsRTFAlreadyAvailable = $true
					}
					else {
						$this.IsRTFAlreadyAvailable = $false
					}
					$this.IsDurableStorageFound = $true
				}
				#If checkpoint container is not found then create new
				else {
					$containerObject = New-AzStorageContainer -Name $this.CAScanProgressSnapshotsContainerName -Context $this.StorageContext -ErrorAction SilentlyContinue
					if ($null -ne $containerObject )
					{
						$this.IsDurableStorageFound = $true
					}
					else 
					{
						Write-Host "Could not find/create partial scan container in storage." -ForegroundColor Yellow
					}
				}
			}
			catch {
				Write-Host "Exception when trying to find/create partial scan container: $_." -ForegroundColor Yellow
				#Eat exception
			}

		}
		
		elseif ($this.ScanSource -eq "CICD") # use extension storage in case of CICD partial scan
		{
				if(![string]::isnullorwhitespace($this.OrgName))
				{
					$rmContext = [ContextHelper]::GetCurrentContext();
					$user = "";
					$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))
                    $uri= "";

                    if (Test-Path env:partialScanURI)
                    {
						#Uri is created in cicd task based on jobid
                        $uri = $env:partialScanURI
                    }
                    else {
					    $uri = [Constants]::StorageUri -f $this.OrgName, $this.OrgName, "ResourceTrackerFile"
                    }

					try {
						$webRequestResult = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)}
						$this.ScanPendingForResources = $webRequestResult.value | ConvertFrom-Json
                        $this.IsRTFAlreadyAvailable = $true;
					}
					catch
					{
                        $this.ScanPendingForResources = $null
                        $this.IsRTFAlreadyAvailable = $false;
					}	
			    }
		}
        
    }

	#Update resource status in ResourceMapTable object
	[void] UpdateResourceStatus([string] $resourceId, [ScanState] $state)
	{
		$resourceValues = @();
		#$this.GetResourceScanTrackerObject();
		if($this.IsListAvailableAndActive())
		{
			$resourceValue = $this.ResourceScanTrackerObj.ResourceMapTable | Where-Object { $_.Id -eq $resourceId};
			if($null -ne $resourceValue)
			{
				$resourceValue.ModifiedDate = [DateTime]::UtcNow;
				$resourceValue.State = $state;
			}
			else
			{
				$resourceValue = [PartialScanResource]@{
					Id = $resourceId;
					State = $state;
					ScanRetryCount = 1;
					CreatedDate = [DateTime]::UtcNow;
					ModifiedDate = [DateTime]::UtcNow;
				}
				$this.ResourceScanTrackerObj.ResourceMapTable +=$resourceValue;
			}
		}
	}

	[void] UpdateResourceScanRetryCount([string] $resourceId)
	{
		$resourceValues = @();
		if($this.IsListAvailableAndActive())
		{
			$resourceValue = $this.ResourceScanTrackerObj.ResourceMapTable | Where-Object { $_.Id -eq $resourceId};
			if($null -ne $resourceValue)
			{
				$resourceValue.ModifiedDate = [DateTime]::UtcNow;
				$resourceValue.ScanRetryCount = $resourceValue.ScanRetryCount + 1;
				if($resourceValue.ScanRetryCount -ge [Constants]::PartialScanMaxRetryCount)
				{
					$resourceValue.State = [ScanState]::ERR
				}
			}
			else
			{
				#do nothing
			}
		}
	}

	# Method to remove obsolete Resource Tracker file
	[void] RemovePartialScanData()
	{
		if ($this.ScanSource -eq "CICD")
		{
            if($null -ne $this.ResourceScanTrackerObj)
		    {
				$rmContext = [ContextHelper]::GetCurrentContext();
				$user = "";
				$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))
                $uri ="";

                if (Test-Path env:partialScanURI)
                    {
						#Uri is created by cicd task based on jobid
                        $uri = $env:partialScanURI
                    }
                else {
					$uri = [Constants]::StorageUri -f $this.OrgName, $this.OrgName, "ResourceTrackerFile"
				}
				
				try {
					if ($this.ResourceScanTrackerObj.ResourceMapTable -ne $null){
						$webRequestResult = Invoke-WebRequest -Uri $uri -Method Delete -ContentType "application/json" -Headers @{Authorization = ("Basic {0}" -f $base64AuthInfo) } 
						$this.ResourceScanTrackerObj = $null
					}
				}
				catch {
					#do nothing
				}
			}
		}
		elseif ($this.ScanSource -eq "CA" -and $this.IsDurableStorageFound) {
			#Move resource tracker file to archive folder
			if($null -ne $this.ControlStateBlob)
			{
				$archiveName = "Checkpoint_" +(Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmss") + ".json";
				#Store final RTF file locally and then upload to archive folder
				[JsonHelper]::ConvertToJsonCustom($this.ResourceScanTrackerObj) | Out-File $this.MasterFilePath -Force

				Set-AzStorageBlobContent -File $this.MasterFilePath -Container $this.CAScanProgressSnapshotsContainerName -Blob (Join-Path $this.OrgName.ToLower() (Join-Path "Archive" $archiveName)) -BlobType Block -Context $this.StorageContext -Force
				Remove-AzStorageBlob -CloudBlob $this.ControlStateBlob.ICloudBlob -Force -Context $this.StorageContext

				#Delete local RTF file
				if (Test-Path (Join-Path $this.AzSKTempStatePath $this.OrgName))
				{
					Remove-Item -Path (Join-Path $this.AzSKTempStatePath $this.OrgName) -Recurse
				}
			}	
		}

        #Use local Resource Tracker files for partial scanning
        elseif ($this.StoreResTrackerLocally) {
		    if($null -ne $this.ResourceScanTrackerObj)
		    {
			    if(![string]::isnullorwhitespace($this.OrgName)){
				    if(Test-Path (Join-Path $this.AzSKTempStatePath $this.OrgName))
				    {
						Remove-Item -Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrgName) $this.ResourceScanTrackerFileName)
						
						<#Create archive folder if not exists
						if(-not (Test-Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrgName) "archive")))
						{
							New-Item -ItemType Directory -Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrgName) "archive")
						}
						$timestamp =(Get-Date -format "yyMMddHHmmss")
						Move-Item -Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrgName) $this.ResourceScanTrackerFileName) -Destination (Join-Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrgName) "archive")"Checkpoint_$($timestamp)")
						#>
					}
			    }
			    $this.ResourceScanTrackerObj = $null
		    }
        }
	}

	#Method to fetch all applicable resources as per input command (including those with "COMP" status in ResourceTracker file)
	[void] CreateResourceMasterList([PSObject] $resourceIds)
	{
		if(($resourceIds | Measure-Object).Count -gt 0)
		{
			[System.Collections.Generic.List[PartialScanResource]] $resourceIdMap = @();
			$progressCount=1
			$resourceIds | ForEach-Object {			
				$resourceValue = [PartialScanResource]@{
					Id = $_.ResourceId;
					State = [ScanState]::INIT;
					ScanRetryCount = 0;
					CreatedDate = [DateTime]::UtcNow;
					ModifiedDate = [DateTime]::UtcNow;
					Name=$_.ResourceName;
					ProjectName = $_.ResourceGroupName
					#ResourceDetails=$_.ResourceDetails
					
				}

				#We dont need to store project name if -dnrr not given or the resource is not release/agentpool
				if($PSCmdlet.MyInvocation.BoundParameters['DoNotRefetchResources']){ 
					if($_.ResourceType -ne "ADO.Release" -and $_.ResourceType -ne "ADO.AgentPool"){
						$resourceValue = $resourceValue | Select-Object -Property * -ExcludeProperty ProjectName						
					}
				}
				else {
					$resourceValue = $resourceValue | Select-Object -Property * -ExcludeProperty ProjectName
				}
				
				#$resourceIdMap.Add($hashId,$resourceValue);
				$resourceIdMap.Add([PartialScanResource] $resourceValue)
				if ($progressCount%100 -eq 0) {				
					Write-Progress -Activity "Tracking $($progressCount) of $($resourceIds.Count) untracked resources " -Status "Progress: " -PercentComplete ($progressCount / $resourceIds.Count * 100)
				}
				$progressCount++;
			}
			Write-Progress -Activity "Tracked all resources" -Status "Ready" -Completed
			$masterControlBlob = [PartialScanResourceMap]@{
				Id = [DateTime]::UtcNow.ToString("yyyyMMdd_HHmmss");
				CreatedDate = [DateTime]::UtcNow;
				ResourceMapTable = $resourceIdMap;
			}

			if ($this.ScanPendingForResources -ne $null -and $this.ScanSource -eq "CICD"){

                if([Helpers]::CheckMember($this.ScanPendingForResources.ResourceMapTable,"value"))
                {
                    $this.ResourceScanTrackerObj = [PartialScanResourceMap]@{
                        Id = $this.ScanPendingForResources.Id;
                        CreatedDate = $this.ScanPendingForResources.CreatedDate;
                        ResourceMapTable = $this.ScanPendingForResources.ResourceMapTable.value;
                    }
                }
                else{
                    $this.ResourceScanTrackerObj = [PartialScanResourceMap]@{
                        Id = $this.ScanPendingForResources.Id;
                        CreatedDate = $this.ScanPendingForResources.CreatedDate;
                        ResourceMapTable = $this.ScanPendingForResources.ResourceMapTable;
                    }
                }
            }
            else{
                $this.ResourceScanTrackerObj = $masterControlBlob;
            }

			if ($this.ScanSource -eq "CICD" -or $this.ScanSource -eq "CA")
			{
				$this.WriteToDurableStorage();
			}
			else {
				$this.WriteToResourceTrackerFile();
			}

			$this.ActiveStatus = [ActiveStatus]::Yes;
		}
	}

	[void] WriteToResourceTrackerFile()
	{
        if ($this.StoreResTrackerLocally) 
        {
			if($null -ne $this.ResourceScanTrackerObj)
			{
				if(![string]::isnullorwhitespace($this.OrgName)){
					if(-not (Test-Path (Join-Path $this.AzSKTempStatePath $this.OrgName)))
					{
						New-Item -ItemType Directory -Path (Join-Path $this.AzSKTempStatePath $this.OrgName) -ErrorAction Stop | Out-Null
					}	
				}
				else{
					if(-not (Test-Path "$this.AzSKTempStatePath"))
					{
						New-Item -ItemType Directory -Path "$this.AzSKTempStatePath" -ErrorAction Stop | Out-Null
					}
				}
				Write-Host "Updating resource tracker file" -ForegroundColor Yellow
				[JsonHelper]::ConvertToJsonCustom($this.ResourceScanTrackerObj) | Out-File $this.MasterFilePath -Force
				Write-Host "Resource tracker file updated" -ForegroundColor Yellow
				
			}
        }
	}

	[void] WriteToDurableStorage()
	{
		if ($this.ScanSource -eq "CICD")
		{
            if($null -ne $this.ResourceScanTrackerObj)
		    {
				if(![string]::isnullorwhitespace($this.OrgName))
				{
					$rmContext = [ContextHelper]::GetCurrentContext();
					$user = "";
                    $uri = "";
					$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))
					$scanObject = $this.ResourceScanTrackerObj | ConvertTo-Json
					$body = "";

                    if (Test-Path env:partialScanURI)
                    {
                        $uri = $env:partialScanURI
                        $JobId ="";
                        $JobId = $uri.Replace('?','/').Split('/')[$JobId.Length -2]
						if ($this.IsRTFAlreadyAvailable -eq $true){
						    $body = @{"id" = $Jobid; "__etag"=-1; "value"= $scanObject;} | ConvertTo-Json
                        }
                        else{
                            $body = @{"id" = $Jobid; "value"= $scanObject;} | ConvertTo-Json
                        }
                    }
                    else {
						$uri = [Constants]::StorageUri -f $this.OrgName, $this.OrgName, "ResourceTrackerFile"
                        if ($this.IsRTFAlreadyAvailable -eq $true){
                            $body = @{"id" = "ResourceTrackerFile";"__etag"=-1; "value"= $scanObject;} | ConvertTo-Json
                        }
                        else{
                            $body = @{"id" = "ResourceTrackerFile"; "value"= $scanObject;} | ConvertTo-Json
                        }
                    }

					try {
						$webRequestResult = Invoke-WebRequest -Uri $uri -Method Put -ContentType "application/json" -Headers @{Authorization = ("Basic {0}" -f $base64AuthInfo) } -Body $body 
                        $this.IsRTFAlreadyAvailable = $true;
					}
					catch
					{
						write-host "Could not update resource tracker file."
					}		
			    }
			}
		}
        elseif ($this.ScanSource -eq "CA" -and $this.IsDurableStorageFound) 
        {
            if ($this.IsRTFAlreadyAvailable) # Copy RTF from memory
            {
                $this.ControlStateBlob.ICloudBlob.UploadText([JsonHelper]::ConvertToJsonCustom($this.ResourceScanTrackerObj) )
            }
            else { # If file is not available in storage then upload it from local for the first instance
                if ($null -ne $this.MasterFilePath -and -not (Test-Path $this.MasterFilePath))
                {
                    # Create directory and resource tracker file
                    $filePath = $this.MasterFilePath.Replace($this.ResourceScanTrackerFileName, "")
                    if (-not (Test-Path $filePath))
                    {
                        New-Item -ItemType Directory -Path $filePath
                    }
                    New-Item -Path $filePath -Name $this.ResourceScanTrackerFileName -ItemType "file" 
                }
                [JsonHelper]::ConvertToJsonCustom($this.ResourceScanTrackerObj) | Out-File $this.MasterFilePath -Force
                Set-AzStorageBlobContent -File $this.MasterFilePath -Container $this.CAScanProgressSnapshotsContainerName -Blob (Join-Path $this.OrgName.ToLower() $this.ResourceScanTrackerFileName) -BlobType Block -Context $this.StorageContext -Force
                $this.ControlStateBlob = Get-AzStorageBlob -Container $this.CAScanProgressSnapshotsContainerName -Context $this.StorageContext -Blob (Join-Path $this.OrgName.ToLower() $this.ResourceScanTrackerFileName) -ErrorAction SilentlyContinue
                $this.IsRTFAlreadyAvailable = $true
			}
        }
	}

	#Method to fetch ResourceTrackerFile as an object
	hidden [void] GetResourceScanTrackerObject()
	{
        try
        {
            if($null -eq $this.ScanPendingForResources)
			{
				return;
			}
			if ($this.ScanSource -eq "CICD") # use extension storage in case of CICD partial scan
			{
				if(![string]::isnullorwhitespace($this.ScanPendingForResources))
				{
					if([Helpers]::CheckMember($this.ScanPendingForResources.ResourceMapTable,"value"))
                    {
                        $this.ResourceScanTrackerObj = [PartialScanResourceMap]@{
                            Id = $this.ScanPendingForResources.Id;
                            CreatedDate = $this.ScanPendingForResources.CreatedDate;
                            ResourceMapTable = $this.ScanPendingForResources.ResourceMapTable.value;
                        }
                    }
                    else{
                        $this.ResourceScanTrackerObj = [PartialScanResourceMap]@{
                            Id = $this.ScanPendingForResources.Id;
                            CreatedDate = $this.ScanPendingForResources.CreatedDate;
                            ResourceMapTable = $this.ScanPendingForResources.ResourceMapTable;
                        }
                    }
				}
			}
			elseif ($this.ScanSource -eq "CA")
			{
				if(![string]::isnullorwhitespace($this.ScanPendingForResources))
				{
					$this.ResourceScanTrackerObj = $this.ScanPendingForResources
				}
			}
            elseif ($this.StoreResTrackerLocally) 
            {
			    if(![string]::isnullorwhitespace($this.OrgName)){
				    if(-not (Test-Path (Join-Path $this.AzSKTempStatePath $this.OrgName)))
				    {
					    New-Item -ItemType Directory -Path (Join-Path $this.AzSKTempStatePath $this.OrgName) -ErrorAction Stop | Out-Null
				    }
			    }
			    else{
				    if(-not (Test-Path "$this.AzSKTempStatePath"))
				    {
					    New-Item -ItemType Directory -Path "$this.AzSKTempStatePath" -ErrorAction Stop | Out-Null
				    }
				}
				$this.ResourceScanTrackerObj = Get-content $this.MasterFilePath | ConvertFrom-Json
            }
        }
        catch{
            $this.ResourceScanTrackerObj = $null
            $this.ScanPendingForResources = $null
            Write-Host "RTF not found"
        }
	}

    #Sending $isControlFixCmd as true in case set-azskadosecuritystatus command is used in order to store RTF in separate folder, so that it does not interfere with GADS command
	[ActiveStatus] IsPartialScanInProgress($orgName, $isControlFixCmd) 
	{
		$this.GetResourceTrackerFile($orgName, $isControlFixCmd);
		if($null -ne $this.ControlSettings.PartialScan)
		{
			$resourceTrackerFileValidforDays = [Int32]::Parse($this.ControlSettings.PartialScan.ResourceTrackerValidforDays);
			$this.GetResourceScanTrackerObject();
			if($null -eq $this.ResourceScanTrackerObj)
			{
				return $this.ActiveStatus = [ActiveStatus]::No;
			}
			$shouldStopScanning = ($this.ResourceScanTrackerObj.ResourceMapTable | Where-Object {$_.State -notin ([ScanState]::COMP,[ScanState]::ERR)} |  Measure-Object).Count -eq 0
			if($this.ResourceScanTrackerObj.CreatedDate.AddDays($resourceTrackerFileValidforDays) -lt [DateTime]::UtcNow -or $shouldStopScanning)
			{
				$this.RemovePartialScanData();
				$this.ScanPendingForResources = $null;
				return $this.ActiveStatus = [ActiveStatus]::No;
			}
			return $this.ActiveStatus = [ActiveStatus]::Yes
		}
		else
		{
			$this.ScanPendingForResources = $null;
			return $this.ActiveStatus = [ActiveStatus]::No;
		}
	}

	[PSObject] GetNonScannedResources()
	{
		#[System.Collections.Generic.List[PartialScanResource]] $nonScannedResources = @();
		$nonScannedResources = @()
        $this.GetResourceScanTrackerObject();
		if($this.IsListAvailableAndActive())
		{
			

			$nonScannedResources +=[PartialScanResource[]] $this.ResourceScanTrackerObj.ResourceMapTable | Where-Object {$_.State -eq [ScanState]::INIT}
			return [PartialScanResource[]] $nonScannedResources;
		}
		return $null;
	}

	[PSObject] GetAllListedResources()
	{
		#[System.Collections.Generic.List[PartialScanResource]] $nonScannedResources = @();
		$nonScannedResources = @()
		$this.GetResourceScanTrackerObject();
		if($this.IsListAvailableAndActive())
		{
			$nonScannedResources +=[PartialScanResource[]]  $this.ResourceScanTrackerObj.ResourceMapTable
			return [PartialScanResource[]] $nonScannedResources;
		}
		return $null;
	}

	[Bool] IsListAvailableAndActive()
	{
		if($null -ne $this.ResourceScanTrackerObj -and $this.ActiveStatus -eq [ActiveStatus]::Yes -and $null -ne $this.ResourceScanTrackerObj.ResourceMapTable)
		{
			return $true
		}
		else
		{
			return $false
		}
	}

    # Collect control results summary data and append to it at every checkpoint. Any changes in this method should be synced with WritePSConsole.ps1 PrintSummaryData method
	[void] CollateSummaryData($event)
	{
		$summary = @($event | select-object @{Name="VerificationResult"; Expression = {$_.ControlResults.VerificationResult}},@{Name="ControlSeverity"; Expression = {$_.ControlItem.ControlSeverity}})

		if(($summary | Measure-Object).Count -ne 0)
		{

			$severities = @();
			$severities += $summary | Select-Object -Property ControlSeverity | Select-Object -ExpandProperty ControlSeverity -Unique;

			$verificationResults = @();
			$verificationResults += $summary | Select-Object -Property VerificationResult | Select-Object -ExpandProperty VerificationResult -Unique;

			if($severities.Count -ne 0)
			{
				# Create summary matrix
				$totalText = "Total";
				$MarkerText = "MarkerText";
				$rows = @();
				$rows += $severities;
				$rows += $MarkerText;
				$rows += $totalText;
				$rows += $MarkerText;

				#Execute below block only once (when first resource is scanned) 
				if([PartialScanManager]::CollatedSummaryCount.Count -eq 0)
				{
					$rows | ForEach-Object {
						$result = [PSObject]::new();
						Add-Member -InputObject $result -Name "Summary" -MemberType NoteProperty -Value $_.ToString()
						Add-Member -InputObject $result -Name $totalText -MemberType NoteProperty -Value 0

						#Get all possible verificationResults initially
						[Enum]::GetNames([VerificationResult]) | 
						ForEach-Object {
							Add-Member -InputObject $result -Name $_.ToString() -MemberType NoteProperty -Value 0
						};
						[PartialScanManager]::CollatedSummaryCount += $result;
					};
				}

				$totalRow = [PartialScanManager]::CollatedSummaryCount | Where-Object { $_.Summary -eq $totalText } | Select-Object -First 1;

				$summary | Group-Object -Property ControlSeverity | ForEach-Object {
					$item = $_;
					$summaryItem = [PartialScanManager]::CollatedSummaryCount | Where-Object { $_.Summary -eq $item.Name } | Select-Object -First 1;
					if($summaryItem)
					{
						$summaryItem.Total += $_.Count;
						if($totalRow)
						{
							$totalRow.Total += $_.Count
						}
						$item.Group | Group-Object -Property VerificationResult | ForEach-Object {
							$propName = $_.Name;
							$summaryItem.$propName += $_.Count;
							if($totalRow)
							{
								$totalRow.$propName += $_.Count
							}
						};
					}
				};
				$markerRows = [PartialScanManager]::CollatedSummaryCount | Where-Object { $_.Summary -eq $MarkerText } 
				$markerRows | ForEach-Object { 
					$markerRow = $_
					Get-Member -InputObject $markerRow -MemberType NoteProperty | ForEach-Object {
							$propName = $_.Name;
							$markerRow.$propName = $this.SummaryMarkerText;				
						}
					};
			}
		}
	}

    # Collect Bug summary data and append to it at every checkpoint. Any changes in this method should be synced with WritePSConsole.ps1 PrintBugSummaryData method
	[void] CollateBugSummaryData($event){
		#gather all control results that have failed/verify as their control result
		#obtain their control severities
		$event | ForEach-Object {
			$item = $_
			if ($item -and $item.ControlResults -and ($item.ControlResults[0].VerificationResult -eq "Failed" -or $item.ControlResults[0].VerificationResult -eq "Verify"))
			{
				$item
				$item.ControlResults[0].Messages | ForEach-Object{
					if($_.Message -eq "New Bug" -or $_.Message -eq "Active Bug" -or $_.Message -eq "Resolved Bug"){
					[PartialScanManager]::CollatedBugSummaryCount += [PSCustomObject]@{
						BugStatus=$_.Message
						ControlSeverity = $item.ControlItem.ControlSeverity;
						
					};
				}
				};
				#Collecting control results where bug has been found (new/active/resolved). This is used to generate BugSummary at the end of scan
				[PartialScanManager]::ControlResultsWithBugSummary += $item
			}
		};

	}
		    # Collect Closed Bugs summary data and append to it at every checkpoint. Any changes in this method should be synced with WritePSConsole.ps1 PrintBugSummaryData method
	[void] CollateClosedBugSummaryData($event){
		#gather all control results that have passed as their control result
		#obtain their control severities
		$TotalWorkItemCount=0;
		$TotalControlsClosedCount=0;
		$event | ForEach-Object {
			$item = $_
			if ($item -and $item.ControlResults)
			{
				$TotalControlsClosedCount+=1;
				# If two bugs are logged against same resource and control in different project, message will contain closed bug twice with different urls
				$item.ControlResults[0].Messages | ForEach-Object{
					if($_.Message -eq "Closed Bug"){
						# CollatedBugSummaryCount is used for PS Console summary printing
						[PartialScanManager]::CollatedBugSummaryCount += [PSCustomObject]@{
							BugStatus=$_.Message
							ControlSeverity = $item.ControlItem.ControlSeverity;
						};
						$TotalWorkItemCount+=1
					}
				};
				#Collecting control results where closed bug has been found. This is used to generate BugSummary at the end of scan
				[PartialScanManager]::ControlResultsWithClosedBugSummary += $item
			}
		};
		[PartialScanManager]::duplicateClosedBugCount+=($TotalWorkItemCount-$TotalControlsClosedCount)

	}

    # Write to csv and append to it at every checkpoint. Any changes in this method should be synced with WriteSummaryFile.ps1 WriteToCSV method
	[void] WriteToCSV([SVTEventContext[]] $arguments, $FilePath)
    {
        if ([string]::IsNullOrEmpty($FilePath)) {
            return;
        }
        [CsvOutputItem[]] $csvItems = @();
		$anyAttestedControls = $null -ne ($arguments | 
			Where-Object { 
				$null -ne ($_.ControlResults | Where-Object { $_.AttestationStatus -ne [AttestationStatus]::None } | Select-Object -First 1) 
			} | Select-Object -First 1);

        $arguments | ForEach-Object {
            $item = $_
            if ($item -and $item.ControlResults) {
				

                $item.ControlResults | ForEach-Object{
                    $csvItem = [CsvOutputItem]@{
                        ControlID = $item.ControlItem.ControlID;
                        ControlSeverity = $item.ControlItem.ControlSeverity;
                        Description = $item.ControlItem.Description;
                        FeatureName = $item.FeatureName;
                        Recommendation = $item.ControlItem.Recommendation;	
                        Rationale = $item.ControlItem.Rationale;
                        AdditionalInfo = $_.AdditionalInfoInCSV
                    };
					if($_.VerificationResult -ne [VerificationResult]::NotScanned)
					{
						$csvItem.Status = $_.VerificationResult.ToString();
					}
					
					if($item.ControlItem.IsBaselineControl)
					{
						$csvItem.IsBaselineControl = "Yes";
					}
					else
					{
						$csvItem.IsBaselineControl = "No";
					}

					if($anyAttestedControls)
					{
						$csvItem.ActualStatus = $_.ActualVerificationResult.ToString();
					}

					if($item.IsResource())
					{
						$csvItem.ResourceName = $item.ResourceContext.ResourceName;
                        $csvItem.ResourceGroupName = $item.ResourceContext.ResourceGroupName;
						try {
							if($item.ResourceContext.ResourceDetails -ne $null -and ([Helpers]::CheckMember($item.ResourceContext.ResourceDetails,"ResourceLink")))
						    {
								$csvItem.ResourceLink = $item.ResourceContext.ResourceDetails.ResourceLink;							
							}
						}
						catch {
							$_
						}
						$csvItem.ResourceId = $item.ResourceContext.ResourceId;
						$csvItem.DetailedLogFile = "/$([Helpers]::SanitizeFolderName($item.ResourceContext.ResourceGroupName))/$($item.FeatureName).LOG";

						
					}
					else
					{
					    $csvItem.ResourceId = $item.OrganizationContext.scope;
						$csvItem.DetailedLogFile = "/$([Helpers]::SanitizeFolderName($item.OrganizationContext.OrganizationName))/$($item.FeatureName).LOG"
						
					}

					if($_.AttestationStatus -ne [AttestationStatus]::None)
					{
						$csvItem.AttestedSubStatus = $_.AttestationStatus.ToString();
						if($null -ne $_.StateManagement -and $null -ne $_.StateManagement.AttestedStateData)
						{
							$csvItem.AttesterJustification = $_.StateManagement.AttestedStateData.Justification
							$csvItem.AttestedBy =  $_.StateManagement.AttestedStateData.AttestedBy
							if(![string]::IsNullOrWhiteSpace($_.StateManagement.AttestedStateData.ExpiryDate))
							{
								$csvItem.AttestationExpiryDate =  $_.StateManagement.AttestedStateData.ExpiryDate
							}
							if(![string]::IsNullOrWhiteSpace($_.StateManagement.AttestedStateData.AttestedDate))
							{
								$csvItem.AttestedOn=  $_.StateManagement.AttestedStateData.AttestedDate
							}
						}
					}
					<#if($_.IsControlInGrace -eq $true)
					{
						$csvItem.IsControlInGrace = "Yes"
					}
					else 
					{
						$csvItem.IsControlInGrace = "No"
					}#>					
                    $csvItems += $csvItem;
                }                                
            }
        } 

        if ($csvItems.Count -gt 0) {
			# Remove Null properties
			$nonNullProps = @();
			$nonNullProps = [CsvOutputItem].GetMembers() | Where-Object { $_.MemberType -eq [System.Reflection.MemberTypes]::Property }| Select-object -Property Name
			
			($csvItems | Select-Object -Property $nonNullProps.Name -ExcludeProperty SupportsAutoFix,ChildResourceName,IsPreviewBaselineControl,UserComments ) | Group-Object -Property FeatureName | Foreach-Object {$_.Group | Export-Csv -Path $FilePath -append -NoTypeInformation}
			[PartialScanManager]::IsCsvUpdatedAtCheckpoint = $true
        }
	}
	[void] 	CollateSARIFData($event)
	{
		$event | ForEach-Object {
			$item = $_
			if ($item -and $item.ControlResults -and ($item.ControlResults[0].VerificationResult -eq "Failed" -or $item.ControlResults[0].VerificationResult -eq "Verify"))
			{
				#Collecting Failed and verify controls
				[PartialScanManager]::ControlResultsWithSARIFSummary += $item
			}
		};
	}
    
    
    [void] FetchControlStateBackup($InternalId)
    {
        $this.BackupControlStateFilePath = (Join-Path $this.BackupControlStatePath $this.OrgName)
        if($InternalId -match "Organization")
        {
            if(-not (Test-Path $this.BackupControlStateFilePath))
            {
                New-Item -ItemType Directory -Path $this.BackupControlStateFilePath -ErrorAction Stop | Out-Null
            }
            else {
                $this.StateOfControlsToBeFixed += Get-Content (Join-Path $this.BackupControlStateFilePath "$InternalId + '.Json'") -Raw | ConvertFrom-Json
            }
        }
        else {
            # validate org level folder exists
            if(-not (Test-Path $this.BackupControlStateFilePath))
            {
                New-Item -ItemType Directory -Path $this.BackupControlStateFilePath -ErrorAction Stop | Out-Null
            }

            $this.BackupControlStateFilePath = (Join-Path $this.BackupControlStateFilePath $this.ProjectName)
            if(-not (Test-Path $this.BackupControlStateFilePath))
            {
                New-Item -ItemType Directory -Path $this.BackupControlStateFilePath -ErrorAction Stop | Out-Null
            }
            else {
                $this.StateOfControlsToBeFixed += Get-Content (Join-Path $this.BackupControlStateFilePath "$($InternalId + '.Json')") -Raw | ConvertFrom-Json
            }
        }
        $this.IsControlStateBackupFetched = $true
    }


    [void] WriteControlFixDataObject($results)
    {
        if ($this.ScanSource -eq "SDL" -or $this.ScanSource -eq "")
        {
            $scannedby = [ContextHelper]::GetCurrentSessionUser();
            $date = [DateTime]::UtcNow;
            $applicableControls = @()
			$controlsDataObject = @();
			if (($results | measure-object).Count -gt 0) {
				if ($results[0].FeatureName -eq "Project") {
					$controlsDataObject = @($results  | Where-Object {$_.ControlItem.Tags -contains 'AutomatedFix' -and ($_.ControlResults.VerificationResult -eq 'Failed' -or $_.ControlResults.VerificationResult -eq 'Verify') -and $null -ne $_.ControlResults.BackupControlState} `
					| Select-Object @{Name="ProjectName"; Expression={$_.ResourceContext.ResourceName}}, @{Name="ResourceName"; Expression={$_.ResourceContext.ResourceName}}, @{Name="ResourceId"; Expression={$_.ResourceContext.ResourceId}}, @{Name="InternalId"; Expression={$_.ControlItem.id}}, @{Name="DataObject"; Expression={$_.ControlResults.BackupControlState}}); 
				}
				else {
					$controlsDataObject = @($results  | Where-Object {$_.ControlItem.Tags -contains 'AutomatedFix' -and ($_.ControlResults.VerificationResult -eq 'Failed' -or $_.ControlResults.VerificationResult -eq 'Verify') -and $null -ne $_.ControlResults.BackupControlState} `
					| Select-Object @{Name="ProjectName"; Expression={$_.ResourceContext.ResourceGroupName}}, @{Name="ResourceName"; Expression={$_.ResourceContext.ResourceName}}, @{Name="ResourceId"; Expression={$_.ResourceContext.ResourceId}}, @{Name="InternalId"; Expression={$_.ControlItem.id}}, @{Name="DataObject"; Expression={$_.ControlResults.BackupControlState}}); 
				}
			}
			if($null -ne $controlsDataObject -and $controlsDataObject.Count -gt 0)
        {
				$controlsDataObject | Add-Member -NotePropertyName ScannedBy -NotePropertyValue $scannedBy 
				$controlsDataObject | Add-Member -NotePropertyName Date -NotePropertyValue $date  

				if(-not $this.IsControlStateBackupFetched)  
				{
					$this.ProjectName = ($controlsDataObject | Select-Object -Property ProjectName -Unique).ProjectName
					$this.ProjectName = $this.ProjectName.Trim()
					$this.FetchControlStateBackup($controlsDataObject[0].InternalId);
				}

				$controlsDataObject = @($controlsDataObject)

				if($controlsDataObject.Count -gt 0)
				{
					$fileName =  $controlsDataObject[0].InternalId + ".json"

					if($null -ne $this.StateOfControlsToBeFixed)
					{
						$existingDataObj = $this.StateOfControlsToBeFixed | where-Object {$_.ResourceId -in $controlsDataObject.ResourceId}
						if (($existingDataObj | Measure-Object).Count -gt 0)
						{
							$this.StateOfControlsToBeFixed = @($this.StateOfControlsToBeFixed | where-Object {$_ -notin $existingDataObj})
						}
					}

					$applicableControls += $controlsDataObject |  select-object -property Date,ResourceId,ResourceName,DataObject,ScannedBy
					$this.StateOfControlsToBeFixed += $applicableControls
					[JsonHelper]::ConvertToJsonCustom($this.StateOfControlsToBeFixed) | Out-File (Join-Path $this.BackupControlStateFilePath $fileName) -Force
				}
            }		
			 
									
            
        }
    }
}

