Set-StrictMode -Version Latest

class PartialScanManager
{
	hidden [string] $subId = $null;
	hidden [PSObject] $ScanPendingForResources = $null;
	hidden [string] $ResourceScanTrackerFileName=$null;
	hidden [PartialScanResourceMap] $ResourceScanTrackerObj = $null
	[PSObject] $ControlSettings;
	hidden [ActiveStatus] $ActiveStatus = [ActiveStatus]::NotStarted;
	hidden [string] $CAScanProgressSnapshotsContainerName = [Constants]::CAScanProgressSnapshotsContainerName
    hidden [string] $AzSKTempStatePath = (Join-Path $([Constants]::AzSKAppFolderPath) "TempState" | Join-Path -ChildPath "PartialScanData");
	hidden [bool] $StoreResTrackerLocally = $false;
	hidden [string] $scanSource = $null;
	hidden [bool] $isRTFAlreadyAvailable = $false;
	hidden [bool] $isDurableStorageFound = $false;
	hidden [string] $masterFilePath;
	$storageContext = $null;
	$controlStateBlob = $null;
	hidden static $CSVCheckpointUpdate = $false; 
	hidden static $CollatedSummaryCount = @();
	hidden static $CollatedBugSummaryCount = @();
	hidden static $ControlResultsWithBugSummary = @();
	hidden [string] $SummaryMarkerText = "------";


	hidden static [PartialScanManager] $Instance = $null;
	
	static [PartialScanManager] GetInstance([PSObject] $StorageAccount, [string] $SubscriptionId)
    {
        if ( $null -eq  [PartialScanManager]::Instance)
        {
			[PartialScanManager]::Instance = [PartialScanManager]::new($SubscriptionId);
		}
		[PartialScanManager]::Instance.subId = $SubscriptionId;
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
    }
	PartialScanManager([string] $SubscriptionId)
	{
		$this.ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
		$this.subId = $SubscriptionId;
		if ([string]::isnullorwhitespace($this.ResourceScanTrackerFileName))
        {
           if([ConfigurationManager]::GetAzSKSettings().IsCentralScanModeOn)
		   {
				$this.ResourceScanTrackerFileName = Join-Path $SubscriptionId $([Constants]::ResourceScanTrackerCMBlobName)
		   }
		   else
		   {
				$this.ResourceScanTrackerFileName = Join-Path $SubscriptionId $([Constants]::ResourceScanTrackerBlobName)
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

     hidden [void] GetResourceTrackerFile($subId)
    {
		$this.scanSource = [AzSKSettings]::GetInstance().GetScanSource();
		$this.subId = $subId

		#Validating the configuration of storing resource tracker file
        if($null -ne $this.ControlSettings.PartialScan)
		{
			$this.StoreResTrackerLocally = [Bool]::Parse($this.ControlSettings.PartialScan.StoreResourceTrackerLocally);
		}

		#Use local Resource Tracker files for partial scanning
        if ($this.StoreResTrackerLocally -and ($this.scanSource -ne "CA" -and $this.scanSource -ne "CICD") )
        {
            if($null -eq $this.ScanPendingForResources)
		    {
			    if(![string]::isnullorwhitespace($this.subId)){
				    if(Test-Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.subId) $this.ResourceScanTrackerFileName))	
			        {
						$this.ScanPendingForResources = Get-Content (Join-Path (Join-Path $this.AzSKTempStatePath $this.subId) $this.ResourceScanTrackerFileName) -Raw
					}
					$this.masterFilePath = (Join-Path (Join-Path $this.AzSKTempStatePath $this.subId) $this.ResourceScanTrackerFileName)
				}
				else {
					$this.masterFilePath = (Join-Path $this.AzSKTempStatePath $this.ResourceScanTrackerFileName)
				}
			}
        }

		If ($this.scanSource -eq "CA") # use storage in ADOScannerRG in case of CA scan
		{
			$this.masterFilePath = (Join-Path (Join-Path $this.AzSKTempStatePath $this.subId) $this.ResourceScanTrackerFileName)

			try {
				#Validate if Storage is found 
				$keys = Get-AzStorageAccountKey -ResourceGroupName $env:StorageRG -Name $env:StorageName
				$this.StorageContext = New-AzStorageContext -StorageAccountName $env:StorageName -StorageAccountKey $keys[0].Value -Protocol Https
				$containerObject = Get-AzStorageContainer -Context $this.StorageContext -Name $this.CAScanProgressSnapshotsContainerName -ErrorAction SilentlyContinue
					
				#If checkpoint container is found then get ResourceTracker.json (if exists)
				if($null -ne $containerObject)
				{
					$this.controlStateBlob = Get-AzStorageBlob -Container $this.CAScanProgressSnapshotsContainerName -Context $this.StorageContext -Blob (Join-Path $this.subId.ToLower() $this.ResourceScanTrackerFileName) -ErrorAction SilentlyContinue

					#If controlStateBlob is null then it will get created when we first write the resource tracker file to storage
					#If its not null this means Resource tracker file has been found in storage and will be used to continue pending scan
					if ($null -ne $this.controlStateBlob)
					{
						if ($null -ne $this.masterFilePath)
						{
							if (-not (Test-Path $this.masterFilePath))
							{
								$filePath = $this.masterFilePath.Replace($this.ResourceScanTrackerFileName, "")
								New-Item -ItemType Directory -Path $filePath
								New-Item -Path $filePath -Name $this.ResourceScanTrackerFileName -ItemType "file" 
							}
							#Copy existing RTF locally to handle any non ascii characters as ICloudBlob.DownloadText() was inserting non ascii charcaters
							Get-AzStorageBlobContent -CloudBlob $this.controlStateBlob.ICloudBlob -Context $this.StorageContext -Destination $this.masterFilePath -Force                
							$this.ScanPendingForResources  = Get-ChildItem -Path $this.masterFilePath -Force | Get-Content | ConvertFrom-Json
							#Delete the local RTF file
							Remove-Item -Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.subId) $this.ResourceScanTrackerFileName)
						}
						$this.isRTFAlreadyAvailable = $true
					}
					$this.isDurableStorageFound = $true
				}
				#If checkpoint container is not found then create new
				else {
					$containerObject = New-AzStorageContainer -Name $this.CAScanProgressSnapshotsContainerName -Context $this.StorageContext -ErrorAction SilentlyContinue
					if ($null -ne $containerObject )
					{
						$this.isDurableStorageFound = $true
					}
					else 
					{
						$this.PublishCustomMessage("Could not find/create partial scan container in storage.", [MessageType]::Warning);
					}
				}
			}
			catch {
				$this.PublishCustomMessage("Exception when trying to find/create partial scan container: $_.", [MessageType]::Warning);
				#Eat exception
			}

		}
		
		elseif ($this.scanSource -eq "CICD") # use extension storage in case of CICD partial scan
		{
				if(![string]::isnullorwhitespace($this.subId))
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
					    $uri = [Constants]::StorageUri -f $this.subId, $this.subId, "ResourceTrackerFile"
                    }

					try {
						$webRequestResult = Invoke-RestMethod -Uri $uri -Method Get -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)}
						$this.ScanPendingForResources = $webRequestResult.value | ConvertFrom-Json
                        $this.isRTFAlreadyAvailable = $true;
					}
					catch
					{
                        $this.ScanPendingForResources = $null
                        $this.isRTFAlreadyAvailable = $false;
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
		If ($this.scanSource -eq "CICD")
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
					$uri = [Constants]::StorageUri -f $this.subId, $this.subId, "ResourceTrackerFile"
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
		elseif ($this.scanSource -eq "CA" -and $this.isDurableStorageFound) {
			#Move resource tracker file to archive folder
			if($null -ne $this.controlStateBlob)
			{
				$archiveName = "Checkpoint_" +(Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmss") + ".json";
				#Store final RTF file locally and then upload to archive folder
				[JsonHelper]::ConvertToJsonCustom($this.ResourceScanTrackerObj) | Out-File $this.masterFilePath -Force

				Set-AzStorageBlobContent -File $this.masterFilePath -Container $this.CAScanProgressSnapshotsContainerName -Blob (Join-Path $this.subId.ToLower() (Join-Path "Archive" $archiveName)) -BlobType Block -Context $this.storageContext -Force
				Remove-AzStorageBlob -CloudBlob $this.controlStateBlob.ICloudBlob -Force -Context $this.StorageContext

				#Delete local RTF file
				Remove-Item -Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.subId) $this.ResourceScanTrackerFileName)
			}	
		}

        #Use local Resource Tracker files for partial scanning
        if ($this.StoreResTrackerLocally) 
            {
		    if($null -ne $this.ResourceScanTrackerObj)
		    {
			    if(![string]::isnullorwhitespace($this.subId)){
				    if(Test-Path (Join-Path $this.AzSKTempStatePath $this.subId))
				    {
						Remove-Item -Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.subId) $this.ResourceScanTrackerFileName)
						
						<#Create archive folder if not exists
						if(-not (Test-Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.subId) "archive")))
						{
							New-Item -ItemType Directory -Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.subId) "archive")
						}
						$timestamp =(Get-Date -format "yyMMddHHmmss")
						Move-Item -Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.subId) $this.ResourceScanTrackerFileName) -Destination (Join-Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.subId) "archive")"Checkpoint_$($timestamp)")
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
			$resourceIdMap = @();
			$resourceIds | ForEach-Object {
				$resourceId = $_;
				$resourceValue = [PartialScanResource]@{
					Id = $resourceId;
					State = [ScanState]::INIT;
					ScanRetryCount = 0;
					CreatedDate = [DateTime]::UtcNow;
					ModifiedDate = [DateTime]::UtcNow;
				}
				#$resourceIdMap.Add($hashId,$resourceValue);
				$resourceIdMap +=$resourceValue
			}
			$masterControlBlob = [PartialScanResourceMap]@{
				Id = [DateTime]::UtcNow.ToString("yyyyMMdd_HHmmss");
				CreatedDate = [DateTime]::UtcNow;
				ResourceMapTable = $resourceIdMap;
			}

			if ($this.ScanPendingForResources -ne $null -and $this.scanSource -eq "CICD"){
                $this.ResourceScanTrackerObj = [PartialScanResourceMap]@{
				    Id = $this.ScanPendingForResources.Id;
				    CreatedDate = $this.ScanPendingForResources.CreatedDate;
				    ResourceMapTable = $this.ScanPendingForResources.ResourceMapTable.value;
			    }
            }
            else{
                $this.ResourceScanTrackerObj = $masterControlBlob;
            }

			If ($this.scanSource -eq "CICD" -or $this.scanSource -eq "CA")
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
        If ($this.StoreResTrackerLocally) 
        {
			if($null -ne $this.ResourceScanTrackerObj)
			{
				if(![string]::isnullorwhitespace($this.subId)){
					if(-not (Test-Path (Join-Path $this.AzSKTempStatePath $this.subId)))
					{
						New-Item -ItemType Directory -Path (Join-Path $this.AzSKTempStatePath $this.subId) -ErrorAction Stop | Out-Null
					}	
				}
				else{
					if(-not (Test-Path "$this.AzSKTempStatePath"))
					{
						New-Item -ItemType Directory -Path "$this.AzSKTempStatePath" -ErrorAction Stop | Out-Null
					}
				}
				[JsonHelper]::ConvertToJsonCustom($this.ResourceScanTrackerObj) | Out-File $this.masterFilePath -Force
			}
        }
	}

	[void] WriteToDurableStorage()
	{
		If ($this.scanSource -eq "CICD")
		{
            if($null -ne $this.ResourceScanTrackerObj)
		    {
				if(![string]::isnullorwhitespace($this.subId))
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
						if ($this.isRTFAlreadyAvailable -eq $true){
						    $body = @{"id" = $Jobid; "__etag"=-1; "value"= $scanObject;} | ConvertTo-Json
                        }
                        else{
                            $body = @{"id" = $Jobid; "value"= $scanObject;} | ConvertTo-Json
                        }
                    }
                    else {
						$uri = [Constants]::StorageUri -f $this.subId, $this.subId, "ResourceTrackerFile"
                        if ($this.isRTFAlreadyAvailable -eq $true){
                            $body = @{"id" = "ResourceTrackerFile";"__etag"=-1; "value"= $scanObject;} | ConvertTo-Json
                        }
                        else{
                            $body = @{"id" = "ResourceTrackerFile"; "value"= $scanObject;} | ConvertTo-Json
                        }
                    }

					try {
						$webRequestResult = Invoke-WebRequest -Uri $uri -Method Put -ContentType "application/json" -Headers @{Authorization = ("Basic {0}" -f $base64AuthInfo) } -Body $body 
                        $this.isRTFAlreadyAvailable = $true;
					}
					catch
					{
						write-host "Could not update resource tracker file."
					}		
			    }
			}
		}
        elseif ($this.scanSource -eq "CA" -and $this.isDurableStorageFound) 
		{
			if ($this.isRTFAlreadyAvailable) # Copy RTF from memory
			{
				$this.controlStateBlob.ICloudBlob.UploadText([JsonHelper]::ConvertToJsonCustom($this.ResourceScanTrackerObj) )
			}
			else { # If file is not avialble in storage then upload it from local for the first instance
				[JsonHelper]::ConvertToJsonCustom($this.ResourceScanTrackerObj) | Out-File $this.masterFilePath -Force
				Set-AzStorageBlobContent -File $this.masterFilePath -Container $this.CAScanProgressSnapshotsContainerName -Blob (Join-Path $this.subId.ToLower() $this.ResourceScanTrackerFileName) -BlobType Block -Context $this.StorageContext -Force
				$this.controlStateBlob = Get-AzStorageBlob -Container $this.CAScanProgressSnapshotsContainerName -Context $this.StorageContext -Blob (Join-Path $this.subId.ToLower() $this.ResourceScanTrackerFileName) -ErrorAction SilentlyContinue
			}
        }
	}

	#Method to fetch ResourceTrackerFile as an object
	hidden [void] GetResourceScanTrackerObject()
	{
            if($null -eq $this.ScanPendingForResources)
			{
				return;
			}
			If ($this.scanSource -eq "CICD") # use extension storage in case of CICD partial scan
			{
				if(![string]::isnullorwhitespace($this.ScanPendingForResources))
				{
					$this.ResourceScanTrackerObj = [PartialScanResourceMap]@{
				        Id = $this.ScanPendingForResources.Id;
				        CreatedDate = $this.ScanPendingForResources.CreatedDate;
				        ResourceMapTable = $this.ScanPendingForResources.ResourceMapTable.value;
			        }
				}
			}
			elseif ($this.scanSource -eq "CA")
			{
				if(![string]::isnullorwhitespace($this.ScanPendingForResources))
				{
					$this.ResourceScanTrackerObj = $this.ScanPendingForResources
				}
			}
            elseif ($this.StoreResTrackerLocally) 
            {
			    if(![string]::isnullorwhitespace($this.subId)){
				    if(-not (Test-Path (Join-Path $this.AzSKTempStatePath $this.subId)))
				    {
					    New-Item -ItemType Directory -Path (Join-Path $this.AzSKTempStatePath $this.subId) -ErrorAction Stop | Out-Null
				    }
			    }
			    else{
				    if(-not (Test-Path "$this.AzSKTempStatePath"))
				    {
					    New-Item -ItemType Directory -Path "$this.AzSKTempStatePath" -ErrorAction Stop | Out-Null
				    }
				}
				$this.ResourceScanTrackerObj = Get-content $this.masterFilePath | ConvertFrom-Json
            }
	}

	[ActiveStatus] IsPartialScanInProgress($subId)
	{
		$this.GetResourceTrackerFile($subId);
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
		$nonScannedResources = @();
        $this.GetResourceScanTrackerObject();
		if($this.IsListAvailableAndActive())
		{
			$nonScannedResources +=[PartialScanResource[]] $this.ResourceScanTrackerObj.ResourceMapTable | Where-Object {$_.State -eq [ScanState]::INIT}
			return $nonScannedResources;
		}
		return $null;
	}

	[PSObject] GetAllListedResources()
	{
		$nonScannedResources = @();
		$this.GetResourceScanTrackerObject();
		if($this.IsListAvailableAndActive())
		{
			$nonScannedResources += $this.ResourceScanTrackerObj.ResourceMapTable
			return $nonScannedResources;
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
						$summaryItem.Total = $_.Count;
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
				        Rationale = $item.ControlItem.Rationale
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
					    $csvItem.ResourceId = $item.SubscriptionContext.scope;
						$csvItem.DetailedLogFile = "/$([Helpers]::SanitizeFolderName($item.SubscriptionContext.SubscriptionName))/$($item.FeatureName).LOG"
						
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
					if($_.IsControlInGrace -eq $true)
					{
						$csvItem.IsControlInGrace = "Yes"
					}
					else 
					{
						$csvItem.IsControlInGrace = "No"
					}					
                    $csvItems += $csvItem;
                }                                
            }
        } 

        if ($csvItems.Count -gt 0) {
			# Remove Null properties
			$nonNullProps = @();
			$nonNullProps = [CsvOutputItem].GetMembers() | Where-Object { $_.MemberType -eq [System.Reflection.MemberTypes]::Property }| Select-object -Property Name
			
			($csvItems | Select-Object -Property $nonNullProps.Name -ExcludeProperty SupportsAutoFix,ChildResourceName,IsPreviewBaselineControl,UserComments ) | Group-Object -Property FeatureName | Foreach-Object {$_.Group | Export-Csv -Path $FilePath -append -NoTypeInformation}
			[PartialScanManager]::CSVCheckpointUpdate = $true
        }
	}	
}

