Set-StrictMode -Version Latest 

class IncScanHelper
{
    hidden [string] $OrgName = $null;
    hidden [string] $ProjectName = $null;
    [PSObject] $ControlSettings;
    hidden [string] $AzSKTempStatePath = (Join-Path $([Constants]::AzSKAppFolderPath) "IncrementalScan");
    hidden [string] $CAScanProgressSnapshotsContainerName = [Constants]::CAScanProgressSnapshotsContainerName;
    hidden [string] $ScanSource = $null;
    $StorageContext = $null;
	$ControlStateBlob = $null;
    $ContainerObject = $null;
    hidden [string] $IncrementalScanTimestampFile=$null;
    hidden [string] $CATempFile = $null;
    hidden [string] $MasterFilePath;
    hidden [PSObject] $ResourceTimestamps = $null;
    hidden [bool] $FirstScan = $false;
    
    IncScanHelper([string] $organizationName, [string] $projectName)
    {
        $this.OrgName = $organizationName
        $this.ProjectName = $projectName
        $this.IncrementalScanTimestampFile = $([Constants]::IncrementalScanTimeStampFile)
        $this.ScanSource = [AzSKSettings]::GetInstance().GetScanSource()
        $this.CATempFile = "CATempLocal.json"
    }
    
    hidden [datetime] GetThresholdTime([string] $rsrcName)
    {
        $latestScan = 0
        # retrieve threshold time from storage based on scan source
        if($this.ScanSource -eq 'SDL')
        {
            if(![string]::isnullorwhitespace($this.OrgName))
            {
                $this.MasterFilePath = (Join-Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrgName) $this.projectName) $this.IncrementalScanTimestampFile)
                if(Test-Path $this.MasterFilePath)	
                {
                    #file exists
                    $this.ResourceTimestamps = Get-Content $this.MasterFilePath | ConvertFrom-Json

                    if([datetime]$this.ResourceTimestamps.$rsrcName -eq 0)
                    {
                        #previous timestamps exist, but not for this resource
                        $this.FirstScan = $true
                    }
                }
                else 
                {
                    #file does not exist
                    $this.FirstScan = $true
                }
            }
        }
        elseif ($this.ScanSource -eq 'CA') 
        {
            $this.MasterFilePath = (Join-Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrgName) $this.ProjectName) $this.IncrementalScanTimestampFile)
            $tempPath = Join-Path $([Constants]::AzSKAppFolderPath) $this.CATempFile
            $blobPath = Join-Path (Join-Path (Join-Path "IncrementalScan" $this.OrgName) $this.ProjectName) $this.IncrementalScanTimestampFile
            try 
            {
				#Validate if Storage is found 
				$keys = Get-AzStorageAccountKey -ResourceGroupName $env:StorageRG -Name $env:StorageName
				$this.StorageContext = New-AzStorageContext -StorageAccountName $env:StorageName -StorageAccountKey $keys[0].Value -Protocol Https
				$this.ContainerObject = Get-AzStorageContainer -Context $this.StorageContext -Name $this.CAScanProgressSnapshotsContainerName -ErrorAction SilentlyContinue 

                if($null -ne $this.ContainerObject)
				{
                    #container exists
					$this.ControlStateBlob = Get-AzStorageBlob -Container $this.CAScanProgressSnapshotsContainerName -Context $this.StorageContext -Blob $blobPath -ErrorAction SilentlyContinue 
                    if($null -ne $this.ControlStateBlob)
                    {
                        # file exists
                        #Copy existing RTF locally to handle any non ascii characters as ICloudBlob.DownloadText() was inserting non ascii charcaters
						Get-AzStorageBlobContent -CloudBlob $this.ControlStateBlob.ICloudBlob -Context $this.StorageContext -Destination $tempPath -Force                
						$this.ResourceTimestamps  = Get-ChildItem -Path $tempPath -Force | Get-Content | ConvertFrom-Json
						#Delete the local file
						Remove-Item -Path $tempPath
                        if([datetime]$this.ResourceTimestamps.$rsrcName -eq 0)
                        {
                            # First incremental scan for current resource
                            $this.FirstScan = $true
                        }
                    }
                    else 
                    {
                        #file does not exist 
                        $this.FirstScan = $true
                    }
                }
                else 
                {
                    #container does not exist
                    $this.FirstScan = $true
                }
            }
            catch
            {
                write-host "Exception when trying to find/create incremental scan container: $_."
                #$this.PublishCustomMessage("Exception when trying to find/create incremental scan container: $_.", [MessageType]::Warning);
            }
        }
        if(-not $this.FirstScan)
        {
            #$this.ResourceTimestamps = (Get-ChildItem -Path $this.MasterFilePath -Force | Get-Content | ConvertFrom-Json)
            return [datetime]$this.ResourceTimestamps.$rsrcName
        }
        return $latestScan
    }
    
    hidden UpdateTimeStamp([string] $rsrcName)
    {
        $timeStamp = (Get-Date)
        if($this.ScanSource -eq 'SDL')
        {
            if($this.FirstScan -eq $true)
            {
                #check if file exists 
                if((-not (Test-Path ($this.AzSKTempStatePath))) -or (-not (Test-Path (Join-Path $this.AzSKTempStatePath $this.OrgName))) -or (-not (Test-Path $this.MasterFilePath)))
                {
                    #Incremental Scan happening first time locally OR Incremental Scan happening first time for Org OR first time for current Project
                    New-Item -Type Directory -Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrgName) $this.ProjectName) -ErrorAction Stop | Out-Null
                    $this.ResourceTimestamps = [IncrementalScanTimestamps]::new($this.OrgName)
                    $this.ResourceTimestamps.$rsrcName = $timeStamp
                    [JsonHelper]::ConvertToJsonCustom($this.ResourceTimestamps) | Out-File $this.MasterFilePath -Force
                }
                else 
                {
                    # file exists for Organization but first time scan for current resource type
                    $this.ResourceTimestamps = Get-ChildItem -Path $this.MasterFilePath -Force | Get-Content | ConvertFrom-Json
                    $this.ResourceTimestamps.$rsrcName = $timeStamp
                    [JsonHelper]::ConvertToJsonCustom($this.ResourceTimestamps) | Out-File $this.MasterFilePath -Force    
                }
            }
            else 
            {
                #not a first time scan for the current resource
                $this.ResourceTimestamps = Get-ChildItem -Path $this.MasterFilePath -Force | Get-Content | ConvertFrom-Json
                $this.ResourceTimestamps.$rsrcName = $timeStamp
                [JsonHelper]::ConvertToJsonCustom($this.ResourceTimestamps) | Out-File $this.MasterFilePath -Force
            }
        }
        elseif ($this.ScanSource -eq 'CA') 
        {
            $tempPath = Join-Path $([Constants]::AzSKAppFolderPath) $this.CATempFile
            $blobPath = Join-Path (Join-Path (Join-Path "IncrementalScan" $this.OrgName) $this.ProjectName) $this.IncrementalScanTimestampFile
            if ($this.FirstScan -eq $true) 
            {
                #check if container object does not exist 
                if($null -eq $this.ContainerObject)
                {
                    $this.ContainerObject = New-AzStorageContainer -Name $this.CAScanProgressSnapshotsContainerName -Context $this.StorageContext -ErrorAction SilentlyContinue
					if ($null -eq $this.ContainerObject )
					{
                    	$this.PublishCustomMessage("Could not find/create partial scan container in storage.", [MessageType]::Warning);
					}
                    $this.ResourceTimestamps = [IncrementalScanTimestamps]::new($this.OrgName)
				}
                if($null -eq $this.ControlStateBlob)
                {
                    $this.ResourceTimestamps = [IncrementalScanTimestamps]::new($this.OrgName)
                }
                else 
                {
                    Get-AzStorageBlobContent -CloudBlob $this.ControlStateBlob.ICloudBlob -Context $this.StorageContext -Destination $tempPath -Force                
					$this.ResourceTimestamps  = Get-ChildItem -Path $tempPath -Force | Get-Content | ConvertFrom-Json
					#Delete the local file
                    Remove-Item -Path $tempPath

                }
                $this.ResourceTimestamps.$rsrcName = $timeStamp
                [JsonHelper]::ConvertToJsonCustom($this.ResourceTimestamps) | Out-File $tempPath -Force
                Set-AzStorageBlobContent -File $tempPath -Container $this.ContainerObject.Name -Blob $blobPath -Context $this.StorageContext -Force
                Remove-Item -Path $tempPath
            }
            else 
            {
                Get-AzStorageBlobContent -CloudBlob $this.ControlStateBlob.ICloudBlob -Context $this.StorageContext -Destination $tempPath -Force                
				$this.ResourceTimestamps  = Get-ChildItem -Path $tempPath -Force | Get-Content | ConvertFrom-Json
				#Delete the local file
                Remove-Item -Path $tempPath
                $this.ResourceTimestamps.$rsrcName = $timeStamp
                [JsonHelper]::ConvertToJsonCustom($this.ResourceTimestamps) | Out-File $tempPath -Force
                Set-AzStorageBlobContent -File $tempPath -Container $this.ContainerObject.Name -Blob $blobPath -Context $this.StorageContext -Force
                Remove-Item -Path $tempPath
            }
        }
    }
    [System.Object[]] GetModifiedBuilds($buildDefnsObj)
    {
        $latestBuildScan = $this.GetThresholdTime("Build")
        if($this.FirstScan -eq $true)
        {
            $this.UpdateTimeStamp("Build")
            return $buildDefnsObj
        }
        $newBuildDefns = @()
        if ([datetime] $buildDefnsObj[0].createdDate -lt $latestBuildScan) 
        {
            # first resource is modified before the threshold time => all consequent are also modified before threshold
            # return empty list
            return $newBuildDefns
        }
        #Binary search 
        [int] $low = 0
        [int] $high = $buildDefnsObj.length - 1
        [int] $size = $buildDefnsObj.length
        [int] $breakIndex = 0
        while($low -le $high)
        {
            [int] $mid = ($low + $high)/2
            [datetime] $modDate = [datetime]($buildDefnsObj[$mid].createdDate)
            if($modDate -ge $latestBuildScan)
            {
                # modified date is after the threshold time
                if(($mid + 1) -eq $size)
                {
                    # all fetched build defs are modified after threshold time
                    # TBD: Fetch more builds or return unmodified
                    return $buildDefnsObj
                }
                else {
                    # mid point is not the last build defn
                    if([datetime]($buildDefnsObj[$mid+1].createdDate) -lt $latestBuildScan)
                    {
                        # changing point found
                        $breakIndex = $mid
                        break
                    }
                    else 
                    {
                        $low = $mid + 1
                    }
                }
            }
            elseif ($modDate -lt $latestBuildScan) 
            {
                if($mid -eq 0)
                {
                    # All fetched builds have been modified before the threshold
                    return $newBuildDefns
                }
                else 
                {
                    if([datetime]($buildDefnsObj[$mid - 1].createdDate)  -ge $latestBuildScan)
                    {
                        $breakIndex = $mid - 1
                        break
                    }    
                    else 
                    {
                        $high = $mid - 1
                    }
                }
            }
        }
        $newBuildDefns = @($buildDefnsObj[0..$breakIndex])
        $this.UpdateTimeStamp("Build")
        return $newBuildDefns
    }
    [System.Object[]] GetModifiedReleases($releaseDefnsObj)
    {
        $latestReleaseScan = $this.GetThresholdTime("Release")
        if($this.FirstScan -eq $true)
        {
            $this.UpdateTimeStamp("Release")
            return $releaseDefnsObj
        }
        $newReleaseDefns = @()
        # Searching Linearly
        foreach ($releaseDefn in $releaseDefnsObj)
        {
            if ([datetime]($releaseDefn.modifiedOn)  -ge $latestReleaseScan) 
            {
                $newReleaseDefns += @($releaseDefn)    
            }
        }
        $this.UpdateTimeStamp("Release")
        return $newReleaseDefns                
    }
}