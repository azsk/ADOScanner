Set-StrictMode -Version Latest 

class IncrementalScanHelper
{
    hidden [string] $OrganizationName = $null;
    hidden [string] $ProjectName = $null;
    hidden [string] $ProjectId = $null;
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
    hidden [datetime] $IncrementalDate = 0;
    [bool] $UpdateTime = $true;
    hidden [datetime] $Timestamp = 0; 
    [bool] $isPartialScanActive = $false;
    
    IncrementalScanHelper([string] $organizationName, [string] $projectName, [datetime] $incrementalDate, [bool] $updateTimestamp, [datetime] $timestamp)
    {
        $this.OrganizationName = $organizationName
        $this.ProjectName = $projectName
        $this.IncrementalScanTimestampFile = $([Constants]::IncrementalScanTimeStampFile)
        $this.ScanSource = [AzSKSettings]::GetInstance().GetScanSource()
        $this.CATempFile = "CATempLocal.json" # temporary file to store Json Data to upload to container (in CA)
        $this.IncrementalDate = $incrementalDate
        $this.MasterFilePath = (Join-Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrganizationName) $this.projectName) $this.IncrementalScanTimestampFile)
        $this.UpdateTime = $updateTimestamp
        $this.Timestamp = $timestamp
        if($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("UsePartialCommits")){
            [PartialScanManager] $partialScanMngr = [PartialScanManager]::GetInstance();
            if(($partialScanMngr.IsPartialScanInProgress($this.OrganizationName, $false) -eq [ActiveStatus]::Yes)){
                $this.isPartialScanActive = $true
            }
        }        
    }
    IncrementalScanHelper([string] $organizationName, [string] $projectId,[string] $projectName, [datetime] $incrementalDate)
    {
        $this.OrganizationName = $organizationName
        $this.ProjectId = $projectId
        $this.IncrementalScanTimestampFile = $([Constants]::IncrementalScanTimeStampFile)
        $this.ScanSource = [AzSKSettings]::GetInstance().GetScanSource()
        $this.CATempFile = "CATempLocal.json" # temporary file to store Json Data to upload to container (in CA)
        $this.IncrementalDate = $incrementalDate
        $this.ProjectName = $projectName 
        $this.MasterFilePath = (Join-Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrganizationName) $this.projectName) $this.IncrementalScanTimestampFile)
        $this.ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
               
    }
    hidden [datetime] GetThresholdTime([string] $resourceType)
    {
        # function to retrieve threshold time from storage, based on scan source.
        $latestScan = 0
        if($this.ScanSource -ne "CA" -and $this.ScanSource -ne "CICD")
        {
            if(![string]::isnullorwhitespace($this.OrganizationName))
            {
                if(Test-Path $this.MasterFilePath)	
                {
                    # File exists. Retrieve last timestamp.
                    $this.ResourceTimestamps = Get-Content $this.MasterFilePath | ConvertFrom-Json

                    if([datetime]$this.ResourceTimestamps.$resourceType -eq 0)
                    {
                        # Previous timestamp does not exist for this resource in the existing file.
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
            $this.MasterFilePath = (Join-Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrganizationName) $this.ProjectName) $this.IncrementalScanTimestampFile)
            $tempPath = Join-Path $([Constants]::AzSKAppFolderPath) $this.CATempFile
            $blobPath = Join-Path (Join-Path (Join-Path "IncrementalScan" $this.OrganizationName) $this.ProjectName) $this.IncrementalScanTimestampFile
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
                        # File exists. Copy existing timestamp file locally 
						Get-AzStorageBlobContent -CloudBlob $this.ControlStateBlob.ICloudBlob -Context $this.StorageContext -Destination $tempPath -Force                
						$this.ResourceTimestamps  = Get-ChildItem -Path $tempPath -Force | Get-Content | ConvertFrom-Json
						#Delete the local file
						Remove-Item -Path $tempPath
                        if([datetime]$this.ResourceTimestamps.$resourceType -eq 0)
                        {
                            # Previous timestamp does not exist for current resource in existing file.
                            $this.FirstScan = $true
                        }
                    }
                    else 
                    {
                        # File does not exist. 
                        $this.FirstScan = $true
                    }
                }
                else 
                {
                    # Container does not exist
                    $this.FirstScan = $true
                }
            }
            catch
            {
                write-host "Exception when trying to find/create incremental scan container: $_."
            }
        }
        if(-not $this.FirstScan)
        {
            if($this.isPartialScanActive){
                if($resourceType -eq 'Build'){
                    $latestScan = [datetime]$this.ResourceTimestamps.BuildPreviousTime
                }
                else {
                    $latestScan = [datetime]$this.ResourceTimestamps.ReleasePreviousTime
                }
            }
            else {
                $latestScan = [datetime]$this.ResourceTimestamps.$resourceType
            }
            
        }
        if($this.IncrementalDate -ne 0)
        {
            # user input of incremental date to be used for scanning incrementally.
            $latestScan = $this.IncrementalDate
            if($this.ScanSource -eq 'CA'){
                $FromTimeZone = [System.TimeZoneInfo]::FindSystemTimeZoneById("Asia/Kolkata")
                $latestScan = [DateTime]::SpecifyKind((Get-Date $latestScan), [DateTimeKind]::Unspecified)
                $latestScan = [System.TimeZoneInfo]::ConvertTimeToUtc($latestScan, $FromTimeZone)

            }
        }
        return $latestScan
    }
    
    UpdateTimeStamp([string] $resourceType)
    {
        # Updates timestamp of current scan to storage, based on scan source.
        if($this.UpdateTime -ne $true)
        {
            return;
        }
        if($this.isPartialScanActive){
            return;
        }
        if($this.ScanSource -ne "CA" -and $this.ScanSource -ne "CICD")
        {
            if($this.FirstScan -eq $true)
            {
                # Check if file exists 
                if((-not (Test-Path ($this.AzSKTempStatePath))) -or (-not (Test-Path (Join-Path $this.AzSKTempStatePath $this.OrganizationName))) -or (-not (Test-Path $this.MasterFilePath)))
                {
                    # Incremental Scan happening first time locally OR Incremental Scan happening first time for Org OR first time for current Project
                    New-Item -Type Directory -Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrganizationName) $this.ProjectName) -ErrorAction Stop | Out-Null
                    $this.ResourceTimestamps = [IncrementalScanTimestamps]::new()
                    $this.ResourceTimestamps.$resourceType = $this.Timestamp
                    [JsonHelper]::ConvertToJsonCustom($this.ResourceTimestamps) | Out-File $this.MasterFilePath -Force
                }
                else 
                {
                    # File exists for Organization and Project but first time scan for current resource type
                    $this.ResourceTimestamps = Get-ChildItem -Path $this.MasterFilePath -Force | Get-Content | ConvertFrom-Json
                    $this.ResourceTimestamps.$resourceType = $this.Timestamp
                    if($resourceType -eq 'Build'){
                        if('BuildPreviousTime' -in $this.ResourceTimestamps.PSobject.Properties.Name){
                            $this.ResourceTimestamps.BuildPreviousTime = "0001-01-01T00:00:00.0000000";
                        }     
                        else {
                            $this.ResourceTimestamps | Add-Member -NotePropertyName BuildPreviousTime -NotePropertyValue "0001-01-01T00:00:00.0000000"
                        }             
                        
                    }
                    else{
                        if('ReleasePreviousTime' -in $this.ResourceTimestamps.PSobject.Properties.Name){
                            $this.ResourceTimestamps.ReleasePreviousTime = "0001-01-01T00:00:00.0000000";
                        }     
                        else {
                            $this.ResourceTimestamps | Add-Member -NotePropertyName ReleasePreviousTime -NotePropertyValue "0001-01-01T00:00:00.0000000"
                        } 
                    }
                    [JsonHelper]::ConvertToJsonCustom($this.ResourceTimestamps) | Out-File $this.MasterFilePath -Force    
                }
            }
            else 
            {
                # Not a first time scan for the current resource
                $this.ResourceTimestamps = Get-ChildItem -Path $this.MasterFilePath -Force | Get-Content | ConvertFrom-Json
                $previousScanTime = $this.ResourceTimestamps.$resourceType;
                if($resourceType -eq 'Build'){
                    if('BuildPreviousTime' -in $this.ResourceTimestamps.PSobject.Properties.Name){
                        $this.ResourceTimestamps.BuildPreviousTime = $previousScanTime;
                    }     
                    else {
                        $this.ResourceTimestamps | Add-Member -NotePropertyName BuildPreviousTime -NotePropertyValue $previousScanTime
                    }             
                    
                }
                else{
                    if('ReleasePreviousTime' -in $this.ResourceTimestamps.PSobject.Properties.Name){
                        $this.ResourceTimestamps.ReleasePreviousTime = $previousScanTime;
                    }     
                    else {
                        $this.ResourceTimestamps | Add-Member -NotePropertyName ReleasePreviousTime -NotePropertyValue $previousScanTime
                    } 
                }
                $this.ResourceTimestamps.$resourceType = $this.Timestamp
                [JsonHelper]::ConvertToJsonCustom($this.ResourceTimestamps) | Out-File $this.MasterFilePath -Force
            }
        }
        elseif ($this.ScanSource -eq 'CA') 
        {
            $tempPath = Join-Path $([Constants]::AzSKAppFolderPath) $this.CATempFile
            $blobPath = Join-Path (Join-Path (Join-Path "IncrementalScan" $this.OrganizationName) $this.ProjectName) $this.IncrementalScanTimestampFile
            if ($this.FirstScan -eq $true) 
            {
                # Check if container object does not exist 
                if($null -eq $this.ContainerObject)
                {
                    # Container does not exist, create container.
                    $this.ContainerObject = New-AzStorageContainer -Name $this.CAScanProgressSnapshotsContainerName -Context $this.StorageContext -ErrorAction SilentlyContinue
					if ($null -eq $this.ContainerObject )
					{
                    	$this.PublishCustomMessage("Could not find/create partial scan container in storage.", [MessageType]::Warning);
					}
                    $this.ResourceTimestamps = [IncrementalScanTimestamps]::new()
				}
                if($null -eq $this.ControlStateBlob)
                {
                    $this.ResourceTimestamps = [IncrementalScanTimestamps]::new()
                }
                else 
                {
                    Get-AzStorageBlobContent -CloudBlob $this.ControlStateBlob.ICloudBlob -Context $this.StorageContext -Destination $tempPath -Force                
					$this.ResourceTimestamps  = Get-ChildItem -Path $tempPath -Force | Get-Content | ConvertFrom-Json
					#Delete the local file
                    Remove-Item -Path $tempPath

                }
                $this.ResourceTimestamps.$resourceType = $this.Timestamp
                if($resourceType -eq 'Build'){
                    if('BuildPreviousTime' -in $this.ResourceTimestamps.PSobject.Properties.Name){
                        $this.ResourceTimestamps.BuildPreviousTime = "0001-01-01T00:00:00.0000000";
                    }     
                    else {
                        $this.ResourceTimestamps | Add-Member -NotePropertyName BuildPreviousTime -NotePropertyValue "0001-01-01T00:00:00.0000000"
                    }             
                    
                }
                else{
                    if('ReleasePreviousTime' -in $this.ResourceTimestamps.PSobject.Properties.Name){
                        $this.ResourceTimestamps.ReleasePreviousTime = "0001-01-01T00:00:00.0000000";
                    }     
                    else {
                        $this.ResourceTimestamps | Add-Member -NotePropertyName ReleasePreviousTime -NotePropertyValue "0001-01-01T00:00:00.0000000"
                    } 
                }
                [JsonHelper]::ConvertToJsonCustom($this.ResourceTimestamps) | Out-File $tempPath -Force
                Set-AzStorageBlobContent -File $tempPath -Container $this.ContainerObject.Name -Blob $blobPath -Context $this.StorageContext -Force
                Remove-Item -Path $tempPath
            }
            else 
            {
                Get-AzStorageBlobContent -CloudBlob $this.ControlStateBlob.ICloudBlob -Context $this.StorageContext -Destination $tempPath -Force                
				$this.ResourceTimestamps  = Get-ChildItem -Path $tempPath -Force | Get-Content | ConvertFrom-Json
                $previousScanTime = $this.ResourceTimestamps.$resourceType;
                if($resourceType -eq 'Build'){
                    if('BuildPreviousTime' -in $this.ResourceTimestamps.PSobject.Properties.Name){
                        $this.ResourceTimestamps.BuildPreviousTime = $previousScanTime;
                    }     
                    else {
                        $this.ResourceTimestamps | Add-Member -NotePropertyName BuildPreviousTime -NotePropertyValue $previousScanTime
                    }             
                    
                }
                else{
                    if('ReleasePreviousTime' -in $this.ResourceTimestamps.PSobject.Properties.Name){
                        $this.ResourceTimestamps.ReleasePreviousTime = $previousScanTime;
                    }     
                    else {
                        $this.ResourceTimestamps | Add-Member -NotePropertyName ReleasePreviousTime -NotePropertyValue $previousScanTime
                    } 
                }
				# Delete the local file
                Remove-Item -Path $tempPath
                $this.ResourceTimestamps.$resourceType = $this.Timestamp
                [JsonHelper]::ConvertToJsonCustom($this.ResourceTimestamps) | Out-File $tempPath -Force
                Set-AzStorageBlobContent -File $tempPath -Container $this.ContainerObject.Name -Blob $blobPath -Context $this.StorageContext -Force
                Remove-Item -Path $tempPath
            }
        }
    }
    [System.Object[]] GetModifiedBuilds($buildDefnsObj)
    {
        # Function to filter builds that have been modified after threshold time
        $latestBuildScan = $this.GetThresholdTime("Build")
        if($this.FirstScan -eq $true -and $this.IncrementalDate -eq 0)
        {
            $this.UpdateTimeStamp("Build")
            return $buildDefnsObj
        }
        if($this.isPartialScanActive -and $latestBuildScan -eq 0){
            return $buildDefnsObj
        }
        $newBuildDefns = @()
        if ([datetime] $buildDefnsObj[0].createdDate -lt $latestBuildScan) 
        {
            # first resource is modified before the threshold time => all consequent are also modified before threshold
            # return empty list
            $this.UpdateTimeStamp("Build")
            return $newBuildDefns
        }
        #Binary search 
        [int] $low = 0 # start index of array
        [int] $high = $buildDefnsObj.length - 1 # last index of array
        [int] $size = $buildDefnsObj.length # total length of array 
        [int] $breakIndex = 0
        while($low -le $high)
        {
            [int] $mid = ($low + $high)/2 # seeking the middle of the array 
            [datetime] $modifiedDate = [datetime]($buildDefnsObj[$mid].createdDate)
            if($modifiedDate -ge $latestBuildScan)
            {
                # modified date is after the threshold time
                if(($mid + 1) -eq $size)
                {
                    # all fetched build defs are modified after threshold time
                    # return unmodified
                    $this.UpdateTimeStamp("Build")
                    return $buildDefnsObj
                }
                else 
                {
                    # mid point is not the last build defn
                    if([datetime]($buildDefnsObj[$mid+1].createdDate) -lt $latestBuildScan)
                    {
                        # changing point found
                        $breakIndex = $mid
                        break
                    }
                    else 
                    {
                        # search on right half
                        $low = $mid + 1
                    }
                }
            }
            elseif ($modifiedDate -lt $latestBuildScan) 
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
                        # changing point found
                        $breakIndex = $mid - 1
                        break
                    }    
                    else 
                    {
                        # search on left half
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
        if($this.FirstScan -eq $true -and $this.IncrementalDate -eq 0)
        {
            $this.UpdateTimeStamp("Release")
            return $releaseDefnsObj
        }
        if($this.isPartialScanActive -and $latestReleaseScan -eq 0){
            return $releaseDefnsObj
        }
        $newReleaseDefns = @()
        # Searching Linearly
        foreach ($releaseDefn in $releaseDefnsObj)
        {
            if ([datetime]($releaseDefn.modifiedOn) -ge $latestReleaseScan) 
            {
                $newReleaseDefns += @($releaseDefn)    
            }
        }
        $this.UpdateTimeStamp("Release")
        return $newReleaseDefns                
    }

    [System.Object[]] GetAuditTrailsForBuilds(){
        $latestBuildScan = $this.GetThresholdTime("Build")
        if($this.ScanSource -ne 'CA'){
            $latestBuildScan=$latestBuildScan.ToUniversalTime();
        }        
        $latestBuildScan =Get-Date $latestBuildScan -Format s
        $buildIds = @();
        if($this.FirstScan -eq $true -and $this.IncrementalDate -eq 0){
            return $buildIds;   
        }
        $auditUrl = "https://auditservice.dev.azure.com/{0}/_apis/audit/auditlog?startTime={1}&api-version=6.0-preview.1" -f $this.OrganizationName, $latestBuildScan
        try {
            $response = [WebRequestHelper]::InvokeGetWebRequest($auditUrl);
            $auditTrails = $response.decoratedAuditLogEntries;
            $modifiedBuilds = $auditTrails | Where-Object {$_.actionId  -eq 'Security.ModifyPermission' -and $_.data.NamespaceName -eq 'Build' -and $_.data.Token -match $this.ProjectId+"/" }
            $restrictedBroaderGroups = @{}
            $broaderGroups = $this.ControlSettings.Build.RestrictedBroaderGroupsForBuild
            $broaderGroups.psobject.properties | foreach { $restrictedBroaderGroups[$_.Name] = $_.Value }
            $modifiedBuilds | foreach {
                $group = ($_.data.SubjectDisplayName -split("\\"))[1]
                if($group -in $restrictedBroaderGroups.keys ){
                    if($_.data.ChangedPermission -in $restrictedBroaderGroups[$group]){
                        $buildIds += (($_.data.Token -split("/"))[1])
                    }
                }
            }
            $buildIds = $buildIds | Select -Unique
        }
        catch {

        }
        return $buildIds;
    }
    
    [System.Object[]] GetModifiedBuildsFromAudit($buildIds, $projectName){
        $totalBuilds = $buildIds.Count
        $buildDefnObj =@()
        $newBuildDefns = @();
        $queryIdCount = 0;
        $currentbuildIds = ""
        $buildIds | foreach {
            
            if($totalBuilds -lt 100){
                $queryIdCount++;
                $currentbuildIds=$currentbuildIds+$_+","
                if($queryIdCount -eq $totalBuilds){
                    $buildDefnURL = "https://{0}.visualstudio.com/{1}/_apis/build/definitions?definitionIds={2}&api-version=6.0" -f $($this.OrganizationName), $projectName, $currentbuildIds;
                    try {
                        $buildDefnObj += ([WebRequestHelper]::InvokeGetWebRequest($buildDefnURL));
                    }
                    catch {

                    }
                }
            }
            else {
                $queryIdCount++;
                $currentbuildIds=$currentbuildIds+$_+",";
                if($queryIdCount -eq 100){
                    $buildDefnURL = "https://{0}.visualstudio.com/{1}/_apis/build/definitions?definitionIds={2}&api-version=6.0" -f $($this.OrganizationName), $projectName, $currentbuildIds;
                    try {
                        $buildDefnObj += ([WebRequestHelper]::InvokeGetWebRequest($buildDefnURL));
                        $queryIdCount =0;
                        $currentbuildIds="";
                        $totalBuilds -=100;                        
                    }
                    catch {

                    }
                }

            }
        }
        $latestBuildScan = $this.GetThresholdTime("Build");              
        foreach ($buildDefn in $buildDefnObj)
        {
            if ([datetime]($buildDefn.CreatedDate) -lt $latestBuildScan) 
            {
                $newBuildDefns += @($buildDefn)    
            }
        }
     
        return $newBuildDefns;
    }

    [System.Object[]] GetAuditTrailsForReleases(){
        $latestReleaseScan = $this.GetThresholdTime("Release");
        if($this.ScanSource -ne 'CA'){
            $latestReleaseScan=$latestReleaseScan.ToUniversalTime();
        }
        $latestReleaseScan = Get-Date $latestReleaseScan -Format s
        $releaseIds = @();
        if($this.FirstScan -eq $true -and $this.IncrementalDate -eq 0){
            return $releaseIds;   
        }
        $auditUrl = "https://auditservice.dev.azure.com/{0}/_apis/audit/auditlog?startTime={1}&api-version=6.0-preview.1" -f $this.OrganizationName, $latestReleaseScan
        try {
            $response = [WebRequestHelper]::InvokeGetWebRequest($auditUrl);
            $auditTrails = $response.decoratedAuditLogEntries;
            $modifiedReleases = $auditTrails | Where-Object {$_.actionId  -eq 'Security.ModifyPermission' -and $_.data.NamespaceName -eq 'ReleaseManagement' -and $_.data.Token -match $this.ProjectId+"/" }
            $restrictedBroaderGroups = @{}
            $broaderGroups = $this.ControlSettings.Release.RestrictedBroaderGroupsForRelease
            $broaderGroups.psobject.properties | foreach { $restrictedBroaderGroups[$_.Name] = $_.Value }
            $modifiedReleases| foreach {
                $group = ($_.data.SubjectDisplayName -split("\\"))[1]
                if($group -in $restrictedBroaderGroups.keys ){
                    if($_.data.ChangedPermission -in $restrictedBroaderGroups[$group]){
                        $releaseIds += (($_.data.Token -split("/"))[1])
                    }
                }
            }
            $releaseIds = $releaseIds | Select -Unique
        }
        catch {

        }
        return $releaseIds;
    }
    
    [System.Object[]] GetModifiedReleasesFromAudit($releaseIds, $projectName){
        $totalReleases = $releaseIds.Count
        $newReleaseDefns = @();
        $releaseDefnObj =@()
        $queryIdCount = 0;
        $currentReleaseIds = ""
        $releaseIds | foreach {
            
            if($totalReleases -lt 100){
                $queryIdCount++;
                $currentReleaseIds=$currentReleaseIds+$_+","
                if($queryIdCount -eq $totalReleases){
                    $releaseDefnURL = "https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?definitionIdFilter={2}&api-version=6.0" -f $($this.OrganizationName), $projectName, $currentReleaseIds;
                    try {
                        $releaseDefnObj += ([WebRequestHelper]::InvokeGetWebRequest($releaseDefnURL));
                    }
                    catch {

                    }
                }
            }
            else {
                $queryIdCount++;
                $currentReleaseIds=$currentReleaseIds+$_+",";
                if($queryIdCount -eq 100){
                    $releaseDefnURL = "https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?definitionIdFilter={2}&api-version=6.0" -f $($this.OrganizationName), $projectName, $currentReleaseIds;
                    try {
                        $releaseDefnObj += ([WebRequestHelper]::InvokeGetWebRequest($releaseDefnURL));
                        $queryIdCount =0;
                        $currentReleaseIds="";
                        $totalReleases -=100;                        
                    }
                    catch {

                    }
                }

            }
        }   
        $latestReleaseScan = $this.GetThresholdTime("Release");              
        foreach ($releaseDefn in $releaseDefnObj)
        {
            if ([datetime]($releaseDefn.modifiedOn) -lt $latestReleaseScan) 
            {
                $newReleaseDefns += @($releaseDefn)    
            }
        }       
      
        return $newReleaseDefns;
    }

}