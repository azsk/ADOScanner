Set-StrictMode -Version Latest

class BatchScanManager 
{
    hidden [string] $OrgName = $null;
	hidden [string] $ProjectName = $null;
    [PSObject] $ControlSettings;
    hidden [string] $BatchScanTrackerFileName=$null;
    hidden [string] $AzSKTempStatePath = (Join-Path $([Constants]::AzSKAppFolderPath) "TempState" | Join-Path -ChildPath "BatchScanData");
    hidden [string] $MasterFilePath;
    hidden [PSObject] $BatchScanTrackerObj = $null;
    hidden [PSObject] $ScanPendingForBatch = $null;
    hidden static [BatchScanManager] $Instance =$null;
    hidden [int] $BatchSize = 0;
    hidden [bool] $isUpdated = $false;

    static [BatchScanManager] GetInstance( [string] $OrganizationName,[string] $ProjectName)
    {
        if ( $null -eq  [BatchScanManager]::Instance)
        {
			[BatchScanManager]::Instance = [BatchScanManager]::new($OrganizationName,$ProjectName);
		}
		[BatchScanManager]::Instance.OrgName = $OrganizationName;
        [BatchScanManager]::Instance.ProjectName = $ProjectName;
        return [BatchScanManager]::Instance
    }
    static [BatchScanManager] GetInstance()
    {
        if ( $null -eq  [BatchScanManager]::Instance)
        {
            [BatchScanManager]::Instance = [BatchScanManager]::new();
        }
        return [BatchScanManager]::Instance
    }
	static [void] ClearInstance()
    {
       [BatchScanManager]::Instance = $null
    }
    BatchScanManager([string] $OrganizationName,[string] $ProjectName){
        $this.ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
		$this.OrgName = $OrganizationName;
        $this.ProjectName=$ProjectName;
        if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("BatchSize")){
            $this.BatchSize = $PSCmdlet.MyInvocation.BoundParameters["BatchSize"]
        }
        else {
            $this.BatchSize = $this.ControlSettings.BatchScan.BatchTrackerUpdateFrequency
        }
        if($PSCmdlet.MyInvocation.BoundParameters.ResourceTypeName -eq "Build_Release"){
            
            $this.BatchSize=$this.BatchSize/2;
        }
        if ([string]::isnullorwhitespace($this.BatchScanTrackerFileName))
        {              
			$this.BatchScanTrackerFileName = [Constants]::BatchScanTrackerBlobName		   
        }
		$this.GetBatchScanTrackerObject();
    }
    BatchScanManager()
	{
		$this.ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
		if ([string]::isnullorwhitespace($this.BatchScanTrackerFileName))
        {
			$this.BatchScanTrackerFileName =  [Constants]::BatchScanTrackerBlobName
        }
		$this.GetBatchScanTrackerObject();
	}

    [int] GetBatchSize()
    {
        return $this.BatchSize
    }

    hidden [void] GetBatchScanTrackerObject(){
        if(![string]::isnullorwhitespace($this.OrgName) -and ![string]::isnullorwhitespace($this.ProjectName)){
            if(-not (Test-Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrgName) $this.ProjectName)))
            {
                New-Item -ItemType Directory -Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrgName) $this.ProjectName) -ErrorAction Stop | Out-Null
            }
        }
        else{
            if(-not (Test-Path "$this.AzSKTempStatePath"))
            {
                New-Item -ItemType Directory -Path "$this.AzSKTempStatePath" -ErrorAction Stop | Out-Null
            }
        }
        if($null -ne $this.MasterFilePath){
            $this.BatchScanTrackerObj = Get-content $this.MasterFilePath | ConvertFrom-Json
        }
        else {
            $this.BatchScanTrackerObj=$null;
        }
        
    }

   [PSObject] GetBatchStatus(){
        return Get-content $this.MasterFilePath | ConvertFrom-Json;
    }

    hidden [void] GetBatchTrackerFile($OrgName,$ProjectName){
        $this.OrgName=$OrgName;
        $this.ProjectName=$ProjectName;
        if(![string]::isnullorwhitespace($this.OrgName) -and ![string]::isnullorwhitespace($this.ProjectName)){
            if(Test-Path (Join-Path (Join-Path $this.AzSKTempStatePath $this.OrgName) $this.BatchScanTrackerFileName))	
            {
                $this.ScanPendingForBatch = Get-Content (Join-Path (Join-Path $this.AzSKTempStatePath (Join-Path $this.OrgName $this.ProjectName)) $this.BatchScanTrackerFileName) -Raw
            }
            $this.MasterFilePath = (Join-Path (Join-Path $this.AzSKTempStatePath (Join-Path $this.OrgName $this.ProjectName)) $this.BatchScanTrackerFileName)
        }
        else {
            $this.MasterFilePath = (Join-Path $this.AzSKTempStatePath $this.BatchScanTrackerFileName)
        }
    }
    [void] RemoveBatchScanData(){
        if($null -ne $this.BatchScanTrackerObj){
            if(![string]::isnullorwhitespace($this.OrgName) -and ![string]::isnullorwhitespace($this.ProjectName)){
                if(Test-Path (Join-Path $this.AzSKTempStatePath (Join-Path $this.OrgName $this.ProjectName)))
                {
                    Remove-Item -Path (Join-Path (Join-Path $this.AzSKTempStatePath (Join-Path $this.OrgName $this.ProjectName)) $this.BatchScanTrackerFileName)
                    
                }
            }
            $this.BatchScanTrackerObj=$null;
        }
    }
    hidden[bool] IsBatchScanInProgress($OrgName,$ProjectName){
        $this.GetBatchTrackerFile($OrgName,$ProjectName);
        if($null -ne $this.ControlSettings.BatchScan){
            $batchTrackerFileValidForDays = [Int32]::Parse($this.ControlSettings.BatchScan.BatchTrackerValidforDays);
            $this.GetBatchScanTrackerObject();
            if($null -eq $this.BatchScanTrackerObj){
                return $false;
            }
            if( (Get-Item $this.MasterFilePath).creationtime.AddDays($batchTrackerFileValidforDays) -lt [DateTime]::UtcNow)
			{
				$this.RemoveBatchScanData();
				$this.ScanPendingForBatch = $null;
				return $false;
			}
			return $true;

        }
        else {
            $this.ScanPendingForBatch=$null;
            return $false;
        }
        return $true;
    }

    [void] CreateBatchMasterList(){
        $batchStatus = [BatchScanResourceMap]@{
            Skip = 0;
            Top = $this.GetBatchSize();
            BuildCurrentContinuationToken=$null;
            BuildNextContinuationToken=$null;
            ReleaseCurrentContinuationToken=$null;
            ReleaseNextContinuationToken=$null;
            BatchScanState= [BatchScanState]::INIT;
            LastModifiedTime = [DateTime]:: UtcNow;
            ResourceCount=0;
            SkipMarker = 'False'
           
        }
        if($PSCmdlet.MyInvocation.BoundParameters.ResourceTypeName -eq "Build"){
            $batchStatus = $batchStatus | Select-Object -Property * -ExcludeProperty ReleaseCurrentContinuationToken
            $batchStatus = $batchStatus | Select-Object -Property * -ExcludeProperty ReleaseNextContinuationToken 
            $batchStatus = $batchStatus | Select-Object -Property * -ExcludeProperty SkipMarker 
                  
        }
        if($PSCmdlet.MyInvocation.BoundParameters.ResourceTypeName -eq "Release"){
            $batchStatus = $batchStatus | Select-Object -Property * -ExcludeProperty BuildCurrentContinuationToken 
            $batchStatus = $batchStatus | Select-Object -Property * -ExcludeProperty BuildNextContinuationToken
            $batchStatus = $batchStatus | Select-Object -Property * -ExcludeProperty SkipMarker             
            
        }
        $this.BatchScanTrackerObj=$batchStatus;
        $this.WriteToBatchTrackerFile()
        
    }

    [void] WriteToBatchTrackerFile() {
        if($null -ne $this.BatchScanTrackerObj){
            if(![string]::isnullorwhitespace($this.OrgName) -and ![string]::isnullorwhitespace($this.ProjectName)){
                if(-not (Test-Path (Join-Path $this.AzSKTempStatePath (Join-Path $this.OrgName $this.ProjectName))))
                {
                    New-Item -ItemType Directory -Path (Join-Path $this.AzSKTempStatePath (Join-Path $this.OrgName $this.ProjectName)) -ErrorAction Stop | Out-Null
                }	
            }
            else{
                if(-not (Test-Path "$this.AzSKTempStatePath"))
                {
                    New-Item -ItemType Directory -Path "$this.AzSKTempStatePath" -ErrorAction Stop | Out-Null
                }
            }
            Write-Host "Updating batch tracker file" -ForegroundColor Green
           [JsonHelper]::ConvertToJsonCustom( $this.BatchScanTrackerObj) | Out-File $this.MasterFilePath -Force
            Write-Host "Batch tracker file updated" -ForegroundColor Green
            
        }
    }

    [bool] isPreviousScanPartiallyComplete(){
        if(![string]::isnullorwhitespace($this.OrgName) -and ![string]::isnullorwhitespace($this.ProjectName)){
            if( ($null -ne $this.MasterFilePath) -and (Test-Path $this.MasterFilePath)){
                $batchStatus = Get-Content $this.MasterFilePath | ConvertFrom-Json
                if($batchStatus.Skip -ne 0 -and [string]::IsNullOrEmpty($batchStatus.ReleaseNextContinuationToken) -and $batchStatus.BatchScanState -eq [BatchScanState]::COMP) {
                   return $true;
                    
                }
                if($batchStatus.Skip -ne 0 -and [string]::IsNullOrEmpty($batchStatus.BuildNextContinuationToken) -and $batchStatus.BatchScanState -eq [BatchScanState]::COMP) {
                    return $true;
                }
                if($batchStatus.Skip -ne 0 -and [string]::IsNullOrEmpty($batchStatus.ReleaseNextContinuationToken) -and [string]::IsNullOrEmpty($batchStatus.ReleaseCurrentContinuationToken)) {
                    return $true;
                     
                }
                 if($batchStatus.Skip -ne 0 -and [string]::IsNullOrEmpty($batchStatus.BuildNextContinuationToken) -and [string]::IsNullOrEmpty($batchStatus.BuildCurrentContinuationToken)) {
                     return $true;
                }

            }
        }
        return $false;
    }

    [void] UpdateBatchMasterList(){
        if(![string]::isnullorwhitespace($this.OrgName) -and ![string]::isnullorwhitespace($this.ProjectName)){
            if(Test-Path $this.MasterFilePath){
                $batchStatus = Get-Content $this.MasterFilePath | ConvertFrom-Json
                $isReleaseScan=$false;
                $isBuildScan=$false;
                if($batchStatus.PSobject.Properties.name -match "ReleaseCurrentContinuationToken") {
                    $isReleaseScan=$true;
                }
                if($batchStatus.PSobject.Properties.name -match "BuildCurrentContinuationToken") {
                    $isBuildScan=$true;
                }
                if($batchStatus.BatchScanState -eq [BatchScanState]:: INIT ){
                    if($batchStatus.Skip -eq 0){
                        if($isReleaseScan) {
                            $batchStatus.ReleaseCurrentContinuationToken=$null;
                        }
                        if($isBuildScan) {
                            $batchStatus.BuildCurrentContinuationToken=$null;
                        }
                        
                        Write-Host "Found a previous batch scan with no scanned builds. Continuing the scan from start `n " -ForegroundColor Green
                        
                    }
                    else
                    {
                        if($PSCmdlet.MyInvocation.BoundParameters.ResourceTypeName -eq 'Build_Release' -and $this.isPreviousScanPartiallyComplete() ){
                            if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("BatchSize")){
                                $this.BatchSize = $PSCmdlet.MyInvocation.BoundParameters["BatchSize"]
                            }
                            else {
                                $this.BatchSize = $this.ControlSettings.BatchScan.BatchTrackerUpdateFrequency
                            }
                        }
                        Write-Host "Found a previous batch scan in progress with $($batchStatus.ResourceCount) resources scanned. Continuing the scan for the last $($batchStatus.Top) resources from previous batch. `n " -ForegroundColor Green
                        
                        if($this.CheckContTokenValidity($batchStatus.LastModifiedTime)){
                            return;
                        }
                        else {
                            if($isBuildScan -and $batchStatus.Skip -ne 0 -and (-not [string]::IsNullOrEmpty($batchStatus.BuildCurrentContinuationToken))){
                                $batchStatus.BuildCurrentContinuationToken=$this.GetUpdatedContToken($batchStatus.Skip,$batchStatus.Top,'Build');
                            }
                            if($isReleaseScan -and $batchStatus.Skip -ne 0 -and (-not [string]::IsNullOrEmpty($batchStatus.ReleaseCurrentContinuationToken))){
                                $batchStatus.ReleaseCurrentContinuationToken=$this.GetUpdatedContToken($batchStatus.Skip,$batchStatus.Top,'Release');
                            }
                            
                            $batchStatus.LastModifiedTime=[DateTime]::UtcNow;
                        }
                    }
                }
                else {
                    if($PSCmdlet.MyInvocation.BoundParameters.ResourceTypeName -eq 'Build_Release' -and $this.isPreviousScanPartiallyComplete() ){
                        if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("BatchSize")){
                            $this.BatchSize = $PSCmdlet.MyInvocation.BoundParameters["BatchSize"]
                        }
                        else {
                            $this.BatchSize = $this.ControlSettings.BatchScan.BatchTrackerUpdateFrequency
                        }
                    }
                    Write-Host "Found a previous batch scan with $($batchStatus.ResourceCount) resources scanned. Starting fresh scan for the next batch of $($batchStatus.Top) resources. `n " -ForegroundColor Green
                    if($PSCmdlet.MyInvocation.BoundParameters.ResourceTypeName -eq 'Build_Release' -and $batchStatus.SkipMarker -eq "False" -and $this.isPreviousScanPartiallyComplete() ){
                        
                        $batchStatus.Skip=$batchStatus.Skip + ($this.GetBatchSize()/2);
                        $batchStatus.SkipMarker = "True"
                    }
                    else {
                        $batchStatus.Skip+=$this.GetBatchSize();
                    }
                    
                    
                    
                    $batchStatus.BatchScanState=[BatchScanState]::INIT
                    
                    if($this.CheckContTokenValidity($batchStatus.LastModifiedTime)){
                        
                        if($isReleaseScan) {
                            $batchStatus.ReleaseCurrentContinuationToken=$batchStatus.ReleaseNextContinuationToken
                        }
                        if($isBuildScan){
                            $batchStatus.BuildCurrentContinuationToken=$batchStatus.BuildNextContinuationToken
                        }
                        
                    }
                    else {
                        if($isBuildScan -and $batchStatus.Skip -ne 0 -and (-not [string]::IsNullOrEmpty($batchStatus.BuildNextContinuationToken))){
                            $batchStatus.BuildCurrentContinuationToken=$this.GetUpdatedContToken($batchStatus.Skip,$batchStatus.Top,'Build');
                        }
                        if($isReleaseScan -and $batchStatus.Skip -ne 0 -and (-not [string]::IsNullOrEmpty($batchStatus.ReleaseNextContinuationToken))){
                            $batchStatus.ReleaseCurrentContinuationToken=$this.GetUpdatedContToken($batchStatus.Skip,$batchStatus.Top,'Release');
                        }
                        if($isBuildScan -and $batchStatus.Skip -ne 0 -and [string]::IsNullOrEmpty($batchStatus.BuildNextContinuationToken)){
                            $batchStatus.BuildCurrentContinuationToken=$batchStatus.BuildNextContinuationToken
                        }
                        if($isReleaseScan -and $batchStatus.Skip -ne 0 -and [string]::IsNullOrEmpty($batchStatus.ReleaseNextContinuationToken)){
                            $batchStatus.ReleaseCurrentContinuationToken=$batchStatus.ReleaseNextContinuationToken
                        }
                       
                        $batchStatus.LastModifiedTime=[DateTime]::UtcNow;
                        
                    }
                   
                }
                $this.BatchScanTrackerObj=$batchStatus;
                $this.WriteToBatchTrackerFile();
            }
        }
       
    }

    hidden [bool] CheckContTokenValidity([DateTime] $lastModifiedTime){
       
        if($lastModifiedTime.AddHours([INT32]::Parse(12)) -lt [DateTime]::UtcNow){
            return $false
        }
        return $true;

    }

    [string] GetSkip(){
        if(![string]::isnullorwhitespace($this.OrgName) -and ![string]::isnullorwhitespace($this.ProjectName)){
            if(Test-Path $this.MasterFilePath){
                $batchStatus = Get-Content $this.MasterFilePath | ConvertFrom-Json
                return $batchStatus.Skip;
            }
        }
        return $null;
    }

    [string] GetTop(){
        if(![string]::isnullorwhitespace($this.OrgName) -and ![string]::isnullorwhitespace($this.ProjectName)){
            if(Test-Path $this.MasterFilePath){
                $batchStatus = Get-Content $this.MasterFilePath | ConvertFrom-Json
                return $batchStatus.Top;
            }
        }
        return $null;
    }

    [string] GetBuildContinuationToken(){
        if(![string]::isnullorwhitespace($this.OrgName) -and ![string]::isnullorwhitespace($this.ProjectName)){
            if(Test-Path $this.MasterFilePath){
                $batchStatus = Get-Content $this.MasterFilePath | ConvertFrom-Json
                return $batchStatus.BuildNextContinuationToken;
            }
        }
        return $null;
    }

    [string] GetReleaseContinuationToken(){
        if(![string]::isnullorwhitespace($this.OrgName) -and ![string]::isnullorwhitespace($this.ProjectName)){
            if(Test-Path $this.MasterFilePath){
                $batchStatus = Get-Content $this.MasterFilePath | ConvertFrom-Json
                return $batchStatus.ReleaseNextContinuationToken;
            }
        }
        return $null;
    }

    [BatchScanState] GetBatchScanState(){
        if(![string]::isnullorwhitespace($this.OrgName) -and ![string]::isnullorwhitespace($this.ProjectName)){
            if(Test-Path $this.MasterFilePath){
                $batchStatus = Get-Content $this.MasterFilePath | ConvertFrom-Json
                return $batchStatus.BatchScanState;
            }
        }
        return $null;
    }

    [string] GetUpdatedContToken([int] $skip, [string] $top, [string] $resourceType){
        $tempSkip=0;
        if($PSCmdlet.MyInvocation.BoundParameters.ResourceTypeName -eq 'Build_Release' -and $this.isPreviousScanPartiallyComplete() ){
            $topNQueryString = '&$top={0}' -f ($this.GetBatchSize()/2); 
        }
        else {
            $topNQueryString = '&$top={0}' -f $this.GetBatchSize();
        }
        
        if($resourceType -eq 'Build'){
            $resourceDefnURL = ("https://dev.azure.com/{0}/{1}/_apis/build/definitions?queryOrder=lastModifiedDescending&api-version=6.0" +$topNQueryString) -f $this.OrgName, $this.ProjectName;
        }
        else {
            $resourceDefnURL = ("https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?api-version=6.0" +$topNQueryString) -f $this.OrgName, $this.ProjectName;
        }
        
        $continuationToken=$null;
        $originalUri=$resourceDefnURL;
        $validationUrl=$null;
        while($tempSkip -lt $skip){
           $validationUrl=$originalUri;
           $originalUri=$resourceDefnURL;
            
            if($PSCmdlet.MyInvocation.BoundParameters.ResourceTypeName -eq 'Build_Release' -and $this.isPreviousScanPartiallyComplete() ){
                $tempSkip+=($this.GetBatchSize()/2); 
            }
            else {
                $tempSkip+=$this.GetBatchSize(); 
            }            
            $updatedUriAndContToken=[WebRequestHelper]:: InvokeWebRequestForContinuationToken($validationUrl,$originalUri,$tempSkip,$resourceType);
            $continuationToken=$updatedUriAndContToken[0];
            $originalUri=$updatedUriAndContToken[1];

        }
        return $continuationToken;

    }



}