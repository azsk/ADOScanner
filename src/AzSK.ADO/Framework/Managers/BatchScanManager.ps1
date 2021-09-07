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
        if($this.CheckIfProjectValid($ProjectName) -eq $false){
            Write-Host "You have supplied an invalid project name. Re run the command with correct project." -ForegroundColor Red
            throw;
        }
        $this.ProjectName=$ProjectName;
        if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("BatchSize")){
            $this.BatchSize = $PSCmdlet.MyInvocation.BoundParameters["BatchSize"]
        }
        else {
            $this.BatchSize = $this.ControlSettings.BatchScan.BatchTrackerUpdateFrequency
        }

        #need to make batch size half as both builds and releases will be scanned
        if($PSCmdlet.MyInvocation.BoundParameters.ResourceTypeName -eq "Build_Release"){
            if($this.BatchSize%2 -eq 0){
                $this.BatchSize=$this.BatchSize/2;
            }
            else {
                $this.BatchSize=($this.BatchSize-1)/2;
            }
            
            
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

    [bool] CheckIfProjectValid($ProjectName){
        $apiURL = 'https://dev.azure.com/{0}/_apis/projects?$top=1000&api-version=6.0' -f $($this.OrgName);
        $responseObj = "";
        try {
            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL) ;
        }
        catch {
            Write-Host 'Project not found: Incorrect project name or you do not have necessary permission to access the project.' -ForegroundColor Red
            throw;
        }
        if (([Helpers]::CheckMember($responseObj, "count") -and $responseObj[0].count -gt 0) -or (($responseObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($responseObj[0], "name")))
        {
            $projects = $responseObj | Where-Object { $ProjectName -contains $_.name }

            if (!$projects) {
                return $false;                  
            }
        }
        return $true;
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
            TokenLastModifiedTime = [DateTime]:: UtcNow;
            ResourceCount=0;
            SkipMarker = 'False';
            UpcError = 'False'
           
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

    #to check if anyone either builds or releases have been scanned and other resource is still left, is useful only when build_release is resource type
    [bool] isPreviousScanPartiallyComplete(){
        if(![string]::isnullorwhitespace($this.OrgName) -and ![string]::isnullorwhitespace($this.ProjectName)){
            if( ($null -ne $this.MasterFilePath) -and (Test-Path $this.MasterFilePath)){
                $batchStatus = Get-Content $this.MasterFilePath | ConvertFrom-Json
                if($batchStatus.Skip -gt 0 -and [string]::IsNullOrEmpty($batchStatus.ReleaseNextContinuationToken) -and $batchStatus.BatchScanState -eq [BatchScanState]::COMP) {
                   return $true;
                    
                }
                if($batchStatus.Skip -gt 0 -and [string]::IsNullOrEmpty($batchStatus.BuildNextContinuationToken) -and $batchStatus.BatchScanState -eq [BatchScanState]::COMP) {
                    return $true;
                }
                if($batchStatus.Skip -gt 0 -and [string]::IsNullOrEmpty($batchStatus.ReleaseNextContinuationToken) -and [string]::IsNullOrEmpty($batchStatus.ReleaseCurrentContinuationToken)) {
                    return $true;
                     
                }
                 if($batchStatus.Skip -gt 0 -and [string]::IsNullOrEmpty($batchStatus.BuildNextContinuationToken) -and [string]::IsNullOrEmpty($batchStatus.BuildCurrentContinuationToken)) {
                     return $true;
                }

            }
        }
        return $false;
    }
    hidden static [PSObject] GetBaseFrameworkPath() {
		$moduleName = $([Constants]::AzSKModuleName)

		#Remove Staging from module name before forming config base path
		$moduleName = $moduleName -replace "Staging", ""

		#Irrespective of whether Dev-Test mode is on or off, base framework path will now remain same as the new source code repo doesn't have AzSK.Framework folder.
		$basePath = (Get-Item $PSScriptRoot).Parent.FullName

		return $basePath
	}

    hidden static [PSObject] LoadFrameworkConfigFile([string] $fileName, [bool] $parseJson) {
        #Load file from AzSK App folder"
        $fileName = $fileName.Split('\')[-1]
        $extension = [System.IO.Path]::GetExtension($fileName);
 
        $basePath = [BatchScanManager]::GetBaseFrameworkPath()
        $rootConfigPath = $basePath | Join-Path -ChildPath "Configurations";
 
        $filePath = (Get-ChildItem $rootConfigPath -Name -Recurse -Include $fileName) | Select-Object -First 1
        if ($filePath) {
            if ($parseJson) {
                if ($extension -eq ".json" -or $extension -eq ".lawsview") {
                    $fileContent = (Get-Content -Raw -Path (Join-Path $rootConfigPath $filePath)) | ConvertFrom-Json
                }
                else {
                    $fileContent = (Get-Content -Raw -Path (Join-Path $rootConfigPath $filePath))
                }
            }
            else {
                $fileContent = (Get-Content -Raw -Path (Join-Path $rootConfigPath $filePath))
            }
        }
        else {
            throw "Unable to find the specified file '$fileName'"
        }
        if (-not $fileContent) {
            throw "The specified file '$fileName' is empty"
        }
 
        return $fileContent;        
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
                        
                        Write-Host "Found a previous batch scan with no scanned resources. Continuing the scan from start `n " -ForegroundColor Green
                        
                    }
                    else
                    {
                        #anyone of the resource has been completely scanned need to make batch size double again
                        if($PSCmdlet.MyInvocation.BoundParameters.ResourceTypeName -eq 'Build_Release' -and $this.isPreviousScanPartiallyComplete() ){
                            if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("BatchSize")){
                                $this.BatchSize = $PSCmdlet.MyInvocation.BoundParameters["BatchSize"]
                            }
                            else {
                                $this.BatchSize = $this.ControlSettings.BatchScan.BatchTrackerUpdateFrequency
                            }
                            if($this.BatchSize%2 -ne 0){
                                $this.BatchSize=$this.BatchSize-1
                            }                           
                            

                        }
                        Write-Host "Found a previous batch scan in progress with $($batchStatus.ResourceCount) resources scanned. Resuming the scan from last batch. `n " -ForegroundColor Green
                        
                        if($this.CheckContTokenValidity($batchStatus.TokenLastModifiedTime)){
                            return;
                        }
                        else {
                            #find the updated token
                            if($isBuildScan -and $batchStatus.Skip -ne 0 -and (-not [string]::IsNullOrEmpty($batchStatus.BuildCurrentContinuationToken))){
                                $batchStatus.BuildCurrentContinuationToken=$this.GetUpdatedContToken($batchStatus.Skip,$batchStatus.Top,'Build');
                            }
                            if($isReleaseScan -and $batchStatus.Skip -ne 0 -and (-not [string]::IsNullOrEmpty($batchStatus.ReleaseCurrentContinuationToken))){
                                $batchStatus.ReleaseCurrentContinuationToken=$this.GetUpdatedContToken($batchStatus.Skip,$batchStatus.Top,'Release');
                            }
                            
                            $batchStatus.TokenLastModifiedTime=[DateTime]::UtcNow;
                        }
                    }
                }
                else {
                    #anyone of the resource has been completely scanned need to make batch size double again
                    if($PSCmdlet.MyInvocation.BoundParameters.ResourceTypeName -eq 'Build_Release' -and $this.isPreviousScanPartiallyComplete() ){
                        if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("BatchSize")){
                            $this.BatchSize = $PSCmdlet.MyInvocation.BoundParameters["BatchSize"]
                        }
                        else {
                            $this.BatchSize = $this.ControlSettings.BatchScan.BatchTrackerUpdateFrequency
                        }
                        if($this.BatchSize%2 -ne 0){
                            $this.BatchSize=$this.BatchSize-1
                        }  
                    }
                    Write-Host "Found a previous batch scan with $($batchStatus.ResourceCount) resources scanned. Starting fresh scan for the next batch. `n " -ForegroundColor Green
                    #anyone of the resource has been completely scanned need to update skip by original batch size. However for the first time skip should only be updated by half
                    if($PSCmdlet.MyInvocation.BoundParameters.ResourceTypeName -eq 'Build_Release' -and $batchStatus.SkipMarker -eq "False" -and $this.isPreviousScanPartiallyComplete() ){
                        
                        $batchStatus.Skip=$batchStatus.Skip + ($this.GetBatchSize()/2);
                        $batchStatus.SkipMarker = "True"
                    }
                    else {
                        $batchStatus.Skip+=$this.GetBatchSize();
                    }
                    
                    
                    
                    $batchStatus.BatchScanState=[BatchScanState]::INIT
                    
                    if($this.CheckContTokenValidity($batchStatus.TokenLastModifiedTime)){
                        
                        if($isReleaseScan) {
                            $batchStatus.ReleaseCurrentContinuationToken=$batchStatus.ReleaseNextContinuationToken
                        }
                        if($isBuildScan){
                            $batchStatus.BuildCurrentContinuationToken=$batchStatus.BuildNextContinuationToken
                        }
                        
                    }
                    else {
                        #find the updated token
                        if($isBuildScan -and $batchStatus.Skip -ne 0 -and (-not [string]::IsNullOrEmpty($batchStatus.BuildNextContinuationToken))){
                            $batchStatus.BuildCurrentContinuationToken=$this.GetUpdatedContToken($batchStatus.Skip,$batchStatus.Top,'Build');
                        }
                        if($isReleaseScan -and $batchStatus.Skip -ne 0 -and (-not [string]::IsNullOrEmpty($batchStatus.ReleaseNextContinuationToken))){
                            $batchStatus.ReleaseCurrentContinuationToken=$this.GetUpdatedContToken($batchStatus.Skip,$batchStatus.Top,'Release');
                        }
                        #in case builds have been completely scanned, i.e end of builds 
                        if($isBuildScan -and $batchStatus.Skip -ne 0 -and [string]::IsNullOrEmpty($batchStatus.BuildNextContinuationToken)){
                            $batchStatus.BuildCurrentContinuationToken=$batchStatus.BuildNextContinuationToken
                        }
                        #in case releases have been completely scanned, i.e end of releases 
                        if($isReleaseScan -and $batchStatus.Skip -ne 0 -and [string]::IsNullOrEmpty($batchStatus.ReleaseNextContinuationToken)){
                            $batchStatus.ReleaseCurrentContinuationToken=$batchStatus.ReleaseNextContinuationToken
                        }
                       
                        $batchStatus.TokenLastModifiedTime=[DateTime]::UtcNow;
                        
                    }
                   
                }
                $this.BatchScanTrackerObj=$batchStatus;
                $this.WriteToBatchTrackerFile();
            }
        }
       
    }

    [bool] IsScanComplete(){
        if($PSCmdlet.MyInvocation.BoundParameters.ResourceTypeName -eq 'Build' -and [string]::IsNullOrEmpty($this.GetBuildContinuationToken()) -and $this.GetBatchScanState() -eq [BatchScanState]::COMP){
            return $true;
        }
        elseif($PSCmdlet.MyInvocation.BoundParameters.ResourceTypeName -eq 'Release' -and [string]::IsNullOrEmpty($this.GetReleaseContinuationToken()) -and $this.GetBatchScanState() -eq [BatchScanState]::COMP){
            return $true;            
        }
        elseif($PSCmdlet.MyInvocation.BoundParameters.ResourceTypeName -eq 'Build_Release' -and [string]::IsNullOrEmpty($this.GetReleaseContinuationToken()) -and [string]::IsNullOrEmpty($this.GetBuildContinuationToken()) -and $this.GetBatchScanState() -eq [BatchScanState]::COMP) {
            return $true;
        }
        else{
            $batchStatus = Get-Content $this.MasterFilePath | ConvertFrom-Json
            if($batchStatus.UpcError -eq 'False'){
                Write-Host "Another project seems to be in partial commit. Therefore the scan for this project cannot be completed. Either complete the scan for the previous project using the GADS command or delete the file %LOCALAPPDATA%/Microsoft/AzSK.ADO/TempState/PartialScanData/[org_name]" -ForegroundColor Yellow
                return $true;
            }
            else{
                return $false;
            }
        }
        return $false;
    }

    hidden [bool] CheckContTokenValidity([DateTime] $lastModifiedTime){
       
        if($lastModifiedTime.AddHours([INT32]::Parse(15)) -lt [DateTime]::UtcNow){
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