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
            Top = $this.ControlSettings.BatchScan.BatchTrackerUpdateFrequency;
            CurrentContinuationToken=$null;
            NextContinuationToken=$null;
            BatchScanState= [BatchScanState]::INIT;
            LastModifiedTime = [DateTime]:: UtcNow;
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

    [void] UpdateBatchMasterList(){
        if(![string]::isnullorwhitespace($this.OrgName) -and ![string]::isnullorwhitespace($this.ProjectName)){
            if(Test-Path $this.MasterFilePath){
                $batchStatus = Get-Content $this.MasterFilePath | ConvertFrom-Json
                
                if($batchStatus.BatchScanState -eq [BatchScanState]:: INIT ){
                    if($batchStatus.Skip -eq 0){
                        $batchStatus.CurrentContinuationToken=$null;
                        Write-Host "Found a previous batch scan with no scanned builds. Continuing the scan from start `n " -ForegroundColor Green
                        
                    }
                    else
                    {
                        Write-Host "Found a previous batch scan in progress with $($batchStatus.Skip) builds scanned. Continuing the scan for the last $($batchStatus.Top) builds from previous batch. `n " -ForegroundColor Green
                        
                        if($this.CheckContTokenValidity($batchStatus.CurrentContinuationToken,$batchStatus.LastModifiedTime)){
                            return;
                        }
                        else {
                            $batchStatus.CurrentContinuationToken=$this.GetUpdatedContToken($batchStatus.Skip,$batchStatus.Top);
                            $batchStatus.LastModifiedTime=[DateTime]::UtcNow;
                        }
                    }
                }
                else {
                    Write-Host "Found a previous batch scan with $($batchStatus.Skip+$batchStatus.Top) builds scanned. Starting fresh scan for the next batch of $($batchStatus.Top) builds. `n " -ForegroundColor Green
                   
                    $batchStatus.Skip+=$this.ControlSettings.BatchScan.BatchTrackerUpdateFrequency;
                    $batchStatus.BatchScanState=[BatchScanState]::INIT
                    
                    if($this.CheckContTokenValidity($batchStatus.NextContinuationToken,$batchStatus.LastModifiedTime)){
                        $batchStatus.CurrentContinuationToken=$batchStatus.NextContinuationToken
                        
                    }
                    else {
                        
                        $batchStatus.CurrentContinuationToken=$this.GetUpdatedContToken($batchStatus.Skip,$batchStatus.Top);
                        $batchStatus.LastModifiedTime=[DateTime]::UtcNow;
                        
                    }
                }
                $this.BatchScanTrackerObj=$batchStatus;
                $this.WriteToBatchTrackerFile();
            }
        }
       
    }

    hidden [bool] CheckContTokenValidity([string] $continuationToken,[DateTime] $lastModifiedTime){
        if($continuationToken -eq ""){
            return $false;
        }
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

    [string] GetContinuationToken(){
        if(![string]::isnullorwhitespace($this.OrgName) -and ![string]::isnullorwhitespace($this.ProjectName)){
            if(Test-Path $this.MasterFilePath){
                $batchStatus = Get-Content $this.MasterFilePath | ConvertFrom-Json
                return $batchStatus.NextContinuationToken;
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

    [void] UpdateContTokenAndDate($contToken, $lastModifiedTime){
        if(![string]::isnullorwhitespace($this.OrgName) -and ![string]::isnullorwhitespace($this.ProjectName)){
            if(Test-Path $this.MasterFilePath){
                $batchStatus = Get-Content $this.MasterFilePath | ConvertFrom-Json
                $batchStatus.ContinuationToken=$contToken;
                $batchStatus.LastModifiedTime=$lastModifiedTime;
                $this.BatchScanTrackerObj=$batchStatus;
                $this.WriteToBatchTrackerFile();
            }
        }
    }

    [string] GetUpdatedContToken([int] $skip, [string] $top){
        $tempSkip=0;
        $topNQueryString = '&$top={0}' -f $this.ControlSettings.BatchScan.BatchTrackerUpdateFrequency
        $buildDefnURL = ("https://dev.azure.com/{0}/{1}/_apis/build/definitions?queryOrder=lastModifiedDescending&api-version=6.0" +$topNQueryString) -f $this.OrgName, $this.ProjectName;
        $continuationToken=$null;
        $originalUri=$buildDefnURL;
        $validationUrl=$null;
        while($tempSkip -ne $skip){
           $validationUrl=$originalUri;
           $originalUri=$buildDefnURL;
            $tempSkip+=$this.ControlSettings.BatchScan.BatchTrackerUpdateFrequency;          
            
            $updatedUriAndContToken=[WebRequestHelper]:: InvokeWebRequestForContinuationToken($validationUrl,$originalUri,$tempSkip);
            $continuationToken=$updatedUriAndContToken[0];
            $originalUri=$updatedUriAndContToken[1];

        }
        return $continuationToken;

    }



}