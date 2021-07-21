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
            $this.BatchScanTrackerObj = Get-content $this.MasterFilePath 
        }
        else {
            $this.BatchScanTrackerObj=$null;
        }
        
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
                    Remove-Item -Path (Join-Path (Join-Path $this.AzSKTempStatePath (Join-Path $this.OrgName $this.ProjectName)) $this.ResourceScanTrackerFileName)
                    
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

    [void] CreateBatchMasterList([string] $OrgName, [string] $ProjectName){
        #TODO: call invoke webrequest in batches, after each batch get id and store as array
        [System.Uri] $validatedUri = $null;
        $orginalUri = "";
        
        $skipCount = 0
        $batchCount = 1;
        $topNQueryString = '&$top=10000'
        $resourceDfnUrl = ("https://dev.azure.com/{0}/{1}/_apis/build/definitions?queryOrder=lastModifiedDescending&api-version=6.0" +$topNQueryString) -f $OrgName, $ProjectName;
                            
        while ([System.Uri]::TryCreate($resourceDfnUrl, [System.UriKind]::Absolute, [ref] $validatedUri)) {
            if ([string]::IsNullOrWhiteSpace($orginalUri)) {
                $orginalUri = $validatedUri.AbsoluteUri;   
            }
            $progressCount = 0;            
            $skipCount += 10000;
            $responseAndUpdatedUri = [WebRequestHelper]::InvokeWebRequestForResourcesInBatch($validatedUri, $orginalUri, $skipCount,"build");
            #API response with resources
            $resourceDefnsObj = $responseAndUpdatedUri[0];
            #updated URI
            $resourceDfnUrl = $responseAndUpdatedUri[1];
            $buildIds=@()
            if ( (($resourceDefnsObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($resourceDefnsObj[0], "name")) -or ([Helpers]::CheckMember($resourceDefnsObj, "count") -and $resourceDefnsObj[0].count -gt 0)) {
                foreach ($resourceDef in $resourceDefnsObj) {
                   $buildIds+=$resourceDef.id
                    Write-Progress -Activity "Fetching builds in batches. This may take time. Fetched $($progressCount) of $(($resourceDefnsObj | Measure-Object).Count) builds of batch $($batchCount) " -Status "Progress: " -PercentComplete ($progressCount / ($resourceDefnsObj | Measure-Object).Count * 100)
                    $progressCount = $progressCount + 1;
                   
                }
                $batchCount = $batchCount + 1;  
                $this.BatchScanTrackerObj=$buildIds 
                $this.WriteToBatchTrackerFile();                          

            }
            else {
                break;
            }
         
        }
        
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
            Write-Host "Updating resource tracker file" -ForegroundColor Yellow
            $this.BatchScanTrackerObj | Out-File -append $this.MasterFilePath -Force
            Write-Host "Resource tracker file updated" -ForegroundColor Yellow
            
        }
    }



}