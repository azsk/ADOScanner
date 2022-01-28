using namespace System.Management.Automation
Set-StrictMode -Version Latest 

class AzSKADOServiceMapping: CommandBase
{    
    [string] $OrgName
    [string] $ProjectName
    [string] $ProjectId
    [string] $BuildMappingsFilePath
    [string] $ReleaseMappingsFilePath
    [string] $RepositoryMappingsFilePath
    [string] $MappingType
    [string] $OutputFolderPath
    [string] $Auto = $false
    [switch] $UseCache #switch to read mapping details from cache
    [string] $StorageAccount; # Storage account name
    [string] $StorageRG;# Storage resource group name
    [string] $Container;# Storage Container to store ST mapping files    
    [object] $StorageAccountCtx;     
    # Power BI Report Storage settings to store ST mapping files
    [string] $ReportStorageAccount;# Storage account name for Dashboard 
    [string] $ReportStorageRG;# Storage resource group name for Dashboard 
    [string] $ReportContainer;#Storage Container to store ST mapping files use by Power Bi  resports    
    [object] $ReportStorageAccountCtx; 
    [object] $Stopwatch;#Create a Stopwatch    
    [string] $AzSKTempStatePath = [Constants]::AzSKTempFolderPath
    [ServiceMappingCacheHelper] $ServiceMappingCacheHelperObj;
    [int] $MappingExpirationLImit #Service id mapping expiration duration
    $BuildSTDetails = @();
    $ReleaseSTDetails =@();
    $RepositorySTDetails =@();
    $storageCachedData = @();#inmemory cached mapping data    
    $lastDuration =0 #track previous resource scan duration
    $IncrementalScan = $false;


	AzSKADOServiceMapping([string] $organizationName, [string] $projectName, [string] $buildFileLocation, [string] $releaseFileLocation, [string] $repositoryFileLocation,[string] $mappingType,[string] $auto,[switch] $useCache, [switch] $IncrementalScan, [InvocationInfo] $invocationContext): 
        Base($organizationName, $invocationContext) 
    { 
        $this.OrgName = $organizationName
        $this.ProjectName = $projectName
        $this.BuildMappingsFilePath = $buildFileLocation
        $this.ReleaseMappingsFilePath = $releaseFileLocation
        $this.RepositoryMappingsFilePath = $repositoryFileLocation
        $this.MappingType = $MappingType
        $this.Auto = $auto.ToLower();      
        $this.UseCache =  $useCache 
        $this.IncrementalScan = $IncrementalScan
        $this.StorageAccount = $env:StorageName;
        $this.StorageRG = $env:StorageRG;
        $this.Container = $env:Container;
        # Power BI Report Storage settings
        $this.ReportStorageAccount = $env:ReportStorageName;
        $this.ReportStorageRG = $env:ReportStorageRG;
        $this.ReportContainer = $env:ReportContainer;  
        # Set Service id mapping expiration duration
        $this.MappingExpirationLimit = $env:MappingExpirationLimit;         
        #get ServiceMapping cache helper instance   
        $this.ServiceMappingCacheHelperObj = [ServiceMappingCacheHelper]::ServiceMappingCacheHelperInstance
        if (!$this.ServiceMappingCacheHelperObj) {
            $this.ServiceMappingCacheHelperObj = [ServiceMappingCacheHelper]::GetInstance($this.OrgName);
        }            
       
        #get storage details
        if($this.Auto -eq 'true'){
            if ($this.StorageRG -and $this.StorageAccount) {
                $keys = Get-AzStorageAccountKey -ResourceGroupName $this.StorageRG -Name $this.StorageAccount
                if ($null -eq $keys)
				{
					$this.PublishCustomMessage("Status:   Storage account not found.", [MessageType]::Error);
				}
                else {
                    #storage context to save ST files for ADO scanner
                    $StorageContext = New-AzStorageContext -StorageAccountName $this.StorageAccount -StorageAccountKey $keys[0].Value -Protocol Https                
                    $this.StorageAccountCtx = $StorageContext.Context;   
                }
                             
            }
            if ($this.ReportStorageRG -and $this.ReportStorageAccount) {
                $keys = Get-AzStorageAccountKey -ResourceGroupName $this.ReportStorageRG -Name $this.ReportStorageAccount
                if ($null -eq $keys)
				{
					$this.PublishCustomMessage("Status:   Storage account not found.", [MessageType]::Error);
				}
                else {
                   #storage context to save ST files for Power Bi reports
                    $ReportStorageContext = New-AzStorageContext -StorageAccountName $this.ReportStorageAccount -StorageAccountKey $keys[0].Value -Protocol Https                                
                    $this.ReportStorageAccountCtx = $ReportStorageContext.Context;  
                }
                             
            }
        }
	}
	
	[MessageData[]] GetSTmapping()
	{       
        $this.Stopwatch =  [system.diagnostics.stopwatch]::StartNew() 
        $this.Stopwatch.Start();        
        if(![string]::IsNullOrWhiteSpace($this.RepositoryMappingsFilePath)) {
            $this.SaveScanDuration("Repository scan started", $false)            
            $this.GetRepositoryMapping();
            $this.SaveScanDuration("Repository scan ended",$true)
        }

        if(![string]::IsNullOrWhiteSpace($this.BuildMappingsFilePath) -and ![string]::IsNullOrWhiteSpace($this.ReleaseMappingsFilePath)){
            if(((Test-Path $this.BuildMappingsFilePath) -and (Test-Path $this.ReleaseMappingsFilePath)) -or $this.Auto -eq 'true')
            {
                $this.GetBuildReleaseMapping();              
                if ([string]::IsNullOrWhiteSpace($this.MappingType) -or $this.MappingType -eq "All" -or $this.MappingType -eq "ServiceConnection")
                {
                    $this.SaveScanDuration("Service Connections scan started", $false)
                    $this.FetchSvcConnMapping();
                    $this.SaveScanDuration("Service Connections scan ended",$true)
                }
                if ([string]::IsNullOrWhiteSpace($this.MappingType) -or $this.MappingType -eq "All" -or $this.MappingType -eq "AgentPool")
                {
                    $this.SaveScanDuration("Agent Pool scan started", $false)
                    $this.storageCachedData = $this.ServiceMappingCacheHelperObj.GetWorkItemByHashAzureTable("All", "","","", $this.projectId)
                    $this.FetchAgentPoolMapping();
                    $this.SaveScanDuration("Agent Pool scan ended",$true)
                }
                if ([string]::IsNullOrWhiteSpace($this.MappingType) -or $this.MappingType -eq "All" -or $this.MappingType -eq "Environment")
                {
                    $this.SaveScanDuration("Environment scan started", $false)
                    $this.FetchEnvironmentMapping();
                    $this.SaveScanDuration("Environment scan ended",$true)
                }
                if ([string]::IsNullOrWhiteSpace($this.MappingType) -or $this.MappingType -eq "All" -or $this.MappingType -eq "VariableGroup" -or $this.MappingType -eq "SecureFile")
                {
                    $this.SaveScanDuration("VariableGroup/SecureFile scan started", $false)
                    # fetch all the cached mappings from cache and add to in-memory collection
                    $this.storageCachedData = $this.ServiceMappingCacheHelperObj.GetWorkItemByHashAzureTable("All", "","","", $this.projectId)
                    if($this.IncrementalScan){
                        if ([string]::IsNullOrWhiteSpace($this.MappingType) -or $this.MappingType -eq "All" -or $this.MappingType -eq "VariableGroup"){
                            $this.FindSTForVGWithIncremental();
            
                        }
                        if ([string]::IsNullOrWhiteSpace($this.MappingType) -or $this.MappingType -eq "All" -or $this.MappingType -eq "VariableGroup"){
                            $this.FindSTForSecureFileWithIncremental();
                        }
                    }
                    else{
                        $this.FetchVarGrpSecureFileMapping();
                    }
                    $this.SaveScanDuration("VariableGroup/SecureFile scan ended",$true)
                }
                if ([string]::IsNullOrWhiteSpace($this.MappingType) -or $this.MappingType -eq "All" -or $this.MappingType -eq "Feed")
                {
                    $this.SaveScanDuration("Feed scan started", $false)
                    $this.FetchFeedMapping();
                    $this.SaveScanDuration("Feed scan ended",$true)
                }
            }
        }
        
		[MessageData[]] $returnMsgs = @();
		$returnMsgs += [MessageData]::new("Returning service mappings.");
		return $returnMsgs
    }
    
    hidden  GetBuildReleaseMapping()
    {  
        if($env:BuildSTData){
            $this.BuildSTDetails = Get-content $env:BuildSTData | ConvertFrom-Json 
            $this.ReleaseSTDetails = Get-content $env:ReleaseSTData | ConvertFrom-Json 
            return;
        }
        $this.SaveScanDuration("Build's repo scan started", $false)
        if($this.Auto -eq 'true'){
            $response = Get-AzStorageBlob -Blob 'BuildServiceMappingData.json' -Container $this.Container -Context $this.StorageAccountCtx 
            $this.BuildSTDetails = $response.ICloudBlob.DownloadText() | ConvertFrom-Json         
        }
        else {
            $this.BuildSTDetails = Get-content $this.BuildMappingsFilePath | ConvertFrom-Json    
        }        
        if ([Helpers]::CheckMember($this.BuildSTDetails, "data") -and ($this.BuildSTDetails.data | Measure-Object).Count -gt 0){
            $this.BuildSTDetails.data = $this.BuildSTDetails.data | where-object {$_.ProjectName -eq $this.ProjectName}            
            if (($this.BuildSTDetails.data | Measure-Object).Count -gt 0){
                $this.ProjectId = $this.BuildSTDetails.data[0].projectId;
            }
        }   

        # Get Build-Repo mappings
        try {            
            $buildObjectListURL = ("https://dev.azure.com/{0}/{1}/_apis/build/definitions?queryOrder=lastModifiedDescending&api-version=6.0" +'&$top=10000') -f $($this.orgName), $this.projectName;       
            $buildObjectList = $this.GetBuildReleaseObjects($buildObjectListURL,'Build');
            $buildObjectList = $buildObjectList | Where-Object {$_.id -notin $this.BuildSTDetails.data.buildDefinitionID}            
            $counter =0
            foreach ($build in $buildObjectList) {               
                try {                
                    $counter++
                    Write-Progress -Activity 'Build mappings...' -CurrentOperation $build.name -PercentComplete (($counter / $buildObjectList.count) * 100)                                   
                    $buildDefnObj = [WebRequestHelper]::InvokeGetWebRequest($build.url);
                    $repositoryName = $buildDefnObj.repository.name;
                    $repoSTData = $this.RepositorySTDetails.Data | Where-Object { ($_.repoName -eq $repositoryName)};
                    if($repoSTData){
                        $this.BuildSTDetails.data+=@([PSCustomObject] @{ buildDefinitionName = $build.name; buildDefinitionID = $build.id; serviceID = $repoSTData.serviceID; projectName = $repoSTData.projectName; projectID = $repoSTData.projectID; orgName = $repoSTData.orgName } )                            
                    }
                }
                catch{

                }           
            }   
            [ServiceMappingCacheHelper]::TelemetryLogging("GetBuildReleaseMapping completed",$null);     
        }
        catch {           
        }    
        if($this.UseCache)
        {
            $this.ExportObjToJsonFile($this.BuildSTDetails, 'BuildSTData.json');
            $this.ExportObjToJsonFileUploadToBlob($this.BuildSTDetails, 'BuildSTData.json');
        }
        $this.SaveScanDuration("Build's repo scan ended", $true)

        $this.SaveScanDuration("Release's repo releases scan started", $false)
        if($this.Auto -eq 'true'){
            $response = Get-AzStorageBlob -Blob 'ReleaseServiceMappingData.json' -Container $this.Container -Context $this.StorageAccountCtx 
            $this.ReleaseSTDetails = $response.ICloudBlob.DownloadText() | ConvertFrom-Json         
        }
        else {
            $this.ReleaseSTDetails = Get-content $this.ReleaseMappingsFilePath | ConvertFrom-Json     
        }        
               
        if ([Helpers]::CheckMember($this.ReleaseSTDetails, "data") -and ($this.ReleaseSTDetails.data | Measure-Object).Count -gt 0)
        {
            $this.ReleaseSTDetails.data = $this.ReleaseSTDetails.data | where-object {$_.ProjectName -eq $this.ProjectName}
            if (($this.ReleaseSTDetails.data | Measure-Object).Count -gt 0 -and [string]::IsNullOrWhiteSpace($this.ProjectId))
            {
                $this.ProjectId = $this.ReleaseSTDetails.data[0].projectId
            }
        }       

        # Get Release-Repo mappings
        try {                         
            $releaseObjectListURL = ("https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?api-version=6.0" ) -f $($this.orgName), $this.projectName;    
            $releaseObjectList = $this.GetBuildReleaseObjects($ReleaseObjectListURL,'Release');
            $releaseObjectList = $releaseObjectList | Where-Object {$_.id -notin $this.ReleaseSTDetails.data.releaseDefinitionID}                     
            $counter =0
            foreach ($release in $releaseObjectList) {  
                try { 
                    $counter++
                    Write-Progress -Activity 'Release mappings...' -CurrentOperation $release.name -PercentComplete (($counter / $releaseObjectList.count) * 100)                                                     
                    $releaseDefnObj = [WebRequestHelper]::InvokeGetWebRequest($release.url);                      
                        if($releaseDefnObj[0].artifacts)
                        {
                                $type = $releaseDefnObj[0].artifacts.type;
                                switch ($type)
                                    {
                                    {($_ -eq "GitHubRelease") -or ($_ -eq "Git")}{
                                        $repositoryName =$releaseDefnObj[0].artifacts.definitionReference.definition.name;
                                        $repoSTData = $this.RepositorySTDetails.Data | Where-Object { ($_.repoName -eq $repositoryName)};
                                        if($repoSTData){
                                            $this.ReleaseSTDetails.data+=@([PSCustomObject] @{ releaseDefinitionName = $release.name; releaseDefinitionID = $release.id; serviceID = $repoSTData.serviceID; projectName = $repoSTData.projectName; projectID = $repoSTData.projectID; orgName = $repoSTData.orgName } )                            
                                        } 
                                    }
                                    Build {  
                                        $buildSTData = $this.BuildSTDetails.Data | Where-Object { ($_.buildDefinitionID -eq $releaseDefnObj[0].artifacts.definitionReference.definition.id) -and ($_.projectID -eq $releaseDefnObj[0].artifacts.definitionReference.project.id)};
                                        If($buildSTData){
                                            $this.ReleaseSTDetails.data+=@([PSCustomObject] @{ releaseDefinitionName = $release.name; releaseDefinitionID = $release.id; serviceID = $buildSTData.serviceID; projectName = $buildSTData.projectName; projectID = $buildSTData.projectID; orgName = $buildSTData.orgName } )                            
                                        }
                                    }                                                                                                                                                                                           
                                }
                        }                                           
                }
                catch{

                }                
            }                                
        }
        catch {
           
        }
        if($this.UseCache)
        {
            $this.ExportObjToJsonFile($this.ReleaseSTDetails, 'ReleaseSTData.json');
            $this.ExportObjToJsonFileUploadToBlob($this.ReleaseSTDetails, 'ReleaseSTData.json');            
        }
        $this.SaveScanDuration("Release's repo releases scan ended", $false)
    }

    hidden GetRepositoryMapping() {  
        if($this.Auto -eq 'true'){
            $response = Get-AzStorageBlob -Blob 'RepoServiceMappingData.json' -Container $this.Container -Context $this.StorageAccountCtx 
            $this.RepositorySTDetails = $response.ICloudBlob.DownloadText() | ConvertFrom-Json         
        }
        else {
            $this.RepositorySTDetails = Get-content $this.RepositoryMappingsFilePath | ConvertFrom-Json     
        }         
        if ([Helpers]::CheckMember($this.RepositorySTDetails, "data") -and ($this.RepositorySTDetails.data | Measure-Object).Count -gt 0)
        {
            $this.RepositorySTDetails.data = $this.RepositorySTDetails.data | where-object {$_.ProjectName -eq $this.ProjectName}
            if (($this.RepositorySTDetails.data | Measure-Object).Count -gt 0)
            {
                $this.ProjectId = $this.RepositorySTDetails.data[0].projectId
            }
        }
        if($this.UseCache)
        {        
            $this.ExportObjToJsonFile($this.RepositorySTDetails, 'RepositorySTData.json');
            $this.ExportObjToJsonFileUploadToBlob($this.RepositorySTDetails, 'RepositorySTData.json');
        }
    }

    hidden ExportObjToJsonFile($serviceMapping, $fileName) {   
        $folderPath ="/" + $this.OrgName.ToLower() + "/" + $this.ProjectName.ToLower(); 
        if($this.auto -eq "true"){
            $this.OutputFolderPath = $this.AzSKTempStatePath + $folderPath;
        }
        else {
            $this.OutputFolderPath = [WriteFolderPath]::GetInstance().FolderPath + $folderPath;         
        }
        If(!(test-path $this.OutputFolderPath)){
            New-Item -ItemType Directory -Force -Path $this.OutputFolderPath
        }                    
        $serviceMapping | ConvertTo-Json -Depth 10 | Out-File (Join-Path $this.OutputFolderPath $fileName) -Encoding ASCII        
    }

    hidden ExportObjToJsonFileUploadToBlob($serviceMapping, $fileName) {
        if($this.auto -eq "true"){
            
        $fileName =$this.OrgName.ToLower() + "/" + $this.ProjectName.ToLower() + "/" + $fileName
            if ($null -ne $this.StorageAccountCtx){
                Set-AzStorageBlobContent -Container $this.Container -File (Join-Path $this.AzSKTempStatePath $fileName) -Blob $fileName -Context $this.StorageAccountCtx -Force
            }
            if ($null -ne $this.ReportStorageAccountCtx){
                Set-AzStorageBlobContent -Container $this.ReportContainer -File (Join-Path $this.AzSKTempStatePath $fileName) -Blob $fileName -Context $this.ReportStorageAccountCtx -Force
            }        
        }
    }
  
    hidden [bool] FetchSvcConnMapping() {  
        $svcConnSTMapping = @{
            data = @();
        };
        try{
            $serviceEndpointURL = ("https://dev.azure.com/{0}/{1}/_apis/serviceendpoint/endpoints?api-version=6.0-preview.4") -f $this.OrgName, $this.ProjectName;
            $serviceEndpointObj = [WebRequestHelper]::InvokeGetWebRequest($serviceEndpointURL)

            $Connections = $null
            if (([Helpers]::CheckMember($serviceEndpointObj, "count") -and $serviceEndpointObj[0].count -gt 0) -or (($serviceEndpointObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($serviceEndpointObj[0], "name"))) {
                $Connections = $serviceEndpointObj
            }

            $this.PublishCustomMessage(([Constants]::DoubleDashLine))
            $this.PublishCustomMessage("Generating service mappings of service connections for project [$($this.ProjectName)]...")
            $this.PublishCustomMessage("Total service connections to be mapped:  $(($Connections | Measure-Object).Count)")
            $counter = 0
            
            $apiURL = "https://{0}.visualstudio.com/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $this.OrgName
            $sourcePageUrl = "https://{0}.visualstudio.com/{1}/_settings/adminservices" -f $this.OrgName, $this.ProjectName;

            #generate access token with datastudio api audience
            $accessToken = [ContextHelper]::GetDataExplorerAccessToken($false)

            $Connections | ForEach-Object {
                $counter++            
                Write-Progress -Activity 'Service connection mappings...' -CurrentOperation $_.Name -PercentComplete (($counter / $Connections.count) * 100)                            
                $inputbody = "{'contributionIds':['ms.vss-serviceEndpoints-web.service-endpoints-details-data-provider'],'dataProviderContext':{'properties':{'serviceEndpointId':'$($_.id)','projectId':'$($this.projectId)','sourcePage':{'url':'$($sourcePageUrl)','routeId':'ms.vss-admin-web.project-admin-hub-route','routeValues':{'project':'$($this.ProjectName)','adminPivot':'adminservices','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json
                $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL, $inputbody); 
                
                try {
                    if ([Helpers]::CheckMember($responseObj, "dataProviders") -and $responseObj.dataProviders."ms.vss-serviceEndpoints-web.service-endpoints-details-data-provider") {
                    
                        #set true when STMapping not found in build & release STData files and need to recheck for azurerm type 
                        $unmappedSerConn = $true;                   
    
                        $serviceConnEndPointDetail = $responseObj.dataProviders."ms.vss-serviceEndpoints-web.service-endpoints-details-data-provider"
                        if ($serviceConnEndPointDetail -and [Helpers]::CheckMember($serviceConnEndPointDetail, "serviceEndpointExecutionHistory") ) {
                            $svcConnJobs = $serviceConnEndPointDetail.serviceEndpointExecutionHistory.data
    
                            #Arranging in descending order of run time.
                            $svcConnJobs = $svcConnJobs | Sort-Object startTime -Descending
                            #Taking Unique runs
                            $svcConnJobs = $svcConnJobs | Select-Object @{l = 'id'; e ={$_.definition.id}}, @{l = 'name'; e ={$_.definition.name}}, @{l = 'planType'; e ={$_.planType}} -Unique
                                            
                            foreach ($job in $svcConnJobs)
                            {                         
                                if ($job.planType -eq "Build") {
                                    $buildSTData = $this.BuildSTDetails.Data | Where-Object { ($_.buildDefinitionID -eq $job.id) };
                                    if($buildSTData){
                                        $svcConnSTMapping.data += @([PSCustomObject] @{ serviceConnectionName = $_.Name; serviceConnectionID = $_.id; serviceID = $buildSTData.serviceID; projectName = $buildSTData.projectName; projectID = $buildSTData.projectID; orgName = $buildSTData.orgName } )
                                        $unmappedSerConn = $false; 
                                        break;
                                    }                                   
                                    
                                }
                                elseif ($job.planType -eq "Release") {
                                    $releaseSTData = $this.ReleaseSTDetails.Data | Where-Object { ($_.releaseDefinitionID -eq $job.id)};
                                    if($releaseSTData){
                                        $svcConnSTMapping.data += @([PSCustomObject] @{ serviceConnectionName = $_.Name; serviceConnectionID = $_.id; serviceID = $releaseSTData.serviceID; projectName = $releaseSTData.projectName; projectID = $releaseSTData.projectID; orgName = $releaseSTData.orgName } )
                                        $unmappedSerConn = $false; 
                                        break;
                                    }                                  
                                }
                            }
                        }
                        if($serviceConnEndPointDetail -and $unmappedSerConn) 
                        {
                            if ($serviceConnEndPointDetail.serviceEndpoint.type -eq "azurerm")
                            {
                                try {                                
                                    $responseObj = $this.GetServiceIdWithSubscrId($serviceConnEndPointDetail.serviceEndpoint.data.subscriptionId,$accessToken)                       
                                    if($responseObj)
                                    {
                                          $serviceId = $responseObj[2].Rows[0][4];
                                          $svcConnSTMapping.data += @([PSCustomObject] @{ serviceConnectionName = $_.Name; serviceConnectionID = $_.id; serviceID = $serviceId; projectName =  $_.serviceEndpointProjectReferences.projectReference.name; projectID = $_.serviceEndpointProjectReferences.projectReference.id; orgName = $this.OrgName } )                                    
                                    }
                                }
                                catch {
                                    
                                }                             
    
                            }   
                        }
                    }
                }
                catch {
                     #eat exception
                }               
            }
        }
        catch
        {
            #eat exception
        }
        $this.PublishCustomMessage("Service mapping found:  $(($svcConnSTMapping.data | Measure-Object).Count)", [MessageType]::Info)
        if($this.UseCache)
        {            
            $this.ExportObjToJsonFile($svcConnSTMapping.data, 'ServiceConnectionSTData.json');
            $this.ExportObjToJsonFileUploadToBlob($svcConnSTMapping.data, 'ServiceConnectionSTData.json');
        }
        return $true;
    }

    hidden [bool] FetchAgentPoolMapping() {
        $agentPoolSTMapping = @{
            data = @();
        };

        try{
            $agentPoolsDefnURL = ("https://{0}.visualstudio.com/{1}/_settings/agentqueues?__rt=fps&__ver=2") -f $this.OrgName, $this.ProjectName;
            $agentPoolsDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($agentPoolsDefnURL);
            #generate access token with datastudio api audience
            $accessToken = [ContextHelper]::GetDataExplorerAccessToken($false)
            $taskAgentQueues = $null;           

            if (([Helpers]::CheckMember($agentPoolsDefnsObj, "fps.dataProviders.data") ) -and (($agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider") -and $agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider".taskAgentQueues)) {
                $taskAgentQueues = $agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider".taskAgentQueues | where-object{$_.pool.isLegacy -eq $false}; 
            }
            
            $this.PublishCustomMessage(([Constants]::DoubleDashLine))
            $this.PublishCustomMessage("Generating service mappings of agent pool for project [$($this.ProjectName)]...")
            $this.PublishCustomMessage("Total agent pool to be mapped:  $(($taskAgentQueues | Measure-Object).Count)")
            $counter = 0

            $taskAgentQueues | ForEach-Object {
                $counter++
                Write-Progress -Activity 'Agent pool mappings...' -CurrentOperation $_.Name -PercentComplete (($counter / $taskAgentQueues.count) * 100)
                $unmappedAgentPool = $true;
                $agtPoolId = $_.id
                $agtPoolName = $_.name
                $agentPoolsURL = "https://{0}.visualstudio.com/{1}/_settings/agentqueues?queueId={2}&__rt=fps&__ver=2" -f $this.orgName, $this.ProjectName, $agtPoolId
                $agentPool = [WebRequestHelper]::InvokeGetWebRequest($agentPoolsURL);

                if (([Helpers]::CheckMember($agentPool[0], "fps.dataProviders.data") ) -and ($agentPool[0].fps.dataProviders.data."ms.vss-build-web.agent-jobs-data-provider")) {
                    $agentPoolJobs = $agentPool[0].fps.dataProviders.data."ms.vss-build-web.agent-jobs-data-provider".jobs | Where-Object { $_.scopeId -eq $this.ProjectId };

                    #Arranging in descending order of run time.
                    $agentPoolJobs = $agentPoolJobs | Sort-Object queueTime -Descending
                    #Taking unique runs
                    $agentPoolJobs = $agentPoolJobs | Select-Object @{l = 'id'; e ={$_.definition.id}}, @{l = 'name'; e ={$_.definition.name}}, @{l = 'planType'; e ={$_.planType}} -Unique
                    #If agent pool has been queued at least once

                    foreach ($job in $agentPoolJobs){
                        if ($job.planType -eq "Build") {
                            $buildSTData = $this.BuildSTDetails.data | Where-Object { ($_.buildDefinitionID -eq $job.id)};
                            if($buildSTData){
                                $agentPoolSTMapping.data += @([PSCustomObject] @{ agentPoolName = $_.Name; agentPoolID = $_.id; serviceID = $buildSTData.serviceID; projectName = $buildSTData.projectName; projectID = $buildSTData.projectID; orgName = $buildSTData.orgName } )
                                $unmappedAgentPool = $false;
                                break;
                            }
                        }
                        elseif ($job.planType -eq "Release") {
                            $releaseSTData = $this.ReleaseSTDetails.data | Where-Object { ($_.releaseDefinitionID -eq $job.id)};
                            if($releaseSTData){
                                $agentPoolSTMapping.data += @([PSCustomObject] @{ agentPoolName = $_.Name; agentPoolID = $_.id; serviceID = $releaseSTData.serviceID; projectName = $releaseSTData.projectName; projectID = $releaseSTData.projectID; orgName = $releaseSTData.orgName } )
                                $unmappedAgentPool = $false;
                                break;
                            }
                        }
                    }
                }
                if($unmappedAgentPool)
                {
                    $agentList = $agentPool[0].fps.dataProviders.data."ms.vss-build-web.agent-pool-data-provider".agents;
                    $exit = $false
                    $agentList | Where-Object {$exit -eq $false} | ForEach-Object {                                                
                        $agtName = $_.Name 
                        $responseObj = $this.GetAgentSubscrId($agtName)
                        if($responseObj)
                        {
                           $logsRows = $responseObj.tables[0].rows;
                           if($logsRows.count -gt 0){
                               $agentSubscriptionID = $logsRows[0][18];
                               try {
                                        $response = $this.GetServiceIdWithSubscrId($agentSubscriptionID,$accessToken)                               
                                        if($response){
                                                $serviceId = $response[2].Rows[0][4];
                                                $agentPoolSTMapping.data += @([PSCustomObject] @{ agentPoolName = $agtPoolName; agentPoolID = $agtPoolId; serviceID = $serviceId; projectName = $this.projectName; projectID = $this.projectId; orgName = $organizationName } );
                                                $exit = $true
                                            } 
                                    }
                              catch {
                                }                                
                           }
                        }                                                
                    }
                }
            }
        }
        catch
        {
            #eat exception
        }
        $this.PublishCustomMessage("Service mapping found:  $(($agentPoolSTMapping.data | Measure-Object).Count)", [MessageType]::Info)
        if($this.UseCache)
        {            
            $this.ExportObjToJsonFile($agentPoolSTMapping.data, 'AgentPoolSTData.json');
            $this.ExportObjToJsonFileUploadToBlob($agentPoolSTMapping.data, 'AgentPoolSTData.json');
        }
        return $true;
    }

    hidden [bool] FetchVarGrpSecureFileMapping() {  
      
        $topNQueryString = '&$top=10000'
        $varGrps = @();
        $secureFiles = @();
        $secureFileDetails = @();
        #generate access token with datastudio api audience
        $accessToken = [ContextHelper]::GetDataExplorerAccessToken($false)
        $variableGroupSTMapping = @{
            data = @();
        };

        $secureFileSTMapping = @{
            data = @();
        };

        try {                               
            $releaseDefnURL = ("https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?api-version=6.0" +$topNQueryString) -f $($this.OrgName), $this.ProjectName;
            $releaseDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($releaseDefnURL);            
                
            if (([Helpers]::CheckMember($releaseDefnsObj, "count") -and $releaseDefnsObj[0].count -gt 0) -or (($releaseDefnsObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($releaseDefnsObj[0], "name"))) {
                
                $this.PublishCustomMessage(([Constants]::DoubleDashLine))
                $this.PublishCustomMessage("Generating service mappings of variable group/secure file using release for project [$($this.ProjectName)]...")
                $this.PublishCustomMessage("Total mappings to be evaluated:  $(($releaseDefnsObj | Measure-Object).Count)")
                $counter = 0

                #This variable is used to store details returned from secure file api(fetching all the secure file details in one call)
                $secureFileDetails = @();

                if (($secureFileDetails | Measure-Object).count -eq 0) {
                    $secureFilesURL = "https://dev.azure.com/{0}/{1}/_apis/distributedtask/securefiles?api-version=6.1-preview.1" -f $this.OrgName, $this.projectId;
                    $secureFileDetails = [WebRequestHelper]::InvokeGetWebRequest($secureFilesURL);
                }

                foreach ($relDef in $releaseDefnsObj) 
                {                   
                    $counter++
                    Write-Progress -Activity 'Variable group/secure file mappings via release...' -CurrentOperation $relDef.Name -PercentComplete (($counter / $releaseDefnsObj.count) * 100)                                                                                            
                    try
                    {
                        $releaseObj = [WebRequestHelper]::InvokeGetWebRequest($relDef.url);
                        
                        #add var groups scoped at release scope.
                        if ($this.MappingType -eq "All" -or $this.MappingType -eq "VariableGroup") {
                            if((($releaseObj[0].variableGroups) | Measure-Object).Count -gt 0)
                            {
                                $varGrps += $releaseObj[0].variableGroups
                            }
                        }

                        #get var grps from each env of release pipeline                        
                        foreach ($env in $releaseObj[0].environments) {
                            if ($this.MappingType -eq "All" -or $this.MappingType -eq "VariableGroup") {
                                if((($env.variableGroups) | Measure-Object).Count -gt 0)
                                {
                                    $varGrps += $env.variableGroups
                                }
                            }

                            try {
                                if ($this.MappingType -eq "All" -or $this.MappingType -eq "SecureFile") {
                                    $workflowtasks = @();
                                    if([Helpers]::CheckMember($env, "deployPhases") )
                                    {
                                        foreach ($deployPhase in $env.deployPhases) {
                                            if ([Helpers]::CheckMember($deployPhase,"workflowtasks")) {
                                                foreach ($workflowtask in $deployPhase.workflowtasks) {
                                                    $workflowtasks += $workflowtask;   
                                                }
                                            }
                                        }
                                    }
                                    foreach ($item in $workflowtasks) {
                                        if ([Helpers]::CheckMember($item, "inputs") -and [Helpers]::CheckMember($item.inputs, "secureFile")) {
                                            $secureFiles += $item.inputs.secureFile;
                                        }
                                    }
                                }
                            }
                            catch {
                                #eat exception
                            } 
                            if($this.UseCache)
                            {
                                # Find Service tree id for variable groups from cache 
                                $this.FindSTWithReleaseForVGSecFileCache($relDef, $varGrps, $secureFiles,$accessToken,$secureFileDetails,$variableGroupSTMapping, $secureFileSTMapping)
                            }
                            else {
                                $this.FindSTWithReleaseForVGSecFile($relDef, $varGrps, $secureFiles,$accessToken,$secureFileDetails,$variableGroupSTMapping, $secureFileSTMapping)
                            }
                        }
                    }
                    Catch{
                        #$this.PublishCustomMessage($_.Exception.Message)
                    }
                }               
                $releaseDefnsObj = $null;
            }
        }
        catch{
            #eat exception
        }

        try {
            $buildDefnURL = ("https://dev.azure.com/{0}/{1}/_apis/build/definitions?queryOrder=lastModifiedDescending&api-version=6.0" + $topNQueryString) -f $($this.OrgName), $this.ProjectName;
            $buildDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($buildDefnURL) 
            
            if (([Helpers]::CheckMember($buildDefnsObj, "count") -and $buildDefnsObj[0].count -gt 0) -or (($buildDefnsObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($buildDefnsObj[0], "name"))) {

                $this.PublishCustomMessage(([Constants]::DoubleDashLine))
                $this.PublishCustomMessage("Generating service mappings of variable group/secure file using build for project [$($this.ProjectName)]...")
                $this.PublishCustomMessage("Total mappings to be evaluated:  $(($buildDefnsObj | Measure-Object).Count)")
                $counter = 0

                foreach ($bldDef in $buildDefnsObj) {
                    $counter++
                    Write-Progress -Activity 'Variable group/secure file mappings via build...' -CurrentOperation $bldDef.Name -PercentComplete (($counter / $buildDefnsObj.count) * 100)

                    $buildObj = [WebRequestHelper]::InvokeGetWebRequest($bldDef.url.split('?')[0]);

                    $secureFiles = @();
                    #getting secure files added in all the tasks.
                    try {
                        if ($this.MappingType -eq "All" -or $this.MappingType -eq "SecureFile") {
                            $tasksSteps =@()
                            if([Helpers]::CheckMember($buildObj, "process") -and [Helpers]::CheckMember($buildObj.process, "Phases") )
                            {
                                foreach ($item in $buildObj.process.Phases) {
                                    if ([Helpers]::CheckMember($item, "steps")) {
                                        $tasksSteps += $item.steps;
                                    }
                                } 
                            }
                            foreach ($itemStep in $tasksSteps) {
                                if ([Helpers]::CheckMember($itemStep, "inputs") -and [Helpers]::CheckMember($itemStep.inputs, "secureFile")) {
                                    $secureFiles += $itemStep.inputs.secureFile;
                                }
                            }
                        }
                    }
                    catch {
                        #eat exception
                    }
                    if($this.UseCache)
                    {
                        # Find Service tree id for variable groups from cache
                        $this.FindSTWithBuildForVGSecFileCache($buildObj, $secureFiles, $accessToken, $secureFileDetails, $variableGroupSTMapping, $secureFileSTMapping)
                    }
                    else {                        
                        $this.FindSTWithBuildForVGSecFile($buildObj, $secureFiles, $accessToken, $secureFileDetails, $variableGroupSTMapping, $secureFileSTMapping)
                    }                                                                                           
                }
                $buildDefnsObj = $null;
            }
        }
        catch{
            #eat exception
        }
          #Removing duplicate entries of the tuple (variableGroupId,serviceId)
            if ($this.MappingType -eq "All" -or $this.MappingType -eq "VariableGroup") {
                $variableGroupSTMapping.data = $variableGroupSTMapping.data | Sort-Object -Unique variableGroupID,serviceID
                $this.PublishCustomMessage("Service mapping found:  $(($variableGroupSTMapping.data | Measure-Object).Count)", [MessageType]::Info)
                if($this.UseCache)
                {          
                    $this.ExportObjToJsonFile($variableGroupSTMapping.data, 'VariableGroupSTData.json');
                    $this.ExportObjToJsonFileUploadToBlob($variableGroupSTMapping.data, 'VariableGroupSTData.json');
                }
            }
            #Removing duplicate entries of the tuple (securefile,serviceId)
            if ($this.MappingType -eq "All" -or $this.MappingType -eq "SecureFile") {
                $secureFileSTMapping.data = $secureFileSTMapping.data | Sort-Object -Unique secureFileID,serviceID
                $this.PublishCustomMessage("Service mapping found:  $(($secureFileSTMapping.data | Measure-Object).Count)", [MessageType]::Info)
                if($this.UseCache)
                { 
                    $this.ExportObjToJsonFile($secureFileSTMapping.data, 'SecureFileSTData.json');
                    $this.ExportObjToJsonFileUploadToBlob($secureFileSTMapping.data, 'SecureFileSTData.json');
                }
            }        
        return $true;
    }

    hidden [bool] FetchEnvironmentMapping() {  
        $environmentSTMapping = @{
            data = @();
        };
        try{
            $environmentURL = 'https://dev.azure.com/{0}/{1}/_apis/distributedtask/environments?$top=10000&api-version=6.0-preview.1' -f $this.OrgName, $this.ProjectName;
            $environmentsObjList = @([WebRequestHelper]::InvokeGetWebRequest($environmentURL));
            #generate access token with datastudio api audience
            $accessToken = [ContextHelper]::GetDataExplorerAccessToken($false)
            $unmappedEnv = $true;   

            if ($environmentsObjList.count -gt 0 ) {
             
                $this.PublishCustomMessage(([Constants]::DoubleDashLine))
                $this.PublishCustomMessage("Generating service mappings of environments for project [$($this.ProjectName)]...")
                $this.PublishCustomMessage("Total environments to be mapped:  $($environmentsObjList.count)")
                $counter = 0
                
                $environmentsObjList | ForEach-Object{
                    $counter++
                    Write-Progress -Activity 'Environments mappings...' -CurrentOperation $_.Name -PercentComplete (($counter / $environmentsObjList.count) * 100)                   

                    $apiURL = "https://dev.azure.com/{0}/{1}/_apis/distributedtask/environments/{2}/environmentdeploymentrecords?top=20&api-version=6.0-preview.1" -f $this.OrgName, $this.ProjectName, $_.id;
                    $envDeploymenyRecords = @([WebRequestHelper]::InvokeGetWebRequest($apiURL));                     
                    
                    if ($envDeploymenyRecords.Count -gt 0 -and [Helpers]::CheckMember($envDeploymenyRecords[0],"definition")) {

                        foreach ($envJob in $envDeploymenyRecords){
                            if ([Helpers]::CheckMember($envJob, "planType") -and $envJob.planType -eq "Build") {
                                $buildSTData = $this.BuildSTDetails.Data | Where-Object { ($_.buildDefinitionID -eq $envJob.definition.id) };
                                if($buildSTData){
                                    $environmentSTMapping.data += @([PSCustomObject] @{ environmentName = $_.Name; environmentID = $_.id; serviceID = $buildSTData.serviceID; projectName = $buildSTData.projectName; projectID = $buildSTData.projectID; orgName = $buildSTData.orgName } )
                                    $unmappedEnv =$false;
                                    break;
                                }
                                
                            }
                            elseif ([Helpers]::CheckMember($envJob, "planType") -and $envJob.planType -eq "Release") {
                                $releaseSTData = $this.ReleaseSTDetails.Data | Where-Object { ($_.releaseDefinitionID -eq $envJob.definition.id)};
                                if($releaseSTData){
                                    $environmentSTMapping.data += @([PSCustomObject] @{ environmentName = $_.Name; environmentID = $_.id; serviceID = $releaseSTData.serviceID; projectName = $releaseSTData.projectName; projectID = $releaseSTData.projectID; orgName = $releaseSTData.orgName } )
                                    $unmappedEnv =$false;
                                    break;
                                }
                            }
                        }
                    }
                    if($unmappedEnv){
                        $envResourceApiURL = "https://dev.azure.com//{0}/{1}/_environments/{2}?view=resources&__rt=fps&__ver=2" -f $this.OrgName, $this.ProjectName, $_.id;
                        $envResourceDetails = @([WebRequestHelper]::InvokeGetWebRequest($envResourceApiURL)); 

                        if ([Helpers]::CheckMember($envResourceDetails, "fps.dataProviders") -and $envResourceDetails.fps.dataProviders.data."ms.vss-environments-web.environment-resources-view-data-provider") {
                            # Type 2 for VM
                           $vmName =  $envResourceDetails.fps.dataProviders.data."ms.vss-environments-web.environment-resources-view-data-provider".environment.resources | Where-Object type -eq 2 | Select-Object name;
                           if($vmName){
                            $responseObj = $this.GetAgentSubscrId($vmName)
                                if($responseObj)
                                {
                                    $logsRows = $responseObj.tables[0].rows;
                                    if($logsRows.count -gt 0){
                                        $agentSubscriptionID = $logsRows[0][18];
                                        try {
                                                $response = $this.GetServiceIdWithSubscrId($agentSubscriptionID,$accessToken)                               
                                                if($response){
                                                        $serviceId = $response[2].Rows[0][4];
                                                        $environmentSTMapping.data += @([PSCustomObject] @{ environmentName = $_.Name; environmentID = $_.id; serviceID = $serviceId; projectName = $this.ProjectName; projectID = $this.ProjectId; orgName = $this.OrgName } )
                                                        $unmappedEnv = $false
                                                        break;
                                                    } 
                                                }
                                        catch {
                                            }                                
                                    }
                                }
                           }
                           if($unmappedEnv){
                               # Type 4 for AKS Cluster
                               $clusterId =  $envResourceDetails.fps.dataProviders.data."ms.vss-environments-web.environment-resources-view-data-provider".environment.resources | Where-Object type -eq 4 | Select-Object id;
                               if($clusterId){
                                $clusterApiURL = "https://dev.azure.com/{0}/{1}/_environments/{2}/providers/kubernetes/{3}?__rt=fps&__ver=2" -f $this.OrgName, $this.ProjectName, $_.id, $clusterId;
                                $clusterDetails = @([WebRequestHelper]::InvokeGetWebRequest($clusterApiURL));                             
                                if($clusterDetails -and [Helpers]::CheckMember($clusterDetails.fps.dataProviders.data,"ms.vss-environments-web.kubernetes-resource-data-provider"))
                                {
                                    $subscripId = $clusterDetails.fps.dataProviders.data."ms.vss-environments-web.kubernetes-resource-data-provider".kubernetesEndpoint.data | Where-Object authorizationType -eq "AzureSubscription" | Select-Object azureSubscriptionId;                                    
                                    if($subscripId){
                                        $response = $this.GetServiceIdWithSubscrId($subscripId,$accessToken)                                                                     
                                        if($response){
                                                $serviceId = $response[2].Rows[0][4];
                                                $environmentSTMapping.data += @([PSCustomObject] @{ environmentName = $_.Name; environmentID = $_.id; serviceID = $serviceId; projectName = $this.ProjectName; projectID = $this.ProjectId; orgName = $this.OrgName } )
                                                break;
                                            }                                                                                                                     
                                    }
                                }
                               }
                           }
                        }
                    }
                    
                }
            }
        }
        catch
        {
            #eat exception
        }
        $this.PublishCustomMessage("Service mapping found:  $(($environmentSTMapping.data | Measure-Object).Count)", [MessageType]::Info)
        if($this.UseCache)
        {            
            $this.ExportObjToJsonFile($environmentSTMapping.data, 'EnvironmentSTData.json');
            $this.ExportObjToJsonFileUploadToBlob($environmentSTMapping.data, 'EnvironmentSTData.json');
        }
        return $true;
    }

    hidden [bool] FetchFeedMapping() {  
        $feedSTMapping = @{
            data = @();
        };
        $feedDefnURL = 'https://feeds.dev.azure.com/{0}/{1}/_apis/packaging/feeds?api-version=6.0-preview.1' -f $this.OrgName, $this.ProjectName;
        $feedDefnsObj = @([WebRequestHelper]::InvokeGetWebRequest($feedDefnURL));
        
        if ($feedDefnsObj.count -gt 0 ) {
             
                $this.PublishCustomMessage(([Constants]::DoubleDashLine))
                $this.PublishCustomMessage("Generating service mappings of feeds for project [$($this.ProjectName)]...")
                $this.PublishCustomMessage("Total feeds to be mapped:  $($feedDefnsObj.count)")
                $counter = 0
                
                $feedDefnsObj | ForEach-Object {
                    try{

                        $counter++
                        Write-Progress -Activity 'Feeds mappings...' -CurrentOperation $_.Name -PercentComplete (($counter / $feedDefnsObj.count) * 100)

                        $feed = $_;
                        #Get feed packages
                        $packagesURL = $feed._links.packages.href;
                        $feedPackages = @([WebRequestHelper]::InvokeGetWebRequest($packagesURL)); 

                        if ($feedPackages.count -gt 0) {

                            $feedPackages = $feedPackages | Select-Object -First 10;
                            foreach ($package in $feedPackages){
                            $provenanceURL = "https://feeds.dev.azure.com/{0}/{1}/_apis/packaging/Feeds/{2}/Packages/{3}/Versions/{4}/provenance?api-version=6.0-preview.1" -f $this.OrgName, $this.ProjectName, $feed.id, $package.id, $package.versions[0].id;
                            $provenanceObj = @([WebRequestHelper]::InvokeGetWebRequest($provenanceURL)); 

                            if ($provenanceObj.Count -gt 0 -and [Helpers]::CheckMember($provenanceObj[0],"provenance.provenanceSource") -and [Helpers]::CheckMember($provenanceObj[0],"provenance.data")) {
                                if ($provenanceObj[0].provenance.provenanceSource -eq "InternalBuild") {
                                    
                                    $definitionId = $provenanceObj[0].provenance.data."System.DefinitionId";
                                    $buildSTData = $this.BuildSTDetails.Data | Where-Object { $_.buildDefinitionID -eq $definitionId };
                                    if($buildSTData){
                                        $feedSTMapping.data += @([PSCustomObject] @{ feedName = $feed.Name; feedID = $feed.id; serviceID = $buildSTData.serviceID; projectName = $buildSTData.projectName; projectID = $buildSTData.projectID; orgName = $buildSTData.orgName } )
                                        break;
                                    }
                                    #if no details found in buildST file the try in repoST file
                                    if (!$buildSTData -and $this.RepositorySTDetails -and $this.RepositorySTDetails.count -gt 0) {
                                        $repoId = $provenanceObj[0].provenance.data."Build.Repository.Id";
                                        $repoSTData = $this.RepositorySTDetails.Data | Where-Object { ($_.repoID -eq $repoId)};
                                        if($repoSTData){
                                            $feedSTMapping.data += @([PSCustomObject] @{ feedName = $feed.Name; feedID = $feed.id; serviceID = $repoSTData.serviceID; projectName = $repoSTData.projectName; projectID = $repoSTData.projectID; orgName = $repoSTData.orgName } )
                                            break;
                                        }
                                    }
                                } 
                                elseif ($provenanceObj[0].provenance.provenanceSource -eq "InternalRelease") {
                                    $definitionId = $provenanceObj[0].provenance.data."Release.DefinitionId";
                                    $releaseSTData = $this.ReleaseSTDetails.Data | Where-Object { $_.releaseDefinitionID -eq $definitionId };
                                    if($buildSTData){
                                        $feedSTMapping.data += @([PSCustomObject] @{ feedName = $feed.Name; feedID = $feed.id; serviceID = $releaseSTData.serviceID; projectName = $releaseSTData.projectName; projectID = $releaseSTData.projectID; orgName = $releaseSTData.orgName } )
                                        break;                                        
                                    }
                                }  
                            }
                            }
                        }
                    }
                    catch
                    {
                        #eat exception
                    }                   
                }
        }
        $this.PublishCustomMessage("Service mapping found:  $(($feedSTMapping.data | Measure-Object).Count)", [MessageType]::Info)
        if($this.UseCache)
        {            
            $this.ExportObjToJsonFile($feedSTMapping.data, 'FeedSTData.json');
            $this.ExportObjToJsonFileUploadToBlob($feedSTMapping.data, 'FeedSTData.json');
        }
        return $true;
    }

    hidden [object] GetServiceIdWithSubscrId($subscriptionID,$accessToken)
    {
        $response = $null
        try {                     
            # call data studio to fetch azure subscription id and servce id mapping
            $apiURL = "https://datastudiostreaming.kusto.windows.net/v2/rest/query"                                                                    
            $inputbody = '{"db": "Shared","csl": "DataStudio_ServiceTree_AzureSubscription_Snapshot | where SubscriptionId contains ''{0}''", "properties": {"Options": {"query_language": "csl","servertimeout": "00:04:00","queryconsistency": "strongconsistency","request_readonly": false,"request_readonly_hardline": false}}}'                                            
            $inputbody = $inputbody.Replace("{0}", $subscriptionID)                                                                                        
            $header = @{
                            "Authorization" = "Bearer " + $accessToken
                        }
            $response = [WebRequestHelper]::InvokeWebRequest([Microsoft.PowerShell.Commands.WebRequestMethod]::Post,$apiURL,$header,$inputbody,"application/json; charset=UTF-8");                             
        }
        catch {
            
        }  
        return $response     
    }

    hidden [object] GetAgentSubscrId($agentName)
    {
        $response = $null
        try {                                  
            
            #generate access token with datastudio api audience             
            $accessToken = [ContextHelper]::GetLAWSAccessToken()
            # call data studio to fetch azure subscription id and servce id mapping
            $apiURL = "https://api.loganalytics.io/v1/workspaces/b32a5e40-0360-40db-a9d4-ec1083b90f0a/query?timespan=P7D"                                                                    
            $inputbody = '{"query":"AzSK_ResourceInvInfo_CL| where Name_s =~ ''{0}''| where ResourceType == ''Microsoft.Compute/virtualMachines''","options":{"truncationMaxSize":67108864},"maxRows":30001,"workspaceFilters":{"regions":[]}}'                                       
            $inputbody = $inputbody.Replace("{0}", $agentName)
            $header = @{
                "Authorization" = "Bearer " + $accessToken
            }                             
            $response = [WebRequestHelper]::InvokeWebRequest([Microsoft.PowerShell.Commands.WebRequestMethod]::Post,$apiURL,$header,$inputbody,"application/json; charset=UTF-8");                           
        }
        catch {
            
        }  
        return $response     
    }

    hidden [object] GetBuildReleaseObjects($resourceUrl,$resourceType)
    {        
        $skipCount = 0        
        $applicableDefnsObj=@();     
        while (($resourceUrl)) 
        {              
            $skipCount = 10000;
            $responseAndUpdatedUri = [WebRequestHelper]::InvokeWebRequestForResourcesInBatch($resourceUrl, $resourceUrl, $skipCount,$resourceType);
            #API response with resources
            $resourceDefnsObj = @($responseAndUpdatedUri[0]);           
            #updated URI: null when there is no continuation token
            $resourceDfnUrl = $responseAndUpdatedUri[1];           
            $applicableDefnsObj+=$resourceDefnsObj;            
            if ( (($applicableDefnsObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($applicableDefnsObj[0], "name")) -or ([Helpers]::CheckMember($applicableDefnsObj, "count") -and $applicableDefnsObj[0].count -gt 0)) 
            {                
                $resourceUrl =$resourceDfnUrl;                                                                      
            }
            else {
                break;
            }           
        }
        Write-Progress -Activity "All $($resourceType)s fetched" -Status "Ready" -Completed
        $resourceDefnsObj = $null;        
        Remove-Variable resourceDefnsObj;        
        return $applicableDefnsObj;
    }

    #adding new mapping info
    hidden [void] AddMappinginfoInCache( [string]  $orgName, [string]  $projectID, [string]  $pipelineID, [string]  $serviceTreeID,[string]  $pipelineLastModified,[string]  $resourceID,[string]  $resourceName,[string]  $resourceType,[string]  $pipelineType,$mappingExpiration) 
    {     
        if($this.IncrementalScan){
            $hash = $this.ServiceMappingCacheHelperObj.GetHashedTag($this.projectId, "", "",$resourceID,$resourceType) 
        }
        else{
            $hash = $this.ServiceMappingCacheHelperObj.GetHashedTag($this.projectId, $pipelineID, $pipelineType,$resourceID,$resourceType) 
        }        
        $resourceInCache = $this.GetResourceDataFromCache($pipelineType,$pipelineID,$resourceType, $resourceID)
        if($resourceInCache)
        {
            $this.ServiceMappingCacheHelperObj.UpdateTableEntity($orgName,$projectID,$pipelineID,$serviceTreeID,$pipelineLastModified, $resourceID, $resourceType, $resourceName, $pipelineType,$mappingExpiration, $this.IncrementalScan)
            #update mapping expiration date as per new scan           
            $rowIndex = [array]::IndexOf($this.storageCachedData.RowKey,$hash)
            $this.storageCachedData[$rowIndex].MappingExpiration = $mappingExpiration            
        }
        else {
            $this.ServiceMappingCacheHelperObj.InsertMappingInfoInTable($orgName,$projectID,$pipelineID,$serviceTreeID,$pipelineLastModified,$resourceID,$resourceType,$resourceName,$pipelineType, $mappingExpiration, $this.IncrementalScan)
            #update in-memory cache with new record             
            $this.storageCachedData+=  @([PSCustomObject] @{"RowKey" =$hash; "OrgName" = $orgName; "ProjectID" = $projectID; "PipelineID" = $pipelineID;"ServiceTreeID" = $serviceTreeID;"PipelineLastModified" = $pipelineLastModified;"ResourceID" = $resourceID;"ResourceType" = $resourceType;"ResourceName" = $resourceName;"PipelineType" = $pipelineType;  "MappingExpiration" = $MappingExpiration}; ) 
        }        
    }
    
    #fetch resource mapping details from in-memory collection
    hidden [object] GetResourceDataFromCache($pipelineType,$pipelineID,$resourceType, $resourceID)
    {  
        $resourceItem =@()         
        if($this.IncrementalScan){
            $hash = $this.ServiceMappingCacheHelperObj.GetHashedTag($this.projectId, "", "",$resourceID,$resourceType) 
        }
        else{
            $hash = $this.ServiceMappingCacheHelperObj.GetHashedTag($this.projectId, $pipelineID, $pipelineType,$resourceID,$resourceType) 
        }         
        $item = $this.storageCachedData | Where-Object -Property RowKey -eq $hash 
        if($item){
            return $item
        }   
        return  $resourceItem            
    }

    # attribution of variable group/ secure file linked with build
    hidden [void] FindSTWithBuildForVGSecFile($buildObj, $secureFiles, $accessToken, $secureFileDetails, $variableGroupSTMapping, $secureFileSTMapping)
    {    
         #Variable to store current build STDATA
         $buildSTData = $null;

        if ($this.MappingType -eq "All" -or $this.MappingType -eq "VariableGroup") {
            if([Helpers]::CheckMember($buildObj[0],"variableGroups"))
            {
                $varGrps = @($buildObj[0].variableGroups)

                $apiURL = "https://{0}.visualstudio.com/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $this.OrgName
                $sourcePageUrl = "https://{0}.visualstudio.com/{1}/_settings/adminservices" -f $this.OrgName, $this.ProjectName;

                $varGrps | ForEach-Object {
                    try {
                        $buildSTData = $this.BuildSTDetails.Data | Where-Object { ($_.buildDefinitionID -eq $buildObj[0].id) -and ($_.projectName -eq $this.ProjectName) };
                        if($buildSTData)
                        {
                            $variableGroupSTMapping.data += @([PSCustomObject] @{ variableGroupName = $_.name; variableGroupID = $_.id; serviceID = $buildSTData.serviceID; projectName = $buildSTData.projectName; projectID = $buildSTData.projectID; orgName = $buildSTData.orgName } )
                            # add variable group mapping details in cache
                            $this.AddMappinginfoInCache($buildSTData.orgName,$buildSTData.projectID,$buildObj.id, $buildSTData.serviceID,$buildObj.createdDate,$_.id,"VariableGroup","Build",(Get-date).AddDays($this.MappingExpirationLimit)); 
                        }
                        else  {
                            if ($varGrps.Type -eq 'AzureKeyVault')
                            {   
                                try {
                                    # get associated service connection id for variable group                 
                                    $servConnID =  $varGrps[0].providerData.serviceEndpointId;  
                                    
                                    # get azure subscription id from service connection                                      
                                    $inputbody = "{'contributionIds':['ms.vss-serviceEndpoints-web.service-endpoints-details-data-provider'],'dataProviderContext':{'properties':{'serviceEndpointId':'$($servConnID)','projectId':'$($this.projectId)','sourcePage':{'url':'$($sourcePageUrl)','routeId':'ms.vss-admin-web.project-admin-hub-route','routeValues':{'project':'$($this.ProjectName)','adminPivot':'adminservices','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json
                                    $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL, $inputbody); 

                                    if ([Helpers]::CheckMember($responseObj, "dataProviders") -and $responseObj.dataProviders."ms.vss-serviceEndpoints-web.service-endpoints-details-data-provider") 
                                    {
                                        $serviceConnEndPointDetail = $responseObj.dataProviders."ms.vss-serviceEndpoints-web.service-endpoints-details-data-provider"
                                        if ($serviceConnEndPointDetail.serviceEndpoint.type -eq "azurerm")
                                        {
                                            try {
                                                $responseObj = $this.GetServiceIdWithSubscrId($serviceConnEndPointDetail.serviceEndpoint.data.subscriptionId,$accessToken)                                
                                                if($responseObj)
                                                {
                                                        $serviceId = $responseObj[2].Rows[0][4];  
                                                        $projectID = $serviceConnEndPointDetail.serviceEndpoint.serviceEndpointProjectReferences.projectReference.id;                                                  
                                                        $variableGroupSTMapping.data += @([PSCustomObject] @{ variableGroupName = $_.name; variableGroupID = $_.id; serviceID = $serviceId; projectName = $serviceConnEndPointDetail.serviceEndpoint.serviceEndpointProjectReferences.projectReference.name; projectID = $projectID; orgName = $this.OrgName } )
                                                        # add variable group mapping details in cache
                                                        $this.AddMappinginfoInCache($this.OrgName,$projectID,$buildObj.id, $serviceId,$buildObj.createdDate,$_.id,$_.name,"VariableGroup","Build",(Get-date).AddDays($this.MappingExpirationLimit)); 
                                                }
                                            }
                                            catch {
                                                
                                            }                                           
                                        }  
                                    }
                                    
                                }
                                catch {
                                    
                                }                                            
                            }
                        }                                                                  
                    }
                    catch {
                        
                    }
                                                    
                }
            }
        }
        if ($this.MappingType -eq "All" -or $this.MappingType -eq "SecureFile") {
            try {
                if(($secureFiles | Measure-Object).Count -gt 0)
                {
                $secureFiles | ForEach-Object{                  
                    $secureFile = $_;
                    $secureFilesObj = $secureFileDetails | Where-Object {$_.Name -eq $secureFile -or $_.Id -eq $secureFile}
                    $secFileExistinSt = $secureFileSTMapping.data | Where-Object -Property secureFileID -eq $secureFile
                    if(!$secFileExistinSt)
                    {
                        if ($secureFilesObj) {
                            if (!$buildSTData) {
                                $buildSTData = $this.BuildSTDetails.Data | Where-Object { ($_.buildDefinitionID -eq $buildObj[0].id) -and ($_.projectName -eq $this.ProjectName) };
                            }
                            if($buildSTData){
                                $secureFileSTMapping.data += @([PSCustomObject] @{ secureFileName = $secureFilesObj.name; secureFileID = $secureFilesObj.id; serviceID = $buildSTData.serviceID; projectName = $buildSTData.projectName; projectID = $buildSTData.projectID; orgName = $buildSTData.orgName } )
                                # add secure file mapping details in cache
                                $this.AddMappinginfoInCache($buildSTData.orgName,$buildSTData.projectID,$buildObj.id, $buildSTData.serviceID,$buildObj.createdDate,$secureFilesObj.id,$secureFilesObj.name,"SecureFile","Build",(Get-date).AddDays($this.MappingExpirationLimit)); 
                            }
                        }
                    }
                }
                }
            }
            catch {
                #eat exception
            }
            
        }
    }

    # find cached mappings for variable group/ secure file linked with build
    hidden [void] FindSTWithBuildForVGSecFileCache($buildObj, $secureFiles, $accessToken, $secureFileDetails, $variableGroupSTMapping, $secureFileSTMapping)
    {           
        if ($this.MappingType -eq "All" -or $this.MappingType -eq "VariableGroup") {
            if([Helpers]::CheckMember($buildObj[0],"variableGroups"))
            {
                $varGrps = @($buildObj[0].variableGroups)                                       
                $varGrps | ForEach-Object {
                    try {
                            $varGroupExistinST = $variableGroupSTMapping.data | Where-Object -Property variableGroupID -eq $_
                            if(!$varGroupExistinST)
                            {                           
                                $cachedVGItem = $this.GetResourceDataFromCache("Build",$relDef.id,"VariableGroup", $_)    
                                $variableGroupSTMapping.data += @([PSCustomObject] @{ variableGroupName = $cachedVGItem.ResourceName; variableGroupID = $cachedVGItem.ResourceID; serviceID = $cachedVGItem.ServiceTreeID; projectName = $this.ProjectName; projectID = $cachedVGItem.ProjectID; orgName = $cachedVGItem.OrgName } )                                                                                                                           
                            }
                    }
                    catch {
                        
                    }
                                                    
                }
                
            }
        }
        if ($this.MappingType -eq "All" -or $this.MappingType -eq "SecureFile") {
            try {
                if(($secureFiles | Measure-Object).Count -gt 0)
                {
                $secureFiles | ForEach-Object{
                    $secFileExistinST = $secureFileSTMapping.data | Where-Object -Property secureFileID -eq $_
                    if (!$secFileExistinST) {   
                            $cachedSecFileItem = $this.GetResourceDataFromCache("Build",$relDef.id,"SecureFile", $_)                   
                            $secureFileSTMapping.data += @([PSCustomObject] @{ secureFileName = $cachedSecFileItem.name; secureFileID = $cachedSecFileItem.id; serviceID = $cachedSecFileItem.serviceID; projectName = $this.ProjectName; projectID = $cachedSecFileItem.ProjectID; orgName = $cachedSecFileItem.OrgName } )
                        }                    
                    }
                }
            }
            catch {
                #eat exception
            }
            
        }
    }

    # attribution of variable group/ secure file linked with release
    hidden [void] FindSTWithReleaseForVGSecFile($relDef, $varGrps,$secureFiles,$accessToken, $secureFileDetails , $variableGroupSTMapping, $secureFileSTMapping)
    {
        if ($this.MappingType -eq "All" -or $this.MappingType -eq "VariableGroup") {
            if(($varGrps | Measure-Object).Count)
            {
                $apiURL = "https://{0}.visualstudio.com/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $this.OrgName;
                $sourcePageUrl = "https://{0}.visualstudio.com/{1}/_settings/adminservices" -f $this.OrgName, $this.ProjectName;

                $varGrps | ForEach-Object {
                    try {                                                                            
                        $varGrpURL = ("https://{0}.visualstudio.com/{1}/_apis/distributedtask/variablegroups/{2}?api-version=6.1-preview.2") -f $this.OrgName, $this.projectId, $_;   
                        $varGroupExistinSt = $variableGroupSTMapping.data | Where-Object -Property variableGroupID -eq $_ 
                        $cachedVGItem = $this.GetResourceDataFromCache("Release",$relDef.id,"VariableGroup", $_) 
                        $mappingValid = $false 
                        if($cachedVGItem)
                        {
                            $mappingValid= $cachedVGItem.MappingExpiration -ge (Get-Date).ToUniversalTime().ToString('dd/MM/yyyy HH:mm:ss') -and $cachedVGItem.PipelineLastModified -ge $relDef.modifiedOn
                        }
                        if(!$varGroupExistinSt -and !$mappingValid)                        
                        { 
                            $header = [WebRequestHelper]::GetAuthHeaderFromUri($varGrpURL)                                                                     
                            $varGrpObj  = Invoke-WebRequest -Uri $varGrpURL -Headers $header                                        

                            if($varGrpObj.Content -ne 'null')
                            {
                                    $varGrpObj = $varGrpObj.Content | ConvertFrom-Json
                                    $releaseSTData = $this.ReleaseSTDetails.Data | Where-Object { ($_.releaseDefinitionID -eq $releaseObj[0].id) };
                                    if($releaseSTData)
                                    {
                                        $variableGroupSTMapping.data += @([PSCustomObject] @{ variableGroupName = $varGrpObj.name; variableGroupID = $varGrpObj.id; serviceID = $releaseSTData.serviceID; projectName = $releaseSTData.projectName; projectID = $releaseSTData.projectID; orgName = $releaseSTData.orgName } )
                                        # add variable group mapping details in cache
                                        $this.AddMappinginfoInCache($releaseSTData.orgName,$releaseSTData.projectID,$relDef.id, $releaseSTData.serviceID,$relDef.modifiedOn,$varGrpObj.id,$varGrpObj.name,"VariableGroup","Release",(Get-date).AddDays($this.MappingExpirationLimit));                                        
                                    }
                                    else {
                                        if ($varGrpObj.Type -eq 'AzureKeyVault') { 
                                            try {
                                                # get associated service connection id for variable group                 
                                                $servConnID =  $varGrpObj[0].providerData.serviceEndpointId;  

                                                # get azure subscription id from service connection                                          
                                                $inputbody = "{'contributionIds':['ms.vss-serviceEndpoints-web.service-endpoints-details-data-provider'],'dataProviderContext':{'properties':{'serviceEndpointId':'$($servConnID)','projectId':'$($this.projectId)','sourcePage':{'url':'$($sourcePageUrl)','routeId':'ms.vss-admin-web.project-admin-hub-route','routeValues':{'project':'$($this.ProjectName)','adminPivot':'adminservices','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json
                                                $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL, $inputbody); 
            
                                                if ([Helpers]::CheckMember($responseObj, "dataProviders") -and $responseObj.dataProviders."ms.vss-serviceEndpoints-web.service-endpoints-details-data-provider") 
                                                {
                                                    $serviceConnEndPointDetail = $responseObj.dataProviders."ms.vss-serviceEndpoints-web.service-endpoints-details-data-provider"
                                                    if ($serviceConnEndPointDetail.serviceEndpoint.type -eq "azurerm")
                                                    {
                                                        try {
                                                            $responseObj = $this.GetServiceIdWithSubscrId($serviceConnEndPointDetail.serviceEndpoint.data.subscriptionId,$accessToken)                               
                                                            if($responseObj)
                                                            {
                                                                    $serviceId = $responseObj[2].Rows[0][4];
                                                                    $projectID = $serviceConnEndPointDetail.serviceEndpoint.serviceEndpointProjectReferences.projectReference.id;
                                                                    $variableGroupSTMapping.data += @([PSCustomObject] @{ variableGroupName = $varGrpObj.name; variableGroupID = $varGrpObj.id; serviceID = $serviceId; projectName = $serviceConnEndPointDetail.serviceEndpoint.serviceEndpointProjectReferences.projectReference.name; projectID = $projectID; orgName = $this.OrgName } )
                                                                    # add variable group mapping details in cache
                                                                    $this.AddMappinginfoInCache($this.OrgName,$projectID ,$relDef.id, $serviceId,$relDef.modifiedOn,$varGrpObj.id,$varGrpObj.name,"VariableGroup","Release",(Get-date).AddDays($this.MappingExpirationLimit)); 
                                                            } 
                                                        }
                                                        catch {
                                                            
                                                        }                                          
            
                                                    }  
                                                }
                                                
                                            }
                                            catch {
                                                
                                            }                                         
                                        }                                         
                                    } 
                            }
                        }
                                                    
                    }
                    catch {
                        
                    }                                                                                                          
                }
            }
        }

        if ($this.MappingType -eq "All" -or $this.MappingType -eq "SecureFile") {
            try {
                if(($secureFiles | Measure-Object).Count -gt 0)
                {
                    $secureFiles | ForEach-Object {                    
                    $secureFile = $_;
                    $secureFilesObj = $secureFileDetails | Where-Object {$_.Name -eq $secureFile -or $_.Id -eq $secureFile}
                    $secFileExistinSt = $secureFileSTMapping.data | Where-Object -Property secureFileID -eq $secureFile
                    $cachedSecFileItem = $this.GetResourceDataFromCache("Release",$relDef.id,"SecureFile", $_) 
                    $mappingValid = $false 
                    if($cachedSecFileItem)
                    {
                        $mappingValid = $cachedSecFileItem.MappingExpiration -ge (Get-Date).ToUniversalTime().ToString('dd/MM/yyyy HH:mm:ss') -and  $cachedSecFileItem.PipelineLastModified -ge $relDef.modifiedOn
                    }
                    if(!$secFileExistinSt -and !$mappingValid)
                    {
                        if ($secureFilesObj) {
                            $releaseSTData = $this.ReleaseSTDetails.Data | Where-Object { ($_.releaseDefinitionID -eq $relDef.id) };
                            if($releaseSTData){
                                $secureFileSTMapping.data += @([PSCustomObject] @{ secureFileName = $secureFilesObj.name; secureFileID = $secureFilesObj.id; serviceID = $releaseSTData.serviceID; projectName = $releaseSTData.projectName; projectID = $releaseSTData.projectID; orgName = $releaseSTData.orgName } )
                                # add secure file mapping details in cache
                                $this.AddMappinginfoInCache($releaseSTData.orgName,$releaseSTData.projectID,$relDef.id, $releaseSTData.serviceID,$relDef.modifiedOn,$secureFilesObj.id,$secureFilesObj.name,"SecureFile","Release",(Get-date).AddDays($this.MappingExpirationLimit)); 
                            }
                        }
                    }
                    }
                }
            }
            catch {
                #eat exception
            }
        }  
    }

    # find cached mappings for variable group/ secure file linked with release
    hidden [void] FindSTWithReleaseForVGSecFileCache($relDef, $varGrps,$secureFiles,$accessToken, $secureFileDetails, $variableGroupSTMapping, $secureFileSTMapping)
    {
        if ($this.MappingType -eq "All" -or $this.MappingType -eq "VariableGroup") {
            if(($varGrps | Measure-Object).Count)
            {               
                $varGrps | ForEach-Object {
                    try {                                                                                                                            
                        $varGroupExistinST = $variableGroupSTMapping.data | Where-Object -Property variableGroupID -eq $_
                        if(!$varGroupExistinST)
                        {                           
                            $cachedVGItem = $this.GetResourceDataFromCache("Release",$relDef.id,"VariableGroup", $_)                                                                                                                      
                            $variableGroupSTMapping.data += @([PSCustomObject] @{ variableGroupName = $cachedVGItem.ResourceName; variableGroupID = $cachedVGItem.ResourceID; serviceID = $cachedVGItem.ServiceTreeID; projectName = $this.ProjectName; projectID = $cachedVGItem.ProjectID; orgName = $cachedVGItem.OrgName } )                                                                                                                           
                        }
                                                    
                    }
                    catch {
                        
                    }                                                                                                          
                }
            }
        }

        if ($this.MappingType -eq "All" -or $this.MappingType -eq "SecureFile") {
            try {
                if(($secureFiles | Measure-Object).Count -gt 0)
                {
                    $secureFiles | ForEach-Object {                                        
                    $secureFilesObj = $secureFileSTMapping.data | Where-Object -Property secureFileID -eq $_
                    if (!$secureFilesObj) {   
                            $cachedSecFileItem = $this.GetResourceDataFromCache("Release",$relDef.id,"SecureFile", $_)                       
                            $secureFileSTMapping.data += @([PSCustomObject] @{ secureFileName = $cachedSecFileItem.ResourceName; secureFileID = $cachedSecFileItem.ResourceID; serviceID = $cachedSecFileItem.ServiceTreeID; projectName = $this.ProjectName; projectID = $cachedSecFileItem.projectID; orgName = $cachedSecFileItem.orgName } )
                        }
                    }
                }
            }
            catch {
                #eat exception
            }
        }  
    }

    # log scan time duration for all resources
    hidden [void] SaveScanDuration($message,[switch]  $finished)
    {
        $duration = [math]::Round($this.Stopwatch.Elapsed.TotalMinutes,0)        
        $this.PublishCustomMessage("$($message) :  $($duration)", [MessageType]::Info);
        if($finished)
        {
            $this.PublishCustomMessage("Total duration to finish the resource scan :  $($duration - $this.lastDuration)", [MessageType]::Info);
            $this.lastDuration = $duration
        }
    }
    
    # method to fetch secure file mappings from cloudmine data
    hidden [void] FindSTForSecureFileWithIncremental() {
        $secureFileDetails = @();
        $secureFileSTMapping = @{
            data = [System.Collections.Generic.List[PSCustomObject]]@();
        };
        #get all secure file details in one common object
        if (($secureFileDetails | Measure-Object).count -eq 0) {
            $secureFilesURL = "https://dev.azure.com/{0}/{1}/_apis/distributedtask/securefiles?api-version=6.1-preview.1" -f $this.OrgName, $this.projectId;
            $secureFileDetails = [WebRequestHelper]::InvokeGetWebRequest($secureFilesURL);
        }
        #either retrieve access token for the cluster or use a token via env variable (to be used to generate mappings when user doesn't have access to cluster and can use another authorized token)
        if ($env:AccessToken) {
            $accessToken = $env:AccessToken
        }
        else {
            $accessToken = [ContextHelper]::GetDataExplorerAccessToken($false)
        }
        if ($env:DataDuration) {
            $dataDuration = $env:DataDuration
        }
        else {
            $dataDuration = 30
        }
        $apiURL = "https://1es.kusto.windows.net/v2/rest/query"       
        <#
            Query:
            BuildDefinitionPhaseStep
            | where OrganizationName =~ ""
            | where EtlProcessDate > ago(1500d)
            | where ProjectId ==""
            | extend securefile = parse_json(ProcessPhaseStepInput).secureFile
            | where isnotnull( securefile)
            | summarize arg_max(EtlProcessDate, *) by tostring(securefile)
            | project  securefile, PipelineDefinition = tostring(BuildDefinitionId), EtlProcessDate, PipelineType="Build"
            | union (
            ReleaseEnvironment
            | where OrganizationName =~ ""
            | where EtlProcessDate > ago(1500d)
            | where ProjectId ==""
            | project EtlProcessDate,Data,ReleaseDefinitionId,ReleaseEnvironmentId
            | extend securefile= todynamic(Data)
            | mv-apply securefile on (project securefile.deployPhasesSnapshot)
            | mv-apply securefile_deployPhasesSnapshot on (project securefile_deployPhasesSnapshot.workflowTasks)
            | where isnotnull(securefile_deployPhasesSnapshot_workflowTasks) and isnotempty(securefile_deployPhasesSnapshot_workflowTasks)
            | mv-apply securefile_deployPhasesSnapshot_workflowTasks on (project securefile_deployPhasesSnapshot_workflowTasks.inputs)
            | extend securefilejson = dynamic_to_json(todynamic(securefile_deployPhasesSnapshot_workflowTasks_inputs))
            | extend securefile = parse_json(securefilejson).secureFile
            | where isnotnull( securefile)
            | summarize arg_max(EtlProcessDate, *) by tostring(securefile)
            | project securefile, PipelineDefinition = tostring(ReleaseDefinitionId), EtlProcessDate, PipelineType="Release"
            )
            | summarize arg_max(EtlProcessDate, *) by tostring(securefile)            
        
        #>                                                             
        $inputbody = '{"db":"AzureDevOps","csl":"BuildDefinitionPhaseStep\n| where OrganizationName =~ ''{0}''| where EtlProcessDate > ago({2}d)| where ProjectId ==''{1}'' | extend securefile = parse_json(ProcessPhaseStepInput).secureFile|where isnotnull( securefile)| summarize arg_max(EtlProcessDate, *) by tostring(securefile) | project  securefile, PipelineDefinition = tostring(BuildDefinitionId), EtlProcessDate, PipelineType=\"Build\"\n| union (\nReleaseEnvironment\n| where OrganizationName =~ ''{0}''\n| where EtlProcessDate > ago({2}d)\n| where ProjectId ==''{1}'' \n| project EtlProcessDate,Data,ReleaseDefinitionId,ReleaseEnvironmentId\n| extend securefile= todynamic(Data)\n| mv-apply securefile on (project securefile.deployPhasesSnapshot)\n| mv-apply securefile_deployPhasesSnapshot on (project securefile_deployPhasesSnapshot.workflowTasks)\n| where isnotnull(securefile_deployPhasesSnapshot_workflowTasks) and isnotempty(securefile_deployPhasesSnapshot_workflowTasks)\n| mv-apply securefile_deployPhasesSnapshot_workflowTasks on (project securefile_deployPhasesSnapshot_workflowTasks.inputs)\n| extend securefilejson = dynamic_to_json(todynamic(securefile_deployPhasesSnapshot_workflowTasks_inputs))\n| extend securefile = parse_json(securefilejson).secureFile\n| where isnotnull( securefile)\n| summarize arg_max(EtlProcessDate, *) by tostring(securefile)\n| project securefile, PipelineDefinition = tostring(ReleaseDefinitionId), EtlProcessDate, PipelineType=\"Release\"\n)\n| summarize arg_max(EtlProcessDate, *) by tostring(securefile)","properties":{"Options":{"servertimeout":"00:04:00","queryconsistency":"strongconsistency","query_language":"csl","request_readonly":false,"request_readonly_hardline":false}}}'  
        $inputbody = $inputbody.Replace("{0}", $this.OrgName)   
        $inputbody = $inputbody.Replace("{1}", $this.projectId)       
        $inputbody = $inputbody.Replace("{2}", $dataDuration)                                                                                        
        $header = @{
            "Authorization" = "Bearer " + $accessToken
        }
        try {
            $response = [WebRequestHelper]::InvokeWebRequest([Microsoft.PowerShell.Commands.WebRequestMethod]::Post, $apiURL, $header, $inputbody, "application/json; charset=UTF-8");  
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $progressCount = 1;
            $response[2].Rows | foreach {
                if ($sw.Elapsed.TotalMilliseconds -ge 10000) {
                    Write-Progress -Activity "Processing variable groups... " -Status "Progress: " -PercentComplete ($progressCount / $response[2].Rows.Count * 100)
                    $sw.Reset(); $sw.Start()
                }
                $secureFileId = $_[0].ToString();
                $pipelineId = $_[2].ToString();
                $pipelineProcessDate = $_[1].ToString();
                $secureFileName = $secureFileDetails | Where-Object { $_.Id -eq $secureFileId }
                #check if secure file exists currently or is the data from a deleted secure file
                if ($secureFileName) {
                    $secureFileName = $secureFileName.Name
                }
                else {
                    return;
                }
                $pipelineType = $_[3].ToString();
                #get ST mapping details depending on the pipeline
                if ($pipelineType -eq "Build") {
                    $pipelineSTData = $this.BuildSTDetails.Data | Where-Object { ($_.buildDefinitionID -eq $pipelineId) }     
                }
                else {
                    $pipelineSTData = $this.ReleaseSTDetails.Data | Where-Object { ($_.releaseDefinitionID -eq $pipelineId) }    
                }
                         
                if ($pipelineSTData) {               
                    $this.AddMappinginfoInCache($pipelineSTData.orgName, $pipelineSTData.projectID, $pipelineId, $pipelineSTData.serviceID, $pipelineProcessDate, $secureFileId, $secureFileName, "SecureFile", $pipelineType, (Get-date).AddDays($this.MappingExpirationLimit)); 
                                      
                }  
                
            }
            #The following query is for secure files used in YAML pipelines. A different query has to be made since this query only returns the secure file name as opposed to the secure file ID from above query
            <#
                Query:
                YamlBuildDefinitionPhaseStep
                | where OrganizationName =~ ""
                | where EtlProcessDate > ago(1500d)
                | where StepRefName =~ "DownloadSecureFile@1"
                | extend securefile = parse_json(ProcessPhaseStepInput).secureFile
                | summarize arg_max(EtlProcessDate,*) by tostring(securefile)
            #>
            $inputbody = '{"db":"AzureDevOps","csl":"YamlBuildDefinitionPhaseStep\n| where OrganizationName =~ ''{0}''\n| where EtlProcessDate > ago({2}d)\n| where ProjectId ==''{1}'' | where StepRefName =~ \"DownloadSecureFile@1\"\n| extend securefile = parse_json(ProcessPhaseStepInput).secureFile\n| summarize arg_max(EtlProcessDate,*) by tostring(securefile)","properties":{"Options":{"servertimeout":"00:04:00","queryconsistency":"strongconsistency","query_language":"csl","request_readonly":false,"request_readonly_hardline":false}}}'
            $inputbody = $inputbody.Replace("{0}", $this.OrgName) 
            $inputbody = $inputbody.Replace("{1}", $this.projectId)       
            $inputbody = $inputbody.Replace("{2}", $dataDuration)   
            $response = [WebRequestHelper]::InvokeWebRequest([Microsoft.PowerShell.Commands.WebRequestMethod]::Post, $apiURL, $header, $inputbody, "application/json; charset=UTF-8"); 
            $response[2].Rows | foreach {
                $secureFileName = $_[0].ToString();
                $pipelineId = $_[4].ToString();
                $pipelineProcessDate = $_[1].ToString();
                $secureFileId = $secureFileDetails | Where-Object { $_.Name -eq $secureFileName }
                if ($secureFileId) {
                    $secureFileId = $secureFileId.Id
                }
                else {
                    return;
                }
                $pipelineType = "Build";
                $item = $this.GetResourceDataFromCache($pipelineType, $pipelineId, "SecureFile", $secureFileId)   
                $pipelineSTData = $this.BuildSTDetails.Data | Where-Object { ($_.buildDefinitionID -eq $pipelineId) }  
                #if data is already in the storage, we had found the mapping previously. Update the mapping only if this pipeline was modified recently.
                if ($item) {
                    if ([datetime] $item.PipelineLastModified -gt $pipelineProcessDate) {
                        return;
                    }
                    #if the pipeline was modified recently but the mapping for this new pipeline doesnt exist, do not do anything 
                    if (!$pipelineSTData) {
                        return;
                    }
                }             
                                     
                if ($pipelineSTData) {               
                    $this.AddMappinginfoInCache($pipelineSTData.orgName, $pipelineSTData.projectID, $pipelineId, $pipelineSTData.serviceID, $pipelineProcessDate, $secureFileId, $secureFileName, "SecureFile", $pipelineType, (Get-date).AddDays($this.MappingExpirationLimit)); 
                                      
                }  
                
            }

            #Create the ST mapping file from the storage table
            $this.storageCachedData | foreach {
                $dateDiff = New-TimeSpan -Start ([datetime]$_.Timestamp) -End ([datetime]::UtcNow)
                #if the mapping has been added in the table recently, we need to find the mapping again as it has been already done above
                #if data is not added today, pipeline mapping might have been changed, hence get the mapping again
                if ($dateDiff.Days -gt 1) {
                    if ($_.Pipelinetype -eq "Build") {
                        $pipelineSTData = $this.BuildSTDetails.Data | Where-Object { ($_.buildDefinitionID -eq $_.PipelineID) }     
                    }
                    else {
                        $pipelineSTData = $this.ReleaseSTDetails.Data | Where-Object { ($_.releaseDefinitionID -eq $_.PipelineID) }    
                    }
                    if ($pipelineSTData) {               
                        $this.AddMappinginfoInCache($pipelineSTData.orgName, $pipelineSTData.projectID, $_.PipelineID, $pipelineSTData.serviceID, $_.PipelineLastModified, $_.ResourceID, $_.ResourceName, "SecureFile", $_.PipelineType, (Get-date).AddDays($this.MappingExpirationLimit)); 
                        $secureFileSTMapping.data += @([PSCustomObject] @{ secureFileName = $_.ResourceName; secureFileID = $_.ResourceID; serviceID = $pipelineSTData.serviceID; projectName = $this.ProjectName; projectID = $_.projectID; orgName = $_.orgName } )                    
                    }
                }
                else {
                    $secureFileSTMapping.data += @([PSCustomObject] @{ secureFileName = $_.ResourceName; secureFileID = $_.ResourceID; serviceID = $_.ServiceTreeID; projectName = $this.ProjectName; projectID = $_.projectID; orgName = $_.orgName } )
                }
            }
            $this.PublishCustomMessage("Service mapping found:  $(($secureFileSTMapping.data | Measure-Object).Count)", [MessageType]::Info)
            if ($this.UseCache) { 
                $this.ExportObjToJsonFile($secureFileSTMapping.data, 'SecureFileSTData.json');
                $this.ExportObjToJsonFileUploadToBlob($secureFileSTMapping.data, 'SecureFileSTData.json');
            }
            
        }
        catch {
            $_
        }        
    }

    #method to fetch variable group mappings from cloudmin data
    hidden [void] FindSTForVGWithIncremental() {
        $variableGroupDetails = @();
        $variableGroupSTMapping = @{
            data = [System.Collections.Generic.List[PSCustomObject]]@();
        };
        #get all variable group details in one object
        if (($variableGroupDetails | Measure-Object).count -eq 0) {
            $variableGroupsURL = "https://dev.azure.com/{0}/{1}/_apis/distributedtask/variablegroups?api-version=6.1-preview.1" -f $this.OrgName, $this.projectId;
            $variableGroupDetails = [WebRequestHelper]::InvokeGetWebRequest($variableGroupsURL);
        }
        #either retrieve access token for the cluster or use a token via env variable (to be used to generate mappings when user doesn't have access to cluster and can use another authorized token)
        if ($env:AccessToken) {
            $accessToken = $env:AccessToken
        }
        else {
            $accessToken = [ContextHelper]::GetDataExplorerAccessToken($false)
        }
        if ($env:DataDuration) {
            $dataDuration = $env:DataDuration
        }
        else {
            $dataDuration = 30
        }
        $apiURL = "https://1es.kusto.windows.net/v2/rest/query"    
        <#
            Query:
            BuildDefinition
            | where OrganizationName =~ ""
            | where EtlProcessDate > ago(1000d)
            | where ProjectId ==""
            | extend vargrp = parse_json(Data).variableGroups
            | mv-apply vargrp on (project vargrp.id)
            | where isnotnull( vargrp_id)
            | summarize arg_max(EtlProcessDate, *) by tostring(vargrp_id)
            | project varid = vargrp_id, PipelineId = tostring(BuildDefinitionId), EtlProcessDate, PipelineType = "Build"
            | union(
            Release
            | where OrganizationName =~ ""
            | where EtlProcessDate > ago(1000d)
            | where ProjectId ==""
            | extend varsdetails =  todynamic(Data).variableGroups
            | mv-apply varsdetails on (project varsdetails.id)
            | summarize arg_max(EtlProcessDate, *) by tostring(varsdetails_id)
            | project varid = varsdetails_id, PipelineId = tostring(ReleaseDefinitionId), EtlProcessDate, PipelineType = "Release"
            | union (
            ReleaseEnvironment
            | where OrganizationName =~ ""
            | where EtlProcessDate > ago(1000d)
            | where ProjectId ==""
            | extend varsdetails = todynamic(Data).variableGroups
            | mv-apply varsdetails on (project varsdetails.id)
            | summarize arg_max(EtlProcessDate, *) by tostring(varsdetails_id)
            | project varid = varsdetails_id, PipelineId = tostring(ReleaseDefinitionId), EtlProcessDate, PipelineType = "Release"
            )
            )
            | summarize arg_max(EtlProcessDate, *) by tostring(varid)
        
        #>                                                                
        $inputbody = '{"db":"AzureDevOps","csl":"set notruncation;\nBuildDefinition\n| where OrganizationName =~ ''{0}''\n| where EtlProcessDate > ago({2}d)\n| where ProjectId ==''{1}''\n| extend vargrp = parse_json(Data).variableGroups\n| mv-apply vargrp on (project vargrp.id)\n| where isnotnull( vargrp_id)\n| summarize arg_max(EtlProcessDate, *) by tostring(vargrp_id)\n| project varid = vargrp_id, PipelineId = tostring(BuildDefinitionId), EtlProcessDate, PipelineType = \"Build\"\n| union(\nRelease\n| where OrganizationName =~ ''{0}''\n| where EtlProcessDate > ago({2}d)\n| where ProjectId ==''{1}''\n| extend varsdetails =  todynamic(Data).variableGroups\n| mv-apply varsdetails on (project varsdetails.id)\n| summarize arg_max(EtlProcessDate, *) by tostring(varsdetails_id)\n| project varid = varsdetails_id, PipelineId = tostring(ReleaseDefinitionId), EtlProcessDate, PipelineType = \"Release\"\n| union (\nReleaseEnvironment\n| where OrganizationName =~ ''{0}''\n| where EtlProcessDate > ago({2}d)\n| where ProjectId ==''{1}''\n| extend varsdetails = todynamic(Data).variableGroups\n| mv-apply varsdetails on (project varsdetails.id)\n| summarize arg_max(EtlProcessDate, *) by tostring(varsdetails_id)\n| project varid = varsdetails_id, PipelineId = tostring(ReleaseDefinitionId), EtlProcessDate, PipelineType = \"Release\"\n)\n)\n| summarize arg_max(EtlProcessDate, *) by tostring(varid)","properties":{"Options":{"servertimeout":"00:04:00","queryconsistency":"strongconsistency","query_language":"csl","request_readonly":false,"request_readonly_hardline":false}}}'  
        $inputbody = $inputbody.Replace("{0}", $this.OrgName)  
        $inputbody = $inputbody.Replace("{1}", $this.projectId)       
        $inputbody = $inputbody.Replace("{2}", $dataDuration)                                                                                             
        $header = @{
            "Authorization" = "Bearer " + $accessToken
        }
        try {
            $response = [WebRequestHelper]::InvokeWebRequest([Microsoft.PowerShell.Commands.WebRequestMethod]::Post, $apiURL, $header, $inputbody, "application/json; charset=UTF-8");  
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $progressCount = 1;
            $response[2].Rows | foreach {
                if ($sw.Elapsed.TotalMilliseconds -ge 10000) {
                    Write-Progress -Activity "Processing variable groups... " -Status "Progress: " -PercentComplete ($progressCount / $response[2].Rows.Count * 100)
                    $sw.Reset(); $sw.Start()
                }
                $progressCount++;
                $variableGroupId = $_[0].ToString();                
                $pipelineId = $_[2].ToString();
                $pipelineProcessDate = $_[1].ToString();
                $variableGroupObj = $variableGroupDetails | Where-Object { $_.Id -eq $variableGroupId }
                #check if variable group exists currently or is the data from a deleted variable group
                if ($variableGroupObj) {
                    $variableGroupName = $variableGroupObj.Name
                }
                else {
                    return;
                }
                $pipelineType = $_[3].ToString();  
                if ($pipelineType -eq "Build") {
                    $pipelineSTData = $this.BuildSTDetails.Data | Where-Object { ($_.buildDefinitionID -eq $pipelineId) }     
                }
                else {
                    $pipelineSTData = $this.ReleaseSTDetails.Data | Where-Object { ($_.releaseDefinitionID -eq $pipelineId) }    
                }
                         
                if ($pipelineSTData) {            
                    $this.AddMappinginfoInCache($pipelineSTData.orgName, $pipelineSTData.projectID, $pipelineId, $pipelineSTData.serviceID, $pipelineProcessDate, $variableGroupId, $variableGroupName, "VariableGroup", $pipelineType, (Get-date).AddDays($this.MappingExpirationLimit)); 
                                      
                }  
                #if pipeline ST data not found, attempt to get service id from AZ key vault
                else {
                    if ($variableGroupObj.Type -eq 'AzureKeyVault') { 
                        $apiURL = "https://{0}.visualstudio.com/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $this.OrgName
                        $sourcePageUrl = "https://{0}.visualstudio.com/{1}/_settings/adminservices" -f $this.OrgName, $this.ProjectName;
                        try {
                            # get associated service connection id for variable group                 
                            $servConnID = $variableGroupObj[0].providerData.serviceEndpointId; 
                            # get azure subscription id from service connection                                          
                            $inputbody = "{'contributionIds':['ms.vss-serviceEndpoints-web.service-endpoints-details-data-provider'],'dataProviderContext':{'properties':{'serviceEndpointId':'$($servConnID)','projectId':'$($this.projectId)','sourcePage':{'url':'$($sourcePageUrl)','routeId':'ms.vss-admin-web.project-admin-hub-route','routeValues':{'project':'$($this.ProjectName)','adminPivot':'adminservices','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json
                            $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL, $inputbody); 

                            if ([Helpers]::CheckMember($responseObj, "dataProviders") -and $responseObj.dataProviders."ms.vss-serviceEndpoints-web.service-endpoints-details-data-provider") {
                                $serviceConnEndPointDetail = $responseObj.dataProviders."ms.vss-serviceEndpoints-web.service-endpoints-details-data-provider"
                                if ($serviceConnEndPointDetail.serviceEndpoint.type -eq "azurerm") {
                                    try {
                                        $responseObj = $this.GetServiceIdWithSubscrId($serviceConnEndPointDetail.serviceEndpoint.data.subscriptionId, $accessToken)                               
                                        if ($responseObj) {
                                            $serviceId = $responseObj[2].Rows[0][4];
                                            $this.AddMappinginfoInCache($this.OrgName, $this.projectId, $pipelineId, $serviceID, $pipelineProcessDate, $variableGroupId, $variableGroupName, "VariableGroup", $pipelineType, (Get-date).AddDays($this.MappingExpirationLimit)); 
                                        } 
                                    }
                                    catch {
                                        
                                    }                                          

                                }  
                            }
                            
                        }
                        catch {
                            
                        }                                         
                    } 
                }
                
            }

            #after getting all mappings, create the ST mapping file
            $this.storageCachedData = $this.ServiceMappingCacheHelperObj.GetWorkItemByHashAzureTable("All", "", "", "", $this.projectId)
            $this.storageCachedData | foreach {
                $dateDiff = New-TimeSpan -Start ([datetime]$_.Timestamp) -End ([datetime]::UtcNow)
                if ($dateDiff.Days -gt 1) {
                    if ($_.MappingExpiration -ge (Get-Date).ToUniversalTime().ToString('dd/MM/yyyy HH:mm:ss') {
                            $varGrpObj = $variableGroupDetails | Where-Object { $_.Id -eq $_.ResourceID }
                            if (!$varGrpObj) {
                                #TODO delete the entry
                            }
                            else {
                                #check if pipeline exists according to pipeline type and add it in archive
                            }
                        } 
                        if ($_.Pipelinetype -eq "Build") {
                            $pipelineSTData = $this.BuildSTDetails.Data | Where-Object { ($_.buildDefinitionID -eq $_.PipelineID) }     
                        }
                        else {
                            $pipelineSTData = $this.ReleaseSTDetails.Data | Where-Object { ($_.releaseDefinitionID -eq $_.PipelineID) }    
                        }
                        if ($pipelineSTData) {               
                            $this.AddMappinginfoInCache($pipelineSTData.orgName, $pipelineSTData.projectID, $_.PipelineID, $pipelineSTData.serviceID, $_.PipelineLastModified, $_.ResourceID, $_.ResourceName, "VariableGroup", $_.PipelineType, (Get-date).AddDays($this.MappingExpirationLimit)); 
                            $variableGroupSTMapping.data += @([PSCustomObject] @{ variableGroupName = $_.ResourceName; variableGroupID = $_.ResourceID; serviceID = $pipelineSTData.serviceID; projectName = $this.ProjectName; projectID = $_.projectID; orgName = $_.orgName } )                    
                        }
                    }
                    else {
                        $variableGroupSTMapping.data += @([PSCustomObject] @{ variableGroupName = $_.ResourceName; variableGroupID = $_.ResourceID; serviceID = $_.ServiceTreeID; projectName = $this.ProjectName; projectID = $_.projectID; orgName = $_.orgName } )
                    }
                }
                $this.PublishCustomMessage("Service mapping found:  $(($variableGroupSTMapping.data | Measure-Object).Count)", [MessageType]::Info)
                if ($this.UseCache) {          
                    $this.ExportObjToJsonFile($variableGroupSTMapping.data, 'VariableGroupSTData.json');
                    $this.ExportObjToJsonFileUploadToBlob($variableGroupSTMapping.data, 'VariableGroupSTData.json');
                }
            }
            catch {
                $_
            }        
        }
    
    }
