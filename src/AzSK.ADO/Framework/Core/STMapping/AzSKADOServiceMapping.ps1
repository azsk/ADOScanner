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
    [string] $StorageAccount; # Storage account name
    [string] $StorageRG;# Storage resource group name
    [string] $Container;# Storage Container to store ST mapping files    
    [object] $StorageAccountCtx;     
    # Power BI Report Storage settings to store ST mapping files
    [string] $ReportStorageAccount;# Storage account name for Dashboard 
    [string] $ReportStorageRG;# Storage resource group name for Dashboard 
    [string] $ReportContainer;#Storage Container to store ST mapping files use by Power Bi  resports    
    [object] $ReportStorageAccountCtx;     
    [string] $AzSKTempStatePath = [Constants]::AzSKTempFolderPath
    $BuildSTDetails = @();
    $ReleaseSTDetails =@();
    $RepositorySTDetails =@();


	AzSKADOServiceMapping([string] $organizationName, [string] $projectName, [string] $buildFileLocation, [string] $releaseFileLocation, [string] $repositoryFileLocation,[string] $mappingType,[string] $auto,[InvocationInfo] $invocationContext): 
        Base($organizationName, $invocationContext) 
    { 
        $this.OrgName = $organizationName
        $this.ProjectName = $projectName
        $this.BuildMappingsFilePath = $buildFileLocation
        $this.ReleaseMappingsFilePath = $releaseFileLocation
        $this.RepositoryMappingsFilePath = $repositoryFileLocation
        $this.MappingType = $MappingType
        $this.Auto = $auto.ToLower();        
        $this.StorageAccount = $env:StorageName;
        $this.StorageRG = $env:StorageRG;
        $this.Container = $env:Container;
        # Power BI Report Storage settings
        $this.ReportStorageAccount = $env:ReportStorageName;
        $this.ReportStorageRG = $env:ReportStorageRG;
        $this.ReportContainer = $env:ReportContainer;                
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
        if(![string]::IsNullOrWhiteSpace($this.RepositoryMappingsFilePath)) {            
            $this.GetRepositoryMapping();
        }

        if(![string]::IsNullOrWhiteSpace($this.BuildMappingsFilePath) -and ![string]::IsNullOrWhiteSpace($this.ReleaseMappingsFilePath)){
            if(((Test-Path $this.BuildMappingsFilePath) -and (Test-Path $this.ReleaseMappingsFilePath)) -or $this.Auto -eq 'true')
            {
                $this.GetBuildReleaseMapping();              
                if ([string]::IsNullOrWhiteSpace($this.MappingType) -or $this.MappingType -eq "All" -or $this.MappingType -eq "ServiceConnection")
                {
                    $this.FetchSvcConnMapping();
                }
                if ([string]::IsNullOrWhiteSpace($this.MappingType) -or $this.MappingType -eq "All" -or $this.MappingType -eq "AgentPool")
                {
                    $this.FetchAgentPoolMapping();
                }
                if ([string]::IsNullOrWhiteSpace($this.MappingType) -or $this.MappingType -eq "All" -or $this.MappingType -eq "Environment")
                {
                    $this.FetchEnvironmentMapping();
                }
                if ([string]::IsNullOrWhiteSpace($this.MappingType) -or $this.MappingType -eq "All" -or $this.MappingType -eq "VariableGroup" -or $this.MappingType -eq "SecureFile")
                {
                    $this.FetchVarGrpSecureFileMapping();
                }
                if ([string]::IsNullOrWhiteSpace($this.MappingType) -or $this.MappingType -eq "All" -or $this.MappingType -eq "Feed")
                {
                    $this.FetchFeedMapping();
                }
            }
        }
        
		[MessageData[]] $returnMsgs = @();
		$returnMsgs += [MessageData]::new("Returning service mappings.");
		return $returnMsgs
    }
    
    hidden  GetBuildReleaseMapping()
    {  
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
        }
        catch {           
        }
        $this.ExportObjToJsonFile($this.BuildSTDetails, 'BuildSTData.json');
        $this.ExportObjToJsonFileUploadToBlob($this.BuildSTDetails, 'BuildSTData.json');
        
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

        $this.ExportObjToJsonFile($this.ReleaseSTDetails, 'ReleaseSTData.json');
        $this.ExportObjToJsonFileUploadToBlob($this.ReleaseSTDetails, 'ReleaseSTData.json');
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
        $this.ExportObjToJsonFile($this.RepositorySTDetails, 'RepositorySTData.json');
        $this.ExportObjToJsonFileUploadToBlob($this.RepositorySTDetails, 'RepositorySTData.json');
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
        $this.ExportObjToJsonFile($svcConnSTMapping.data, 'ServiceConnectionSTData.json');
        $this.ExportObjToJsonFileUploadToBlob($svcConnSTMapping.data, 'ServiceConnectionSTData.json');
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
        $this.ExportObjToJsonFile($agentPoolSTMapping.data, 'AgentPoolSTData.json');
        $this.ExportObjToJsonFileUploadToBlob($agentPoolSTMapping.data, 'AgentPoolSTData.json');
        return $true;
    }

    hidden [bool] FetchVarGrpSecureFileMapping() {  
      
        $topNQueryString = '&$top=10000'
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
                
                #generate access token with datastudio api audience
                $accessToken = [ContextHelper]::GetDataExplorerAccessToken($false)
                
                #This variable is used to store details returned from secure file api(fetching all the secure file details in one call)
                $secureFileDetails = @();
                foreach ($relDef in $releaseDefnsObj) {

                    $counter++
                    Write-Progress -Activity 'Variable group/secure file mappings via release...' -CurrentOperation $relDef.Name -PercentComplete (($counter / $releaseDefnsObj.count) * 100)

                    try
                    {
                        $releaseObj = [WebRequestHelper]::InvokeGetWebRequest($relDef.url);
                        $varGrps = @();
                        
                        #add var groups scoped at release scope.
                        if ($this.MappingType -eq "All" -or $this.MappingType -eq "VariableGroup") {
                            if((($releaseObj[0].variableGroups) | Measure-Object).Count -gt 0)
                            {
                                $varGrps += $releaseObj[0].variableGroups
                            }
                        }

                        #get var grps from each env of release pipeline
                        $secureFiles = @();
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
                        }

                        if ($this.MappingType -eq "All" -or $this.MappingType -eq "VariableGroup") {
                            if(($varGrps | Measure-Object).Count -gt 0)
                            {
                                $apiURL = "https://{0}.visualstudio.com/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $this.OrgName;
                                $sourcePageUrl = "https://{0}.visualstudio.com/{1}/_settings/adminservices" -f $this.OrgName, $this.ProjectName;

                                $varGrps | ForEach-Object {
                                    try {                                                                            
                                        $varGrpURL = ("https://{0}.visualstudio.com/{1}/_apis/distributedtask/variablegroups/{2}?api-version=6.1-preview.2") -f $this.OrgName, $this.projectId, $_;                                                                     
                                        $header = [WebRequestHelper]::GetAuthHeaderFromUri($varGrpURL)                                                                     
                                        $varGrpObj  = Invoke-WebRequest -Uri $varGrpURL -Headers $header                                        

                                        if($varGrpObj.Content -ne 'null')
                                        {
                                            $varGrpObj = $varGrpObj.Content | ConvertFrom-Json
                                            $releaseSTData = $this.ReleaseSTDetails.Data | Where-Object { ($_.releaseDefinitionID -eq $releaseObj[0].id) };
                                            if($releaseSTData)
                                            {
                                                $variableGroupSTMapping.data += @([PSCustomObject] @{ variableGroupName = $varGrpObj.name; variableGroupID = $varGrpObj.id; serviceID = $releaseSTData.serviceID; projectName = $releaseSTData.projectName; projectID = $releaseSTData.projectID; orgName = $releaseSTData.orgName } )
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
                                                                            $variableGroupSTMapping.data += @([PSCustomObject] @{ variableGroupName = $varGrpObj.name; variableGroupID = $varGrpObj.id; serviceID = $serviceId; projectName = $serviceConnEndPointDetail.serviceEndpoint.serviceEndpointProjectReferences.projectReference.name; projectID = $serviceConnEndPointDetail.serviceEndpoint.serviceEndpointProjectReferences.projectReference.id; orgName = $this.OrgName } )
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
                                    if (($secureFileDetails | Measure-Object).count -eq 0) {
                                        $secureFilesURL = "https://dev.azure.com/{0}/{1}/_apis/distributedtask/securefiles?api-version=6.1-preview.1" -f $this.OrgName, $this.projectId;
                                        $secureFileDetails = [WebRequestHelper]::InvokeGetWebRequest($secureFilesURL);
                                    }
                                    $secureFile = $_;
                                    $secureFilesObj = $secureFileDetails | Where {$_.Name -eq $secureFile -or $_.Id -eq $secureFile}

                                    if ($secureFilesObj) {
                                        $releaseSTData = $this.ReleaseSTDetails.Data | Where-Object { ($_.releaseDefinitionID -eq $relDef.id) };
                                        if($releaseSTData){
                                            $secureFileSTMapping.data += @([PSCustomObject] @{ secureFileName = $secureFilesObj.name; secureFileID = $secureFilesObj.id; serviceID = $releaseSTData.serviceID; projectName = $releaseSTData.projectName; projectID = $releaseSTData.projectID; orgName = $releaseSTData.orgName } )
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
                    
                    #Variable to store current build STDAT
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
                                                                    $variableGroupSTMapping.data += @([PSCustomObject] @{ variableGroupName = $_.name; variableGroupID = $_.id; serviceID = $serviceId; projectName = $serviceConnEndPointDetail.serviceEndpoint.serviceEndpointProjectReferences.projectReference.name; projectID = $serviceConnEndPointDetail.serviceEndpoint.serviceEndpointProjectReferences.projectReference.id; orgName = $this.OrgName } )
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
                                if (($secureFileDetails | Measure-Object).count -eq 0) {
                                    $secureFilesURL = "https://dev.azure.com/{0}/{1}/_apis/distributedtask/securefiles?api-version=6.1-preview.1" -f $this.OrgName, $this.projectId;
                                    $secureFileDetails = [WebRequestHelper]::InvokeGetWebRequest($secureFilesURL);
                                }
                                $secureFile = $_;
                                $secureFilesObj = $secureFileDetails | Where {$_.Name -eq $secureFile -or $_.Id -eq $secureFile}

                                if ($secureFilesObj) {
                                    if (!$buildSTData) {
                                        $buildSTData = $this.BuildSTDetails.Data | Where-Object { ($_.buildDefinitionID -eq $buildObj[0].id) -and ($_.projectName -eq $this.ProjectName) };
                                    }
                                    if($buildSTData){
                                        $secureFileSTMapping.data += @([PSCustomObject] @{ secureFileName = $secureFilesObj.name; secureFileID = $secureFilesObj.id; serviceID = $buildSTData.serviceID; projectName = $buildSTData.projectName; projectID = $buildSTData.projectID; orgName = $buildSTData.orgName } )
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
            $this.ExportObjToJsonFile($variableGroupSTMapping.data, 'VariableGroupSTData.json');
            $this.ExportObjToJsonFileUploadToBlob($variableGroupSTMapping.data, 'VariableGroupSTData.json');
        }
        #Removing duplicate entries of the tuple (securefile,serviceId)
        if ($this.MappingType -eq "All" -or $this.MappingType -eq "SecureFile") {
            $secureFileSTMapping.data = $secureFileSTMapping.data | Sort-Object -Unique secureFileID,serviceID
            $this.PublishCustomMessage("Service mapping found:  $(($secureFileSTMapping.data | Measure-Object).Count)", [MessageType]::Info)
            $this.ExportObjToJsonFile($secureFileSTMapping.data, 'SecureFileSTData.json');
            $this.ExportObjToJsonFileUploadToBlob($secureFileSTMapping.data, 'SecureFileSTData.json');
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
        $this.ExportObjToJsonFile($environmentSTMapping.data, 'EnvironmentSTData.json');
        $this.ExportObjToJsonFileUploadToBlob($environmentSTMapping.data, 'EnvironmentSTData.json');
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
        $this.ExportObjToJsonFile($feedSTMapping.data, 'FeedSTData.json');
        $this.ExportObjToJsonFileUploadToBlob($feedSTMapping.data, 'FeedSTData.json');
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
    
}
