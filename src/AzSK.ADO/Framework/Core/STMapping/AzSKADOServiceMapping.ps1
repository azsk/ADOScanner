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
    $BuildSTDetails = @();
    $ReleaseSTDetails =@();
    $RepositorySTDetails =@();


	AzSKADOServiceMapping([string] $organizationName, [string] $projectName, [string] $buildFileLocation, [string] $releaseFileLocation, [string] $repositoryFileLocation,[string] $mappingType, [InvocationInfo] $invocationContext): 
        Base($organizationName, $invocationContext) 
    { 
        $this.OrgName = $organizationName
        $this.ProjectName = $projectName
        $this.BuildMappingsFilePath = $buildFileLocation
        $this.ReleaseMappingsFilePath = $releaseFileLocation
        $this.RepositoryMappingsFilePath = $repositoryFileLocation
        $this.MappingType = $MappingType
	}
	
	[MessageData[]] GetSTmapping()
	{
        if(![string]::IsNullOrWhiteSpace($this.RepositoryMappingsFilePath) -and(Test-Path $this.RepositoryMappingsFilePath)) {
            $this.GetRepositoryMapping();
        }

        if(![string]::IsNullOrWhiteSpace($this.BuildMappingsFilePath) -and ![string]::IsNullOrWhiteSpace($this.ReleaseMappingsFilePath)){
            if((Test-Path $this.BuildMappingsFilePath) -and (Test-Path $this.ReleaseMappingsFilePath))
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
    
    hidden  GetBuildReleaseMapping() {  
        $this.BuildSTDetails = Get-content $this.BuildMappingsFilePath | ConvertFrom-Json
        if ([Helpers]::CheckMember($this.BuildSTDetails, "data") -and ($this.BuildSTDetails.data | Measure-Object).Count -gt 0)
        {
            $this.BuildSTDetails.data = $this.BuildSTDetails.data | where-object {$_.ProjectName -eq $this.ProjectName}
            if (($this.BuildSTDetails.data | Measure-Object).Count -gt 0)
            {
                $this.ProjectId = $this.BuildSTDetails.data[0].projectId
            }
        }
        $this.ExportObjToJsonFile($this.BuildSTDetails, 'BuildSTData.json');

        $this.ReleaseSTDetails = Get-content $this.ReleaseMappingsFilePath | ConvertFrom-Json
        if ([Helpers]::CheckMember($this.ReleaseSTDetails, "data") -and ($this.ReleaseSTDetails.data | Measure-Object).Count -gt 0)
        {
            $this.ReleaseSTDetails.data = $this.ReleaseSTDetails.data | where-object {$_.ProjectName -eq $this.ProjectName}
            if (($this.ReleaseSTDetails.data | Measure-Object).Count -gt 0 -and [string]::IsNullOrWhiteSpace($this.ProjectId))
            {
                $this.ProjectId = $this.ReleaseSTDetails.data[0].projectId
            }
        }
        $this.ExportObjToJsonFile($this.ReleaseSTDetails, 'ReleaseSTData.json');

    }

    hidden GetRepositoryMapping() {  
        $this.RepositorySTDetails = Get-content $this.RepositoryMappingsFilePath | ConvertFrom-Json
        if ([Helpers]::CheckMember($this.RepositorySTDetails, "data") -and ($this.RepositorySTDetails.data | Measure-Object).Count -gt 0)
        {
            $this.RepositorySTDetails.data = $this.RepositorySTDetails.data | where-object {$_.ProjectName -eq $this.ProjectName}
            if (($this.RepositorySTDetails.data | Measure-Object).Count -gt 0)
            {
                $this.ProjectId = $this.RepositorySTDetails.data[0].projectId
            }
        }
        $this.ExportObjToJsonFile($this.RepositorySTDetails, 'RepositorySTData.json');
    }

    hidden ExportObjToJsonFile($serviceMapping, $fileName) {  
        if ([string]::IsNullOrWhiteSpace($this.OutputFolderPath))
        {
            $this.OutputFolderPath = [WriteFolderPath]::GetInstance().FolderPath;
        }
        $serviceMapping | ConvertTo-Json -Depth 10 | Out-File (Join-Path $this.OutputFolderPath $fileName) -Encoding ASCII 
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
            
            $Connections | ForEach-Object {
                $counter++
                Write-Progress -Activity 'Service connection mappings...' -CurrentOperation $_.Name -PercentComplete (($counter / $Connections.count) * 100)

                $apiURL = "https://{0}.visualstudio.com/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $this.OrgName
                $sourcePageUrl = "https://{0}.visualstudio.com/{1}/_settings/adminservices" -f $this.OrgName, $this.ProjectName;
                $inputbody = "{'contributionIds':['ms.vss-serviceEndpoints-web.service-endpoints-details-data-provider'],'dataProviderContext':{'properties':{'serviceEndpointId':'$($_.id)','projectId':'$($this.projectId)','sourcePage':{'url':'$($sourcePageUrl)','routeId':'ms.vss-admin-web.project-admin-hub-route','routeValues':{'project':'$($this.ProjectName)','adminPivot':'adminservices','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json
                $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL, $inputbody); 
                
                if ([Helpers]::CheckMember($responseObj, "dataProviders") -and $responseObj.dataProviders."ms.vss-serviceEndpoints-web.service-endpoints-details-data-provider") {
                    
                    $serviceConnEndPointDetail = $responseObj.dataProviders."ms.vss-serviceEndpoints-web.service-endpoints-details-data-provider"
                    if ($serviceConnEndPointDetail -and [Helpers]::CheckMember($serviceConnEndPointDetail, "serviceEndpointExecutionHistory") ) {
                        $svcConnJobs = $serviceConnEndPointDetail.serviceEndpointExecutionHistory.data

                        #Arranging in descending order of run time.
                        $svcConnJobs = $svcConnJobs | Sort-Object startTime -Descending
                        #Taking last 10 runs
                        $svcConnJobs = $svcConnJobs | Select-Object -First 10
                        
                        foreach ($job in $svcConnJobs){
                            if ([Helpers]::CheckMember($job, "planType") -and $job.planType -eq "Build") {
                                $buildSTData = $this.BuildSTDetails.Data | Where-Object { ($_.buildDefinitionID -eq $job.definition.id) };
                                if($buildSTData){
                                    $svcConnSTMapping.data += @([PSCustomObject] @{ serviceConnectionName = $_.Name; serviceConnectionID = $_.id; serviceID = $buildSTData.serviceID; projectName = $buildSTData.projectName; projectID = $buildSTData.projectID; orgName = $buildSTData.orgName } )
                                    break;
                                }
                                
                            }
                            elseif ([Helpers]::CheckMember($job, "planType") -and $job.planType -eq "Release") {
                                $releaseSTData = $this.ReleaseSTDetails.Data | Where-Object { ($_.releaseDefinitionID -eq $job.definition.id)};
                                if($releaseSTData){
                                    $svcConnSTMapping.data += @([PSCustomObject] @{ serviceConnectionName = $_.Name; serviceConnectionID = $_.id; serviceID = $releaseSTData.serviceID; projectName = $releaseSTData.projectName; projectID = $releaseSTData.projectID; orgName = $releaseSTData.orgName } )
                                    break;
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
        $this.PublishCustomMessage("Service mapping found:  $(($svcConnSTMapping.data | Measure-Object).Count)", [MessageType]::Info)

        $this.ExportObjToJsonFile($svcConnSTMapping, 'ServiceConnectionSTData.json');
        return $true;
    }

    hidden [bool] FetchAgentPoolMapping() {  
        $agentPoolSTMapping = @{
            data = @();
        };

        try{
            $agentPoolsDefnURL = ("https://{0}.visualstudio.com/{1}/_settings/agentqueues?__rt=fps&__ver=2") -f $this.OrgName, $this.ProjectName;
            $agentPoolsDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($agentPoolsDefnURL);
            
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

                $agtPoolId = $_.id
                $agentPoolsURL = "https://{0}.visualstudio.com/{1}/_settings/agentqueues?queueId={2}&__rt=fps&__ver=2" -f $this.orgName, $this.ProjectId, $agtPoolId
                $agentPool = [WebRequestHelper]::InvokeGetWebRequest($agentPoolsURL);
                
                if (([Helpers]::CheckMember($agentPool[0], "fps.dataProviders.data") ) -and ($agentPool[0].fps.dataProviders.data."ms.vss-build-web.agent-jobs-data-provider")) {
                    $agentPoolJobs = $agentPool[0].fps.dataProviders.data."ms.vss-build-web.agent-jobs-data-provider".jobs | Where-Object { $_.scopeId -eq $this.ProjectId };

                    #Arranging in descending order of run time.
                    $agentPoolJobs = $agentPoolJobs | Sort-Object queueTime -Descending
                    #Taking last 10 runs
                    $agentPoolJobs = $agentPoolJobs | Select-Object -First 10
                    #If agent pool has been queued at least once

                    foreach ($job in $agentPoolJobs){
                        if ([Helpers]::CheckMember($job, "planType") -and $job.planType -eq "Build") {
                            $buildSTData = $this.BuildSTDetails.data | Where-Object { ($_.buildDefinitionID -eq $job.definition.id)};
                            if($buildSTData){
                                $agentPoolSTMapping.data += @([PSCustomObject] @{ agentPoolName = $_.Name; agentPoolID = $_.id; serviceID = $buildSTData.serviceID; projectName = $buildSTData.projectName; projectID = $buildSTData.projectID; orgName = $buildSTData.orgName } )
                                break;
                            }
                        }
                        elseif ([Helpers]::CheckMember($job, "planType") -and $job.planType -eq "Release") {
                            $releaseSTData = $this.ReleaseSTDetails.data | Where-Object { ($_.releaseDefinitionID -eq $job.definition.id)};
                            if($releaseSTData){
                                $agentPoolSTMapping.data += @([PSCustomObject] @{ agentPoolName = $_.Name; agentPoolID = $_.id; serviceID = $releaseSTData.serviceID; projectName = $releaseSTData.projectName; projectID = $releaseSTData.projectID; orgName = $releaseSTData.orgName } )
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
        $this.PublishCustomMessage("Service mapping found:  $(($agentPoolSTMapping.data | Measure-Object).Count)", [MessageType]::Info)

        $this.ExportObjToJsonFile($agentPoolSTMapping, 'AgentPoolSTData.json');
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

        $releaseDefnURL = ("https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?api-version=6.0" +$topNQueryString) -f $($this.OrgName), $this.ProjectName;
        $releaseDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($releaseDefnURL);
          
        if (([Helpers]::CheckMember($releaseDefnsObj, "count") -and $releaseDefnsObj[0].count -gt 0) -or (($releaseDefnsObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($releaseDefnsObj[0], "name"))) {
            
            $this.PublishCustomMessage(([Constants]::DoubleDashLine))
            $this.PublishCustomMessage("Generating service mappings of variable group/secure file using release for project [$($this.ProjectName)]...")
            $this.PublishCustomMessage("Total mappings to be evaluated:  $(($releaseDefnsObj | Measure-Object).Count)")
            $counter = 0

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
                                if([Helpers]::CheckMember($env, "deployPhases.workflowtasks") )
                                {
                                    $workflowtasks += $env.deployPhases.workflowtasks;
                                }
                                foreach ($item in $workflowtasks) {
                                    if ([Helpers]::CheckMember($item, "inputs.secureFile")) {
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
                        $varGrps | ForEach-Object{
                            $varGrpURL = ("https://{0}.visualstudio.com/{1}/_apis/distributedtask/variablegroups/{2}?api-version=6.1-preview.2") -f $this.OrgName, $this.projectId, $_;
                            $varGrpObj = [WebRequestHelper]::InvokeGetWebRequest($varGrpURL);

                            $releaseSTData = $this.ReleaseSTDetails.Data | Where-Object { ($_.releaseDefinitionID -eq $releaseObj[0].id) };
                            if($releaseSTData){
                                $variableGroupSTMapping.data += @([PSCustomObject] @{ variableGroupName = $varGrpObj.name; variableGroupID = $varGrpObj.id; serviceID = $releaseSTData.serviceID; projectName = $releaseSTData.projectName; projectID = $releaseSTData.projectID; orgName = $releaseSTData.orgName } )
                            }
                        }
                        }
                    }

                    if ($this.MappingType -eq "All" -or $this.MappingType -eq "SecureFile") {
                        try {
                            if(($secureFiles | Measure-Object).Count -gt 0)
                            {
                                $secureFiles | ForEach-Object{
                                if ($secureFileDetails.count -eq 0) {
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

                    #getting secure files added in all the tasks.
                    try {
                        if ($this.MappingType -eq "All" -or $this.MappingType -eq "SecureFile") {
                            $tasksSteps =@()
                            if([Helpers]::CheckMember($buildObj, "process.Phases.steps") )
                            {
                                $tasksSteps += $buildObj.process.Phases.steps;
                            }
                            foreach ($itemStep in $tasksSteps) {
                                if ([Helpers]::CheckMember($itemStep, "inputs.secureFile")) {
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
                            $varGrps = $buildObj[0].variableGroups
                            $varGrps | ForEach-Object{

                                $buildSTData = $this.BuildSTDetails.Data | Where-Object { ($_.buildDefinitionID -eq $buildObj[0].id) -and ($_.projectName -eq $this.ProjectName) };
                                if($buildSTData){
                                    $variableGroupSTMapping.data += @([PSCustomObject] @{ variableGroupName = $_.name; variableGroupID = $_.id; serviceID = $buildSTData.serviceID; projectName = $buildSTData.projectName; projectID = $buildSTData.projectID; orgName = $buildSTData.orgName } )
                                }
                            }
                        }
                    }
                    if ($this.MappingType -eq "All" -or $this.MappingType -eq "SecureFile") {
                        $secureFiles = @();
                        try {
                            if(($secureFiles | Measure-Object).Count -gt 0)
                            {
                            $secureFiles | ForEach-Object{
                                if ($secureFileDetails.count -eq 0) {
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
        if ($this.MappingType -eq "All" -or $this.MappingType -eq "SecureFile") {
            $variableGroupSTMapping.data = $variableGroupSTMapping.data | Sort-Object -Unique variableGroupID,serviceID

            $this.PublishCustomMessage("Service mapping found:  $(($variableGroupSTMapping.data | Measure-Object).Count)", [MessageType]::Info)

            $this.ExportObjToJsonFile($variableGroupSTMapping, 'VariableGroupSTData.json');
        }
        #Removing duplicate entries of the tuple (securefile,serviceId)
        if ($this.MappingType -eq "All" -or $this.MappingType -eq "SecureFile") {
            $secureFileSTMapping.data = $secureFileSTMapping.data | Sort-Object -Unique secureFileID,serviceID

            $this.PublishCustomMessage("Service mapping found:  $(($secureFileSTMapping.data | Measure-Object).Count)", [MessageType]::Info)

            $this.ExportObjToJsonFile($secureFileSTMapping, 'SecureFileSTData.json');
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

            if ($environmentsObjList.count -gt 0 ) {
             
                $this.PublishCustomMessage(([Constants]::DoubleDashLine))
                $this.PublishCustomMessage("Generating service mappings of environments for project [$($this.ProjectName)]...")
                $this.PublishCustomMessage("Total environments to be mapped:  $($environmentsObjList.count)")
                $counter = 0
                
                $environmentsObjList | ForEach-Object {
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
                                    break;
                                }
                                
                            }
                            elseif ([Helpers]::CheckMember($envJob, "planType") -and $envJob.planType -eq "Release") {
                                $releaseSTData = $this.ReleaseSTDetails.Data | Where-Object { ($_.releaseDefinitionID -eq $envJob.definition.id)};
                                if($releaseSTData){
                                    $environmentSTMapping.data += @([PSCustomObject] @{ environmentName = $_.Name; environmentID = $_.id; serviceID = $releaseSTData.serviceID; projectName = $releaseSTData.projectName; projectID = $releaseSTData.projectID; orgName = $releaseSTData.orgName } )
                                    break;
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

        $this.ExportObjToJsonFile($environmentSTMapping, 'EnvironmentSTData.json');
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

                        if ($feedPackages.count -gt 0 -and [Helpers]::CheckMember($feedPackages[0],"name")) {

                            $feedPackages = $feedPackages | Select-Object -First 10;
                            foreach ($package in $feedPackages){
                            $provenanceURL = "https://feeds.dev.azure.com/{0}/{1}/_apis/packaging/Feeds/{2}/Packages/{3}/Versions/{4}/provenance?api-version=6.0-preview.1" -f $this.OrgName, $this.ProjectName, $feed.id, $package.id, $package.versions[0].id;
                            $provenanceObj = @([WebRequestHelper]::InvokeGetWebRequest($provenanceURL)); 

                            if ($provenanceObj.Count -gt 0 -and [Helpers]::CheckMember($provenanceObj[0],"provenance.provenanceSource") -and [Helpers]::CheckMember($provenanceObj[0],"provenance.data")) {
                                
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

        $this.ExportObjToJsonFile($feedSTMapping, 'FeedSTData.json');
        return $true;
    }

}
