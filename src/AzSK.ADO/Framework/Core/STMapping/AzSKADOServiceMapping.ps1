using namespace System.Management.Automation
Set-StrictMode -Version Latest 

class AzSKADOServiceMapping: CommandBase
{    
    [string] $OrgName
    [string] $ProjectName
    [string] $ProjectId
    [string] $BuildMappingsFilePath
    [string] $ReleaseMappingsFilePath
    [string] $MappingType
    [string] $OutputFolderPath
    $BuildSTDetails = @();
    $ReleaseSTDetails =@();


	AzSKADOServiceMapping([string] $subscriptionId, [string] $projectName, [string] $buildFileLocation, [string] $releaseFileLocation, [string] $mappingType, [InvocationInfo] $invocationContext): 
        Base($subscriptionId, $invocationContext) 
    { 
        $this.OrgName = $subscriptionId
        $this.ProjectName = $projectName
        $this.BuildMappingsFilePath = $buildFileLocation
        $this.ReleaseMappingsFilePath = $releaseFileLocation
        $this.MappingType = $MappingType
	}
	
	[MessageData[]] GetSTmapping()
	{
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
                if ([string]::IsNullOrWhiteSpace($this.MappingType) -or $this.MappingType -eq "All" -or $this.MappingType -eq "VariableGroup")
                {
                    $this.FetchVarGrpMapping();
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
            $serviceEndpointURL = ("https://dev.azure.com/{0}/{1}/_apis/serviceendpoint/endpoints?api-version=4.1-preview.1") -f $this.OrgName, $this.ProjectName;
            $serviceEndpointObj = [WebRequestHelper]::InvokeGetWebRequest($serviceEndpointURL)

            $Connections = $null
            if (([Helpers]::CheckMember($serviceEndpointObj, "count") -and $serviceEndpointObj[0].count -gt 0) -or (($serviceEndpointObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($serviceEndpointObj[0], "name"))) {
                $Connections = $serviceEndpointObj | Where-Object { ($_.type -eq "azurerm" -or $_.type -eq "azure" -or $_.type -eq "git" -or $_.type -eq "github" -or $_.type -eq "externaltfs") } 
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

    hidden [bool] FetchVarGrpMapping() {  
      
        $topNQueryString = '&$top=10000'
        $variableGroupSTMapping = @{
            data = @();
        };

        $releaseDefnURL = ("https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?api-version=4.1-preview.3" +$topNQueryString) -f $($this.OrgName), $this.ProjectName;
        $releaseDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($releaseDefnURL);
          
        if (([Helpers]::CheckMember($releaseDefnsObj, "count") -and $releaseDefnsObj[0].count -gt 0) -or (($releaseDefnsObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($releaseDefnsObj[0], "name"))) {
            
            $this.PublishCustomMessage(([Constants]::DoubleDashLine))
            $this.PublishCustomMessage("Generating service mappings of variable group using release for project [$($this.ProjectName)]...")
            $this.PublishCustomMessage("Total mappings to be evaluated:  $(($releaseDefnsObj | Measure-Object).Count)")
            $counter = 0

            foreach ($relDef in $releaseDefnsObj) {

                $counter++
                Write-Progress -Activity 'Variable group mappings via release...' -CurrentOperation $relDef.Name -PercentComplete (($counter / $releaseDefnsObj.count) * 100)

                try
                {
                    $releaseObj = [WebRequestHelper]::InvokeGetWebRequest($relDef.url);
                    $varGrps = @();
                    
                    #add var groups scoped at release scope.
                    if((($releaseObj[0].variableGroups) | Measure-Object).Count -gt 0)
                    {
                        $varGrps += $releaseObj[0].variableGroups
                    }

                    #get var grps from each env of release pipeline
                    foreach ($env in $releaseObj[0].environments) {
                        if((($env.variableGroups) | Measure-Object).Count -gt 0)
                        {
                            $varGrps += $env.variableGroups
                        }
                    }

                    if(($varGrps | Measure-Object).Count -gt 0)
                    {
                        $varGrps | ForEach-Object{
                            $varGrpURL = ("https://{0}.visualstudio.com/{1}/_apis/distributedtask/variablegroups/{2}") -f $this.OrgName, $this.projectId, $_;
                            $varGrpObj = [WebRequestHelper]::InvokeGetWebRequest($varGrpURL);

                            $releaseSTData = $this.ReleaseSTDetails.Data | Where-Object { ($_.releaseDefinitionID -eq $releaseObj[0].id) };
                            if($releaseSTData){
                                $variableGroupSTMapping.data += @([PSCustomObject] @{ variableGroupName = $varGrpObj.name; variableGroupID = $varGrpObj.id; serviceID = $releaseSTData.serviceID; projectName = $releaseSTData.projectName; projectID = $releaseSTData.projectID; orgName = $releaseSTData.orgName } )
                            }
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
            $buildDefnURL = ("https://dev.azure.com/{0}/{1}/_apis/build/definitions?api-version=4.1" + $topNQueryString) -f $this.OrgName, $this.ProjectName;
            $buildDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($buildDefnURL) 
            
            if (([Helpers]::CheckMember($buildDefnsObj, "count") -and $buildDefnsObj[0].count -gt 0) -or (($buildDefnsObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($buildDefnsObj[0], "name"))) {

                $this.PublishCustomMessage(([Constants]::DoubleDashLine))
                $this.PublishCustomMessage("Generating service mappings of variable group using build for project [$($this.ProjectName)]...")
                $this.PublishCustomMessage("Total mappings to be evaluated:  $(($buildDefnsObj | Measure-Object).Count)")
                $counter = 0

                foreach ($bldDef in $buildDefnsObj) {
                    $counter++
                    Write-Progress -Activity 'Variable group mappings via build...' -CurrentOperation $bldDef.Name -PercentComplete (($counter / $buildDefnsObj.count) * 100)

                    $buildObj = [WebRequestHelper]::InvokeGetWebRequest($bldDef.url.split('?')[0]);

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
                $buildDefnsObj = $null;
            }
        }
        catch{
            #eat exception
        }

        #Removing duplicate entries of the tuple (variableGroupId,serviceId)
        $variableGroupSTMapping.data = $variableGroupSTMapping.data | Sort-Object -Unique variableGroupID,serviceID

        $this.PublishCustomMessage("Service mapping found:  $(($variableGroupSTMapping.data | Measure-Object).Count)", [MessageType]::Info)

        $this.ExportObjToJsonFile($variableGroupSTMapping, 'VariableGroupSTData.json');
        return $true;
    }
}
