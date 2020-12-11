Set-StrictMode -Version Latest

class SVTResourceResolver: AzSKRoot {
    [string[]] $ResourceNames = @();
    [string] $ResourceType = "";
    [ResourceTypeName] $ResourceTypeName = [ResourceTypeName]::All;
    [Hashtable] $Tag = $null;
    [string] $TagName = "";
    [string[]] $TagValue = "";
    hidden [string[]] $ResourceGroups = @();
    [ResourceTypeName] $ExcludeResourceTypeName = [ResourceTypeName]::All;
    [string[]] $ExcludeResourceNames = @();
    [SVTResource[]] $ExcludedResources = @();
    [int] $MaxObjectsToScan;
    [SVTResource[]] $SVTResources = @();
    [int] $SVTResourcesFoundCount = 0;
    
    [string] $ResourcePath;
    [string] $organizationName
    hidden [string[]] $ProjectNames = @();
    hidden [string[]] $BuildNames = @();
    hidden [string[]] $RepoNames = @()
    hidden [string[]] $ReleaseNames = @();
    hidden [string[]] $AgentPools = @();
    hidden [string[]] $ServiceConnections = @();
    hidden [string[]] $VariableGroups = @();
    hidden [PSObject] $ControlSettings; 
    #Local variable for longrunningscan for command parameter
    [bool] $allowLongRunningScan = $false
    #Local variables for longrunningscan for controlsettings variables
    [bool] $isAllowLongRunningScanInPolicy = $true
    [int] $longRunningScanCheckPoint = 1000;

    hidden [string[]] $serviceId = @();

    [bool] $includeAdminControls = $false;
    [bool] $isUserPCA = $false;

    $orgTelemetryData = @{
        installed_extensions = 0;
        organization_name = "";
    };

    SVTResourceResolver([string]$organizationName, $ProjectNames, $BuildNames, $RepoNames, $ReleaseNames, $AgentPools, $ServiceConnectionNames, $VariableGroupNames, $MaxObj, $ScanAllArtifacts, $PATToken, $ResourceTypeName, $AllowLongRunningScan, $ServiceId, $IncludeAdminControls): Base($organizationName, $PATToken) {
        $this.MaxObjectsToScan = $MaxObj #default = 0 => scan all if "*" specified...
        $this.SetallTheParamValues($organizationName, $ProjectNames, $BuildNames, $RepoNames, $ReleaseNames, $AgentPools, $ServiceConnectionNames, $VariableGroupNames, $ScanAllArtifacts, $PATToken, $ResourceTypeName, $AllowLongRunningScan, $ServiceId, $IncludeAdminControls);            
    }

    [void] SetallTheParamValues([string]$organizationName, $ProjectNames, $BuildNames, $RepoNames, $ReleaseNames, $AgentPools, $ServiceConnectionNames, $VariableGroupNames, $ScanAllArtifacts, $PATToken, $ResourceTypeName, $AllowLongRunningScan, $ServiceId, $IncludeAdminControls) { 
        $this.organizationName = $organizationName
        $this.ResourceTypeName = $ResourceTypeName
        $this.allowLongRunningScan = $AllowLongRunningScan
        $this.includeAdminControls = $IncludeAdminControls

        if (-not [string]::IsNullOrEmpty($ProjectNames)) {
            $this.ProjectNames += $this.ConvertToStringArray($ProjectNames);

            if ($this.ProjectNames.Count -eq 0) {
                throw [SuppressedException] "The parameter 'ProjectNames' does not contain any string."
            }
        }
        elseif ($ResourceTypeName -eq [ResourceTypeName]::Project -or $ResourceTypeName -eq [ResourceTypeName]::Org_Project_User) {
            $this.ProjectNames = "*"
        }	

        if (-not [string]::IsNullOrEmpty($BuildNames)) {
            $this.BuildNames += $this.ConvertToStringArray($BuildNames);
            if ($this.BuildNames.Count -eq 0) {
                throw [SuppressedException] "The parameter 'BuildNames' does not contain any string."
            }
        }
        elseif ($ResourceTypeName -eq [ResourceTypeName]::Build -or $ResourceTypeName -eq [ResourceTypeName]::Build_Release) {
            $this.BuildNames = "*"
        }

        if (-not [string]::IsNullOrEmpty($RepoNames)) {
            $this.RepoNames += $this.ConvertToStringArray($RepoNames);
            if ($this.RepoNames.Count -eq 0) {
                throw [SuppressedException] "The parameter 'RepoNames' does not contain any string."
            }
        }
        elseif ($ResourceTypeName -eq [ResourceTypeName]::Repo) {
            $this.RepoNames = "*"
        }

        if (-not [string]::IsNullOrEmpty($ReleaseNames)) {
            $this.ReleaseNames += $this.ConvertToStringArray($ReleaseNames);
            if ($this.ReleaseNames.Count -eq 0) {
                throw [SuppressedException] "The parameter 'ReleaseNames' does not contain any string."
            }
        }
        elseif ($ResourceTypeName -eq [ResourceTypeName]::Release -or $ResourceTypeName -eq [ResourceTypeName]::Build_Release) {
            $this.ReleaseNames = "*"
        }

        if (-not [string]::IsNullOrEmpty($ServiceConnectionNames)) {
            $this.ServiceConnections += $this.ConvertToStringArray($ServiceConnectionNames);

            if ($this.ServiceConnections.Count -eq 0) {
                throw [SuppressedException] "The parameter 'ServiceConnectionNames' does not contain any string."
            }
        }	
        elseif ($ResourceTypeName -eq [ResourceTypeName]::ServiceConnection) {
            $this.ServiceConnections = "*"
        }

        if (-not [string]::IsNullOrEmpty($AgentPools)) {
            $this.AgentPools += $this.ConvertToStringArray($AgentPools);
            if ($this.AgentPools.Count -eq 0) {
                throw [SuppressedException] "The parameter 'AgentPools' does not contain any string."
            }
        }
        elseif ($ResourceTypeName -eq [ResourceTypeName]::AgentPool) {
            $this.AgentPools = "*"
        }

        if (-not [string]::IsNullOrEmpty($VariableGroupNames)) {
            $this.VariableGroups += $this.ConvertToStringArray($VariableGroupNames);

            if ($this.VariableGroups.Count -eq 0) {
                throw [SuppressedException] "The parameter 'VariableGroupNames' does not contain any string."
            }
        }	
        elseif ($ResourceTypeName -eq [ResourceTypeName]::VariableGroup) {
            $this.VariableGroups = "*"
        }

        if (-not [string]::IsNullOrEmpty($ServiceId)) {
            $this.serviceId += $this.ConvertToStringArray($ServiceId);
            if ($this.serviceId.Count -eq 0) {
                throw [SuppressedException] "The parameter 'ServiceId' does not contain any string."
            }
        }

        #User should always provide project name (comma separated list or '*') to scan builds in an org. Else no controls will be scanned if -rtn is 'Build'
        #if (-not [string]::IsNullOrEmpty($ResourceTypeName) -and $ResourceTypeName -ne "All" -and ([string]::IsNullOrEmpty($ProjectNames))) {
        #    $this.ProjectNames = "*"
        #}

        if ($ScanAllArtifacts -and [string]::IsNullOrEmpty($ServiceId)) {
            #ScanAllArtifacts should scan all artifacts within the targeted projects (if provided explicitly)
            if ([string]::IsNullOrEmpty($ProjectNames)) {
                $this.ProjectNames = "*"
            }
            $this.BuildNames = "*"
            $this.RepoNames = "*"
            $this.ReleaseNames = "*"
            $this.AgentPools = "*"
            $this.ServiceConnections = "*"
            $this.VariableGroups = "*"
        }  

        if (( $this.MaxObjectsToScan -eq 0 -or $this.MaxObjectsToScan -gt $this.longRunningScanCheckPoint) -and ($this.ProjectNames -eq "*" -or $this.BuildNames -eq "*" -or $this.RepoNames -eq "*" -or $this.ReleaseNames -eq "*" -or $this.ServiceConnections -eq "*" -or $this.AgentPools -eq "*" -or $this.VariableGroups -eq "*")) {            
            $this.PublishCustomMessage("Using '*' can take a long time for the scan to complete in larger projects. `nYou may want to provide a comma-separated list of projects, builds, releases, service connections, agent pools and variable groups. `n ", [MessageType]::Warning);
            <# BUGBUG: [Aug-2020] Removing this until we can determine the right approach to init org-policy-url for ADO.
            if (!$this.ControlSettings) {
                $this.ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
            }
            #fetch control settings to check whether large scans are allowed in the org
            $this.isAllowLongRunningScanInPolicy = $this.ControlSettings.IsAllowLongRunningScan; 
            $this.longRunningScanCheckPoint = $this.ControlSettings.LongRunningScanCheckPoint;     
            #>
  
        }
    }

    [void] GetResourceCount($projectName, $organizationId, $projectId) {
        [Hashtable] $projectData = @{
            projectName = $projectName;
            repositories = 0;
            testplan = 0;
            pipelines = 0;
            taskgroups = 0;
        };
        # fetching the repository count of a project
        try{
            $resourceURL = "https://dev.azure.com/$($this.organizationName)/$($projectName)/_apis/git/repositories?api-version=6.0"
            $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL) ;
            # $this.AddSVTResource("Repos", $projectName, "ADO.Repo", "organization/$organizationId/project/$projectId", $null, "");
            $projectData['repositories'] = $responseList.Length
            # fetching the testplan count of a project
            $resourceURL = "https://dev.azure.com/$($this.organizationName)/$($projectName)/_apis/testplan/plans?api-version=6.0-preview.1"
            $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL) ;
            $projectData['testplan'] = $responseList.Length
            # fetching the pipelines count of a project
            $resourceURL = "https://dev.azure.com/$($this.organizationName)/$($projectName)/_apis/pipelines?api-version=6.0-preview.1"
            $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL) ;
            $projectData['pipelines'] = $responseList.Length
            # fetching the taskgroups count of a project
            $resourceURL = "https://dev.azure.com/$($this.organizationName)/$($projectName)/_apis/distributedtask/taskgroups?api-version=6.0-preview.1"
            $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL) ;
            $projectData['taskgroups'] = $responseList.Length
        }
        catch {}
        [AIOrgTelemetryHelper]::PublishEvent("Projects resources count", $projectData, @{})
    }

    [void] LoadResourcesForScan() {
        #Call APIS for Organization,User/Builds/Releases/ServiceConnections 
        $organizationId = "";
        
        #Checking if org name is correct 
        $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $($this.organizationName);
        
        $inputbody = "{'contributionIds':['ms.vss-features.my-organizations-data-provider'],'dataProviderContext':{'properties':{'sourcePage':{'url':'https://dev.azure.com/$($this.organizationName)','routeId':'ms.vss-tfs-web.suite-me-page-route','routeValues':{'view':'projects','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json
        try {
            $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL, $inputbody);
            $organizationId = ($responseObj[0].dataProviders."ms.vss-features.my-organizations-data-provider".organizations | Where-Object {$_.name -eq $this.organizationName}).id
            $inputbody = $null;
            Remove-Variable inputbody;
        }
        catch {
            Write-Host 'Organization not found: Incorrect organization name or you do not have neccessary permission to access the organization.' -ForegroundColor Red
            throw;
        }
        if ($this.ResourceTypeName -in ([ResourceTypeName]::Organization, [ResourceTypeName]::All, [ResourceTypeName]::Org_Project_User) -and ([string]::IsNullOrEmpty($this.serviceId)) ) 
        {
            #First condition if 'includeAdminControls' switch is passed or user is admin(PCA).
            #Second condition if explicitly -rtn flag passed to org or Org_Project_User 
            #Third condition if 'gads' contains only admin scan parame, then no need to ask for includeAdminControls switch
            if (($this.includeAdminControls -or $this.isAdminControlScan()))
            {
                #Select Org/User by default...
                $link = "https://dev.azure.com/$($this.organizationName)/_settings"
                $this.AddSVTResource($this.organizationName, $null ,"ADO.Organization", "organization/$($organizationId)", $null, $link);
            }
            elseif ( ($this.ResourceTypeName -in ([ResourceTypeName]::Organization, [ResourceTypeName]::Org_Project_User)) -or ( $this.BuildNames.Count -eq 0 -and $this.ReleaseNames.Count -eq 0 -and $this.ServiceConnections.Count -eq 0 -and $this.AgentPools.Count -eq 0 -and $this.VariableGroups.Count -eq 0) ) {
                $this.PublishCustomMessage("You have requested scan for organization controls. However, you do not have admin permission. Use '-IncludeAdminControls' if you'd still like to scan them. (Some controls may not scan correctly due to access issues.)", [MessageType]::Info);
                $this.PublishCustomMessage("`r`n");
            }
        }

        if ($this.ResourceTypeName -in ([ResourceTypeName]::User, [ResourceTypeName]::All, [ResourceTypeName]::Org_Project_User, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User)) {

            $link = "https://dev.azure.com/$($this.organizationName)/_settings/users"
            $this.AddSVTResource($this.organizationName, $null,"ADO.User", "organization/$($organizationId)/user", $null, $link);
            
        }

        $topNQueryString = ""
        if ($this.MaxObjectsToScan -ne 0)
        {
            #Add this to QS only if $MaxObj is specified. If so, this will download only $maxObj configs.
            $topNQueryString = '&$top='+ $this.MaxObjectsToScan
        }
        #Get project resources
        if ($this.ProjectNames.Count -gt 0) {
            $this.PublishCustomMessage("Querying api for resources to be scanned. This may take a while...");

            $this.PublishCustomMessage("Getting project configurations...");
            #TODO: By default api return only 100 projects. Added $top=500 to fetch first 500 projects.
            $apiURL = 'https://dev.azure.com/{0}/_apis/projects?$top=500&api-version=5.1' -f $($this.SubscriptionContext.SubscriptionName);
            $responseObj = "";
            try { 
                $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL) ;
            }
            catch {
                Write-Host 'Project not found: Incorrect project name or you do not have neccessary permission to access the project.' -ForegroundColor Red
                throw;
            }
            if (([Helpers]::CheckMember($responseObj, "count") -and $responseObj[0].count -gt 0) -or (($responseObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($responseObj[0], "name")))
            {
                if($this.ProjectNames -eq "*")
                {
                    $projects = $responseObj
                }
                else {
                    $projects = $responseObj | Where-Object { $this.ProjectNames -contains $_.name } 
                }
                
                $responseObj = $null;  
                Remove-Variable responseObj;
                
                $nProj = $this.MaxObjectsToScan;
                if (!$projects) {
                    Write-Host 'No project found to perform the scan.' -ForegroundColor Red
                }
                $TotalSvc = 0;
                $ScannableSvc = 0;
                # fetching the installed extensions count for the organization
                $resourceURL = "https://extmgmt.dev.azure.com/$($this.organizationName)/_apis/extensionmanagement/installedextensions?api-version=6.0-preview.1"
                try { 
                    $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL) ;
                }
                catch {}
                # storing the data into a data structure (orgTelemetryData)
                $this.orgTelemetryData["installed_extensions"] = $responseList.Length
                $this.orgTelemetryData["organization_name"] = $this.organizationName
                foreach ($thisProj in $projects) 
                {
                    $projectName = $thisProj.name
                    $projectId = $thisProj.id;
                    # getting all the resources count
                    # and sending them to telemetry as well
                    $this.GetResourceCount($projectName, $organizationId, $projectId)
                    if ($this.ResourceTypeName -in ([ResourceTypeName]::Project, [ResourceTypeName]::All, [ResourceTypeName]::Org_Project_User)  -and ([string]::IsNullOrEmpty($this.serviceId))) 
                    {
                        #First condition if 'includeAdminControls' switch is passed or user is PCA or User is PA.
                        #Second condition if explicitly -rtn flag passed to org or Org_Project_User 
                        #Adding $this.isAdminControlScan() check in the end in case $this.isUserPCA is not checked (this happens when u scan using -svcid flag and org controls are not resolved/scanned)
                        if ( ($this.includeAdminControls -or $this.isUserPCA -or $this.isUserPA($projectName) -or $this.isAdminControlScan()))  {
                            $link = $thisProj.url.Replace('/_apis/projects', '') + '/_settings/'
                            $resourceId = "organization/$organizationId/project/$projectId" 
                            $this.AddSVTResource($thisProj.name, $this.organizationName,"ADO.Project", $resourceId, $thisProj, $link);
                        }
                        #Third condition if 'gads' contains only admin scan parame, then no need to ask for includeAdminControls switch
                        elseif ( ($this.ResourceTypeName -in ([ResourceTypeName]::Project, [ResourceTypeName]::Org_Project_User)) -or ( $this.BuildNames.Count -eq 0 -and $this.ReleaseNames.Count -eq 0 -and $this.ServiceConnections.Count -eq 0 -and $this.AgentPools.Count -eq 0 -and $this.VariableGroups.Count -eq 0) ) {
                            $this.PublishCustomMessage("`r`n");
                            $this.PublishCustomMessage("You have requested scan for project controls. However, you do not have admin permission. Use '-IncludeAdminControls' if you'd still like to scan them. (Some controls may not scan correctly due to access issues.)", [MessageType]::Info);
                        }
                    }
                    #check if long running scan allowed or not.
                    if(!$this.isAllowLongRunningScanCheck())
                    {
                        return;
                    }

                    if($this.serviceId.Count -gt 0) {
                        $this.FetchServiceAssociatedResources($this.serviceId, $projectName);
                    }

                    if ($this.BuildNames.Count -gt 0 -and ($this.ResourceTypeName -in ([ResourceTypeName]::Build, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User))) {
                        if ($this.ProjectNames -ne "*") {
                            $this.PublishCustomMessage("Getting build configurations...");
                        }

                        if ($this.BuildNames -eq "*") {
                            $buildDefnURL = ("https://dev.azure.com/{0}/{1}/_apis/build/definitions?api-version=4.1" +$topNQueryString) -f $($this.SubscriptionContext.SubscriptionName), $thisProj.name;
                            $buildDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($buildDefnURL) 
                            if (([Helpers]::CheckMember($buildDefnsObj, "count") -and $buildDefnsObj[0].count -gt 0) -or (($buildDefnsObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($buildDefnsObj[0], "name"))) {
                                $nObj = $this.MaxObjectsToScan
                                foreach ($bldDef in $buildDefnsObj) {
                                    $link = $bldDef.url.split('?')[0].replace('_apis/build/Definitions/', '_build?definitionId=');
                                    $buildResourceId = "organization/$organizationId/project/$projectId/build/$($bldDef.id)";
                                    $this.AddSVTResource($bldDef.name, $bldDef.project.name, "ADO.Build", $buildResourceId, $bldDef, $link);
                                   
                                    if (--$nObj -eq 0) { break; } 
                                }
                                $buildDefnsObj = $null;
                                Remove-Variable buildDefnsObj;
                            }
                        }
                        else {
                            $this.BuildNames | ForEach-Object {
                                $buildName = $_
                                $buildDefnURL = "https://{0}.visualstudio.com/{1}/_apis/build/definitions?name={2}&api-version=5.1-preview.7" -f $($this.SubscriptionContext.SubscriptionName), $projectName, $buildName;
                                $buildDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($buildDefnURL) 
                                if (([Helpers]::CheckMember($buildDefnsObj, "count") -and $buildDefnsObj[0].count -gt 0) -or (($buildDefnsObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($buildDefnsObj[0], "name"))) {
                                    foreach ($bldDef in $buildDefnsObj) {
                                        $link = $bldDef.url.split('?')[0].replace('_apis/build/Definitions/', '_build?definitionId=');
                                        $buildResourceId = "organization/$organizationId/project/$projectId/build/$($bldDef.id)";
                                        $this.AddSVTResource($bldDef.name, $bldDef.project.name, "ADO.Build", $buildResourceId, $bldDef, $link);
                                        
                                    }
                                    $buildDefnsObj = $null;
                                    Remove-Variable buildDefnsObj;
                                }
                            }
                        }
                        
                        #Initialysing null to SecurityNamespaceId variable for new scan, it is static variable, setting once only in svc class and same value is applicable for all the svc con withing org
                        [Build]::SecurityNamespaceId = $null;
                            
                    }
                    # repos
                    if ($this.RepoNames.Count -gt 0 -and ($this.ResourceTypeName -in ([ResourceTypeName]::Repo, [ResourceTypeName]::All))) {
                        if ($this.ProjectNames -ne "*") {
                            $this.PublishCustomMessage("Getting repos configurations...");
                        }
                        $repoDefnURL = ("https://dev.azure.com/$($this.organizationName)/$($projectName)/_apis/git/repositories?api-version=6.0")
                        $repoDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($repoDefnURL) 
                        if ($this.RepoNames -eq "*") {
                            if (([Helpers]::CheckMember($repoDefnsObj, "count") -and $repoDefnsObj[0].count -gt 0) -or (($repoDefnsObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($repoDefnsObj[0], "name"))) {
                                $nObj = $this.MaxObjectsToScan
                                foreach ($repo in $repoDefnsObj) {
                                    $link = $repo.url.split('?')[0].replace('_apis/git/repositories', '_git');
                                    $repoResourceId = "organization/$organizationId/project/$projectId/repositories/$($repo.id)";
                                    $this.AddSVTResource($repo.name, $repo.project.name, "ADO.Repo", $repoResourceId, $repo, $link);
                                   
                                    if (--$nObj -eq 0) { break; } 
                                }
                                $repoDefnsObj = $null;
                                Remove-Variable repoDefnsObj;
                            }
                        }
                        else {
                            $this.RepoNames | ForEach-Object {
                                $repoName = $_
                                $repoURL = "https://dev.azure.com/$($this.organizationName)/$($projectName)/_apis/git/repositories/$($repoName)?api-version=5.0"
                                $repo = [WebRequestHelper]::InvokeGetWebRequest($repoURL) 
                                $link = $repo.url.split('?')[0].replace('_apis/git/repositories', '_git');
                                $repoResourceId = "organization/$organizationId/project/$projectId/repositories/$($repo.id)";
                                $this.AddSVTResource($repo.name, $repo.project.name, "ADO.Repo", $repoResourceId, $repo, $link);
                            }
                        }
                            
                    }
                    #check if long running scan allowed or not.
                    if(!$this.isAllowLongRunningScanCheck())
                    {
                        return;
                    }
                    if ($this.ReleaseNames.Count -gt 0 -and ($this.ResourceTypeName -in ([ResourceTypeName]::Release, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User)))
                    {
                        if ($this.ProjectNames -ne "*") {
                            $this.PublishCustomMessage("Getting release configurations...");
                        }
                        if ($this.ReleaseNames -eq "*") 
                        {
                            $releaseDefnURL = ("https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?api-version=4.1-preview.3" +$topNQueryString) -f $($this.SubscriptionContext.SubscriptionName), $projectName;
                            $releaseDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($releaseDefnURL);
                            if (([Helpers]::CheckMember($releaseDefnsObj, "count") -and $releaseDefnsObj[0].count -gt 0) -or (($releaseDefnsObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($releaseDefnsObj[0], "name"))) {
                                $nObj = $this.MaxObjectsToScan
                                foreach ($relDef in $releaseDefnsObj) {
                                    $link = "https://dev.azure.com/{0}/{1}/_release?_a=releases&view=mine&definitionId={2}" -f $this.SubscriptionContext.SubscriptionName, $projectName, $relDef.url.split('/')[-1];
                                    $releaseResourceId = "organization/$organizationId/project/$projectId/release/$($relDef.id)";
                                    $this.AddSVTResource($relDef.name, $projectName, "ADO.Release", $releaseResourceId, $null, $link);
                                    
                                    if (--$nObj -eq 0) { break; } 
                                }
                                $releaseDefnsObj = $null;
                            }
                        }
                        else {
                            try {
                                $this.ReleaseNames | ForEach-Object {
                                    $releaseName = $_
                                    $releaseDefnURL = "https://{0}.vsrm.visualstudio.com/_apis/Contribution/HierarchyQuery/project/{1}?api-version=5.0-preview.1" -f $($this.SubscriptionContext.SubscriptionName), $projectName;
                                    $inputbody = "{
                                    'contributionIds': [
                                        'ms.vss-releaseManagement-web.search-definitions-data-provider'
                                    ],
                                    'dataProviderContext': {
                                        'properties': {
                                            'searchText': '$releaseName',
                                            'sourcePage': {
                                                'routeValues': {
                                                    'project': '$projectName'
                                                }
                                            }
                                        }
                                    }
                                }" | ConvertFrom-Json
                                
                                    $releaseDefnsObj = [WebRequestHelper]::InvokePostWebRequest($releaseDefnURL, $inputbody);
                                    if (([Helpers]::CheckMember($releaseDefnsObj, "dataProviders") -and $releaseDefnsObj.dataProviders."ms.vss-releaseManagement-web.search-definitions-data-provider") -and [Helpers]::CheckMember($releaseDefnsObj.dataProviders."ms.vss-releaseManagement-web.search-definitions-data-provider", "releaseDefinitions") ) {

                                        $releaseDefinitions = $releaseDefnsObj.dataProviders."ms.vss-releaseManagement-web.search-definitions-data-provider".releaseDefinitions  | Where-Object {$_.name -eq $releaseName };

                                        foreach ($relDef in $releaseDefinitions) {
                                            $link = "https://dev.azure.com/{0}/{1}/_release?_a=releases&view=mine&definitionId={2}" -f $this.SubscriptionContext.SubscriptionName, $projectName, $relDef.url.split('/')[-1];
                                            $releaseResourceId = "organization/$organizationId/project/$projectId/release/$($relDef.id)";
                                            $this.AddSVTResource($relDef.name, $projectName, "ADO.Release", $releaseResourceId, $null, $link);
                                            
                                        }
                                        $releaseDefinitions = $null;
                                    }

                                }
                            }
                            catch {
                                #Write-Error $_.Exception.Message;
                                Write-Warning "Release pipelines for the project [$($projectName)] could not be fetched.";
                            }
                        }

                        #Initialysing null to SecurityNamespaceId variable for new scan, it is static variable, setting once only in release class and same value is applicable for all the release pipelines withing org
                        [Release]::SecurityNamespaceId = $null;
                            
                    }
                    #check if long running scan allowed or not.
                    if(!$this.isAllowLongRunningScanCheck())
                    {
                        return;
                    }

                    #Note: $topNQueryString is currently not supported in the SvcConn and AgentPool APIs.
                    if ($this.ServiceConnections.Count -gt 0 -and ($this.ResourceTypeName -in ([ResourceTypeName]::ServiceConnection, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User)))
                    {
                        if ($this.ProjectNames -ne "*") {
                            $this.PublishCustomMessage("Getting service endpoint configurations...");
                        }
                    
                        # Here we are fetching all the svc conns in the project and then filtering out. But in build & release we fetch them individually unless '*' is used for fetching all of them.
                        $serviceEndpointURL = ("https://dev.azure.com/{0}/{1}/_apis/serviceendpoint/endpoints?api-version=4.1-preview.1") -f $($this.organizationName), $($projectName);
                        $serviceEndpointObj = [WebRequestHelper]::InvokeGetWebRequest($serviceEndpointURL)
                        $TotalSvc += ($serviceEndpointObj | Measure-Object).Count
                    
                        if (([Helpers]::CheckMember($serviceEndpointObj, "count") -and $serviceEndpointObj[0].count -gt 0) -or (($serviceEndpointObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($serviceEndpointObj[0], "name"))) {
                            # Currently get only Azure Connections as all controls are applicable for same
                    
                            $Connections = $null;
                            if ($this.ServiceConnections -eq "*") {
                                $Connections = $serviceEndpointObj | Where-Object { ($_.type -eq "azurerm" -or $_.type -eq "azure" -or $_.type -eq "git" -or $_.type -eq "github" -or $_.type -eq "externaltfs") } 
                            }
                            else {
                                $Connections = $serviceEndpointObj | Where-Object { ($_.type -eq "azurerm" -or $_.type -eq "azure" -or $_.type -eq "git" -or $_.type -eq "github" -or $_.type -eq "externaltfs") -and ($this.ServiceConnections -eq $_.name) }  
                            }
                            $ScannableSvc += ($connections | Measure-Object).Count

                            #Initialising null to SecurityNamespaceId variable for new scan, it is static variable, setting once only in svc class and same value is applicable for all the svc con withing org
                            [ServiceConnection]::SecurityNamespaceId = $null;
                            $serviceEndpointObj = $null;
                            Remove-Variable  serviceEndpointObj;
                            $nObj = $this.MaxObjectsToScan
                            foreach ($connectionObject in $Connections) {
                                $resourceId = "organization/$organizationId/project/$projectId/serviceconnection/$($connectionObject.Id)";
                                $link = "https://dev.azure.com/$($this.organizationName)/$projectId/_settings/adminservices?resourceId=$($connectionObject.Id)"; 
                                $this.AddSVTResource($connectionObject.name, $projectName, "ADO.ServiceConnection", $resourceId, $connectionObject, $link);
                                
                                if (--$nObj -eq 0) { break; }
                            }
                        }
                    }
                    #check if long running scan allowed or not.
                    if(!$this.isAllowLongRunningScanCheck())
                    {
                        return;
                    }                    
                    if ($this.AgentPools.Count -gt 0 -and ($this.ResourceTypeName -in ([ResourceTypeName]::AgentPool, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User))) 
                    {
                        if ($this.ProjectNames -ne "*") {
                            $this.PublishCustomMessage("Getting agent pools configurations...");
                        }
                        # Here we are fetching all the agent pools in the project and then filtering out. But in build & release we fetch them individually unless '*' is used for fetching all of them.
                        $agentPoolsDefnURL = ("https://{0}.visualstudio.com/{1}/_settings/agentqueues?__rt=fps&__ver=2") -f $($this.SubscriptionContext.SubscriptionName), $projectName;
                        try {
                        
                            $agentPoolsDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($agentPoolsDefnURL);
                            
                            #Here the return obj for agent pool is different than prj, build, release & svc conns. Also, Azure Pipelines agent pool will always be a part of org and project. We can't delete it.
                            if (([Helpers]::CheckMember($agentPoolsDefnsObj, "fps.dataProviders.data") ) -and (($agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider") -and $agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider".taskAgentQueues)) {
                                $nObj = $this.MaxObjectsToScan
                                $taskAgentQueues = $null;
                                if ($this.AgentPools -eq "*") {
                                    # We need to filter out legacy agent pools (Hosted, Hosted VS 2017 etc.) as they are not visible to user on the portal. As a result, they won't be able to remediate their respective controls
                                    $taskAgentQueues = $agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider".taskAgentQueues | where-object{$_.pool.isLegacy -eq $false};
                                }
                                else {
                                    $taskAgentQueues = $agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider".taskAgentQueues | Where-Object {($_.pool.isLegacy -eq $false) -and ($this.AgentPools -contains $_.name) } 
                                }

                                #Filtering out "Azure Pipelines" agent pool from scan as it is created by ADO by default and some of its settings are not editable (grant access to all pipelines, auto-provisioning etc.)
                                $taskAgentQueues = $taskAgentQueues | where-object{$_.name -ne "Azure Pipelines"};
                                
                                foreach ($taq in $taskAgentQueues) {
                                    $resourceId = "https://{0}.visualstudio.com/_apis/securityroles/scopes/distributedtask.agentqueuerole/roleassignments/resources/{1}_{2}" -f $($this.SubscriptionContext.SubscriptionName), $($taq.projectId), $taq.id
                                    $agtpoolResourceId = "organization/$organizationId/project/$projectId/agentpool/$($taq.id)";
                                    $link = "https://{0}.visualstudio.com/{1}/_settings/agentqueues?queueId={2}&view=security" -f $($this.SubscriptionContext.SubscriptionName), $($taq.projectId), $taq.id
                                    $this.AddSVTResource($taq.name, $projectName, "ADO.AgentPool", $agtpoolResourceId, $null, $link);
                                    
                                    if (--$nObj -eq 0) { break; }
                                }
                                $taskAgentQueues = $null;
                                Remove-Variable taskAgentQueues;
                            }
                        }
                        catch {
                            Write-Warning "Agent pools for the project [$($projectName)] could not be fetched.";
                        }              
                    }
                    #check if long running scan allowed or not.
                    if(!$this.isAllowLongRunningScanCheck())
                    {
                        return;
                    }
                    if ($this.VariableGroups.Count -gt 0 -and ($this.ResourceTypeName -in ([ResourceTypeName]::VariableGroup, [ResourceTypeName]::All)))
                    {
                        if ($this.ProjectNames -ne "*") {
                            $this.PublishCustomMessage("Getting variable group configurations...");
                        }
                    
                        # Here we are fetching all the var grps in the project and then filtering out. But in build & release we fetch them individually unless '*' is used for fetching all of them.
                        $variableGroupURL = ("https://{0}.visualstudio.com/{1}/_apis/distributedtask/variablegroups?api-version=6.1-preview.2") -f $($this.organizationName), $projectId;
                        $variableGroupObj = [WebRequestHelper]::InvokeGetWebRequest($variableGroupURL)
                    
                        if (([Helpers]::CheckMember($variableGroupObj, "count") -and $variableGroupObj[0].count -gt 0) -or (($variableGroupObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($variableGroupObj[0], "name"))) {
                    
                            $varGroups = $null;
                            if ($this.VariableGroups -eq "*") {
                                $varGroups = $variableGroupObj 
                            }
                            else {
                                $varGroups = $variableGroupObj | Where-Object { $this.VariableGroups -eq $_.name }  
                            }

                            $nObj = $this.MaxObjectsToScan
                            foreach ($group in $varGroups) {
                                $resourceId = "organization/$organizationId/project/$projectId/variablegroup/$($group.Id)";
                                $link = ("https://{0}.visualstudio.com/{1}/_library?itemType=VariableGroups&view=VariableGroupView&variableGroupId={2}") -f $($this.organizationName), $projectName, $($group.Id); 
                                $this.AddSVTResource($group.name, $projectName, "ADO.VariableGroup", $resourceId, $group, $link);
                                
                                if (--$nObj -eq 0) { break; }
                            }
                        }
                    }
                    #check if long running scan allowed or not.
                    if(!$this.isAllowLongRunningScanCheck())
                    {
                        return;
                    }                    
                    if (--$nProj -eq 0) { break; } #nProj is set to MaxObj before loop.
                    
                }
                #sending the details to telemetry as well
                [AIOrgTelemetryHelper]::PublishEvent("Organization resources count",  $this.orgTelemetryData, @{})
                if ($TotalSvc -gt 0)
                {
                    #$this.PublishCustomMessage("Total service connections: $TotalSvc");
                    #$this.PublishCustomMessage("Total service connections that will be scanned: $ScannableSvc");

                    $properties =  @{ 
                        "TotalServiceConnections" = $TotalSvc;
                        "ScannableServiceConnections" = $ScannableSvc; 
                    }
                    [AIOrgTelemetryHelper]::PublishEvent( "Service Connections count",$properties, @{})
                }
            }
        }
        $this.SVTResourcesFoundCount = $this.SVTResources.Count
    }

    [bool] isAllowLongRunningScanCheck()
    {
        if ($this.SVTResources.count -gt $this.longRunningScanCheckPoint) 
        {
            if (!$this.isAllowLongRunningScanInPolicy) {
                Write-Host ([Constants]::LongRunningScanStopByPolicyMsg) -ForegroundColor Yellow;
                $this.SVTResources = $null
                return $false;
            }
            elseif(!$this.allowLongRunningScan)
            {
                Write-Host ([Constants]::LongRunningScanStopMsg -f $this.longRunningScanCheckPoint) -ForegroundColor Yellow;
                $this.SVTResources = $null
                return $false;
            }
        }
        return $true;
    }

    [void] AddSVTResource([string] $name, [string] $resourceGroupName, [string] $resourceType, [string] $resourceId, [PSObject] $resourceDetailsObj, $resourceLink)
    {
        $svtResource = [SVTResource]::new();
        $svtResource.ResourceName = $name;
        if ($resourceGroupName) {
            $svtResource.ResourceGroupName = $resourceGroupName;
        }
        $svtResource.ResourceType = $resourceType;
        $svtResource.ResourceId = $resourceId;
        $svtResource.ResourceTypeMapping = ([SVTMapping]::AzSKADOResourceMapping | Where-Object { $_.ResourceType -eq $resourceType } | Select-Object -First 1)

        if ($resourceDetailsObj) {
            $svtResource.ResourceDetails = $resourceDetailsObj;
            $svtResource.ResourceDetails | Add-Member -Name 'ResourceLink' -Type NoteProperty -Value $resourceLink;
        }
        else {
            $svtResource.ResourceDetails = New-Object -TypeName psobject -Property @{ ResourceLink = $resourceLink }
        }                         
                                        
        $this.SVTResources += $svtResource
    }

    [void] FetchServiceAssociatedResources($svcId, $projectName)
    {
        $this.PublishCustomMessage("Getting service associated resources...");
        $metaInfo = [MetaInfoProvider]::Instance;
        
        $rsrcList = $metaInfo.FetchServiceAssociatedResources($svcId, $projectName, $this.ResourceTypeName);
        $bFoundSvcMappedObjects = $false
        if ($null -ne $rsrcList)
        {
            if ($this.ResourceTypeName -in ([ResourceTypeName]::Build, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User))
            {
                if ($rsrcList.Builds -and $rsrcList.Builds.Count -gt 0)
                {
                    $this.BuildNames = $rsrcList.Builds.buildDefinitionName
                    $bFoundSvcMappedObjects = $true
                } 
            }
            if ($this.ResourceTypeName -in ([ResourceTypeName]::Release, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User))
            {
                if ($rsrcList.Releases -and $rsrcList.Releases.Count -gt 0)
                {
                    $this.ReleaseNames = $rsrcList.Releases.releaseDefinitionName
                    $bFoundSvcMappedObjects = $true
                }
            }
            if ($this.ResourceTypeName -in ([ResourceTypeName]::ServiceConnection, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User))
            {
                if ($rsrcList.ServiceConnections -and $rsrcList.ServiceConnections.Count -gt 0)
                {
                    $this.ServiceConnections = $rsrcList.ServiceConnections.serviceConnectionName
                    $bFoundSvcMappedObjects = $true
                }
            }
            if ($this.ResourceTypeName -in ([ResourceTypeName]::AgentPool, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User))
            {
                if ($rsrcList.AgentPools -and $rsrcList.AgentPools.Count -gt 0)
                {
                    $this.AgentPools = $rsrcList.AgentPools.agentPoolName
                    $bFoundSvcMappedObjects = $true
                }
            }
            if ($this.ResourceTypeName -in ([ResourceTypeName]::VariableGroup, [ResourceTypeName]::All))
            {
                if ($rsrcList.VariableGroups -and $rsrcList.VariableGroups.Count -gt 0)
                {
                    $this.VariableGroups = $rsrcList.VariableGroups.variableGroupName
                    $bFoundSvcMappedObjects = $true
                }
            }
        }
        if ($bFoundSvcMappedObjects -eq $false)
        {
            $this.PublishCustomMessage("Could not find any objects mapped to the provided service id.", [MessageType]::Warning);
        }
    }
    #check for PCA group members
    [bool] isAdminControlScan()
    {
        $allowedAdminGrp = $null;
        if (!$this.ControlSettings) {
            $this.ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
        }
        if ([Helpers]::CheckMember($this.ControlSettings, "AllowAdminControlScanForGroups")) {
            $allowedAdminGrp = $this.ControlSettings.AllowAdminControlScanForGroups | where { $_.ResourceType -eq "Organization" } | select-object -property GroupNames 
        }
        $this.isUserPCA = [AdministratorHelper]::isUserOrgAdminMember($this.organizationName, $allowedAdminGrp);
        return $this.isUserPCA;
    }

    #check for PA group members
    [bool] isUserPA($project)
    {
        $allowedAdminGrp = $null;
        if (!$this.ControlSettings) {
            $this.ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
        }
        if ([Helpers]::CheckMember($this.ControlSettings, "AllowAdminControlScanForGroups")) {
            $allowedAdminGrp = $this.ControlSettings.AllowAdminControlScanForGroups | where { $_.ResourceType -eq "Project" } | select-object -property GroupNames 
        }
        
        return [AdministratorHelper]::isUserProjectAdminMember($this.organizationName, $project, $allowedAdminGrp);
    }
}
