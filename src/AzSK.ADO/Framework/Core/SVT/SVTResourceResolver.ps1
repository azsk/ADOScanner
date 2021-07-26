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

	[bool] $IsAIEnabled = $false;

    [string] $ResourcePath;
    [string] $BuildsFolderPath;
    [string] $ReleasesFolderPath;
    [string] $organizationName
    hidden [string[]] $ProjectNames = @();
    hidden [string[]] $BuildNames = @();
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

    hidden [string[]] $serviceIds = @();

    [bool] $includeAdminControls = $false;
    [bool] $isUserPCA = $false;
    [bool] $skipOrgUserControls = $false

    [bool] $UsePartialCommits=$false;
    [bool] $DoNotRefetchResources=$false;
    [bool] $isPartialScanActive=$false;
    [PSObject] $nonScannedResources;

    hidden [string[]] $BuildIds = @();
    hidden [string[]] $ReleaseIds = @();
    hidden [string[]] $AgentPoolIds = @();
    hidden [string[]] $ServiceConnectionIds = @();
    hidden [string[]] $VariableGroupIds = @();
    hidden [bool] $isServiceIdBasedScan = $false;

    #Common svt resources
    hidden [string[]] $RepoNames = @();
    hidden [string[]] $SecureFileNames = @();
    hidden [string[]] $FeedNames = @();
    hidden [string[]] $EnvironmentNames = @();


    SVTResourceResolver([string]$organizationName, $ProjectNames, $BuildNames, $ReleaseNames, $AgentPools, $ServiceConnectionNames, $VariableGroupNames, $MaxObj, $ScanAllResources, $PATToken, $ResourceTypeName, $AllowLongRunningScan, $ServiceIds, $IncludeAdminControls, $skipOrgUserControls, $RepoNames, $SecureFileNames, $FeedNames, $EnvironmentNames,$BuildsFolderPath,$ReleasesFolderPath,$UsePartialCommits,$DoNotRefetchResources): Base($organizationName, $PATToken) {


        $this.MaxObjectsToScan = $MaxObj #default = 0 => scan all if "*" specified...
        $this.SetallTheParamValues($organizationName, $ProjectNames, $BuildNames, $ReleaseNames, $AgentPools, $ServiceConnectionNames, $VariableGroupNames, $ScanAllResources, $PATToken, $ResourceTypeName, $AllowLongRunningScan, $ServiceIds, $IncludeAdminControls, $BuildsFolderPath,$ReleasesFolderPath,$UsePartialCommits,$DoNotRefetchResources);
        $this.skipOrgUserControls = $skipOrgUserControls

        $this.RepoNames += $this.ConvertToStringArray($RepoNames);
        $this.SecureFileNames += $this.ConvertToStringArray($SecureFileNames);
        $this.FeedNames += $this.ConvertToStringArray($FeedNames);

        [PartialScanManager]::ClearInstance();
    

        $this.EnvironmentNames += $this.ConvertToStringArray($EnvironmentNames);
    }

    #Constructor for Set-AzSKADOSecurityStatus
    SVTResourceResolver([string]$organizationName, $ProjectNames, $ResourceNames, $ExcludeResourceNames, $PATToken, $ResourceTypeName): Base($organizationName, $PATToken) {

        $this.organizationName = $organizationName
        $this.ProjectNames = $ProjectNames
        $this.ResourceTypeName = $ResourceTypeName

        if (-not [string]::IsNullOrEmpty($ResourceNames)) {
            $this.ResourceNames += $this.ConvertToStringArray($ResourceNames);
        }
        if (-not [string]::IsNullOrEmpty($ExcludeResourceNames)) {
                $this.ExcludeResourceNames += $this.ConvertToStringArray($ExcludeResourceNames);
        }
    }


    [void] SetallTheParamValues([string]$organizationName, $ProjectNames, $BuildNames, $ReleaseNames, $AgentPools, $ServiceConnectionNames, $VariableGroupNames, $ScanAllResources, $PATToken, $ResourceTypeName, $AllowLongRunningScan, $ServiceIds, $IncludeAdminControls,$BuildsFolderPath,$ReleasesFolderPath,$UsePartialCommits,$DoNotRefetchResources) {

        $this.organizationName = $organizationName
        $this.ResourceTypeName = $ResourceTypeName
        $this.allowLongRunningScan = $AllowLongRunningScan
        $this.includeAdminControls = $IncludeAdminControls
        $this.BuildsFolderPath = $BuildsFolderPath.Trim()
        $this.UsePartialCommits=$UsePartialCommits
        $this.DoNotRefetchResources=$DoNotRefetchResources
        $this.ReleasesFolderPath = $ReleasesFolderPath.Trim()

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

        if (-not [string]::IsNullOrEmpty($ServiceIds)) {
            $this.serviceIds += $this.ConvertToStringArray($ServiceIds);
            $this.ProjectNames += $this.ConvertToStringArray($ProjectNames);
            if ($this.serviceId.Count -eq 0) {
                throw [SuppressedException] "The parameter 'ServiceId' does not contain any string."
            }
        }

        #User should always provide project name (comma separated list or '*') to scan builds in an org. Else no controls will be scanned if -rtn is 'Build'
        #if (-not [string]::IsNullOrEmpty($ResourceTypeName) -and $ResourceTypeName -ne "All" -and ([string]::IsNullOrEmpty($ProjectNames))) {
        #    $this.ProjectNames = "*"
        #}

        if ($ScanAllResources -and [string]::IsNullOrEmpty($ServiceIds)) {
            #ScanAllResources should scan all artifacts within the targeted projects (if provided explicitly)
            if ([string]::IsNullOrEmpty($ProjectNames)) {
                $this.ProjectNames = "*"
            }
            $this.BuildNames = "*"
            $this.ReleaseNames = "*"
            $this.AgentPools = "*"
            $this.ServiceConnections = "*"
            $this.VariableGroups = "*"
            $this.RepoNames = "*"
            $this.SecureFileNames = "*"
            $this.FeedNames = "*"
            $this.EnvironmentNames = "*"
        }

        if (( $this.MaxObjectsToScan -eq 0 -or $this.MaxObjectsToScan -gt $this.longRunningScanCheckPoint) -and ($this.ProjectNames -eq "*" -or $this.BuildNames -eq "*" -or $this.ReleaseNames -eq "*" -or $this.ServiceConnections -eq "*" -or $this.AgentPools -eq "*" -or $this.VariableGroups -eq "*")) {
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

    [void] LoadResourcesForScan() {
        #Call APIS for Organization,User/Builds/Releases/ServiceConnections
        $organizationId = "";

        if ([RemoteReportHelper]::IsAIOrgTelemetryEnabled()) {
            $this.IsAIEnabled = $true;
        }

        #Checking if org name is correct
        try {
            if (-not [string]::IsNullOrWhiteSpace($env:RefreshToken) -and -not [string]::IsNullOrWhiteSpace($env:ClientSecret))
            {
                $apiURL = "https://app.vssps.visualstudio.com/_apis/accounts"
                $responseObj = "";

                $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL) ;
                if (-not [string]::IsNullOrEmpty($responseObj) -and ($responseObj | Measure-Object).Count -gt 0)
                {
                    $organizationId = ($responseObj | Where-Object {$_.accountname -eq $this.organizationname}).AccountId
                }
                Remove-Variable responseObj;
            }
            else
            {
                $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $($this.organizationName);

                $inputbody = "{'contributionIds':['ms.vss-features.my-organizations-data-provider'],'dataProviderContext':{'properties':{'sourcePage':{'url':'https://dev.azure.com/$($this.organizationName)','routeId':'ms.vss-tfs-web.suite-me-page-route','routeValues':{'view':'projects','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json
                $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL, $inputbody);
                $organizationId = ($responseObj[0].dataProviders."ms.vss-features.my-organizations-data-provider".organizations | Where-Object {$_.name -eq $this.organizationName}).id
                $inputbody = $null;
                Remove-Variable inputbody;
            }
        }
        catch {
            $user = [ContextHelper]::GetCurrentSessionUser();
            $this.PublishCustomMessage("Organization not found: Incorrect organization name or '$($user)' account does not have necessary permission to access the organization. Use -ResetCredentials parameter in command to login with another account. `n", [MessageType]::Warning);
            throw;
        }
        if ($this.ResourceTypeName -in ([ResourceTypeName]::Organization, [ResourceTypeName]::All, [ResourceTypeName]::Org_Project_User) -and ([string]::IsNullOrEmpty($this.serviceIds)) )
        {
            #First condition if 'includeAdminControls' switch is passed or user is admin(PCA).
            #Second condition if explicitly -rtn flag passed to org or Org_Project_User
            #Third condition if 'gads' contains only admin scan parame, then no need to ask for includeAdminControls switch
            if (-not $this.skipOrgUserControls) {
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
        }
        if (-not $this.skipOrgUserControls) {
            if ($this.ResourceTypeName -in ([ResourceTypeName]::User, [ResourceTypeName]::All, [ResourceTypeName]::Org_Project_User, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User)) {

                $link = "https://dev.azure.com/$($this.organizationName)/_settings/users"
                $this.AddSVTResource($this.organizationName, $null,"ADO.User", "organization/$($organizationId)/user", $null, $link);

            }
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
            #TODO: By default api return only 100 projects. Added $top=1000 to fetch first 1000 projects. If there are morethan 1000 projects, pagination is implemented to fetch them
            $apiURL = 'https://dev.azure.com/{0}/_apis/projects?$top=1000&api-version=6.0' -f $($this.OrganizationContext.OrganizationName);
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
                foreach ($thisProj in $projects)
                {
                    $projectName = $thisProj.name
                    $projectId = $thisProj.id;
                    [Hashtable] $projectData = @{
                        projectName = $projectName;
                        repositories = -1;
                        testPlan = -1;
                        build = -1;
                        release = -1;
                        taskGroups = -1;
                        agentPools = -1;
                        variableGroups = -1;
                        serviceConnections = -1;
                    };

                    if($this.UsePartialCommits -and $this.DoNotRefetchResources){
                        
                        [PartialScanManager] $partialScanMngr = [PartialScanManager]::GetInstance();
                        if(($partialScanMngr.IsPartialScanInProgress($this.OrganizationContext.OrganizationName) -eq [ActiveStatus]::Yes)  ){
                            Write-Host "Resuming scan from last commit. Fetching unscanned resources..." -ForegroundColor Yellow
                            $this.nonScannedResources = $partialScanMngr.GetNonScannedResources();
                            $this.IsPartialScanActive=$true;
                        }
                        else {
                            $this.IsPartialScanActive=$false;
                        }
                    }

                    if($this.IsPartialScanActive -and $this.nonScannedResources.Count -ne 0){
                        #$this.PublishCustomMessage("Resuming scan from last commit")
                        if ($this.BuildNames.Count -gt 0 -and ($this.ResourceTypeName -in ([ResourceTypeName]::Build, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User))) {
                            $this.createBuildSVTResource($projectName,$organizationId,$projectId);
                        }
                        if ($this.ServiceConnections.Count -gt 0 -and ($this.ResourceTypeName -in ([ResourceTypeName]::ServiceConnection, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User))){
                            $this.createServiceConnectionSVTResource($projectName,$organizationId,$projectId,$projectData)
                        }
                        $progressCount=1



                        foreach($nonScannedResource in $this.nonScannedResources){
                            $nonScannedResourceType=$this.FindResourceTypeFromPartialScan($nonScannedResource.Id)
                            $nonScannedresourceLink=$this.CreateResourceLinkFromPartialScan($nonScannedResource.Id,$nonScannedResourceType,$this.organizationName,$projectName,$projectId)
                            if($nonScannedResourceType -eq "ADO.Project"){
                                $this.AddSVTResource($nonScannedResource.Name,$projectName,$nonScannedResourceType, $nonScannedResource.Id,$thisProj , $nonScannedresourceLink)
                            }
                            elseif($nonScannedResourceType -eq "ADO.Organization" -or $nonScannedResourceType -eq "ADO.User"){
                                $this.AddSVTResource($nonScannedResource.Name,$null,$nonScannedResourceType, $nonScannedResource.Id, $null, $nonScannedresourceLink)
                            }
                            elseif($nonScannedResourceType -eq "ADO.Release" -or $nonScannedResourceType -eq "ADO.AgentPool"){
                                $this.AddSVTResource($nonScannedResource.Name,$projectName,$nonScannedResourceType, $nonScannedResource.Id,$null , $nonScannedresourceLink)
                            }
                            
                            Write-Progress -Activity "Fetching $($progressCount) of $($this.nonScannedResources.Length) unscanned resources " -Status "Progress: " -PercentComplete ($progressCount / $this.nonScannedResources.Length * 100)
                            $progressCount++;
                            


                        }
                        Write-Progress -Activity "All resources fetched" -Status "Ready" -Completed

                    }

                    else{

                    if ($this.ResourceTypeName -in ([ResourceTypeName]::Project, [ResourceTypeName]::All, [ResourceTypeName]::Org_Project_User)  -and ([string]::IsNullOrEmpty($this.serviceIds)))
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

                    if($this.serviceIds.Count -gt 0) 
                    {
                        foreach ($thisServiceId in $this.serviceIds)
                        {
                            $this.FetchServiceAssociatedResources($thisServiceId, $projectName);
                        }
                    }

                    if ($this.BuildNames.Count -gt 0 -and ($this.ResourceTypeName -in ([ResourceTypeName]::Build, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User))) {
                        if ($this.ProjectNames -ne "*") {
                            $this.PublishCustomMessage("Getting build configurations...");
                        }
                        if(-not [string]::IsNullOrEmpty($this.BuildsFolderPath)){
                            # Validate folder path is valid
                            $path = $this.BuildsFolderPath;
                            $this.BuildsFolderPath = $this.BuildsFolderPath.Replace(' ','%20').Replace('\','%5C')
                            $buildFoldersURL = "https://dev.azure.com/{0}/{1}/_apis/build/folders/{2}?api-version=6.1-preview.2"  -f $($this.OrganizationContext.OrganizationName), $thisProj.name, $this.BuildsFolderPath
                            $buildFoldersObj = [WebRequestHelper]::InvokeGetWebRequest($buildFoldersURL)
                            if($null -eq $buildFoldersObj -or (![Helpers]::CheckMember($buildFoldersObj[0],"Path"))){
                                $this.PublishCustomMessage("Folder path not found. Please validate the -BuildsFolderPath provided in the command. `n", [MessageType]::Warning);
                            }
                            else {
                                #Iterate on each folder to get applicale build definition if folders count is le 100
                                if ([string]::IsNullOrEmpty($topNQueryString)) {
                                    $topNQueryString = '&$top=10000'
                                }
                                $nObj=$this.MaxObjectsToScan;
                                if($buildFoldersObj.Count -le 100)
                                {
                                    $folderCount=1
                                    
                                    foreach($path in $buildFoldersObj.Path)
                                    {
                                        
                                        $formattedPath = $path.Replace(' ','%20').Replace('\','%5C')
                                        $buildDefByFolderURL = ('https://dev.azure.com/{0}/{1}/_apis/build/definitions?path={2}&queryOrder=lastModifiedDescending'+$topNQueryString) -f $($this.OrganizationContext.OrganizationName), $thisProj.name, $formattedPath
                                        Write-Progress -Activity "Searching in folder $($folderCount) of $($buildFoldersObj.Count) : $($path) " -Status "Progress: " -PercentComplete ($folderCount/ $buildFoldersObj.Count * 100)
                                        $this.addResourceToSVT($buildDefByFolderURL,"build",$projectName,$organizationId,$projectId,$true,$false,$null,[ref]$nObj)
                                        #if($nObj -eq 0) {break;} 
                                        $folderCount++;
                                    }
                                    Write-Progress -Activity "All builds fetched" -Status "Ready" -Completed
                                }
                                else {                                 
                                    $buildDefURL = ("https://dev.azure.com/{0}/{1}/_apis/build/definitions?queryOrder=lastModifiedDescending&api-version=6.0" + $topNQueryString) -f $($this.OrganizationContext.OrganizationName), $thisProj.name;
                                    $this.addResourceToSVT($buildDefURL,"build",$projectName, $organizationId, $projectId, $true, $true, $path,[ref]$nObj)                                  
                                }

                            }
                        }
                        elseif ($this.BuildNames -eq "*") {
                            if ([string]::IsNullOrEmpty($topNQueryString)) {
                                $topNQueryString = '&$top=10000'
                                $buildDefnURL = ("https://dev.azure.com/{0}/{1}/_apis/build/definitions?queryOrder=lastModifiedDescending&api-version=6.0" +$topNQueryString) -f $($this.OrganizationContext.OrganizationName), $thisProj.name;
                            }
                            else {
                                $buildDefnURL = ("https://dev.azure.com/{0}/{1}/_apis/build/definitions?api-version=6.0" +$topNQueryString) -f $($this.OrganizationContext.OrganizationName), $thisProj.name;
                            }

                            $nObj=$this.MaxObjectsToScan
                            $this.addResourceToSVT($buildDefnURL,"build",$projectName,$organizationId,$projectId,$false,$false,$null,[ref]$nObj);


                            }
                        
                        else {

                            $buildDefnURL = "";
                            #If service id based scan then will break the loop after one run because, sending all build ids to api as comma separated in one go.
                            for ($i = 0; $i -lt $this.BuildNames.Count; $i++) {
                                #If service id based scan then send all build ids to api as comma separated in one go.
                                if ($this.isServiceIdBasedScan -eq $true) {
                                    $buildDefnURL = "https://{0}.visualstudio.com/{1}/_apis/build/definitions?definitionIds={2}&api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $projectName, ($this.BuildIds -join ",");
                                }
                                else { #If normal scan (not service id based) then send each build name in api one by one.
                                    $buildDefnURL = "https://{0}.visualstudio.com/{1}/_apis/build/definitions?name={2}&api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $projectName, $this.BuildNames[$i];
                                }
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
                                #If service id based scan then no need to run loop as all the build ids has been sent to api as comma separated list in one go. so break the loop.
                                if ($this.isServiceIdBasedScan -eq $true) {
                                    break;
                                }
                            }
                        }

                        #Initialysing null to SecurityNamespaceId variable for new scan, it is static variable, setting once only in svc class and same value is applicable for all the svc con withing org
                        [Build]::SecurityNamespaceId = $null;

                    }
                    #check if long running scan allowed or not.
                    if(!$this.isAllowLongRunningScanCheck())
                    {
                        return;
                    }
                    if ($this.ReleaseNames.Count -gt 0 -and ($this.ResourceTypeName -in ([ResourceTypeName]::Release, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User)))
                    {
                        if ($this.ProjectNames -ne "*") {
                            $this.PublishCustomMessage("Getting release configurations...");
                        }


                        if(-not [string]::IsNullOrEmpty($this.ReleasesFolderPath)){
                            # Validate folder path is valid
                            $path = $this.ReleasesFolderPath;
                            $this.ReleasesFolderPath = $this.ReleasesFolderPath.Replace(' ','%20').Replace('\','%5C')
                            $releasesFoldersURL = "https://vsrm.dev.azure.com/{0}/{1}/_apis/release/folders/{2}?api-version=6.1-preview.2"  -f $($this.OrganizationContext.OrganizationName), $thisProj.name, $this.ReleasesFolderPath
                            $releasesFoldersObj = [WebRequestHelper]::InvokeGetWebRequest($releasesFoldersURL)
                            if($null -eq $releasesFoldersObj -or (![Helpers]::CheckMember($releasesFoldersObj[0],"Path"))){
                                $this.PublishCustomMessage("Folder path not found. Please validate the -ReleasesFolderPath provided in the command. `n", [MessageType]::Warning);
                            }
                            else {
                               #API doesnt provide all folders in a path, fallback to fetch all resources and then filter
                                $nObj=$this.MaxObjectsToScan                                                               
                                $releaseDefURL = ("https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?api-version=6.0" ) -f $($this.OrganizationContext.OrganizationName), $thisProj.name;
                                $this.addResourceToSVT($releaseDefURL,"release",$projectName, $organizationId, $projectId, $true, $true, $path,[ref]$nObj)                                  
                                

                            }
                           
                            
                            
                            
                        }


                        elseif ($this.ReleaseNames -eq "*")
                        {
                            $nObj=$this.MaxObjectsToScan
                            $releaseDefnURL = ("https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?api-version=6.0") -f $($this.OrganizationContext.OrganizationName), $projectName;
                            $this.addResourceToSVT($releaseDefnURL,"release",$projectName,$organizationId,$projectId,$false,$false,$null,[ref]$nObj);
                        }
                        else {
                            try {
                                $releaseDefnsObj = $null;
                                #If service id based scan then will break the loop after one run because, sending all release ids to api as comma separated in one go.
                                for ($i = 0; $i -lt $this.ReleaseNames.Count; $i++) {
                                    #If service id based scan then send all release ids to api as comma separated in one go.
                                    if ($this.isServiceIdBasedScan -eq $true) {
                                        $url = "https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?definitionIdFilter={2}&api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $projectName, ($this.ReleaseIds -join ",");
                                    }
                                    else { #If normal scan (not service id based) then send each release name in api one by one.
                                        $url = "https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?searchText={2}&isExactNameMatch=true&api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $projectName, $this.ReleaseNames[$i];
                                    }
                                    $releaseDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($url);

                                    foreach ($relDef in $releaseDefnsObj) {
                                        $link = "https://dev.azure.com/{0}/{1}/_release?_a=releases&view=mine&definitionId={2}" -f $this.OrganizationContext.OrganizationName, $projectName, $relDef.url.split('/')[-1];
                                        $releaseResourceId = "organization/$organizationId/project/$projectId/release/$($relDef.id)";
                                        $this.AddSVTResource($relDef.name, $projectName, "ADO.Release", $releaseResourceId, $null, $link);
                                    }
                                    #If service id based scan then no need to run loop as all the release ids has been sent to api as comma separated list in one go. so break the loop.
                                    if ($this.isServiceIdBasedScan -eq $true) {
                                        break;
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
                    if ($this.ServiceConnections.Count -gt 0 -and ($this.ResourceTypeName -in ([ResourceTypeName]::ServiceConnection, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User)))
                    {
                        if ($this.ProjectNames -ne "*") {
                            $this.PublishCustomMessage("Getting service endpoint configurations...");
                        }

                        # Here we are fetching all the svc conns in the project and then filtering out. But in build & release we fetch them individually unless '*' is used for fetching all of them.
                        $serviceEndpointURL = ("https://dev.azure.com/{0}/{1}/_apis/serviceendpoint/endpoints?includeDetails=True&api-version=6.0-preview.4") -f $($this.organizationName), $($projectName);
                        $serviceEndpointObj = [WebRequestHelper]::InvokeGetWebRequest($serviceEndpointURL)
                        $TotalSvc += ($serviceEndpointObj | Measure-Object).Count
                        # service connection count here
                        $projectData["serviceConnections"] = ($serviceEndpointObj | Measure-Object).Count;

                        if (([Helpers]::CheckMember($serviceEndpointObj, "count") -and $serviceEndpointObj[0].count -gt 0) -or (($serviceEndpointObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($serviceEndpointObj[0], "name"))) {
                            # Currently get only Azure Connections as all controls are applicable for same

                            $Connections = $null;
                            if ($this.ServiceConnections -eq "*") {
                                $Connections = $serviceEndpointObj #| Where-Object { ($_.type -eq "azurerm" -or $_.type -eq "azure" -or $_.type -eq "git" -or $_.type -eq "github" -or $_.type -eq "externaltfs" -or $_.type -eq "externalnpmregistry" -or $_.type -eq "generic" -or $_.type -eq "externalnugetfeed" -or $_.type -eq "PRSS" -or $_.type -eq "ESRPScan") }
                            }
                            else {
                                #If service id based scan then filter with serviceconnection ids
                                if ($this.isServiceIdBasedScan -eq $true) {
                                    $Connections = $serviceEndpointObj | Where-Object {  ($this.ServiceConnectionIds -eq $_.Id) }  # ($_.type -eq "azurerm" -or $_.type -eq "azure" -or $_.type -eq "git" -or $_.type -eq "github" -or $_.type -eq "externaltfs" -or $_.type -eq "externalnpmregistry" -or $_.type -eq "generic" -or $_.type -eq "externalnugetfeed" -or $_.type -eq "PRSS" -or $_.type -eq "ESRPScan") -and
                                }
                                else {
                                    $Connections = $serviceEndpointObj | Where-Object {  ($this.ServiceConnections -eq $_.name) }  # ($_.type -eq "azurerm" -or $_.type -eq "azure" -or $_.type -eq "git" -or $_.type -eq "github" -or $_.type -eq "externaltfs" -or $_.type -eq "externalnpmregistry" -or $_.type -eq "generic" -or $_.type -eq "externalnugetfeed" -or $_.type -eq "PRSS" -or $_.type -eq "ESRPScan" -or $_.type -eq "servicefabric") -and
                                }
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
                    if ($this.AgentPools.Count -gt 0 -and ($this.ResourceTypeName -in ([ResourceTypeName]::AgentPool, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User)))
                    {
                        if ($this.ProjectNames -ne "*") {
                            $this.PublishCustomMessage("Getting agent pools configurations...");
                        }
                        # Here we are fetching all the agent pools in the project and then filtering out. But in build & release we fetch them individually unless '*' is used for fetching all of them.
                        if (-not [string]::IsNullOrWhiteSpace($env:RefreshToken) -and -not [string]::IsNullOrWhiteSpace($env:ClientSecret))
                        {
                            $agentPoolsDefnURL =  "https://dev.azure.com/{0}/{1}/_apis/distributedtask/queues?api-version=6.1-preview.1" -f $($this.OrganizationContext.OrganizationName), $projectName;

                            try {
                                $agentPoolsDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($agentPoolsDefnURL);

                                if (($agentPoolsDefnsObj | Measure-Object).Count -gt 0 ) {
                                    $nObj = $this.MaxObjectsToScan

                                    $projectData["agentPools"] = ($agentPoolsDefnsObj | Measure-Object).Count

                                    if ($this.AgentPools -eq "*") {
                                        # We need to filter out legacy agent pools (Hosted, Hosted VS 2017 etc.) as they are not visible to user on the portal. As a result, they won't be able to remediate their respective controls
                                        $taskAgentQueues = $agentPoolsDefnsObj | where-object{$_.pool.isLegacy -eq $false};
                                    }
                                    else {
                                        #If service id based scan then filter with agent pool ids
                                        if ($this.isServiceIdBasedScan -eq $true) {
                                            $taskAgentQueues = $agentPoolsDefnsObj | Where-Object {($_.pool.isLegacy -eq $false) -and ($this.AgentPoolIds -contains $_.Id) }
                                        }
                                        else {
                                            $taskAgentQueues = $agentPoolsDefnsObj | Where-Object {($_.pool.isLegacy -eq $false) -and ($this.AgentPools -contains $_.name) }
                                        }
                                    }
                                    #Filtering out "Azure Pipelines" agent pool from scan as it is created by ADO by default and some of its settings are not editable (grant access to all pipelines, auto-provisioning etc.)
                                    $taskAgentQueues = $taskAgentQueues | where-object{$_.name -ne "Azure Pipelines"};

                                    foreach ($taq in $taskAgentQueues) {
                                        $resourceId = "https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.agentqueuerole/roleassignments/resources/{1}_{2}" -f $($this.OrganizationContext.OrganizationName), $($taq.projectId), $taq.id
                                        $agtpoolResourceId = "organization/$organizationId/project/$projectId/agentpool/$($taq.id)";
                                        $link = "https://dev.azure.com/{0}/{1}/_settings/agentqueues?queueId={2}&view=security" -f $($this.OrganizationContext.OrganizationName), $($taq.projectId), $taq.id
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
                        else {
                            $agentPoolsDefnURL = ("https://dev.azure.com/{0}/{1}/_settings/agentqueues?__rt=fps&__ver=2") -f $($this.OrganizationContext.OrganizationName), $projectName;
                            try {

                                $agentPoolsDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($agentPoolsDefnURL);

                                #Here the return obj for agent pool is different than prj, build, release & svc conns. Also, Azure Pipelines agent pool will always be a part of org and project. We can't delete it.
                                if (([Helpers]::CheckMember($agentPoolsDefnsObj, "fps.dataProviders.data") ) -and (($agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider") -and $agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider".taskAgentQueues)) {
                                    $nObj = $this.MaxObjectsToScan
                                    $taskAgentQueues = $null;
                                    if(($agentPoolsDefnsObj | Measure-Object).Count -gt 0) {
                                        $allAgentPools = $agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider".taskAgentQueues;
                                        $projectData["agentPools"] = ($allAgentPools | Measure-Object).Count
                                    }
                                    if ($this.AgentPools -eq "*") {
                                        # We need to filter out legacy agent pools (Hosted, Hosted VS 2017 etc.) as they are not visible to user on the portal. As a result, they won't be able to remediate their respective controls
                                        $taskAgentQueues = $agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider".taskAgentQueues | where-object{$_.pool.isLegacy -eq $false};
                                    }
                                    else {
                                        #If service id based scan then filter with agent pool ids
                                        if ($this.isServiceIdBasedScan -eq $true) {
                                            $taskAgentQueues = $agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider".taskAgentQueues | Where-Object {($_.pool.isLegacy -eq $false) -and ($this.AgentPoolIds -contains $_.Id) }
                                        }
                                        else {
                                            $taskAgentQueues = $agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider".taskAgentQueues | Where-Object {($_.pool.isLegacy -eq $false) -and ($this.AgentPools -contains $_.name) }
                                        }
                                    }
                                    #Filtering out "Azure Pipelines" agent pool from scan as it is created by ADO by default and some of its settings are not editable (grant access to all pipelines, auto-provisioning etc.)
                                    $taskAgentQueues = $taskAgentQueues | where-object{$_.name -ne "Azure Pipelines"};

                                    foreach ($taq in $taskAgentQueues) {
                                        $resourceId = "https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.agentqueuerole/roleassignments/resources/{1}_{2}" -f $($this.OrganizationContext.OrganizationName), $($taq.projectId), $taq.id
                                        $agtpoolResourceId = "organization/$organizationId/project/$projectId/agentpool/$($taq.id)";
                                        $link = "https://dev.azure.com/{0}/{1}/_settings/agentqueues?queueId={2}&view=security" -f $($this.OrganizationContext.OrganizationName), $($taq.projectId), $taq.id
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
                    }
                    #check if long running scan allowed or not.
                    if(!$this.isAllowLongRunningScanCheck())
                    {
                        return;
                    }
                    if ($this.VariableGroups.Count -gt 0 -and ($this.ResourceTypeName -in ([ResourceTypeName]::VariableGroup, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User)))
                    {
                        if ($this.ProjectNames -ne "*") {
                            $this.PublishCustomMessage("Getting variable group configurations...");
                        }
                        try
                        {
                            if ($this.VariableGroups -eq "*") {
                                $variableGroupURL = ("https://dev.azure.com/{0}/{1}/_apis/distributedtask/variablegroups?api-version=6.1-preview.2" +$topNQueryString) -f $($this.organizationName), $projectId;
                                $variableGroupObj = [WebRequestHelper]::InvokeGetWebRequest($variableGroupURL)

                                if (([Helpers]::CheckMember($variableGroupObj, "count") -and $variableGroupObj[0].count -gt 0) -or (($variableGroupObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($variableGroupObj[0], "name"))) 
                                {
                                    foreach ($group in $variableGroupObj) {
                                        $resourceId = "organization/$organizationId/project/$projectId/variablegroup/$($group.Id)";
                                        $link = ("https://dev.azure.com/{0}/{1}/_library?itemType=VariableGroups&view=VariableGroupView&variableGroupId={2}") -f $($this.organizationName), $projectName, $($group.Id);
                                        $this.AddSVTResource($group.name, $projectName, "ADO.VariableGroup", $resourceId, $group, $link);
                                    }
                                    $variableGroupObj = $null
                                }
                            }
                            else {
                                for ($i = 0; $i -lt $this.VariableGroups.Count; $i++) {
                                    # This API does not support multiple variable group names at one go.
                                    $variableGroupURL = ("https://dev.azure.com/{0}/{1}/_apis/distributedtask/variablegroups?groupName={2}&api-version=6.0-preview.2") -f $($this.organizationName), $projectId, $this.VariableGroups[$i];
                                    $variableGroupObj = [WebRequestHelper]::InvokeGetWebRequest($variableGroupURL)

                                    if (([Helpers]::CheckMember($variableGroupObj, "count") -and $variableGroupObj[0].count -gt 0) -or (($variableGroupObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($variableGroupObj[0], "name"))) 
                                    {
                                        $varGroup = $null;
                                        #If service id based scan then filter with variablegroup ids
                                        if ($this.isServiceIdBasedScan -eq $true) {
                                            $varGroup = $variableGroupObj | Where-Object { $this.VariableGroupIds -eq $_.Id }
                                        }
                                        else {
                                            $varGroup = $variableGroupObj | Where-Object { $this.VariableGroups -eq $_.name }
                                        }
                                        foreach ($group in $varGroup) {
                                            $resourceId = "organization/$organizationId/project/$projectId/variablegroup/$($group.Id)";
                                            $link = ("https://dev.azure.com/{0}/{1}/_library?itemType=VariableGroups&view=VariableGroupView&variableGroupId={2}") -f $($this.organizationName), $projectName, $($group.Id);
                                            $this.AddSVTResource($group.name, $projectName, "ADO.VariableGroup", $resourceId, $group, $link);
                                        }
                                    }
                                }
                            }
                        }
                        catch {
                            Write-Warning "Variable groups for the project [$($projectName)] could not be fetched.";
                        }
                        
                    }

                    #Creating resource in common resource resolver
                    if ($this.RepoNames.count -gt 0 -or $this.SecureFileNames.count -gt 0 -or $this.FeedNames.count -gt 0 -or $this.EnvironmentNames.count -gt 0 -or ($this.ResourceTypeName -in ([ResourceTypeName]::Repository, [ResourceTypeName]::SecureFile, [ResourceTypeName]::Feed, [ResourceTypeName]::Environment))) {
                        $commonSVTResourceResolverObj = [CommonSVTResourceResolver]::new($this.organizationName, $organizationId, $projectId);
                        $this.SVTResources += $commonSVTResourceResolverObj.LoadResourcesForScan($projectName, $this.RepoNames, $this.SecureFileNames, $this.FeedNames, $this.EnvironmentNames, $this.ResourceTypeName, $this.MaxObjectsToScan);
                    }

                    #Fetch only those resources for which data obj backup is available in local 
                    if([ControlHelper]::ControlFixBackup.Count -gt 0)
                    {
                        $this.SVTResources = @($this.SVTResources | Where-Object {[ControlHelper]::ControlFixBackup.ResourceId -contains $_.ResourceId})
                        if ($this.ResourceNames.count -gt 0) {
                            $this.SVTResources = @($this.SVTResources | Where-Object {$this.ResourceNames -contains $_.ResourceName})
                        }
                        if ($this.ExcludeResourceNames.count -gt 0) {
                            $this.SVTResources = @($this.SVTResources | Where-Object {$this.ExcludeResourceNames -notcontains $_.ResourceName})
                        }
                    }

                    # getting all the resources count
                    # and sending them to telemetry as well
                    $scanSource = [AzSKSettings]::GetInstance().GetScanSource(); # Disabling resource telemetry for SDL scan.
                    if($this.IsAIEnabled -eq $true -and $scanSource -ne 'SDL') {
                        [InventoryHelper]::GetResourceCount($this.organizationName, $projectName, $projectId, $projectData);
                    }
                    #check if long running scan allowed or not.
                    if(!$this.isAllowLongRunningScanCheck())
                    {
                        return;
                    }
                    if (--$nProj -eq 0) { break; } #nProj is set to MaxObj before loop.
                }
                    

            }
                
                #Display count of total svc and svcs to be scanned
                #sending the details to telemetry as well
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
            if(![Helpers]::CheckMember($svtResource.ResourceDetails,'ResourceLink')){
            $svtResource.ResourceDetails | Add-Member -Name 'ResourceLink' -Type NoteProperty -Value $resourceLink;
            }
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
            $this.isServiceIdBasedScan = $true;
            if ($this.ResourceTypeName -in ([ResourceTypeName]::Build, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User))
            {
                if ($rsrcList.Builds -and $rsrcList.Builds.Count -gt 0)
                {
                    $this.BuildNames += $rsrcList.Builds.buildDefinitionName
                    $this.BuildIds += $rsrcList.Builds.buildDefinitionId
                    $bFoundSvcMappedObjects = $true
                }
            }
            if ($this.ResourceTypeName -in ([ResourceTypeName]::Release, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User))
            {
                if ($rsrcList.Releases -and $rsrcList.Releases.Count -gt 0)
                {
                    $this.ReleaseNames += $rsrcList.Releases.releaseDefinitionName
                    $this.ReleaseIds += $rsrcList.Releases.releaseDefinitionId
                    $bFoundSvcMappedObjects = $true
                }
            }
            if ($this.ResourceTypeName -in ([ResourceTypeName]::ServiceConnection, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User))
            {
                if ($rsrcList.ServiceConnections -and $rsrcList.ServiceConnections.Count -gt 0)
                {
                    $this.ServiceConnections += $rsrcList.ServiceConnections.serviceConnectionName
                    $this.ServiceConnectionIds += $rsrcList.ServiceConnections.ServiceConnectionId
                    $bFoundSvcMappedObjects = $true
                }
            }
            if ($this.ResourceTypeName -in ([ResourceTypeName]::AgentPool, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User))
            {
                if ($rsrcList.AgentPools -and $rsrcList.AgentPools.Count -gt 0)
                {
                    $this.AgentPools += $rsrcList.AgentPools.agentPoolName
                    $this.AgentPoolIds += $rsrcList.AgentPools.agentPoolId
                    $bFoundSvcMappedObjects = $true
                }
            }
            if ($this.ResourceTypeName -in ([ResourceTypeName]::VariableGroup, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User))
            {
                if ($rsrcList.VariableGroups -and $rsrcList.VariableGroups.Count -gt 0)
                {
                    $this.VariableGroups += $rsrcList.VariableGroups.variableGroupName
                    $this.VariableGroupIds += $rsrcList.VariableGroups.variableGroupId
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

    # getting resources count and sending them to telemetry as well
    [void] GetResourceCount($projectName, $organizationId, $projectId, $projectData) {
        try{
            # fetching the repository count of a project
            $resourceURL = "https://dev.azure.com/$($this.organizationName)/$($projectName)/_apis/git/repositories?api-version=6.1-preview.1"
            $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL) ;
            $projectData['repositories'] = ($responseList | Measure-Object).Count

            # fetching the testPlan count of a project
            $resourceURL = "https://dev.azure.com/$($this.organizationName)/$($projectName)/_apis/testplan/plans?api-version=6.0-preview.1"
            $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL) ;
            $projectData['testPlan'] = ($responseList | Measure-Object).Count

            # fetching the taskGroups count of a project
            $resourceURL = "https://dev.azure.com/$($this.organizationName)/$($projectName)/_apis/distributedtask/taskgroups?api-version=6.0-preview.1"
            $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL) ;
            $projectData['taskGroups'] = ($responseList | Measure-Object).Count

            # fetch the builds count
            $resourceURL = ("https://dev.azure.com/{0}/{1}/_apis/build/definitions?api-version=6.0&queryOrder=lastModifiedDescending&`$top=10000") -f $($this.OrganizationContext.OrganizationName), $projectName;
            $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL);
            $projectData['build'] = ($responseList | Measure-Object).Count

            # fetch the release count
            $resourceURL = ("https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?api-version=6.0&`$top=10000") -f $($this.OrganizationContext.OrganizationName), $projectName;
            $responseList = [WebRequestHelper]::InvokeGetWebRequest($resourceURL);
            $projectData['release'] = ($responseList | Measure-Object).Count;

            # fetch the agent pools count
            if($projectData["agentPools"] -eq -1) {
                $agentPoolsDefnURL = ("https://dev.azure.com/{0}/{1}/_settings/agentqueues?__rt=fps&__ver=2") -f $($this.OrganizationContext.OrganizationName), $projectName;
                $agentPoolsDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($agentPoolsDefnURL);
                if (([Helpers]::CheckMember($agentPoolsDefnsObj, "fps.dataProviders.data") ) -and (($agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider") -and $agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider".taskAgentQueues)) {
                    $taskAgentQueues = $agentPoolsDefnsObj.fps.dataProviders.data."ms.vss-build-web.agent-queues-data-provider".taskAgentQueues;
                    $projectData["agentPools"] = ($taskAgentQueues | Measure-Object).Count
                }
            }

            # fetch the variable groups count
            if ($projectData["variableGroups"] -eq -1) {
                $variableGroupURL = ("https://dev.azure.com/{0}/{1}/_apis/distributedtask/variablegroups?api-version=6.1-preview.2") -f $($this.organizationName), $projectId;
                $variableGroupObj = [WebRequestHelper]::InvokeGetWebRequest($variableGroupURL)
                if (([Helpers]::CheckMember($variableGroupObj, "count") -and $variableGroupObj[0].count -gt 0) -or (($variableGroupObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($variableGroupObj[0], "name"))) {
                    $varGroups = $variableGroupObj
                    $projectData["variableGroups"] = ($varGroups | Measure-Object).Count
                }
            }
        }
        catch {}
        [AIOrgTelemetryHelper]::PublishEvent("Projects resources count", $projectData, @{})
    }


    #only for build and release
    [void] addResourceToSVT([string] $resourceDfnUrl, [string] $resourceType, [string] $projectName, [string] $organizationId, [string]$projectId,  [bool]  $isFolderPathGiven, [bool] $isFolderSizegt100,[string] $path,[ref] $nObj){
        [System.Uri] $validatedUri = $null;
        $orginalUri = "";
        
        $skipCount = 0
        $batchCount = 1;
        #$nObj = $this.MaxObjectsToScan
     
        while ([System.Uri]::TryCreate($resourceDfnUrl, [System.UriKind]::Absolute, [ref] $validatedUri)) {
            if ([string]::IsNullOrWhiteSpace($orginalUri)) {
                $orginalUri = $validatedUri.AbsoluteUri;   
            }
            $progressCount = 0;
            $applicableDefnsObj=@();
            $skipCount += 10000;
            $responseAndUpdatedUri = [WebRequestHelper]::InvokeWebRequestForResourcesInBatch($validatedUri, $orginalUri, $skipCount,$resourceType);
            #API response with resources
            $resourceDefnsObj = $responseAndUpdatedUri[0];
            #updated URI
            $resourceDfnUrl = $responseAndUpdatedUri[1];

            if($isFolderPathGiven -and $isFolderSizegt100){
              
                  
                   $applicableDefnsObj = $resourceDefnsObj | Where-Object {$_.path -eq "\$($path)" -or $_.path -replace '\s','' -match [System.Text.RegularExpressions.Regex]::Escape("$($path -replace '\s','')")}
              
            }
            #in case its not a folder based scan or folder cnt <100
            else {
                $applicableDefnsObj=$resourceDefnsObj;
            }
            
                                
            if ( (($applicableDefnsObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($applicableDefnsObj[0], "name")) -or ([Helpers]::CheckMember($applicableDefnsObj, "count") -and $applicableDefnsObj[0].count -gt 0)) {
                if($resourceType -eq "build"){
                    $tempLink=($applicableDefnsObj[0].url -split('Definitions/'))[0].replace('_apis/build/', '_build?definitionId=');
                }
                else {
                    $tempLink = "https://dev.azure.com/{0}/{1}/_release?_a=releases&view=mine&definitionId=" -f $this.OrganizationContext.OrganizationName, $projectName;
                                   
                }
                foreach ($resourceDef in $applicableDefnsObj) {
                    #$link = $resourceDef.url.split('?')[0].replace('_apis/build/Definitions/', '_build?definitionId=');
                    $link=$tempLink+$resourceDef.id
                    $resourceId = "organization/$organizationId/project/$projectId/$($resourceType)/$($resourceDef.id)";
                    if($resourceType -eq "build"){
                        $this.AddSVTResource($resourceDef.name, $resourceDef.project.name, "ADO.Build", $resourceId, $resourceDef, $link);

                    }
                    else {
                        $this.AddSVTResource($resourceDef.name, $projectName, "ADO.Release", $resourceId, $null, $link);

                    }
                                        
                    Write-Progress -Activity "Fetching $($resourceType)s in batches. This may take time. Fetched $($progressCount) of $(($applicableDefnsObj | Measure-Object).Count) $($resourceType)s of batch $($batchCount) " -Status "Progress: " -PercentComplete ($progressCount / ($applicableDefnsObj | Measure-Object).Count * 100)
                    $progressCount = $progressCount + 1;
                    if (--$nObj.Value -eq 0) { break; }
                }
                $batchCount = $batchCount + 1;                             

            }
            else {
                break;
            }
            if ($nObj.Value -eq 0) { break; }
        }
        Write-Progress -Activity "All $($resourceType)s fetched" -Status "Ready" -Completed
        $resourceDefnsObj = $null;
        $applicableDefnsObj=$null;
        Remove-Variable resourceDefnsObj;
        Remove-Variable applicableDefnsObj;
    }

    [void] createServiceConnectionSVTResource($projectName,$organizationId,$projectId,$projectData){
        $serviceEndpointURL = ("https://dev.azure.com/{0}/{1}/_apis/serviceendpoint/endpoints?includeDetails=True&api-version=6.0-preview.4") -f $($this.organizationName), $($projectName);
                        $serviceEndpointObj = [WebRequestHelper]::InvokeGetWebRequest($serviceEndpointURL)
                        $TotalSvc += ($serviceEndpointObj | Measure-Object).Count
                        # service connection count here
                        $projectData["serviceConnections"] = ($serviceEndpointObj | Measure-Object).Count;

                        if (([Helpers]::CheckMember($serviceEndpointObj, "count") -and $serviceEndpointObj[0].count -gt 0) -or (($serviceEndpointObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($serviceEndpointObj[0], "name"))) {
                            # Currently get only Azure Connections as all controls are applicable for same

                            $Connections = $null;
                            if ($this.ServiceConnections -eq "*") {
                                $Connections = $serviceEndpointObj #| Where-Object { ($_.type -eq "azurerm" -or $_.type -eq "azure" -or $_.type -eq "git" -or $_.type -eq "github" -or $_.type -eq "externaltfs" -or $_.type -eq "externalnpmregistry" -or $_.type -eq "generic" -or $_.type -eq "externalnugetfeed" -or $_.type -eq "PRSS" -or $_.type -eq "ESRPScan") }
                            }
                            else {
                                #If service id based scan then filter with serviceconnection ids
                                if ($this.isServiceIdBasedScan -eq $true) {
                                    $Connections = $serviceEndpointObj | Where-Object {  ($this.ServiceConnectionIds -eq $_.Id) }  # ($_.type -eq "azurerm" -or $_.type -eq "azure" -or $_.type -eq "git" -or $_.type -eq "github" -or $_.type -eq "externaltfs" -or $_.type -eq "externalnpmregistry" -or $_.type -eq "generic" -or $_.type -eq "externalnugetfeed" -or $_.type -eq "PRSS" -or $_.type -eq "ESRPScan") -and
                                }
                                else {
                                    $Connections = $serviceEndpointObj | Where-Object {  ($this.ServiceConnections -eq $_.name) }  # ($_.type -eq "azurerm" -or $_.type -eq "azure" -or $_.type -eq "git" -or $_.type -eq "github" -or $_.type -eq "externaltfs" -or $_.type -eq "externalnpmregistry" -or $_.type -eq "generic" -or $_.type -eq "externalnugetfeed" -or $_.type -eq "PRSS" -or $_.type -eq "ESRPScan" -or $_.type -eq "servicefabric") -and
                                }
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

    [void] createBuildSVTResource($projectName,$organizationId,$projectId){
        if(-not [string]::IsNullOrEmpty($this.BuildsFolderPath)){
            # Validate folder path is valid
            $path = $this.BuildsFolderPath;
            $this.BuildsFolderPath = $this.BuildsFolderPath.Replace(' ','%20').Replace('\','%5C')
            $buildFoldersURL = "https://dev.azure.com/{0}/{1}/_apis/build/folders/{2}?api-version=6.1-preview.2"  -f $($this.OrganizationContext.OrganizationName), $projectName, $this.BuildsFolderPath
            $buildFoldersObj = [WebRequestHelper]::InvokeGetWebRequest($buildFoldersURL)
            if($null -eq $buildFoldersObj -or (![Helpers]::CheckMember($buildFoldersObj[0],"Path"))){
                $this.PublishCustomMessage("Folder path not found. Please validate the -BuildsFolderPath provided in the command. `n", [MessageType]::Warning);
            }
            else {
                #Iterate on each folder to get applicale build definition if folders count is le 100
                if ([string]::IsNullOrEmpty($topNQueryString)) {
                    $topNQueryString = '&$top=10000'
                }
                $nObj=$this.MaxObjectsToScan;
                if($buildFoldersObj.Count -le 100)
                {
                    $folderCount=1
                    
                    foreach($path in $buildFoldersObj.Path)
                    {
                        
                        $formattedPath = $path.Replace(' ','%20').Replace('\','%5C')
                        $buildDefByFolderURL = ('https://dev.azure.com/{0}/{1}/_apis/build/definitions?path={2}&queryOrder=lastModifiedDescending'+$topNQueryString) -f $($this.OrganizationContext.OrganizationName), $projectName, $formattedPath
                        Write-Progress -Activity "Searching in folder $($folderCount) of $($buildFoldersObj.Count) : $($path) " -Status "Progress: " -PercentComplete ($folderCount/ $buildFoldersObj.Count * 100)
                        $this.addResourceToSVT($buildDefByFolderURL,"build",$projectName,$organizationId,$projectId,$true,$false,$null,[ref]$nObj)
                        if($nObj -eq 0) {break;}
                        $folderCount++;
                    }
                    Write-Progress -Activity "All builds fetched" -Status "Ready" -Completed
                }
                else {                                 
                    $buildDefURL = ("https://dev.azure.com/{0}/{1}/_apis/build/definitions?queryOrder=lastModifiedDescending&api-version=6.0" + $topNQueryString) -f $($this.OrganizationContext.OrganizationName), $projectName;
                    $this.addResourceToSVT($buildDefURL,"build",$projectName, $organizationId, $projectId, $true, $true, $path,[ref]$nObj)                                  
                }

            }
        }
        elseif ($this.BuildNames -eq "*") {
            if ([string]::IsNullOrEmpty($topNQueryString)) {
                $topNQueryString = '&$top=10000'
                $buildDefnURL = ("https://dev.azure.com/{0}/{1}/_apis/build/definitions?queryOrder=lastModifiedDescending&api-version=6.0" +$topNQueryString) -f $($this.OrganizationContext.OrganizationName), $projectName;
            }
            else {
                $buildDefnURL = ("https://dev.azure.com/{0}/{1}/_apis/build/definitions?api-version=6.0" +$topNQueryString) -f $($this.OrganizationContext.OrganizationName), $projectName;
            }
            $nObj=$this.MaxObjectsToScan
            $this.addResourceToSVT($buildDefnURL,"build",$projectName,$organizationId,$projectId,$false,$false,$null,[ref]$nObj);
            }
        
        else {

            $buildDefnURL = "";
            #If service id based scan then will break the loop after one run because, sending all build ids to api as comma separated in one go.
            for ($i = 0; $i -lt $this.BuildNames.Count; $i++) {
                #If service id based scan then send all build ids to api as comma separated in one go.
                if ($this.isServiceIdBasedScan -eq $true) {
                    $buildDefnURL = "https://{0}.visualstudio.com/{1}/_apis/build/definitions?definitionIds={2}&api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $projectName, ($this.BuildIds -join ",");
                }
                else { #If normal scan (not service id based) then send each build name in api one by one.
                    $buildDefnURL = "https://{0}.visualstudio.com/{1}/_apis/build/definitions?name={2}&api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $projectName, $this.BuildNames[$i];
                }
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
                #If service id based scan then no need to run loop as all the build ids has been sent to api as comma separated list in one go. so break the loop.
                if ($this.isServiceIdBasedScan -eq $true) {
                    break;
                }
            }
        }
    }

    [string] FindResourceTypeFromPartialScan($nonScannedResourceId){
        $type="";
        switch -wildcard ($nonScannedResourceId) {
            "*/build/*" {$type="ADO.Build";Break;}
            "*/release/*" {$type="ADO.Release"; Break}
            "*/agentpool/*" {$type="ADO.AgentPool"; Break}
            "*/serviceconnection/*" {$type="ADO.ServiceConnection"; Break}
            "*/user" {$type="ADO.User"; Break}
            "*/project/*" {$type="ADO.Project"}
            
            Default {$type="ADO.Organization"}
        }
        return $type;
    }

    [string] CreateResourceLinkFromPartialScan($nonScannedResourceId,$resourceType,$orgName,$projName,$projId){
        $resourceLink="https://dev.azure.com/{0}/" -f $($orgName);
        switch ($resourceType) {
           
            "ADO.Release" {
                $definitionId=($nonScannedResourceId -split('/release/'))[1];
                $resourceLink+=$projName+"/_release?_a=releases&view=mine&definitionId="+$definitionId;
                Break
            }
            "ADO.AgentPool" {
                $definitionId=($nonScannedResourceId -split('/agentpool/'))[1];
                $resourceLink+=$projId+"/_settings/agentqueues?queueId="+$definitionId+"&view=security";
                Break
            }
            "ADO.ServiceConnection" {
                $definitionId=($nonScannedResourceId -split('/serviceconnection/'))[1];
                $resourceLink+=$projId+"/_settings/adminservices?resourceId="+$definitionId;
                Break
            
            }
            "ADO.Project" {
                $resourceLink+=$projId+"/_settings/";
                Break
            }
            "ADO.Organization" {
                $resourceLink+="_settings";
                Break
            }
            "ADO.User" {
                $resourceLink+="_settings/users";
            }
            Default {}
        }
        return $resourceLink
    }

    
    [void] FetchControlFixBackupFile($orgName, $projName, $internalId)
	{
        [ControlHelper]::ControlFixBackup = @()
        $BackupControlStateRootFolder = (Join-Path $([Constants]::AzSKAppFolderPath) "TempState" | Join-Path -ChildPath "BackupControlState");
        if($internalId -match "Organization")
        {
            $BackupControlStateControlJson = (Join-Path $BackupControlStateRootFolder $orgName)
        }
        else
        {
            $BackupControlStateControlJson = (Join-Path (Join-Path $BackupControlStateRootFolder $orgName) $projName)
        }
        $fileName = $internalId + ".json"
        if(Test-Path (Join-Path $BackupControlStateControlJson $fileName))
        {
            [ControlHelper]::ControlFixBackup += Get-Content (Join-Path $BackupControlStateControlJson $fileName) -Raw | ConvertFrom-Json
        }
        else {
            $this.PublishCustomMessage("`nBackup of control data object not found. Please run GADS with -PrepareforControlFix param to generate the backup.",[MessageType]::Warning);
        }
	}


}
