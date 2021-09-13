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
    [System.Collections.Generic.List[SVTResource]] $ExcludedResources = @();
    [int] $MaxObjectsToScan;
    [System.Collections.Generic.List[SVTResource]] $SVTResources = @();
    [int] $SVTResourcesFoundCount = 0;

    [bool] $IsAIEnabled = $false;
    [bool] $IsAutomatedFixUndoCmd = $false;

    [string] $ResourcePath;
    [string] $BuildsFolderPath;
    [string] $ReleasesFolderPath;
    [bool] $BatchScan;
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

    [bool] $UseIncrementalScan = $false
    [DateTime] $IncrementalDate = 0

    [bool] $UsePartialCommits=$false;
    [bool] $DoNotRefetchResources=$false;
    [bool] $isPartialScanActive=$false;
    [bool] $isDnrrAllProject = $false;
    [bool] $shouldFetchResource = $true;
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



    SVTResourceResolver([string]$organizationName, $ProjectNames, $BuildNames, $ReleaseNames, $AgentPools, $ServiceConnectionNames, $VariableGroupNames, $MaxObj, $ScanAllResources, $PATToken, $ResourceTypeName, $AllowLongRunningScan, $ServiceIds, $IncludeAdminControls, $skipOrgUserControls, $RepoNames, $SecureFileNames, $FeedNames, $EnvironmentNames,$BuildsFolderPath,$ReleasesFolderPath,$UsePartialCommits,$DoNotRefetchResources,$BatchScan, $UseIncrementalScan, $IncrementalDate): Base($organizationName, $PATToken) {


        $this.MaxObjectsToScan = $MaxObj #default = 0 => scan all if "*" specified...
        $this.SetallTheParamValues($organizationName, $ProjectNames, $BuildNames, $ReleaseNames, $AgentPools, $ServiceConnectionNames, $VariableGroupNames, $ScanAllResources, $PATToken, $ResourceTypeName, $AllowLongRunningScan, $ServiceIds, $IncludeAdminControls, $BuildsFolderPath,$ReleasesFolderPath,$UsePartialCommits,$DoNotRefetchResources,$BatchScan, $UseIncrementalScan, $IncrementalDate);
        $this.skipOrgUserControls = $skipOrgUserControls

        $this.RepoNames += $this.ConvertToStringArray($RepoNames);
        $this.SecureFileNames += $this.ConvertToStringArray($SecureFileNames);
        $this.FeedNames += $this.ConvertToStringArray($FeedNames);

        [PartialScanManager]::ClearInstance();
    

        $this.EnvironmentNames += $this.ConvertToStringArray($EnvironmentNames);
    }

    #Constructor for Set-AzSKADOSecurityStatus
    SVTResourceResolver([string]$organizationName, $ProjectNames, $ResourceNames, $ExcludeResourceNames, $PATToken, $ResourceTypeName, $UndoFix, $ControlId): Base($organizationName, $PATToken) {
        if($UndoFix) {
            if (!$this.ControlSettings) {
                $this.ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
            }
            if($this.ControlSettings.AutomatedFix.RevertDeletedResourcesControlList -contains $ControlId)
            {
                #When controls undo fix is called, resources need to be fetched from deleted list (only for controls ids in RevertDeletedResourcesControlList)
                $this.IsAutomatedFixUndoCmd = $true
            }
        }
        $this.organizationName = $organizationName
        $this.ProjectNames = $ProjectNames
        $this.ResourceTypeName = $ResourceTypeName

        if (-not [string]::IsNullOrEmpty($ResourceNames)) {
            $this.ResourceNames += $this.ConvertToStringArray($ResourceNames);
        }
        if (-not [string]::IsNullOrEmpty($ExcludeResourceNames)) {
                $this.ExcludeResourceNames += $this.ConvertToStringArray($ExcludeResourceNames);
        }
        $this.SetallTheParamValues($ResourceTypeName)
    }


    [void] SetallTheParamValues([string]$organizationName, $ProjectNames, $BuildNames, $ReleaseNames, $AgentPools, $ServiceConnectionNames, $VariableGroupNames, $ScanAllResources, $PATToken, $ResourceTypeName, $AllowLongRunningScan, $ServiceIds, $IncludeAdminControls,$BuildsFolderPath,$ReleasesFolderPath,$UsePartialCommits,$DoNotRefetchResources,$BatchScan, $UseIncrementalScan, $IncrementalDate) {

        $this.organizationName = $organizationName
        $this.ResourceTypeName = $ResourceTypeName
        $this.allowLongRunningScan = $AllowLongRunningScan
        $this.includeAdminControls = $IncludeAdminControls
        $this.BuildsFolderPath = $BuildsFolderPath.Trim()
        $this.UsePartialCommits=$UsePartialCommits
        $this.DoNotRefetchResources=$DoNotRefetchResources
        $this.ReleasesFolderPath = $ReleasesFolderPath.Trim()
        $this.UseIncrementalScan = $UseIncrementalScan
        
        if (-not [string]::IsNullOrWhiteSpace($IncrementalDate)) 
        {
            $this.IncrementalDate = $IncrementalDate    
        }
        else 
        {
            $this.IncrementalDate = [datetime] 0    
        }
        $this.BatchScan = $BatchScan

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
        elseif ($ResourceTypeName -eq [ResourceTypeName]::ServiceConnection -or $ResourceTypeName -eq [ResourceTypeName]::SvcConn_AgentPool_VarGroup_CommonSVTResources) {
            $this.ServiceConnections = "*"
        }

        if (-not [string]::IsNullOrEmpty($AgentPools)) {
            $this.AgentPools += $this.ConvertToStringArray($AgentPools);
            if ($this.AgentPools.Count -eq 0) {
                throw [SuppressedException] "The parameter 'AgentPools' does not contain any string."
            }
        }
        elseif ($ResourceTypeName -eq [ResourceTypeName]::AgentPool -or $ResourceTypeName -eq [ResourceTypeName]::SvcConn_AgentPool_VarGroup_CommonSVTResources) {
            $this.AgentPools = "*"
        }

        if (-not [string]::IsNullOrEmpty($VariableGroupNames)) {
            $this.VariableGroups += $this.ConvertToStringArray($VariableGroupNames);

            if ($this.VariableGroups.Count -eq 0) {
                throw [SuppressedException] "The parameter 'VariableGroupNames' does not contain any string."
            }
        }
        elseif ($ResourceTypeName -eq [ResourceTypeName]::VariableGroup -or $ResourceTypeName -eq [ResourceTypeName]::SvcConn_AgentPool_VarGroup_CommonSVTResources) {
            $this.VariableGroups = "*"
        }

        if (-not [string]::IsNullOrEmpty($ServiceIds)) {
            $this.serviceIds += $this.ConvertToStringArray($ServiceIds);
            if ($this.serviceIds.Count -eq 0) {
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
        if($this.UseIncrementalScan -eq $true)
        {
            $this.PublishCustomMessage("Incremental Scan is currently supported only for Builds and Releases. `n ", [MessageType]::Warning);        
            
        }
    }


    # Method called for Set-AzSKADOSecurityStatus, invoked from constructor 

    [void] SetallTheParamValues($ResourceTypeName) {
    
        if ($ResourceTypeName -eq [ResourceTypeName]::Build ) {
            if([string]::IsNullOrWhitespace($this.ResourceNames))
            {
                $this.BuildNames = "*"
            }
            else{
                $this.BuildNames = $this.ResourceNames
            }
        }
        elseif ($ResourceTypeName -eq [ResourceTypeName]::Release) {
            if([string]::IsNullOrWhitespace($this.ResourceNames))
            {
                $this.ReleaseNames = "*"
            }
            else{
                $this.ReleaseNames = $this.ResourceNames
            }
        }
        elseif ($ResourceTypeName -eq [ResourceTypeName]::ServiceConnection) {
            if([string]::IsNullOrWhitespace($this.ResourceNames))
            {
                $this.ServiceConnections = "*"
            }
            else{
                $this.ServiceConnections = $this.ResourceNames
            }
        }
        elseif ($ResourceTypeName -eq [ResourceTypeName]::AgentPool) {
            if([string]::IsNullOrWhitespace($this.ResourceNames))
            {
                $this.AgentPools = "*"
            }
            else{
                $this.AgentPools = $this.ResourceNames
            }
        }
        elseif ($ResourceTypeName -eq [ResourceTypeName]::VariableGroup) {
            if([string]::IsNullOrWhitespace($this.ResourceNames))
            {
                $this.VariableGroups = "*"
            }
            else{
                $this.VariableGroups = $this.ResourceNames
            }
        }
        elseif ($ResourceTypeName -eq [ResourceTypeName]::Repository) {
            if([string]::IsNullOrWhitespace($this.ResourceNames))
            {
                $this.RepoNames = "*"
            }
            else{
                $this.RepoNames = $this.ResourceNames
            }
        }
        elseif ($ResourceTypeName -eq [ResourceTypeName]::SecureFile) {
            if([string]::IsNullOrWhitespace($this.ResourceNames))
            {
                $this.SecureFileNames = "*"
            }
            else{
                $this.SecureFileNames = $this.ResourceNames
            }
        }
        elseif ($ResourceTypeName -eq [ResourceTypeName]::Feed) {
            if([string]::IsNullOrWhitespace($this.ResourceNames))
            {
                $this.FeedNames = "*"
            }
            else{
                $this.FeedNames = $this.ResourceNames
            }
        }
        elseif ($ResourceTypeName -eq [ResourceTypeName]::Environment) {
            if([string]::IsNullOrWhitespace($this.ResourceNames))
            {
                $this.EnvironmentNames = "*"
            }
            else{
                $this.EnvironmentNames = $this.ResourceNames
            }
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
            if ($this.ResourceTypeName -in ([ResourceTypeName]::User, [ResourceTypeName]::All, [ResourceTypeName]::Org_Project_User, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User_CommonSVTResources)) {

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

                    if($this.UsePartialCommits -and $this.DoNotRefetchResources -and $this.isDnrrAllProject -eq $false){
                        
                        [PartialScanManager] $partialScanMngr = [PartialScanManager]::GetInstance();
                        if(($partialScanMngr.IsPartialScanInProgress($this.OrganizationContext.OrganizationName, $false) -eq [ActiveStatus]::Yes)  ){
                            Write-Host "Resuming scan from last commit. Fetching unscanned resources..." -ForegroundColor Yellow
                            $this.nonScannedResources = $partialScanMngr.GetNonScannedResources();
                            $this.IsPartialScanActive=$true;
                        }
                        else {
                            $this.IsPartialScanActive=$false;
                        }
                    }

                    if($this.IsPartialScanActive -and $this.nonScannedResources.Count -ne 0 -and $this.isDnrrAllProject -eq $false){
                        #The tracker is loaded in one go, so no need to load it again when we are looping through multiple projects
                        if($null -ne $projects -and ($projects | Measure-Object).Count -gt 1){
                            $this.isDnrrAllProject = $true;
                        }
                        $progressCount=1
                        foreach($nonScannedResource in $this.nonScannedResources){
                            $nonScannedResourceType=$this.FindResourceTypeFromPartialScan($nonScannedResource.Id)
                            $nonScannedresourceLink=$this.CreateResourceLinkFromPartialScan($nonScannedResource.Id,$nonScannedResourceType,$this.organizationName,$nonScannedResource.ProjectName,$projectId)
                            if($nonScannedResourceType -eq "ADO.Release" -or $nonScannedResourceType -eq "ADO.AgentPool"){
                                $this.AddSVTResource($nonScannedResource.Name,$nonScannedResource.ProjectName,$nonScannedResourceType, $nonScannedResource.Id,$null , $nonScannedresourceLink)
                            }

                            if ($progressCount%100 -eq 0) {
                                Write-Progress -Activity "Fetching $($progressCount) of $($this.nonScannedResources.Count) unscanned resources " -Status "Progress: " -PercentComplete ($progressCount / $this.nonScannedResources.Count * 100)
                            }
                            $progressCount++;
                            


                        }
                        Write-Progress -Activity "All resources fetched" -Status "Ready" -Completed
                        #to be used with release and agent pool to check if we need to call apis for fetching resources or it has been already done via the tracker
                        $this.shouldFetchResource = $false

                    }

                    

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
                        $inputBuildNames = @()
                        $inputReleaseNames = @()
                        $inputSvcNames = @()
                        $inputAgentPoolNames = @()
                        $inputVargrpNames = @()
                        $inputRepoNames = @()
                        $inputFeedNames = @()
                        $inputEnvNames = @()
                        $inputSecFileNames = @()

                        $inputBuildNames = $this.BuildNames;
                        $this.BuildNames =@();
   
                        $inputReleaseNames = $this.ReleaseNames;
                        $this.ReleaseNames =@();
                        
                        $inputSvcNames = $this.ServiceConnections;
                        $this.ServiceConnections =@();
                        
                        $inputAgentPoolNames = $this.AgentPools;
                        $this.AgentPools =@();
                        
                        $inputVargrpNames = $this.VariableGroups;
                        $this.VariableGroups =@();
                        
                        $inputRepoNames = $this.RepoNames;
                        $this.RepoNames  =@();
                        
                        $inputFeedNames = $this.FeedNames;
                        $this.FeedNames  =@();
                        
                        $inputEnvNames = $this.EnvironmentNames ;
                        $this.EnvironmentNames =@();
                            
                        $inputSecFileNames = $this.SecureFileNames ;
                        $this.SecureFileNames =@();             
                        
                        $this.PublishCustomMessage("Getting service associated resources...");                        
                        foreach ($thisServiceId in $this.serviceIds)
                        {                                                       
                            $this.FetchServiceAssociatedResources($thisServiceId, $projectName,$inputBuildNames,$inputReleaseNames,$inputSvcNames,$inputAgentPoolNames,$inputVargrpNames,$inputRepoNames,$inputFeedNames,$inputEnvNames,$inputSecFileNames);
                        }                      
                    }

                    if ($this.BuildNames.Count -gt 0 -and ($this.ResourceTypeName -in ([ResourceTypeName]::Build, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User_CommonSVTResources))) {
                        if ($this.ProjectNames -ne "*") {
                            $this.PublishCustomMessage("Getting build configurations...");
                        }

                        #When Undo fix for build/release inactive controls is called, resources need to be fetched from deleted list
                        if ($this.IsAutomatedFixUndoCmd)
                        {
                            $url = 'https://dev.azure.com/{0}/{1}/_build/deleted?__rt=fps&__ver=2 ' -f $($this.OrganizationContext.OrganizationName), $thisProj.name
                            $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($url));
                            $buildDefnsObj = @()
                            if([Helpers]::CheckMember($responseObj,"fps.dataProviders.data") -and $responseObj.fps.dataProviders.data.'ms.vss-build-web.deleted-pipelines-data-provider' -and [Helpers]::CheckMember($responseObj.fps.dataProviders.data.'ms.vss-build-web.deleted-pipelines-data-provider',"pipelines") -and  $responseObj.fps.dataProviders.data.'ms.vss-build-web.deleted-pipelines-data-provider'.pipelines)
                            {
                                $buildDefnsObj = $responseObj.fps.dataProviders.data."ms.vss-build-web.deleted-pipelines-data-provider".pipelines;
                            }
                            if ($buildDefnsObj.count -gt 0) {
                                foreach ($bldDef in $buildDefnsObj) {
                                    $buildResourceId = "organization/$organizationId/project/$projectId/build/$($bldDef.id)";
                                    $this.AddSVTResource($bldDef.name, $thisProj.name, "ADO.Build", $buildResourceId, $bldDef, $null);
                                }
                                $buildDefnsObj = $null;
                                Remove-Variable buildDefnsObj;
                            }
                        }
                        else
                        {
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

                                if($this.BatchScan){
                                    $this.addBuildsToSvtInBatchScan($projectName,$projectId,$path)
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
                        }
                        elseif ($this.BuildNames -eq "*") {
                            if($this.BatchScan){
                                $this.addBuildsToSvtInBatchScan($projectName,$projectId,$null);
                            }
                            else {
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
                           

                            }
                        
                        else {
                            $nObj=$this.MaxObjectsToScan;
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
                                        if (--$nObj -eq 0) { break; }
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

                        #Initialysing null to SecurityNamespaceId variable for new scan, it is static variable, setting once only in svc class and same value is applicable for all the svc con withing org
                        [Build]::SecurityNamespaceId = $null;

                    }
                    #check if long running scan allowed or not.
                    if(!$this.isAllowLongRunningScanCheck())
                    {
                        return;
                    }
                    if ($this.ReleaseNames.Count -gt 0 -and ($this.ResourceTypeName -in ([ResourceTypeName]::Release, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User_CommonSVTResources)) -and $this.shouldFetchResource -eq $true)

                    {
                        if ($this.ProjectNames -ne "*") {
                            $this.PublishCustomMessage("Getting release configurations...");
                        }
                        #When Undo fix for build/release inactive controls is called, resources need to be fetched from deleted list
                        if ($this.IsAutomatedFixUndoCmd)
                        {
                            $accessToken = [RemoteApiHelper]::GetAccessToken()
                            $apiURL = "https://vsrm.dev.azure.com/{0}/_apis/Contribution/HierarchyQuery/project/{1}" -f $($this.organizationName), $projectId
                            $inputbody = "{'contributionIds':['ms.vss-releaseManagement-web.deleted-definitions-data-provider'],'dataProviderContext':{'properties':{'sourcePage':{'url':'https://dev.azure.com/$($this.organizationName)/$projectName/_release?view=deleted','routeId':'ms.vss-releaseManagement-web.hub-explorer-3-default-route','routeValues':{'project':'$projectName','viewname':'hub-explorer-3-view','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json
                            $headers = @{
                                "Authorization"= ("Bearer " + $accessToken); 
                                "Accept"="application/json;api-version=5.0-preview.1;excludeUrls=true;enumsAsNumbers=true;msDateFormat=true;noArrayWrap=true";
                                "content-type"="application/json";
                            };

                            $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL,$headers, $inputbody);
                            $releaseDefnsObj = @()
                            if([Helpers]::CheckMember($responseObj,"dataProviders") -and $responseObj.dataProviders.'ms.vss-releaseManagement-web.deleted-definitions-data-provider' -and [Helpers]::CheckMember($responseObj.dataProviders.'ms.vss-releaseManagement-web.deleted-definitions-data-provider',"releaseDefinitions") -and  $responseObj.dataProviders.'ms.vss-releaseManagement-web.deleted-definitions-data-provider'.releaseDefinitions)
                            {
                                $releaseDefnsObj = $responseObj.dataProviders."ms.vss-releaseManagement-web.deleted-definitions-data-provider".releaseDefinitions;
                            }

                            if ($releaseDefnsObj.count -gt 0) {
                                foreach ($relDef in $releaseDefnsObj) {
                                    $releaseResourceId = "organization/$organizationId/project/$projectId/release/$($relDef.id)";
                                    $this.AddSVTResource($relDef.name, $projectName, "ADO.Release", $releaseResourceId, $relDef, $null);
                                }
                                $releaseDefnsObj = $null;
                                Remove-Variable releaseDefnsObj;
                            }
                        }
                        else
                        {

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
                                if($this.BatchScan){
                                    $this.addReleasesToSvtInBatchScan($projectName,$projectId,$path)
                                }
                                else {
                               #API doesnt provide all folders in a path, fallback to fetch all resources and then filter
                                $nObj=$this.MaxObjectsToScan                                                               
                                $releaseDefURL = ("https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?api-version=6.0" ) -f $($this.OrganizationContext.OrganizationName), $thisProj.name;
                                $this.addResourceToSVT($releaseDefURL,"release",$projectName, $organizationId, $projectId, $true, $true, $path,[ref]$nObj)   
                                }                               
                                

                            }
                           
                            
                            
                            
                        }


                        elseif ($this.ReleaseNames -eq "*")
                        {
                            if($this.BatchScan){
                                $this.addReleasesToSvtInBatchScan($projectName,$projectId,$null);
                            }
                            else {
                            $nObj=$this.MaxObjectsToScan
                            $releaseDefnURL = ("https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?api-version=6.0") -f $($this.OrganizationContext.OrganizationName), $projectName;
                            $this.addResourceToSVT($releaseDefnURL,"release",$projectName,$organizationId,$projectId,$false,$false,$null,[ref]$nObj);
                            }
                        }
                        else {
                            try {
                                $nObj=$this.MaxObjectsToScan
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
                                        if (--$nObj -eq 0) { break; }
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
                    if ($this.ServiceConnections.Count -gt 0 -and ($this.ResourceTypeName -in ([ResourceTypeName]::ServiceConnection, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User_CommonSVTResources, [ResourceTypeName]::SvcConn_AgentPool_VarGroup_CommonSVTResources)))
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

                    if ($this.AgentPools.Count -gt 0 -and ($this.ResourceTypeName -in ([ResourceTypeName]::AgentPool, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User_CommonSVTResources, [ResourceTypeName]::SvcConn_AgentPool_VarGroup_CommonSVTResources)) -and $this.shouldFetchResource -eq $true)


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
                    if ($this.VariableGroups.Count -gt 0 -and ($this.ResourceTypeName -in ([ResourceTypeName]::VariableGroup, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User_CommonSVTResources, [ResourceTypeName]::SvcConn_AgentPool_VarGroup_CommonSVTResources)))
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
                    if ($this.RepoNames.count -gt 0 -or $this.SecureFileNames.count -gt 0 -or $this.FeedNames.count -gt 0 -or $this.EnvironmentNames.count -gt 0 -or ($this.ResourceTypeName -in ([ResourceTypeName]::Repository, [ResourceTypeName]::SecureFile, [ResourceTypeName]::Feed, [ResourceTypeName]::Environment,[ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User_CommonSVTResources, [ResourceTypeName]::SvcConn_AgentPool_VarGroup_CommonSVTResources))) {
                        $commonSVTResourceResolverObj = [CommonSVTResourceResolver]::new($this.organizationName, $organizationId, $projectId);
                        $this.SVTResources +=  [SVTResource[]] $commonSVTResourceResolverObj.LoadResourcesForScan($projectName, $this.RepoNames, $this.SecureFileNames, $this.FeedNames, $this.EnvironmentNames, $this.ResourceTypeName, $this.MaxObjectsToScan, $this.isServiceIdBasedScan);
                    }

                    #Fetch only those resources for which data obj backup is available in local 
                    if([ControlHelper]::ControlFixBackup.Count -gt 0)
                    {
                        $this.SVTResources = $this.SVTResources | Where-Object {[ControlHelper]::ControlFixBackup.ResourceId -contains $_.ResourceId}
                        if ($this.ResourceNames.count -gt 0) {
                            $this.SVTResources = $this.SVTResources | Where-Object {$this.ResourceNames -contains $_.ResourceName}
                        }
                        if ($this.ExcludeResourceNames.count -gt 0) {
                            $this.SVTResources = $this.SVTResources | Where-Object {$this.ExcludeResourceNames -notcontains $_.ResourceName}
                        }

                        #Filter backup of only applicable resources
                        [ControlHelper]::ControlFixBackup = @([ControlHelper]::ControlFixBackup | Where-Object {$this.SVTResources.ResourceId -contains $_.ResourceId})
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

        $this.SVTResources.Add($svtResource)
    }

    [void] FetchServiceAssociatedResources($svcId, $projectName,$inputBuildNames,$inputReleaseNames,$inputSvcNames,$inputAgentPoolNames,$inputVargrpNames,$inputRepoNames,$inputFeedNames,$inputEnvNames,$inputSecFileNames)
    {        
        $metaInfo = [MetaInfoProvider]::Instance;

        $rsrcList = $metaInfo.FetchServiceAssociatedResources($svcId, $projectName, $this.ResourceTypeName);
        $bFoundSvcMappedObjects = $false
        if ($null -ne $rsrcList)
        {
            $this.isServiceIdBasedScan = $true;
            if ($this.ResourceTypeName -in ([ResourceTypeName]::Build, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User_CommonSVTResources))
            {
                if ($rsrcList.Builds -and $rsrcList.Builds.Count -gt 0)
                {
                    if ($inputBuildNames -ne "*") {
                        $rsrcList.Builds = @($rsrcList.Builds | Where { $_.buildDefinitionName -in $inputBuildNames });
                    }
                    if ($rsrcList.Builds -and $rsrcList.Builds.Count -gt 0) {
                        $this.BuildNames += $rsrcList.Builds.buildDefinitionName
                        $this.BuildIds += $rsrcList.Builds.buildDefinitionId
                        $bFoundSvcMappedObjects = $true
                    }                   
                }
            }
            if ($this.ResourceTypeName -in ([ResourceTypeName]::Release, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User_CommonSVTResources))
            {
                if ($rsrcList.Releases -and $rsrcList.Releases.Count -gt 0)
                {
                    if ($inputReleaseNames -ne "*") {
                        $rsrcList.Releases = @($rsrcList.Releases | Where { $_.releaseDefinitionName -in $inputReleaseNames });
                    }
                    if ($rsrcList.Releases -and $rsrcList.Releases.Count -gt 0) {
                        $this.ReleaseNames += $rsrcList.Releases.releaseDefinitionName
                        $this.ReleaseIds += $rsrcList.Releases.releaseDefinitionId
                        $bFoundSvcMappedObjects = $true
                    }                 
                }
            }
            if ($this.ResourceTypeName -in ([ResourceTypeName]::ServiceConnection, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User_CommonSVTResources,[ResourceTypeName]::SvcConn_AgentPool_VarGroup_User_CommonSVTResources))
            {
                if ($rsrcList.ServiceConnections -and $rsrcList.ServiceConnections.Count -gt 0)
                {
                    if ($inputSvcNames-ne "*") {
                        $rsrcList.ServiceConnections = @($rsrcList.ServiceConnections | Where { $_.serviceConnectionName -in $inputSvcNames }); 
                    }
                    if ($rsrcList.ServiceConnections -and $rsrcList.ServiceConnections.Count -gt 0) {
                        $this.ServiceConnections += $rsrcList.ServiceConnections.serviceConnectionName
                        $this.ServiceConnectionIds += $rsrcList.ServiceConnections.ServiceConnectionId
                        $bFoundSvcMappedObjects = $true
                    }                  
                }
            }
            if ($this.ResourceTypeName -in ([ResourceTypeName]::AgentPool, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User_CommonSVTResources,[ResourceTypeName]::SvcConn_AgentPool_VarGroup_User_CommonSVTResources))
            {
                if ($rsrcList.AgentPools -and $rsrcList.AgentPools.Count -gt 0)
                {
                    if ($inputAgentPoolNames -ne "*") {
                        $rsrcList.AgentPools = @($rsrcList.AgentPools | Where { $_.agentPoolName -in $inputAgentPoolNames }); 
                    }
                    if ($rsrcList.AgentPools -and $rsrcList.AgentPools.Count -gt 0) {
                        $this.AgentPools += $rsrcList.AgentPools.agentPoolName
                        $this.AgentPoolIds += $rsrcList.AgentPools.agentPoolId
                        $bFoundSvcMappedObjects = $true
                    }                 
                }
            }
            if ($this.ResourceTypeName -in ([ResourceTypeName]::VariableGroup, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User_CommonSVTResources,[ResourceTypeName]::SvcConn_AgentPool_VarGroup_User_CommonSVTResources))
            {
                if ($rsrcList.VariableGroups -and $rsrcList.VariableGroups.Count -gt 0)
                {
                    if ($inputVargrpNames -ne "*") {
                        $rsrcList.VariableGroups = @($rsrcList.VariableGroups | Where { $_.variableGroupName -in $inputVargrpNames }); 
                    }
                    if ($rsrcList.VariableGroups -and $rsrcList.VariableGroups.Count -gt 0) {
                        $this.VariableGroups += $rsrcList.VariableGroups.variableGroupName
                        $this.VariableGroupIds += $rsrcList.VariableGroups.variableGroupId
                        $bFoundSvcMappedObjects = $true
                    }                 
                }
            }
            #TODO: Remove this try catch in 2110
            try
            {
                if ($this.ResourceTypeName -in ([ResourceTypeName]::Repository, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User_CommonSVTResources, [ResourceTypeName]::SvcConn_AgentPool_VarGroup_CommonSVTResources))
                {
                    if ($rsrcList.Repositories -and $rsrcList.Repositories.Count -gt 0)
                    {
                        if ($inputRepoNames -ne "*") {
                            $rsrcList.Repositories = @($rsrcList.repositories | Where { $_.repoName -in $inputRepoNames }); 
                        }
                        if ($rsrcList.Repositories -and $rsrcList.Repositories.Count -gt 0) {
                            $this.RepoNames += $rsrcList.Repositories.repoName
                            $bFoundSvcMappedObjects = $true
                        }                      
                    }
                }
                if ($this.ResourceTypeName -in ([ResourceTypeName]::Feed, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User_CommonSVTResources, [ResourceTypeName]::SvcConn_AgentPool_VarGroup_CommonSVTResources))
                {
                    if ($rsrcList.Feeds -and $rsrcList.Feeds.Count -gt 0)
                    {
                        if ($inputFeedNames -ne "*") {
                            $rsrcList.Feeds = @($rsrcList.Feeds | Where { $_.feedName -in $inputFeedNames }); 
                        }
                        if ($rsrcList.Feeds -and $rsrcList.Feeds.Count -gt 0) {
                            $this.FeedNames += $rsrcList.Feeds.feedName
                            $bFoundSvcMappedObjects = $true
                        }                     
                    }
                }
                if ($this.ResourceTypeName -in ([ResourceTypeName]::SecureFile, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User_CommonSVTResources, [ResourceTypeName]::SvcConn_AgentPool_VarGroup_CommonSVTResources))
                {
                    if ($rsrcList.SecureFiles -and $rsrcList.SecureFiles.Count -gt 0)
                    {
                        if ($inputSecFileNames -ne "*") {
                            $rsrcList.SecureFiles = @($rsrcList.SecureFiles | Where { $_.secureFileName -in $inputSecFileNames }); 
                        }
                        if ($rsrcList.SecureFiles -and $rsrcList.SecureFiles.Count -gt 0) {
                            $this.SecureFileNames += $rsrcList.SecureFiles.secureFileName
                            $bFoundSvcMappedObjects = $true
                        }                    
                    }
                }
                if ($this.ResourceTypeName -in ([ResourceTypeName]::Environment, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_VarGroup_User_CommonSVTResources, [ResourceTypeName]::SvcConn_AgentPool_VarGroup_CommonSVTResources))
                {
                    if ($rsrcList.Environments -and $rsrcList.Environments.Count -gt 0)
                    {
                        if ($inputEnvNames -ne "*") {
                            $rsrcList.Environments = @($rsrcList.Environments | Where { $_.environmentName -in $inputEnvNames }); 
                        }
                        if ($rsrcList.Environments -and $rsrcList.Environments.Count -gt 0) {
                            $this.EnvironmentNames += $rsrcList.Environments.environmentName
                            $bFoundSvcMappedObjects = $true
                        }                  
                    }
                }
            }
            catch{
                #eat the exception
            }
        }
        if ($bFoundSvcMappedObjects -eq $false)
        {
            $this.PublishCustomMessage("Could not find any objects mapped to the provided service id : $svcId", [MessageType]::Warning);
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
        $timestamp = (Get-Date)
        # to break out from looping and making further API calls after first call, when not all resources in first fetch are modified after threshold date
        $breakLoop = $false 
        $resourcesFromAuditAdded = $false;
        $modifiedResources = @()
        if($this.UseIncrementalScan -eq $true){
            $incrementalScanHelperObjAudit = [IncrementalScanHelper]::new($this.OrganizationContext.OrganizationName, $projectId,$projectName, $this.IncrementalDate);
            
            if($resourceType -eq "build"){
                $buildIdsFromAudit = @($incrementalScanHelperObjAudit.GetAuditTrailsForBuilds());
                if($buildIdsFromAudit.Count -eq 0 -or $null -ne $buildIdsFromAudit[0]){
                    $modifiedResources=@($incrementalScanHelperObjAudit.GetModifiedBuildsFromAudit($buildIdsFromAudit,$projectName))
                }
            }
            else {
                $releaseIdsFromAudit = @($incrementalScanHelperObjAudit.GetAuditTrailsForReleases());
                if($releaseIdsFromAudit.Count -eq 0 -or $null -ne $releaseIdsFromAudit[0]){
                    $modifiedResources=@($incrementalScanHelperObjAudit.GetModifiedReleasesFromAudit($releaseIdsFromAudit,$projectName))
                }
            }
            

        }


        while ([System.Uri]::TryCreate($resourceDfnUrl, [System.UriKind]::Absolute, [ref] $validatedUri)) {
            if ([string]::IsNullOrWhiteSpace($orginalUri)) {
                $orginalUri = $validatedUri.AbsoluteUri;   
            }
            $progressCount = 0;
            $applicableDefnsObj=@();
            $skipCount += 10000;
            $responseAndUpdatedUri = [WebRequestHelper]::InvokeWebRequestForResourcesInBatch($validatedUri, $orginalUri, $skipCount,$resourceType);
            #API response with resources
            $resourceDefnsObj = @($responseAndUpdatedUri[0]);
            #count of all resources fetched
            $totalCount = $resourceDefnsObj.Count
            #updated URI: null when there is no continuation token
            $resourceDfnUrl = $responseAndUpdatedUri[1];

            if($isFolderPathGiven -and $isFolderSizegt100)
            {
                $applicableDefnsObj = $resourceDefnsObj | Where-Object {$_.path -eq "\$($path)" -or $_.path -replace '\s','' -match [System.Text.RegularExpressions.Regex]::Escape("$($path -replace '\s','')")}
            }
            #in case its not a folder based scan or folder cnt <100
            else 
            {
                $applicableDefnsObj=$resourceDefnsObj;
            }
            if ( (($applicableDefnsObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($applicableDefnsObj[0], "name")) -or ([Helpers]::CheckMember($applicableDefnsObj, "count") -and $applicableDefnsObj[0].count -gt 0)) 
            {
                if($resourceType -eq "build"){
                    $tempLink=($applicableDefnsObj[0].url -split('Definitions/'))[0].replace('_apis/build/', '_build?definitionId=');
                }
                else {
                    $tempLink = "https://dev.azure.com/{0}/{1}/_release?_a=releases&view=mine&definitionId=" -f $this.OrganizationContext.OrganizationName, $projectName;
                                   
                }
                if($this.UseIncrementalScan -eq $true)
                {
                    $updateTimestamp = $true
                    if(-not [string]::IsNullOrWhiteSpace($resourceDfnUrl))
                    {
                        $updateTimestamp = $false
                    }
                    $incrementalScanHelperObj = [IncrementalScanHelper]::new($this.OrganizationContext.OrganizationName, $projectName, $this.IncrementalDate, $updateTimestamp, $timestamp)
                    if($resourceType -eq "build")
                    {
                        $applicableDefnsObj = @($incrementalScanHelperObj.GetModifiedBuilds($applicableDefnsObj))
                        if($applicableDefnsObj.Count -lt $totalCount -and $updateTimestamp -eq $false)
                        {
                            # a continuation token was previously found but no need for making more API calls as even some resources in the first batch are unmodified since last threshold timestamp
                            # update Incremental Scan Helper Object data member UpdateTime to $true, then call function to Update Timestamp
                            $incrementalScanHelperObj.UpdateTime = $true
                            $incrementalScanHelperObj.UpdateTimeStamp("Build")
                            $breakLoop = $true
                        }
                    }
                    else 
                    {
                        $applicableDefnsObj = @($incrementalScanHelperObj.GetModifiedReleases($applicableDefnsObj))    
                    }
                    if($modifiedResources.Count -gt 0 -and $resourcesFromAuditAdded -eq $false){
                        $applicableDefnsObj+=$modifiedResources;
                        $resourcesFromAuditAdded = $true;
                    }
                }
                if($applicableDefnsObj.Count -lt $nObj.Value)
                {
                    $nObj.Value = $applicableDefnsObj.Count;
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
                    if ($progressCount%100 -eq 0) {                                        
                        Write-Progress -Activity "Fetching $($resourceType)s in batches. This may take time. Fetched $($progressCount) of $(($applicableDefnsObj | Measure-Object).Count) $($resourceType)s of batch $($batchCount) " -Status "Progress: " -PercentComplete ($progressCount / ($applicableDefnsObj | Measure-Object).Count * 100)
                    }
                    $progressCount = $progressCount + 1;
                    if (--$nObj.Value -eq 0) { break; }
                }
                $batchCount = $batchCount + 1;                             

            }
            else {
                break;
            }
            if ($nObj.Value -eq 0) { break; }
            if($breakLoop -eq $true) { break; }
        }
        Write-Progress -Activity "All $($resourceType)s fetched" -Status "Ready" -Completed
        $resourceDefnsObj = $null;
        $applicableDefnsObj=$null;
        Remove-Variable resourceDefnsObj;
        Remove-Variable applicableDefnsObj;
    }

        
    [string] FindResourceTypeFromPartialScan($nonScannedResourceId){
        $type="";
        switch -wildcard ($nonScannedResourceId) {
            "*/release/*" {$type="ADO.Release"; Break}
            "*/agentpool/*" {$type="ADO.AgentPool"; Break}           
            
            Default {}
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

    [void] addBuildsToSvtInBatchScan($ProjectName,$ProjectId,$Path){
        if($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("BatchScanMultipleProjects")){
            [BatchScanManagerForMultipleProjects] $batchScanMngr = [BatchScanManagerForMultipleProjects]:: GetInstance();
        }
        else {
            [BatchScanManager] $batchScanMngr = [BatchScanManager]:: GetInstance();
        }
        
        $batchStatus= $batchScanMngr.GetBatchStatus();

        if(-not("BuildCurrentContinuationToken" -in $batchStatus.PSobject.Properties.Name)){
            Write-Error -Message "A previous batch with different resource type was found to still be in progress. You can either run the command with the same parameters as the previous batch or if you wish to scan with the current new command you should clear the given folders: %LOCALAPPDATA%/Microsoft/AzSK.ADO/Tempstate/BatchScanData/[org_name] and %LOCALAPPDATA%/Microsoft/AzSK.ADO/Tempstate/PartialScanData/[org_name]" -Category InvalidArgument
        }
        #all builds have been scanned
        if([string]::IsNullOrEmpty($batchStatus.BuildCurrentContinuationToken) -and $batchStatus.Skip -gt 0){
           
            return;
        }
        $topNQueryString = '&$top={0}' -f $batchScanMngr.GetBatchSize();
        
        if($null -ne $batchStatus.BuildCurrentContinuationToken){
            $buildDefURL= ("https://dev.azure.com/{0}/{1}/_apis/build/definitions?queryOrder=lastModifiedDescending&api-version=6.0&%24skip={2}&continuationToken={3}" +$topNQueryString) -f $($this.OrganizationContext.OrganizationName), $ProjectName, $batchStatus.Skip, $batchStatus.BuildCurrentContinuationToken;
        }
        else {
            $buildDefURL= ("https://dev.azure.com/{0}/{1}/_apis/build/definitions?queryOrder=lastModifiedDescending&api-version=6.0&%24skip={2}" +$topNQueryString) -f $($this.OrganizationContext.OrganizationName), $ProjectName, $batchStatus.Skip;
        }
        $updatedUriAndContToken=[WebRequestHelper]:: InvokeWebRequestForContinuationToken($buildDefURL,$buildDefURL,$null,'build');
        $continuationToken=$updatedUriAndContToken[0];
        $buildDefnsObj=$updatedUriAndContToken[2];

        if($null -ne $Path){            
                  
            $buildDefnsObj = $buildDefnsObj | Where-Object {$_.path -eq "\$($Path)" -or $_.path -replace '\s','' -match [System.Text.RegularExpressions.Regex]::Escape("$($Path -replace '\s','')")}
       
        }
        $progressCount=1
        if (([Helpers]::CheckMember($buildDefnsObj, "count") -and $buildDefnsObj[0].count -gt 0) -or (($buildDefnsObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($buildDefnsObj[0], "name"))) {
            foreach ($bldDef in $buildDefnsObj) {
                $link = $bldDef.url.split('?')[0].replace('_apis/build/Definitions/', '_build?definitionId=');
                $buildResourceId = "organization/$($this.OrganizationContext.OrganizationId)/project/$ProjectId/build/$($bldDef.id)";
                $this.AddSVTResource($bldDef.name, $bldDef.project.name, "ADO.Build", $buildResourceId, $bldDef, $link);
                if ($progressCount%100 -eq 0) {                
                    Write-Progress -Activity "Fetched $($progressCount) out of $(($buildDefnsObj | Measure-Object).Count) builds " -Status "Progress: " -PercentComplete ($progressCount / ($buildDefnsObj | Measure-Object).Count * 100)
                }
                $progressCount+=1
            }
            $buildDefnsObj = $null;
            Remove-Variable buildDefnsObj;
        }
        Write-Progress -Activity "All builds fetched" -Status "Ready" -Completed
        $batchStatus.BuildNextContinuationToken=$continuationToken;
        $batchStatus.TokenLastModifiedTime=[DateTime]::UtcNow;
        $batchScanMngr.BatchScanTrackerObj = $batchStatus;
        $batchScanMngr.WriteToBatchTrackerFile();
        
    }

    [void] addReleasesToSvtInBatchScan($ProjectName,$ProjectId,$Path){
        if($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("BatchScanMultipleProjects")){
            [BatchScanManagerForMultipleProjects] $batchScanMngr = [BatchScanManagerForMultipleProjects]:: GetInstance();
        }
        else {
            [BatchScanManager] $batchScanMngr = [BatchScanManager]:: GetInstance();
        }
        $batchStatus= $batchScanMngr.GetBatchStatus();
        if(-not("ReleaseCurrentContinuationToken" -in $batchStatus.PSobject.Properties.Name)){
            Write-Error -Message "A previous batch with different resource type was found to still be in progress. You can either run the command with the same parameters as the previous batch or if you wish to scan with the current new command you should clear the given folders: %LOCALAPPDATA%/Microsoft/AzSK.ADO/Tempstate/BatchScanData/[org_name] and %LOCALAPPDATA%/Microsoft/AzSK.ADO/Tempstate/PartialScanData/[org_name]" -Category InvalidArgument
        }
        #all releases have been scanned
        if([string]::IsNullOrEmpty($batchStatus.ReleaseCurrentContinuationToken) -and $batchStatus.Skip -gt 0){
            return;
        }
        $topNQueryString = '&$top={0}' -f $batchScanMngr.GetBatchSize();
        if($null -ne $batchStatus.ReleaseCurrentContinuationToken){
            $releaseDefURL= ("https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?api-version=6.0&continuationToken={2}" +$topNQueryString) -f $($this.OrganizationContext.OrganizationName), $ProjectName, $batchStatus.ReleaseCurrentContinuationToken;
        }
        else {
            $releaseDefURL= ("https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions?api-version=6.0" +$topNQueryString ) -f $($this.OrganizationContext.OrganizationName), $ProjectName;
        }
        $updatedUriAndContToken=[WebRequestHelper]:: InvokeWebRequestForContinuationToken($releaseDefURL,$releaseDefURL,$null,'release');
        $continuationToken=$updatedUriAndContToken[0];
        $releaseDefnsObj=$updatedUriAndContToken[2];

        if($null -ne $Path){            
                  
            $releaseDefnsObj = $releaseDefnsObj | Where-Object {$_.path -eq "\$($Path)" -or $_.path -replace '\s','' -match [System.Text.RegularExpressions.Regex]::Escape("$($Path -replace '\s','')")}
       
        }
        $progressCount=1
        if (([Helpers]::CheckMember($releaseDefnsObj, "count") -and $releaseDefnsObj[0].count -gt 0) -or (($releaseDefnsObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($releaseDefnsObj[0], "name"))) {
            $tempLink = "https://dev.azure.com/{0}/{1}/_release?_a=releases&view=mine&definitionId=" -f $this.OrganizationContext.OrganizationName, $projectName;
            foreach ($releaseDef in $releaseDefnsObj) {
                $link = $tempLink+$releaseDef.id
                $releaseResourceId = "organization/$($this.OrganizationContext.OrganizationId)/project/$ProjectId/release/$($releaseDef.id)";
                $this.AddSVTResource($releaseDef.name, $ProjectName, "ADO.Release", $releaseResourceId, $null, $link);
                if ($progressCount%100 -eq 0){
                    Write-Progress -Activity "Fetched $($progressCount) out of $(($releaseDefnsObj | Measure-Object).Count) releases " -Status "Progress: " -PercentComplete ($progressCount / ($releaseDefnsObj | Measure-Object).Count * 100)
                }
                $progressCount+=1
            }
            $releaseDefnsObj = $null;
            Remove-Variable releaseDefnsObj;
        }
        Write-Progress -Activity "All releases fetched" -Status "Ready" -Completed
        $batchStatus.ReleaseNextContinuationToken=$continuationToken;
        $batchStatus.TokenLastModifiedTime=[DateTime]::UtcNow;
        $batchScanMngr.BatchScanTrackerObj = $batchStatus;
        $batchScanMngr.WriteToBatchTrackerFile();
        
    }


}