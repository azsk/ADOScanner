Set-StrictMode -Version Latest
class Project: ADOSVTBase
{
    [PSObject] $PipelineSettingsObj = $null
    hidden $PAMembers = @()
    hidden $Repos = $null
    hidden [PSObject] $graphPermissions = @{hasGraphAccess = $false; graphAccessToken = $null}; # This is used to check user has graph permissions to compute the graph api operations.
    hidden $GuestMembers = @()
    hidden $AllUsersInOrg = @()

    Project([string] $organizationName, [SVTResource] $svtResource): Base($organizationName,$svtResource)
    {
        $this.Repos = $null
        $this.GetPipelineSettingsObj()
        $this.graphPermissions.hasGraphAccess = [IdentityHelpers]::HasGraphAccess();
        if ($this.graphPermissions.hasGraphAccess) {
            $this.graphPermissions.graphAccessToken = [IdentityHelpers]::graphAccessToken
        }

        # If switch ALtControlEvaluationMethod is set as true in org policy, then evaluating control using graph API. If not then fall back to RegEx based evaluation.
        if ([string]::IsNullOrWhiteSpace([IdentityHelpers]::ALTControlEvaluationMethod)) {
            [IdentityHelpers]::ALTControlEvaluationMethod = "GraphThenRegEx"
            if ([Helpers]::CheckMember($this.ControlSettings, "ALTControlEvaluationMethod"))
            {
                if (($this.ControlSettings.ALtControlEvaluationMethod -eq "Graph")) {
                    [IdentityHelpers]::ALTControlEvaluationMethod = "Graph"
                }
                elseif (($this.ControlSettings.ALtControlEvaluationMethod -eq "RegEx")) {
                    [IdentityHelpers]::ALTControlEvaluationMethod = "RegEx"
                }
            }
        }
    }

    GetPipelineSettingsObj()
    {
        $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $($this.OrganizationContext.OrganizationName);
        #TODO: testing adding below line commenting above line
        #$apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $($this.OrganizationContext.OrganizationName);

        $orgUrl = "https://dev.azure.com/{0}" -f $($this.OrganizationContext.OrganizationName);
        $projectName = $this.ResourceContext.ResourceName;
        #$inputbody =  "{'contributionIds':['ms.vss-org-web.collection-admin-policy-data-provider'],'context':{'properties':{'sourcePage':{'url':'$orgUrl/_settings/policy','routeId':'ms.vss-admin-web.collection-admin-hub-route','routeValues':{'adminPivot':'policy','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json
        $inputbody = "{'contributionIds':['ms.vss-build-web.pipelines-general-settings-data-provider'],'dataProviderContext':{'properties':{'sourcePage':{'url':'$orgUrl/$projectName/_settings/settings','routeId':'ms.vss-admin-web.project-admin-hub-route','routeValues':{'project':'$projectName','adminPivot':'settings','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json

        $responseObj = $null
        try{
            $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL,$inputbody);
        }
        catch{
            #Write-Host "Pipeline settings for the project [$projectName] can not be fetched."
        }

        if($responseObj){
            if([Helpers]::CheckMember($responseObj,"dataProviders"))
            {
                try {
                    if($responseObj.dataProviders.'ms.vss-build-web.pipelines-general-settings-data-provider'){
                        $this.PipelineSettingsObj = $responseObj.dataProviders.'ms.vss-build-web.pipelines-general-settings-data-provider'
                    }
                }
                catch {
                    #Write-Host "Pipeline settings for the project [$projectName] can not be fetched."
                }
            }
        }
    }

    hidden [ControlResult] CheckProjectVisibility([ControlResult] $controlResult)
	{
        try
        {
            $controlResult.VerificationResult = [VerificationResult]::Failed
            if([Helpers]::CheckMember($this.ResourceContext.ResourceDetails,"visibility"))
            {
                $visibility = $this.ResourceContext.ResourceDetails.visibility;
                if(($visibility -eq "private") -or ($visibility -eq "organization"))
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "Project visibility is set to '$visibility'.");

                }
                else # For orgs with public projects allowed, this control needs to be attested by the project admins.
                {
                    $controlResult.AddMessage("Project visibility is set to '$visibility'.");
                }
                $controlResult.AdditionalInfo += "Project visibility is set to: " + $visibility;
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Error,"Project visibility details could not be fetched.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,"Project visibility details could not be fetched.");
            $controlResult.LogException($_)
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckBadgeAnonAccess([ControlResult] $controlResult)
    {
       if($this.PipelineSettingsObj)
       {

            if($this.PipelineSettingsObj.statusBadgesArePrivate.enabled -eq $true )
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Anonymous access to status badge API is disabled. It is set as '$($this.PipelineSettingsObj.statusBadgesArePrivate.orgEnabled)' at organization scope.");
            }
            else{
                $controlResult.AddMessage([VerificationResult]::Failed, "Anonymous access to status badge API is enabled. It is set as '$($this.PipelineSettingsObj.statusBadgesArePrivate.orgEnabled)' at organization scope.");
            }
       }
       else{
            $controlResult.AddMessage([VerificationResult]::Manual, "Pipeline settings could not be fetched due to insufficient permissions at project scope.");
       }
        return $controlResult
    }

    hidden [ControlResult] CheckSettableQueueTime([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        if($this.PipelineSettingsObj)
        {            
            if($this.PipelineSettingsObj.enforceSettableVar.enabled -eq $true )
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Only explicitly marked 'settable at queue time' variables can be set at queue time. It is set as '$($this.PipelineSettingsObj.enforceSettableVar.orgEnabled)' at organization scope.");
            }
            else{
                $controlResult.AddMessage("All variables can be set at queue time. It is set as '$($this.PipelineSettingsObj.enforceSettableVar.orgEnabled)' at organization scope.");
            }
        }
        else{
            $controlResult.AddMessage([VerificationResult]::Error, "Pipeline settings could not be fetched for the project.");
        }
        return $controlResult
    }

    hidden [ControlResult] CheckJobAuthZScope([ControlResult] $controlResult)
    {
        if($this.PipelineSettingsObj)
        {
            $orgLevelScope = $this.PipelineSettingsObj.enforceJobAuthScope.orgEnabled;
            $prjLevelScope = $this.PipelineSettingsObj.enforceJobAuthScope.enabled;

            if($prjLevelScope -eq $true )
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Job authorization scope is limited to current project for non-release pipelines.");
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Failed, "Job authorization scope is set to project collection for non-release pipelines.");
            }

            if($orgLevelScope -eq $true )
            {
                $controlResult.AddMessage("This setting is enabled (limited to current project) at organization level.");
            }
            else
            {
                $controlResult.AddMessage("This setting is disabled (set to project collection) at organization level.");
            }
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch project pipeline settings.");
        }
        return $controlResult
    }

    hidden [ControlResult] CheckJobAuthZReleaseScope([ControlResult] $controlResult)
    {
        if($this.PipelineSettingsObj)
        {
            $orgLevelScope = $this.PipelineSettingsObj.enforceJobAuthScopeForReleases.orgEnabled;
            $prjLevelScope = $this.PipelineSettingsObj.enforceJobAuthScopeForReleases.enabled;

            if($prjLevelScope -eq $true )
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Job authorization scope is limited to current project for release pipelines.");
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Failed, "Job authorization scope is set to project collection for release pipelines.");
            }

            if($orgLevelScope -eq $true )
            {
                $controlResult.AddMessage("This setting is enabled (limited to current project) at organization level.");
            }
            else
            {
                $controlResult.AddMessage("This setting is disabled (set to project collection) at organization level.");
            }
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch project pipeline settings.");
        }
        return $controlResult
    }

    hidden [ControlResult] CheckAuthZRepoScope([ControlResult] $controlResult)
    {
        if($this.PipelineSettingsObj)
        {
            $orgLevelScope = $this.PipelineSettingsObj.enforceReferencedRepoScopedToken.orgEnabled;
            $prjLevelScope = $this.PipelineSettingsObj.enforceReferencedRepoScopedToken.enabled;

            if($prjLevelScope -eq $true )
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Job authorization scope of pipelines is limited to explicitly referenced Azure DevOps repositories.");
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Failed, "Job authorization scope of pipelines is set to all Azure DevOps repositories in the authorized projects.");
            }

            if($orgLevelScope -eq $true )
            {
                $controlResult.AddMessage("This setting is enabled (limited to explicitly referenced Azure DevOps repositories) at organization level.");
            }
            else
            {
                $controlResult.AddMessage("This setting is disabled (set to all Azure DevOps repositories in authorized projects) at organization level.");
            }
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch project pipeline settings.");
        }
        return $controlResult
    }

    hidden [ControlResult] CheckPublishMetadata([ControlResult] $controlResult)
    {
       if($this.PipelineSettingsObj)
       {

            if($this.PipelineSettingsObj.publishPipelineMetadata.enabled -eq $true )
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Publishing metadata from pipeline is enabled. It is set as '$($this.PipelineSettingsObj.publishPipelineMetadata.orgEnabled)' at organization scope.");
            }
            else{
                $controlResult.AddMessage([VerificationResult]::Failed, "Publishing metadata from pipeline is disabled. It is set as '$($this.PipelineSettingsObj.publishPipelineMetadata.orgEnabled)' at organization scope.");
            }
       }
       else{
            $controlResult.AddMessage([VerificationResult]::Manual, "Pipeline settings could not be fetched due to insufficient permissions at project scope.");
       }
        return $controlResult
    }

    hidden [ControlResult] CheckRBACAccess([ControlResult] $controlResult)
    {
        <#
            This control has been currently removed from control JSON file.
            {
                "ControlID": "ADO_Project_AuthZ_Min_RBAC_Access",
                "Description": "All teams/groups must be granted minimum required permissions on the project.",
                "Id": "Project120",
                "ControlSeverity": "High",
                "Automated": "No",
                "MethodName": "CheckRBACAccess",
                "Rationale": "Granting minimum access by leveraging RBAC feature ensures that users are granted just enough permissions to perform their tasks. This minimizes exposure of the resources in case of user/service account compromise.",
                "Recommendation": "Refer: https://docs.microsoft.com/en-us/azure/devops/organizations/security/set-project-collection-level-permissions?view=vsts&tabs=new-nav",
                "Tags": [
                            "SDL",
                            "TCP",
                            "Manual",
                            "AuthZ",
                            "RBAC"
                        ],
                "Enabled": true
            }
        #>
        $url = 'https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1' -f $($this.OrganizationContext.OrganizationName);
        $inputbody = '{"contributionIds":["ms.vss-admin-web.org-admin-groups-data-provider"],"dataProviderContext":{"properties":{"sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"permissions","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json
        $inputbody.dataProviderContext.properties.sourcePage.url = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ResourceContext.ResourceName)/_settings/permissions";
        $inputbody.dataProviderContext.properties.sourcePage.routeValues.Project =$this.ResourceContext.ResourceName;

        $groupsObj = [WebRequestHelper]::InvokePostWebRequest($url,$inputbody);

        $Allgroups =  @()
         $groupsObj.dataProviders."ms.vss-admin-web.org-admin-groups-data-provider".identities  | ForEach-Object {
            $Allgroups += $_;
        }

        $descrurl ='https://vssps.dev.azure.com/{0}/_apis/graph/descriptors/{1}?api-version=6.0-preview.1' -f $($this.OrganizationContext.OrganizationName), $this.ResourceContext.ResourceId.split('/')[-1];
        $descr = [WebRequestHelper]::InvokeGetWebRequest($descrurl);

        $apiURL = "https://vssps.dev.azure.com/{0}/_apis/Graph/Users?scopeDescriptor={1}&api-version=6.0-preview.1" -f $($this.OrganizationContext.OrganizationName), $descr[0];
        $usersObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);

        <# $Users =  @()
        $usersObj[0].items | ForEach-Object {
                $Users+= $_
        } #>

        $groups = ($Allgroups | Select-Object -Property @{Name="Name"; Expression = {$_.displayName}},@{Name="Description"; Expression = {$_.description}});

        $UsersNames = ($usersObj | Select-Object -Property @{Name="Name"; Expression = {$_.displayName}},@{Name="mailAddress"; Expression = {$_.mailAddress}})

        if ( (($groups | Measure-Object).Count -gt 0) -or (($UsersNames | Measure-Object).Count -gt 0)) {
            $controlResult.AddMessage([VerificationResult]::Verify, "Verify users and groups present on project");

            $controlResult.AddMessage("Verify groups has access on project", $groups);
            $controlResult.AddMessage("Verify users has access on project", $UsersNames);
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,  "No users or groups found");
        }

        return $controlResult
    }

    hidden [ControlResult] JustifyGroupMember([ControlResult] $controlResult)
    {
        $grpmember = @();
        $url = 'https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1' -f $($this.OrganizationContext.OrganizationName);
        $inputbody = '{"contributionIds":["ms.vss-admin-web.org-admin-groups-data-provider"],"dataProviderContext":{"properties":{"sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"permissions","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json
        $inputbody.dataProviderContext.properties.sourcePage.url = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ResourceContext.ResourceName)/_settings/permissions";
        $inputbody.dataProviderContext.properties.sourcePage.routeValues.Project =$this.ResourceContext.ResourceName;

        $groupsObj = [WebRequestHelper]::InvokePostWebRequest($url,$inputbody);

        $groups =  @()
         $groupsObj.dataProviders."ms.vss-admin-web.org-admin-groups-data-provider".identities  | ForEach-Object {
            $groups += $_;
        }

        $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview" -f $($this.OrganizationContext.OrganizationName);

        $membercount =0;
        Foreach ($group in $groups){
            $groupmember = @();
         $descriptor = $group.descriptor;
         $inputbody =  '{"contributionIds":["ms.vss-admin-web.org-admin-members-data-provider"],"dataProviderContext":{"properties":{"subjectDescriptor":"","sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"permissions","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json

         $inputbody.dataProviderContext.properties.subjectDescriptor = $descriptor;
         $inputbody.dataProviderContext.properties.sourcePage.url = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ResourceContext.ResourceName)/_settings/permissions?subjectDescriptor=$($descriptor)";
         $inputbody.dataProviderContext.properties.sourcePage.routeValues.Project =$this.ResourceContext.ResourceName;

         $usersObj = [WebRequestHelper]::InvokePostWebRequest($apiURL,$inputbody);

         if([Helpers]::CheckMember($usersObj.dataProviders.'ms.vss-admin-web.org-admin-members-data-provider', "identities")) {
            $usersObj.dataProviders."ms.vss-admin-web.org-admin-members-data-provider".identities  | ForEach-Object {
                $groupmember += $_;
            }
        }

        $grpmember = ($groupmember | Select-Object -Property @{Name="Name"; Expression = {$_.displayName}},@{Name="mailAddress"; Expression = {$_.mailAddress}});
        if ($grpmember -ne $null) {
            $membercount= $membercount + 1
            $controlResult.AddMessage("Verify below members of the group: '$($group.principalname)', Description: $($group.description)", $grpmember);
        }

        }

        if ( $membercount  -gt 0)  {
            $controlResult.AddMessage([VerificationResult]::Verify, "Verify members of groups present on project");
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,  "No users or groups found");
        }

        return $controlResult
    }

    hidden [ControlResult] CheckMinPACount([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        $TotalPAMembers = 0;
        if ($this.PAMembers.Count -eq 0) {
            $this.PAMembers += @([AdministratorHelper]::GetTotalPAMembers($this.OrganizationContext.OrganizationName,$this.ResourceContext.ResourceName))
        }
        if([Helpers]::CheckMember($this.PAMembers[0],"mailAddress"))
        {
            $TotalPAMembers = $this.PAMembers.Count
        }
        
        $controlResult.AddMessage("There are a total of $TotalPAMembers Project Administrators in your project.")
        if ($TotalPAMembers -gt 0) {
            if ($this.graphPermissions.hasGraphAccess)
            {
                $SvcAndHumanAccounts = [IdentityHelpers]::DistinguishHumanAndServiceAccount($this.PAMembers, $this.OrganizationContext.OrganizationName)
                $humanAccounts = @($SvcAndHumanAccounts.humanAccount | Select-Object displayName, mailAddress)
                $svcAccounts = @($SvcAndHumanAccounts.serviceAccount | Select-Object displayName, mailAddress)
                
                # In case of graph access we will only evaluate the control on the basis of human accounts
                if($humanAccounts.count -lt $this.ControlSettings.Project.MinPAMembersPermissible){
                    $controlResult.AddMessage([VerificationResult]::Failed,"Number of human administrators configured are less than the minimum required administrators count: $($this.ControlSettings.Project.MinPAMembersPermissible)");
                }
                else{
                    $controlResult.AddMessage([VerificationResult]::Passed,"Number of human administrators configured meet the minimum required administrators count: $($this.ControlSettings.Project.MinPAMembersPermissible)");
                }
                if($TotalPAMembers -gt 0){
                    $controlResult.AddMessage("Current set of Project Administrators: ")
                    $controlResult.AdditionalInfo += "Count of Project Administrators: " + $TotalPAMembers;
                }

                if ($humanAccounts.count -gt 0) {                   
                    $controlResult.AddMessage("`nHuman administrators: $($humanAccounts.Count)")
                    $display = ($humanAccounts|FT  -AutoSize | Out-String -Width 512)
                    $controlResult.AddMessage($display)
                    $controlResult.SetStateData("List of human Project Administrators: ",$humanAccounts)
                }

                if ($svcAccounts.count -gt 0) {                   
                    $controlResult.AddMessage("`nService accounts: $($svcAccounts.Count)")
                    $display = ($svcAccounts|FT  -AutoSize | Out-String -Width 512)
                    $controlResult.AddMessage($display)
                    $controlResult.SetStateData("List of service account Project Administrators: ",$svcAccounts)
                }
            }
            else
            {
                ## TODO: Add warning that control was evaluated without graph access ( Once Sourabh is done with its Graph access task)
                $this.PAMembers = @($this.PAMembers | Select-Object displayName,mailAddress)
                if($TotalPAMembers -lt $this.ControlSettings.Project.MinPAMembersPermissible){
                    $controlResult.AddMessage([VerificationResult]::Failed,"Number of administrators configured are less than the minimum required administrators count: $($this.ControlSettings.Project.MinPAMembersPermissible)");
                }
                else{
                    $controlResult.AddMessage([VerificationResult]::Passed,"Number of administrators configured meet the minimum required administrators count: $($this.ControlSettings.Project.MinPAMembersPermissible)");
                }
                if($TotalPAMembers -gt 0){
                    $controlResult.AddMessage("Current set of Project Administrators: ")
                    $display = ($this.PAMembers|FT  -AutoSize | Out-String -Width 512)
                    $controlResult.AddMessage($display)
                    $controlResult.SetStateData("List of Project Administrators: ",$this.PAMembers)
                    $controlResult.AdditionalInfo += "Count of Project Administrators: " + $TotalPAMembers;
                }
            }
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Failed,"No Project Administrators are configured in the project.");
        }

        return $controlResult
    }

    hidden [ControlResult] CheckMaxPACount([ControlResult] $controlResult)
    {
        $TotalPAMembers = 0;
        if (($this.PAMembers | Measure-Object).Count -eq 0) {
            $this.PAMembers += [AdministratorHelper]::GetTotalPAMembers($this.OrganizationContext.OrganizationName,$this.ResourceContext.ResourceName)
        }
        $TotalPAMembers = ($this.PAMembers | Measure-Object).Count
        $controlResult.AddMessage("There are a total of $TotalPAMembers Project Administrators in your project.")
        if ($TotalPAMembers -gt 0)
        {
            if ($this.graphPermissions.hasGraphAccess)
            {
                $SvcAndHumanAccounts = [IdentityHelpers]::DistinguishHumanAndServiceAccount($this.PAMembers, $this.OrganizationContext.OrganizationName)
                $HumanAcccountCount = ($SvcAndHumanAccounts.humanAccount | Measure-Object).Count
                if($HumanAcccountCount -gt $this.ControlSettings.Project.MaxPAMembersPermissible){
                    $controlResult.AddMessage([VerificationResult]::Failed,"Number of administrators configured are more than the approved limit: $($this.ControlSettings.Project.MaxPAMembersPermissible)");
                }
                else{
                    $controlResult.AddMessage([VerificationResult]::Passed,"Number of administrators configured are within than the approved limit: $($this.ControlSettings.Project.MaxPAMembersPermissible)");
                }
                if($TotalPAMembers -gt 0){
                    $controlResult.AddMessage("Verify the following Project Administrators: ")
                    $controlResult.AdditionalInfo += "Total number of Project Administrators: " + $TotalPAMembers;
                }

                if (($SvcAndHumanAccounts.humanAccount | Measure-Object).Count -gt 0) {
                    $humanAccounts = $SvcAndHumanAccounts.humanAccount | Select-Object displayName, mailAddress
                    $controlResult.AddMessage("`nHuman Administrators: $(($humanAccounts| Measure-Object).Count)", $humanAccounts)
                    $controlResult.SetStateData("List of human Project Administrators: ",$humanAccounts)
                }

                if (($SvcAndHumanAccounts.serviceAccount | Measure-Object).Count -gt 0) {
                    $svcAccounts = $SvcAndHumanAccounts.serviceAccount | Select-Object displayName, mailAddress
                    $controlResult.AddMessage("`nService Account Administrators: $(($svcAccounts| Measure-Object).Count)", $svcAccounts)
                    $controlResult.SetStateData("List of service account Project Administrators: ",$svcAccounts)
                }
            }
            else
            {
                $this.PAMembers = $this.PAMembers | Select-Object displayName,mailAddress
                if($TotalPAMembers -gt $this.ControlSettings.Project.MaxPAMembersPermissible){
                    $controlResult.AddMessage([VerificationResult]::Failed,"Number of administrators configured are more than the approved limit: $($this.ControlSettings.Project.MaxPAMembersPermissible).");
                }
                else{
                    $controlResult.AddMessage([VerificationResult]::Passed,"Number of administrators configured are within than the approved limit: $($this.ControlSettings.Project.MaxPAMembersPermissible).");
                }
                if($TotalPAMembers -gt 0){
                    $controlResult.AddMessage("Verify the following Project Administrators: ",$this.PAMembers)
                    $controlResult.SetStateData("List of Project Administrators: ",$this.PAMembers)
                    $controlResult.AdditionalInfo += "Total number of Project Administrators: " + $TotalPAMembers;
                }
            }
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Failed,"No Project Administrators are configured in the project.");
        }

        return $controlResult
    }

    hidden [ControlResult] CheckSCALTForAdminMembers([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            if(($null -ne $this.ControlSettings) -and [Helpers]::CheckMember($this.ControlSettings, "Project.GroupsToCheckForSCAltMembers"))
            {

                $adminGroupNames = @($this.ControlSettings.Project.GroupsToCheckForSCAltMembers);
                if ($adminGroupNames.Count -gt 0)
                {
                    #api call to get descriptor for organization groups. This will be used to fetch membership of individual groups later.
                    $url = 'https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1' -f $($this.OrganizationContext.OrganizationName);
                    $inputbody = '{"contributionIds":["ms.vss-admin-web.org-admin-groups-data-provider"],"dataProviderContext":{"properties":{"sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"permissions","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json
                    $inputbody.dataProviderContext.properties.sourcePage.url = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ResourceContext.ResourceName)/_settings/permissions";
                    $inputbody.dataProviderContext.properties.sourcePage.routeValues.Project = $this.ResourceContext.ResourceName;

                    $response = [WebRequestHelper]::InvokePostWebRequest($url, $inputbody);

                    if ($response -and [Helpers]::CheckMember($response[0], "dataProviders") -and $response[0].dataProviders."ms.vss-admin-web.org-admin-groups-data-provider")
                    {
                        $adminGroups = @();
                        $adminGroups += $response.dataProviders."ms.vss-admin-web.org-admin-groups-data-provider".identities | where { $_.displayName -in $adminGroupNames }

                        if($adminGroups.Count -gt 0)
                        {
                            #global variable to track admin members across all admin groups
                            $allAdminMembers = @();

                            for ($i = 0; $i -lt $adminGroups.Count; $i++)
                            {
                                # [AdministratorHelper]::AllPAMembers is a static variable. Always needs ro be initialized. At the end of each iteration, it will be populated with members of that particular admin group.
                                [AdministratorHelper]::AllPAMembers = @();
                                # Helper function to fetch flattened out list of group members.
                                [AdministratorHelper]::FindPAMembers($adminGroups[$i].descriptor,  $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceName)

                                $groupMembers = @();
                                # Add the members of current group to this temp variable.
                                $groupMembers += [AdministratorHelper]::AllPAMembers
                                # Create a custom object to append members of current group with the group name. Each of these custom object is added to the global variable $allAdminMembers for further analysis of SC-Alt detection.
                                $groupMembers | ForEach-Object {$allAdminMembers += @( [PSCustomObject] @{ name = $_.displayName; mailAddress = $_.mailAddress; id = $_.originId; groupName = $adminGroups[$i].displayName } )}
                            }

                            # clearing cached value in [AdministratorHelper]::AllPAMembers as it can be used in attestation later and might have incorrect group loaded.
                            [AdministratorHelper]::AllPAMembers = @();
                            # Filtering out distinct entries. A user might be added directly to the admin group or might be a member of a child group of the admin group.
                            $allAdminMembers = @($allAdminMembers| Sort-Object -Property id -Unique)

                            if($allAdminMembers.Count -gt 0)
                            {
                                $useGraphEvaluation = $false
                                $useRegExEvaluation = $false
                                if ([IdentityHelpers]::ALTControlEvaluationMethod -eq "GraphThenRegEx") {
                                    if ($this.graphPermissions.hasGraphAccess){
                                        $useGraphEvaluation = $true
                                    }
                                    else {
                                        $useRegExEvaluation = $true
                                    }
                                }

                                if ([IdentityHelpers]::ALTControlEvaluationMethod -eq "Graph" -or $useGraphEvaluation)
                                {
                                    if ($this.graphPermissions.hasGraphAccess)
                                    {
                                        $allAdmins = [IdentityHelpers]::DistinguishAltAndNonAltAccount($allAdminMembers)
                                        $SCMembers = $allAdmins.altAccount
                                        $nonSCMembers = $allAdmins.nonAltAccount

                                        $nonSCCount = $nonSCMembers.Count
                                        $SCCount = $SCMembers.Count

                                        if ($nonSCCount -gt 0)
                                        {
                                            $nonSCMembers = $nonSCMembers | Select-Object name,mailAddress,groupName
                                            $stateData = @();
                                            $stateData += $nonSCMembers
                                            $controlResult.AddMessage([VerificationResult]::Failed, "`nCount of non-ALT accounts with admin privileges:  $nonSCCount");
                                            $controlResult.AddMessage("List of non-ALT accounts: ", $($stateData | Format-Table -AutoSize | Out-String));
                                            $controlResult.SetStateData("List of non-ALT accounts: ", $stateData);
                                            $controlResult.AdditionalInfo += "Count of non-ALT accounts with admin privileges: " + $nonSCCount;
                                        }
                                        else
                                        {
                                            $controlResult.AddMessage([VerificationResult]::Passed, "No users have admin privileges with non SC-ALT accounts.");
                                        }
                                        if ($SCCount -gt 0)
                                        {
                                            $SCMembers = $SCMembers | Select-Object name,mailAddress,groupName
                                            $SCData = @();
                                            $SCData += $SCMembers
                                            $controlResult.AddMessage("`nCount of ALT accounts with admin privileges: $SCCount");
                                            $controlResult.AdditionalInfo += "Count of ALT accounts with admin privileges: " + $SCCount;
                                            $controlResult.AddMessage("List of ALT accounts: ", $($SCData | Format-Table -AutoSize | Out-String));
                                        }
                                    }
                                    else {
                                        $controlResult.AddMessage([VerificationResult]::Error, "The signed-in user identity does not have graph permission.");
                                    }
                                }

                                if ([IdentityHelpers]::ALTControlEvaluationMethod -eq "RegEx" -or $useRegExEvaluation)
                                {
                                    if([Helpers]::CheckMember($this.ControlSettings, "AlernateAccountRegularExpressionForOrg")){
                                        $matchToSCAlt = $this.ControlSettings.AlernateAccountRegularExpressionForOrg
                                        #currently SC-ALT regex is a singleton expression. In case we have multiple regex - we need to make the controlsetting entry as an array and accordingly loop the regex here.
                                        if (-not [string]::IsNullOrEmpty($matchToSCAlt))
                                        {
                                            $nonSCMembers = @();
                                            $nonSCMembers += $allAdminMembers | Where-Object { $_.mailAddress -notmatch $matchToSCAlt }
                                            $nonSCCount = $nonSCMembers.Count

                                            $SCMembers = @();
                                            $SCMembers += $allAdminMembers | Where-Object { $_.mailAddress -match $matchToSCAlt }
                                            $SCCount = $SCMembers.Count

                                            if ($nonSCCount -gt 0)
                                            {
                                                $nonSCMembers = $nonSCMembers | Select-Object name,mailAddress,groupName
                                                $stateData = @();
                                                $stateData += $nonSCMembers
                                                $controlResult.AddMessage([VerificationResult]::Failed, "`nCount of non-ALT accounts with admin privileges: $nonSCCount");
                                                $controlResult.AddMessage("List of non-ALT accounts: ", $($stateData | Format-Table -AutoSize | Out-String));
                                                $controlResult.SetStateData("List of non-ALT accounts: ", $stateData);
                                                $controlResult.AdditionalInfo += "Count of non-ALT accounts with admin privileges: " + $nonSCCount;
                                            }
                                            else
                                            {
                                                $controlResult.AddMessage([VerificationResult]::Passed, "No users have admin privileges with non SC-ALT accounts.");
                                            }
                                            if ($SCCount -gt 0)
                                            {
                                                $SCMembers = $SCMembers | Select-Object name,mailAddress,groupName
                                                $SCData = @();
                                                $SCData += $SCMembers
                                                $controlResult.AddMessage("`nCount of ALT accounts with admin privileges: $SCCount");
                                                $controlResult.AdditionalInfo += "Count of ALT accounts with admin privileges: " + $SCCount;
                                                $controlResult.AddMessage("List of ALT accounts: ", $($SCData | Format-Table -AutoSize | Out-String));
                                            }
                                        }
                                        else {
                                            $controlResult.AddMessage([VerificationResult]::Manual, "Regular expressions for detecting SC-ALT account is not defined in the organization.");
                                        }
                                    }
                                    else{
                                        $controlResult.AddMessage([VerificationResult]::Error, "Regular expressions for detecting SC-ALT account is not defined in the organization. Please update your ControlSettings.json as per the latest AzSK.ADO PowerShell module.");
                                    }
                                }
                            }
                            else
                            { #count is 0 then there is no members added in the admin groups
                                $controlResult.AddMessage([VerificationResult]::Passed, "Admin groups does not have any members.");
                            }
                        }
                        else
                        {
                            $controlResult.AddMessage([VerificationResult]::Error, "Could not find the list of administrator groups in the project.");
                        }
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Error, "Could not find the list of groups in the project.");
                    }
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Manual, "List of administrator groups for detecting non SC-ALT accounts is not defined in your project.");
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Error, "List of administrator groups for detecting non SC-ALT accounts is not defined in your project. Please update your ControlSettings.json as per the latest AzSK.ADO PowerShell module.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of groups in the project.");
            $controlResult.LogException($_)
        }

        return $controlResult
    }

    hidden [ControlResult] CheckAllPipelinesAccessOnFeeds([ControlResult] $controlResult)
    {

        <#
            {
            "ControlID": "ADO_Project_AuthZ_Restrict_Feed_Permissions",
            "Description": "Do not allow a broad group of users to upload packages to feed.",
            "Id": "Project230",
            "ControlSeverity": "High",
            "Automated": "Yes",
            "MethodName": "CheckAllPipelinesAccessOnFeeds",
            "Rationale": "If a broad group of users (e.g., Contributors) have permissions to upload package to feed, then integrity of your pipeline can be compromised by a malicious user who uploads a package.",
            "Recommendation": "1. Go to Project --> 2. Artifacts --> 3. Select Feed --> 4. Feed Settings --> 5. Permissions --> 6. Groups --> 7. Review users/groups which have administrator and contributor roles.",
            "Tags": [
                "SDL",
                "TCP",
                "AuthZ",
                "RBAC",
                "MSW"
            ],
            "Enabled": true
            }
        #>
        try
        {
            $controlResult.VerificationResult = [VerificationResult]::Failed
            $url = 'https://feeds.dev.azure.com/{0}/{1}/_apis/packaging/feeds?api-version=6.0-preview.1' -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceName;
            $feedsObj = @([WebRequestHelper]::InvokeGetWebRequest($url));

            $FeedsWithBroadAccess = @();
            $GroupsToCheckForFeedPermission = $null;
            $TotalFeedsCount = $feedsObj.Count

            if ( $TotalFeedsCount -gt 0 -and [Helpers]::CheckMember($feedsObj[0],"Id"))
            {
                $controlResult.AddMessage("Total number of feeds found: $($TotalFeedsCount)")
                $controlResult.AdditionalInfo += "Total number of feeds found: " + $TotalFeedsCount;

                if ($this.ControlSettings -and [Helpers]::CheckMember($this.ControlSettings, "Project.GroupsToCheckForFeedPermission") ) {
                    $GroupsToCheckForFeedPermission = @($this.ControlSettings.Project.GroupsToCheckForFeedPermission)
                }

                if($null -ne $GroupsToCheckForFeedPermission -and $GroupsToCheckForFeedPermission.Count -gt 0)
                {
                    foreach ($feed in $feedsObj)
                    {
                        #GET https://feeds.dev.azure.com/{organization}/{project}/_apis/packaging/Feeds/{feedId}/permissions?api-version=6.0-preview.1
                        #Using visualstudio api because new api (dev.azure.com) is giving null in the displayName property.
                        $url = 'https://{0}.feeds.visualstudio.com/{1}/_apis/Packaging/Feeds/{2}/Permissions?includeIds=true&excludeInheritedPermissions=false&includeDeletedFeeds=false' -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceName, $feed.Id;
                        $feedPermissionObj = @([WebRequestHelper]::InvokeGetWebRequest($url));

                        $feedsPermission = ($feedPermissionObj | Where-Object {$_.role -eq "administrator" -or $_.role -eq "contributor" -or $_.role -eq "collaborator"}) | Select-Object -Property @{Name="FeedName"; Expression = {$feed.name}},@{Name="Role"; Expression = {$_.role}},@{Name="DisplayName"; Expression = {$_.displayName}} ;
                        $FeedsWithBroadAccess += $feedsPermission | Where-Object { $GroupsToCheckForFeedPermission -contains $_.DisplayName.split('\')[-1] }
                    }

                    $FeedsAtRisk = $FeedsWithBroadAccess.count;
                    if ($FeedsAtRisk -gt 0)
                    {
                        $controlResult.AddMessage([VerificationResult]::Failed, "List of feeds: ");
                        $controlResult.AddMessage("`nNote: `nThe following groups are considered as broad groups:");
                        $controlResult.AddMessage(($GroupsToCheckForFeedPermission | FT | Out-String))
                        $controlResult.AddMessage("`nCount of feeds with contributor/administrator/collaborator permission: $FeedsAtRisk");
                        $controlResult.AdditionalInfo += "Count of feeds with contributor/administrator/collaborator permission: " + $FeedsAtRisk;

                        $display = ($FeedsWithBroadAccess |  FT FeedName, Role, DisplayName -AutoSize | Out-String -Width 512)
                        $controlResult.AddMessage($display)
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed,  "No feeds in the project are exposed to uploads from broad group of users.");
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Error, "List of groups for checking feed permission is not defined in control settings for your organization.");
                }
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed,  "No feeds found in the project.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not fetch project feed settings.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckEnviornmentAccess([ControlResult] $controlResult)
    {
        try
        {
            $apiURL = "https://dev.azure.com/{0}/{1}/_apis/distributedtask/environments?api-version=6.0-preview.1" -f $($this.OrganizationContext.OrganizationName), $($this.ResourceContext.ResourceName);
            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);

            # TODO: When there are no environments configured, CheckMember in the below condition returns false when checknull flag [third param in CheckMember] is not specified (default value is $true). Assiging it $false. Need to revisit.
            if(([Helpers]::CheckMember($responseObj[0],"count",$false)) -and ($responseObj[0].count -eq 0))
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "No environment has been configured in the project.");
            }
            # When environments are configured - the below condition will be true.
            elseif((-not ([Helpers]::CheckMember($responseObj[0],"count"))) -and ($responseObj.Count -gt 0))
            {
                $environmentsWithOpenAccess = @();
                foreach ($item in $responseObj)
                {
                    $url = "https://dev.azure.com/{0}/{1}/_apis/pipelines/pipelinePermissions/environment/{2}" -f $($this.OrganizationContext.OrganizationName), $($this.ResourceContext.ResourceDetails.id), $($item.id);
                    $apiResponse = [WebRequestHelper]::InvokeGetWebRequest($url);
                    if (([Helpers]::CheckMember($apiResponse,"allPipelines")) -and ($apiResponse.allPipelines.authorized -eq $true))
                    {
                        $environmentsWithOpenAccess += $item | Select-Object id, name;
                    }
                }
                $environmentsWithOpenAccessCount = ($environmentsWithOpenAccess | Measure-Object).Count;
                if($environmentsWithOpenAccessCount -gt 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Total number of environments in the project that are accessible to all pipelines: $($environmentsWithOpenAccessCount)");
                    $controlResult.AddMessage("List of environments in the project that are accessible to all pipelines: ", $environmentsWithOpenAccess);
                    $controlResult.AdditionalInfo += "Total number of environments in the project that are accessible to all pipelines: " + $environmentsWithOpenAccessCount;
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "There are no environments that are accessible to all pipelines.");
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "No environments found in the project.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of environments in the project.");
            $controlResult.LogException($_)
        }
       return $controlResult
    }

    hidden [ControlResult] CheckSecureFilesPermission([ControlResult] $controlResult) {
        # getting the project ID
        <#
            {
            "ControlID": "ADO_Project_AuthZ_Dont_Grant_All_Pipelines_Access_To_Secure_Files",
            "Description": "Do not make secure files accessible to all pipelines.",
            "Id": "Project250",
            "ControlSeverity": "High",
            "Automated": "Yes",
            "MethodName": "CheckSecureFilesPermission",
            "Rationale": "If a secure file is granted access to all pipelines, an unauthorized user can steal information from the secure files by building a pipeline and accessing the secure file.",
            "Recommendation": "1. Go to Project --> 2. Pipelines --> 3. Library --> 4. Secure Files --> 5. select your secure file from the list --> 6. click Security --> 7. Under 'Pipeline Permissions', remove pipelines that secure file no more requires access to or click 'Restrict Permission' to avoid granting access to all pipelines.",
            "Tags": [
                "SDL",
                "AuthZ",
                "Automated",
                "Best Practice",
                "MSW"
            ],
            "Enabled": true
            }
        #>
        $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
        $url = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($projectId)/_apis/distributedtask/securefiles?api-version=6.1-preview.1"
        try {
            $response = [WebRequestHelper]::InvokeGetWebRequest($url);
            # check on response object, if null -> no secure files present
            if(([Helpers]::CheckMember($response[0],"count",$false)) -and ($response[0].count -eq 0)) {
                $controlResult.AddMessage([VerificationResult]::Passed, "There are no secure files present.");
            }
            # else there are secure files present
            elseif((-not ([Helpers]::CheckMember($response[0],"count"))) -and ($response.Count -gt 0)) {
                # object to keep a track of authorized secure files and their count
                [Hashtable] $secFiles = @{
                    count = 0;
                    names = @();
                };
                foreach ($secFile in $response) {
                    $url = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($projectId)/_apis/build/authorizedresources?type=securefile&id=$($secFile.id)&api-version=6.0-preview.1"
                    $resp = [WebRequestHelper]::InvokeGetWebRequest($url);
                    # check if the secure file is authorized
                    if((-not ([Helpers]::CheckMember($resp[0],"count"))) -and ($resp.Count -gt 0)) {
                        if([Helpers]::CheckMember($resp, "authorized")) {
                            if($resp.authorized) {
                                $secFiles.count += 1;
                                $secFiles.names += $secFile.name;
                            }
                        }
                    }
                }
                # there are secure files present that are authorized
                if($secFiles.count -gt 0) {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Total number of secure files in the project that are authorized for use in all pipelines: $($secFiles.count)");
                    $controlResult.AddMessage("List of secure files in the project that are authorized for use in all pipelines: ", $secFiles.names);
                    $controlResult.AdditionalInfo += "Total number of secure files in the project that are authorized for use in all pipelines: " + $secFiles.count;
                }
                # there are no secure files present that are authorized
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "There are no secure files in the project that are authorized for use in all pipelines.");
                }
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of secure files.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckAuthorEmailValidationPolicy([ControlResult] $controlResult) {
        # body for post request
        $url = 'https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1' -f $($this.OrganizationContext.OrganizationName);
        $inputbody = '{"contributionIds":["ms.vss-code-web.repository-policies-data-provider"],"dataProviderContext":{"properties":{"projectId": "","sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"repositories","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json
        $inputbody.dataProviderContext.properties.projectId = "$($this.ResourceContext.ResourceDetails.id)"
        $inputbody.dataProviderContext.properties.sourcePage.routeValues.project = "$($this.ResourceContext.ResourceName)"
        $inputbody.dataProviderContext.properties.sourcePage.url = "https://$($this.OrganizationContext.OrganizationName).visualstudio.com/$($this.ResourceContext.ResourceName)/_settings/repositories?_a=policies"

        try {
            $response = [WebRequestHelper]::InvokePostWebRequest($url, $inputbody);
            if ([Helpers]::CheckMember($response, "dataProviders") -and $response.dataProviders.'ms.vss-code-web.repository-policies-data-provider' -and [Helpers]::CheckMember($response.dataProviders.'ms.vss-code-web.repository-policies-data-provider', "policyGroups")) {
                # fetching policy groups
                $policyGroups = $response.dataProviders."ms.vss-code-web.repository-policies-data-provider".policyGroups
                # fetching "Commit author email validation"
                $authorEmailPolicyId = $this.ControlSettings.Repo.AuthorEmailValidationPolicyID
                $commitAuthorEmailPattern = $this.ControlSettings.Repo.CommitAuthorEmailPattern
                if ([Helpers]::CheckMember($policyGroups, $authorEmailPolicyId)) {
                    $currentScopePoliciesEmail = $policyGroups."$($authorEmailPolicyId)".currentScopePolicies
                    $controlResult.AddMessage("`nNote: Commits from the following email ids are considered as 'trusted': `n`t[$($commitAuthorEmailPattern -join ', ')]");
                    # validating email patterns
                    $flag = 0;
                    $emailPatterns = $currentScopePoliciesEmail.settings.authorEmailPatterns
                    $invalidPattern = @()
                    if ($emailPatterns -eq $null) { $flag = 1; }
                    else {
                        foreach ($val in $emailPatterns) {
                            if ($val -notin $commitAuthorEmailPattern -and (-not [string]::IsNullOrEmpty($val))) {
                                $flag = 1;
                                $invalidPattern += $val
                            }
                        }
                    }
                    if ($flag -eq 0) {
                        $controlResult.AddMessage([VerificationResult]::Passed, "Commit author email validation is set as per the organizational requirements.");
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Verify, "Commit author email validation is not set as per the organizational requirements.");
                        if($invalidPattern.Count -gt 0) {
                            $controlResult.AddMessage("List of commit author email patterns that are not trusted: $($invalidPattern)")
                        }
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Failed, "'Commit author email validation' policy is disabled.");
                }
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch repository policies.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch repository policies $($_).");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckCredentialsAndSecretsPolicy([ControlResult] $controlResult) {
        # body for post request
        $url = 'https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1' -f $($this.OrganizationContext.OrganizationName);
        $inputbody = '{"contributionIds":["ms.vss-code-web.repository-policies-data-provider"],"dataProviderContext":{"properties":{"projectId": "","sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"repositories","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json
        $inputbody.dataProviderContext.properties.projectId = "$($this.ResourceContext.ResourceDetails.id)"
        $inputbody.dataProviderContext.properties.sourcePage.routeValues.project = "$($this.ResourceContext.ResourceName)"
        $inputbody.dataProviderContext.properties.sourcePage.url = "https://$($this.OrganizationContext.OrganizationName).visualstudio.com/$($this.ResourceContext.ResourceName)/_settings/repositories?_a=policies"

        try {
            $response = [WebRequestHelper]::InvokePostWebRequest($url, $inputbody);
            if ([Helpers]::CheckMember($response, "dataProviders") -and $response.dataProviders.'ms.vss-code-web.repository-policies-data-provider' -and [Helpers]::CheckMember($response.dataProviders.'ms.vss-code-web.repository-policies-data-provider', "policyGroups")) {
                # fetching policy groups
                $policyGroups = $response.dataProviders."ms.vss-code-web.repository-policies-data-provider".policyGroups
                # fetching "Secrets scanning restriction"
                $credScanId = $this.ControlSettings.Repo.CredScanPolicyID
                if ([Helpers]::CheckMember($policyGroups, $credScanId)) {
                    $currentScopePoliciesSecrets = $policyGroups."$($credScanId)".currentScopePolicies
                    if ($currentScopePoliciesSecrets.isEnabled) {
                        $controlResult.AddMessage([VerificationResult]::Passed, "Check for credentials and other secrets is enabled.");
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Failed, "Check for credentials and other secrets is disabled.");
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Check for credentials and other secrets is disabled.");
                }
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch repository policies.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch repository policies $($_).");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [PSObject] FetchRepositoriesList() {
        if($null -eq $this.Repos) {
            # fetch repositories
            $repoDefnURL = ("https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ResourceContext.ResourceName)/_apis/git/repositories?api-version=6.1-preview.1")
            try {
                $repoDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($repoDefnURL);
                $this.Repos = $repoDefnsObj;
            }
            catch {
                $this.Repos = $null
            }
        }
        return $this.Repos
    }

    hidden [ControlResult] CheckInactiveRepo([ControlResult] $controlResult) {
        <#
            {
            "ControlID": "ADO_Project_DP_Inactive_Repos",
            "Description": "Inactive repositories must be removed if no more required.",
            "Id": "Project280",
            "ControlSeverity": "Medium",
            "Automated": "Yes",
            "MethodName": "CheckInactiveRepo",
            "Rationale": "Each additional repository being accessed by pipelines increases the attack surface. To minimize this risk ensure that only active and legitimate repositories are present in project.",
            "Recommendation": "To remove inactive repository, follow the steps given here: 1. Navigate to the project settings -> 2. Repositories -> 3. Select the repository and delete.",
            "Tags": [
                "SDL",
                "TCP",
                "Automated",
                "DP"
            ],
            "Enabled": true
            }
        #>
        try {
            $repoDefnsObj = $this.FetchRepositoriesList()
            $inactiveRepos = @()
            $threshold = $this.ControlSettings.Repo.RepoHistoryPeriodInDays
            if (-not ($repoDefnsObj.Length -eq 1 -and [Helpers]::CheckMember($repoDefnsObj,"count") -and $repoDefnsObj[0].count -eq 0)) {
                $currentDate = Get-Date
                foreach ($repo in $repoDefnsObj) {
                    # check if repo is disabled or not
                    if($repo.isDisabled) {
                        $inactiveRepos += $repo.name
                    }
                    else {
                        # check if repo has commits in past RepoHistoryPeriodInDays days
                        $thresholdDate = $currentDate.AddDays(-$threshold);
                        $url = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ResourceContext.ResourceName)/_apis/git/repositories/$($repo.id)/commits?searchCriteria.fromDate=$($thresholdDate)&&api-version=6.0"
                        try{
                            $res = [WebRequestHelper]::InvokeGetWebRequest($url);
                            # When there are no commits, CheckMember in the below condition returns false when checknull flag [third param in CheckMember] is not specified (default value is $true). Assiging it $false.
                            if (([Helpers]::CheckMember($res[0], "count", $false)) -and ($res[0].count -eq 0)) {
                                $inactiveRepos += $repo.name
                            }
                        }
                        catch{
                            $controlResult.AddMessage("Could not fetch the history of repository [$($repo.name)].");
                            $controlResult.LogException($_)
                        }
                    }
                }
                $inactivecount = $inactiveRepos.Count
                if ($inactivecount -gt 0) {
                    $inactiveRepos = $inactiveRepos | sort-object
                    $controlResult.AddMessage([VerificationResult]::Failed, "Total number of inactive repositories that have no commits in last $($threshold) days: $($inactivecount) ", $inactiveRepos);
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "There are no inactive repositories in the project.");
                }
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of repositories in the project.", $_);
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckRepoRBACAccess([ControlResult] $controlResult) {
        <#
            {
            "ControlID": "ADO_Project_AuthZ_Repo_Grant_Min_RBAC_Access",
            "Description": "All teams/groups must be granted minimum required permissions on repositories.",
            "Id": "Project290",
            "ControlSeverity": "High",
            "Automated": "Yes",
            "MethodName": "CheckRepoRBACAccess",
            "Rationale": "Granting minimum access by leveraging RBAC feature ensures that users are granted just enough permissions to perform their tasks. This minimizes exposure of the resources in case of user/service account compromise.",
            "Recommendation": "Go to Project Settings --> Repositories --> Permissions --> Validate whether each user/group is granted minimum required access to repositories.",
            "Tags": [
                "SDL",
                "TCP",
                "Automated",
                "AuthZ",
                "RBAC"
            ],
            "Enabled": true
            }
        #>

        $accessList = @()
        #permissionSetId = '2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87' is the std. namespaceID. Refer: https://docs.microsoft.com/en-us/azure/devops/organizations/security/manage-tokens-namespaces?view=azure-devops#namespaces-and-their-ids
        try{

            $url = 'https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1' -f $($this.OrganizationContext.OrganizationName);
            $refererUrl = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ResourceContext.ResourceName)/_settings/repositories?_a=permissions";
            $inputbody = '{"contributionIds":["ms.vss-admin-web.security-view-members-data-provider"],"dataProviderContext":{"properties":{"permissionSetId": "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87","permissionSetToken":"","sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"repositories","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json
            $inputbody.dataProviderContext.properties.sourcePage.url = $refererUrl
            $inputbody.dataProviderContext.properties.sourcePage.routeValues.Project = $this.ResourceContext.ResourceName;
            $inputbody.dataProviderContext.properties.permissionSetToken = "repoV2/$($this.ResourceContext.ResourceDetails.id)"

            # Get list of all users and groups granted permissions on all repositories
            $responseObj = [WebRequestHelper]::InvokePostWebRequest($url, $inputbody);

            # Iterate through each user/group to fetch detailed permissions list
            if([Helpers]::CheckMember($responseObj[0],"dataProviders") -and ($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider') -and ([Helpers]::CheckMember($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider',"identities")))
            {
                $body = '{"contributionIds":["ms.vss-admin-web.security-view-permissions-data-provider"],"dataProviderContext":{"properties":{"subjectDescriptor":"","permissionSetId": "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87","permissionSetToken":"","accountName":"","sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"repositories","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json
                $body.dataProviderContext.properties.sourcePage.url = $refererUrl
                $body.dataProviderContext.properties.sourcePage.routeValues.Project = $this.ResourceContext.ResourceName;
                $body.dataProviderContext.properties.permissionSetToken = "repoV2/$($this.ResourceContext.ResourceDetails.id)"

                $accessList += $responseObj.dataProviders."ms.vss-admin-web.security-view-members-data-provider".identities | Where-Object { $_.subjectKind -eq "group" } | ForEach-Object {
                    $identity = $_
                    $body.dataProviderContext.properties.accountName = $_.principalName
                    $body.dataProviderContext.properties.subjectDescriptor = $_.descriptor

                    $identityPermissions = [WebRequestHelper]::InvokePostWebRequest($url, $body);
                    $configuredPermissions = $identityPermissions.dataproviders."ms.vss-admin-web.security-view-permissions-data-provider".subjectPermissions | Where-Object {$_.permissionDisplayString -ne 'Not set'}
                    return @{ IdentityName = $identity.DisplayName; IdentityType = $identity.subjectKind; Permissions = ($configuredPermissions | Select-Object @{Name="Name"; Expression = {$_.displayName}},@{Name="Permission"; Expression = {$_.permissionDisplayString}}) }
                }

                $accessList += $responseObj.dataProviders."ms.vss-admin-web.security-view-members-data-provider".identities | Where-Object { $_.subjectKind -eq "user" } | ForEach-Object {
                    $identity = $_
                    $body.dataProviderContext.properties.subjectDescriptor = $_.descriptor

                    $identityPermissions = [WebRequestHelper]::InvokePostWebRequest($url, $body);
                    $configuredPermissions = $identityPermissions.dataproviders."ms.vss-admin-web.security-view-permissions-data-provider".subjectPermissions | Where-Object {$_.permissionDisplayString -ne 'Not set'}
                    return @{ IdentityName = $identity.DisplayName; IdentityType = $identity.subjectKind; Permissions = ($configuredPermissions | Select-Object @{Name="Name"; Expression = {$_.displayName}},@{Name="Permission"; Expression = {$_.permissionDisplayString}}) }
                }
            }

            if(($accessList | Measure-Object).Count -ne 0)
            {
                $accessList= $accessList | Select-Object -Property @{Name="IdentityName"; Expression = {$_.IdentityName}},@{Name="IdentityType"; Expression = {$_.IdentityType}},@{Name="Permissions"; Expression = {$_.Permissions}}
                $controlResult.AddMessage([VerificationResult]::Verify,"Validate that the following identities have been provided with minimum RBAC access to repositories.", $accessList);
                $controlResult.SetStateData("List of identities having access to repositories: ", ($responseObj.dataProviders."ms.vss-admin-web.security-view-members-data-provider".identities | Select-Object -Property @{Name="IdentityName"; Expression = {$_.FriendlyDisplayName}},@{Name="IdentityType"; Expression = {$_.subjectKind}},@{Name="Scope"; Expression = {$_.Scope}}));
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed,"No identities have been explicitly provided access to repositories.");
            }
            $responseObj = $null;

        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Manual,"Unable to fetch repositories permission details. $($_) Please verify from portal all teams/groups are granted minimum required permissions.");
            $controlResult.LogException($_)
        }

        return $controlResult
    }

    hidden [ControlResult] CheckInheritedPermissions([ControlResult] $controlResult) {
        $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
        #permissionSetId = '2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87' is the std. namespaceID. Refer: https://docs.microsoft.com/en-us/azure/devops/organizations/security/manage-tokens-namespaces?view=azure-devops#namespaces-and-their-ids
        $repoNamespaceId = '2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87'
        try
        {
            $repoPermissionUrl = 'https://dev.azure.com/{0}/_apis/accesscontrollists/{1}?api-version=6.0' -f $this.OrganizationContext.OrganizationName, $repoNamespaceId;
            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($repoPermissionUrl)
            if ($null -ne $responseObj -and ($responseObj | Measure-Object).Count -gt 0)
            {
                $repoDefnsObj = $this.FetchRepositoriesList()
                $failedRepos = @()
                $passedRepos = @()
                foreach ($repo in $repoDefnsObj)
                {
                    $repoToken = "repoV2/$projectId/$($repo.id)"
                    $repoObj = $responseObj | where-object {$_.token -eq $repoToken}
                    if ($null -ne $repoObj -and ($repoObj | Measure-Object).Count -gt 0 -and $repoObj.inheritPermissions)
                    {
                        $failedRepos += $repo.name
                    }
                    else
                    {
                        $passedRepos += $repo.name
                    }
                }

                $failedReposCount = $failedRepos.Count
                $passedReposCount = $passedRepos.Count
                $passedRepos = $passedRepos | sort-object
                if($failedReposCount -gt 0)
                {
                    $failedRepos = $failedRepos | sort-object
                    $controlResult.AddMessage([VerificationResult]::Failed, "Inherited permissions are enabled on the repositories.");
                    $controlResult.AddMessage("Total number of repositories on which inherited permissions are enabled: $failedReposCount", $failedRepos);
                    $controlResult.AddMessage("Total number of repositories on which inherited permissions are disabled: $passedReposCount", $passedRepos);
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "Inherited permissions are disabled on all repositories.");
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the permission details for repositories in the project.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch list of repositories in the project. $($_).");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckInactiveProject([ControlResult] $controlResult) {

        # these variables are used to make table which will show inactivity status for resource types.
        $Reporow = @()
        $Buildrow = @()
        $Releaserow = @()
        $AgentPoolrow = @()
        $ServiceConnectionrow = @()

        ## Checking Inactive Repos
        $IsRepoActive = $false
        $inactiveRepocount = 0
        try {
            $repoDefnsObj = $this.FetchRepositoriesList()

            if(($repoDefnsObj | Measure-Object).count -gt 0 -and -not ([Helpers]::CheckMember($repoDefnsObj,"count") -and $repoDefnsObj[0].count -eq 0) )
            {
                # filtering out the disabled
                $repoDefnsObj = $repoDefnsObj | Where-Object { $_.IsDisabled -ne $true }
                $inactiveRepos = @()
                $threshold = $this.ControlSettings.Repo.RepoHistoryPeriodInDays
                $currentDate = Get-Date
                $thresholdDate = $currentDate.AddDays(-$threshold);
                foreach ($repo in $repoDefnsObj) {
                        # check if repo has commits in past RepoHistoryPeriodInDays days
                        $url = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ResourceContext.ResourceName)/_apis/git/repositories/$($repo.id)/commits?searchCriteria.fromDate=$($thresholdDate)&&api-version=6.0"
                        try{
                            $res = [WebRequestHelper]::InvokeGetWebRequest($url);
                            # When there are no commits, CheckMember in the below condition returns false when checknull flag [third param in CheckMember] is not specified (default value is $true). Assiging it $false.
                            if (([Helpers]::CheckMember($res[0], "count", $false)) -and ($res[0].count -eq 0)) {
                                $inactiveRepos += $repo.name
                            }
                        }
                        catch{
                            $controlResult.AddMessage("Could not fetch the history of repository [$($repo.name)].");
                            $controlResult.LogException($_)
                        }
                    }
                $inactiveRepocount = $inactiveRepos.Count
                if ($inactiveRepocount -gt 0)
                {
                    if($inactiveRepocount -ne ($repoDefnsObj | Measure-Object).count)
                    {
                        $IsRepoActive = $true
                    }
                    $inactiveRepos = $inactiveRepos | sort-object
                    $Reporow = New-Object psobject -Property $([ordered] @{"Resource Type"="Repository";"IsActive"="$($IsRepoActive)"; "Additional Info" = "Total number of inactive repositories that have no commits in last $($threshold) days: $($inactiveRepocount) => {$($inactiveRepos -join ", ")} "})
                }
                else {
                        $IsRepoActive = $true
                        $Reporow = New-Object psobject -Property $([ordered] @{"Resource Type"="Repository";"IsActive"="$($IsRepoActive)"; "Additional Info" = "There are no inactive repositories in the project."})
                }
            }
            else {
                $Reporow = New-Object psobject -Property $([ordered] @{"Resource Type"="Repository";"IsActive"="$($IsRepoActive)"; "Additional Info" = "All repositories are disabled in the project."})
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch the list of repositories in the project.");
            $controlResult.LogException($_)
        }

        ## Checking Inactive build
        $IsBuildActive = $false
        $threshold = $this.ControlSettings.Build.BuildHistoryPeriodInDays
        $currentDate = Get-Date
        $thresholdDate = $currentDate.AddDays(-$threshold);
        $url = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ResourceContext.ResourceName)/_apis/build/builds?minTime=$($thresholdDate)&api-version=6.0"
        try{
            $res = [WebRequestHelper]::InvokeGetWebRequest($url);
            if(-not ([Helpers]::CheckMember($res,"count") -and $res[0].count -eq 0 -and $res.Length -eq 1 ))
            {
                $res = $res | Sort-Object -Property queueTime -Descending  # most recent/latest build first
                if($res[0].queueTime -gt $thresholdDate)
                {
                    ## active build
                    $IsBuildActive = $true
                    $Buildrow = New-Object psobject -Property $([ordered] @{"Resource Type"="Build definition";"IsActive"="$($IsBuildActive)"; "Additional Info" = "Builds are queued in the project. Most recent build is [$($res[0].definition.name)] which was last queued on [$($res[0].queueTime)]"})
                }
                else {
                    $Buildrow = New-Object psobject -Property $([ordered] @{"Resource Type"="Build definition";"IsActive"="$($IsBuildActive)"; "Additional Info" = "Builds are not queued in the project."})
                }
            }
            else {
                $Buildrow = New-Object psobject -Property $([ordered] @{"Resource Type"="Build definition";"IsActive"="$($IsBuildActive)"; "Additional Info" = "No builds are created/queued since [$($thresholdDate)]"})
            }
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch build details after timpestamp: [$($thresholdDate)].");
            $controlResult.LogException($_)
        }


        ## Checking Inactive Release
        $IsReleaseActive = $false
        $threshold = $this.ControlSettings.Release.ReleaseHistoryPeriodInDays
        $currentDate = Get-Date
        $thresholdDate = $currentDate.AddDays(-$threshold);

        # Below API will arrange all deployments in project in descending order (latest first) and give first object of that sorted array
        $url = "https://vsrm.dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ResourceContext.ResourceName)/_apis/release/deployments?queryOrder=descending&`$top=1"
        try{
            $res = [WebRequestHelper]::InvokeGetWebRequest($url);
            if(-not ([Helpers]::CheckMember($res,"count") -and $res[0].count -eq 0 -and $res.Length -eq 1))
            {
                # $res[0] will contain latest release deployment
                if($res[0].queuedOn -gt $thresholdDate)
                {
                    ## active Release
                    $IsReleaseActive = $true
                    $Releaserow = New-Object psobject -Property $([ordered] @{"Resource Type"="Release definition";"IsActive"="$($IsReleaseActive)"; "Additional Info" = "Releases are queued in the project.Most recent release is [$($res[0].release.name)] of release definition [$($res[0].releasedefinition.name)] which was last queued on [$($res[0].queuedOn)]"})
                }
                else {
                    $Releaserow = New-Object psobject -Property $([ordered] @{"Resource Type"="Release definition";"IsActive"="$($IsReleaseActive)"; "Additional Info" = "Releases are not queued in the project."})
                }
            }
                else {
                    $Releaserow = New-Object psobject -Property $([ordered] @{"Resource Type"="Release definition";"IsActive"="$($IsReleaseActive)"; "Additional Info" = "No Releases are created/queued since [$($thresholdDate)]"})
                }
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch Release details after timpestamp: [$($thresholdDate)].");
            $controlResult.LogException($_)
        }

         ## Checking AgentPools
         $IsAgentPoolActive = $false
         $thresholdLimit = $this.ControlSettings.AgentPool.AgentPoolHistoryPeriodInDays

         # Fetch All Agent Pools
         $url = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ResourceContext.ResourceName)/_apis/distributedtask/queues?api-version=6.0-preview.1"
         try{
             $res = [WebRequestHelper]::InvokeGetWebRequest($url);
             $taskAgentQueues = @()
             if(($res | Measure-Object).Count -ne 0)
             {
                 # Filter out legacy agent pools (Hosted, Hosted VS 2017 etc.) as they are not visible to user on the portal.
                $taskAgentQueues = $res | where-object{ ($_.pool.isLegacy -eq $false)};
                if(($taskAgentQueues | Measure-Object).Count -ne 0)
                {
                    foreach ($AgentPool in $taskAgentQueues)
                    {
                        $url = "https://dev.azure.com/{0}/{1}/_settings/agentqueues?queueId={2}&__rt=fps&__ver=2" -f $($this.OrganizationContext.OrganizationName), $($this.ResourceContext.ResourceDetails.id) ,$AgentPool.id;
                        $res = [WebRequestHelper]::InvokeGetWebRequest($url);
                        if (([Helpers]::CheckMember($res[0], "fps.dataProviders.data") ) -and ($res[0].fps.dataProviders.data."ms.vss-build-web.agent-jobs-data-provider"))
                        {
                            #Filtering agent pool jobs specific to the current project.
                            $agentPoolJobs = $res[0].fps.dataProviders.data."ms.vss-build-web.agent-jobs-data-provider".jobs | Where-Object {$_.scopeId -eq $this.ResourceContext.ResourceDetails.id};
                            #Arranging in descending order of run time.
                            $agentPoolJobs = $agentPoolJobs | Sort-Object queueTime -Descending
                            #If agent pool has been queued at least once
                            if (($agentPoolJobs | Measure-Object).Count -gt 0)
                            {
                                #Get the last queue timestamp of the agent pool
                                if ([Helpers]::CheckMember($agentPoolJobs[0], "finishTime"))
                                {
                                    $agtPoolLastRunDate = $agentPoolJobs[0].finishTime;

                                    if ((((Get-Date) - $agtPoolLastRunDate).Days) -gt $thresholdLimit)
                                    {
                                        ## Inactive pool
                                        continue
                                    }
                                    else
                                    {
                                        ## Active pool
                                        $IsAgentPoolActive = $true
                                        $AgentPoolrow = New-Object psobject -Property $([ordered] @{"Resource Type"="AgentPool";"IsActive"="$($IsAgentPoolActive)"; "Additional Info" = "Agent pool has been queued in the last $thresholdLimit days."})
                                        break
                                    }
                                }
                                else
                                {
                                    ## Active pool
                                    $IsAgentPoolActive = $true
                                    $AgentPoolrow = New-Object psobject -Property $([ordered] @{"Resource Type"="AgentPool";"IsActive"="$($IsAgentPoolActive)"; "Additional Info" = "Agent pool was being queued during control evaluation."})
                                    break
                                }
                            }
                            else
                            {
                                continue
                            }
                        }
                        else
                        {
                            $controlResult.AddMessage("Could not fetch agent pool details.");
                        }
                    }
                    if(-not $IsAgentPoolActive)
                    {
                        $AgentPoolrow = New-Object psobject -Property $([ordered] @{"Resource Type"="AgentPool";"IsActive"="$($IsAgentPoolActive)"; "Additional Info" = "Agent pool has not been queued in the last $thresholdLimit days."})
                    }
                }
                else {
                    $AgentPoolrow = New-Object psobject -Property $([ordered] @{"Resource Type"="AgentPool";"IsActive"="$($IsAgentPoolActive)"; "Additional Info" = "No Agent pools are there in project."})
                }
            }
            else {
                $controlResult.AddMessage("Could not fetch Agent pool details")
            }
         }
         catch{
             $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch Agent pool details");
             $controlResult.LogException($_)
         }

        # Checking Service Connections
        $IsServiceConnectionActive = $false
        $thresholdLimit = $this.ControlSettings.ServiceConnection.ServiceConnectionHistoryPeriodInDays

         $url = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ResourceContext.ResourceName)/_apis/serviceendpoint/endpoints?api-version=6.0-preview.4"

        try
        {
            $res = [WebRequestHelper]::InvokeGetWebRequest($url);

            if(-not ([Helpers]::CheckMember($res,"count") -and $res[0].count -eq 0 -and $res.Length -eq 1 ))
            {
                foreach ($endpoint in $res)
                {
                    $url ="https://dev.azure.com/{0}/{1}/_apis/serviceendpoint/{2}/executionhistory?api-version=6.0-preview.1" -f $($this.OrganizationContext.OrganizationName), $($this.ResourceContext.ResourceDetails.id) ,$endpoint.id;
                    $endpointUsage = [WebRequestHelper]::InvokeGetWebRequest($url);
                    if ([Helpers]::CheckMember($endpointUsage[0],"data") -and [Helpers]::CheckMember($endpointUsage[0].data,"finishTime"))
                    {
                        $SClastRunDate = $endpointUsage[0].data.finishTime

                        #format date
                        $formatLastRunTimeSpan = New-TimeSpan -Start (Get-Date $SClastRunDate)

                        if ($formatLastRunTimeSpan.Days -gt $thresholdLimit)
                            {
                                # Inactive
                                continue
                            }
                            else
                            {
                                $IsServiceConnectionActive = $true
                                $ServiceConnectionrow = New-Object psobject -Property $([ordered] @{"Resource Type"="ServiceConnection";"IsActive"="$($IsServiceConnectionActive)"; "Additional Info" = "Service connection has been used in the last $thresholdLimit days."})
                                break
                            }
                    }
                }
                if(-not $IsServiceConnectionActive)
                {
                    $ServiceConnectionrow = New-Object psobject -Property $([ordered] @{"Resource Type"="ServiceConnection";"IsActive"="$($IsServiceConnectionActive)"; "Additional Info" = "Service connection has never been used."})
                }
            }
            else {
                $ServiceConnectionrow = New-Object psobject -Property $([ordered] @{"Resource Type"="ServiceConnection";"IsActive"="$($IsServiceConnectionActive)"; "Additional Info" = "No Service Connections are present in project."})
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch Service connection details");
            $controlResult.LogException($_)
        }

        if( $controlResult.VerificationResult -ne [VerificationResult]::Error)
        {
            $controlResult.AddMessage("Below mentioned resource types are considered for checking inactivity of a project:")
            $table = @($Reporow;$Buildrow;$Releaserow;$AgentPoolrow;$ServiceConnectionrow) | Format-Table -AutoSize | Out-String -Width 512
            $controlResult.AddMessage($table)

            $IsProjectActive  = $IsRepoActive -or $IsBuildActive -or $IsReleaseActive -or $IsAgentPoolActive -or $IsServiceConnectionActive
            if($IsProjectActive)
            {
                if(($inactiveRepocount -gt 0) -and  (($IsRepoActive -eq $true) -and ($IsBuildActive -eq $true) -and  ($IsReleaseActive -eq $true) -and ($IsAgentPoolActive -eq $true) -and ($IsServiceConnectionActive -eq $true)))
                {
                    $controlResult.AddMessage([VerificationResult]::Verify,"One or more repositories are inactive.")
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed,"Project is active. See above table.")
                }
            }
            else {
            $controlResult.AddMessage([VerificationResult]::Failed,"Project is inactive. See above table.")
            }
        }


        return $controlResult

    }

    hidden [void] FetchGuestMembersInOrg()
    {
        try {
            $apiURL = "https://vsaex.dev.azure.com/{0}/_apis/UserEntitlements?%24filter=userType%20eq%20%27guest%27&%24orderBy=name%20Ascending&api-version=6.1-preview.3" -f $($this.OrganizationContext.OrganizationName)
            $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($apiURL));

            $guestAccounts =  @()
            if(($null -ne $responseObj) -and $responseObj.Count -gt 0 -and ([Helpers]::CheckMember($responseObj[0], 'members')))
            {
                $guestAccounts = @($responseObj[0].members)
                $continuationToken =  $responseObj[0].continuationToken # Use the continuationToken for pagination

                while ($null -ne $continuationToken){
                    $urlEncodedToken = [System.Web.HttpUtility]::UrlEncode($continuationToken)
                    $apiURL = "https://vsaex.dev.azure.com/{0}/_apis/UserEntitlements?continuationToken=$urlEncodedToken&%24filter=userType%20eq%20%27guest%27&%24orderBy=name%20Ascending&api-version=6.1-preview.3" -f $($this.OrganizationContext.OrganizationName);
                    try{
                          $response = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
                          $guestAccounts += $response[0].members
                          $continuationToken =  $response[0].continuationToken
                        }
                    catch
                        {
                            # Eating the exception here as we could not fetch the further guest users
                            $continuationToken = $null
                            throw
                        }
                }
                $this.GuestMembers = @($guestAccounts)
            }
        }
        catch {
           throw
        }
    }

    hidden [void] FetchAllUsersInOrg()
    {
        try {
            $apiURL = "https://vsaex.dev.azure.com/{0}/_apis/UserEntitlements?filter=&sortOption=lastAccessDate+ascending&api-version=6.1-preview.3" -f $($this.OrganizationContext.OrganizationName)
            $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($apiURL));

            $AllUsersAccounts =  @()
            if(($null -ne $responseObj) -and $responseObj.Count -gt 0 -and ([Helpers]::CheckMember($responseObj[0], 'members')))
            {
                $AllUsersAccounts = @($responseObj[0].members)
                $continuationToken =  $responseObj[0].continuationToken # Use the continuationToken for pagination

                while ($null -ne $continuationToken){
                    $urlEncodedToken = [System.Web.HttpUtility]::UrlEncode($continuationToken)
                    $apiURL = "https://vsaex.dev.azure.com/{0}/_apis/UserEntitlements?continuationToken=$urlEncodedToken&filter=&sortOption=lastAccessDate+ascending&api-version=6.1-preview.3" -f $($this.OrganizationContext.OrganizationName);
                    try{
                          $response = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
                          $AllUsersAccounts += $response[0].members
                          $continuationToken =  $response[0].continuationToken
                        }
                    catch
                        {
                            # Eating the exception here as we could not fetch the further guest users
                            $continuationToken = $null
                            throw
                        }
                    }
                    $this.AllUsersInOrg = @($AllUsersAccounts)
                }
            }
        catch {
            throw
        }

    }

    hidden [ControlResult] CheckGuestUsersAccessInAdminRoles([ControlResult] $controlResult)
    {
        if($this.ControlSettings -and [Helpers]::CheckMember($this.ControlSettings,"Project.AdminGroupsToCheckForGuestUser"))
        {
            try {
                $controlResult.VerificationResult = [VerificationResult]::Failed
                $AdminGroupsToCheckForGuestUser = @($this.ControlSettings.Project.AdminGroupsToCheckForGuestUser)
                if($this.GuestMembers.Count -eq 0)
                {
                    $this.FetchGuestMembersInOrg()
                }

                $guestAccounts = @($this.GuestMembers)
                if($guestAccounts.Count -gt 0)
                {
                    $formattedData = @()
                    $guestAccounts | ForEach-Object {
                        if([Helpers]::CheckMember($_,"user.descriptor"))
                        {
                           try
                            {
                                $url = "https://vssps.dev.azure.com/$($this.OrganizationContext.OrganizationName)/_apis/Graph/Memberships/$($_.user.descriptor)?api-version=6.0-preview.1"
                                $response = @([WebRequestHelper]::InvokeGetWebRequest($url));
                                if([Helpers]::CheckMember($response[0],"containerDescriptor"))
                                {
                                    foreach ($obj in $response)
                                    {
                                        $url = "https://vssps.dev.azure.com/$($this.OrganizationContext.OrganizationName)/_apis/graph/groups/$($obj.containerDescriptor)?api-version=6.0-preview.1";
                                        $res = @([WebRequestHelper]::InvokeGetWebRequest($url));
                                        $data = $res.principalName.Split("\");
                                        $scope =  $data[0] -replace '[\[\]]'
                                        $group = $data[1]
                                        if($scope -eq $this.ResourceContext.ResourceName -and ($group -in $AdminGroupsToCheckForGuestUser) )
                                        {
                                            $formattedData += @{
                                                Group = $data[1];
                                                Scope = $data[0];
                                                Name = $_.user.displayName;
                                                PrincipalName = $_.user.principalName;
                                            }
                                        }
                                    }
                                }
                            }
                            catch
                            {
                                $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch the membership details for the user")
                            }
                        }
                        else {
                            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch descriptor for guest user");
                        }
                    }
                    if($formattedData.Count -gt 0)
                    {
                        $formattedData = $formattedData | select-object @{Name="Display Name"; Expression={$_.Name}}, @{Name="User or scope"; Expression={$_.Scope}} , @{Name="Group"; Expression={$_.Group}}, @{Name="Principal Name"; Expression={$_.PrincipalName}}
                        $groups = $formattedData | Group-Object "Principal Name"
                        $results = @()
                        $results += foreach( $grpObj in $groups ){
                                      $PrincipalName = $grpObj.name
                                      $OrgGroup = $grpObj.group.group -join ','
                                      $DisplayName = $grpObj.group."Display Name" | select -Unique
                                      $Scope = $grpObj.group."User or scope" | select -Unique
                                      [PSCustomObject]@{ PrincipalName = $PrincipalName ; DisplayName = $DisplayName ; Group = $OrgGroup ; Scope = $Scope }
                                    }

                        $controlResult.AddMessage([VerificationResult]::Failed,"Count of guest users in admin roles: $($results.count) ");
                        $controlResult.AddMessage("`nGuest users list :")
                        $display = ($results | FT PrincipalName, DisplayName, Group  -AutoSize | Out-String -Width 512)
                        $controlResult.AddMessage($display)
                        $controlResult.SetStateData("Guest users list : ", $results);
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Passed, "No guest users have admin roles in the project.");
                    }

                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No Guest User found.");
                }
                $controlResult.AddMessage("`nNote:`nThe following groups are considered for administrator privileges: `n$($AdminGroupsToCheckForGuestUser | FT | out-string)`n");
            }
            catch
            {
                $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch user entitlements.");
                $controlResult.LogException($_)
            }
        }
        else{
            $controlResult.AddMessage([VerificationResult]::Error, "List of admin groups for detecting guest accounts is not defined in control setting of your organization.");
        }

        return $controlResult
    }

    hidden [ControlResult] CheckInactiveUsersInAdminRoles([ControlResult] $controlResult)
    {
        if($this.ControlSettings -and  [Helpers]::CheckMember($this.ControlSettings,"Project.AdminGroupsToCheckForInactiveUser"))
        {
            try
            {
                $controlResult.VerificationResult = [VerificationResult]::Failed
                $AdminGroupsToCheckForInactiveUser = @($this.ControlSettings.Project.AdminGroupsToCheckForInactiveUser)
       
                $inactiveUsersWithAdminAccess = @()
                $inactivityPeriodInDays = 90
                if([Helpers]::CheckMember($this.ControlSettings,"Project.AdminInactivityThresholdInDays"))
                {
                    $inactivityPeriodInDays = $this.ControlSettings.Organization.AdminInactivityThresholdInDays
                }
                $thresholdDate =  (Get-Date).AddDays(-$inactivityPeriodInDays)
                ## API Call to fetch project level groups
                $url = 'https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1' -f $($this.OrganizationContext.OrganizationName);
                $inputbody = '{"contributionIds":["ms.vss-admin-web.org-admin-groups-data-provider"],"dataProviderContext":{"properties":{"sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"permissions","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json
                $inputbody.dataProviderContext.properties.sourcePage.url = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ResourceContext.ResourceName)/_settings/permissions";
                $inputbody.dataProviderContext.properties.sourcePage.routeValues.Project = $this.ResourceContext.ResourceName;
    
                $response = [WebRequestHelper]::InvokePostWebRequest($url, $inputbody);

                if([Helpers]::CheckMember($response[0],"dataProviders") -and $response[0].dataProviders."ms.vss-admin-web.org-admin-groups-data-provider")
                {
                    $ReqdAdminGroups = @();
                    $ReqdAdminGroups += $response.dataProviders."ms.vss-admin-web.org-admin-groups-data-provider".identities | where { $_.displayName -in $AdminGroupsToCheckForInactiveUser }
                    
                    $allAdminMembers =@();

                    $ReqdAdminGroups | ForEach-Object{
                        $currentGroup = $_

                        # [AdministratorHelper]::AllPCAMembers is a static variable. Always needs to be initialized. At the end of each iteration, it will be populated with members of that particular admin group.
                        [AdministratorHelper]::AllPCAMembers = @();
                        # Helper function to fetch flattened out list of group members.
                        [AdministratorHelper]::FindPCAMembers($currentGroup.descriptor, $this.OrganizationContext.OrganizationName)

                        $groupMembers = @();

                        # Add the members of current group to this temp variable.
                        $groupMembers += [AdministratorHelper]::AllPCAMembers
                        # Create a custom object to append members of current group with the group name. Each of these custom object is added to the global variable $allAdminMembers for further analysis of SC-Alt detection.
                        if($groupMembers.count -gt 0)
                        {
                            $groupMembers | ForEach-Object {$allAdminMembers += @( [PSCustomObject] @{ name = $_.displayName; mailAddress = $_.mailAddress; groupName = $currentGroup.displayName ; descriptor = $_.descriptor } )} 
                        }
                    }
                
                    $AdminUsersMasterList = @()
                    $AdminUsersFailureCases = @()

                    if($allAdminMembers.count -gt 0)
                    {
                        $groups = $allAdminMembers | Group-Object "mailAddress"
                        $AdminUsersMasterList += foreach( $grpobj in $groups ){                                      
                                                  $PrincipalName = $grpobj.name
                                                  $OrgGroup = ($grpobj.group.groupName  | select -Unique)-join ','
                                                  $DisplayName = $grpobj.group.name | select -Unique
                                                  $date = ""
                                                  $descriptor = $grpobj.group.descriptor | select -Unique
                                                  [PSCustomObject]@{ PrincipalName = $PrincipalName ; DisplayName = $DisplayName ; Group = $OrgGroup ; LastAccessedDate = $date ; Descriptor = $descriptor}
                                                }
                                            
                        $inactiveUsersWithAdminAccess =@()                        

                        if($AdminUsersMasterList.count -gt 0)
                        {
                            $controlResult.AddMessage("`nFound $($AdminUsersMasterList.count) users in admin roles overall.")
                            $controlResult.AddMessage("`nLooking for admin users who have not been active for $($inactivityPeriodInDays) days.")
                            $currentObj = $null
                            $AdminUsersMasterList | ForEach-Object{
                                try 
                                {
                                    if([Helpers]::CheckMember($_,"PrincipalName"))
                                    {
                                        $currentObj = $_
                                        $url = "https://vsaex.dev.azure.com/{0}/_apis/UserEntitlements?%24filter=name%20eq%20%27{1}%27&%24orderBy=name%20Ascending&api-version=6.1-preview.3" -f $($this.OrganizationContext.OrganizationName), $_.PrincipalName;
                                        $response = @([WebRequestHelper]::InvokeGetWebRequest($url));
                                        if([Helpers]::CheckMember($response[0],"members.lastAccessedDate"))
                                        {
                                            $members = @($response[0].members)
                                            if($members.count -gt 1)
                                            {
                                                $members = $members | where-object {$_.user.descriptor -eq $currentObj.Descriptor }
                                            }
                                            $dateobj = [datetime]::Parse($members[0].lastAccessedDate)
                                            if($dateobj -lt $thresholdDate )
                                            {
                                                $formatLastRunTimeSpan = New-TimeSpan -Start $dateobj
                                                if(($formatLastRunTimeSpan).Days -gt 10000)
                                                {
                                                    $_.LastAccessedDate = "User was never active"
                                                }
                                                else {
                                                    $_.LastAccessedDate = $dateobj.ToString("MM-dd-yyyy")
                                                }
                                                $inactiveUsersWithAdminAccess += $_
                                            }                        
                                        }
                                    }
                                }
                                catch 
                                {
                                    $controlResult.LogException($_)
                                    $AdminUsersFailureCases += $currentObj
                                }
                            }
                        }                        
                    }
                    else {
                       $controlResult.AddMessage([VerificationResult]::Passed, "No user found with admin roles in the project.")
                    }                       
                    
                    if($null -eq (Compare-Object -ReferenceObject $AdminUsersMasterList -DifferenceObject $AdminUsersFailureCases))
                    {
                        $controlResult.AddMessage([VerificationResult]::Error, "Unable to fetch details of inactive users in admin role. Please run the scan with admin priveleges.")
                    }                    
                    elseif($inactiveUsersWithAdminAccess.count -gt 0)
                    {
                        $controlResult.AddMessage([VerificationResult]::Failed,"Count of inactive users in admin roles: $($inactiveUsersWithAdminAccess.count) ");
                        $controlResult.AddMessage("`nInactive user details:")
                        $display = ($inactiveUsersWithAdminAccess|FT PrincipalName,DisplayName,Group,LastAccessedDate  -AutoSize | Out-String -Width 512)
                        $controlResult.AddMessage($display)
                        $controlResult.SetStateData("List of inactive users: ", $inactiveUsersWithAdminAccess);
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Passed, "No users in project admin roles found to be inactive for $($inactivityPeriodInDays) days.");
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Error, "Could not find the list of groups in the project.")
                }
                $controlResult.AddMessage("`nNote:`nThe following groups are considered for administrator privileges: `n$($AdminGroupsToCheckForInactiveUser|FT|Out-String)");        
            }
            catch
            {
                $controlResult.AddMessage([VerificationResult]::Error, "Not able to fetch project level groups")
                $controlResult.LogException($_)
            }         
        }
        else{
            $controlResult.AddMessage([VerificationResult]::Error, "List of admin groups for detecting inactive accounts is not defined in control setting of your organization.");
        }        
        return $controlResult;
    }

    hidden [ControlResult] CheckBroaderGroupInheritanceSettingsForBuild([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            $orgName = $($this.OrganizationContext.OrganizationName)
            $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
            $projectName = $this.ResourceContext.ResourceName;
            $permissionSetToken = $projectId
            if ([Helpers]::CheckMember($this.ControlSettings.Build, "RestrictedBroaderGroupsForBuild") -and [Helpers]::CheckMember($this.ControlSettings.Build, "ExcessivePermissionsForBroadGroups")) {
                $broaderGroups = $this.ControlSettings.Build.RestrictedBroaderGroupsForBuild
                $excessivePermissions = $this.ControlSettings.Build.ExcessivePermissionsForBroadGroups
                $namespacesApiURL = "https://dev.azure.com/{0}/_apis/securitynamespaces?api-version=6.0" -f $($orgName)
                $securityNamespacesObj = [WebRequestHelper]::InvokeGetWebRequest($namespacesApiURL);
                $buildSecurityNamespaceId = ($securityNamespacesObj | Where-Object { ($_.Name -eq "Build") -and ($_.actions.name -contains "ViewBuilds")}).namespaceId
                $buildURL = "https://dev.azure.com/$orgName/$projectName/_build"
                $allowPermissionBits = @(1,3)
                $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery/project/{1}?api-version=5.0-preview.1" -f $orgName, $projectId
                $inputbody = "{
                'contributionIds': [
                    'ms.vss-admin-web.security-view-members-data-provider'
                ],
                'dataProviderContext': {
                    'properties': {
                        'permissionSetId': '$buildSecurityNamespaceId',
                        'permissionSetToken': '$permissionSetToken',
                        'sourcePage': {
                            'url': '$buildURL',
                            'routeId': 'ms.vss-build-web.pipeline-details-route',
                            'routeValues': {
                                'project': '$projectName',
                                'viewname': 'details',
                                'controller': 'ContributedPage',
                                'action': 'Execute'
                            }
                        }
                    }
                }
                }" | ConvertFrom-Json
                $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL, $inputbody);
                if ([Helpers]::CheckMember($responseObj[0], "dataProviders") -and ($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider') -and ([Helpers]::CheckMember($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider', "identities"))) {

                    $broaderGroupsList = @($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider'.identities | Where-Object { $_.subjectKind -eq 'group' -and $broaderGroups -contains $_.displayName })
                    # $broaderGroupsList would be empty if none of its permissions are set i.e. all perms are 'Not Set'.

                    if ($broaderGroupsList.Count) {
                        $groupsWithExcessivePermissionsList = @()
                        foreach ($broderGroup in $broaderGroupsList) {
                            $broaderGroupInputbody = "{
                                'contributionIds': [
                                    'ms.vss-admin-web.security-view-permissions-data-provider'
                                ],
                                'dataProviderContext': {
                                    'properties': {
                                        'subjectDescriptor': '$($broderGroup.descriptor)',
                                        'permissionSetId': '$buildSecurityNamespaceId',
                                        'permissionSetToken': '$permissionSetToken',
                                        'accountName': '$(($broderGroup.principalName).Replace('\','\\'))',
                                        'sourcePage': {
                                            'url': '$buildURL',
                                            'routeId': 'ms.vss-build-web.pipeline-details-route',
                                            'routeValues': {
                                                'project': '$projectName',
                                                'viewname': 'details',
                                                'controller': 'ContributedPage',
                                                'action': 'Execute'
                                            }
                                        }
                                    }
                                }
                            }" | ConvertFrom-Json

                            #Web request to fetch RBAC permissions of broader groups on build.
                            $broaderGroupResponseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL, $broaderGroupInputbody);
                            $broaderGroupRBACObj = $broaderGroupResponseObj[0].dataProviders.'ms.vss-admin-web.security-view-permissions-data-provider'.subjectPermissions
                            $excessivePermissionList = $broaderGroupRBACObj | Where-Object { $_.displayName -in $excessivePermissions }
                            $excessiveEditPermissions = @()
                            $excessivePermissionList | ForEach-Object {
                                #effectivePermissionValue equals to 1 implies edit build pipeline perms is set to 'Allow'. Its value is 3 if it is set to Allow (inherited). This param is not available if it is 'Not Set'.
                                if ([Helpers]::CheckMember($_, "effectivePermissionValue")) {
                                    if ($allowPermissionBits -contains $_.effectivePermissionValue) {
                                        $excessiveEditPermissions += $_
                                    }
                                }
                            }
                            if ($excessiveEditPermissions.Count -gt 0) {
                                $excessivePermissionsGroupObj = @{}
                                $excessivePermissionsGroupObj['Group'] = $broderGroup.principalName
                                $excessivePermissionsGroupObj['ExcessivePermissions'] = $($excessiveEditPermissions.displayName -join ', ')
                                $groupsWithExcessivePermissionsList += $excessivePermissionsGroupObj
                            }
                        }
                        if ($groupsWithExcessivePermissionsList.count -gt 0) {
                            #TODO: Do we need to put state object?
                            $controlResult.AddMessage([VerificationResult]::Failed, "Build pipelines are set to inherit excessive permissions for a broad group of users at project level.");
                            $formattedGroupsData = $groupsWithExcessivePermissionsList | Select @{l = 'Group'; e = { $_.Group} }, @{l = 'ExcessivePermissions'; e = { $_.ExcessivePermissions } }
                            $formattedBroaderGrpTable = ($formattedGroupsData | Out-String)
                            $controlResult.AddMessage("`nList of groups : `n$formattedBroaderGrpTable");
                            $controlResult.AdditionalInfo += "List of excessive permissions on which broader groups have access:  $($groupsWithExcessivePermissionsList.Group).";
                        }
                        else {
                            $controlResult.AddMessage([VerificationResult]::Passed, "Build pipelines are not allowed to inherit excessive permissions for a broad group of users at project level.");
                        }
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Passed, "Broader groups do not have access to the build pipelines at a project level.");
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch RBAC details of the build pipelines at a project level.");
                }
                $controlResult.AddMessage("`nNote:`nFollowing groups are considered 'broad groups':`n$($broaderGroups | FT | Out-String )`n");
                $controlResult.AddMessage("`nFollowing permissions are considered 'excessive':`n$($excessivePermissions | FT | Out-String  )`n");
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Error, "Broader groups or excessive permissions are not defined in control settings for your organization.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch RBAC details of the build pipelines at a project level.");
            $controlResult.LogException($_)
        }

        return $controlResult;
    }


  hidden [ControlResult] CheckBroaderGroupInheritanceSettingsForRelease([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            $orgName = $($this.OrganizationContext.OrganizationName)
            $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
            $projectName = $this.ResourceContext.ResourceName;
            $permissionSetToken = $projectId
            if ([Helpers]::CheckMember($this.ControlSettings.Release, "RestrictedBroaderGroupsForRelease") -and [Helpers]::CheckMember($this.ControlSettings.Release, "ExcessivePermissionsForBroadGroups")) {
                $broaderGroups = $this.ControlSettings.Release.RestrictedBroaderGroupsForRelease
                $excessivePermissions = $this.ControlSettings.Release.ExcessivePermissionsForBroadGroups
                $namespacesApiURL = "https://dev.azure.com/{0}/_apis/securitynamespaces?api-version=6.0" -f $($orgName)
                $securityNamespacesObj = [WebRequestHelper]::InvokeGetWebRequest($namespacesApiURL);
                $releaseSecurityNamespaceId = ($securityNamespacesObj | Where-Object { ($_.Name -eq "ReleaseManagement") -and ($_.actions.name -contains "ViewReleaseDefinition")}).namespaceId
                $releaseURL = "https://dev.azure.com/$orgName/$projectName/_release"
                $allowPermissionBits = @(1,3)
                $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery/project/{1}?api-version=5.0-preview.1" -f $orgName, $projectId
                $inputbody = "{
                'contributionIds': [
                    'ms.vss-admin-web.security-view-members-data-provider'
                ],
                'dataProviderContext': {
                    'properties': {
                        'permissionSetId': '$releaseSecurityNamespaceId',
                        'permissionSetToken': '$permissionSetToken',
                        'sourcePage': {
                            'url': '$releaseURL',
                            'routeId': 'ms.vss-releaseManagement-web.hub-explorer-3-default-route',
                            'routeValues': {
                                'project': '$projectName',
                                'viewname': 'details',
                                'controller': 'ContributedPage',
                                'action': 'Execute'
                            }
                        }
                    }
                }
                }" | ConvertFrom-Json
                # Todo - Add comments (Also for build, release controls)
                $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL, $inputbody);
                if ([Helpers]::CheckMember($responseObj[0], "dataProviders") -and ($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider') -and ([Helpers]::CheckMember($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider', "identities"))) {

                    $broaderGroupsList = @($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider'.identities | Where-Object { $_.subjectKind -eq 'group' -and $broaderGroups -contains $_.displayName })
                    # $broaderGroupsList would be empty if none of its permissions are set i.e. all perms are 'Not Set'.

                    if ($broaderGroupsList.Count) {
                        $groupsWithExcessivePermissionsList = @()
                        foreach ($broderGroup in $broaderGroupsList) {
                            $broaderGroupInputbody = "{
                                'contributionIds': [
                                    'ms.vss-admin-web.security-view-permissions-data-provider'
                                ],
                                'dataProviderContext': {
                                    'properties': {
                                        'subjectDescriptor': '$($broderGroup.descriptor)',
                                        'permissionSetId': '$releaseSecurityNamespaceId',
                                        'permissionSetToken': '$permissionSetToken',
                                        'accountName': '$(($broderGroup.principalName).Replace('\','\\'))',
                                        'sourcePage': {
                                            'url': '$releaseURL',
                                            'routeId': 'ms.vss-releaseManagement-web.hub-explorer-3-default-route',
                                            'routeValues': {
                                                'project': '$projectName',
                                                'viewname': 'details',
                                                'controller': 'ContributedPage',
                                                'action': 'Execute'
                                            }
                                        }
                                    }
                                }
                            }" | ConvertFrom-Json

                            #Web request to fetch RBAC permissions of broader groups on release.
                            $broaderGroupResponseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL, $broaderGroupInputbody);
                            $broaderGroupRBACObj = $broaderGroupResponseObj[0].dataProviders.'ms.vss-admin-web.security-view-permissions-data-provider'.subjectPermissions
                            $excessivePermissionList = $broaderGroupRBACObj | Where-Object { $_.displayName -in $excessivePermissions }
                            $excessiveEditPermissions = @()
                            $excessivePermissionList | ForEach-Object {
                                #effectivePermissionValue equals to 1 implies edit release pipeline perms is set to 'Allow'. Its value is 3 if it is set to Allow (inherited). This param is not available if it is 'Not Set'.
                                if ([Helpers]::CheckMember($_, "effectivePermissionValue")) {
                                    if ($allowPermissionBits -contains $_.effectivePermissionValue) {
                                        $excessiveEditPermissions += $_
                                    }
                                }
                            }
                            if ($excessiveEditPermissions.Count -gt 0) {
                                $excessivePermissionsGroupObj = @{}
                                $excessivePermissionsGroupObj['Group'] = $broderGroup.principalName
                                $excessivePermissionsGroupObj['ExcessivePermissions'] = $($excessiveEditPermissions.displayName -join ', ')
                                $groupsWithExcessivePermissionsList += $excessivePermissionsGroupObj
                            }
                        }
                        if ($groupsWithExcessivePermissionsList.count -gt 0) {
                            #TODO: Do we need to put state object?
                            $controlResult.AddMessage([VerificationResult]::Failed, "Release pipelines are set to inherit excessive permissions for a broad group of users at project level.");
                            $formattedGroupsData = $groupsWithExcessivePermissionsList | Select @{l = 'Group'; e = { $_.Group} }, @{l = 'ExcessivePermissions'; e = { $_.ExcessivePermissions } }
                            $formattedBroaderGrpTable = ($formattedGroupsData | Out-String)
                            $controlResult.AddMessage("`nList of groups : `n$formattedBroaderGrpTable");
                            $controlResult.AdditionalInfo += "List of excessive permissions on which broader groups have access:  $($groupsWithExcessivePermissionsList.Group).";
                        }
                        else {
                            $controlResult.AddMessage([VerificationResult]::Passed, "Broader Groups do not have excessive permissions on the release pipelines at a project level.");
                        }
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Passed, "Broader groups do not have access to the release pipelines at a project level.");
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch RBAC details of the pipelines at a project level.");
                }
                $controlResult.AddMessage("`nNote:`nFollowing groups are considered 'broad groups':`n$($broaderGroups | FT | Out-String)`n");
                $controlResult.AddMessage("`nFollowing permissions are considered 'excessive':`n$($excessivePermissions | FT | Out-String)`n");
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Error, "Broader groups or excessive permissions are not defined in control settings for your organization.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch RBAC details of the release pipelines at a project level.");
            $controlResult.LogException($_)
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckBroaderGroupInheritanceSettingsForSvcConn ([ControlResult] $controlResult) {
        $controlResult.VerificationResult = [VerificationResult]::Failed

        try {
            $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
            $apiURL = "https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.serviceendpointrole/roleassignments/resources/{1}" -f $($this.OrganizationContext.OrganizationName), $($projectId);
            $serviceEndPointIdentity = @([WebRequestHelper]::InvokeGetWebRequest($apiURL));
            $restrictedGroups = @();
            if ([Helpers]::CheckMember($this.ControlSettings, "ServiceConnection.RestrictedBroaderGroupsForSvcConn") ) {
                $restrictedBroaderGroupsForSvcConn = $this.ControlSettings.ServiceConnection.RestrictedBroaderGroupsForSvcConn;

                if (($serviceEndPointIdentity.Count -gt 0) -and [Helpers]::CheckMember($serviceEndPointIdentity, "identity")) {
                    # match all the identities added on service connection with defined restricted list
                    $roleAssignments = @();
                    $roleAssignments +=   ($serviceEndPointIdentity | Select-Object -Property @{Name="Name"; Expression = {$_.identity.displayName}},@{Name="Role"; Expression = {$_.role.displayName}});
                    #Checking where broader groups have user/admin permission for service connection
                    $restrictedGroups += @($roleAssignments | Where-Object { $restrictedBroaderGroupsForSvcConn -contains $_.Name.split('\')[-1] -and ($_.Role -eq "Administrator" -or $_.Role -eq "User") })

                    $restrictedGroupsCount = $restrictedGroups.Count

                    # fail the control if restricted group found on service connection
                    if ($restrictedGroupsCount -gt 0) {
                        $controlResult.AddMessage([VerificationResult]::Failed, "Service connections are set to inherit excessive permissions for a broad group of users at project level.");
                        $controlResult.AddMessage("Count of broader groups: $($restrictedGroupsCount)`n")
                        $formattedGroupsData = $restrictedGroups | Select @{l = 'Group'; e = { $_.Name} }, @{l = 'Role'; e = { $_.Role } }
                        $formattedGroupsTable = ($formattedGroupsData | FT -AutoSize | Out-String)
                        $controlResult.AddMessage("`nList of groups: ", $formattedGroupsTable)
                        $controlResult.SetStateData("List of groups: ", $formattedGroupsData)
                        $controlResult.AdditionalInfo += "Count of broader groups that have user/administrator access to service connection at a project level:  $($restrictedGroupsCount)";
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Passed, "No broader groups have user/administrator access to service connection at a project level.");
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No broader groups have user/administrator access to service connection at a project level.");
                }
                $controlResult.AddMessage("`nNote:`nThe following groups are considered 'broad' which should not have user/administrator privileges: `n$($restrictedBroaderGroupsForSvcConn | FT | out-string )`n");
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Error, "List of broader groups for service connection is not defined in control settings for your organization.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Unable to fetch service connections details. $($_)Please verify from portal that you are not granting global security groups access to service connections");
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckBroaderGroupInheritanceSettingsForAgentpool ([ControlResult] $controlResult) {
        try {
            $controlResult.VerificationResult = [VerificationResult]::Failed

            if ($this.ControlSettings -and [Helpers]::CheckMember($this.ControlSettings, "AgentPool.RestrictedBroaderGroupsForAgentPool")) {
                $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
                $apiURL = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/_apis/securityroles/scopes/distributedtask.agentqueuerole/roleassignments/resources/$($projectId)";
                $agentPoolPermObj = @([WebRequestHelper]::InvokeGetWebRequest($apiURL));
                $restrictedBroaderGroupsForAgentPool = $this.ControlSettings.AgentPool.RestrictedBroaderGroupsForAgentPool;

                if (($agentPoolPermObj.Count -gt 0) -and [Helpers]::CheckMember($agentPoolPermObj, "identity")) {
                    # match all the identities added on agentpool with defined restricted list
                    $roleAssignments = @($agentPoolPermObj | Select-Object -Property @{Name="Name"; Expression = {$_.identity.displayName}},@{Name="Role"; Expression = {$_.role.displayName}});
                    # Checking whether the broader groups have User/Admin permissions
                    $restrictedGroups = @($roleAssignments | Where-Object { $restrictedBroaderGroupsForAgentPool -contains $_.Name.split('\')[-1] -and ($_.Role -eq "Administrator" -or $_.Role -eq "User") })

                    $restrictedGroupsCount = $restrictedGroups.Count
                    # fail the control if restricted group found on agentpool
                    if ($restrictedGroupsCount -gt 0) {
                        $controlResult.AddMessage([VerificationResult]::Failed, "Agent pools are set to inherit excessive permissions for a broad group of users at project level.");
                        $controlResult.AddMessage([VerificationResult]::Failed, "Count of broader groups: $($restrictedGroupsCount)");
                        $formattedGroupsData = $restrictedGroups | Select @{l = 'Group'; e = { $_.Name} }, @{l = 'Role'; e = { $_.Role } }
                        $formattedGroupsTable = ($formattedGroupsData | Out-String)
                        $controlResult.AddMessage("`nList of groups: $formattedGroupsTable")
                        $controlResult.SetStateData("List of groups: ", $restrictedGroups)
                        $controlResult.AdditionalInfo += "Count of broader groups that have user/administrator access to agent pool at a project level: $($restrictedGroupsCount)";
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Passed, "No broader groups have user/administrator access to agent pool at a project level.");
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No groups have given access to agent pool at a project level.");
                }
                $controlResult.AddMessage("`nNote:`nThe following groups are considered 'broad' which should not have user/administrator privileges: `n$($restrictedBroaderGroupsForAgentPool | FT | out-string )`n");
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Error, "List of restricted broader groups for agent pool is not defined in control settings for your organization.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the agent pool permissions at a project level.");
            $controlResult.LogException($_)
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckBroaderGroupInheritanceSettingsForVarGrp ([ControlResult] $controlResult) {

        try {
            $controlResult.VerificationResult = [VerificationResult]::Failed
            $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]

            if ($this.ControlSettings -and [Helpers]::CheckMember($this.ControlSettings, "VariableGroup.RestrictedBroaderGroupsForVariableGroup") -and [Helpers]::CheckMember($this.ControlSettings, "VariableGroup.RestrictedRolesForBroaderGroupsInVariableGroup")) {
                $restrictedBroaderGroupsForVarGrp = $this.ControlSettings.VariableGroup.RestrictedBroaderGroupsForVariableGroup;
                $restrictedRolesForBroaderGroupsInvarGrp = $this.ControlSettings.VariableGroup.RestrictedRolesForBroaderGroupsInVariableGroup;

                #Fetch variable group RBAC
                $roleAssignments = @();

                $url = 'https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.library/roleassignments/resources/{1}%240' -f $($this.OrganizationContext.OrganizationName), $($projectId);
                $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($url));
                if($responseObj.Count -gt 0)
                {
                    $roleAssignments += ($responseObj  | Select-Object -Property @{Name="Name"; Expression = {$_.identity.displayName}}, @{Name="Role"; Expression = {$_.role.displayName}});
                }

                # Checking whether the broader groups have User/Admin permissions
                $restrictedGroups = @($roleAssignments | Where-Object { ($restrictedBroaderGroupsForVarGrp -contains $_.Name.split('\')[-1]) -and  ($restrictedRolesForBroaderGroupsInvarGrp -contains $_.Role) })
                $restrictedGroupsCount = $restrictedGroups.Count

                # fail the control if restricted group found on variable group
                if ($restrictedGroupsCount -gt 0) {
                    $controlResult.AddMessage([VerificationResult]::Failed, "`nCount of broader groups that have administrator access to variable group at a project level: $($restrictedGroupsCount)");
                    $formattedGroupsData = $restrictedGroups | Select @{l = 'Group'; e = { $_.Name} }, @{l = 'Role'; e = { $_.Role } }
                    $formattedGroupsTable = ($formattedGroupsData | FT -AutoSize | Out-String)
                    $controlResult.AddMessage("`nList of groups: `n$formattedGroupsTable")
                    $controlResult.SetStateData("List of groups: ", $restrictedGroups)
                    $controlResult.AdditionalInfo += "Count of broader groups that have administrator access to variable group at a project level: $($restrictedGroupsCount)";
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No broader groups have administrator access to variable group at a project level.");
                }
                $controlResult.AddMessage("Note:`nThe following groups are considered 'broad' and should not have administrator privileges: `n[$($restrictedBroaderGroupsForVarGrp | FT | out-string)");
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Error, "List of restricted broader groups and restricted roles for variable group is not defined in the control settings for your organization policy.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the variable group permissions at a project level.");
            $controlResult.LogException($_)
        }

        return $controlResult;
    }
}
