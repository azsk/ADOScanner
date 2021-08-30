Set-StrictMode -Version Latest
class CommonSVTControls: ADOSVTBase {

    hidden [PSObject] $Repos; # This is used for fetching repo details
    #hidden [PSObject] $ProjectId;
    hidden [string] $checkInheritedPermissionsSecureFile = $false
    hidden [string] $checkInheritedPermissionsEnvironment = $false
    hidden [object] $repoInheritePermissions = @{};
    hidden static [bool] $BroaderGroupMemberCountCheckEnabledFeed = $false;
    hidden static [bool] $BroaderGroupMemberCountCheckEnabledEnvironment = $false;
    hidden static [bool] $BroaderGroupMemberCountCheckEnabledSecureFile = $false;
    hidden static $AllowedMemberCountInBroaderGroupsFeed = $null;
    hidden static $AllowedMemberCountInBroaderGroupsEnvironment = $null;
    hidden static $AllowedMemberCountInBroaderGroupsSecureFile = $null;

    CommonSVTControls([string] $organizationName, [SVTResource] $svtResource): Base($organizationName, $svtResource) {

        if ([Helpers]::CheckMember($this.ControlSettings, "SecureFile.CheckForInheritedPermissions") -and $this.ControlSettings.SecureFile.CheckForInheritedPermissions) {
            $this.checkInheritedPermissionsSecureFile = $true
        }

        if ([Helpers]::CheckMember($this.ControlSettings, "Environment.CheckForInheritedPermissions") -and $this.ControlSettings.Environment.CheckForInheritedPermissions) {
            $this.checkInheritedPermissionsEnvironment = $true
        }

        if ($null -eq [CommonSVTControls]::AllowedMemberCountInBroaderGroupsFeed)
        {
            if ([Helpers]::CheckMember($this.ControlSettings, "Feed.CheckForBroadGroupMemberCount") -and [Helpers]::CheckMember($this.ControlSettings, "Feed.AllowedBroadGroupMemberCount")) {
                [CommonSVTControls]::BroaderGroupMemberCountCheckEnabledFeed = $this.ControlSettings.Feed.CheckForBroadGroupMemberCount
                [CommonSVTControls]::AllowedMemberCountInBroaderGroupsFeed = $this.ControlSettings.Feed.AllowedBroadGroupMemberCount
            }
        }

        if ($null -eq [CommonSVTControls]::AllowedMemberCountInBroaderGroupsEnvironment)
        {
            if ([Helpers]::CheckMember($this.ControlSettings, "Environment.CheckForBroadGroupMemberCount") -and [Helpers]::CheckMember($this.ControlSettings, "Environment.AllowedBroadGroupMemberCount")) {
                [CommonSVTControls]::BroaderGroupMemberCountCheckEnabledEnvironment = $this.ControlSettings.Environment.CheckForBroadGroupMemberCount
                [CommonSVTControls]::AllowedMemberCountInBroaderGroupsEnvironment = $this.ControlSettings.Environment.AllowedBroadGroupMemberCount
            }
        }

        if ($null -eq [CommonSVTControls]::AllowedMemberCountInBroaderGroupsSecureFile)
        {
            if ([Helpers]::CheckMember($this.ControlSettings, "SecureFile.CheckForBroadGroupMemberCount") -and [Helpers]::CheckMember($this.ControlSettings, "SecureFile.AllowedBroadGroupMemberCount")) {
                [CommonSVTControls]::BroaderGroupMemberCountCheckEnabledSecureFile = $this.ControlSettings.SecureFile.CheckForBroadGroupMemberCount
                [CommonSVTControls]::AllowedMemberCountInBroaderGroupsSecureFile = $this.ControlSettings.SecureFile.AllowedBroadGroupMemberCount
            }
        }
    }

    hidden [ControlResult] CheckInactiveRepo([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            $repoDefnsObj = $this.ResourceContext.ResourceDetails;
            $threshold = $this.ControlSettings.Repo.RepoHistoryPeriodInDays

            $currentDate = Get-Date
            # check if repo is disabled or not
            if ($repoDefnsObj.isDisabled) {
                $controlResult.AddMessage([VerificationResult]::Failed, "Repositories does not have any commits in last $($threshold) days. ");
            }
            else {
                # check if repo has commits in past RepoHistoryPeriodInDays days
                $thresholdDate = $currentDate.AddDays(-$threshold);
                $url = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ResourceContext.ResourceGroupName)/_apis/git/repositories/$($repoDefnsObj.id)/commits?searchCriteria.fromDate=$($thresholdDate)&&api-version=6.0"
                try {
                    $repoCommitHistoryObj = @();
                    $repoCommitHistoryObj += @([WebRequestHelper]::InvokeGetWebRequest($url))
                    # When there are no commits, CheckMember in the below condition returns false when checknull flag [third param in CheckMember] is not specified (default value is $true). Assiging it $false.
                    if (([Helpers]::CheckMember($repoCommitHistoryObj[0], "count", $false)) -and ($repoCommitHistoryObj[0].count -eq 0)) {
                        $controlResult.AddMessage([VerificationResult]::Failed, "Repositories does not have any commits in last $($threshold) days. ");
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Passed, "Repositories is in active state.");
                    }
                }
                catch {
                    $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the history of repository [$($repoDefnsObj.name)].");
                    $controlResult.LogException($_)
                }
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch details of repository.", $_);
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckRepositoryPipelinePermission([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
            $url = "https://dev.azure.com/{0}/{1}/_apis/pipelines/pipelinePermissions/repository/{2}.{3}" -f $this.OrganizationContext.OrganizationName, $projectId, $projectId, $this.ResourceContext.ResourceDetails.Id;
            $repoPipelinePermissionObj = @([WebRequestHelper]::InvokeGetWebRequest($url));

            if (([Helpers]::CheckMember($repoPipelinePermissionObj[0], "allPipelines")) -and ($repoPipelinePermissionObj[0].allPipelines.authorized -eq $true))
            {
                $controlResult.AddMessage([VerificationResult]::Failed, "Repository is accessible to all pipelines.");
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Repository is not accessible to all pipelines.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch repository pipeline permission.");
            $controlResult.LogException($_)
        }
       return $controlResult
    }

    hidden [ControlResult] CheckRepoRBACAccess([ControlResult] $controlResult) {

        #Control is dissabled mow
        <#
        {
      "ControlID": "ADO_Repository_AuthZ_Grant_Min_RBAC_Access",
      "Description": "All teams/groups must be granted minimum required permissions on repositories.",
      "Id": "Repository110",
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
    },
        #>
        $accessList = @()
        #permissionSetId = '2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87' is the std. namespaceID. Refer: https://docs.microsoft.com/en-us/azure/devops/organizations/security/manage-tokens-namespaces?view=azure-devops#namespaces-and-their-ids
        try{

            $url = 'https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1' -f $($this.OrganizationContext.OrganizationName);
            $refererUrl = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ResourceContext.ResourceGroupName)/_settings/repositories?_a=permissions";
            $inputbody = '{"contributionIds":["ms.vss-admin-web.security-view-members-data-provider"],"dataProviderContext":{"properties":{"permissionSetId": "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87","permissionSetToken":"","sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"repositories","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json
            $inputbody.dataProviderContext.properties.sourcePage.url = $refererUrl
            $inputbody.dataProviderContext.properties.sourcePage.routeValues.Project = $this.ResourceContext.ResourceGroupName;
            $inputbody.dataProviderContext.properties.permissionSetToken = "repoV2/$($this.ResourceContext.ResourceDetails.id)"

            # Get list of all users and groups granted permissions on all repositories
            $responseObj = [WebRequestHelper]::InvokePostWebRequest($url, $inputbody);

            # Iterate through each user/group to fetch detailed permissions list
            if([Helpers]::CheckMember($responseObj[0],"dataProviders") -and ($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider') -and ([Helpers]::CheckMember($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider',"identities")))
            {
                $body = '{"contributionIds":["ms.vss-admin-web.security-view-permissions-data-provider"],"dataProviderContext":{"properties":{"subjectDescriptor":"","permissionSetId": "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87","permissionSetToken":"","accountName":"","sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"repositories","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json
                $body.dataProviderContext.properties.sourcePage.url = $refererUrl
                $body.dataProviderContext.properties.sourcePage.routeValues.Project = $this.ResourceContext.ResourceGroupName;
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

    hidden [ControlResult] CheckInheritedPermissionsOnRepository([ControlResult] $controlResult) {

        $controlResult.VerificationResult = [VerificationResult]::Failed
        $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
        $projectName = $this.ResourceContext.ResourceGroupName;
        #permissionSetId = '2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87' is the std. namespaceID. Refer: https://docs.microsoft.com/en-us/azure/devops/organizations/security/manage-tokens-namespaces?view=azure-devops#namespaces-and-their-ids

        try
        {
            # Fetch the repo permissions only if not already fetch, for all the repositories in the organization
            if (!$this.repoInheritePermissions.ContainsKey($projectName)) {
                $repoPermissionUrl = 'https://dev.azure.com/{0}/_apis/accesscontrollists/2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87?api-version=6.0' -f $this.OrganizationContext.OrganizationName;
                $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($repoPermissionUrl));
                $respoPermissionResponseObj = $responseObj | where-object {($_.token -match "^repoV2/$projectId\/.{36}$") -and $_.inheritPermissions -eq $true}
                
                $this.repoInheritePermissions.Add($projectName, $respoPermissionResponseObj);
                #Clearing local variable
                $responseObj = $null;
                $respoPermissionResponseObj = $null;
            }
            
            if ($this.repoInheritePermissions.ContainsKey($projectName))
            {
                # Filter the inherited permissions specific to the given project
                $repoPermission = @($this.repoInheritePermissions."$projectName" | where-object { $_.token -eq "repoV2/$projectId/$($this.ResourceContext.ResourceDetails.Id)" });
                
                if($repoPermission.Count -gt 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Inherited permission is enabled on the repository.");
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "Inherited permission is disabled on the repository.");
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the permission details for repositories.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch permission details for repositories. $($_).");
            $controlResult.LogException($_)
        }
        return $controlResult
    }


    hidden [PSObject] FetchRepositoriesList() {
        if($null -eq $this.Repos) {
            # fetch repositories
            $repoDefnURL = ("https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ResourceContext.ResourceGroupName)/_apis/git/repositories?api-version=6.1-preview.1")
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

    hidden [ControlResult] CheckBroaderGroupAccessOnFeeds([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            if ([Helpers]::CheckMember($this.ControlSettings, "Feed.RestrictedBroaderGroupsForFeeds"))
            {
                $restrictedBroaderGroups = @{}
                $restrictedBroaderGroupsForFeeds = $this.ControlSettings.Feed.RestrictedBroaderGroupsForFeeds;
                $restrictedBroaderGroupsForFeeds.psobject.properties | foreach { $restrictedBroaderGroups[$_.Name] = $_.Value }

                #GET https://feeds.dev.azure.com/{organization}/{project}/_apis/packaging/Feeds/{feedId}/permissions?api-version=6.0-preview.1
                #Using visualstudio api because new api (dev.azure.com) is giving null in the displayName property.

                #orgFeedURL will be used to identify if feed is org scoped or project scoped
                $orgFeedURL = 'https://feeds.dev.azure.com/{0}/_apis/packaging/feeds*'  -f $this.OrganizationContext.OrganizationName
                $scope = "Project"
                if ($this.ResourceContext.ResourceDetails.url -match $orgFeedURL){
                    $url = 'https://{0}.feeds.visualstudio.com/_apis/Packaging/Feeds/{1}/Permissions?includeIds=true&excludeInheritedPermissions=false&includeDeletedFeeds=false' -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceDetails.Id;
                    $controlResult.AddMessage("`n***Organization scoped feed***")
                    $scope = "Organization"
                }
                else {
                    $url = 'https://{0}.feeds.visualstudio.com/{1}/_apis/Packaging/Feeds/{2}/Permissions?includeIds=true&excludeInheritedPermissions=false&includeDeletedFeeds=false' -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName, $this.ResourceContext.ResourceDetails.Id;
                    $controlResult.AddMessage("`n***Project scoped feed***")
                }
                $feedPermissionList = @([WebRequestHelper]::InvokeGetWebRequest($url));
                $excesiveFeedsPermissions = @($feedPermissionList | Where-Object { $restrictedBroaderGroups.keys -contains $_.displayName.split('\')[-1] -and ($_.role -in $restrictedBroaderGroups[$_.displayName.split('\')[-1]])})
                $feedWithBroaderGroup = @($excesiveFeedsPermissions | Select-Object -Property @{Name="FeedName"; Expression = {$this.ResourceContext.ResourceName}},@{Name="Role"; Expression = {$_.role}},@{Name="Name"; Expression = {$_.displayName}}) ;

                if ([CommonSVTControls]::BroaderGroupMemberCountCheckEnabledFeed -and $feedWithBroaderGroup.Count -gt 0)
                {
                    $broaderGroupsWithExcessiveMembers = @([ControlHelper]::FilterBroadGroupMembers($feedWithBroaderGroup, [CommonSVTControls]::AllowedMemberCountInBroaderGroupsFeed, $true))
                    $feedWithBroaderGroup = @($feedWithBroaderGroup | Where-Object {$broaderGroupsWithExcessiveMembers -contains $_.Name})
                }

                $feedWithBroaderGroupCount = $feedWithBroaderGroup.count;

                if ($feedWithBroaderGroupCount -gt 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Count of broader groups that have administrator/contributor/collaborator access to feed: $($feedWithBroaderGroupCount)")

                    $display = ($feedWithBroaderGroup |  FT Name, Role -AutoSize | Out-String -Width 512)
                    $controlResult.AddMessage("`nList of groups: ", $display)
                    $controlResult.SetStateData("List of groups: ", $feedWithBroaderGroup);
                    if ($this.ControlFixBackupRequired)
                    {
                        #Data object that will be required to fix the control
                        $excesiveFeedsPermissions | ForEach-Object{
                            $_ | Add-Member -MemberType NoteProperty -Name "Scope" -Value $scope
                        }
                        $controlResult.BackupControlState = $excesiveFeedsPermissions;
                    }
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,  "Feed is not granted with administrator/contributor/collaborator permission to broad groups.");
                }
                $displayObj = $restrictedBroaderGroups.Keys | Select-Object @{Name = "Broader Group"; Expression = {$_}}, @{Name = "Excessive Permissions"; Expression = {$restrictedBroaderGroups[$_] -join ', '}}
                $controlResult.AddMessage("`nNote: `nThe following groups are considered 'broader groups': `n$($displayObj | FT | out-string)");
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Error,  "List of broader groups for feeds is not defined in control settings for your organization.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not fetch feed permissions.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckBroaderGroupAccessOnFeedsAutomatedFix([ControlResult] $controlResult)
    {
        try{
            $RawDataObjForControlFix = @();
            $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject
            $scope = $RawDataObjForControlFix[0].Scope

            $body = "["

            if (-not $this.UndoFix)
            {
                foreach ($identity in $RawDataObjForControlFix) 
                {
                    $roleId = [int][FeedPermissions] "Reader"
                    if ($body.length -gt 1) {$body += ","}
                    $body += @"
                        {
                            "displayName": "$($($identity.displayName).Replace('\','\\'))",
                            "identityId": "$($identity.identityId)",
                            "role": $roleId,
                            "identityDescriptor": "$($($identity.identityDescriptor).Replace('\','\\'))",
                            "isInheritedRole": false
                        }
"@;
                }
                $RawDataObjForControlFix | Add-Member -NotePropertyName NewRole -NotePropertyValue "Reader"
                $RawDataObjForControlFix = @($RawDataObjForControlFix  | Select-Object @{Name="DisplayName"; Expression={$_.DisplayName}}, @{Name="OldRole"; Expression={$_.Role}},@{Name="NewRole"; Expression={$_.NewRole}})
            }
            else {
                foreach ($identity in $RawDataObjForControlFix) 
                {
                    $roleId = [int][FeedPermissions] "$($identity.role)"
                    if ($body.length -gt 1) {$body += ","}
                    $body += @"
                        {
                            "displayName": "$($($identity.displayName).Replace('\','\\'))",
                            "identityId": "$($identity.identityId)",
                            "role": $roleId,
                            "identityDescriptor": "$($($identity.identityDescriptor).Replace('\','\\'))",
                            "isInheritedRole": false
                        }
"@;
                }
                $RawDataObjForControlFix | Add-Member -NotePropertyName OldRole -NotePropertyValue "Reader"
                $RawDataObjForControlFix = @($RawDataObjForControlFix  | Select-Object @{Name="DisplayName"; Expression={$_.DisplayName}}, @{Name="OldRole"; Expression={$_.OldRole}},@{Name="NewRole"; Expression={$_.Role}})
            }

            #Patch request
            $body += "]"
            if ($scope -eq "Organization")
            {
                $url = "https://feeds.dev.azure.com/{0}/_apis/packaging/Feeds/{1}/permissions?api-version=6.1-preview.1"  -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceDetails.Id;
            }
            else {
                $url = "https://feeds.dev.azure.com/{0}/{1}/_apis/packaging/Feeds/{2}/permissions?api-version=6.1-preview.1"  -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName, $this.ResourceContext.ResourceDetails.Id;
            }
            $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($url)
            Invoke-RestMethod -Uri $url -Method Patch -ContentType "application/json" -Headers $header -Body $body

            $controlResult.AddMessage([VerificationResult]::Fixed,  "Permission for broader groups have been changed as below: ");
            $display = ($RawDataObjForControlFix |  FT -AutoSize | Out-String -Width 512)

            $controlResult.AddMessage("`n$display");
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckSecureFilesPermission([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try {
            $url = "https://dev.azure.com/{0}/{1}/_apis/build/authorizedresources?type=securefile&id={2}&api-version=6.0-preview.1" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName, $this.ResourceContext.ResourceDetails.Id
            $secureFileObj = @([WebRequestHelper]::InvokeGetWebRequest($url));

            if(($secureFileObj.Count -gt 0) -and [Helpers]::CheckMember($secureFileObj[0], "authorized") -and  $secureFileObj[0].authorized -eq $true) {
                $controlResult.AddMessage([VerificationResult]::Failed, "Secure file is accesible to all pipelines.");
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed, "Secure file is not accesible to all pipelines.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch authorization details of secure file.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckBroaderGroupAccessOnSecureFile([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            if ([Helpers]::CheckMember($this.ControlSettings, "SecureFile.RestrictedBroaderGroupsForSecureFile"))
            {
                $restrictedBroaderGroups = @{}
                $restrictedBroaderGroupsForSecureFile = $this.ControlSettings.SecureFile.RestrictedBroaderGroupsForSecureFile
                $restrictedBroaderGroupsForSecureFile.psobject.properties | foreach { $restrictedBroaderGroups[$_.Name] = $_.Value }

                $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
                $url = 'https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.securefile/roleassignments/resources/{1}%24{2}' -f $this.OrganizationContext.OrganizationName, $projectId, $this.ResourceContext.ResourceDetails.Id;
                $secureFilePermissionList = @([WebRequestHelper]::InvokeGetWebRequest($url));

                $roleAssignmentsToCheck = $secureFilePermissionList;
                if ($this.checkInheritedPermissionsSecureFile -eq $false) {
                    $roleAssignmentsToCheck = $secureFilePermissionList | where-object { $_.access -ne "inherited" }
                }
                
                $excesiveSecureFilePermissions = @($roleAssignmentsToCheck | Where-Object { $restrictedBroaderGroups.keys -contains $_.identity.displayName.split('\')[-1] -and ($_.role.name -in $restrictedBroaderGroups[$_.identity.displayName.split('\')[-1]])})
                $secureFileWithBroaderGroup = @($excesiveSecureFilePermissions | Select-Object -Property @{Name="SecureFileName"; Expression = {$this.ResourceContext.ResourceName}},@{Name="Role"; Expression = {$_.role.name}},@{Name="Name"; Expression = {$_.identity.displayName}}) ;

                if ([CommonSVTControls]::BroaderGroupMemberCountCheckEnabledSecureFile -and $secureFileWithBroaderGroup.Count -gt 0)
                {
                    $broaderGroupsWithExcessiveMembers = @([ControlHelper]::FilterBroadGroupMembers($secureFileWithBroaderGroup, [CommonSVTControls]::AllowedMemberCountInBroaderGroupsSecureFile, $true))
                    $secureFileWithBroaderGroup = @($secureFileWithBroaderGroup | Where-Object {$broaderGroupsWithExcessiveMembers -contains $_.Name})
                }

                $secureFileWithBroaderGroupCount = $secureFileWithBroaderGroup.count;

                if ($secureFileWithBroaderGroupCount -gt 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Count of broader groups that have user/administrator access to secure file: $($secureFileWithBroaderGroupCount)")
                    $display = ($secureFileWithBroaderGroup |  FT  Name, Role -AutoSize | Out-String -Width 512)
                    $controlResult.AddMessage("`nList of groups: ", $display)
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,  "Secure file is not granted with user/administrator permission to broad groups.");
                }
                $displayObj = $restrictedBroaderGroups.Keys | Select-Object @{Name = "Broader Group"; Expression = {$_}}, @{Name = "Excessive Permissions"; Expression = {$restrictedBroaderGroups[$_] -join ', '}}
                $controlResult.AddMessage("`nNote: `nThe following groups are considered 'broader groups': `n$($displayObj | FT | out-string)");
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Error,  "List of broader groups for secure file is not defined in control settings for your organization.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not fetch secure file permissions.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckEnviornmentAccess([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            $url = "https://dev.azure.com/{0}/{1}/_apis/pipelines/pipelinePermissions/environment/{2}" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName, $this.ResourceContext.ResourceDetails.Id;
            $envPipelinePermissionObj = @([WebRequestHelper]::InvokeGetWebRequest($url));

            if (($envPipelinePermissionObj.Count -gt 0) -and ([Helpers]::CheckMember($envPipelinePermissionObj[0],"allPipelines")) -and ($envPipelinePermissionObj[0].allPipelines.authorized -eq $true))
            {
                $controlResult.AddMessage([VerificationResult]::Failed, "Environment is accessible to all pipelines.");
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Environment is not accessible to all pipelines.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch environment's pipeline permission setting.");
            $controlResult.LogException($_)
        }
       return $controlResult
    }

    hidden [ControlResult] CheckBroaderGroupAccessOnEnvironment([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            if ([Helpers]::CheckMember($this.ControlSettings, "Environment.RestrictedBroaderGroupsForEnvironment"))
            {
                $restrictedBroaderGroups = @{}
                $restrictedBroaderGroupsForEnvironment = $this.ControlSettings.Environment.RestrictedBroaderGroupsForEnvironment
                $restrictedBroaderGroupsForEnvironment.psobject.properties | foreach { $restrictedBroaderGroups[$_.Name] = $_.Value }

                $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
                $url = 'https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.environmentreferencerole/roleassignments/resources/{1}_{2}' -f $this.OrganizationContext.OrganizationName, $projectId, $this.ResourceContext.ResourceDetails.Id;
                $environmentPermissionList = @([WebRequestHelper]::InvokeGetWebRequest($url));

                $roleAssignmentsToCheck = $environmentPermissionList;
                if ($this.checkInheritedPermissionsEnvironment -eq $false) {
                    $roleAssignmentsToCheck = $environmentPermissionList | where-object { $_.access -ne "inherited" }
                }
                
                #$excesiveEnvironmentPermissions = @(($roleAssignmentsToCheck | Where-Object {$_.role.name -eq "administrator" -or $_.role.name -eq "user"}) | Select-Object -Property @{Name="EnvironmentName"; Expression = {$this.ResourceContext.ResourceName}},@{Name="Role"; Expression = {$_.role.name}},@{Name="DisplayName"; Expression = {$_.identity.displayName}}) ;
                #$environmentWithBroaderGroup = @($excesiveEnvironmentPermissions | Where-Object { $restrictedBroaderGroupsForEnvironment -contains $_.DisplayName.split('\')[-1] })
                
                $excesiveEnvironmentPermissions = @($roleAssignmentsToCheck | Where-Object { $restrictedBroaderGroups.keys -contains $_.identity.displayName.split('\')[-1] -and ($_.role.name -in $restrictedBroaderGroups[$_.identity.displayName.split('\')[-1]])})
                $environmentWithBroaderGroup = @($excesiveEnvironmentPermissions | Select-Object -Property @{Name="SecureFileName"; Expression = {$this.ResourceContext.ResourceName}},@{Name="Role"; Expression = {$_.role.name}},@{Name="Name"; Expression = {$_.identity.displayName}}) ;

                if ([CommonSVTControls]::BroaderGroupMemberCountCheckEnabledEnvironment -and $environmentWithBroaderGroup.Count -gt 0)
                {
                    $broaderGroupsWithExcessiveMembers = @([ControlHelper]::FilterBroadGroupMembers($environmentWithBroaderGroup, [CommonSVTControls]::AllowedMemberCountInBroaderGroupsEnvironment, $true))
                    $environmentWithBroaderGroup = @($environmentWithBroaderGroup | Where-Object {$broaderGroupsWithExcessiveMembers -contains $_.Name})
                }
                
                $environmentWithBroaderGroupCount = $environmentWithBroaderGroup.count;

                if ($environmentWithBroaderGroupCount -gt 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Count of broader groups that have user/administrator access to environment: $($environmentWithBroaderGroupCount)")
                    $display = ($environmentWithBroaderGroup |  FT Name, Role -AutoSize | Out-String -Width 512)
                    $controlResult.AddMessage("`nList of groups: ", $display)
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,  "Environment is not granted with user/administrator permission to broad groups.");
                }
                $displayObj = $restrictedBroaderGroups.Keys | Select-Object @{Name = "Broader Group"; Expression = {$_}}, @{Name = "Excessive Permissions"; Expression = {$restrictedBroaderGroups[$_] -join ', '}}
                $controlResult.AddMessage("`nNote: `nThe following groups are considered 'broader groups': `n$($displayObj | FT | out-string)");
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Error,  "List of broader groups for environment is not defined in control settings for your organization.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not fetch environment permissions.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }
    
    hidden [ControlResult] CheckBuildSvcAccAccessOnFeeds([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            #orgFeedURL will be used to identify if feed is org scoped or project scoped
            $orgFeedURL = 'https://feeds.dev.azure.com/{0}/_apis/packaging/feeds*'  -f $this.OrganizationContext.OrganizationName
            $scope = "Project"
            if ($this.ResourceContext.ResourceDetails.url -match $orgFeedURL){
                $url = 'https://{0}.feeds.visualstudio.com/_apis/Packaging/Feeds/{1}/Permissions?includeIds=true&excludeInheritedPermissions=false&includeDeletedFeeds=false' -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceDetails.Id;
                $controlResult.AddMessage("`n***Organization scoped feed***")
                $scope = "Organization"
            }
            else {
                $url = 'https://{0}.feeds.visualstudio.com/{1}/_apis/Packaging/Feeds/{2}/Permissions?includeIds=true&excludeInheritedPermissions=false&includeDeletedFeeds=false' -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName, $this.ResourceContext.ResourceDetails.Id;
                $controlResult.AddMessage("`n***Project scoped feed***")
            }
            $feedPermissionList = @([WebRequestHelper]::InvokeGetWebRequest($url));

            $restrictedRolesForBroaderGroupsInFeeds = $this.ControlSettings.Feed.RestrictedRolesForBroaderGroupsInFeeds;

            $excessiveBuildSvcAccFeedsPerm = @($feedPermissionList | Where-Object {($restrictedRolesForBroaderGroupsInFeeds -contains $_.role) -and `
                (($_.DisplayName.split('\')[-1] -like "*Project Collection Build Service ($($this.OrganizationContext.OrganizationName))") -or `
                ($_.DisplayName.split('\')[-1] -like "*Build Service ($($this.OrganizationContext.OrganizationName))" ))}) 

            $feedWithBuildSvcAcc = @($excessiveBuildSvcAccFeedsPerm | Select-Object -Property @{Name="Role"; Expression = {$_.role}},@{Name="DisplayName"; Expression = {$_.displayName}}) ;
            $feedWithBuildSvcAccCount = $feedWithBuildSvcAcc.count;

            if ($feedWithBuildSvcAccCount -gt 0)
            {
                $controlResult.AddMessage([VerificationResult]::Failed, "Count of build service accounts that have administrator/contributor/collaborator access to feed: $($feedWithBuildSvcAccCount)")

                $display = ($feedWithBuildSvcAcc |  FT Role, DisplayName -AutoSize | Out-String -Width 512)
                $controlResult.AddMessage("`nList of groups: ", $display)
                $controlResult.SetStateData("List of groups: ", $feedWithBuildSvcAcc);
                if ($this.ControlFixBackupRequired)
                {
                    #Data object that will be required to fix the control
                    $excessiveBuildSvcAccFeedsPerm | ForEach-Object{
                        $_ | Add-Member -MemberType NoteProperty -Name "Scope" -Value $scope
                    }
                    $controlResult.BackupControlState = $excessiveBuildSvcAccFeedsPerm;
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed,  "Feed is not granted with administrator/contributor/collaborator permission to build service accounts.");
            }            
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not fetch feed permissions.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckBuildSvcAccAccessOnFeedsAutomatedFix([ControlResult] $controlResult)
    {
        try{
            $RawDataObjForControlFix = @();
            $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject
            $scope = $RawDataObjForControlFix[0].Scope
            $isBuildSVcAccUsedToPublishPackage = $false

            $body = "["

            if (-not $this.UndoFix)
            {
                #If last 10 published packages are published via Build service accounts, user should provide -Force switch in the command
                if (-not $this.invocationContext.BoundParameters["Force"])
                {
                    $isBuildSVcAccUsedToPublishPackage = $this.ValidateBuildSvcAccInPackage($scope);
                }

                if ($isBuildSVcAccUsedToPublishPackage -eq $false)
                {
                    foreach ($identity in $RawDataObjForControlFix) 
                    {
                        $roleId = [int][FeedPermissions] "Reader"
                        if ($body.length -gt 1) {$body += ","}
                        $body += @"
                            {
                                "displayName": "$($($identity.displayName).Replace('\','\\'))",
                                "identityId": "$($identity.identityId)",
                                "role": $roleId,
                                "identityDescriptor": "$($($identity.identityDescriptor).Replace('\','\\'))",
                                "isInheritedRole": false
                            }
"@;
                    }
                    $RawDataObjForControlFix | Add-Member -NotePropertyName NewRole -NotePropertyValue "Reader"
                    $RawDataObjForControlFix = @($RawDataObjForControlFix  | Select-Object @{Name="DisplayName"; Expression={$_.DisplayName}}, @{Name="OldRole"; Expression={$_.Role}},@{Name="NewRole"; Expression={$_.NewRole}})
                }
                else {
                    $this.PublishCustomMessage("Build service accounts have been used recently to publish package. Please use -Force in the command to apply fix for such feeds.`n",[MessageType]::Warning);
                    $controlResult.AddMessage([VerificationResult]::Verify,  "Build service accounts have been used recently to publish package. Please use -Force in the command to apply fix for such feeds.");
                    return $controlResult;
                }
            }
            else {
                foreach ($identity in $RawDataObjForControlFix) 
                {
                    $roleId = [int][FeedPermissions] "$($identity.role)"
                    if ($body.length -gt 1) {$body += ","}
                    $body += @"
                        {
                            "displayName": "$($($identity.displayName).Replace('\','\\'))",
                            "identityId": "$($identity.identityId)",
                            "role": $roleId,
                            "identityDescriptor": "$($($identity.identityDescriptor).Replace('\','\\'))",
                            "isInheritedRole": false
                        }
"@;
                }
                $RawDataObjForControlFix | Add-Member -NotePropertyName OldRole -NotePropertyValue "Reader"
                $RawDataObjForControlFix = @($RawDataObjForControlFix  | Select-Object @{Name="DisplayName"; Expression={$_.DisplayName}}, @{Name="OldRole"; Expression={$_.OldRole}},@{Name="NewRole"; Expression={$_.Role}})
            }
            
            #Patch request
            $body += "]"
            if ($scope -eq "Organization")
            {
                $url = "https://feeds.dev.azure.com/{0}/_apis/packaging/Feeds/{1}/permissions?api-version=6.1-preview.1"  -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceDetails.Id;
            }
            else {
                $url = "https://feeds.dev.azure.com/{0}/{1}/_apis/packaging/Feeds/{2}/permissions?api-version=6.1-preview.1"  -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName, $this.ResourceContext.ResourceDetails.Id;
            }
            $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($url)
            Invoke-RestMethod -Uri $url -Method Patch -ContentType "application/json" -Headers $header -Body $body

            $controlResult.AddMessage([VerificationResult]::Fixed,  "Permission for Build service accounts have been changed as below: ");
            $display = ($RawDataObjForControlFix |  FT -AutoSize | Out-String -Width 512)

            $controlResult.AddMessage("`n$display");
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [boolean] ValidateBuildSvcAccInPackage($scope)
    {
        $isBuildSvsAccUsed = $false
        try 
        {
            if ($scope -eq "Organization")
            {
                #$top in this api returns data alphabetically. Also queryorder is not supported.
                $url = "https://feeds.dev.azure.com/{0}/_apis/packaging/Feeds/{1}/packages?api-version=6.0-preview.1" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceDetails.Id;
            }
            else {
                $url = "https://feeds.dev.azure.com/{0}/{1}/_apis/packaging/Feeds/{2}/packages?api-version=6.0-preview.1" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName, $this.ResourceContext.ResourceDetails.Id;
            }
            $packageList = @([WebRequestHelper]::InvokeGetWebRequest($url));

            #Get top 10 published packages 
            $recentPackages = $packageList | Sort-Object -Property @{Expression={$_.versions.publishdate}; Descending = $true } | Select-Object -First 10
            foreach ($package in $recentPackages)
            {
                if ($scope -eq "Organization")
                {
                    $provenanceURL = "https://feeds.dev.azure.com/{0}/_apis/packaging/Feeds/{1}/Packages/{2}/Versions/{3}/provenance?api-version=6.0-preview.1" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceDetails.Id, $package.id, $package.versions.id ;
                }
                else
                {
                    $provenanceURL = "https://feeds.dev.azure.com/{0}/{1}/_apis/packaging/Feeds/{2}/Packages/{3}/Versions/{4}/provenance?api-version=6.0-preview.1" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName, $this.ResourceContext.ResourceDetails.Id, $package.id, $package.versions.id ;
                }
                $provenanceDetails = @([WebRequestHelper]::InvokeGetWebRequest($provenanceURL));

                if ($provenanceDetails.provenance.data.'Common.IdentityDisplayName' -like "*Project Collection Build Service ($($this.OrganizationContext.OrganizationName))" -or $provenanceDetails.provenance.data.'Common.IdentityDisplayName' -like "*Build Service ($($this.OrganizationContext.OrganizationName))")
                {
                    $isBuildSvsAccUsed = $true
                    break;
                }
            }
        }
        catch
        {
            #eat exception
        }
        return $isBuildSvsAccUsed
    }

    hidden [ControlResult] CheckBuildSvcAcctAccessOnRepository([ControlResult] $controlResult)
	{
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            # Fetching repository RBAC using portal api's because no documented api present for this purpose.
            $url = 'https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1' -f $($this.OrganizationContext.OrganizationName);
            $refererUrl = "https://dev.azure.com/{0}/{1}/_settings/repositories?repo={2}&_a=permissionsMid" -f $($this.OrganizationContext.OrganizationName), $($this.ResourceContext.ResourceGroupName), $($this.ResourceContext.ResourceDetails.id)
            $inputbody = '{"contributionIds":["ms.vss-admin-web.security-view-members-data-provider"],"dataProviderContext":{"properties":{"permissionSetId": "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87","permissionSetToken":"","sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"repositories","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json
            $inputbody.dataProviderContext.properties.sourcePage.url = $refererUrl
            $inputbody.dataProviderContext.properties.sourcePage.routeValues.Project = $this.ResourceContext.ResourceGroupName;
            $inputbody.dataProviderContext.properties.permissionSetToken = "repoV2/$($this.ResourceContext.ResourceDetails.Project.id)/$($this.ResourceContext.ResourceDetails.id)"

            $responseObj = [WebRequestHelper]::InvokePostWebRequest($url, $inputbody);
            $repositoryIdentities = @();

            if([Helpers]::CheckMember($responseObj[0],"dataProviders") -and ($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider') -and ([Helpers]::CheckMember($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider',"identities")))
            {
                $repositoryIdentities = @($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider'.identities)
            }

            if($repositoryIdentities.Count -gt 0)
            {
                $buildServieAccountOnRepo = @()
                foreach ($identity in $repositoryIdentities)
                {
                    if ($identity.displayName -like '*Project Collection Build Service Accounts' -or $identity.displayName -like "*Build Service ($($this.OrganizationContext.OrganizationName))")
                    {
                        $buildServieAccountOnRepo += $identity.displayName;
                    }
                }
                $restrictedBuildSVCAcctCount = $buildServieAccountOnRepo.Count;
                if($restrictedBuildSVCAcctCount -gt 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Count of restricted Build Service groups that have access to repository: $($restrictedBuildSVCAcctCount)")
                    $controlResult.AddMessage("`nList of 'Build Service' Accounts: ", $($buildServieAccountOnRepo | FT | Out-String))
                    $controlResult.SetStateData("List of 'Build Service' Accounts: ", $buildServieAccountOnRepo)
                    $controlResult.AdditionalInfo += "Count of restricted Build Service groups that have access to service connection: $($restrictedBuildSVCAcctCount)";
                }
                else{
                    $controlResult.AddMessage([VerificationResult]::Passed,"Build Service accounts are not granted access to the repository.");
                }

            }
            else{
                $controlResult.AddMessage([VerificationResult]::Error,"Unable to fetch repository permission details.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,"Unable to fetch repository permission details.");
            $controlResult.LogException($_)
        }
        return $controlResult;
    }
}