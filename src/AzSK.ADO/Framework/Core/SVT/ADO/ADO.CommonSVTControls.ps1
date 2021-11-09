Set-StrictMode -Version Latest
class CommonSVTControls: ADOSVTBase {

    hidden [PSObject] $Repos; # This is used for fetching repo details
    #hidden [PSObject] $ProjectId;
    hidden [string] $checkInheritedPermissionsSecureFile = $false
    hidden [string] $checkInheritedPermissionsEnvironment = $false
    hidden [string] $checkInheritedPermissionsRepo = $false
    hidden [string] $checkInheritedPermissionsFeed = $false
    hidden [object] $repoInheritePermissions = @{};
    hidden [PSObject] $excessivePermissionBitsForRepo = @(1)
    hidden [PSObject] $excessivePermissionsForRepoBranch = $null;
    hidden [string] $repoPermissionSetId = "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87";

    CommonSVTControls([string] $organizationName, [SVTResource] $svtResource): Base($organizationName, $svtResource) {

        if ([Helpers]::CheckMember($this.ControlSettings, "SecureFile.CheckForInheritedPermissions") -and $this.ControlSettings.SecureFile.CheckForInheritedPermissions) {
            $this.checkInheritedPermissionsSecureFile = $true
        }

        if ([Helpers]::CheckMember($this.ControlSettings, "Environment.CheckForInheritedPermissions") -and $this.ControlSettings.Environment.CheckForInheritedPermissions) {
            $this.checkInheritedPermissionsEnvironment = $true
        }

        if ([Helpers]::CheckMember($this.ControlSettings, "Repo.CheckForInheritedPermissions") -and $this.ControlSettings.Build.CheckForInheritedPermissions) {
            #allow permission bit for inherited permission is '3'
            $this.checkInheritedPermissionsRepo = $true
            $this.excessivePermissionBitsForRepo = @(1,3)
        }

        if ([Helpers]::CheckMember($this.ControlSettings.Feed, "CheckForInheritedPermissions") -and $this.ControlSettings.Feed.CheckForInheritedPermissions) {
            $this.checkInheritedPermissionsFeed = $true
        }

        $this.excessivePermissionsForRepoBranch = $this.ControlSettings.Repo.ExcessivePermissionsForBranch        

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
                $controlResult.AddMessage([VerificationResult]::Failed, "Repository is accessible to all YAML pipelines.");
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Repository is not accessible to all YAML pipelines.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch repository pipeline permission.");
            $controlResult.LogException($_)
        }
       return $controlResult
    }
    hidden [ControlResult] CheckBuildServiceAccessOnBranch([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            $isControlPassing = $true
            $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]           
            $url = 'https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1' -f $($this.OrganizationContext.OrganizationName);
            $inputbody = '{"contributionIds":["ms.vss-admin-web.security-view-members-data-provider"],"dataProviderContext":{"properties":{"permissionSetId": "","permissionSetToken":"","sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"repositories","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json
            $inputbody.dataProviderContext.properties.sourcePage.routeValues.Project = $this.ResourceContext.ResourceGroupName;
            $inputbody.dataProviderContext.properties.permissionSetId = $this.repoPermissionSetId
            #first check permissions for all branches
            $inputbody.dataProviderContext.properties.permissionSetToken = "repoV2/$($projectId)/$($this.ResourceContext.ResourceDetails.id)/refs^heads/" 
            #calling the common method to get permissions object on this level    
            $autoFixStateData = @();       
            $excessivePermissionsListOnAllBranches = $this.CheckPermsOnBranch($url,$inputBody,$projectId,$null)
            if ($null -ne $excessivePermissionsListOnAllBranches -and $excessivePermissionsListOnAllBranches.count -gt 0) {
                $isControlPassing = $false        
                $controlResult.AddMessage([VerificationResult]::Failed, "Build service groups have excessive permissions on 'All Branches' level of the repository.");
                $formattedGroupsData = $excessivePermissionsListOnAllBranches | Select @{l = 'Group'; e = { $_.Group} }, @{l = 'ExcessivePermissions'; e = { $_.ExcessivePermissions } }
                $formattedBuildServiceGrpTable = ($formattedGroupsData | Out-String -Width 512)
                $controlResult.AddMessage("`nList of groups : `n$formattedBuildServiceGrpTable");
                $groups = $formattedGroupsData | ForEach-Object { $_.Group + ': ' + $_.ExcessivePermissions } 
                $groups =  $groups -join ' ; '
                $controlResult.AdditionalInfo += "List of Build service groups  with excessive permission on 'All Branches' level:  $($groups); ";
                $controlResult.AdditionalInfoInCSV+= "'All Branches' level excessive permissions: $($groups); "                        
                if ($this.ControlFixBackupRequired)
                {
                    $autoFixStateData +=$excessivePermissionsListOnAllBranches;
                    #Data object that will be required to fix the control
                    $controlResult.BackupControlState = $autoFixStateData;
                }
            }
            else {
                $controlResult.AddMessage("Build service groups do not have excessive permissions on 'All Branches' level of the repository.");
            }
            #get all eligible branches from settings and check for each of them
            $individualBranches = $this.ControlSettings.Repo.BranchesToCheckForExcessivePermissions
            $individualBranches | foreach {
                $inputbody.dataProviderContext.properties.permissionSetToken = "repoV2/$($projectId)/$($this.ResourceContext.ResourceDetails.id)/refs^heads^$($_)/"
                $excessivePermissionsListOnBranch = $this.CheckPermsOnBranch($url,$inputBody,$projectId,$_)
                if ($null -ne $excessivePermissionsListOnBranch -and $excessivePermissionsListOnBranch.count -gt 0) 
                {
                    if($isControlPassing){
                        $isControlPassing = $false
                        $controlResult.AddMessage([VerificationResult]::Failed, "Build service groups  have excessive permissions on '$($_)' branch of the repository.");
                    }
                    else{
                        $controlResult.AddMessage("Build service groups  have excessive permissions on '$($_)' branch of the repository.");
                    }                  
                    
                    $formattedGroupsData = $excessivePermissionsListOnBranch | Select @{l = 'Group'; e = { $_.Group} }, @{l = 'ExcessivePermissions'; e = { $_.ExcessivePermissions } }
                    $formattedBuildServiceGrpTable = ($formattedGroupsData | Out-String -Width 512)
                    $controlResult.AddMessage("`nList of groups : `n$formattedBuildServiceGrpTable");                    
                    $groups = $formattedGroupsData | ForEach-Object { $_.Group + ': ' + $_.ExcessivePermissions } 
                    $groups =  $groups -join ' ; '
                    $controlResult.AdditionalInfo += "List of Build service groups with excessive permission on $($_) branch:  $($groups); ";
                    $controlResult.AdditionalInfoInCSV+= "$_ branch excessive permissions: $($groups); " 
                    if ($this.ControlFixBackupRequired)
                    {
                        $autoFixStateData +=$excessivePermissionsListOnBranch;
                        #Data object that will be required to fix the control
                        $controlResult.BackupControlState = $autoFixStateData;
                    }                     
                }
                else {
                    $controlResult.AddMessage("Build service groups  do not have excessive permissions on '$($_)' branch of the repository.");
                }
            }
            #only when all the branches are passing, this controls will be passed
            if($isControlPassing){
                $controlResult.AddMessage([VerificationResult]::Passed, "Build service groups do not have excessive permissions on either 'all branch' level or individual branches in the repository");
                $controlResult.AdditionalInfoInCSV = 'NA'
            } 

            $controlResult.AddMessage("`nFollowing permissions are considered 'excessive':`n$($this.excessivePermissionsForRepoBranch | FT | Out-String)");
        
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch repository permissions.");
            $controlResult.LogException($_)
        }
       return $controlResult
    }

    hidden [ControlResult] CheckBuildServiceAccessOnBranchAutomatedFix([ControlResult] $controlResult)
    {
        try{
            $RawDataObjForControlFix = @();
            $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject
            $url = "https://dev.azure.com/{0}/_apis/AccessControlEntries/{1}?api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $this.repoPermissionSetId

            if (-not $this.UndoFix) {
                foreach ($identity in $RawDataObjForControlFix) 
                {   
                    $excessivePermissions = $identity.ExcessivePermissions -split ";"
                    $descriptor = $identity.Descriptor
                    foreach ($excessivePermission in $excessivePermissions) {
                        if ($excessivePermission.trim() -eq 'Force push (rewrite history, delete branches and tags)') {
                            $roleId = [int][RepoPermissions] 'Forcepush'
                        }
                        elseif ($excessivePermission.trim() -eq "Remove others' locks") {
                            $roleId = [int][RepoPermissions] 'Removeotherslocks'
                        }
                        else {
                            $roleId = [int][RepoPermissions] $excessivePermission.Replace(" ","").trim();  
                        }
                        #need to invoke a post request which does not accept all permissions added in the body at once
                        #hence need to call invoke seperately for each permission
                         $body = "{
                            'token': '$($identity.PermissionSetToken)',
                            'merge': true,
                            'accessControlEntries' : [{
                                'descriptor' : '$descriptor',
                                'allow':0,
                                'deny':$($roleId)                              
                            }]
                        }" | ConvertFrom-Json

                        $result = [WebRequestHelper]:: InvokePostWebRequest($url,$body)

                    }
                    $identity | Add-Member -NotePropertyName OldPermission -NotePropertyValue "Allow"
                    $identity | Add-Member -NotePropertyName NewPermission -NotePropertyValue "Deny"

                }
            }
            else {
                foreach ($identity in $RawDataObjForControlFix) 
                {
                    
                    $descriptor = $identity.Descriptor
                    $excessivePermissions = $identity.ExcessivePermissions -split ";"
                    foreach ($excessivePermission in $excessivePermissions) {
                        if ($excessivePermission.trim() -eq 'Force push (rewrite history, delete branches and tags)') {
                            $roleId = [int][RepoPermissions] 'Forcepush'
                        }
                        elseif ($excessivePermission.trim() -eq "Remove others' locks") {
                            $roleId = [int][RepoPermissions] 'Removeotherslocks'
                        }
                        else {
                            $roleId = [int][RepoPermissions] $excessivePermission.Replace(" ","").trim();  
                        }
                        
                         $body = "{
                            'token': '$($identity.PermissionSetToken)',
                            'merge': true,
                            'accessControlEntries' : [{
                                'descriptor' : '$descriptor',
                                'allow':$($roleId),
                                'deny':0                              
                            }]
                        }" | ConvertFrom-Json

                        [WebRequestHelper]:: InvokePostWebRequest($url,$body)

                    }
                    $identity | Add-Member -NotePropertyName OldPermission -NotePropertyValue "Deny"
                    $identity | Add-Member -NotePropertyName NewPermission -NotePropertyValue "Allow"
                }
            }
            
            $controlResult.AddMessage([VerificationResult]::Fixed,  "Permissions for build service accounts on branches have been changed as below: ");
            $formattedGroupsData = $RawDataObjForControlFix | Select @{l = 'Group'; e = { $_.Group } }, @{l = 'ExcessivePermissions'; e = { $_.ExcessivePermissions }}, @{l = 'OldPermission'; e = { $_.OldPermission }}, @{l = 'NewPermission'; e = { $_.NewPermission } }
            $display = ($formattedGroupsData |  FT -AutoSize | Out-String -Width 512)

            $controlResult.AddMessage("`n$display");
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    #common method to get excessive permisions for every group for a branch
    hidden [Object] CheckPermsOnBranch($url,$inputBody,$projectId,$branch){
        $responseObj = [WebRequestHelper]::InvokePostWebRequest($url, $inputbody);
        if([Helpers]::CheckMember($responseObj[0],"dataProviders") -and ($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider') -and ([Helpers]::CheckMember($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider',"identities")))
            {
                
            $broaderGroupsList = @($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider'.identities | Where-Object { $_.subjectKind -eq 'group' -and $_.displayName -like "*Project Collection Build Service Accounts" })
            $broaderGroupsList+=@($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider'.identities | Where-Object { $_.subjectKind -eq 'user' -and ($_.displayName -match "Project Collection Build Service ($($this.OrganizationContext.OrganizationName))" -or $_.displayName -like "*Build Service ($($this.OrganizationContext.OrganizationName))" )})
            if ($broaderGroupsList.Count) {
                $groupsWithExcessivePermissionsList = @()
                foreach ($broaderGroup in $broaderGroupsList) {
                    $broaderGroupInputbody = "{'contributionIds':['ms.vss-admin-web.security-view-permissions-data-provider'],'dataProviderContext':{'properties':{'subjectDescriptor':'','permissionSetId':'','permissionSetToken':'','accountName':'','sourcePage':{'routeId':'ms.vss-admin-web.project-admin-hub-route','routeValues':{'project':'PrivateProjectWithRepo','adminPivot':'repositories','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json
                    $broaderGroupInputbody.dataProviderContext.properties.sourcePage.routeValues.Project = $this.ResourceContext.ResourceGroupName;
                    $broaderGroupInputbody.dataProviderContext.properties.permissionSetId = $this.repoPermissionSetId
                    if($null -eq $branch){
                        $broaderGroupInputbody.dataProviderContext.properties.permissionSetToken = "repoV2/$($projectId)/$($this.ResourceContext.ResourceDetails.id)/refs^heads/"
                    }
                    else {
                        $broaderGroupInputbody.dataProviderContext.properties.permissionSetToken = "repoV2/$($projectId)/$($this.ResourceContext.ResourceDetails.id)/refs^heads^$($branch)/"
                    }
                    
                    $broaderGroupInputbody.dataProviderContext.properties.subjectDescriptor = $broaderGroup.descriptor
                    $broaderGroupResponseObj = @([WebRequestHelper]::InvokePostWebRequest($url, $broaderGroupInputbody));
                    $broaderGroupRBACObj = @($broaderGroupResponseObj[0].dataProviders.'ms.vss-admin-web.security-view-permissions-data-provider'.subjectPermissions)
                    $excessivePermissionList = $broaderGroupRBACObj | Where-Object { $_.displayName -in $this.excessivePermissionsForRepoBranch }
                    $excessivePermissionsPerGroup = @()
                    $excessivePermissionList | ForEach-Object {                                
                        if ([Helpers]::CheckMember($_, "effectivePermissionValue")) {
                            if ($this.excessivePermissionBitsForRepo -contains $_.effectivePermissionValue) {
                                $excessivePermissionsPerGroup += $_
                            }
                        }
                    }
                    if ($excessivePermissionsPerGroup.Count -gt 0) {
                        $groupFoundWithExcessivePermissions = $true
                            # For PCBSA, resolve the group and check if PBS, PCBS are part of it
                        if ($broaderGroup.displayName -like '*Project Collection Build Service Accounts') {
                            $groupFoundWithExcessivePermissions = $false
                            $url="https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.1-preview" -f $($this.OrganizationContext.OrganizationName);                                
                            $postbody="{'contributionIds':['ms.vss-admin-web.org-admin-members-data-provider'],'dataProviderContext':{'properties':{'subjectDescriptor':'','sourcePage':{'url':'','routeId':'ms.vss-admin-web.collection-admin-hub-route','routeValues':{'adminPivot':'groups','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json
                            $postbody.dataProviderContext.properties.subjectDescriptor = $broaderGroup.descriptor
                            $bodyUrl = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/_settings/groups?subjectDescriptor=$($broaderGroup.descriptor)"
                            $postbody.dataProviderContext.properties.sourcePage.url = $bodyUrl                               
                            try {
                                $response = [WebRequestHelper]::InvokePostWebRequest($url, $postbody)
                                if([Helpers]::CheckMember($response.dataProviders.'ms.vss-admin-web.org-admin-members-data-provider', "identities"))
                                {
                                    $buildServiceAccountIdentities = $response.dataProviders.'ms.vss-admin-web.org-admin-members-data-provider'.identities
                                    foreach ($eachIdentity in $buildServiceAccountIdentities) {
                                        if ($eachIdentity.displayName -like "*Project Collection Build Service ($($this.OrganizationContext.OrganizationName))" -or $eachIdentity.displayName -like "*Build Service ($($this.OrganizationContext.OrganizationName))") {
                                            $groupFoundWithExcessivePermissions = $true                                          
                                        }                                        
                                    }
                                } 
                            }    
                            catch {}                            
                                               
                        }
                        if ($groupFoundWithExcessivePermissions -eq $true) {
                            $excessivePermissionsGroupObj = @{}
                            $excessivePermissionsGroupObj['Group'] = $broaderGroup.displayName
                            $excessivePermissionsGroupObj['ExcessivePermissions'] = $($excessivePermissionsPerGroup.displayName -join '; ') 
                            $excessivePermissionsGroupObj['Descriptor'] = $broaderGroupResponseObj[0].dataProviders.'ms.vss-admin-web.security-view-permissions-data-provider'.identityDescriptor
                            $excessivePermissionsGroupObj['PermissionSetToken'] = $excessivePermissionsPerGroup[0].token                           
                            $groupsWithExcessivePermissionsList += $excessivePermissionsGroupObj
                        }
                    }
                }
                return $groupsWithExcessivePermissionsList;                

            }
            else{
                return $null;
            }
        }
        return $null;
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
            $restrictedBroaderGroups = @{}
            $restrictedBroaderGroupsForFeeds = $this.ControlSettings.Feed.RestrictedBroaderGroupsForFeeds

            if(@($restrictedBroaderGroupsForFeeds.psobject.properties).Count -gt 0){
                $restrictedBroaderGroupsForFeeds.psobject.properties | foreach { $restrictedBroaderGroups[$_.Name] = $_.Value }

                #GET https://feeds.dev.azure.com/{organization}/{project}/_apis/packaging/Feeds/{feedId}/permissions?api-version=6.0-preview.1
                #Using visualstudio api because new api (dev.azure.com) is giving null in the displayName property.

                #orgFeedURL will be used to identify if feed is org scoped or project scoped
                $scope = "Project"
                
                #Project property does not exist of org scoped feeds
                if ("Project" -notin $this.ResourceContext.ResourceDetails.PSobject.Properties.name){
                    $url = 'https://{0}.feeds.visualstudio.com/_apis/Packaging/Feeds/{1}/Permissions?includeIds=true&excludeInheritedPermissions=false&includeDeletedFeeds=false' -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceDetails.Id;
                    $controlResult.AddMessage("`n***Organization scoped feed***")
                    $scope = "Organization"
                }
                else {
                    $url = 'https://{0}.feeds.visualstudio.com/{1}/_apis/Packaging/Feeds/{2}/Permissions?includeIds=true&excludeInheritedPermissions=false&includeDeletedFeeds=false' -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName, $this.ResourceContext.ResourceDetails.Id;
                    $controlResult.AddMessage("`n***Project scoped feed***")
                }
                $feedPermissionList = @([WebRequestHelper]::InvokeGetWebRequest($url));
                if ($this.checkInheritedPermissionsFeed -eq $false) {
                    $feedPermissionList = $feedPermissionList | where-object { $_.isInheritedRole -eq $false }
                }
                
                $excesiveFeedsPermissions = @($feedPermissionList | Where-Object { $restrictedBroaderGroups.keys -contains $_.displayName.split('\')[-1] -and ($_.role -in $restrictedBroaderGroups[$_.displayName.split('\')[-1]])})
                $feedWithBroaderGroup = @($excesiveFeedsPermissions | Select-Object -Property @{Name="FeedName"; Expression = {$this.ResourceContext.ResourceName}},@{Name="Role"; Expression = {$_.role}},@{Name="Name"; Expression = {$_.displayName}}) ;

                if ($this.ControlSettings.CheckForBroadGroupMemberCount -and $feedWithBroaderGroup.Count -gt 0)
                {
                    $broaderGroupsWithExcessiveMembers = @([ControlHelper]::FilterBroadGroupMembers($feedWithBroaderGroup, $true))
                    $feedWithBroaderGroup = @($feedWithBroaderGroup | Where-Object {$broaderGroupsWithExcessiveMembers -contains $_.Name})
                }

                $feedWithBroaderGroupCount = $feedWithBroaderGroup.count;

                if ($feedWithBroaderGroupCount -gt 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Count of broader groups that have administrator/contributor/collaborator access to feed: $($feedWithBroaderGroupCount)")

                    $display = ($feedWithBroaderGroup |  FT Name, Role -AutoSize | Out-String -Width 512)
                    $controlResult.AddMessage("`nList of groups: ", $display)
                    $controlResult.SetStateData("List of groups: ", $feedWithBroaderGroup);
                    $groups = $feedWithBroaderGroup | ForEach-Object { $_.Name + ': ' + $_.Role } 
                    $controlResult.AdditionalInfoInCSV = $groups -join ' ; '

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
                    $controlResult.AdditionalInfoInCSV = "NA";
                }
                $displayObj = $restrictedBroaderGroups.Keys | Select-Object @{Name = "Broader Group"; Expression = {$_}}, @{Name = "Excessive Permissions"; Expression = {$restrictedBroaderGroups[$_] -join ', '}}
                $controlResult.AddMessage("`nNote: `nThe following groups are considered 'broader groups': `n$($displayObj | FT -AutoSize | out-string)");
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Error, "List of broader groups for feeds is not defined in control settings for your organization.");
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
                $controlResult.AddMessage([VerificationResult]::Failed, "Secure file is accesible to all YAML pipelines.");
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed, "Secure file is not accesible to all YAML pipelines.");
                try {
                    $url = "https://dev.azure.com/{0}/{1}/_apis/pipelines/pipelinePermissions/securefile/{2}" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName, $this.ResourceContext.ResourceDetails.Id;
                    $secureFilePipelinePermObj = @([WebRequestHelper]::InvokeGetWebRequest($url));
                    $buildPipelineIds = @();
                    if ($secureFilePipelinePermObj.Count -gt 0 -and $secureFilePipelinePermObj.pipelines.Count -gt 0) {
                        $buildPipelineIds = $secureFilePipelinePermObj.pipelines.id
                        $buildDefnURL = "https://{0}.visualstudio.com/{1}/_apis/build/definitions?definitionIds={2}&api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $this.ResourceContext.ResourceGroupName, ($buildPipelineIds -join ",");
                        $buildDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($buildDefnURL);
                        if (([Helpers]::CheckMember($buildDefnsObj,"name"))) {
                            $controlResult.AdditionalInfoInCSV = "NumYAMLPipelineWithAccess: $($buildDefnsObj.Count)"
                            $controlResult.AdditionalInfoInCSV = "List: " + ($buildDefnsObj.Name -join ",")
                        }
                    }
                }
                catch {
                }
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
            $restrictedBroaderGroups = @{}
            $restrictedBroaderGroupsForSecureFile = $this.ControlSettings.SecureFile.RestrictedBroaderGroupsForSecureFile

            if(@($restrictedBroaderGroupsForSecureFile.psobject.properties).Count -gt 0){
                $restrictedBroaderGroupsForSecureFile.psobject.properties | foreach { $restrictedBroaderGroups[$_.Name] = $_.Value }

                $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
                $url = 'https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.securefile/roleassignments/resources/{1}%24{2}' -f $this.OrganizationContext.OrganizationName, $projectId, $this.ResourceContext.ResourceDetails.Id;
                $secureFilePermissionList = @([WebRequestHelper]::InvokeGetWebRequest($url));

                $roleAssignmentsToCheck = $secureFilePermissionList;
                if ($this.checkInheritedPermissionsSecureFile -eq $false) {
                    $roleAssignmentsToCheck = $secureFilePermissionList | where-object { $_.access -ne "inherited" }
                }
                
                $excesiveSecureFilePermissions = @($roleAssignmentsToCheck | Where-Object { $restrictedBroaderGroups.keys -contains $_.identity.displayName.split('\')[-1] -and ($_.role.name -in $restrictedBroaderGroups[$_.identity.displayName.split('\')[-1]])})
                $secureFileWithBroaderGroup = @($excesiveSecureFilePermissions | Select-Object -Property @{Name="SecureFileName"; Expression = {$this.ResourceContext.ResourceName}},@{Name="Role"; Expression = {$_.role.name}},@{Name="Name"; Expression = {$_.identity.displayName}}, @{Name="Id"; Expression = {$_.identity.id}}) ;

                if ($this.ControlSettings.CheckForBroadGroupMemberCount -and $secureFileWithBroaderGroup.Count -gt 0)
                {
                    $broaderGroupsWithExcessiveMembers = @([ControlHelper]::FilterBroadGroupMembers($secureFileWithBroaderGroup, $true))
                    $secureFileWithBroaderGroup = @($secureFileWithBroaderGroup | Where-Object {$broaderGroupsWithExcessiveMembers -contains $_.Name})
                }

                $secureFileWithBroaderGroupCount = $secureFileWithBroaderGroup.count;

                if ($secureFileWithBroaderGroupCount -gt 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Count of broader groups that have user/administrator access to secure file: $($secureFileWithBroaderGroupCount)")
                    
                    $display = ($secureFileWithBroaderGroup |  FT  Name, Role -AutoSize | Out-String -Width 512)
                    $controlResult.AddMessage("`nList of groups: ", $display)

                    if ($this.ControlFixBackupRequired) {
                        #Data object that will be required to fix the control
                        $controlResult.BackupControlState = $secureFileWithBroaderGroup;
                    }

                    $groups = $secureFileWithBroaderGroup | ForEach-Object { $_.Name + ': ' + $_.Role } 
                    $controlResult.AdditionalInfoInCSV = $groups -join ' ; '
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,  "Secure file is not granted with user/administrator permission to broad groups.");
                }
                $displayObj = $restrictedBroaderGroups.Keys | Select-Object @{Name = "Broader Group"; Expression = {$_}}, @{Name = "Excessive Permissions"; Expression = {$restrictedBroaderGroups[$_] -join ', '}}
                $controlResult.AddMessage("`nNote: `nThe following groups are considered 'broader groups': `n$($displayObj | FT -AutoSize | out-string)");
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Error, "List of broader groups for secure file is not defined in control settings for your organization.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not fetch secure file permissions.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckBroaderGroupAccessOnSecureFileAutomatedFix ([ControlResult] $controlResult) 
    {
        try 
        {
            $RawDataObjForControlFix = @();
            $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject   
            $body = "["

            if (-not $this.UndoFix)
            {
                foreach ($identity in $RawDataObjForControlFix) 
                {                    
                    if ($body.length -gt 1) {$body += ","}
                    $body += @"
                        {
                            "userId": "$($identity.id)",
                            "roleName": "Reader"                                                   
                        }
"@;
                }
                $RawDataObjForControlFix | Add-Member -NotePropertyName NewRole -NotePropertyValue "Reader"
                $RawDataObjForControlFix = @($RawDataObjForControlFix  | Select-Object DisplayName, @{Name="OldRole"; Expression={$_.Role}}, NewRole)
            }
            else {
                foreach ($identity in $RawDataObjForControlFix) 
                {                    
                    if ($body.length -gt 1) {$body += ","}
                    $body += @"
                        {
                            "userId": "$($identity.id)",
                            "roleName": "$($identity.role)"                            
                        }
"@;
                }
                $RawDataObjForControlFix | Add-Member -NotePropertyName OldRole -NotePropertyValue "Reader"
                $RawDataObjForControlFix = @($RawDataObjForControlFix  | Select-Object DisplayName, OldRole, @{Name="NewRole"; Expression={$_.Role}})
            }            
            $body += "]"
            #Put request
            $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
            $url = "https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.securefile/roleassignments/resources/{1}%24{2}?api-version=6.1-preview.1" -f $($this.OrganizationContext.OrganizationName),$projectId,$($this.ResourceContext.ResourceDetails.Id);          
            $rmContext = [ContextHelper]::GetCurrentContext();
            $user = "";
            $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))
			$webRequestResult = Invoke-RestMethod -Uri $url -Method Put -ContentType "application/json" -Headers @{Authorization = ("Basic {0}" -f $base64AuthInfo) } -Body $body							    
            $controlResult.AddMessage([VerificationResult]::Fixed,  "Permission for broader groups have been changed as below: ");
            $display = ($RawDataObjForControlFix |  FT -AutoSize | Out-String -Width 512)
            $controlResult.AddMessage("`n$display");
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
            $controlResult.LogException($_)
        }        
        return $controlResult;
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
                $controlResult.AddMessage([VerificationResult]::Failed, "Environment is accessible to all YAML pipelines.");
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Environment is not accessible to all YAML pipelines.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch environment's pipeline permission setting.");
            $controlResult.LogException($_)
        }
       return $controlResult
    }

    hidden [ControlResult] CheckPreDeploymentApprovalOnEnv([ControlResult] $controlResult){
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try{
            $url = "https://dev.azure.com/{0}/{1}/_apis/pipelines/checks/configurations?resourceType=environment&resourceId={2}&api-version=6.1-preview.1" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName, $this.ResourceContext.ResourceDetails.Id;
            $response = [WebRequestHelper]::InvokeGetWebRequest($url);
            if([Helpers]::CheckMember($response, "count") -and $response[0].count -eq 0){
                $controlResult.AddMessage([VerificationResult]::Failed, "No approvals and checks have been defined for the environment.");
            }
            else{
                $approvals = @($response | Where-Object{$_.type.name -eq "Approval"})
                if($approvals.Count -eq 0){
                    $controlResult.AddMessage([VerificationResult]::Failed, "No approvals have been defined for the environment.");
                }
                else{
                    $controlResult.AddMessage([VerificationResult]::Passed, "Approvals have been enabled for the environment.");
                }
            }

        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch approvals and checks on the environment.");
        }
        return $controlResult
    }

    hidden [ControlResult] CheckPreDeploymentApproversOnEnv([ControlResult] $controlResult){
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try{
            $url = "https://dev.azure.com/{0}/{1}/_apis/pipelines/checks/queryconfigurations?`$expand=settings&api-version=6.1-preview.1" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName;
            #using ps invoke web request instead of helper method, as post body (json array) not supported in helper method
            $rmContext = [ContextHelper]::GetCurrentContext();
            $user = "";
            $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))  
            $body = "[{'name':  '$($this.ResourceContext.ResourceDetails.Name)','id':  '$($this.ResourceContext.ResourceDetails.Id)','type':  'environment'}]"
            $response = @(Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $body)
            if([Helpers]::CheckMember($response, "count") -and $response[0].count -eq 0){
                $controlResult.AddMessage([VerificationResult]::Failed, "No approvals and checks have been defined for the environment.");
            }
            else{
                $approvals = @($response.value | Where-Object{$_.type.name -eq "Approval"})
                if($approvals.Count -eq 0){
                    $controlResult.AddMessage([VerificationResult]::Failed, "No approvals have been defined for the environment.");
                }
                else{
                  $approvers = $approvals.settings.approvers | Select @{n='Approver name';e={$_.displayName}},@{n='Approver id';e = {$_.uniqueName}}
                    $formattedApproversTable = ($approvers| FT -AutoSize | Out-String -width 512)
                    $controlResult.AddMessage("`nList of approvers : `n$formattedApproversTable");
                    $controlResult.AdditionalInfo += "List of approvers on environment  $($approvers).";
                    $controlResult.AddMessage([VerificationResult]::Verify, "Validate users/groups added as approver within the environment.");
                }
            }

        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch list of approvers on the environment.");
        }
        return $controlResult
    }

    hidden [ControlResult] CheckBroaderGroupAccessOnEnvironment([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            if ([Helpers]::CheckMember($this.ControlSettings, "Environment.RestrictedBroaderGroupsForEnvironment")) {
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
                
                $excesiveEnvironmentPermissions = @($roleAssignmentsToCheck | Where-Object { $restrictedBroaderGroups.keys -contains $_.identity.displayName.split('\')[-1] -and ($_.role.name -in $restrictedBroaderGroups[$_.identity.displayName.split('\')[-1]])})
                $environmentWithBroaderGroup = @($excesiveEnvironmentPermissions | Select-Object -Property @{Name="EnvironmentName"; Expression = {$this.ResourceContext.ResourceName}},@{Name="Role"; Expression = {$_.role.name}},@{Name="Name"; Expression = {$_.identity.displayName}}) ;

                if ($this.ControlSettings.CheckForBroadGroupMemberCount -and $environmentWithBroaderGroup.Count -gt 0)
                {
                    $broaderGroupsWithExcessiveMembers = @([ControlHelper]::FilterBroadGroupMembers($environmentWithBroaderGroup, $true))
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
                $controlResult.AddMessage("`nNote: `nThe following groups are considered 'broader groups': `n$($displayObj | FT -AutoSize | out-string)");
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

    hidden [ControlResult] CheckBranchHygieneOnEnv([ControlResult] $controlResult){
        try{
            $url = "https://dev.azure.com/{0}/{1}/_apis/pipelines/checks/queryconfigurations?`$expand=settings&api-version=6.1-preview.1" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName;
            #using ps invoke web request instead of helper method, as post body (json array) not supported in helper method
            $rmContext = [ContextHelper]::GetCurrentContext();
            $user = "";
            $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))  
            $body = "[{'name':  '$($this.ResourceContext.ResourceDetails.Name)','id':  '$($this.ResourceContext.ResourceDetails.Id)','type':  'environment'}]"
            $response = @(Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $body)
            if([Helpers]::CheckMember($response, "count") -and $response[0].count -eq 0){
                $controlResult.AddMessage([VerificationResult]::Failed, "No approvals and checks have been defined for the environment.");
            }
            else{
                $branchControl = @()
                try{
                    $branchControl = @($response.value | Where-Object {$_.PSObject.Properties.Name -contains "settings"})
                    $branchControl = @($branchControl.settings | Where-Object {$_.PSObject.Properties.Name -contains "displayName" -and $_.displayName -eq "Branch Control"})
                }
                catch{
                    $branchControl = @()
                }
                if($branchControl.Count -eq 0){
                    $controlResult.AddMessage([VerificationResult]::Failed, "Branch control has not been defined for the environment.");
                }
                else{
                    #response is a string of branches seperaed via comma
                    $branches = ($branchControl.inputs.allowedBranches).Split(",");
                    $nonPermissibleBranchesFound = $false
                    foreach($branch in $branches){
                        try{
                            #allowed format is refs/heads/branch
                            $branch = ($branch -split 'refs/heads/')[1]
                        }
                        catch{
                            #to catch branch names like *, refs/tags etc.
                            $nonPermissibleBranchesFound = $true;
                            break;
                        }                        
                        if($branch -notin $this.ControlSettings.Build.BranchesToCheckForYAMLScript){
                            $nonPermissibleBranchesFound = $true;
                            break;
                        }
                    }
                    if($nonPermissibleBranchesFound -eq $false){
                        $controlResult.AddMessage([VerificationResult]::Passed, "Deployments to the environment is allowed via standard branches only.");
                    }
                    else{
                        $controlResult.AddMessage([VerificationResult]::Verify, "Validate the branches approved for deployment to the environment.");
                    }
                    $branches = $branches | Select @{n='Branch name';e={$_}}
                    $formattedBranchesTable = ($branches| FT -AutoSize | Out-String -width 512)
                    $controlResult.AddMessage("`nList of branches : `n$formattedBranchesTable");
                    $controlResult.AdditionalInfo += "List of branches approved on environment  $($branches).";
                    
                }
            }

        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch branch control checks on the environment.");
        }
        return $controlResult
    }
    
    hidden [ControlResult] CheckBuildSvcAccAccessOnFeeds([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            #orgFeedURL will be used to identify if feed is org scoped or project scoped
            $scope = "Project"
            #Project property does not exist of org scoped feeds
            if ("Project" -notin $this.ResourceContext.ResourceDetails.PSobject.Properties.name){
                $url = 'https://{0}.feeds.visualstudio.com/_apis/Packaging/Feeds/{1}/Permissions?includeIds=true&excludeInheritedPermissions=false&includeDeletedFeeds=false' -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceDetails.Id;
                $controlResult.AddMessage("`n***Organization scoped feed***")
                $scope = "Organization"
            }
            else {
                $url = 'https://{0}.feeds.visualstudio.com/{1}/_apis/Packaging/Feeds/{2}/Permissions?includeIds=true&excludeInheritedPermissions=false&includeDeletedFeeds=false' -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName, $this.ResourceContext.ResourceDetails.Id;
                $controlResult.AddMessage("`n***Project scoped feed***")
            }
            $feedPermissionList = @([WebRequestHelper]::InvokeGetWebRequest($url));

            $restrictedRolesForBroaderGroupsInFeeds = $this.ControlSettings.Feed.RestrictedRolesForBuildSvcAccountsInFeed;

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

                $groups = $feedWithBuildSvcAcc | ForEach-Object { $_.DisplayName + ': ' + $_.Role } 
                $controlResult.AdditionalInfoInCSV = "$($groups -join ' ; ')"

                #Fetching identity used to publish last 10 packages
                $accUsedToPublishPackage = $this.ValidateBuildSvcAccInPackage($scope, $true);
                if ($accUsedToPublishPackage.packagesInfo.count -gt 0)
                {
                    $controlResult.AddMessage("`nList of last 10 published packages and identity used to publish: ", ($accUsedToPublishPackage.packagesInfo | FT | Out-String -Width 512))
                    $uniqueIdentities = $accUsedToPublishPackage.packagesInfo | select-object -Property IdentityName -Unique
                    $controlResult.AdditionalInfo += "List of identities used to publish last 10 packages: $($uniqueIdentities.IdentityName -join ', ')";
                    $controlResult.AdditionalInfoInCSV += "; Last 10 publishers: $($uniqueIdentities.IdentityName -join ', ')";
                }
                else
                {
                    $controlResult.AdditionalInfo += "No package found";
                    $controlResult.AdditionalInfoInCSV += "; No package found";
                }

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
                $controlResult.AdditionalInfoInCSV = "NA";
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
                    $isBuildSVcAccUsedToPublishPackage = $this.ValidateBuildSvcAccInPackage($scope, $false);
                }

                if ($isBuildSVcAccUsedToPublishPackage.isBuildSvcAccUsed -eq $false)
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

    hidden [psobject] ValidateBuildSvcAccInPackage($scope, $detailedList)
    {
        $isBuildSvsAccUsed = $false
        $packagesInfo = @()
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

            if ( $packageList.Count -gt 0 -and [Helpers]::CheckMember($packageList[0],"Id"))
            {
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

                    $pkgDetails = New-Object -TypeName PSObject
                    $pkgDetails | Add-Member -NotePropertyName PackageName -NotePropertyValue $package.name
                    $pkgDetails | Add-Member -NotePropertyName IdentityName -NotePropertyValue $provenanceDetails.provenance.data.'Common.IdentityDisplayName'

                    $packagesInfo += $pkgDetails 

                    if (-not $detailedList)
                    {
                        if ($provenanceDetails.provenance.data.'Common.IdentityDisplayName' -like "*Project Collection Build Service ($($this.OrganizationContext.OrganizationName))" -or $provenanceDetails.provenance.data.'Common.IdentityDisplayName' -like "*Build Service ($($this.OrganizationContext.OrganizationName))")
                        {
                            $isBuildSvsAccUsed = $true
                            break;
                        }
                    }
                }
            }
        }
        catch
        {
            #eat exception
        }
        $returnObj = New-Object -TypeName PSObject
        $returnObj | Add-Member -NotePropertyName isBuildSvcAccUsed -NotePropertyValue $isBuildSvsAccUsed
        $returnObj | Add-Member -NotePropertyName packagesInfo -NotePropertyValue $packagesInfo 

        return $returnObj
    }

    hidden [ControlResult] CheckBuildSvcAcctAccessOnRepository([ControlResult] $controlResult)
	{
        $controlResult.VerificationResult = [VerificationResult]::Failed
        $excessivePermissions = $this.ControlSettings.Repo.RestrictedRolesForBuildSvcAccountsInRepo
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
                # fetch the groups that have access to the repo
                $groupPermissionsBody = '{"contributionIds":["ms.vss-admin-web.security-view-permissions-data-provider"],"dataProviderContext":{"properties":{"subjectDescriptor":"","permissionSetId":"2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87","permissionSetToken":"","accountName":"","sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"repositories","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json
                $groupPermissionsBody.dataProviderContext.properties.sourcePage.url = $refererUrl
                $groupPermissionsBody.dataProviderContext.properties.sourcePage.routeValues.Project = $this.ResourceContext.ResourceGroupName;
                $groupPermissionsBody.dataProviderContext.properties.permissionSetToken = "repoV2/$($this.ResourceContext.ResourceDetails.Project.id)/$($this.ResourceContext.ResourceDetails.id)"
                $buildServieAccountOnRepo = @()
                $groupsWithExcessivePermissionsList = @()
                foreach ($identity in $repositoryIdentities)
                {
                    if ($identity.displayName -like '*Project Collection Build Service Accounts' -or $identity.displayName -like "*Project Collection Build Service ($($this.OrganizationContext.OrganizationName))" -or $identity.displayName -like "*Build Service ($($this.OrganizationContext.OrganizationName))") {
                        $groupPermissionsBody.dataProviderContext.properties.subjectDescriptor = $identity.descriptor    
                        $responseObj = [WebRequestHelper]::InvokePostWebRequest($url, $groupPermissionsBody);
                        $buildServiceAccountRbacObj = @($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-permissions-data-provider'.subjectPermissions)
                        $excessivePermissionList = $buildServiceAccountRbacObj | Where-Object { $_.displayName -in $excessivePermissions }
                        $excessivePermissionsPerGroup = @()
                        $excessivePermissionList | ForEach-Object {
                            #effectivePermissionValue equals to 1 implies edit build pipeline perms is set to 'Allow'. Its value is 3 if it is set to Allow (inherited). This param is not available if it is 'Not Set'.
                            if ([Helpers]::CheckMember($_, "effectivePermissionValue")) {
                                if ($this.excessivePermissionBitsForRepo -contains $_.effectivePermissionValue) {
                                    $excessivePermissionsPerGroup += $_
                                }
                            }
                        }   
                        if ($excessivePermissionsPerGroup.Count -gt 0) {
                            $groupFoundWithExcessivePermissions = $true
                            # For PCBSA, resolve the group and check if PBS, PCBS are part of it
                            if ($identity.displayName -like '*Project Collection Build Service Accounts') {
                                $groupFoundWithExcessivePermissions = $false
                                $url="https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.1-preview" -f $($this.OrganizationContext.OrganizationName);                                
                                $postbody=@'
                                {"contributionIds":["ms.vss-admin-web.org-admin-members-data-provider"],"dataProviderContext":{"properties":{"subjectDescriptor":"{0}","sourcePage":{"url":"https://dev.azure.com/{2}/_settings/groups?subjectDescriptor={1}","routeId":"ms.vss-admin-web.collection-admin-hub-route","routeValues":{"adminPivot":"groups","controller":"ContributedPage","action":"Execute"}}}}}
'@
                                $postbody=$postbody.Replace("{0}",$identity.descriptor )
                                $postbody=$postbody.Replace("{1}",$this.OrganizationContext.OrganizationName)
                                $rmContext = [ContextHelper]::GetCurrentContext();
                                $user = "";
                                $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))   
                                try {
                                    $response = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $postbody
                                    if([Helpers]::CheckMember($response.dataProviders.'ms.vss-admin-web.org-admin-members-data-provider', "identities"))
                                    {
                                        $buildServiceAccountIdentities = $response.dataProviders.'ms.vss-admin-web.org-admin-members-data-provider'.identities
                                        foreach ($eachIdentity in $buildServiceAccountIdentities) {
                                          if ($eachIdentity.displayName -like "*Project Collection Build Service ($($this.OrganizationContext.OrganizationName))" -or $eachIdentity.displayName -like "*Build Service ($($this.OrganizationContext.OrganizationName))") {

                                                $groupFoundWithExcessivePermissions = $true                                          
                                            }                                        
                                        }
                                    } 
                                }    
                                catch {}                    
                            }
                            if ($groupFoundWithExcessivePermissions -eq $true) {
                                $excessivePermissionsGroupObj = @{}
                                $excessivePermissionsGroupObj['Group'] = $identity.displayName
                                $excessivePermissionsGroupObj['ExcessivePermissions'] = $($excessivePermissionsPerGroup.displayName -join '; ')
                                $excessivePermissionsGroupObj['Descriptor'] = $responseObj[0].dataProviders.'ms.vss-admin-web.security-view-permissions-data-provider'.identityDescriptor
                                $excessivePermissionsGroupObj['PermissionSetToken'] = $excessivePermissionsPerGroup[0].token
                                $groupsWithExcessivePermissionsList += $excessivePermissionsGroupObj
                            }
                        }                 
                    }

                }
                if ($groupsWithExcessivePermissionsList.count -gt 0) {
                    #TODO: Do we need to put state object?
                    $controlResult.AddMessage([VerificationResult]::Failed, "Count of restricted Build Service groups that have access to repository: $($groupsWithExcessivePermissionsList.count)");
                    $formattedGroupsData = $groupsWithExcessivePermissionsList | Select @{l = 'Group'; e = { $_.Group} }, @{l = 'ExcessivePermissions'; e = { $_.ExcessivePermissions } }
                    $formattedBroaderGrpTable = ($formattedGroupsData | Out-String  -Width 512 )
                    $controlResult.AddMessage("`nList of 'Build Service' Accounts: $formattedBroaderGrpTable");
                    $controlResult.SetStateData("List of 'Build Service' Accounts: ", $formattedGroupsData)
                    $additionalInfoInCSV = $formattedGroupsData | ForEach-Object { $_.Group + ': ' + $_.ExcessivePermissions }
                    $additionalInfoInCSV = $additionalInfoInCSV -join ' ; ' 
                    $controlResult.AdditionalInfo += "Count of restricted Build Service groups that have access to repository: $($groupsWithExcessivePermissionsList.Count)";
                    $controlResult.AdditionalInfoInCSV+= "'Repo' level excessive permissions: $($additionalInfoInCSV); "  

                    if ($this.ControlFixBackupRequired)
                    {
                        #Data object that will be required to fix the control
                        $controlResult.BackupControlState = $groupsWithExcessivePermissionsList;
                    }
                }

                else {
                    $controlResult.AddMessage([VerificationResult]::Passed,"Build Service accounts are not granted access to the repository.");
                    $controlResult.AdditionalInfoInCSV = "NA";
                }
            }
            else{
                $controlResult.AddMessage([VerificationResult]::Error,"Unable to fetch repository permission details.");
            }
            $controlResult.AddMessage("`nNote:`nFollowing permissions are considered 'excessive':`n$($excessivePermissions | FT -AutoSize | Out-String -Width 512)");
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,"Unable to fetch repository permission details.");
            $controlResult.LogException($_)
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckBuildSvcAcctAccessOnRepositoryAutomatedFix([ControlResult] $controlResult)
    {
        try{
            $RawDataObjForControlFix = @();
            $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject
            $url = "https://dev.azure.com/{0}/_apis/AccessControlEntries/{1}?api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $this.repoPermissionSetId

            if (-not $this.UndoFix) {
                foreach ($identity in $RawDataObjForControlFix) 
                {   
                    $excessivePermissions = $identity.ExcessivePermissions -split ";"
                    $descriptor = $identity.Descriptor
                    foreach ($excessivePermission in $excessivePermissions) {
                        if ($excessivePermission.trim() -eq 'Force push (rewrite history, delete branches and tags)') {
                            $roleId = [int][RepoPermissions] 'Forcepush'
                        }
                        elseif ($excessivePermission.trim() -eq "Remove others' locks") {
                            $roleId = [int][RepoPermissions] 'Removeotherslocks'
                        }
                        else {
                            $roleId = [int][RepoPermissions] $excessivePermission.Replace(" ","").trim();  
                        }
                        #need to invoke a post request which does not accept all permissions added in the body at once
                        #hence need to call invoke seperately for each permission
                         $body = "{
                            'token': '$($identity.PermissionSetToken)',
                            'merge': true,
                            'accessControlEntries' : [{
                                'descriptor' : '$descriptor',
                                'allow':0,
                                'deny':$($roleId)                              
                            }]
                        }" | ConvertFrom-Json

                        $result = [WebRequestHelper]:: InvokePostWebRequest($url,$body)

                    }
                    $identity | Add-Member -NotePropertyName OldPermission -NotePropertyValue "Allow"
                    $identity | Add-Member -NotePropertyName NewPermission -NotePropertyValue "Deny"

                }
            }
            else {
                foreach ($identity in $RawDataObjForControlFix) 
                {                    
                    $descriptor = $identity.Descriptor
                    $excessivePermissions = $identity.ExcessivePermissions -split ";"
                    foreach ($excessivePermission in $excessivePermissions) {
                        if ($excessivePermission.trim() -eq 'Force push (rewrite history, delete branches and tags)') {
                            $roleId = [int][RepoPermissions] 'Forcepush'
                        }
                        elseif ($excessivePermission.trim() -eq "Remove others' locks") {
                            $roleId = [int][RepoPermissions] 'Removeotherslocks'
                        }
                        else {
                            $roleId = [int][RepoPermissions] $excessivePermission.Replace(" ","").trim();  
                        }
                        
                         $body = "{
                            'token': '$($identity.PermissionSetToken)',
                            'merge': true,
                            'accessControlEntries' : [{
                                'descriptor' : '$descriptor',
                                'allow':$($roleId),
                                'deny':0                              
                            }]
                        }" | ConvertFrom-Json

                        [WebRequestHelper]:: InvokePostWebRequest($url,$body)

                    }
                    $identity | Add-Member -NotePropertyName OldPermission -NotePropertyValue "Deny"
                    $identity | Add-Member -NotePropertyName NewPermission -NotePropertyValue "Allow"
                }
            }
            
            $controlResult.AddMessage([VerificationResult]::Fixed,  "Permissions for build service accounts have been changed as below: ");
            $formattedGroupsData = $RawDataObjForControlFix | Select @{l = 'Group'; e = { $_.Group } }, @{l = 'ExcessivePermissions'; e = { $_.ExcessivePermissions }}, @{l = 'OldPermission'; e = { $_.OldPermission }}, @{l = 'NewPermission'; e = { $_.NewPermission } }
            $display = ($formattedGroupsData |  FT -AutoSize | Out-String -Width 512)

            $controlResult.AddMessage("`n$display");
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }
    hidden [ControlResult] CheckCredentialsAndSecretsPolicyOnRepository([ControlResult] $controlResult) {
        # body for post request
        
        $controlResult.VerificationResult = [VerificationResult]::Failed
        $url = 'https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1' -f $($this.OrganizationContext.OrganizationName);
        $inputbody = '{"contributionIds": ["ms.vss-code-web.repository-policies-data-provider"],"dataProviderContext": {"properties": {"projectId": "","repositoryId": "","sourcePage": {"url": "","routeId": "ms.vss-admin-web.project-admin-hub-route","routeValues": {"project": "","adminPivot": "repositories","controller": "ContributedPage","action": "Execute"}}}}}' | ConvertFrom-Json
        $inputbody.dataProviderContext.properties.projectId = "$($this.ResourceContext.ResourceDetails.project.id)"
        $inputbody.dataProviderContext.properties.repositoryId = "$($this.ResourceContext.ResourceDetails.id)"
        $inputbody.dataProviderContext.properties.sourcePage.routeValues.project = "$($this.ResourceContext.ResourceDetails.project.Name)"
        $inputbody.dataProviderContext.properties.sourcePage.url = "https://dev.azure.com/{0}/{1}/_settings/repositories?repo={2}&_a=policiesMid" -f $($this.OrganizationContext.OrganizationName),$($this.ResourceContext.ResourceGroupName),$($this.ResourceContext.ResourceDetails.id)
                                                                    
        try {
            $response = [WebRequestHelper]::InvokePostWebRequest($url, $inputbody);
            if ([Helpers]::CheckMember($response, "dataProviders") -and $response.dataProviders.'ms.vss-code-web.repository-policies-data-provider' -and [Helpers]::CheckMember($response.dataProviders.'ms.vss-code-web.repository-policies-data-provider', "policyGroups")) {
                # fetching policy groups
                $policyGroups = $response.dataProviders."ms.vss-code-web.repository-policies-data-provider".policyGroups
                # fetching "Secrets scanning restriction"
                $credScanId = $this.ControlSettings.Repo.CredScanPolicyID
                if ([Helpers]::CheckMember($policyGroups, $credScanId )) {
                     $currentScopePoliciesSecrets = $policyGroups."$($credScanId)".currentScopePolicies
                    if($null -eq $currentScopePoliciesSecrets){
                        $currentScopePoliciesSecrets = $policyGroups."$($credScanId)".inheritedPolicies
                    }
                    if ([Helpers]::CheckMember($currentScopePoliciesSecrets, "isEnabled") -and $currentScopePoliciesSecrets.isEnabled) {
                        $controlResult.AddMessage([VerificationResult]::Passed, "Check for credentials and other secrets is enabled.");
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Failed, "Check for credentials and other secrets is disabled.");
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Policy to check for credentials and other secrets on the repository not found.");
                }
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch repository policies.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch repository policies.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckForInactiveFeeds([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            #orgFeedURL will be used to identify if feed is org scoped or project scoped
            $scope = "Project"
            #Project property does not exist of org scoped feeds
            if ("Project" -notin $this.ResourceContext.ResourceDetails.PSobject.Properties.name){
                $scope = "Organization"
            }

            if ($scope -eq "Organization")
            {
                $url = "https://{0}.feeds.visualstudio.com/_apis/Packaging/Feeds/{1}/Packages?includeDescription=true&includeDeleted=false" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceDetails.Id;
            }
            else
            {
                $url = "https://{0}.feeds.visualstudio.com/{1}/_apis/Packaging/Feeds/{2}/Packages?includeDescription=true&includeDeleted=false" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceDetails.project.id, $this.ResourceContext.ResourceDetails.Id;
            }

            $pakagesList = @([WebRequestHelper]::InvokeGetWebRequest($url));

            $inactiveLimit = $this.ControlSettings.FeedsAndPackages.ThreshHoldDaysForFeedsAndPackagesInactivity;

            if ($pakagesList.Count -gt 1)
            {
                $pakagesList = $pakagesList |Sort-Object -Property @{Expression={$_.versions[0].publishDate}} -Descending
                $latestPackage = $pakagesList[0] | select-object name, @{l="publishedDate"; e = {([datetime] $_.versions[0].publishDate).ToString("d MMM yyyy")}}, @{l="version";e={$_.versions.version}}, protocolType
                $lastPublishDate = $latestPackage.publishedDate
                if ((((Get-Date) - [datetime]::Parse($lastPublishDate)).Days) -gt $inactiveLimit)
                {
                    if ($scope -eq "Organization")
                    {
                        $packageUrl = "https://{0}.feeds.visualstudio.com/_apis/Packaging/Feeds/{1}/PackageMetricsBatch?api-version=5.1-preview.1" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceDetails.Id;
                    }
                    else
                    {
                        $packageUrl = "https://{0}.feeds.visualstudio.com/{1}/_apis/Packaging/Feeds/{2}/PackageMetricsBatch?api-version=5.1-preview.1" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceDetails.project.id, $this.ResourceContext.ResourceDetails.Id;
                    }

                    $body = "{'packageIds':['$($pakagesList.id -join "','")']}"
                    $rmContext = [ContextHelper]::GetCurrentContext();
                    $user = "";
                    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))  
                    $response = @(Invoke-RestMethod -Uri $packageUrl -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $body)
                    $lastDownloadedPackage = $response.value | sort-object lastDownloaded -descending | Select-Object -first 1
                    $lastDownloadedPackage = $lastDownloadedPackage | select-object @{l="Name";e={$pakagesList | Where-Object {$_.id -eq $lastDownloadedPackage.packageId}| Select-Object name}}, downloadCount, @{l="lastDownloaded"; e={([datetime] $_.lastDownloaded).ToString("d MMM yyyy")}}
                    $lastDownloadedDate = $lastDownloadedPackage.lastDownloaded

                    if ((((Get-Date) - [datetime]::Parse($lastDownloadedDate)).Days) -gt $inactiveLimit)
                    {
                        $controlResult.AddMessage([VerificationResult]::Failed,  "Feed was inactive from last $((((Get-Date) - [datetime]::Parse($lastDownloadedDate)).Days)) days.");
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed,  "Feed package was last downloaded on $(([datetime] $lastDownloadedDate).ToString("d MMM yyyy")).");
                    }
                    $lastDownloadedPackage = ($lastDownloadedPackage | FT -AutoSize | Out-String -Width 512)
                    $controlResult.AddMessage("`nLatest downloaded package in the feed: ", $lastDownloadedPackage);
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,  "Feed package was last published on $(([datetime] $lastPublishDate).ToString("d MMM yyyy")).");
                }
                $latestPackage = ($latestPackage | FT -AutoSize | Out-String -Width 512)
                $controlResult.AddMessage("`nLatest published package in the feed: ", $latestPackage);
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Failed,  "Feed does not contain any packages.");
            }         
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not fetch feed activity details.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }
}
