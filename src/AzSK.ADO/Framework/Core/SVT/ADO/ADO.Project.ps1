Set-StrictMode -Version Latest 
class Project: ADOSVTBase
{    
    [PSObject] $PipelineSettingsObj = $null
    hidden $PAMembers = @()

    Project([string] $subscriptionId, [SVTResource] $svtResource): Base($subscriptionId,$svtResource) 
    {
        $this.GetPipelineSettingsObj()
    }

    GetPipelineSettingsObj()
    {
        $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $($this.SubscriptionContext.SubscriptionName);
        #TODO: testing adding below line commenting above line
        #$apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $($this.SubscriptionContext.SubscriptionName);

        $orgUrl = "https://dev.azure.com/{0}" -f $($this.SubscriptionContext.SubscriptionName);
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

    hidden [ControlResult] CheckPublicProjects([ControlResult] $controlResult)
	{
        try 
        {
            if([Helpers]::CheckMember($this.ResourceContext.ResourceDetails,"visibility"))
            {
                $visibility = $this.ResourceContext.ResourceDetails.visibility;
                if(($visibility -eq "private") -or ($visibility -eq "organization"))
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "Project visibility is set to '$visibility'."); 

                }
                else # For orgs with public projects allowed, this control needs to be attested by the project admins. 
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Project visibility is set to '$visibility'.");
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
       if($this.PipelineSettingsObj)
       {
            
            if($this.PipelineSettingsObj.enforceSettableVar.enabled -eq $true )
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Only limited variables can be set at queue time. It is set as '$($this.PipelineSettingsObj.enforceSettableVar.orgEnabled)' at organization scope.");
            }
            else{
                $controlResult.AddMessage([VerificationResult]::Failed, "All variables can be set at queue time. It is set as '$($this.PipelineSettingsObj.enforceSettableVar.orgEnabled)' at organization scope.");
            }       
       }
       else{
            $controlResult.AddMessage([VerificationResult]::Manual, "Pipeline settings could not be fetched due to insufficient permissions at project scope.");
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
        $url = 'https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1' -f $($this.SubscriptionContext.SubscriptionName);
        $inputbody = '{"contributionIds":["ms.vss-admin-web.org-admin-groups-data-provider"],"dataProviderContext":{"properties":{"sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"permissions","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json
        $inputbody.dataProviderContext.properties.sourcePage.url = "https://dev.azure.com/$($this.SubscriptionContext.SubscriptionName)/$($this.ResourceContext.ResourceName)/_settings/permissions";
        $inputbody.dataProviderContext.properties.sourcePage.routeValues.Project =$this.ResourceContext.ResourceName;

        $groupsObj = [WebRequestHelper]::InvokePostWebRequest($url,$inputbody); 

        $Allgroups =  @()
         $groupsObj.dataProviders."ms.vss-admin-web.org-admin-groups-data-provider".identities  | ForEach-Object {
            $Allgroups += $_;
        }  

        $descrurl ='https://vssps.dev.azure.com/{0}/_apis/graph/descriptors/{1}?api-version=5.0-preview.1' -f $($this.SubscriptionContext.SubscriptionName), $this.ResourceContext.ResourceId.split('/')[-1];
        $descr = [WebRequestHelper]::InvokeGetWebRequest($descrurl);

        $apiURL = "https://vssps.dev.azure.com/{0}/_apis/Graph/Users?scopeDescriptor={1}" -f $($this.SubscriptionContext.SubscriptionName), $descr[0];
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
        $url = 'https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1' -f $($this.SubscriptionContext.SubscriptionName);
        $inputbody = '{"contributionIds":["ms.vss-admin-web.org-admin-groups-data-provider"],"dataProviderContext":{"properties":{"sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"permissions","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json
        $inputbody.dataProviderContext.properties.sourcePage.url = "https://dev.azure.com/$($this.SubscriptionContext.SubscriptionName)/$($this.ResourceContext.ResourceName)/_settings/permissions";
        $inputbody.dataProviderContext.properties.sourcePage.routeValues.Project =$this.ResourceContext.ResourceName;

        $groupsObj = [WebRequestHelper]::InvokePostWebRequest($url,$inputbody); 

        $groups =  @()
         $groupsObj.dataProviders."ms.vss-admin-web.org-admin-groups-data-provider".identities  | ForEach-Object {
            $groups += $_;
        } 
         
        $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview" -f $($this.SubscriptionContext.SubscriptionName);

        $membercount =0;
        Foreach ($group in $groups){
            $groupmember = @();
         $descriptor = $group.descriptor;
         $inputbody =  '{"contributionIds":["ms.vss-admin-web.org-admin-members-data-provider"],"dataProviderContext":{"properties":{"subjectDescriptor":"","sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"permissions","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json
                       
         $inputbody.dataProviderContext.properties.subjectDescriptor = $descriptor;
         $inputbody.dataProviderContext.properties.sourcePage.url = "https://dev.azure.com/$($this.SubscriptionContext.SubscriptionName)/$($this.ResourceContext.ResourceName)/_settings/permissions?subjectDescriptor=$($descriptor)";
         $inputbody.dataProviderContext.properties.sourcePage.routeValues.Project =$this.ResourceContext.ResourceName;

         $usersObj = [WebRequestHelper]::InvokePostWebRequest($apiURL,$inputbody);

         $usersObj.dataProviders."ms.vss-admin-web.org-admin-members-data-provider".identities  | ForEach-Object {
            $groupmember += $_;
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
        $TotalPAMembers = 0;
        if (($this.PAMembers | Measure-Object).Count -eq 0) {
            $this.PAMembers += [AdministratorHelper]::GetTotalPAMembers($this.SubscriptionContext.SubscriptionName,$this.ResourceContext.ResourceName)
            $this.PAMembers = $this.PAMembers | Select-Object displayName,mailAddress
        }
        $TotalPAMembers = ($this.PAMembers | Measure-Object).Count
        $controlResult.AddMessage("There are a total of $TotalPAMembers Project Administrators in your project.")
        if($TotalPAMembers -lt $this.ControlSettings.Project.MinPAMembersPermissible){
            $controlResult.AddMessage([VerificationResult]::Failed,"Number of administrators configured are less than the minimum required administrators count: $($this.ControlSettings.Project.MinPAMembersPermissible).");
        }
        else{
            $controlResult.AddMessage([VerificationResult]::Passed,"Number of administrators configured are more than the minimum required administrators count: $($this.ControlSettings.Project.MinPAMembersPermissible).");
        }
        if($TotalPAMembers -gt 0){
            $controlResult.AddMessage("Verify the following Project Administrators: ",$this.PAMembers)
            $controlResult.SetStateData("List of Project Administrators: ",$this.PAMembers)
            $controlResult.AdditionalInfo += "Total number of Project Administrators: " + $TotalPAMembers;
        }    
        return $controlResult
    }

    hidden [ControlResult] CheckMaxPACount([ControlResult] $controlResult)
    {
        $TotalPAMembers = 0;
        if (($this.PAMembers | Measure-Object).Count -eq 0) {
            $this.PAMembers += [AdministratorHelper]::GetTotalPAMembers($this.SubscriptionContext.SubscriptionName,$this.ResourceContext.ResourceName)
            $this.PAMembers = $this.PAMembers | Select-Object displayName,mailAddress
        }
        $TotalPAMembers = ($this.PAMembers | Measure-Object).Count
        $controlResult.AddMessage("There are a total of $TotalPAMembers Project Administrators in your project.")
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
        return $controlResult
    }

    hidden [ControlResult] CheckSCALTForAdminMembers([ControlResult] $controlResult)
    {
        try
        {
            if(($null -ne $this.ControlSettings) -and [Helpers]::CheckMember($this.ControlSettings, "Project.GroupsToCheckForSCAltMembers"))
            {

                $adminGroupNames = $this.ControlSettings.Project.GroupsToCheckForSCAltMembers;
                if (($adminGroupNames | Measure-Object).Count -gt 0) 
                {
                    #api call to get descriptor for organization groups. This will be used to fetch membership of individual groups later.
                    $url = 'https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1' -f $($this.SubscriptionContext.SubscriptionName);
                    $inputbody = '{"contributionIds":["ms.vss-admin-web.org-admin-groups-data-provider"],"dataProviderContext":{"properties":{"sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"permissions","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json
                    $inputbody.dataProviderContext.properties.sourcePage.url = "https://dev.azure.com/$($this.SubscriptionContext.SubscriptionName)/$($this.ResourceContext.ResourceName)/_settings/permissions";
                    $inputbody.dataProviderContext.properties.sourcePage.routeValues.Project = $this.ResourceContext.ResourceName;
        
                    $response = [WebRequestHelper]::InvokePostWebRequest($url, $inputbody);    
                    
                    if ($response -and [Helpers]::CheckMember($response[0], "dataProviders") -and $response[0].dataProviders."ms.vss-admin-web.org-admin-groups-data-provider") 
                    {
                        $adminGroups = @();
                        $adminGroups += $response.dataProviders."ms.vss-admin-web.org-admin-groups-data-provider".identities | where { $_.displayName -in $adminGroupNames }
                        
                        if(($adminGroups | Measure-Object).Count -gt 0)
                        {
                            #global variable to track admin members across all admin groups
                            $allAdminMembers = @();
                            
                            for ($i = 0; $i -lt $adminGroups.Count; $i++) 
                            {
                                # [AdministratorHelper]::AllPAMembers is a static variable. Always needs ro be initialized. At the end of each iteration, it will be populated with members of that particular admin group.
                                [AdministratorHelper]::AllPAMembers = @();
                                # Helper function to fetch flattened out list of group members.
                                [AdministratorHelper]::FindPAMembers($adminGroups[$i].descriptor,  $this.SubscriptionContext.SubscriptionName, $this.ResourceContext.ResourceName)
                                
                                $groupMembers = @();
                                # Add the members of current group to this temp variable.
                                $groupMembers += [AdministratorHelper]::AllPAMembers
                                # Create a custom object to append members of current group with the group name. Each of these custom object is added to the global variable $allAdminMembers for further analysis of SC-Alt detection.
                                $groupMembers | ForEach-Object {$allAdminMembers += @( [PSCustomObject] @{ name = $_.displayName; mailAddress = $_.mailAddress; id = $_.originId; groupName = $adminGroups[$i].displayName } )} 
                            }
                            
                            # clearing cached value in [AdministratorHelper]::AllPAMembers as it can be used in attestation later and might have incorrect group loaded.
                            [AdministratorHelper]::AllPAMembers = @();
                            # Filtering out distinct entries. A user might be added directly to the admin group or might be a member of a child group of the admin group.
                            $allAdminMembers = $allAdminMembers| Sort-Object -Property id -Unique

                            if(($allAdminMembers | Measure-Object).Count -gt 0)
                            {
                                if([Helpers]::CheckMember($this.ControlSettings, "AlernateAccountRegularExpressionForOrg")){
                                    $matchToSCAlt = $this.ControlSettings.AlernateAccountRegularExpressionForOrg
                                    #currently SC-ALT regex is a singleton expression. In case we have multiple regex - we need to make the controlsetting entry as an array and accordingly loop the regex here.
                                    if (-not [string]::IsNullOrEmpty($matchToSCAlt)) 
                                    {
                                        $nonSCMembers = @();
                                        $nonSCMembers += $allAdminMembers | Where-Object { $_.mailAddress -notmatch $matchToSCAlt }
                                        $nonSCCount = ($nonSCMembers | Measure-Object).Count

                                        $SCMembers = @();
                                        $SCMembers += $allAdminMembers | Where-Object { $_.mailAddress -match $matchToSCAlt }   
                                        $SCCount = ($SCMembers | Measure-Object).Count

                                        if ($nonSCCount -gt 0) 
                                        {
                                            $nonSCMembers = $nonSCMembers | Select-Object name,mailAddress,groupName
                                            $stateData = @();
                                            $stateData += $nonSCMembers
                                            $controlResult.AddMessage([VerificationResult]::Failed, "`nTotal number of non SC-ALT accounts with admin privileges: $nonSCCount"); 
                                            $controlResult.AddMessage("Review the non SC-ALT accounts with admin privileges: ", $stateData);  
                                            $controlResult.SetStateData("List of non SC-ALT accounts with admin privileges: ", $stateData);
                                            $controlResult.AdditionalInfo += "Total number of non SC-ALT accounts with admin privileges: " + $nonSCCount;
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
                                            $controlResult.AddMessage("`nTotal number of SC-ALT accounts with admin privileges: $SCCount");
                                            $controlResult.AdditionalInfo += "Total number of SC-ALT accounts with admin privileges: " + $SCCount;  
                                            $controlResult.AddMessage("SC-ALT accounts with admin privileges: ", $SCData);  
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
        }
       
        return $controlResult
    }

    hidden [ControlResult] CheckFeedAccess([ControlResult] $controlResult)
    {
        try
        {
            $url = 'https://feeds.dev.azure.com/{0}/{1}/_apis/packaging/feeds?api-version=6.0-preview.1' -f $this.SubscriptionContext.SubscriptionName, $this.ResourceContext.ResourceName;
            $feedsObj = [WebRequestHelper]::InvokeGetWebRequest($url); 

            $feedsWithUploadPkgPermission = @();
            $GroupsToCheckForFeedPermission = $null;
            if (($feedsObj | Measure-Object).Count -gt 0) 
            {
                $controlResult.AddMessage("Total number of feeds found: $($feedsObj.count)")

                if ([Helpers]::CheckMember($this.ControlSettings.Project, "GroupsToCheckForFeedPermission")) {
                    $GroupsToCheckForFeedPermission = $this.ControlSettings.Project.GroupsToCheckForFeedPermission
                }
                
                foreach ($feed in $feedsObj) 
                {
                    #GET https://feeds.dev.azure.com/{organization}/{project}/_apis/packaging/Feeds/{feedId}/permissions?api-version=6.0-preview.1
                    #Using visualstudio api because new api (dev.azure.com) is giving null in the displayName property.
                    $url = 'https://{0}.feeds.visualstudio.com/{1}/_apis/Packaging/Feeds/{2}/Permissions?includeIds=true&excludeInheritedPermissions=false&includeDeletedFeeds=false' -f $this.SubscriptionContext.SubscriptionName, $this.ResourceContext.ResourceName, $feed.Id;
                    $feedPermissionObj = [WebRequestHelper]::InvokeGetWebRequest($url); 

                    $feedsPermission = ($feedPermissionObj | Where-Object {$_.role -eq "administrator" -or $_.role -eq "contributor"}) | Select-Object -Property @{Name="FeedName"; Expression = {$feed.name}},@{Name="Role"; Expression = {$_.role}},@{Name="DisplayName"; Expression = {$_.displayName}} ;
                    $feedsWithUploadPkgPermission += $feedsPermission | Where-Object { $GroupsToCheckForFeedPermission -contains $_.DisplayName.split('\')[-1] }
                }
            }
 
            $feedCount = ($feedsWithUploadPkgPermission | Measure-Object).Count;
            if ($feedCount -gt 0) 
            {
                $controlResult.AddMessage("`nNote: The following groups are considered as 'critical': [$GroupsToCheckForFeedPermission]");
                $controlResult.AddMessage("`nTotal number of feeds that have contributor/administrator permission: $feedCount");
                $controlResult.AddMessage([VerificationResult]::Failed, "List of feeds that have contributor/administrator permission: ");

                $display = ($feedsWithUploadPkgPermission |  FT FeedName, Role, DisplayName -AutoSize | Out-String -Width 512)
                $controlResult.AddMessage($display)
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed,  "No feeds found in the project.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Passed,  "Could not fetch project feed settings.");
        }
        return $controlResult
    }
    
    hidden [ControlResult] CheckEnviornmentAccess([ControlResult] $controlResult)
    {
        try
        {
            $apiURL = "https://dev.azure.com/{0}/{1}/_apis/distributedtask/environments?api-version=6.0-preview.1" -f $($this.SubscriptionContext.SubscriptionName), $($this.ResourceContext.ResourceName);
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
                    $url = "https://dev.azure.com/{0}/{1}/_apis/pipelines/pipelinePermissions/environment/{2}" -f $($this.SubscriptionContext.SubscriptionName), $($this.ResourceContext.ResourceDetails.id), $($item.id);
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
        }
       return $controlResult
    }
    
    hidden [ControlResult] CheckSecureFilesPermission([ControlResult] $controlResult) {
        # getting the project ID
        $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
        $url = "https://dev.azure.com/$($this.SubscriptionContext.SubscriptionName)/$($projectId)/_apis/distributedtask/securefiles?api-version=6.1-preview.1"
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
                    $url = "https://dev.azure.com/$($this.SubscriptionContext.SubscriptionName)/$($projectId)/_apis/build/authorizedresources?type=securefile&id=$($secFile.id)"
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
                }
                # there are no secure files present that are authorized
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "There are no secure files in the project that are authorized for use in all pipelines.");
                }
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of secure files.");
        }
        return $controlResult
    }

    hidden [ControlResult] CheckTaskGroupReference([ControlResult] $controlResult)
    {
        $sw = [System.Diagnostics.Stopwatch]::StartNew();
        try
        {
            $apiURL = "https://dev.azure.com/{0}/{1}/_apis/distributedtask/taskgroups?api-version=6.0-preview.1" -f $($this.SubscriptionContext.SubscriptionName), $($this.ResourceContext.ResourceDetails.id);
            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
            if(($responseObj | Measure-Object).Count -gt 0 )
            {
                $controlResult.AddMessage("Total number of task groups in the project: $(($responseObj | Measure-Object).Count)");
                $activeTG = @();
                $inactiveTG = @();
                $i = 0;
                Write-Host " Total TG : $(($responseObj | Measure-Object).Count)";
                foreach ($item in $responseObj) 
                {
                    try
                    {
                        $buildURL = "https://dev.azure.com/{0}/{1}/_apis/build/Definitions?taskIdFilter={2}" -f $($this.SubscriptionContext.SubscriptionName), $($this.ResourceContext.ResourceDetails.id), $($item.id);
                        $apiBuildResponse = [WebRequestHelper]::InvokeGetWebRequest($buildURL);
                        if((-not ([Helpers]::CheckMember($apiBuildResponse[0],"count",$false))) -and ($apiBuildResponse.Count -gt 0))
                        {
                            #$buildWithReference += $apiBuildResponse | Select-Object id, name;
                            $foundActiveBuild = $this.CheckBuildReferenceforTG($apiBuildResponse);
                        }
                        else {
                            $foundActiveBuild = $false;
                        }
                        $apiBuildResponse = $null;
                    }
                    catch
                    {
                        #Ingnore;
                        $foundActiveBuild = $false;
                    }
                    $foundActiveRelease = $false;
                    if(-not $foundActiveBuild){
                    try 
                    {
                        $releaseURL = "https://vsrm.dev.azure.com/{0}/{1}/_apis/Release/definitionEnvironments?taskGroupId={2}" -f $($this.SubscriptionContext.SubscriptionName), $($this.ResourceContext.ResourceDetails.id), $($item.id);
                        $apiReleaseResponse = [WebRequestHelper]::InvokeGetWebRequest($releaseURL);
                        if((-not ([Helpers]::CheckMember($apiReleaseResponse[0],"count",$false))) -and ($apiReleaseResponse.Count -gt 0))
                        {
                            #$releaseWithReference += $apiReleaseResponse | Select-Object releaseDefinitionId, releaseDefinitionName;
                            $foundActiveRelease = $this.CheckReleaseReferenceforTG($apiReleaseResponse);
                        }
                        else {
                            $foundActiveRelease = $false;
                        }
                        $apiReleaseResponse = $null;
                    }
                    catch
                    {
                        #Ignore;
                        $foundActiveRelease = $false;
                    }
                    }

                    if($foundActiveBuild -or $foundActiveRelease)
                    {
                        $activeTG += $item | Select-Object id, name;
                    }
                    else {
                        $inactiveTG += $item | Select-Object id, name;
                    }
                    
                    Write-Host "[ $i ] Completed TG [$($item.name)] : $($sw.Elapsed)";
                    $i = $i+1;
                }

                $inactiveTGCount = ($inactiveTG | Measure-Object).Count;
                $activeTGCount = ($activeTG | Measure-Object).Count;
                if($inactiveTGCount -gt 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Inactive task groups was found in the project.");
                    $controlResult.AddMessage("Total number of inactive task groups in the project: $($inactiveTGCount)");
                    $controlResult.AddMessage("List of inactive task groups in the project: ", $inactiveTG);
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No inactive task groups was found in the project.");
                    $controlResult.AddMessage("Total number of active task groups in the project: $($activeTGCount)");
                    $controlResult.AddMessage("List of active task groups in the project: ", $activeTG);
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "No task groups was found in the project.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of task groups in the project.");
        }
        $sw.Stop();
        $controlResult.AddMessage("Total execution time taken by core function : $($sw.Elapsed)");
       return $controlResult
    }

    hidden [bool] CheckBuildReferenceforTG([PSObject] $builds)
    {
        if (($builds | Measure-Object).Count -gt 0)
        {
            foreach ($build in $builds) 
            {
                $buildURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery/project/{1}?api-version=5.0-preview.1" -f $($this.SubscriptionContext.SubscriptionName),$($this.ResourceContext.ResourceDetails.id);
                $orgURL='https://dev.azure.com/{0}/{1}/_build?view=folders' -f $($this.SubscriptionContext.SubscriptionName),$($this.ResourceContext.ResourceName)
                $inputbody1="{'contributionIds':['ms.vss-build-web.pipelines-data-provider'],'dataProviderContext':{'properties':{'definitionIds':'$($build.id)','sourcePage':{'url':'$orgURL','routeId':'ms.vss-build-web.pipelines-hub-route','routeValues':{'project':'$($this.ResourceContext.ResourceName)','viewname':'pipelines','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json
                $responseBuildObj = [WebRequestHelper]::InvokePostWebRequest($buildURL,$inputbody1);
                if([Helpers]::CheckMember($responseBuildObj,"dataProviders") -and $responseBuildObj.dataProviders.'ms.vss-build-web.pipelines-data-provider' -and [Helpers]::CheckMember($responseBuildObj.dataProviders.'ms.vss-build-web.pipelines-data-provider',"pipelines") -and  $responseBuildObj.dataProviders.'ms.vss-build-web.pipelines-data-provider'.pipelines)
                {
                    $buildRun = $responseBuildObj.dataProviders.'ms.vss-build-web.pipelines-data-provider'.pipelines
                    if(($buildRun | Measure-Object).Count -gt 0 )
                    {
                        if($null -ne $buildRun[0].latestRun)
                        {
                            if ([datetime]::Parse( $buildRun[0].latestRun.queueTime) -gt (Get-Date).AddDays( - $($this.ControlSettings.Build.BuildHistoryPeriodInDays)))
                            {
                                return $true;
                                break;
                            }
                        }
                    }
                }
            } 
        }
        return $false;
    }

    hidden [bool] CheckReleaseReferenceforTG([PSObject] $releases)
    {
        if (($releases | Measure-Object).Count -gt 0)
        {
            foreach ($release in $releases) 
            {
                $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery/project/{1}?api-version=5.0-preview.1" -f $($this.SubscriptionContext.SubscriptionName),$($this.ResourceContext.ResourceDetails.id);
                $inputbody2 =  "{'contributionIds': ['ms.vss-releaseManagement-web.releases-list-data-provider'],'dataProviderContext': {'properties': {'definitionIds':'$($release.releaseDefinitionId)','definitionId': '$($release.releaseDefinitionId)','fetchAllReleases': true,'sourcePage': {'url': 'https://dev.azure.com/$($this.SubscriptionContext.SubscriptionName)/$($this.ResourceContext.ResourceName)/_release?_a=releases&view=mine&definitionId=$($release.releaseDefinitionId)','routeId': 'ms.vss-releaseManagement-web.hub-explorer-3-default-route','routeValues': {'project': '$($this.ResourceContext.ResourceName)','viewname': 'hub-explorer-3-view','controller': 'ContributedPage','action': 'Execute'}}}}}"  | ConvertFrom-Json 
                $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL,$inputbody2);
                if([Helpers]::CheckMember($responseObj,"dataProviders") -and $responseObj.dataProviders.'ms.vss-releaseManagement-web.releases-list-data-provider')
                {
                    $releaseRuns = $responseObj.dataProviders.'ms.vss-releaseManagement-web.releases-list-data-provider'.releases
                    if(($releaseRuns | Measure-Object).Count -gt 0 )
                    {
                        if($null -ne $releaseRuns[0].createdOn)
                        { 
                            if([datetime]::Parse( $releaseRuns[0].createdOn) -gt (Get-Date).AddDays(-$($this.ControlSettings.Release.ReleaseHistoryPeriodInDays)))
                            {
                                return $true;
                                break;
                            }
                        }
                    }
                }
            }
        }
        return $false;
    }
}