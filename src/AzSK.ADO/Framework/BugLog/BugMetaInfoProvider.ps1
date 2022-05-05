Set-StrictMode -Version Latest
class BugMetaInfoProvider {

    hidden [PSObject] $ControlSettingsBugLog
    hidden [string] $ServiceId
    hidden static [PSObject] $ServiceTreeInfo
    hidden [PSObject] $InvocationContext
    hidden [bool] $BugLogUsingCSV = $false;
    hidden [string] $STMappingFilePath = $null
    hidden static $OrgMappingObj = @{}
    hidden static [PSObject] $emailRegEx
    hidden static $AssigneeForUnmappedResources = @{}
    hidden static [string] $GetAssigneeUsingFallbackMethod = $false
    hidden static $UserInactivityLimit;
    hidden static $UserActivityCache = @();
    hidden static $CheckForUserInactivity;

    BugMetaInfoProvider() {
        if ($null -eq [BugMetaInfoProvider]::emailRegEx) {
            $ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
            [BugMetaInfoProvider]::emailRegEx = $ControlSettings.Patterns | where {$_.RegexCode -eq "Email"} | Select-Object -Property RegexList;
            [BugMetaInfoProvider]::GetAssigneeUsingFallbackMethod = $ControlSettings.BugLogging.GetAssigneeUsingFallbackMethod

            if ([Helpers]::CheckMember($ControlSettings.BugLogging, "CheckForUserInactivity")) {
                [BugMetaInfoProvider]::UserInactivityLimit = $ControlSettings.BugLogging.UserInactivityLimit;
                [BugMetaInfoProvider]::CheckForUserInactivity = $ControlSettings.BugLogging.CheckForUserInactivity;
            }
        }
    }

    BugMetaInfoProvider($bugLogUsingCSV, $stMappingFilePath) {
        $this.BugLogUsingCSV = $bugLogUsingCSV;
        $this.STMappingFilePath = $stMappingFilePath;
    }

    hidden [string] GetAssignee([SVTEventContext[]] $ControlResult, $controlSettingsBugLog, $isBugLogCustomFlow, $serviceIdPassedInCMD, $invocationContext) {
        $this.ControlSettingsBugLog = $controlSettingsBugLog;
        #flag to check if pluggable bug logging interface (service tree)
        if ($isBugLogCustomFlow) {
            $this.InvocationContext = $invocationContext;	
            return $this.BugLogCustomFlow($ControlResult, $serviceIdPassedInCMD)
        }
        else {
            return $this.GetAssigneeFallback($ControlResult);
        }
    }

    hidden [string] GetAssignee([SVTEventContext[]] $ControlResult, $invocationContext) {
        $this.InvocationContext = $invocationContext;	
        return $this.BugLogCustomFlow($ControlResult, "")
    }

    hidden [string] BugLogCustomFlow($ControlResult, $serviceIdPassedInCMD)
    {
        $resourceType = $ControlResult.ResourceContext.ResourceTypeName
        $projectName = $ControlResult[0].ResourceContext.ResourceGroupName;
        $assignee = "";
        try 
         {
            #assign to the person running the scan, as to reach at this point of code, it is ensured the user is PCA/PA and only they or other PCA
            #PA members can fix the control
            if($ResourceType -eq 'Organization' -or $ResourceType -eq 'Project') {
                $assignee = [ContextHelper]::GetCurrentSessionUser();
            }
            else {
                $rscId = ($ControlResult.ResourceContext.ResourceId -split "$resourceType/")[-1];
                $assignee = $this.CalculateAssignee($rscId, $projectName, $resourceType, $serviceIdPassedInCMD);
                if (!$assignee -and (!$this.BugLogUsingCSV)) {
                    $assignee = $this.GetAssigneeFallback($ControlResult)
                }
            }            
        }
        catch {
            return "";
        }
        return $assignee;
    }

    hidden [string] CalculateAssignee($rscId, $projectName, $resourceType, $serviceIdPassedInCMD) 
    {
        $metaInfo = [MetaInfoProvider]::Instance;
        $assignee = "";
        try {
            #If serviceid based scan then get servicetreeinfo details only once.
            #First condition if not serviceid based scan then go inside every time.
            #Second condition if serviceid based scan and [BugMetaInfoProvider]::ServiceTreeInfo not null then only go inside.
            if (!$serviceIdPassedInCMD -or ($serviceIdPassedInCMD -and ![BugMetaInfoProvider]::ServiceTreeInfo)) {
                [BugMetaInfoProvider]::ServiceTreeInfo = $metaInfo.FetchResourceMappingWithServiceData($rscId, $projectName, $resourceType, $this.STMappingFilePath);
            }
            if([BugMetaInfoProvider]::ServiceTreeInfo)
            {
                #Filter based on area path match project name and take first items (if duplicate service tree entry found).
                #Split areapath to match with projectname
                if (!$this.BugLogUsingCSV) {
                    [BugMetaInfoProvider]::ServiceTreeInfo = ([BugMetaInfoProvider]::ServiceTreeInfo | Where {($_.areaPath).Split('\')[0] -eq $projectName})[0]
                }
                $this.ServiceId = [BugMetaInfoProvider]::ServiceTreeInfo.serviceId;
                #Check if area path is not supplied in command parameter then only set from service tree.
                if (!$this.InvocationContext.BoundParameters["AreaPath"]) {
                    [BugLogPathManager]::AreaPath = [BugMetaInfoProvider]::ServiceTreeInfo.areaPath.Replace("\", "\\");
                }
                $domainNameForAssignee = ""
                if([Helpers]::CheckMember($this.ControlSettingsBugLog, "DomainName"))
                {
                    $domainNameForAssignee = $this.ControlSettingsBugLog.DomainName;
                }
                elseif ($this.BugLogUsingCSV) {
                    $domainNameForAssignee = "microsoft.com";
                }
                $assignee = [BugMetaInfoProvider]::ServiceTreeInfo.devOwner.Split(";")[0] + "@"+ $domainNameForAssignee
            }
        }
        catch {
            Write-Host "Could not find service tree data file." -ForegroundColor Yellow
        }
        return $assignee;	
    }

    hidden [string] GetAssigneeFallback([SVTEventContext[]] $ControlResult) {
        if ($ControlResult.ResourceContext.ResourceId -in [BugMetaInfoProvider]::AssigneeForUnmappedResources.Keys ) {
            return [BugMetaInfoProvider]::AssigneeForUnmappedResources[$ControlResult.ResourceContext.ResourceId]
        }
        $ResourceType = $ControlResult.ResourceContext.ResourceTypeName
        $ResourceName = $ControlResult.ResourceContext.ResourceName
        $organizationName = $ControlResult.OrganizationContext.OrganizationName;
        $eventBaseObj = [EventBase]::new()
        switch -regex ($ResourceType) {
            #assign to the creator of service connection
            'ServiceConnection' {
                $assignee = $ControlResult.ResourceContext.ResourceDetails.createdBy.uniqueName

                if ([BugMetaInfoProvider]::GetAssigneeUsingFallbackMethod) 
                {
                    if (($assignee -inotmatch [BugMetaInfoProvider]::emailRegEx.RegexList[0]) -or ([IdentityHelpers]::IsServiceAccount($assignee, 'User', [IdentityHelpers]::graphAccessToken)) -or !$this.isUserActive($organizationName,$assignee)) 
                    {
                        $assignee = "";
                        $apiURL = "https://dev.azure.com/{0}/{1}/_apis/serviceendpoint/{2}/executionhistory?top=1&api-version=6.0-preview.1" -f $organizationName, $($ControlResult.ResourceContext.ResourceGroupName), $($ControlResult.ResourceContext.ResourceDetails.id);
                        $executionHistory = [WebRequestHelper]::InvokeGetWebRequest($apiURL);

                        # get assignee from the the build/release jobs history
                        if (([Helpers]::CheckMember($executionHistory, "data") ) -and (($executionHistory.data | Measure-Object).Count -gt 0) )
                        {
                            $pipelineType = $executionHistory.data[0].planType
                            $pipelineId = $executionHistory.data[0].definition.id
                            if ($pipelineType -eq 'Release') {
                                $assignee = $this.FetchAssigneeFromRelease($organizationName, $ControlResult.ResourceContext.ResourceGroupName, $pipelineId)
                            }
                            else {
                                $assignee = $this.FetchAssigneeFromBuild($organizationName, $ControlResult.ResourceContext.ResourceGroupName, $pipelineId)
                            }
                        }
                        # if no build/release jobs associated with service connection, then fecth assignee from permissions
                        # asignee not found from build/release
                        elseif (!$assignee) 
                        {
                            try {
                                $projectId = ($ControlResult.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
                                $apiURL = "https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.serviceendpointrole/roleassignments/resources/{1}_{2}" -f $organizationName, $projectId, $ControlResult.ResourceContext.ResourceId.split('/')[-1]
                                $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
                                $roles =   @(($responseObj | where {$_.role.displayname -eq 'Administrator'} |select identity) | where {(-not ($_.identity.displayname).Contains("\")) -and ($_.identity.displayname -notin @("GitHub", "Microsoft.VisualStudio.Services.TFS"))} )
                                if ($roles.Count -gt 0) {
                                    $userId = $roles[0].identity.id
                                    $assignee = $this.getUserFromUserId($organizationName, $userId)
                                }
                            }
                            catch {
                                $assignee = ""
                                $eventBaseObj.PublishCustomMessage("Assignee Could not be determind.")
                            }
                        }
                    }  
                }

                [BugMetaInfoProvider]::AssigneeForUnmappedResources[$ControlResult.ResourceContext.ResourceId] = $assignee; 
                return $assignee
            }
            #assign to the creator of agent pool
            'AgentPool' {
                $apiurl = "https://dev.azure.com/{0}/_apis/distributedtask/pools?poolName={1}&api-version=6.0" -f $organizationName, $ResourceName
                try {
                    $response = [WebRequestHelper]::InvokeGetWebRequest($apiurl)
                    $assignee = $response.createdBy.uniqueName

                    if ([BugMetaInfoProvider]::GetAssigneeUsingFallbackMethod) 
                    {
                        # if assignee is service account, then fetch assignee from jobs/permissions
                        if (($assignee -inotmatch [BugMetaInfoProvider]::emailRegEx.RegexList[0]) -or ([IdentityHelpers]::IsServiceAccount($assignee, 'User', [IdentityHelpers]::graphAccessToken)) -or !$this.isUserActive($organizationName,$assignee)) 
                        {
                            $assignee = "";
                            $agentPoolsURL = "https://dev.azure.com/{0}/{1}/_settings/agentqueues?queueId={2}&__rt=fps&__ver=2 " -f $organizationName, $ControlResult.ResourceContext.ResourceGroupName, $ControlResult.ResourceContext.ResourceId.split('/')[-1]
                            $agentPool = [WebRequestHelper]::InvokeGetWebRequest($agentPoolsURL);
                            # get assignee from the the build/release jobs history
                            if (([Helpers]::CheckMember($agentPool[0], "fps.dataProviders.data") ) -and ([Helpers]::CheckMember($agentPool[0].fps.dataProviders.data."ms.vss-build-web.agent-jobs-data-provider", "jobs")) )
                            {
                                $pipelineType = $agentPool[0].fps.dataProviders.data."ms.vss-build-web.agent-jobs-data-provider".jobs[0].planType
                                $pipelineId = $agentPool[0].fps.dataProviders.data."ms.vss-build-web.agent-jobs-data-provider".jobs[0].definition.id
                                if ($pipelineType -eq 'Release') {
                                    $assignee = $this.FetchAssigneeFromRelease($organizationName, $ControlResult.ResourceContext.ResourceGroupName, $pipelineId)
                                }
                                else {
                                    $assignee = $this.FetchAssigneeFromBuild($organizationName, $ControlResult.ResourceContext.ResourceGroupName, $pipelineId)
                                }
                            }
                            # if no build/release jobs associated with agentpool, then fecth assignee from permissions
                            elseif(!$assignee) 
                            {
                                try {
                                    $projectId = ($ControlResult.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
                                    $apiURL = "https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.agentqueuerole/roleassignments/resources/{1}_{2}" -f $organizationName, $projectId, $ControlResult.ResourceContext.ResourceId.split('/')[-1]
                                    $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($apiURL));
                                    $roles =   @( ($responseObj | where {$_.role.displayname -eq 'Administrator'} |select identity) | where {(-not ($_.identity.displayname).Contains("\")) -and ($_.identity.displayname -notin @("GitHub", "Microsoft.VisualStudio.Services.TFS"))} )
                                    if ($roles.Count -gt 0) {
                                        $userId = $roles[0].identity.id
                                        $assignee = $this.getUserFromUserId($organizationName, $userId)
                                    }
                                }
                                catch {
                                    $assignee = ""
                                    $eventBaseObj.PublishCustomMessage("Assignee Could not be determind.")
                                }
                            }
                        }
                    }    
                }
                catch {
                    $assignee = "";
                }
                [BugMetaInfoProvider]::AssigneeForUnmappedResources[$ControlResult.ResourceContext.ResourceId] = $assignee
                return $assignee
            }
            #assign to the creator of variable group
            'VariableGroup' {
                $assignee = $ControlResult.ResourceContext.ResourceDetails.createdBy.uniqueName

                if ([BugMetaInfoProvider]::GetAssigneeUsingFallbackMethod) 
                {
                    if (($assignee -inotmatch [BugMetaInfoProvider]::emailRegEx.RegexList[0]) -or ([IdentityHelpers]::IsServiceAccount($assignee, 'User', [IdentityHelpers]::graphAccessToken)) -or !$this.isUserActive($organizationName,$assignee)) 
                    {
                        $assignee = "";
                        if ([Helpers]::CheckMember($ControlResult.ResourceContext.ResourceDetails, "modifiedBy")) {
                            $assignee = $ControlResult.ResourceContext.ResourceDetails.modifiedBy.uniqueName
                        }
                    }

                    if (($assignee -inotmatch [BugMetaInfoProvider]::emailRegEx.RegexList[0]) -or ([IdentityHelpers]::IsServiceAccount($assignee, 'User', [IdentityHelpers]::graphAccessToken)) -or !$this.isUserActive($organizationName,$assignee)) 
                    {
                        $assignee = "";
                        # if no createdby/modifiedby found then fecth assignee from permissions
                        try {
                            $projectId = ($ControlResult.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
                            $apiURL = "https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.variablegroup/roleassignments/resources/{1}%24{2}?api-version=6.1-preview.1" -f $organizationName, $projectId, $ControlResult.ResourceContext.ResourceId.split('/')[-1]
                            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
                            $roles =   @( ($responseObj | where {$_.role.displayname -eq 'Administrator'} |select identity) | where {(-not ($_.identity.displayname).Contains("\")) -and ($_.identity.displayname -notin @("GitHub", "Microsoft.VisualStudio.Services.TFS"))} )
                            if ($roles.Count -gt 0) {
                                $userId = $roles[0].identity.id
                                $assignee = $this.getUserFromUserId($organizationName, $userId)
                            }
                        }
                        catch {  
                            $assignee = ""
                            $eventBaseObj.PublishCustomMessage("Assignee Could not be determind.")
                        }
                    }
                }
                [BugMetaInfoProvider]::AssigneeForUnmappedResources[$ControlResult.ResourceContext.ResourceId] = $assignee
                return $assignee
            }
            #assign to the person who recently triggered the build pipeline, or if the pipeline is empty assign it to the creator
            'Build' {
                $definitionId = $ControlResult.ResourceContext.ResourceDetails.id;
    
                try {
                    $assignee = $this.FetchAssigneeFromBuild($organizationName, $ControlResult.ResourceContext.ResourceGroupName , $definitionId)
                }
                catch {
                    $assignee = "";
                }
                [BugMetaInfoProvider]::AssigneeForUnmappedResources[$ControlResult.ResourceContext.ResourceId] = $assignee
                return $assignee	
			    	
            }
            #assign to the person who recently triggered the release pipeline, or if the pipeline is empty assign it to the creator
            'Release' {
                $definitionId = ($ControlResult.ResourceContext.ResourceId -split "release/")[-1];
                try {
                    $assignee = $this.FetchAssigneeFromRelease($organizationName, $ControlResult.ResourceContext.ResourceGroupName , $definitionId)
                }
                catch {
                    $assignee = "";
                }
                [BugMetaInfoProvider]::AssigneeForUnmappedResources[$ControlResult.ResourceContext.ResourceId] = $assignee
                return $assignee
            }
            'Repository' {
                try {
                    $assignee = ""
                    $url = 'https://dev.azure.com/{0}/{1}/_apis/git/repositories/{2}/commits?searchCriteria.$top=1&api-version=6.0' -f $organizationName, $ControlResult.ResourceContext.ResourceGroupName, $ControlResult.ResourceContext.ResourceDetails.Id;
                    $repoLatestCommit = @([WebRequestHelper]::InvokeGetWebRequest($url));
                    if ($repoLatestCommit.count -gt 0 -and [Helpers]::CheckMember($repoLatestCommit[0],"author")) {
                        $assignee = $repoLatestCommit[0].author.email;
                    }

                    if ([BugMetaInfoProvider]::GetAssigneeUsingFallbackMethod) 
                    {
                        #getting assignee from the repository permissions
                        if (($assignee -inotmatch [BugMetaInfoProvider]::emailRegEx.RegexList[0]) -or ([IdentityHelpers]::IsServiceAccount($assignee, 'User', [IdentityHelpers]::graphAccessToken)) -or !$this.isUserActive($organizationName,$assignee)) 
                        {
                            $assignee = "";
                            try{
                                $accessList = @()
                                $url = 'https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1' -f $organizationName;
                                $refererUrl = "https://dev.azure.com/{0}/{1}/_settings/repositories?repo={2}&_a=permissionsMid" -f $organizationName, $ControlResult.ResourceContext.ResourceGroupName, $ControlResult.ResourceContext.ResourceDetails.Id
                                $inputbody = '{"contributionIds":["ms.vss-admin-web.security-view-members-data-provider"],"dataProviderContext":{"properties":{"permissionSetId": "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87","permissionSetToken":"","sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"repositories","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json
                                $inputbody.dataProviderContext.properties.sourcePage.url = $refererUrl
                                $inputbody.dataProviderContext.properties.sourcePage.routeValues.Project = $ControlResult.ResourceContext.ResourceGroupName;
                                $inputbody.dataProviderContext.properties.permissionSetToken = "repoV2/$($ControlResult.ResourceContext.ResourceDetails.Project.id)/$($ControlResult.ResourceContext.ResourceDetails.id)"
                                $responseObj = [WebRequestHelper]::InvokePostWebRequest($url, $inputbody);
                                
                                # Iterate through each user/group to fetch detailed permissions list
                                if([Helpers]::CheckMember($responseObj[0],"dataProviders") -and ($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider') -and ([Helpers]::CheckMember($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider',"identities")))
                                {
                                    $body = '{"contributionIds":["ms.vss-admin-web.security-view-permissions-data-provider"],"dataProviderContext":{"properties":{"subjectDescriptor":"","permissionSetId": "2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87","permissionSetToken":"","accountName":"","sourcePage":{"url":"","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"","adminPivot":"repositories","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json
                                    $body.dataProviderContext.properties.sourcePage.url = $refererUrl
                                    $body.dataProviderContext.properties.sourcePage.routeValues.Project = $ControlResult.ResourceContext.ResourceGroupName;
                                    $body.dataProviderContext.properties.permissionSetToken = "repoV2/$($ControlResult.ResourceContext.ResourceDetails.Project.id)/$($ControlResult.ResourceContext.ResourceDetails.id)"
                                    $accessList += $responseObj.dataProviders."ms.vss-admin-web.security-view-members-data-provider".identities | Where-Object { ($_.subjectKind -eq "user") -and (-not [string]::IsNullOrEmpty($_.mailAddress))} | ForEach-Object {
                                        $identity = $_
                                        $body.dataProviderContext.properties.subjectDescriptor = $_.descriptor
                                        $identityPermissions = [WebRequestHelper]::InvokePostWebRequest($url, $body);
                                        $configuredPermissions = @($identityPermissions.dataproviders."ms.vss-admin-web.security-view-permissions-data-provider".subjectPermissions | Where-Object {$_.permissionDisplayString -ne 'Not set'})
                                        if ($configuredPermissions.Count -ge 12) {
                                            return $identity
                                        }
                                    }

                                    if ($accessList.Count -gt 0) {
                                        $assignee = $accessList[0].mailAddress
                                    }
                                }
                            }
                            catch {
                                $assignee = ""
                                $eventBaseObj.PublishCustomMessage("Assignee Could not be determind.")
                            }
                        }
                    } 
                }
                catch {
                    $assignee = "";
                }
                [BugMetaInfoProvider]::AssigneeForUnmappedResources[$ControlResult.ResourceContext.ResourceId] = $assignee
                return $assignee
            }
            'SecureFile' {
                $assignee = $ControlResult.ResourceContext.ResourceDetails.createdBy.uniqueName

                if ([BugMetaInfoProvider]::GetAssigneeUsingFallbackMethod) 
                {
                    if (($assignee -inotmatch [BugMetaInfoProvider]::emailRegEx.RegexList[0]) -or ([IdentityHelpers]::IsServiceAccount($assignee, 'User', [IdentityHelpers]::graphAccessToken)) -or !$this.isUserActive($organizationName,$assignee)) 
                    {
                        $assignee = "";
                        if ([Helpers]::CheckMember($ControlResult.ResourceContext.ResourceDetails, "modifiedBy")) {
                            $assignee = $ControlResult.ResourceContext.ResourceDetails.modifiedBy.uniqueName
                        }
                    }

                    # if assignee is service account, then fetch assignee from jobs/permissions
                    if (($assignee -inotmatch [BugMetaInfoProvider]::emailRegEx.RegexList[0]) -or ([IdentityHelpers]::IsServiceAccount($assignee, 'User', [IdentityHelpers]::graphAccessToken)) -or !$this.isUserActive($organizationName,$assignee)) 
                    {
                        $assignee = "";
                        try {
                            $projectId = ($ControlResult.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
                            $apiURL = "https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.securefile/roleassignments/resources/{1}%24{2}" -f $organizationName, $projectId, $ControlResult.ResourceContext.ResourceId.split('/')[-1]
                            $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($apiURL));
                            $roles =   @( ($responseObj | where {$_.role.displayname -eq 'Administrator'} |select identity) | where {(-not ($_.identity.displayname).Contains("\")) -and ($_.identity.displayname -notin @("GitHub", "Microsoft.VisualStudio.Services.TFS"))} )
                            if ($roles.Count -gt 0) {
                                $userId = $roles[0].identity.id
                                $assignee = $this.getUserFromUserId($organizationName, $userId)
                            }
                        }
                        catch {
                            $assignee = ""
                            $eventBaseObj.PublishCustomMessage("Assignee Could not be determind.")
                        }
                    }
                }
                    
                [BugMetaInfoProvider]::AssigneeForUnmappedResources[$ControlResult.ResourceContext.ResourceId] = $assignee
                return $assignee
            }
            'Feed' {
                try {
                    $assignee = ""
                    if ("Project" -notin $ControlResult.ResourceContext.ResourceDetails.PSobject.Properties.name){
                        $url = 'https://{0}.feeds.visualstudio.com/_apis/Packaging/Feeds/{1}/Permissions?includeIds=true&excludeInheritedPermissions=false&includeDeletedFeeds=false' -f $organizationName, $ControlResult.ResourceContext.ResourceDetails.Id;
                    }
                    else {
                        $url = 'https://{0}.feeds.visualstudio.com/{1}/_apis/Packaging/Feeds/{2}/Permissions?includeIds=true&excludeInheritedPermissions=false&includeDeletedFeeds=false' -f $organizationName, $ControlResult.ResourceContext.ResourceGroupName, $ControlResult.ResourceContext.ResourceDetails.Id;
                    }
                    $feedPermissionList = @([WebRequestHelper]::InvokeGetWebRequest($url));
                    if ($feedPermissionList.count -gt 0 -and [Helpers]::CheckMember($feedPermissionList[0],"identityDescriptor")) {
                        $roles = $feedPermissionList | Where {$_.role -eq 'Administrator'}
                        if ($roles.count -ge 1) {
                            $resourceOwners = @($roles.identityDescriptor.Split('\') | Where {$_ -match [BugMetaInfoProvider]::emailRegEx.RegexList[0]})
                            if ($resourceOwners.count -ge 1) {
                                $allAssignee = $resourceOwners | Select-Object @{l="mailaddress";e={$_}}, @{l="subjectKind";e={"User"}}
                                $SvcAndHumanAccounts = [IdentityHelpers]::DistinguishHumanAndServiceAccount($allAssignee, $organizationName)
                                if ($SvcAndHumanAccounts.humanAccount.Count -gt 0) {
                                    $assignee = $SvcAndHumanAccounts.humanAccount[0].mailAddress
                                }
                            }
                        }
                    }
                }
                catch {
                    $assignee = "";
                }
                [BugMetaInfoProvider]::AssigneeForUnmappedResources[$ControlResult.ResourceContext.ResourceId] = $assignee
                return $assignee
            }
            'Environment' {
                $assignee = $ControlResult.ResourceContext.ResourceDetails.createdBy.uniqueName

                if ([BugMetaInfoProvider]::GetAssigneeUsingFallbackMethod) 
                {
                    if (($assignee -inotmatch [BugMetaInfoProvider]::emailRegEx.RegexList[0]) -or ([IdentityHelpers]::IsServiceAccount($assignee, 'User', [IdentityHelpers]::graphAccessToken)) -or !$this.isUserActive($organizationName,$assignee)) 
                    {
                        $assignee = "";
                        if ([Helpers]::CheckMember($ControlResult.ResourceContext.ResourceDetails, "lastModifiedBy")) {
                            $assignee = $ControlResult.ResourceContext.ResourceDetails.lastModifiedBy.uniqueName
                        }
                    }
                    
                    # if assignee is service account, then fetch assignee from jobs/permissions
                    if (($assignee -inotmatch [BugMetaInfoProvider]::emailRegEx.RegexList[0]) -or ([IdentityHelpers]::IsServiceAccount($assignee, 'User', [IdentityHelpers]::graphAccessToken)) -or !$this.isUserActive($organizationName,$assignee)) 
                    {
                        $assignee = "";
                        $url = "https://dev.azure.com/{0}/{1}/_environments/{2}?view=resources&__rt=fps&__ver=2" -f $organizationName, $ControlResult.ResourceContext.ResourceGroupName, $ControlResult.ResourceContext.ResourceId.split('/')[-1]
                        $envDetails = [WebRequestHelper]::InvokeGetWebRequest($url);
                        # get assignee from the the build/release jobs history
                        if (([Helpers]::CheckMember($envDetails[0], "fps.dataProviders.data") ) -and ([Helpers]::CheckMember($envDetails[0].fps.dataProviders.data."ms.vss-environments-web.environment-deployment-history-data-provider", "deploymentExecutionRecords")) )
                        {
                            $pipelineType = $envDetails[0].fps.dataProviders.data."ms.vss-environments-web.environment-deployment-history-data-provider".deploymentExecutionRecords[0].planType
                            $pipelineId = $envDetails[0].fps.dataProviders.data."ms.vss-environments-web.environment-deployment-history-data-provider".deploymentExecutionRecords[0].definition.id
                            if ($pipelineType -eq 'Release') {
                                $assignee = $this.FetchAssigneeFromRelease($organizationName, $ControlResult.ResourceContext.ResourceGroupName, $pipelineId)
                            }
                            else {
                                $assignee = $this.FetchAssigneeFromBuild($organizationName, $ControlResult.ResourceContext.ResourceGroupName, $pipelineId)
                            }
                        }
                        # if no build/release jobs associated with agentpool, then fecth assignee from permissions
                        elseif(!$assignee) 
                        {
                            try {
                                $projectId = ($ControlResult.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
                                $apiURL = "https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.environmentreferencerole/roleassignments/resources/{1}_{2}?api-version=5.0-preview.1" -f $organizationName, $projectId, $ControlResult.ResourceContext.ResourceId.split('/')[-1]
                                $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($apiURL));
                                $roles =   @( ($responseObj | where {$_.role.displayname -eq 'Administrator'} |select identity) | where {(-not ($_.identity.displayname).Contains("\")) -and ($_.identity.displayname -notin @("GitHub", "Microsoft.VisualStudio.Services.TFS"))} )
                                if ($roles.Count -gt 0) {
                                    $userId = $roles[0].identity.id
                                    $assignee = $this.getUserFromUserId($organizationName, $userId)
                                }
                            }
                            catch {
                                $assignee = ""
                                $eventBaseObj.PublishCustomMessage("Assignee Could not be determind.") 
                            }
                        }
                    }
                }
                    
                [BugMetaInfoProvider]::AssigneeForUnmappedResources[$ControlResult.ResourceContext.ResourceId] = $assignee
                return $assignee
            }  
            #assign to the person running the scan, as to reach at this point of code, it is ensured the user is PCA/PA and only they or other PCA
            #PA members can fix the control
            'Organization' {
                return [ContextHelper]::GetCurrentSessionUser();
            }
            'Project' {
                return [ContextHelper]::GetCurrentSessionUser();
    
            }
        }
        return "";
    }

    hidden [string] GetAssigneeFromOrgMapping($organizationName){
        $assignee = $null;
        if([BugMetaInfoProvider]::OrgMappingObj.ContainsKey($organizationName)){
            return [BugMetaInfoProvider]::OrgMappingObj[$organizationName]
        }
        if (![string]::IsNullOrWhiteSpace($this.STMappingFilePath))
        {
            # $orgMapping = Get-Content "$([string]::IsNullOrWhiteSpace($this.STMappingFilePath))\OrgSTData.csv" | ConvertFrom-Csv 
            $orgMapping = Get-Content "$($this.STMappingFilePath)\OrgSTData.csv" | ConvertFrom-Csv
            $orgOwnerDetails = @($orgMapping | where {$_."ADO Org Name" -eq $organizationName})
            if($orgOwnerDetails.Count -gt 0){
                $assignee = $orgOwnerDetails[0]."OwnerAlias"   
                [BugMetaInfoProvider]::OrgMappingObj[$organizationName] = $assignee
            }
        }
        return $assignee;
    }

    hidden [string] FetchAssigneeFromBuild($organizationName, $projectName, $definitionId) 
    {
        $assignee = "";
        try 
        {
            $apiurl = "https://dev.azure.com/{0}/{1}/_apis/build/builds?definitions={2}&api-version=6.0" -f $organizationName, $projectName, $definitionId;
            $response = [WebRequestHelper]::InvokeGetWebRequest($apiurl)
            #check for recent trigger
            if ([Helpers]::CheckMember($response, "requestedBy")) {
                $assignee = $response[0].requestedBy.uniqueName
                if ($assignee -inotmatch [BugMetaInfoProvider]::emailRegEx.RegexList[0] -or ([IdentityHelpers]::IsServiceAccount($assignee, 'User', [IdentityHelpers]::graphAccessToken))) {
                    $assignee = $response[0].lastChangedBy.uniqueName
                }
            }
            #if no triggers found assign to the creator
            else {
                $apiurl = "https://dev.azure.com/{0}/{1}/_apis/build/definitions/{2}?api-version=6.0" -f $organizationName, $projectName, $definitionId;
                $response = [WebRequestHelper]::InvokeGetWebRequest($apiurl)
                $assignee = $response.authoredBy.uniqueName
            }
            
            if ([BugMetaInfoProvider]::GetAssigneeUsingFallbackMethod) 
            {
                # if assignee is service account, get assignee from the the build update history
                if ($assignee -inotmatch [BugMetaInfoProvider]::emailRegEx.RegexList[0] -or ([IdentityHelpers]::IsServiceAccount($assignee, 'User', [IdentityHelpers]::graphAccessToken))) {
                    $url = "https://dev.azure.com/{0}/{1}/_apis/build/definitions/{2}/revisions" -f $organizationName, $projectName, $definitionId;
                    $response = [WebRequestHelper]::InvokeGetWebRequest($url)
                    if ([Helpers]::CheckMember($response, "changedBy")) {
                        $response = @($response | Where-Object {$_.changedBy.uniqueName -imatch [BugMetaInfoProvider]::emailRegEx.RegexList[0] }| Sort-Object -Property changedDate -descending)
                        if ($response.count -gt 0) {
                            $allAssignee = @()
                            $response | ForEach-Object {$allAssignee += @( [PSCustomObject] @{ mailAddress = $_.changedBy.uniqueName; subjectKind = 'User' } )} | Select-Object -Unique
                            $allAssignee = $allAssignee | Select-Object mailaddress, subjectKind -unique
                            $SvcAndHumanAccounts = [IdentityHelpers]::DistinguishHumanAndServiceAccount($allAssignee, $organizationName)
                            if ($SvcAndHumanAccounts.humanAccount.Count -gt 0) {
                                $assignee = $SvcAndHumanAccounts.humanAccount[0].mailAddress
                            }
                        }
                    }
                }
            }
        }
        catch {
        }

        return $assignee;	
    }

    hidden [string] FetchAssigneeFromRelease($organizationName, $projectName, $definitionId) 
    {
        $assignee = "";
        try 
        {
            $apiurl = "https://vsrm.dev.azure.com/{0}/{1}/_apis/release/releases?definitionId={2}&api-version=6.0" -f $organizationName, $projectName , $definitionId;
            $response = [WebRequestHelper]::InvokeGetWebRequest($apiurl)
            #check for recent trigger
            if ([Helpers]::CheckMember($response, "modifiedBy")) {
                $assignee = $response[0].modifiedBy.uniqueName
            }
            #if no triggers found assign to the creator
            else {
                $apiurl = "https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions/{2}?&api-version=6.0" -f $organizationName, $projectName, $definitionId;
                $response = [WebRequestHelper]::InvokeGetWebRequest($apiurl)
                $assignee = $response.createdBy.uniqueName
            }

            if ([BugMetaInfoProvider]::GetAssigneeUsingFallbackMethod) 
            {
                # if assignee is service account, get assignee from the the release update history
                if ($assignee -inotmatch [BugMetaInfoProvider]::emailRegEx.RegexList[0] -or ([IdentityHelpers]::IsServiceAccount($assignee, 'User', [IdentityHelpers]::graphAccessToken))) {
                    $assignee = "";
                    $url = "https://{0}.vsrm.visualstudio.com/{1}/_apis/Release/definitions/{2}/revisions" -f $organizationName, $projectName, $definitionId;
                    $response = [WebRequestHelper]::InvokeGetWebRequest($url)
                    if ([Helpers]::CheckMember($response, "changedBy")) {
                        $response = @($response | Where-Object {$_.changedBy.uniqueName -imatch [BugMetaInfoProvider]::emailRegEx.RegexList[0] }| Sort-Object -Property changedDate -descending)
                        if ($response.count -gt 0) {
                            $allAssignee = @()
                            $response | ForEach-Object {$allAssignee += @( [PSCustomObject] @{ mailAddress = $_.changedBy.uniqueName; subjectKind = 'User' } )} | Select-Object -Unique
                            $allAssignee = $allAssignee | Select-Object mailaddress, subjectKind -unique
                            $SvcAndHumanAccounts = [IdentityHelpers]::DistinguishHumanAndServiceAccount($allAssignee, $organizationName)
                            if ($SvcAndHumanAccounts.humanAccount.Count -gt 0) {
                                $assignee = $SvcAndHumanAccounts.humanAccount[0].mailAddress
                            }
                        }
                    }
                }
            }
        }
        catch {
            Write-Host("Pipeline not found");
        }

        return $assignee;	
    }

    hidden [string] getUserFromUserId($organizationName, $userId) 
    {
        try 
        {
            # User descriptor is base 64 encoding of user id
            # $url = "https://vssps.dev.azure.com/{0}/_apis/graph/descriptors/{1}?api-version=6.0-preview.1" -f $organizationName, $userId
            # $userDescriptor = [WebRequestHelper]::InvokeGetWebRequest($url);
            $userDescriptor = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($userId))
            $userProfileURL = "https://vssps.dev.azure.com/{0}/_apis/graph/users/aad.{1}?api-version=6.0-preview.1" -f $organizationName, $userDescriptor
            $userProfile = [WebRequestHelper]::InvokeGetWebRequest($userProfileURL)
            return $userProfile[0].mailAddress
        }
        catch {
            return ""
        }
    }

    hidden [bool] isUserActive($organizationName,$mailAddress){
        $isUserActive = $true
        if(![BugMetaInfoProvider]::CheckForUserInactivity){
            return $true
        }
        try{
            $userActivity = [BugMetaInfoProvider]::UserActivityCache | where {$_.id -eq $mailAddress}
            if($userActivity){
                return $userActivity.isActive
            }
            else {
                $url = "https://vsaex.dev.azure.com/{0}/_apis/userentitlements?api-version=6.0-preview.3&`$filter=name eq '{1}'" -f $organizationName, $mailAddress
                $response = [WebRequestHelper]::InvokeGetWebRequest($url);
                if($response[0].members.count -gt 0){
                    [datetime] $lastAccessedDate = $response[0].members[0].lastAccessedDate
                    if(((Get-Date)-$lastAccessedDate).Days -gt [BugMetaInfoProvider]::UserInactivityLimit){
                        $isUserActive= $false;
                    }
                }
                else{
                    $isUserActive= $false
                }
            }

        }
        catch{
            $isUserActive= $false
        }
        [BugMetaInfoProvider]::UserActivityCache += (@{id = $mailAddress;isActive = $isUserActive})
        return $isUserActive
    }
    
    #method to obtain sign in ID of TF scoped identities
    hidden [string] GetAssigneeFromTFScopedIdentity($identity,$organizationName){
        $assignee = $null;
        #TF scoped identities with alternate email address will be in the format: a.b@microsoft.com
        if($identity -like "*.*@microsoft.com"){
            #check for the correct identitity corresponding to this email
            $url="https://dev.azure.com/{0}/_apis/IdentityPicker/Identities?api-version=7.1-preview.1" -f $organizationName
            $body = "{'query':'{0}','identityTypes':['user'],'operationScopes':['ims','source'],'properties':['DisplayName','Active','SignInAddress'],'filterByEntityIds':[],'options':{'MinResults':40,'MaxResults':40}}" | ConvertFrom-Json
            $body.query = $identity
            try{
                $responseObj = [WebRequestHelper]::InvokePostWebRequest($url,$body)
                #if any user has been found, assign this bug to the sign in address of the user
                if($responseObj.results[0].identities.count -gt 0){
                    $assignee = $responseObj.results[0].identities[0].signInAddress
                }
            }
            catch{
                return $assignee;
            }                    
        }
        else{
            return $assignee;
        }

        return $assignee;
    }

}
