Set-StrictMode -Version Latest
class Organization: ADOSVTBase
{
    [PSObject] $ServiceEndPointsObj = $null
    [PSObject] $PipelineSettingsObj = $null
    [PSObject] $OrgPolicyObj = $null
    static $InstalledExtensionInfo
    static $SharedExtensionInfo
    static $AutoInjectedExtensionInfo
    hidden [PSObject] $allExtensionsObj; # This is used to fetch all extensions (shared+installed+requested) object so that it can be used in installed extension control where top publisher could not be computed.
    hidden [PSObject] $installedExtensionObj # This is used to store install extensions details, that we fetch using documented API. This object contains some additional properties for installed extensions (e.g. Scopes), that are missing in portal API.
    hidden [PSObject] $graphPermissions = @{hasGraphAccess = $false; graphAccessToken = $null}; # This is used to check user has graph permissions to compute the graph api operations.
    hidden $GuestMembers = @()
    hidden $AllUsersInOrg = @()
    hidden $PCAMembersList = @()
    hidden $svcAccountsList = @()
    hidden $humanAccountsList = @()
    hidden [PSObject] $extensionDetailsFromOrgPolicy = @{knownExtPublishers = @(); extensionsLastUpdatedInYears = 2; ExemptedExtensionNames = @(); nonProductionExtensionIndicators = @(); extensionCriticalScopes = @(); isKnownPublishersPropertyPresent=$false; islastUpdatedPropertyPresent=$false; isCriticalScopesPropertyPresent=$false; isNonProdIndicatorsPropertyPresent=$false; isComputed=$false}; 
    hidden [PSObject] $ComputedExtensionDetails = @{}; 

    #TODO: testing below line
    hidden [string] $SecurityNamespaceId;
    Organization([string] $organizationName, [SVTResource] $svtResource): Base($organizationName,$svtResource)
    {
        $this.GetOrgPolicyObject()
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

    GetOrgPolicyObject()
    {
        try
        {
            $uri ="https://dev.azure.com/{0}/_settings/organizationPolicy?__rt=fps&__ver=2" -f $($this.OrganizationContext.OrganizationName);
            $response = [WebRequestHelper]::InvokeGetWebRequest($uri);

            if($response -and [Helpers]::CheckMember($response.fps.dataProviders,"data") -and $response.fps.dataProviders.data.'ms.vss-admin-web.organization-policies-data-provider')
            {
                $this.OrgPolicyObj = $response.fps.dataProviders.data.'ms.vss-admin-web.organization-policies-data-provider'.policies
            }
        }
        catch # Added above new api to get User policy settings, old api is not returning. Fallback to old API in catch
        {
            $apiURL = "https://vsaex.dev.azure.com/{0}/_apis/Contribution/dataProviders/query?api-version=5.0-preview.1" -f $($this.OrganizationContext.OrganizationName);

            $orgUrl = "https://dev.azure.com/{0}" -f $($this.OrganizationContext.OrganizationName);
            $inputbody =  "{'contributionIds':['ms.vss-org-web.collection-admin-policy-data-provider'],'context':{'properties':{'sourcePage':{'url':'$orgUrl/_settings/policy','routeId':'ms.vss-admin-web.collection-admin-hub-route','routeValues':{'adminPivot':'policy','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json
            $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL,$inputbody);
            if([Helpers]::CheckMember($responseObj,"data") -and $responseObj.data.'ms.vss-org-web.collection-admin-policy-data-provider')
            {
                $this.OrgPolicyObj = $responseObj.data.'ms.vss-org-web.collection-admin-policy-data-provider'.policies
            }
        }
    }

    GetPipelineSettingsObj()
    {
        $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $($this.OrganizationContext.OrganizationName);

        $orgUrl = "https://dev.azure.com/{0}" -f $($this.OrganizationContext.OrganizationName);
        #$inputbody =  "{'contributionIds':['ms.vss-org-web.collection-admin-policy-data-provider'],'context':{'properties':{'sourcePage':{'url':'$orgUrl/_settings/policy','routeId':'ms.vss-admin-web.collection-admin-hub-route','routeValues':{'adminPivot':'policy','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json
        $inputbody = "{'contributionIds':['ms.vss-build-web.pipelines-org-settings-data-provider'],'dataProviderContext':{'properties':{'sourcePage':{'url':'$orgUrl/_settings/pipelinessettings','routeId':'ms.vss-admin-web.collection-admin-hub-route','routeValues':{'adminPivot':'pipelinessettings','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json

        $responseObj = $null

        try{
            $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL,$inputbody);
        }
        catch{
            #Write-Host "Pipeline settings for the organization [$($this.OrganizationContext.OrganizationName)] can not be fetched."
        }


        if([Helpers]::CheckMember($responseObj,"dataProviders"))
        {
            try {
             if($responseObj.dataProviders.'ms.vss-build-web.pipelines-org-settings-data-provider')
              {
                  $this.PipelineSettingsObj = $responseObj.dataProviders.'ms.vss-build-web.pipelines-org-settings-data-provider'
              }
            }
            catch {
                #Write-Host "Pipeline settings for the organization [$($this.OrganizationContext.OrganizationName)] can not be fetched."
            }

        }
    }

    hidden [ControlResult] CheckProCollSerAcc([ControlResult] $controlResult)
    {
        try
        {
            #api call to get PCSA descriptor which used to get PCSA members api call.
            $url = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $($this.OrganizationContext.OrganizationName);
            $body = '{"contributionIds":["ms.vss-admin-web.org-admin-groups-data-provider"],"dataProviderContext":{"properties":{"sourcePage":{"url":"https://dev.azure.com/{0}/_settings/groups","routeId":"ms.vss-admin-web.collection-admin-hub-route","routeValues":{"adminPivot":"groups","controller":"ContributedPage","action":"Execute"}}}}}'
            $body = ($body.Replace("{0}", $this.OrganizationContext.OrganizationName)) | ConvertFrom-Json
            $response = [WebRequestHelper]::InvokePostWebRequest($url,$body);

            $accname = "Project Collection Service Accounts"; #Enterprise Service Accounts
            if ($response -and [Helpers]::CheckMember($response[0],"dataProviders") -and $response[0].dataProviders."ms.vss-admin-web.org-admin-groups-data-provider") {

                $prcollobj = $response.dataProviders."ms.vss-admin-web.org-admin-groups-data-provider".identities | where {$_.displayName -eq $accname}
                #$prcollobj = $responseObj | where {$_.displayName -eq $accname}

                if(($prcollobj | Measure-Object).Count -gt 0)
                {
                    #pai call to get PCSA members
                    $prmemberurl = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $($this.OrganizationContext.OrganizationName);
                    $inputbody = '{"contributionIds":["ms.vss-admin-web.org-admin-members-data-provider"],"dataProviderContext":{"properties":{"subjectDescriptor":"{0}","sourcePage":{"url":"https://dev.azure.com/{1}/_settings/groups?subjectDescriptor={0}","routeId":"ms.vss-admin-web.collection-admin-hub-route","routeValues":{"adminPivot":"groups","controller":"ContributedPage","action":"Execute"}}}}}'
                    $inputbody = $inputbody.Replace("{0}",$prcollobj.descriptor)
                    $inputbody = $inputbody.Replace("{1}",$this.OrganizationContext.OrganizationName) | ConvertFrom-Json

                    $responsePrCollObj = [WebRequestHelper]::InvokePostWebRequest($prmemberurl,$inputbody);
                    $responsePrCollData = $responsePrCollObj.dataProviders.'ms.vss-admin-web.org-admin-members-data-provider'.identities
                    $memberCount = ($responsePrCollData | Measure-Object).Count
                    if($memberCount -gt 0){
                        $responsePrCollData = $responsePrCollData | Select-Object displayName,mailAddress,subjectKind
                        $stateData = @();
                        $stateData += $responsePrCollData
                        $controlResult.AddMessage("Total number of Project Collection Service Accounts: $($memberCount)");
                        $controlResult.AdditionalInfo += "Total number of Project Collection Service Accounts: " + $memberCount;
                        $controlResult.AddMessage([VerificationResult]::Verify, "Review the members of the group Project Collection Service Accounts: ", $stateData);
                        $controlResult.SetStateData("Members of the Project Collection Service Accounts group: ", $stateData);
                    }
                    else
                    { #count is 0 then there is no member in the prj coll ser acc group
                        $controlResult.AddMessage([VerificationResult]::Passed, "Project Collection Service Accounts group does not have any member.");
                    }
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Error, "Project Collection Service Accounts group could not be fetched.");
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Error, "Project Collection Service Accounts group could not be fetched.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of groups in the organization.");
            $controlResult.LogException($_)
        }

        return $controlResult
    }

    hidden [ControlResult] CheckSCALTForAdminMembers([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            if(($null -ne $this.ControlSettings) -and [Helpers]::CheckMember($this.ControlSettings, "Organization.GroupsToCheckForSCAltMembers"))
            {
                $adminGroupNames = @($this.ControlSettings.Organization.GroupsToCheckForSCAltMembers);
                if ($adminGroupNames.Count -gt 0)
                {
                    #api call to get descriptor for organization groups. This will be used to fetch membership of individual groups later.
                    $url = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $($this.OrganizationContext.OrganizationName);
                    $body = '{"contributionIds":["ms.vss-admin-web.org-admin-groups-data-provider"],"dataProviderContext":{"properties":{"sourcePage":{"url":"https://dev.azure.com/{0}/_settings/groups","routeId":"ms.vss-admin-web.collection-admin-hub-route","routeValues":{"adminPivot":"groups","controller":"ContributedPage","action":"Execute"}}}}}'
                    $body = ($body.Replace("{0}", $this.OrganizationContext.OrganizationName)) | ConvertFrom-Json
                    $response = [WebRequestHelper]::InvokePostWebRequest($url,$body);

                    if ($response -and [Helpers]::CheckMember($response[0],"dataProviders") -and $response[0].dataProviders."ms.vss-admin-web.org-admin-groups-data-provider")
                    {
                        $adminGroups = @();
                        $adminGroups += $response.dataProviders."ms.vss-admin-web.org-admin-groups-data-provider".identities | where { $_.displayName -in $adminGroupNames }
                        $PCSAGroup = @($response.dataProviders."ms.vss-admin-web.org-admin-groups-data-provider".identities | where { $_.displayName -eq "Project Collection Service Accounts"})
                        if(($adminGroups | Measure-Object).Count -gt 0)
                        {
                            #global variable to track admin members across all admin groups
                            $allAdminMembers = @();
                            $allPCSAMembers = @();

                            for ($i = 0; $i -lt $adminGroups.Count; $i++)
                            {
                                # [AdministratorHelper]::AllPCAMembers is a static variable. Always needs to be initialized. At the end of each iteration, it will be populated with members of that particular admin group.
                                [AdministratorHelper]::AllPCAMembers = @();
                                # Helper function to fetch flattened out list of group members.
                                [AdministratorHelper]::FindPCAMembers($adminGroups[$i].descriptor, $this.OrganizationContext.OrganizationName)

                                $groupMembers = @();
                                # Add the members of current group to this temp variable.
                                $groupMembers += [AdministratorHelper]::AllPCAMembers
                                # Create a custom object to append members of current group with the group name. Each of these custom object is added to the global variable $allAdminMembers for further analysis of SC-Alt detection.
                                $groupMembers | ForEach-Object {$allAdminMembers += @( [PSCustomObject] @{ name = $_.displayName; mailAddress = $_.mailAddress; id = $_.originId; groupName = $adminGroups[$i].displayName } )}
                            } 
                            if($PCSAGroup.Count -gt 0)
                            {

                                # [AdministratorHelper]::AllPCAMembers is a static variable. Needs to be reinitialized as it might contain group info from the previous for loop.
                                [AdministratorHelper]::AllPCAMembers = @();
                                # Helper function to fetch flattened out list of group members.
                                [AdministratorHelper]::FindPCAMembers($PCSAGroup.descriptor, $this.OrganizationContext.OrganizationName)

                                $groupMembers = @();
                                # Add the members of current group to this temp variable.
                                $groupMembers += [AdministratorHelper]::AllPCAMembers

                                # Preparing the list of members of PCSA which needs to be subtracted from $allAdminMembers
                                #USE IDENTITY ID
                                $groupMembers | ForEach-Object {$allPCSAMembers += @( [PSCustomObject] @{ name = $_.displayName; mailAddress = $_.mailAddress; id = $_.originId; groupName = "Project Collection Administrators" } )}

                            }

                            #Removing PCSA members from PCA members using id.
                            #TODO: HAVE ANOTHER CONTROL TO CHECK FOR PCA because some service accounts might be added directly as PCA and as well as part of PCSA. This new control will serve as a hygiene control.
                            if($allPCSAMembers.Count -gt 0)
                            {
                                $allAdminMembers = $allAdminMembers | ? {$_.id -notin $allPCSAMembers.id}
                            }

                            # clearing cached value in [AdministratorHelper]::AllPCAMembers as it can be used in attestation later and might have incorrect group loaded.
                            [AdministratorHelper]::AllPCAMembers = @();

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
                                    else
                                    {
                                        $controlResult.AddMessage([VerificationResult]::Error, "The signed-in user identity does not have graph permission.");
                                    }
                                }

                                if ([IdentityHelpers]::ALTControlEvaluationMethod -eq "RegEx" -or $useRegExEvaluation)
                                {
                                    if([Helpers]::CheckMember($this.ControlSettings, "AlernateAccountRegularExpressionForOrg"))
                                    {
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
                                                $controlResult.AddMessage([VerificationResult]::Failed, "`nCount of non-ALT accounts with admin privileges:  $nonSCCount"); 
                                                $controlResult.AddMessage("List of non SC-ALT accounts: ", $($stateData | Format-Table -AutoSize | Out-String));  
                                                $controlResult.SetStateData("List of non SC-ALT accounts: ", $stateData);
                                                $controlResult.AdditionalInfo += "Count of non SC-ALT accounts with admin privileges: " + $nonSCCount;
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
                                    else
                                    {
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
                            $controlResult.AddMessage([VerificationResult]::Error, "Could not find the list of administrator groups in the organization.");
                        }
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Error, "Could not find the list of groups in the organization.");
                    }
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Manual, "List of administrator groups for detecting non SC-Alt accounts is not defined in your organization.");
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Error, "List of administrator groups for detecting non SC-Alt accounts is not defined in your organization. Please update your ControlSettings.json as per the latest AzSK.ADO PowerShell module.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of groups in the organization.");
            $controlResult.LogException($_)
        }

        return $controlResult
    }

    hidden [ControlResult] CheckAADConfiguration([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            $apiURL = "https://dev.azure.com/{0}/_settings/organizationAad?__rt=fps&__ver=2" -f $($this.OrganizationContext.OrganizationName);
            $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($apiURL));

            if([Helpers]::CheckMember($responseObj[0],"fps.dataProviders.data") -and (-not [string]::IsNullOrWhiteSpace($responseObj[0].fps.dataProviders.data."ms.vss-admin-web.organization-admin-aad-data-provider".orgnizationTenantData.domain)))
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Organization is configured with [$($responseObj[0].fps.dataProviders.data.'ms.vss-admin-web.organization-admin-aad-data-provider'.orgnizationTenantData.displayName)] directory.");
                $controlResult.AdditionalInfo += "Organization is configured with [$($responseObj[0].fps.dataProviders.data.'ms.vss-admin-web.organization-admin-aad-data-provider'.orgnizationTenantData.displayName)] directory.";
            }
            else
            {
                $controlResult.AddMessage("Organization is not configured with AAD.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch AAD configuration details.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }


    hidden [ControlResult] CheckAltAuthSettings([ControlResult] $controlResult)
    {
       if([Helpers]::CheckMember($this.OrgPolicyObj,"applicationConnection"))
       {
           try {
               #https://devblogs.microsoft.com/devops/azure-devops-will-no-longer-support-alternate-credentials-authentication/
                $altAuthObj = $this.OrgPolicyObj.applicationConnection | Where-Object {$_.Policy.Name -eq "Policy.DisallowBasicAuthentication"}
                 if(($altAuthObj | Measure-Object).Count -gt 0)
                {
                     if($altAuthObj.policy.effectiveValue -eq $false )
                     {
                         $controlResult.AddMessage([VerificationResult]::Passed,
                                                     "Alternate authentication is disabled in organization.");
                     }
                     else {
                         $controlResult.AddMessage([VerificationResult]::Failed,
                                                     "Alternate authentication is enabled in organization.");
                     }
                 }
             }
             catch {
                $controlResult.AddMessage([VerificationResult]::Passed,
                "Alternate authentication is no longer supported in Azure DevOps.");
                $controlResult.LogException($_)
             }
        }

        return $controlResult
    }

    hidden [ControlResult] CheckExternalUserPolicy([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed

        if([Helpers]::CheckMember($this.OrgPolicyObj,"user"))
        {
            $guestAuthObj = @($this.OrgPolicyObj.user | Where-Object {$_.Policy.Name -eq "Policy.DisallowAadGuestUserAccess"})
            if($guestAuthObj.Count -gt 0)
            {
                if($guestAuthObj.policy.effectiveValue -eq $false )
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,"External guest access is disabled in the organization.");
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "External guest access is enabled in the organization.");
                    if($this.GuestMembers.Count -eq 0)
                    {
                        $this.FetchGuestMembersInOrg()
                    }                        
                    $totalGuestCount = $this.GuestMembers.Count
                    if($totalGuestCount -gt 0) {
                        $controlResult.AddMessage("`nCount of guest users in the organization: $($totalGuestCount)");
                        $controlResult.AdditionalInfo += "Count of guest users in the organization: " + $totalGuestCount;
                    }
                }
            }
            else
            {
                #Manual control status because external guest access notion is not applicable when AAD is not configured. Instead invite GitHub user policy is available in non-AAD backed orgs.
                $controlResult.AddMessage([VerificationResult]::Manual, "Could not fetch external guest access policy details of the organization. This policy is available only when the organization is connected to AAD.");
            }
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch user policy details of the organization.");
        }
        return $controlResult
    }

    hidden [ControlResult] CheckPublicProjectPolicy([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        if([Helpers]::CheckMember($this.OrgPolicyObj,"security"))
        {
            $publicProjectAccessObj = $this.OrgPolicyObj.security | Where-Object {$_.Policy.Name -eq "Policy.AllowAnonymousAccess"}
            if($publicProjectAccessObj -ne $null)
            {
                    if($publicProjectAccessObj.policy.effectiveValue -eq $false )
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed, "Public projects are not allowed in the organization.");
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Failed, "Public projects are allowed in the organization.");
                    }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the organization security policy for public projects.");
            }
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the organization security policies.");
        }
        return $controlResult
    }

    hidden [ControlResult] ValidateInstalledExtensions([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            if($null -eq $this.installedExtensionObj)
            {
                $apiURL = "https://extmgmt.dev.azure.com/{0}/_apis/extensionmanagement/installedextensions?api-version=6.0-preview.1" -f $($this.OrganizationContext.OrganizationName);
                $this.installedExtensionObj = @([WebRequestHelper]::InvokeGetWebRequest($apiURL));
            }

            if($this.installedExtensionObj.Count -gt 0 ) #includes both custom installed and built in extensions.
            {
                $extensionList = $this.installedExtensionObj | Select-Object extensionName,publisherId,publisherName,version,flags,lastPublished,scopes,extensionId # 'flags' is not available in every extension. It is visible only for built in extensions. Hence this appends 'flags' to trimmed objects.
                $extensionList = @($extensionList | Where-Object {$_.flags -notlike "*builtin*" }) # to filter out extensions that are built in and are not visible on portal.
                $ftWidth = 512 #Used for table output width to avoid "..." truncation
                $extCount = $extensionList.Count;

                if($extCount -gt 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Verify, "`nReview the list of installed extensions for your organization: ");
                    $controlResult.AddMessage("Count of installed extensions: " + $extCount);
                    $controlResult.AdditionalInfo += "Count of installed extensions: " + $extCount;
                    $this.ExtensionControlHelper($controlResult, $extensionList, 'Installed')
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No installed extensions found.");
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "No installed extensions found.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of installed extensions.");
            $controlResult.LogException($_)
        }

        return $controlResult
    }

    hidden [ControlResult] ValidateSharedExtensions([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            if($null -eq $this.allExtensionsObj)
            {
                $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $($this.OrganizationContext.OrganizationName);
                $orgURL="https://dev.azure.com/{0}/_settings/extensions" -f $($this.OrganizationContext.OrganizationName);
                $inputbody =  "{'contributionIds':['ms.vss-extmgmt-web.ext-management-hub'],'dataProviderContext':{'properties':{'sourcePage':{'url':'$orgURL','routeId':'ms.vss-admin-web.collection-admin-hub-route','routeValues':{'adminPivot':'extensions','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json
                $this.allExtensionsObj = @([WebRequestHelper]::InvokePostWebRequest($apiURL,$inputbody));
            }

            if([Helpers]::CheckMember($this.allExtensionsObj[0],"dataProviders") -and $this.allExtensionsObj.dataProviders.'ms.vss-extmgmt-web.extensionManagmentHub-collection-data-provider')
            {
                $sharedExtensions = @($this.allExtensionsObj[0].dataProviders.'ms.vss-extmgmt-web.extensionManagmentHub-collection-data-provider'.sharedExtensions)
                $sharedCount = $sharedExtensions.Count
                if($sharedCount -gt 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Verify, "Review the list of shared extensions for your organization: ");
                    $controlResult.AddMessage("Count of shared extensions: " + $sharedCount);
                    $controlResult.AdditionalInfo += "Count of shared extensions: " + $sharedCount;
                    $sharedExtList = $sharedExtensions | Select-Object extensionId, extensionName, isCertifiedPublisher, @{Name="lastPublished";Expression={$_.lastUpdated}}, publisherId, publisherName, version, scopes
                    $this.ExtensionControlHelper($controlResult, $sharedExtList, 'Shared')
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No shared extensions found.");
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of shared extensions.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of shared extensions.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckGuestIdentities([ControlResult] $controlResult)
    {
        try
        {
            if($this.GuestMembers.Count -eq 0)
            {
                $this.FetchGuestMembersInOrg()
            }
            $guestUsers = @($this.GuestMembers)
            if($guestUsers.Count -gt 0)
            {
                $guestList = @();
                $guestList +=  ($guestUsers | Select-Object @{Name="Id"; Expression = {$_.id}},@{Name="IdentityType"; Expression = {$_.user.subjectKind}},@{Name="DisplayName"; Expression = {$_.user.displayName}}, @{Name="MailAddress"; Expression = {$_.user.mailAddress}},@{Name="AccessLevel"; Expression = {$_.accessLevel.licenseDisplayName}},@{Name="LastAccessedDate"; Expression = {$_.lastAccessedDate}},@{Name="InactiveFromDays"; Expression = { if (((Get-Date) -[datetime]::Parse($_.lastAccessedDate)).Days -gt 10000){return "User was never active."} else {return ((Get-Date) -[datetime]::Parse($_.lastAccessedDate)).Days} }})
                $stateData = @();
                $stateData += ($guestUsers | Select-Object @{Name="Id"; Expression = {$_.id}},@{Name="IdentityType"; Expression = {$_.user.subjectKind}},@{Name="DisplayName"; Expression = {$_.user.displayName}}, @{Name="MailAddress"; Expression = {$_.user.mailAddress}})
                # $guestListDetailed would be same if DetailedScan is not enabled.
                $guestListDetailed = $guestList

                if([AzSKRoot]::IsDetailedScanRequired -eq $true)
                {
                    # If DetailedScan is enabled. fetch the project entitlements for the guest user
                    $guestListDetailed = $guestList | ForEach-Object {
                        try{
                            $guestUser = $_
                            $apiURL = "https://vsaex.dev.azure.com/{0}/_apis/userentitlements/{1}?api-version=6.1-preview.3" -f $($this.OrganizationContext.OrganizationName), $($guestUser.Id);
                            $projectEntitlements = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
                            $userProjectEntitlements = $projectEntitlements[0].projectEntitlements
                        }
                        catch {
                            $userProjectEntitlements = "Could not fetch project entitlement details of the user."
                            $controlResult.LogException($_)
                        }
                        return @{Id = $guestUser.Id; IdentityType = $guestUser.IdentityType; DisplayName = $guestUser.IdentityType; MailAddress = $guestUser.MailAddress; AccessLevel = $guestUser.AccessLevel; LastAccessedDate = $guestUser.LastAccessedDate; InactiveFromDays = $guestUser.InactiveFromDays; ProjectEntitlements = $userProjectEntitlements}
                    }
                }

                $totalGuestCount = ($guestListDetailed | Measure-Object).Count
                $controlResult.AddMessage("Displaying all guest users in the organization...");
                $controlResult.AddMessage([VerificationResult]::Verify,"Total number of guest users in the organization: $($totalGuestCount)");
                $controlResult.AdditionalInfo += "Total number of guest users in the organization: " + $totalGuestCount;
                $inactiveGuestUsers = $guestListDetailed | Where-Object { $_.InactiveFromDays -eq "User was never active." }
                $inactiveCount = ($inactiveGuestUsers | Measure-Object).Count
                if($inactiveCount) {
                    $controlResult.AddMessage("`nTotal number of guest users who were never active: $($inactiveCount)");
                    $controlResult.AdditionalInfo += "Total number of inactive guest users in the organization: " + $inactiveCount;
                    $controlResult.AddMessage("List of guest users who were never active: ",$inactiveGuestUsers);
                }

                $activeGuestUsers = $guestListDetailed | Where-Object { $_.InactiveFromDays -ne "User was never active." }
                $activeCount = ($activeGuestUsers | Measure-Object).Count
                if($activeCount) {
                    $controlResult.AddMessage("`nTotal number of guest users who are active: $($activeCount)");
                    $controlResult.AdditionalInfo += "Total number of active guest users in the organization: " + $activeCount;
                    $controlResult.AddMessage("List of guest users who are active: ",$activeGuestUsers);
                }
                $controlResult.SetStateData("Guest users list: ", $stateData);
            }
            else #external guest access notion is not applicable when AAD is not configured. Instead GitHub user notion is available in non-AAD backed orgs.
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "There are no guest users in the organization.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of guest identities.");
            $controlResult.LogException($_)
        }

        return $controlResult
    }

    hidden [ControlResult] CheckExtensionManagers([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            $apiURL = "https://extmgmt.dev.azure.com/{0}/_apis/securityroles/scopes/ems.manage.ui/roleassignments/resources/ems-ui" -f $($this.OrganizationContext.OrganizationName);
            $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($apiURL));

            # If no ext. managers are present, 'count' property is available for $responseObj[0] and its value is 0.
            # If ext. managers are assigned, 'count' property is not available for $responseObj[0].
            #'Count' is a PSObject property and 'count' is response object property. Notice the case sensitivity here.

            # TODO: When there are no managers check member in the below condition returns false when checknull flag [third param in CheckMember] is not specified (default value is $true). Assiging it $false. Need to revisit.
            if(([Helpers]::CheckMember($responseObj[0],"count",$false)) -and ($responseObj[0].count -eq 0))
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "No extension managers assigned.");
            }
             # When there are managers - the below condition will be true.
            elseif((-not ([Helpers]::CheckMember($responseObj[0],"count"))) -and ($responseObj.Count -gt 0))
            {
                $controlResult.AddMessage("Count of extension managers present: " + $responseObj.Count)
                $controlResult.AdditionalInfo += "Count of extension managers present: " + $responseObj.Count;
                $extensionManagerList =  @($responseObj | Select-Object @{Name="IdentityName"; Expression = {$_.identity.displayName}},@{Name="Role"; Expression = {$_.role.displayName}})
                $controlResult.AddMessage([VerificationResult]::Verify, "Review the list of extension managers as under: `n",$($extensionManagerList | FT | out-string));
                $controlResult.SetStateData("List of extension managers: ", $extensionManagerList);
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "No extension managers assigned.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of extension managers.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckInactiveUsers([ControlResult] $controlResult)
    {
        try {
            $topInactiveUsers = $this.ControlSettings.Organization.TopInactiveUserCount
            $apiURL = "https://vsaex.dev.azure.com/{0}/_apis/UserEntitlements?top={1}&filter=&sortOption=lastAccessDate+ascending&api-version=6.1-preview.3" -f $($this.OrganizationContext.OrganizationName), $topInActiveUsers;
            $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($apiURL));

            if($responseObj.Count -gt 0)
            {
                $inactiveUsers =  @()
                $inactivityThresholdInDays = $this.ControlSettings.Organization.InActiveUserActivityLogsPeriodInDays
                $thresholdDate = (Get-Date).AddDays(-$($inactivityThresholdInDays))
                $responseObj[0].items | ForEach-Object {
                    if([datetime]::Parse($_.lastAccessedDate) -lt $thresholdDate)
                    {
                        $inactiveUsers+= $_
                    }
                }
                if($inactiveUsers.Count -gt 0)
                {
                    $controlResult.AddMessage("Found $($inactiveUsers.Count) inactive for last $($inactivityThresholdInDays) days.")
                    if($inactiveUsers.Count -ge $topInactiveUsers)
                    {
                        $controlResult.AddMessage("Displaying top $($topInactiveUsers) inactive users")
                    }
                    #inactive user with days from how many days user is inactive, if user account created and was never active, in this case lastaccessdate is default 01-01-0001
                    $inactiveUsers = ($inactiveUsers | Select-Object -Property @{Name="Name"; Expression = {$_.User.displayName}},@{Name="mailAddress"; Expression = {$_.User.mailAddress}},@{Name="InactiveFromDays"; Expression = { if (((Get-Date) -[datetime]::Parse($_.lastAccessedDate)).Days -gt 10000){return "User was never active."} else {return ((Get-Date) -[datetime]::Parse($_.lastAccessedDate)).Days} }})
                    #set data for attestation
                    $inactiveUsersStateData = ($inactiveUsers | Select-Object -Property @{Name="Name"; Expression = {$_.Name}},@{Name="mailAddress"; Expression = {$_.mailAddress}})

                    $inactiveUsersCount = ($inactiveUsers | Measure-Object).Count
                    $controlResult.AddMessage([VerificationResult]::Failed,"Total number of inactive users present in the organization: $($inactiveUsersCount)");
                    $controlResult.AdditionalInfo += "Total number of inactive users present in the organization: " + $inactiveUsersCount;
                    $controlResult.SetStateData("Inactive users list: ", $inactiveUsersStateData);

                    # segregate never active users from the list
                    $neverActiveUsers = $inactiveUsers | Where-Object {$_.InactiveFromDays -eq "User was never active."}
                    $inactiveUsersWithDays = $inactiveUsers | Where-Object {$_.InactiveFromDays -ne "User was never active."}

                    $neverActiveUsersCount = ($neverActiveUsers | Measure-Object).Count
                    if ($neverActiveUsersCount -gt 0) {
                        $controlResult.AddMessage("`nTotal number of users who were never active: $($neverActiveUsersCount)");
                        $controlResult.AddMessage("Review users present in the organization who were never active: ",$neverActiveUsers);
                        $ftWidth = 512 #To avoid "..." truncation
                        $display = ($neverActiveUsers |  FT mailAddress, Name, InactiveFromDays -AutoSize | Out-String -Width $ftWidth)
                        $controlResult.AddMessage("Review users present in the organization who were never active: ",$display);
                        $controlResult.AdditionalInfo += "Total number of users who were never active: " + $neverActiveUsersCount;
                        $controlResult.AdditionalInfo += "List of users who were never active: " + [JsonHelper]::ConvertToJsonCustomCompressed($neverActiveUsers);
                    }

                    $inactiveUsersWithDaysCount = ($inactiveUsersWithDays | Measure-Object).Count
                    if($inactiveUsersWithDaysCount -gt 0) {
                        $controlResult.AddMessage("`nTotal number of users who are inactive from last $($this.ControlSettings.Organization.InActiveUserActivityLogsPeriodInDays) days: $($inactiveUsersWithDaysCount)");
                        $controlResult.AddMessage("Review users present in the organization who are inactive from last $($this.ControlSettings.Organization.InActiveUserActivityLogsPeriodInDays) days: ",$inactiveUsersWithDays);
                        $ftWidth = 512 #To avoid "..." truncation
                        $display = ($inactiveUsersWithDays |  FT mailAddress, Name, InactiveFromDays -AutoSize | Out-String -Width $ftWidth)
                        $controlResult.AddMessage("Review users present in the organization who are inactive from last $($this.ControlSettings.Organization.InActiveUserActivityLogsPeriodInDays) days: ",$display);
                        $controlResult.AdditionalInfo += "Total number of users who are inactive from last $($this.ControlSettings.Organization.InActiveUserActivityLogsPeriodInDays) days: " + $inactiveUsersWithDaysCount;
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No users found to be inactive for last $($inactivityThresholdInDays) days.")
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "No users found in the org.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of users in the organization.");
            $controlResult.LogException($_)
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckDisconnectedIdentities([ControlResult] $controlResult)
    {
        #Note : Admin Permissions are required to fetch disconnected accounts
        try
        {
            $controlResult.VerificationResult = [VerificationResult]::Failed
            $apiURL = "https://dev.azure.com/{0}/_apis/OrganizationSettings/DisconnectedUser" -f $($this.OrganizationContext.OrganizationName);
            $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($apiURL));

            #Disabling null check to CheckMember because if there are no disconnected users - it will return null.
            if ([Helpers]::CheckMember($responseObj[0], "users",$false))
            {
                $disconnectedUsersCount = $responseObj[0].users.Count
                if ($disconnectedUsersCount -gt 0 )
                {
                    $disconnectedUsersList += @($responseObj[0].users | Select-Object -Property @{Name = "Name"; Expression = { $_.displayName } }, @{Name = "MailAddress"; Expression = { $_.preferredEmailAddress } })
                    $controlResult.AddMessage("Count of disconnected users: $($disconnectedUsersCount)`n");
                    $controlResult.AddMessage([VerificationResult]::Failed, "Remove access for below disconnected users: ", ($disconnectedUsersList | FT | out-string));
                    $controlResult.SetStateData("Disconnected users list: ", $disconnectedUsersList);
                    $controlResult.AdditionalInfo += "Count of disconnected users: " + $disconnectedUsersCount ;
                    $controlResult.AdditionalInfo += "List of disconnected users: " + $disconnectedUsersList;
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No disconnected users found for this organization.");
                }
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of disconnected users for this organization.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of disconnected users for this organization.");
            $controlResult.LogException($_)
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckRBACAccess([ControlResult] $controlResult)
    {
        <#
            This control has been currently removed from control JSON file.
            {
                "ControlID": "ADO_Organization_AuthZ_Min_RBAC_Access",
                "Description": "All teams/groups must be granted minimum required permissions in your organization.",
                "Id": "Organization200",
                "ControlSeverity": "High",
                "Automated": "No",
                "MethodName": "CheckRBACAccess",
                "Rationale": "Granting minimum access by leveraging RBAC feature ensures that users are granted just enough permissions to perform their tasks. This minimizes exposure of the resources in case of user/service account compromise.",
                "Recommendation": "Go to Organization Settings --> Permissions --> Select team/group --> Validate Permissions",
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
        $url= "https://vssps.dev.azure.com/{0}/_apis/graph/groups?api-version=6.0-preview.1" -f $($this.OrganizationContext.OrganizationName);
        $groupsObj = [WebRequestHelper]::InvokeGetWebRequest($url);

        $apiURL = "https://vsaex.dev.azure.com/{0}/_apis/UserEntitlements?top=50&filter=&sortOption=lastAccessDate+ascending&api-version=6.1-preview.3" -f $($this.OrganizationContext.OrganizationName);
        $usersObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);

        $Users =  @()
        $usersObj[0].items | ForEach-Object {
                $Users+= $_
        }

        $groups = ($groupsObj | Select-Object -Property @{Name="Name"; Expression = {$_.displayName}},@{Name="mailAddress"; Expression = {$_.mailAddress}});

        $UsersNames = ($Users | Select-Object -Property @{Name="Name"; Expression = {$_.User.displayName}},@{Name="mailAddress"; Expression = {$_.User.mailAddress}})

        if ( (($groups | Measure-Object).Count -gt 0) -or (($UsersNames | Measure-Object).Count -gt 0)) {
            $controlResult.AddMessage([VerificationResult]::Verify, "Verify users and groups present on Organization");

            $controlResult.AddMessage("Verify groups present on Organization", $groups);
            $controlResult.AddMessage("Verify users present on Organization", $UsersNames);
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
        $url= "https://vssps.dev.azure.com/{0}/_apis/graph/groups?api-version=6.0-preview.1" -f $($this.OrganizationContext.OrganizationName);
        $groupsObj = [WebRequestHelper]::InvokeGetWebRequest($url);

        $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview" -f $($this.OrganizationContext.OrganizationName);

        $membercount =0;
        Foreach ($group in $groupsObj){
         $groupmember = @();
         $descriptor = $group.descriptor;
         $inputbody =  '{"contributionIds":["ms.vss-admin-web.org-admin-members-data-provider"],"dataProviderContext":{"properties":{"subjectDescriptor":"","sourcePage":{"url":"","routeId":"ms.vss-admin-web.collection-admin-hub-route","routeValues":{"adminPivot":"groups","controller":"ContributedPage","action":"Execute"}}}}}' | ConvertFrom-Json

         $inputbody.dataProviderContext.properties.subjectDescriptor = $descriptor;
         $inputbody.dataProviderContext.properties.sourcePage.url = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/_settings/groups?subjectDescriptor=$($descriptor)";
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
            $controlResult.AddMessage([VerificationResult]::Verify, "Verify members of groups present on Organization");
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,  "No users or groups found");
        }

        return $controlResult
    }

    hidden [ControlResult] CheckOAuthAppAccess([ControlResult] $controlResult)
    {
       if([Helpers]::CheckMember($this.OrgPolicyObj,"applicationConnection"))
       {
            $OAuthObj = $this.OrgPolicyObj.applicationConnection | Where-Object {$_.Policy.Name -eq "Policy.DisallowOAuthAuthentication"}
            if(($OAuthObj | Measure-Object).Count -gt 0)
            {
                if($OAuthObj.policy.effectiveValue -eq $true )
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Third-party application access via OAuth is enabled.");
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "Third-party application access via OAuth is disabled.");
                }
            }
       }
        return $controlResult
    }

    hidden [ControlResult] CheckSSHAuthN([ControlResult] $controlResult)
    {
       if([Helpers]::CheckMember($this.OrgPolicyObj,"applicationConnection"))
       {
            $SSHAuthObj = $this.OrgPolicyObj.applicationConnection | Where-Object {$_.Policy.Name -eq "Policy.DisallowSecureShell"}
            if(($SSHAuthObj | Measure-Object).Count -gt 0)
            {
                if($SSHAuthObj.policy.effectiveValue -eq $true )
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Connecting to Git repos via SSH authentication is enabled in the organization.");
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "Connecting to Git repos via SSH authentication is disabled in the organization.");
                }
            }
       }
        return $controlResult
    }

    hidden [ControlResult] CheckEnterpriseAccess([ControlResult] $controlResult)
    {
       if([Helpers]::CheckMember($this.OrgPolicyObj,"security"))
       {
            $CAPObj = $this.OrgPolicyObj.security | Where-Object {$_.Policy.Name -eq "Policy.AllowOrgAccess"}
            if(($CAPObj | Measure-Object).Count -gt 0)
            {
                if($CAPObj.policy.effectiveValue -eq $true )
                {
                    $controlResult.AddMessage([VerificationResult]::Verify,
                                                "Enterprise access to projects is enabled.");
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed,
                                                "Enterprise access to projects is disabled.");
                }
            }
       }
        return $controlResult
    }

    hidden [ControlResult] CheckCAP([ControlResult] $controlResult)
    {
       if([Helpers]::CheckMember($this.OrgPolicyObj,"security"))
       {
            $CAPObj = $this.OrgPolicyObj.security | Where-Object {$_.Policy.Name -eq "Policy.EnforceAADConditionalAccess"}
            if(($CAPObj | Measure-Object).Count -gt 0)
            {
                if($CAPObj.policy.effectiveValue -eq $true )
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,
                                                "AAD conditional access policy validation is enabled.");
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Failed,
                                                "AAD conditional access policy validation is disabled.");
                }
            }
       }
        return $controlResult
    }

    hidden [ControlResult] CheckBadgeAnonAccess([ControlResult] $controlResult)
    {
       if($this.PipelineSettingsObj)
       {

            if($this.PipelineSettingsObj.statusBadgesArePrivate -eq $true )
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Anonymous access to status badge API is disabled.");
            }
            else{
                $controlResult.AddMessage([VerificationResult]::Failed, "Anonymous access to status badge API is enabled.");
            }
       }
       else{
            $controlResult.AddMessage([VerificationResult]::Manual, "Pipeline settings could not be fetched due to insufficient permissions at organization scope.");
       }
        return $controlResult
    }

    hidden [ControlResult] CheckSettableQueueTime([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        if($this.PipelineSettingsObj)
        {
            if($this.PipelineSettingsObj.enforceSettableVar -eq $true )
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Only explicitly marked 'settable at queue time' variables can be set at queue time.");
            }
            else{
                $controlResult.AddMessage([VerificationResult]::Failed, "All variables can be set at queue time.");
            }
        }
        else{
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the organization pipeline settings.");
        }
        return $controlResult
    }

    hidden [ControlResult] CheckJobAuthZScope([ControlResult] $controlResult)
    {
       $controlResult.VerificationResult = [VerificationResult]::Failed
       if($this.PipelineSettingsObj)
       {
            $orgLevelScope = $this.PipelineSettingsObj.enforceJobAuthScope

            if($orgLevelScope -eq $true )
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Job authorization scope is limited to current project for non-release pipelines at organization level.");
            }
            else{
                $controlResult.AddMessage([VerificationResult]::Failed, "Job authorization scope is set to project collection for non-release pipelines at organization level.");
            }
       }
       else{
             $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the organization pipeline settings.");
       }
        return $controlResult
    }

    hidden [ControlResult] CheckJobAuthZReleaseScope([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
       if($this.PipelineSettingsObj)
       {
            $orgLevelScope = $this.PipelineSettingsObj.enforceJobAuthScopeForReleases

            if($orgLevelScope -eq $true )
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Job authorization scope is limited to current project for release pipelines at organization level.");
            }
            else{
                $controlResult.AddMessage([VerificationResult]::Failed, "Job authorization scope is set to project collection for release pipelines at organization level.");
            }
       }
       else{
             $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the organization pipeline settings.");
       }
        return $controlResult
    }

    hidden [ControlResult] CheckAuthZRepoScope([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed;
        if($this.PipelineSettingsObj)
        {
            $orgLevelScope = $this.PipelineSettingsObj.enforceReferencedRepoScopedToken
 
            if($orgLevelScope -eq $true )
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Job authorization scope of pipelines is limited to explicitly referenced Azure DevOps repositories at organization level.");
            }
            else{
                $controlResult.AddMessage([VerificationResult]::Failed, "Job authorization scope of pipelines is set to all Azure DevOps repositories in the authorized projects at organization level.");
            }
        }
        else{
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the organization pipeline settings.");
        }
        return $controlResult
    }

    hidden [ControlResult] CheckBuiltInTask([ControlResult] $controlResult)
    {
       <# This control has been currently removed from control JSON file.
         {
            "ControlID": "ADO_Organization_SI_Review_BuiltIn_Tasks_Setting",
            "Description": "Review built-in tasks from being used in pipelines.",
            "Id": "Organization334",
            "ControlSeverity": "Medium",
            "Automated": "Yes",
            "MethodName": "CheckBuiltInTask",
            "Rationale": "Running built-in tasks from untrusted source can lead to all type of attacks and loss of sensitive enterprise data.",
            "Recommendation": "Go to Organization settings --> Pipelines --> Settings --> Task restrictions --> Turn on 'Disable built-in tasks' flag.",
            "Tags": [
                "SDL",
                "TCP",
                "Automated",
                "SI"
            ],
            "Enabled": true
         },
       #>
       if($this.PipelineSettingsObj)
       {
            $orgLevelScope = $this.PipelineSettingsObj.disableInBoxTasksVar

            if($orgLevelScope -eq $true )
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Built-in tasks are disabled at organization level.");
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Failed, "Built-in tasks are not disabled at organization level.");
            }
       }
       else
       {
             $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the organization pipeline settings.");
       }
        return $controlResult
    }

    hidden [ControlResult] CheckMarketplaceTask([ControlResult] $controlResult)
    {
        <# This control has been currently removed from control JSON file.
         {
            "ControlID": "ADO_Organization_SI_Review_Marketplace_Tasks_Setting",
            "Description": "Review Marketplace tasks from being used in pipelines.",
            "Id": "Organization336",
            "ControlSeverity": "Medium",
            "Automated": "Yes",
            "MethodName": "CheckMarketplaceTask",
            "Rationale": "Running Marketplace tasks from untrusted source can lead to all type of attacks and loss of sensitive enterprise data.",
            "Recommendation": "Go to Organization settings --> Pipelines --> Settings --> Task restrictions --> Turn on 'Disable Marketplace tasks'.",
            "Tags": [
                "SDL",
                "TCP",
                "Automated",
                "SI"
            ],
            "Enabled": true
         },
       #>
       if($this.PipelineSettingsObj)
       {
            $orgLevelScope = $this.PipelineSettingsObj.disableMarketplaceTasksVar

            if($orgLevelScope -eq $true )
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Market place tasks are disabled at organization level.");
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Failed, "Market place tasks are not disabled at organization level.");
            }
       }
       else
       {
             $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the organization pipeline settings.");
       }
        return $controlResult
    }

    hidden [ControlResult] CheckPolicyProjectTeamAdminUserInvitation([ControlResult] $controlResult)
    {
        if([Helpers]::CheckMember($this.OrgPolicyObj,"user"))
        {
            $userPolicyObj = $this.OrgPolicyObj.user
            $userInviteObj = $userPolicyObj | Where-Object {$_.Policy.Name -eq "Policy.AllowTeamAdminsInvitationsAccessToken"}
            if(($userInviteObj | Measure-Object).Count -gt 0)
            {

                if($userInviteObj.policy.effectiveValue -eq $false )
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,"Team and project administrators are not allowed to invite new users.");
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Team and project administrators are allowed to invite new users.");
                }
            }
            else
            {
                #Manual control status because the notion of team and project admins inviting new users is not applicable when AAD is not configured.
                $controlResult.AddMessage([VerificationResult]::Manual, "Could not fetch invite new user policy details of the organization. This policy is available only when the organization is connected to AAD.");
            }
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch user policy details of the organization.");
        }
        return $controlResult
    }

    hidden [ControlResult] CheckRequestAccessPolicy([ControlResult] $controlResult)
    {
        <# This control has been currently removed from control JSON file.
        {
            "ControlID": "ADO_Organization_AuthZ_Disable_Request_Access",
            "Description": "Stop your users from requesting access to your organization or project within your organization, by disabling the request access policy.",
            "Id": "Organization339",
            "ControlSeverity": "Medium",
            "Automated": "Yes",
            "MethodName": "CheckRequestAccessPolicy",
            "Rationale": "When request access policy is enabled, users can request access to a resource. Disabling this policy will prevent users from requesting access to organization or project within the organization.",
            "Recommendation": "Go to Organization Settings --> Policy --> User Policy --> Disable 'Request Access'.",
            "Tags": [
                "SDL",
                "TCP",
                "Automated",
                "AuthZ"
            ],
            "Enabled": true
        },
        #>
        if([Helpers]::CheckMember($this.OrgPolicyObj,"user"))
        {
            $userPolicyObj = $this.OrgPolicyObj.user
            $requestAccessObj = $userPolicyObj | Where-Object {$_.Policy.Name -eq "Policy.AllowRequestAccessToken"}
            if(($requestAccessObj | Measure-Object).Count -gt 0)
            {

                if($requestAccessObj.policy.effectiveValue -eq $false )
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,"Users can not request access to organization or projects within the organization.");
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Users can request access to organization or projects within the organization.");
                }
            }
            else
            {
                #Manual control status because the notion of request access is not applicable when AAD is not configured.
                $controlResult.AddMessage([VerificationResult]::Manual, "Could not fetch request access policy details of the organization. This policy is available only when the organization is connected to AAD.");
            }
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch user policy details of the organization.");
        }
        return $controlResult
    }

    hidden [ControlResult] CheckAutoInjectedExtensions([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            if($null -eq $this.installedExtensionObj)
            {
                $url ="https://extmgmt.dev.azure.com/{0}/_apis/extensionmanagement/installedextensions?api-version=6.0-preview.1" -f $($this.OrganizationContext.OrganizationName);
                $this.installedExtensionObj = @([WebRequestHelper]::InvokeGetWebRequest($url));
            }

            $autoInjExt = @();
            foreach($extension in $this.installedExtensionObj)
            {
                foreach($cont in $extension.contributions)
                {
                    if([Helpers]::CheckMember($cont,"type"))
                    {
                        if($cont.type -eq "ms.azure-pipelines.pipeline-decorator")
                        {
                            $autoInjExt +=  $extension
                            break;
                        }
                    }
                }
            }

            if ($autoInjExt.Count -gt 0)
            {
                $autoInjExt = $autoInjExt | Select-Object extensionName,publisherId,publisherName,version,flags,lastPublished,scopes,extensionId # 'flags' is not available in every extension. It is visible only for built in extensions. Hence this appends 'flags' to trimmed objects.
                $autoInjExt = @($autoInjExt | Where-Object {$_.flags -notlike "*builtin*" }) # to filter out extensions that are built in and are not visible on portal.
                $ftWidth = 512 #Used for table output width to avoid "..." truncation
                $extCount = $autoInjExt.Count;

                if($extCount -gt 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Verify, "`nReview the list of auto-injected extensions for your organization: ");
                    $controlResult.AddMessage("Count of auto-injected extensions: " + $extCount);
                    $controlResult.AdditionalInfo += "Count of auto-injected extensions: " + $extCount;
                    $this.ExtensionControlHelper($controlResult, $autoInjExt, 'AutoInjected')
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No auto-injected extensions found.");
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed,"No auto-injected tasks found at organization level");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,"Couldn't fetch the list of installed extensions in the organization.");
            $controlResult.LogException($_)
        }

        return $controlResult
    }

    hidden [ControlResult] CheckMinPCACount([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try{
            $TotalPCAMembers=0
            if ($this.PCAMembersList.Count -eq 0) {
                $this.PCAMembersList =@([AdministratorHelper]::GetTotalPCAMembers($this.OrganizationContext.OrganizationName))
            }
            $PCAMembers = $this.PCAMembersList
            $TotalPCAMembers = $PCAMembers.Count
            $controlResult.AddMessage("There are a total of $TotalPCAMembers Project Collection Administrators in your organization.")
            if ($this.graphPermissions.hasGraphAccess)
            {
                if($this.svcAccountsList.Count -eq 0 -and $this.humanAccountsList.Count -eq 0){
                    $SvcAndHumanAccounts = [IdentityHelpers]::DistinguishHumanAndServiceAccount($PCAMembers, $this.OrganizationContext.OrganizationName)
                    $this.svcAccountsList = @($SvcAndHumanAccounts.serviceAccount | Select-Object displayName, mailAddress);
                    $this.humanAccountsList= @($SvcAndHumanAccounts.humanAccount | Select-Object displayName, mailAddress);
                }
                $svcAccounts=$this.svcAccountsList
                $humanAccounts=$this.humanAccountsList
                if($humanAccounts.Count -lt $this.ControlSettings.Organization.MinPCAMembersPermissible){
                    $controlResult.AddMessage([VerificationResult]::Failed,"Number of human administrators configured are less than the minimum required administrators count: $($this.ControlSettings.Organization.MinPCAMembersPermissible)");
                }
                else{
                    $controlResult.AddMessage([VerificationResult]::Passed,"Number of human administrators configured meet the minimum required administrators count: $($this.ControlSettings.Organization.MinPCAMembersPermissible)");
                }
                [AdministratorHelper]::PopulatePCAResultsToControl($humanAccounts, $svcAccounts, $controlResult)
            }
            ## TODO: Add warning that control was evaluated without graph access ( Once Sourabh is done with its Graph access task)
            else
            {
                $PCAMembers = @($PCAMembers | Select-Object displayName,mailAddress)
                if($TotalPCAMembers -lt $this.ControlSettings.Organization.MinPCAMembersPermissible){
                    $controlResult.AddMessage([VerificationResult]::Failed,"Number of administrators configured are less than the minimum required administrators count: $($this.ControlSettings.Organization.MinPCAMembersPermissible)");
                }
                else{
                    $controlResult.AddMessage([VerificationResult]::Passed,"Number of administrators configured meet the minimum required administrators count: $($this.ControlSettings.Organization.MinPCAMembersPermissible)");
                }
                if($TotalPCAMembers -gt 0){
                    $display=($PCAMembers |  FT displayName, mailAddress -AutoSize | Out-String -Width 512)
                    $controlResult.AddMessage("Current set of Project Collection Administrators: `n",$display)
                    $controlResult.SetStateData("List of Project Collection Administrators: ",$PCAMembers)
                    $controlResult.AdditionalInfo = "Count of Project Collection Administrators: " + $TotalPCAMembers;
                }
            }
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,"Couldn't fetch the list of Project Collection Administrators.");
            $controlResult.LogException($_)
        }

        return $controlResult
    }

    hidden [ControlResult] CheckMaxPCACount([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try{
            $TotalPCAMembers=0
            
            if ($this.PCAMembersList.Count -eq 0) {
                $this.PCAMembersList =@([AdministratorHelper]::GetTotalPCAMembers($this.OrganizationContext.OrganizationName))
            }
            $PCAMembers = $this.PCAMembersList
            $TotalPCAMembers = $PCAMembers.Count
            $controlResult.AddMessage("There are a total of $TotalPCAMembers Project Collection Administrators in your organization.")
            if ($this.graphPermissions.hasGraphAccess)
            {  
                if($this.svcAccountsList.Count -eq 0 -and $this.humanAccountsList.Count -eq 0){
                    $SvcAndHumanAccounts = [IdentityHelpers]::DistinguishHumanAndServiceAccount($PCAMembers, $this.OrganizationContext.OrganizationName)
                    $this.svcAccountsList = @($SvcAndHumanAccounts.serviceAccount | Select-Object displayName, mailAddress);
                    $this.humanAccountsList= @($SvcAndHumanAccounts.humanAccount | Select-Object displayName, mailAddress);
                }
                $svcAccounts=$this.svcAccountsList
                $humanAccounts=$this.humanAccountsList
                
                if($humanAccounts.Count -gt $this.ControlSettings.Organization.MaxPCAMembersPermissible){
                    $controlResult.AddMessage([VerificationResult]::Failed,"Number of human administrators configured are more than the approved limit: $($this.ControlSettings.Organization.MaxPCAMembersPermissible)");
                }
                else{
                    $controlResult.AddMessage([VerificationResult]::Passed,"Number of human administrators configured are within the approved limit: $($this.ControlSettings.Organization.MaxPCAMembersPermissible)");
                }
                [AdministratorHelper]::PopulatePCAResultsToControl($humanAccounts, $svcAccounts, $controlResult)
            }
            ## TODO: Add warning that control was evaluated without graph access ( Once Sourabh is done with its Graph access task)
            else
            {
                $PCAMembers = @($PCAMembers | Select-Object displayName,mailAddress)
                if($TotalPCAMembers -gt $this.ControlSettings.Organization.MaxPCAMembersPermissible){
                    $controlResult.AddMessage([VerificationResult]::Failed,"Number of administrators configured are more than the approved limit: $($this.ControlSettings.Organization.MaxPCAMembersPermissible)");
                }
                else{
                    $controlResult.AddMessage([VerificationResult]::Passed,"Number of administrators configured are within the approved limit: $($this.ControlSettings.Organization.MaxPCAMembersPermissible)");
                }
                 
                if($TotalPCAMembers -gt 0){
                    $display=($PCAMembers |  FT displayName, mailAddress -AutoSize | Out-String -Width 512)
                    $controlResult.AddMessage("Current set of Project Collection Administrators: `n",$display)
                    $controlResult.SetStateData("List of Project Collection Administrators: ",$PCAMembers)
                    $controlResult.AdditionalInfo = "Count of Project Collection Administrators: " + $TotalPCAMembers;
                }
            }
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,"Couldn't fetch the list of Project Collection Administrators.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckAuditStream([ControlResult] $controlResult)
    {
        #Note : Admin access is required to fetch the audit streams configure in organization
        try
        {
            $controlResult.VerificationResult = [VerificationResult]::Failed
            $url ="https://auditservice.dev.azure.com/{0}/_apis/audit/streams?api-version=6.0-preview.1" -f $($this.OrganizationContext.OrganizationName);
            $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($url));

            # If no audit streams are configured, 'count' property is available for $responseObj[0] and its value is 0.
            # If audit streams are configured, 'count' property is not available for $responseObj[0].
            #'Count' is a PSObject property and 'count' is response object property. Notice the case sensitivity here.

            if(([Helpers]::CheckMember($responseObj[0],"count",$false)) -and ($responseObj[0].count -eq 0))
            {
                $controlResult.AddMessage([VerificationResult]::Failed, "Audit streaming is not setup for the organization.");
            }
             # When audit streams are configured - the below condition will be true.
            elseif((-not ([Helpers]::CheckMember($responseObj[0],"count"))) -and ($responseObj.Count -gt 0))
            {
                $enabledStreams = @($responseObj | Where-Object {$_.status -eq 'enabled'} | Select-Object consumerType,displayName,status)
                $enabledStreamsCount = $enabledStreams.Count
                $totalStreamsCount = $responseObj.Count
                $controlResult.AddMessage("`nCount of configured audit streams: $($totalStreamsCount)");
                $controlResult.AdditionalInfo += "Count of configured audit streams: " + $totalStreamsCount;
                if ($enabledStreamsCount -gt 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "One or more audit streams configured on the organization are currently enabled.");
                    $controlResult.AddMessage("`nCount of configured audit streams that are enabled: $($enabledStreamsCount)");
                    $controlResult.AddMessage(($enabledStreams | FT | out-string));
                    $controlResult.AdditionalInfo += "Count of configured audit streams that are enabled: " + $enabledStreamsCount;
                    $controlResult.AdditionalInfo += "List of configured audit streams that are enabled: " + $enabledStreams;
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "None of the audit streams that have been configured are currently enabled.");
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Failed, "No audit stream has been configured on the organization.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of audit streams enabled on the organization.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] ValidateRequestedExtensions([ControlResult] $controlResult)
    {
        #TODO: Need to add deep scan support for requested extensions. Currently there is no documented api for requested extensions and in portal api response, required properties are missing to perform deep scan. PG bug id: 7628393.
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            if($null -eq $this.allExtensionsObj)
            {
                $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $($this.OrganizationContext.OrganizationName);
                $orgURL="https://dev.azure.com/{0}/_settings/extensions" -f $($this.OrganizationContext.OrganizationName);
                $inputbody =  "{'contributionIds':['ms.vss-extmgmt-web.ext-management-hub'],'dataProviderContext':{'properties':{'sourcePage':{'url':'$orgURL','routeId':'ms.vss-admin-web.collection-admin-hub-route','routeValues':{'adminPivot':'extensions','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json
                $this.allExtensionsObj = @([WebRequestHelper]::InvokePostWebRequest($apiURL,$inputbody));
            }
            if([Helpers]::CheckMember($this.allExtensionsObj[0],"dataProviders") -and $this.allExtensionsObj.dataProviders.'ms.vss-extmgmt-web.extensionManagmentHub-collection-data-provider')
            {
                $requestedExtensions = @($this.allExtensionsObj[0].dataProviders.'ms.vss-extmgmt-web.extensionManagmentHub-collection-data-provider'.requestedExtensions)
                if($requestedExtensions.Count -gt 0)
                {
                    $PendingExtensionsForApproval = @($requestedExtensions | Where-Object { $_.requestState -eq "0" })
                    $PendingExtensionsForApproval =  @($PendingExtensionsForApproval | Select-Object extensionID, publisherId,@{Name="Requested By";Expression={$_.requests.userName}})
                    $ftWidth = 512 #To avoid "..." truncation
                    $pendingExtCount = $PendingExtensionsForApproval.Count

                    if($pendingExtCount -gt 0)
                    {
                        $controlResult.AddMessage([VerificationResult]::Verify, "`nReview the list of requested extensions for your organization that are pending for approval: ");
                        $controlResult.AddMessage("Count of requested extensions that are pending for approval: $($pendingExtCount)")
                        $controlResult.AdditionalInfo += "Count of requested extensions that are pending for approval: " + $pendingExtCount;
                        $display = ($PendingExtensionsForApproval |  FT -AutoSize | Out-String -Width $ftWidth)
                        $controlResult.AddMessage($display)
                        $controlResult.SetStateData("List of pending requested extensions: ", $PendingExtensionsForApproval);
                        $controlResult.AdditionalInfo += "List of requested extensions: " + [JsonHelper]::ConvertToJsonCustomCompressed($PendingExtensionsForApproval);

                        <# Not displaying approved and rejected extension details as these details are not required.
                            $ApprovedExtensions = @($requestedExtensions | Where-Object { $_.requestState -eq "1" })
                            if($ApprovedExtensions.Count -gt 0)
                            {
                                $controlResult.AddMessage("Count of requested extensions that are approved: " + $ApprovedExtensions.Count)
                                $controlResult.AddMessage("`nList of approved extension: ")
                                $display = ($ApprovedExtensions |  FT extensionID, publisherId,@{Name="Requested By";Expression={$_.requests.userName}} -AutoSize | Out-String -Width $ftWidth)
                                $controlResult.AddMessage($display)
                            }
                            $RejectedExtensions = @($requestedExtensions | Where-Object { $_.requestState -eq "2" })
                            if($RejectedExtensions.Count -gt 0)
                            {
                                $controlResult.AddMessage("Count of requested extensions that are rejected: " + $RejectedExtensions.Count)
                                $controlResult.AddMessage("`nList of rejected extension: ")
                                $display = ($RejectedExtensions |  FT extensionID, publisherId,@{Name="Requested By";Expression={$_.requests.userName}} -AutoSize | Out-String -Width $ftWidth)
                                $controlResult.AddMessage($display)
                            }
                        #>
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed, "No requested extensions found that are pending for approval.");
                    }       
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No requested extensions found.");
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of requested extensions.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of requested extensions.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckInactiveGuestUsers([ControlResult] $controlResult)
    {
        try {
            $controlResult.VerificationResult = [VerificationResult]::Failed
            if($this.GuestMembers.Count -eq 0)
            {
                $this.FetchGuestMembersInOrg()
            }
            $users = @($this.GuestMembers)

            if($users.Count -gt 0)
            {
                $inactiveGuestUsers = @()
                $GuestUserInactivePeriodInDays = 90;
                if ([Helpers]::CheckMember($this.ControlSettings.Organization, "GuestUserInactivePeriodInDays") -and (-not [String]::IsNullOrEmpty($this.ControlSettings.Organization.GuestUserInactivePeriodInDays))) {
                    $GuestUserInactivePeriodInDays = $this.ControlSettings.Organization.GuestUserInactivePeriodInDays
                }

                $thresholdDate = (Get-Date).AddDays(-$($GuestUserInactivePeriodInDays))
                $users | ForEach-Object {
                    if([datetime]::Parse($_.lastAccessedDate) -lt $thresholdDate)
                    {
                        $inactiveGuestUsers+= $_
                    }
                }

                $inactiveGuestUsersCount = $inactiveGuestUsers.Count
                $controlResult.AddMessage("`nFound total $($users.Count) guest users.");
                if($inactiveGuestUsersCount -gt 0)
                {
                    #If user account created and was never active, in this case lastaccessdate is default 01-01-0001
                    $inactiveUsers = ($inactiveGuestUsers | Select-Object -Property @{Name="Name"; Expression = {$_.User.displayName}},@{Name="Email"; Expression = {$_.User.mailAddress}},@{Name="InactiveFromDays"; Expression = { if (((Get-Date) -[datetime]::Parse($_.lastAccessedDate)).Days -gt 10000){return "User was never active."} else {return ((Get-Date) -[datetime]::Parse($_.lastAccessedDate)).Days} }})
                    #set data for attestation
                    $inactiveUsersStateData = ($inactiveUsers | Select-Object -Property @{Name="Name"; Expression = {$_.Name}},@{Name="Email"; Expression = {$_.Email}}) #Can Expect drift, are there any org level attestations?

                    #$inactiveUsersCount = ($inactiveUsers | Measure-Object).Count
                    $controlResult.AddMessage([VerificationResult]::Failed,"Count of inactive guest users in the organization: $($inactiveGuestUsersCount)");
                    $controlResult.AdditionalInfo += "Count of inactive guest users in the organization: " + $inactiveGuestUsersCount;
                    $controlResult.SetStateData("Inactive guest users list: ", $inactiveUsersStateData);

                    # segregate never active users from the list
                    $neverActiveUsers = $inactiveUsers | Where-Object {$_.InactiveFromDays -eq "User was never active."}
                    $inactiveUsersWithDays = $inactiveUsers | Where-Object {$_.InactiveFromDays -ne "User was never active."}

                    $neverActiveUsersCount = ($neverActiveUsers | Measure-Object).Count
                    if ($neverActiveUsersCount -gt 0) {
                        $controlResult.AddMessage("`nCount of users who were never active: $($neverActiveUsersCount)");
                        $neverActiveUsersTable = ($neverActiveUsers | FT | Out-String)
                        $controlResult.AddMessage("Never active guest users list: `n$neverActiveUsersTable"); # show in table
                        $controlResult.AdditionalInfo += "Count of users who were never active: " + $neverActiveUsersCount;
                        $controlResult.AdditionalInfo += "List of users who were never active: " + [JsonHelper]::ConvertToJsonCustomCompressed($neverActiveUsers);
                    }

                    $inactiveUsersWithDaysCount = ($inactiveUsersWithDays | Measure-Object).Count
                    if($inactiveUsersWithDaysCount -gt 0) {
                        $controlResult.AddMessage("`nCount of guest users who are inactive from last $($GuestUserInactivePeriodInDays) days: $($inactiveUsersWithDaysCount)");
                        $inactiveUsersTable = ($inactiveUsersWithDays | FT | Out-String)
                        $controlResult.AddMessage("Inactive guest users list: `n$inactiveUsersTable");
                        $controlResult.AdditionalInfo += "Count of guest users who are inactive from last $($GuestUserInactivePeriodInDays) days: " + $inactiveUsersWithDaysCount;
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No guest users found to be inactive from last $($GuestUserInactivePeriodInDays) days.")
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "No guest users found in org.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of guest users in the organization.");
            $controlResult.LogException($_)
        }
        return $controlResult;
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
        if($this.ControlSettings -and [Helpers]::CheckMember($this.ControlSettings,"Organization.AdminGroupsToCheckForGuestUser"))
        {
            try {
                $controlResult.VerificationResult = [VerificationResult]::Failed
                $AdminGroupsToCheckForGuestUser = @($this.ControlSettings.Organization.AdminGroupsToCheckForGuestUser)

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
                                        if($scope -eq $this.OrganizationContext.OrganizationName -and ($group -in $AdminGroupsToCheckForGuestUser) )
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
                        $results += foreach( $grpobj in $groups ){
                                      $PrincipalName = $grpobj.name
                                      $OrgGroup = $grpobj.group.group -join ','
                                      $DisplayName = $grpobj.group."Display Name" | select -Unique
                                      $Scope = $grpobj.group."User or scope" | select -Unique
                                      [PSCustomObject]@{ PrincipalName = $PrincipalName ; DisplayName = $DisplayName ; Group = $OrgGroup ; Scope = $Scope }
                                    }

                        $controlResult.AddMessage([VerificationResult]::Failed,"Count of guest users in admin roles: $($results.count) ");
                        $controlResult.AddMessage("`nGuest account details:")
                        $display = ($results|FT  -AutoSize | Out-String -Width 512)
                        $controlResult.AddMessage($display)
                        $controlResult.SetStateData("List of guest users: ", $results);
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Passed, "No guest users have admin roles in the organization.");
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
            $controlResult.AddMessage([VerificationResult]::Error, "List of admin groups for detecting non guest accounts is not defined in control setting of your organization.");
        }

        return $controlResult
    }

    hidden [ControlResult] CheckInactiveUsersInAdminRoles([ControlResult] $controlResult)
    {
        if($this.ControlSettings -and  [Helpers]::CheckMember($this.ControlSettings,"Organization.AdminGroupsToCheckForInactiveUser"))
        {
            try
            {
                $controlResult.VerificationResult = [VerificationResult]::Failed
                $AdminGroupsToCheckForInactiveUser = @($this.ControlSettings.Organization.AdminGroupsToCheckForInactiveUser)

                $inactiveUsersWithAdminAccess = @()
                $inactivityThresholdInDays = 90
                if([Helpers]::CheckMember($this.ControlSettings,"Organization.AdminInactivityThresholdInDays"))
                {
                    $inactivityThresholdInDays = $this.ControlSettings.Organization.AdminInactivityThresholdInDays
                }

                $thresholdDate = (Get-Date).AddDays(-$inactivityThresholdInDays)
                ## API Call to fetch Org level collection groups
                $url = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1"
                $body = '{"contributionIds": ["ms.vss-admin-web.org-admin-groups-data-provider"],"dataProviderContext": {"properties": {"sourcePage":{"url":"","routeId":"ms.vss-admin-web.collection-admin-hub-route","routeValues":{"adminPivot":"groups","controller":"ContributedPage","action":"Execute"}}}}}'| ConvertFrom-Json

                $body.dataProviderContext.properties.sourcePage.url = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/_settings/groups"
                $response = @([WebRequestHelper]::InvokePostWebRequest($url, $body))

                if([Helpers]::CheckMember($response[0],"dataProviders") -and $response[0].dataProviders."ms.vss-admin-web.org-admin-groups-data-provider")
                {
                    $OrgCollectionGroups = @($response[0].dataProviders.'ms.vss-admin-web.org-admin-groups-data-provider'.identities)
                    $ReqdAdminGroups = @($OrgCollectionGroups | Where-Object { $_.displayName -in $AdminGroupsToCheckForInactiveUser })

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
                    $controlResult.AddMessage("Found total $($allAdminMembers.count) admin users in the org.")
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
                       $controlResult.AddMessage([VerificationResult]::Passed, "No user found with admin roles in the organization.")
                    }

                    if($null -eq (Compare-Object -ReferenceObject $AdminUsersMasterList -DifferenceObject $AdminUsersFailureCases))
                    {
                        $controlResult.AddMessage([VerificationResult]::Error, "Unable to fetch details of inactive users in admin role. Please run the scan with admin priveleges.")
                    }
                    elseif($inactiveUsersWithAdminAccess.count -gt 0)
                    {
                        $controlResult.AddMessage([VerificationResult]::Failed,"Count of users found inactive for $($inactivityThresholdInDays) days in admin roles: $($inactiveUsersWithAdminAccess.count) ");
                        $controlResult.AddMessage("`nInactive admin user details:")
                        $display = ($inactiveUsersWithAdminAccess|FT PrincipalName,DisplayName,Group,LastAccessedDate  -AutoSize | Out-String -Width 512)
                        $controlResult.AddMessage($display)
                        $controlResult.SetStateData("List of inactive users: ", $inactiveUsersWithAdminAccess);
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Passed, "No users in org admin roles have been inactive for $($inactivityThresholdInDays) days.");
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Error, "Not able to fetch Org level collection groups")
                }
                $controlResult.AddMessage("`nNote:`nThe following groups are considered for administrator privileges: `n$($AdminGroupsToCheckForInactiveUser|FT|Out-String)");
            }
            catch
            {
                $controlResult.AddMessage([VerificationResult]::Error, "Not able to fetch Org level collection groups")
                $controlResult.LogException($_)
            }
        }
        else{
            $controlResult.AddMessage([VerificationResult]::Error, "List of admin groups for detecting inactive accounts is not defined in control setting of your organization.");
        }
        return $controlResult;
    }

    hidden [void] GetExtensionPropertiesFromControlSetting()
    {
        if ([AzSKRoot]::IsDetailedScanRequired -eq $true -and [Helpers]::CheckMember($this.ControlSettings, "Organization"))
        {
            if([Helpers]::CheckMember($this.ControlSettings.Organization, "KnownExtensionPublishers"))
            {
                $this.extensionDetailsFromOrgPolicy.knownExtPublishers = $this.ControlSettings.Organization.KnownExtensionPublishers;
                $this.extensionDetailsFromOrgPolicy.isKnownPublishersPropertyPresent = $true
            }

            if([Helpers]::CheckMember($this.ControlSettings.Organization, "ExtensionsLastUpdatedInYears"))
            {
                $this.extensionDetailsFromOrgPolicy.extensionsLastUpdatedInYears = $this.ControlSettings.Organization.ExtensionsLastUpdatedInYears
                $this.extensionDetailsFromOrgPolicy.islastUpdatedPropertyPresent = $true
            }

            if([Helpers]::CheckMember($this.ControlSettings.Organization, "ExtensionCriticalScopes") )
            {
                $this.extensionDetailsFromOrgPolicy.extensionCriticalScopes=$this.ControlSettings.Organization.ExtensionCriticalScopes;
                $this.extensionDetailsFromOrgPolicy.isCriticalScopesPropertyPresent = $true
            }

            if([Helpers]::CheckMember($this.ControlSettings.Organization, "NonProductionExtensionIndicators"))
            {
                $this.extensionDetailsFromOrgPolicy.nonProductionExtensionIndicators =$this.ControlSettings.Organization.NonProductionExtensionIndicators;
                $this.extensionDetailsFromOrgPolicy.isNonProdIndicatorsPropertyPresent = $true
            }

            if([Helpers]::CheckMember($this.ControlSettings.Organization, "ExemptedExtensionNames"))
            {
                $this.extensionDetailsFromOrgPolicy.ExemptedExtensionNames += $this.ControlSettings.Organization.ExemptedExtensionNames;
            }

            $this.extensionDetailsFromOrgPolicy.isComputed = $true
        }
    }

    hidden [psobject] ComputeExtensionDetails($extensionListObj, $scanType)
    {
        $this.ComputedExtensionDetails = @{knownExtensions = @(); unknownExtensions = @(); staleExtensionList = @(); extensionListWithCriticalScopes = @(); extensionListWithNonProductionExtensionIndicators = @(); nonProdExtensions = @(); topPublisherExtensions=@(); privateExtensions=@()}; 
        $date = Get-Date
        $thresholdDate = $date.AddYears(-$this.extensionDetailsFromOrgPolicy.extensionsLastUpdatedInYears)
        $combinedTable = @()
        $extensionListObj | ForEach-Object {
            $extensionInfo="" | Select-Object ExtensionName,PublisherId,PublisherName,Version,KnownPublisher,TooOld,LastPublished,SensitivePermissions,Scopes,NonProdByName,Preview,TopPublisher,PrivateVisibility,MarketPlaceAverageRating,Score,NoOfInstalls,MaxScore
            $extensionInfo.ExtensionName = $_.extensionName
            $extensionInfo.PublisherId = $_.publisherId
            $extensionInfo.PublisherName = $_.publisherName
            $extensionInfo.Version = $_.version
            $extensionInfo.LastPublished = ([datetime] $_.lastPublished).ToString("d MMM yyyy")
            $extensionInfo.Score = 0
            $extensionInfo.MaxScore = 0

            # Checking for known publishers
            $extensionInfo.MaxScore += 10 # Known publisher score
            if($_.publisherName -in $this.extensionDetailsFromOrgPolicy.knownExtPublishers)
            {
                $extensionInfo.KnownPublisher = "Yes"
                $this.ComputedExtensionDetails.knownExtensions += $_
                $extensionInfo.Score += 10
            }
            else {
                $extensionInfo.KnownPublisher = "No"
                $this.ComputedExtensionDetails.unKnownExtensions += $_
            }

            # Checking whether extension is too old or not
            if(([datetime] $_.lastPublished) -lt $thresholdDate)
            {
                $this.ComputedExtensionDetails.staleExtensionList += $_
                $extensionInfo.TooOld = "Yes"
                $diffInYears = [Math]::Round(($thresholdDate - ([datetime] $_.lastPublished)).Days/365)
                $extensionInfo.Score -= $diffInYears * (5)
            }
            else {
                $extensionInfo.TooOld = "No"
            }

            # fetchinbg scope details for shared and requested extensions
            if ($scanType -eq 'Shared' -or $scanType -eq 'Requested') {
                $scopes = @()
                try {
                    $orgId = ($this.ResourceContext.ResourceId -split("/"))[1]
                    $uri = 'https://marketplace.visualstudio.com/acquisition?itemName={0}.{1}&targetId={2}&utm_source=vstsproduct&utm_medium=ExtHubManageList' -f $_.publisherId, $_.extensionId, $orgId
                    $header = [WebRequestHelper]::GetAuthHeaderFromUri($uri)
                    $response = Invoke-Webrequest -URI $uri -Headers $header
                    $searchClass = "vss-item-scope"
                    $parsedHTML = $response.ParsedHtml.getElementsByClassName($searchClass) | % { $_.text}
                    $scopes += $parsedHTML | ConvertFrom-Json
                    $_.scopes = $scopes.Value
                }
                catch {
                    #eat exception
                }
            }

            #Checking whether extension have sensitive permissions
            $riskyScopes = @($_.scopes | ? {$_ -in $this.extensionDetailsFromOrgPolicy.extensionCriticalScopes})
            if($riskyScopes.count -gt 0)
            {
                $this.ComputedExtensionDetails.extensionListWithCriticalScopes += $_
                $extensionInfo.SensitivePermissions = ($riskyScopes -join ',' )
                $extensionInfo.Score -= $riskyScopes.Count * 5
            }
            else {
                $extensionInfo.SensitivePermissions = "None"
            }

            # Checking whether extension name comes under exempted extension name or non prod indicators
            $extensionInfo.MaxScore += 10 # Score for extension Name  not in non prod indicators
            if($_.extensionName -in $this.extensionDetailsFromOrgPolicy.ExemptedExtensionNames)
            {
                $extensionInfo.NonProdByName = "No"
                $extensionInfo.Score += 10
            }
            else
            {
                $isExtensionNameInIndicators = $false
                for($j=0;$j -lt $this.extensionDetailsFromOrgPolicy.nonProductionExtensionIndicators.Count;$j++)
                {
                    if( $_.extensionName -match $this.extensionDetailsFromOrgPolicy.nonProductionExtensionIndicators[$j])
                    {
                        $isExtensionNameInIndicators = $true
                        break
                    }
                }
                if($isExtensionNameInIndicators)
                {
                    $extensionInfo.NonProdByName = "Yes"
                    $this.ComputedExtensionDetails.extensionListWithNonProductionExtensionIndicators += $_
                    $extensionInfo.Score -= 10
                }
                else
                {
                    $extensionInfo.NonProdByName = "No"
                    $extensionInfo.Score += 10
                }
            }

            $url="https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery?api-version=6.1-preview.1"
            $inputbody = "{
                'assetTypes': null,
                'filters': [
                    {
                        'criteria': [
                            {
                                'filterType': 7,
                                'value': '$($_.publisherId).$($_.extensionId)'
                            }
                        ]
                    }
                ],
                'flags': 870
            }"
            try {
                $response= Invoke-WebRequest -Uri $url `
                -Method Post `
                -ContentType "application/json" `
                -Body $inputbody `
                -UseBasicParsing

                $responseObject=$response.Content | ConvertFrom-Json
            }
            catch {
                #eat exception
            }

            # if response object does not get details of extension, those extensions are private extensions
            $extensionInfo.MaxScore += 10   # Private visibility score
            $extensionInfo.MaxScore += 10   # Preview in Gallery flags score
            $extensionInfo.MaxScore += 10   # Marketplace average rating score
            $extensionInfo.MaxScore += 10   # Top publisher certification score

            if([Helpers]::CheckMember($responseobject.results[0], "extensions") -eq $false )
            {
                $extensionInfo.PrivateVisibility = "Yes"
                $extensionInfo.Preview = "Unavailable"
                $extensionInfo.Score -= 10

                if($null -eq $this.allExtensionsObj)
                {
                    $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $($this.OrganizationContext.OrganizationName);
                    $orgURL="https://dev.azure.com/{0}/_settings/extensions" -f $($this.OrganizationContext.OrganizationName);
                    $inputbody =  "{'contributionIds':['ms.vss-extmgmt-web.ext-management-hub'],'dataProviderContext':{'properties':{'sourcePage':{'url':'$orgURL','routeId':'ms.vss-admin-web.collection-admin-hub-route','routeValues':{'adminPivot':'extensions','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json
                    $this.allExtensionsObj = [WebRequestHelper]::InvokePostWebRequest($apiURL,$inputbody);
                }
                if ($scanType -eq 'Installed' -or $scanType -eq 'AutoInjected') {
                
                    $allInstalledExtensions = @()
                    if(($allInstalledExtensions.Count -eq 0) -and [Helpers]::CheckMember($this.allExtensionsObj[0],"dataProviders") -and $this.allExtensionsObj.dataProviders.'ms.vss-extmgmt-web.extensionManagmentHub-collection-data-provider')
                    {
                        # Using sharedExtension Object so that we can get details of all extensions from shared extension api and later use it to compute top publisher for installed extension
                        $allInstalledExtensions = $this.allExtensionsObj[0].dataProviders.'ms.vss-extmgmt-web.extensionManagmentHub-collection-data-provider'.installedextensions
                    }
                    $currentExtension = $_

                    #This refernce variable contains current private extension's top publisher details
                    $refVar = ($allInstalledExtensions | Where-Object {($_.extensionId -eq $currentExtension.extensionId) -and ($_.publisherId -eq $currentExtension.publisherId) })
                }
                else {
                    $refVar = $_
                }

                # if refvar is null then making Unavailable for top publisher
                if($refVar)
                {
                    if($refVar.isCertifiedPublisher)
                    {
                        $extensionInfo.TopPublisher = "Yes"
                        $extensionInfo.Score += 10
                    }
                    else {
                        $extensionInfo.TopPublisher = "No"
                    }
                }
                else {
                    $extensionInfo.TopPublisher = "Unavailable"
                }

                $this.ComputedExtensionDetails.privateExtensions += $_
            }
            else
            {
                $extensionInfo.PrivateVisibility = "No"
                $extensionInfo.Score += 10
                $extensionflags=$responseobject.results[0].extensions.flags

                if($extensionflags -match 'Preview')
                {
                    $extensionInfo.Preview = "Yes"
                    $this.ComputedExtensionDetails.nonProdExtensions += $_
                    $extensionInfo.Score -= 10
                }
                else {
                    $extensionInfo.Preview = "No"
                    $extensionInfo.Score += 10
                }

                $publisherFlags = $responseobject.results[0].extensions.publisher.flags
                if($publisherFlags -match "Certified")
                {
                    $extensionInfo.TopPublisher = "Yes"
                    $this.ComputedExtensionDetails.topPublisherExtensions += $_
                    $extensionInfo.Score += 10
                }
                else {
                    $extensionInfo.TopPublisher = "No"
                }
            }

            if([Helpers]::CheckMember($responseObject.results[0].extensions,"statistics"))
            {
                $statistics = $responseObject.results[0].extensions.statistics
                $extensionInfo.NoOfInstalls = 0
                $statistics | ForEach-Object {
                    if($_.statisticName -eq "averagerating")
                    {
                        $extensionInfo.MarketPlaceAverageRating = [Math]::Round($_.Value,1)
                        $extensionInfo.Score += [Math]::Round($extensionInfo.MarketPlaceAverageRating*2)
                    }
                    if($_.statisticName -eq "install")
                    {
                        $extensionInfo.NoOfInstalls += $_.Value
                    }
                    if($_.statisticName -eq "onpremDownloads")
                    {
                        $extensionInfo.NoOfInstalls += $_.Value
                    }

                }
                if($null -eq $extensionInfo.MarketPlaceAverageRating)
                {
                    $extensionInfo.MarketPlaceAverageRating = 0
                }

            }
            else {
                $extensionInfo.MarketPlaceAverageRating = "Unavailable"
                $extensionInfo.NoOfInstalls = "Unavailable"
            }

            $combinedTable += $extensionInfo
        }
        return $combinedTable
    }

    hidden ExtensionControlHelper($controlResult, $extensionList, $scanType)
    {
        $ftWidth = 512
        if (-not $this.extensionDetailsFromOrgPolicy.isComputed) {
            $this.GetExtensionPropertiesFromControlSetting()
        }

        if ([AzSKRoot]::IsDetailedScanRequired -eq $false) 
        {
            if (([Helpers]::CheckMember($this.ControlSettings ,"Organization.KnownExtensionPublishers")))
            {
                $knownExtPublishers = $this.ControlSettings.Organization.KnownExtensionPublishers;

                $knownExtensions = @($extensionList | Where-Object {$_.publisherName -in $knownExtPublishers})
                $knownCount = $knownExtensions.Count

                $unknownExtensions = @($extensionList | Where-Object {$_.publisherName -notin $knownExtPublishers})
                $unknownCount = $unknownExtensions.Count
                if($unknownCount -gt 0){

                    $controlResult.AddMessage("`nCount of extensions (from publishers not in 'known publishers' list): $unknownCount");
                    $controlResult.AdditionalInfo += "Count of extensions (from publishers not in 'known publishers' list): " + $unknownCount;
                    $controlResult.AddMessage("`nExtension details (from publishers not in 'known publishers' list): ")
                    $display = ($unknownExtensions |  FT ExtensionName, publisherId, publisherName, Version -AutoSize | Out-String -Width $ftWidth)
                    $controlResult.AddMessage($display)
                    $controlResult.AdditionalInfo += "Extensions (from unknown publishers): " + [JsonHelper]::ConvertToJsonCustomCompressed($unknownExtensions);
                }
                if($knownCount -gt 0){
                    $controlResult.AddMessage("`nCount of extensions (from publishers in the 'known publishers' list): $knownCount");
                    $controlResult.AdditionalInfo += "Count of extensions (from publishers in the 'known publishers' list): " + $knownCount;
                    $controlResult.AddMessage("`nExtension details (from publishers in the 'known publishers' list): ")
                    $display = ($knownExtensions |FT ExtensionName, publisherId, publisherName, Version -AutoSize | Out-String -Width $ftWidth)
                    $controlResult.AddMessage($display)
                }

                $stateData = @{
                    known_Extensions = @($knownExtensions);
                    unknown_Extensions = @($unknownExtensions);
                };

                $controlResult.SetStateData("List of extensions: ", $stateData);
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Error, "List of known extension publishers is not defined in control settings for your organization.");
            }
        }
        else ## Deep scan start
        {
            $this.PublishCustomMessage("You have requested for a detailed scan, this will take a few minutes..`n",[MessageType]::Warning);
            $controlResult.AddMessage([Constants]::HashLine)
            if( !($this.extensionDetailsFromOrgPolicy.isKnownPublishersPropertyPresent -and $this.extensionDetailsFromOrgPolicy.islastUpdatedPropertyPresent -and $this.extensionDetailsFromOrgPolicy.isCriticalScopesPropertyPresent -and $this.extensionDetailsFromOrgPolicy.isNonProdIndicatorsPropertyPresent))
            {
                $controlResult.AddMessage("*** Note: Some settings are not present in the policy configuration. ***")
            }
            $controlResult.AddMessage("`nNote: Apart from this LOG, a combined listing of all extensions and their security sensitive attributes has been published to the '$($this.ResourceContext.ResourceName)"+"_"+"$($scanType)"+"ExtensionInfo.CSV' file in the current folder. Columns with value as 'Unavailable' indicate that data was not available.")

            $infotable = [ordered] @{
                "KnownPublisher" = "Yes/No [if extension is from [$($this.extensionDetailsFromOrgPolicy.knownExtPublishers -join ', ')]]";
                "Too old (> $($this.extensionDetailsFromOrgPolicy.extensionsLastUpdatedInYears) yrs)" = "Yes/No [if extension has not been updated by publishers for more than [$($this.extensionDetailsFromOrgPolicy.extensionsLastUpdatedInYears)] yrs]";
                "SensitivePermissions" = "Lists if any permissions requested by extension are in the sensitive permissions list. (See list below for the permissions considered sensitive.)";
                "NonProd (GalleryFlag)" = "Yes/No [if the gallery flags in the manifest mention 'preview']";
                "NonProd (ExtensionName)" = "Yes/No [if extension name indicates [$($this.extensionDetailsFromOrgPolicy.nonProductionExtensionIndicators -join ', ')]]";
                "TopPublisher" = "Yes/No [if extension's publisher has 'Top Publisher' certification]";
                "PrivateVisibility" = "Yes/No [if extension has been shared privately with the org]" ;
                "Score" = "Secure score of extension. (See further below for the scoring scheme.) "
            }

            $scoretable = @(
                New-Object psobject -Property $([ordered] @{"Parameter"="'Top Publisher' certification";"Score (if Yes)"="+10"; "Score (if No)" = "0"});
                New-Object psobject -Property $([ordered] @{"Parameter"="Known publishers";"Score (if Yes)"="+10"; "Score (if No)" = "0"});
                New-Object psobject -Property $([ordered] @{"Parameter"="Too old ( x years )";"Score (if Yes)"="-5*(No. of years when extension was last published before threshhold)"; "Score (if No)" = "0"})
                New-Object psobject -Property $([ordered] @{"Parameter"="Sensitive permissions(n)";"Score (if Yes)"="-5*(No. of sensitive permmissions found)"; "Score (if No)" = "0"});
                New-Object psobject -Property $([ordered] @{"Parameter"="NonProd (GalleryFlag)";"Score (if Yes)"="-10"; "Score (if No)" = "+10"})
                New-Object psobject -Property $([ordered] @{"Parameter"="NonProd (ExtensionName)";"Score (if Yes)"="-10"; "Score (if No)" = "+10"})
                New-Object psobject -Property $([ordered] @{"Parameter"="Private visibility";"Score (if Yes)"="-10"; "Score (if No)" = "+10"})
                New-Object psobject -Property $([ordered] @{"Parameter"="Average Rating ";"Score (if Yes)"="+2*(Marketplace average rating)"; "Score (if No)" = "0"})
            ) | Format-Table -AutoSize | Out-String -Width $ftWidth

            $helperTable = $infotable.keys | Select @{l='Column';e={$_}},@{l='Interpretation';e={$infotable.$_}} | Format-Table -AutoSize | Out-String -Width $ftWidth
            $controlResult.AddMessage($helperTable)
            $controlResult.AddMessage("The following extension permissions are considered sensitive: ")
            if(!$this.extensionDetailsFromOrgPolicy.isCriticalScopesPropertyPresent)
            {
                $controlResult.AddMessage("*** 'Extension critical scopes' setting is not present in the policy configuration. ***")
            }
            $controlResult.AddMessage($this.extensionDetailsFromOrgPolicy.extensionCriticalScopes)
            $controlResult.AddMessage("`nThe following scheme is used for assigning secure score: ")
            $controlResult.AddMessage($scoretable)
            
            $combinedTable = @($this.ComputeExtensionDetails($extensionList, $scanType))
            $MaxScore = $combinedTable[0].MaxScore
            $controlResult.AddMessage("Note: Using this scheme an extension can get a maximum secure score of [$MaxScore].`n")
            $controlResult.AddMessage([Constants]::HashLine)
            $controlResult.AddMessage([Constants]::SingleDashLine +"`nLooking for extensions from 'known publishers'`n"+[Constants]::SingleDashLine)
            $controlResult.AddMessage("`nNote: The following are considered as 'known publishers': `n`t[$($this.extensionDetailsFromOrgPolicy.knownExtPublishers -join ', ')]");
            if(!$this.extensionDetailsFromOrgPolicy.IsKnownPublishersPropertyPresent)
            {
                $controlResult.AddMessage("*** 'Known publisher' setting is not present in the policy configuration. ***")
            }
            $unknownCount = $this.ComputedExtensionDetails.unKnownExtensions.Count
            if($unknownCount -gt 0){

                $controlResult.AddMessage("`nCount of extensions (from publishers not in 'known publishers' list): $unknownCount");
                $controlResult.AdditionalInfo += "Count of extensions (from publishers not in 'known publishers' list): " + $unknownCount;
                $controlResult.AddMessage("`nExtension details (from publishers not in 'known publishers' list): ")
                $display = ($this.ComputedExtensionDetails.unKnownExtensions |  FT ExtensionName, publisherId, publisherName, Version -AutoSize | Out-String -Width $ftWidth)
                $controlResult.AddMessage($display)
                $controlResult.AdditionalInfo += "Extensions (from unknown publishers): " + [JsonHelper]::ConvertToJsonCustomCompressed($this.ComputedExtensionDetails.unKnownExtensions);
            }

            $knownCount = $this.ComputedExtensionDetails.knownExtensions.Count
            if($knownCount -gt 0){
                $controlResult.AddMessage("`nCount of extensions (from publishers in the 'known publishers' list): $knownCount");
                $controlResult.AdditionalInfo += "Count of extensions (from publishers in the 'known publishers' list): " + $knownCount;
                $controlResult.AddMessage("`nExtension details (from publishers in the 'known publishers' list): ")
                $display = ($this.ComputedExtensionDetails.knownExtensions|FT ExtensionName, publisherId, publisherName, Version -AutoSize | Out-String -Width $ftWidth)
                $controlResult.AddMessage($display)
            }

            $stateData = @{
                known_Extensions = @($this.ComputedExtensionDetails.knownExtensions);
                unKnown_Extensions = @($this.ComputedExtensionDetails.unKnownExtensions);
            };

            $controlResult.SetStateData("List of extensions: ", $stateData);

            if($this.ComputedExtensionDetails.staleExtensionList.count -gt 0)
            {
                $controlResult.AddMessage([Constants]::HashLine)
                $controlResult.AddMessage([Constants]::SingleDashLine +"`nLooking for extensions that have not been updated by publishers for more than [$($this.extensionDetailsFromOrgPolicy.extensionsLastUpdatedInYears)] years...`n" +[Constants]::SingleDashLine)
                if(!$this.extensionDetailsFromOrgPolicy.islastUpdatedPropertyPresent)
                {
                    $controlResult.AddMessage("***'Last Updated' setting is not present in the policy configuration.***")
                }
                $controlResult.AddMessage("`nCount of extensions that haven't been updated in the last [$($this.extensionDetailsFromOrgPolicy.extensionsLastUpdatedInYears)] years: "+ $this.ComputedExtensionDetails.staleExtensionList.count)
                $controlResult.AddMessage("`nExtension details (oldest first): ")
                $display = ($this.ComputedExtensionDetails.staleExtensionList| Sort-Object lastPublished | FT ExtensionName, @{Name = "lastPublished"; Expression = { ([datetime] $_.lastPublished).ToString("d MMM yyyy")} }, PublisherId, PublisherName, version -AutoSize | Out-String -Width $ftWidth)
                $controlResult.AddMessage($display)
            }

            if($this.ComputedExtensionDetails.extensionListWithCriticalScopes.count -gt 0)
            {
                $controlResult.AddMessage([Constants]::HashLine)
                $controlResult.AddMessage([Constants]::SingleDashLine + "`nLooking for extensions that have sensitive access permissions...`n" + [Constants]::SingleDashLine)
                if(!$this.extensionDetailsFromOrgPolicy.isCriticalScopesPropertyPresent)
                {
                    $controlResult.AddMessage("*** 'Extension critical scopes' setting is not present in the policy configuration. ***")
                }
                $controlResult.AddMessage("Note: The following permissions are considered sensitive: `n`t[$($this.extensionDetailsFromOrgPolicy.extensionCriticalScopes -join ', ')]")
                $controlResult.AddMessage("`nCount of extensions that have sensitive access permissions: "+ $this.ComputedExtensionDetails.extensionListWithCriticalScopes.count)
                $controlResult.AddMessage("`nExtension details (extensions that have sensitive access permissions): ")
                $display= ($this.ComputedExtensionDetails.extensionListWithCriticalScopes | FT ExtensionName, scopes, PublisherId, PublisherName  -AutoSize | Out-String -Width $ftWidth)
                $controlResult.AddMessage($display)
            }

            if($this.ComputedExtensionDetails.extensionListWithNonProductionExtensionIndicators.count -gt 0)
            {
                $controlResult.AddMessage([Constants]::HashLine)
                $controlResult.AddMessage([Constants]::SingleDashLine+"`nLooking for extensions that are not production ready...`n"+[Constants]::SingleDashLine)
                if(!$this.extensionDetailsFromOrgPolicy.isNonProdIndicatorsPropertyPresent)
                {
                    $controlResult.AddMessage("*** 'Non-production extension indicators' setting is not present in the policy configuration. ***")
                }
                $controlResult.AddMessage("Note: This checks for extensions with words [$($this.extensionDetailsFromOrgPolicy.nonProductionExtensionIndicators -join ', ')] in extension names.")
                $controlResult.AddMessage("`nCount of non-production extensions (based on name):  "+ $this.ComputedExtensionDetails.extensionListWithNonProductionExtensionIndicators.count)
                $controlResult.AddMessage("`nExtension details (non-production extensions (based on name)):  ")
                $controlResult.AddMessage( ($this.ComputedExtensionDetails.extensionListWithNonProductionExtensionIndicators | FT ExtensionName, PublisherId, PublisherName -AutoSize | Out-String -Width $ftWidth))
            }

            if($this.ComputedExtensionDetails.nonProdExtensions.count -gt 0)
            {
                $controlResult.AddMessage([Constants]::HashLine)
                $controlResult.AddMessage([Constants]::SingleDashLine+"`nLooking for extensions that are marked 'Preview' via gallery flags...`n"+[Constants]::SingleDashLine)
                $controlResult.AddMessage("`nCount of extensions marked as 'Preview' via gallery flags: "+ $this.ComputedExtensionDetails.nonProdExtensions.count);
                $controlResult.AddMessage("`nExtension details (extensions which are marked as 'Preview' via gallery flags): ")
                $controlResult.AddMessage(($this.ComputedExtensionDetails.nonProdExtensions | FT ExtensionName, PublisherId, PublisherName -AutoSize | Out-String -Width $ftWidth));
            }

            if($this.ComputedExtensionDetails.topPublisherExtensions.count -gt 0)
            {
                $controlResult.AddMessage([Constants]::HashLine)
                $controlResult.AddMessage([Constants]::SingleDashLine+"`nLooking for extensions that are from publishers with a 'Top Publisher' certification...`n"+[Constants]::SingleDashLine);
                $controlResult.AddMessage("`nCount of extensions from 'Top Publishers': "+$this.ComputedExtensionDetails.topPublisherExtensions.count);
                $controlResult.AddMessage("`nExtension details (extensions from 'Top Publishers'): ")
                $controlResult.AddMessage(($this.ComputedExtensionDetails.topPublisherExtensions | FT ExtensionName, PublisherId, PublisherName -AutoSize | Out-String -Width $ftWidth) );
            }

            if($this.ComputedExtensionDetails.privateExtensions.count -gt 0)
            {
                $controlResult.AddMessage([Constants]::HashLine)
                $controlResult.AddMessage([Constants]::SingleDashLine+"`nLooking for extensions that have 'private' visibility for the org...`n"+[Constants]::SingleDashLine);
                $controlResult.AddMessage("`nCount of extensions with 'private' visibility: "+$this.ComputedExtensionDetails.privateExtensions.count);
                $controlResult.AddMessage("`nExtension details (extensions with 'private' visibility): ")
                $controlResult.AddMessage(($this.ComputedExtensionDetails.privateExtensions | FT ExtensionName, PublisherId, PublisherName -AutoSize | Out-String -Width $ftWidth));
            }

            if ($scanType -eq 'Installed') {
                [Organization]::InstalledExtensionInfo = $combinedTable
            }
            elseif ($scanType -eq 'Shared') {
                [Organization]::SharedExtensionInfo = $combinedTable
            }
            elseif ($scanType -eq 'Requested') {
                [Organization]::RequestedExtensionInfo = $combinedTable
            }
            elseif ($scanType -eq 'AutoInjected') {
                [Organization]::AutoInjectedExtensionInfo = $combinedTable
            }
        }
        ## end Deep scan
        
    }
}