Set-StrictMode -Version Latest 
class Organization: ADOSVTBase
{    
    [PSObject] $ServiceEndPointsObj = $null
    [PSObject] $PipelineSettingsObj = $null
    [PSObject] $OrgPolicyObj = $null
    static $InstalledExtensionInfo
    hidden [PSObject] $allExtensionsObj; # This is used to fetch all extensions (shared+installed+requested) object so that it can be used in installed extension control where top publisher could not be computed.
    
    #TODO: testing below line
    hidden [string] $SecurityNamespaceId;
    Organization([string] $organizationName, [SVTResource] $svtResource): Base($organizationName,$svtResource) 
    { 
        $this.GetOrgPolicyObject()
        $this.GetPipelineSettingsObj()
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
        }
       
        return $controlResult
    }

    hidden [ControlResult] CheckSCALTForAdminMembers([ControlResult] $controlResult)
    {
        try
        {
            if(($null -ne $this.ControlSettings) -and [Helpers]::CheckMember($this.ControlSettings, "Organization.GroupsToCheckForSCAltMembers"))
            {

                $adminGroupNames = $this.ControlSettings.Organization.GroupsToCheckForSCAltMembers;
                if (($adminGroupNames | Measure-Object).Count -gt 0) 
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
                        $PCSAGroup = $response.dataProviders."ms.vss-admin-web.org-admin-groups-data-provider".identities | where { $_.displayName -eq "Project Collection Service Accounts"}
                            
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
                            
                            if(($PCSAGroup | Measure-Object).Count -gt 0)
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
                            if(($allPCSAMembers | Measure-Object).Count -gt 0)
                            {
                                $allAdminMembers = $allAdminMembers | ? {$_.id -notin $allPCSAMembers.id}
                            }

                            # clearing cached value in [AdministratorHelper]::AllPCAMembers as it can be used in attestation later and might have incorrect group loaded.
                            [AdministratorHelper]::AllPCAMembers = @();
                            
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
                                            $controlResult.AddMessage([VerificationResult]::Failed, "`nTotal number of non SC-ALT accounts with admin privileges:  $nonSCCount"); 
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
        }
       
        return $controlResult
    }

    hidden [ControlResult] CheckAADConfiguration([ControlResult] $controlResult)
    {
        try 
        {
            $apiURL = "https://dev.azure.com/{0}/_settings/organizationAad?__rt=fps&__ver=2" -f $($this.OrganizationContext.OrganizationName);
            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
            
            if(([Helpers]::CheckMember($responseObj[0],"fps.dataProviders.data") ) -and  (($responseObj[0].fps.dataProviders.data."ms.vss-admin-web.organization-admin-aad-data-provider") -and $responseObj[0].fps.dataProviders.data."ms.vss-admin-web.organization-admin-aad-data-provider".orgnizationTenantData) -and (-not [string]::IsNullOrWhiteSpace($responseObj[0].fps.dataProviders.data."ms.vss-admin-web.organization-admin-aad-data-provider".orgnizationTenantData.domain)))
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Organization is configured with [$($responseObj.fps.dataProviders.data.'ms.vss-admin-web.organization-admin-aad-data-provider'.orgnizationTenantData.displayName)] directory.");
                $controlResult.AdditionalInfo += "Organization is configured with [$($responseObj.fps.dataProviders.data.'ms.vss-admin-web.organization-admin-aad-data-provider'.orgnizationTenantData.displayName)] directory.";
            }
            else 
            {
                $controlResult.AddMessage([VerificationResult]::Failed, "Organization is not configured with AAD.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch AAD configuration details.");
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
             }
        }

        return $controlResult
    }

    hidden [ControlResult] CheckExternalUserPolicy([ControlResult] $controlResult)
    {
        if([Helpers]::CheckMember($this.OrgPolicyObj,"user"))
        {
            $userPolicyObj = $this.OrgPolicyObj.user; 
            $guestAuthObj = $userPolicyObj | Where-Object {$_.Policy.Name -eq "Policy.DisallowAadGuestUserAccess"}
            if(($guestAuthObj | Measure-Object).Count -gt 0)
            {
                if($guestAuthObj.policy.effectiveValue -eq $false )
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,"External guest access is disabled in the organization.");
                }
                else 
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "External guest access is enabled in the organization.");
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
        if([Helpers]::CheckMember($this.OrgPolicyObj,"security"))
        {
            $guestAuthObj = $this.OrgPolicyObj.security | Where-Object {$_.Policy.Name -eq "Policy.AllowAnonymousAccess"}
            if(($guestAuthObj | Measure-Object).Count -gt 0)
            {
                    if($guestAuthObj.policy.effectiveValue -eq $false )
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
                $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the public project security policies.");
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
        try 
        {           
            $apiURL = "https://extmgmt.dev.azure.com/{0}/_apis/extensionmanagement/installedextensions?api-version=6.0-preview.1" -f $($this.OrganizationContext.OrganizationName);
            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
            
            if(($responseObj | Measure-Object).Count -gt 0 ) #includes both custom installed and built in extensions.
            {               
                $extensionList = $responseObj | Select-Object extensionName,publisherId,publisherName,version,flags,lastPublished,scopes,extensionId # 'flags' is not available in every extension. It is visible only for built in extensions. Hence this appends 'flags' to trimmed objects.
                $extensionList = $extensionList | Where-Object {$_.flags -notlike "*builtin*" } # to filter out extensions that are built in and are not visible on portal.
                $ftWidth = 512 #Used for table output width to avoid "..." truncation
                $extCount = ($extensionList | Measure-Object ).Count;

                if($extCount -gt 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Verify, "`nReview the list of installed extensions for your org: ");                                   
                    $controlResult.AddMessage("No. of installed extensions: " + $extCount);
                    $controlResult.AdditionalInfo += "No. of installed extensions: " + $extCount;             
                    if([AzSKRoot]::IsDetailedScanRequired -eq $false)
                    {
                        #if([Helpers]::CheckMember($this.ControlSettings, "Organization.KnownExtensionPublishersId"))
                        #{$knownExtPublishersId = $this.ControlSettings.Organization.KnownExtensionPublishersId;}
                        $knownExtPublishers = $this.ControlSettings.Organization.KnownExtensionPublishers;

                        $knownExtensions = @();
                        #$knownExtensions += $extensionList | Where-Object {$_.publisherId -in $KnownExtPublishersId}
                        $knownExtensions += $extensionList | Where-Object {$_.publisherName -in $knownExtPublishers}
                        $knownCount = ($knownExtensions | Measure-Object).Count
                    
                        $unKnownExtensions = @(); #Publishers not Known by Microsoft
                        #$unKnownExtensions += $extensionList | Where-Object {$_.publisherId -notin $KnownExtPublishersId}
                        $unKnownExtensions += $extensionList | Where-Object {$_.publisherName -notin $knownExtPublishers}
                        $unKnownCount = ($unKnownExtensions | Measure-Object).Count
                    
                        $controlResult.AddMessage("`nNote: The following publishers are considered as 'known publishers': `n`t[$($knownExtPublishers -join ', ')]"); 

                        if($unKnownCount -gt 0){
                            $controlResult.AddMessage("`nNo. of extensions (from publishers not in 'known publishers' list): $unKnownCount");
                            $controlResult.AdditionalInfo += "No. of installed extensions (from publishers not in 'known publishers' list): " + $unKnownCount;
                            $controlResult.AddMessage("`nExtension details: ")
                            $display = ($unKnownExtensions |  FT ExtensionName, publisherId, publisherName, Version -AutoSize | Out-String -Width $ftWidth)
                            $controlResult.AddMessage($display)
                            $controlResult.AdditionalInfo += "Installed extensions (from 'unknown publishers'): " + [JsonHelper]::ConvertToJsonCustomCompressed($unKnownExtensions);
                        }

                        if($knownCount -gt 0){
                            $controlResult.AddMessage("`nNo. of  extensions (from publishers in the 'known publishers' list): $knownCount");
                            $controlResult.AdditionalInfo += "No. of extensions (from publishers in the 'known publishers' list): " + $knownCount;
                            $controlResult.AddMessage("`nExtension details: ")
                            $display = ($knownExtensions|FT ExtensionName, publisherId, publisherName, Version -AutoSize | Out-String -Width $ftWidth)
                            $controlResult.AddMessage($display)
                        }

                        $stateData = @{
                            known_Extensions = @();
                            unKnown_Extensions = @();
                        };

                        $stateData.known_Extensions += $knownExtensions
                        $stateData.unKnown_Extensions += $unKnownExtensions

                        $controlResult.SetStateData("List of installed extensions: ", $stateData);
                    }

                    ## Deep scan start
                    if([AzSKRoot]::IsDetailedScanRequired -eq $true)
                    {   
                        $this.PublishCustomMessage("You have requested for detailed scan, it will take few minutes..`n",[MessageType]::Warning);
                        $isKnownPublishersPropertyPresent = $false
                        $islastUpdatedPropertyPresent = $false
                        $isCriticalScopesPropertyPresent = $false
                        $isNonProdIndicatorsPropertyPresent = $false

                        if($null -ne $this.ControlSettings)
                        {   
                            if([Helpers]::CheckMember($this.ControlSettings, "Organization.KnownExtensionPublishers"))
                            {
                                $knownExtPublishers = $this.ControlSettings.Organization.KnownExtensionPublishers;
                                $isKnownPublishersPropertyPresent = $true
                            }
                            else {
                                $knownExtPublishers = @()
                            }

                            if([Helpers]::CheckMember($this.ControlSettings, "Organization.ExtensionsLastUpdatedInYears"))
                            {
                                $extensionsLastUpdatedInYears = $this.ControlSettings.Organization.ExtensionsLastUpdatedInYears
                                $islastUpdatedPropertyPresent = $true
                            }
                            else {
                                $extensionsLastUpdatedInYears = 2 ##Default value
                            }
                            
                            if([Helpers]::CheckMember($this.ControlSettings, "Organization.ExtensionCriticalScopes") )
                            {
                                $extensionCriticalScopes=$this.ControlSettings.Organization.ExtensionCriticalScopes;
                                $isCriticalScopesPropertyPresent = $true
                            }
                            else{
                                $extensionCriticalScopes = @()
                            }

                            if([Helpers]::CheckMember($this.ControlSettings, "Organization.NonProductionExtensionIndicators"))
                            {
                                $nonProductionExtensionIndicators =$this.ControlSettings.Organization.NonProductionExtensionIndicators;
                                $isNonProdIndicatorsPropertyPresent = $true
                            }
                            else {
                                $nonProductionExtensionIndicators = @()
                            }                            
                            
                            $ExemptedExtensionNames = @()
                            if([Helpers]::CheckMember($this.ControlSettings, "Organization.ExemptedExtensionNames"))
                            {
                                $ExemptedExtensionNames += $this.ControlSettings.Organization.ExemptedExtensionNames;
                            }  

                            $controlResult.AddMessage([Constants]::HashLine)   
                            if( !($isKnownPublishersPropertyPresent -and $islastUpdatedPropertyPresent -and $isCriticalScopesPropertyPresent -and $isNonProdIndicatorsPropertyPresent))
                            {
                                $controlResult.AddMessage("***Note: Some settings are not present in the policy configuration.***")
                            }                         
                            $controlResult.AddMessage("`nNote: Apart from this LOG, a combined listing of all extensions and their security sensitive attributes has been output to the '$($this.ResourceContext.ResourceName)"+"_ExtensionInfo.CSV' file in the current folder. Columns with value as 'Unavailable' indicate that data was not available.")
                            
                            $infotable = [ordered] @{ 
                                "KnownPublisher" = "Yes/No [if extension is from [$($knownExtPublishers -join ', ')]]";
                                "Too Old (> $($extensionsLastUpdatedInYears)year(s))" = "Yes/No [if extension has not been updated by publishers for more than [$extensionsLastUpdatedInYears] year(s)]";
                                "SensitivePermissions" = "Lists if any permissions requested by extension are in the sensitive permissions list. (See list below for the full list of permissions considered to be sensitive.)";
                                "NonProd (GalleryFlag)" = "Yes/No [if the gallery flags in the manifest mention 'preview']";
                                "NonProd (ExtensionName)" = "Yes/No [if extension name indicates [$($nonProductionExtensionIndicators -join ', ')]]";
                                "TopPublisher" = "Yes/No [if extension's publisher has 'Top Publisher' certification]";
                                "PrivateVisibility" = "Yes/No [if extension has been shared privately with the org]" ;
                                "Score" = "Secure score of extension. (See further below for the scoring scheme.) "
                            }  

                            $scoretable = @(
                                New-Object psobject -Property $([ordered] @{"Parameter"="'Top Publisher' certification";"Score (if Yes)"="+10"; "Score (if No)" = "0"});
                                New-Object psobject -Property $([ordered] @{"Parameter"="Known publishers";"Score (if Yes)"="+10"; "Score (if No)" = "0"});
                                New-Object psobject -Property $([ordered] @{"Parameter"="Too Old ( x years )";"Score (if Yes)"="-5*(No. of years when extension was last published before threshhold)"; "Score (if No)" = "0"})
                                New-Object psobject -Property $([ordered] @{"Parameter"="Sensitive permissions(n)";"Score (if Yes)"="-5*(No. of sensitive permmissions found)"; "Score (if No)" = "0"});
                                New-Object psobject -Property $([ordered] @{"Parameter"="NonProd (GalleryFlag)";"Score (if Yes)"="-10"; "Score (if No)" = "+10"})
                                New-Object psobject -Property $([ordered] @{"Parameter"="NonProd (ExtensionName)";"Score (if Yes)"="-10"; "Score (if No)" = "+10"})
                                New-Object psobject -Property $([ordered] @{"Parameter"="Private visibility";"Score (if Yes)"="-10"; "Score (if No)" = "+10"})
                                New-Object psobject -Property $([ordered] @{"Parameter"="Average Rating ";"Score (if Yes)"="+2*(Marketplace average rating)"; "Score (if No)" = "0"})
                            ) | Format-Table -AutoSize | Out-String -Width $ftWidth
                            
                            $helperTable = $infotable.keys | Select @{l='Column';e={$_}},@{l='Interpretation';e={$infotable.$_}} | Format-Table -AutoSize | Out-String -Width $ftWidth
                            $controlResult.AddMessage($helperTable)
                            $controlResult.AddMessage("The following extension permissions are considered sensitive:")
                            if(!$isCriticalScopesPropertyPresent)
                            {
                                $controlResult.AddMessage("***'Extension critical scopes' setting is not present in the policy configuration.***")
                            } 
                            $controlResult.AddMessage($extensionCriticalScopes)
                            $controlResult.AddMessage("`nThe following scheme is used for assigning secure score:")
                            $controlResult.AddMessage($scoretable)

                            $combinedTable=@()
                            $knownExtensions=@()
                            $unKnownExtensions = @()
                            $staleExtensionList = @()
                            $extensionListWithCriticalScopes = @()
                            $extensionListWithNonProductionExtensionIndicators=@()
                            $privateExtensions = @()
                            $nonProdExtensions = @()
                            $topPublisherExtensions = @()
                            [Organization]::InstalledExtensionInfo = @()
                            $allInstalledExtensions = @() # This variable gets all installed extensions details from $allExtensionsObj


                            $date = Get-Date                            
                            $thresholdDate = $date.AddYears(-$extensionsLastUpdatedInYears)

                            $extensionList | ForEach-Object {
                                $extensionInfo="" | Select-Object ExtensionName,PublisherId,PublisherName,Version,KnownPublisher,TooOld,LastPublished,SensitivePermissions,Scopes,NonProdByName,Preview,TopPublisher,PrivateVisibility,MarketPlaceAverageRating,Score,NoOfInstalls,MaxScore
                                $extensionInfo.ExtensionName = $_.extensionName
                                $extensionInfo.PublisherId = $_.publisherId
                                $extensionInfo.PublisherName = $_.publisherName
                                $extensionInfo.Version = $_.version
                                $extensionInfo.LastPublished = ([datetime] $_.lastPublished).ToString("MM-dd-yyyy")
                                $extensionInfo.Score = 0
                                $extensionInfo.MaxScore = 0                                
                                
                                # Checking for known publishers
                                $extensionInfo.MaxScore += 10 # Known publisher score
                                if($_.publisherName -in $knownExtPublishers)
                                {
                                    $extensionInfo.KnownPublisher = "Yes"
                                    $knownExtensions += $_
                                    $extensionInfo.Score += 10
                                }
                                else {
                                    $extensionInfo.KnownPublisher = "No"
                                    $unKnownExtensions += $_
                                }
                                
                                # Checking whether extension is too old or not
                                if(([datetime] $_.lastPublished) -lt $thresholdDate)
                                {
                                    $staleExtensionList += $_
                                    $extensionInfo.TooOld = "Yes"
                                    $diffInYears = [Math]::Round(($thresholdDate - ([datetime] $_.lastPublished)).Days/365)
                                    $extensionInfo.Score -= $diffInYears * (5)
                                }
                                else {
                                    $extensionInfo.TooOld = "No"                                    
                                }
                                
                                # Checking whether extension have sensitive permissions
                                $riskyScopes = @($_.scopes | ? {$_ -in $extensionCriticalScopes})
                                if($riskyScopes.count -gt 0)
                                {
                                    $extensionListWithCriticalScopes += $_
                                    $extensionInfo.SensitivePermissions = ($riskyScopes -join ',' )
                                    $extensionInfo.Score -= $riskyScopes.Count * 5
                                }
                                else {
                                    $extensionInfo.SensitivePermissions = "None"
                                }
                                
                                # Checking whether extension name comes under exempted extension name or non prod indicators
                                $extensionInfo.MaxScore += 10 # Score for extension Name  not in non prod indicators
                                if($_.extensionName -in $ExemptedExtensionNames)
                                {
                                    $extensionInfo.NonProdByName = "No"  
                                    $extensionInfo.Score += 10 
                                }
                                else 
                                {
                                    $isExtensionNameInIndicators = $false
                                    for($j=0;$j -lt $nonProductionExtensionIndicators.Count;$j++)
                                    {
                                        if( $_.extensionName -match $nonProductionExtensionIndicators[$j])
                                        {
                                            $isExtensionNameInIndicators = $true
                                            break
                                        }
                                    }
                                    if($isExtensionNameInIndicators)
                                    {    
                                        $extensionInfo.NonProdByName = "Yes"
                                        $extensionListWithNonProductionExtensionIndicators += $_
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
        
                                    $response= Invoke-WebRequest -Uri $url `
                                        -Method Post `
                                        -ContentType "application/json" `
                                        -Body $inputbody `
                                        -UseBasicParsing
        
                                    $responseObject=$response.Content | ConvertFrom-Json
    
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
                                        
                                        if(($allInstalledExtensions.Count -eq 0) -and [Helpers]::CheckMember($this.allExtensionsObj[0],"dataProviders") -and $this.allExtensionsObj.dataProviders.'ms.vss-extmgmt-web.extensionManagmentHub-collection-data-provider')
                                        {                                 
                                            # Using sharedExtension Object so that we can get details of all extensions from shared extension api and later use it to compute top publisher for installed extension
                                            $allInstalledExtensions = $this.allExtensionsObj[0].dataProviders.'ms.vss-extmgmt-web.extensionManagmentHub-collection-data-provider'.installedextensions
                                        }
                                        $currentExtension = $_

                                        #This refernce variable contains current private extension's top publisher details
                                        $refVar = ($allInstalledExtensions | Where-Object {($_.extensionId -eq $currentExtension.extensionId) -and ($_.publisherId -eq $currentExtension.publisherId) })

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
                                         
                                        $privateExtensions += $_
                                    }
                                    else
                                    {
                                        $extensionInfo.PrivateVisibility = "No"
                                        $extensionInfo.Score += 10
                                        $extensionflags=$responseobject.results[0].extensions.flags
                                        
                                        if($extensionflags -match 'Preview')
                                        {
                                            $extensionInfo.Preview = "Yes"
                                            $nonProdExtensions += $_
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
                                            $topPublisherExtensions += $_
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
                            $MaxScore = $combinedTable[0].MaxScore
                            $controlResult.AddMessage("Note: Using this scheme an extension can get a maximum secure score of $MaxScore.`n")
                            $controlResult.AddMessage([Constants]::HashLine)                          
                            $controlResult.AddMessage([Constants]::SingleDashLine +"`nLooking for extensions from known publishers`n"+[Constants]::SingleDashLine) 
                            $controlResult.AddMessage("`nNote: The following are considered as 'known' publishers: `n`t[$($knownExtPublishers -join ', ')]");
                            if(!$IsKnownPublishersPropertyPresent)
                                {
                                    $controlResult.AddMessage("***'Known publisher' setting is not present in the policy configuration.***")
                                } 
                            $unKnownCount = ($unKnownExtensions | Measure-Object).Count
                            if($unKnownCount -gt 0){
                                                               
                                $controlResult.AddMessage("`nNo. of extensions (from publishers not in 'known publishers' list): $unKnownCount");
                                $controlResult.AdditionalInfo += "No. of installed extensions (from publishers not in 'known publishers' list): " + $unKnownCount;
                                $controlResult.AddMessage("`nExtension details (from publishers not in 'known publishers' list): ")
                                $display = ($unKnownExtensions |  FT ExtensionName, publisherId, publisherName, Version -AutoSize | Out-String -Width $ftWidth)
                                $controlResult.AddMessage($display)
                                $controlResult.AdditionalInfo += "Installed extensions (from unknown publishers): " + [JsonHelper]::ConvertToJsonCustomCompressed($unKnownExtensions);
                            }

                            $knownCount = ($knownExtensions | Measure-Object).Count        
                            if($knownCount -gt 0){
                                $controlResult.AddMessage("`nNo. of  extensions (from publishers in the 'known publishers' list): $knownCount");
                                $controlResult.AdditionalInfo += "No. of extensions (from publishers in the 'known publishers' list): " + $knownCount;
                                $controlResult.AddMessage("`nExtension details (from publishers in the 'known publishers' list): ")
                                $display = ($knownExtensions|FT ExtensionName, publisherId, publisherName, Version -AutoSize | Out-String -Width $ftWidth)
                                $controlResult.AddMessage($display)
                            }
                            

                            $stateData = @{
                                known_Extensions = @();
                                unKnown_Extensions = @();
                            };
        
                            $stateData.known_Extensions += $knownExtensions
                            $stateData.unKnown_Extensions += $unKnownExtensions
                            $controlResult.SetStateData("List of installed extensions: ", $stateData);

                            
                             
                            if($staleExtensionList.count -gt 0)
                                {
                                    $controlResult.AddMessage([Constants]::HashLine)                          
                                    $controlResult.AddMessage([Constants]::SingleDashLine +"`nLooking for extensions that have not been updated by publishers for more than [$extensionsLastUpdatedInYears] years...`n" +[Constants]::SingleDashLine)
                                    if(!$islastUpdatedPropertyPresent)
                                    {
                                        $controlResult.AddMessage("***'Last Updated' setting is not present in the policy configuration.***")
                                    }
                                    $controlResult.AddMessage("`nNo. of extensions that haven't been updated in the last [$extensionsLastUpdatedInYears] years: "+ $staleExtensionList.count)
                                    $controlResult.AddMessage("`nExtension details (oldest first): ")
                                    $display = ($staleExtensionList| Sort-Object lastPublished | FT ExtensionName, @{Name = "lastPublished (MM-dd-yyyy)"; Expression = { ([datetime] $_.lastPublished).ToString("MM-dd-yyyy")} }, PublisherId, PublisherName, version -AutoSize | Out-String -Width $ftWidth)
                                    $controlResult.AddMessage($display)
                                }                           
                        
                            if($extensionListWithCriticalScopes.count -gt 0)
                                {  
                                    $controlResult.AddMessage([Constants]::HashLine)                            
                                    $controlResult.AddMessage([Constants]::SingleDashLine + "`nLooking for extensions that have sensitive access permissions...`n" + [Constants]::SingleDashLine)
                                    if(!$isCriticalScopesPropertyPresent)
                                    {
                                        $controlResult.AddMessage("***'Extension critical scopes' setting is not present in the policy configuration.***")
                                    } 
                                    $controlResult.AddMessage("Note: The following permissions are considered sensitive: `n`t[$($extensionCriticalScopes -join ', ')]")
                                    $controlResult.AddMessage("`nNo. of extensions that have sensitive access permissions: "+ $extensionListWithCriticalScopes.count)                        
                                    $controlResult.AddMessage("`nExtension details (extensions that have sensitive access permissions): ")
                                    $display= ($extensionListWithCriticalScopes | FT ExtensionName, scopes, PublisherId, PublisherName  -AutoSize | Out-String -Width $ftWidth)
                                    $controlResult.AddMessage($display) 
                                }
                            
                            
                            if($extensionListWithNonProductionExtensionIndicators.count -gt 0)
                                {   
                                    $controlResult.AddMessage([Constants]::HashLine)
                                    $controlResult.AddMessage([Constants]::SingleDashLine+"`nLooking for extensions that are not production ready...`n"+[Constants]::SingleDashLine)
                                    if(!$isNonProdIndicatorsPropertyPresent)
                                    {
                                        $controlResult.AddMessage("***'Non-production extension indicators' setting is not present in the policy configuration.***")
                                    } 
                                    $controlResult.AddMessage("Note: This checks for extensions with words [$($nonProductionExtensionIndicators -join ', ')] in extension names.")
                                    $controlResult.AddMessage("`nNo. of non-production extensions (based on name):  "+ $extensionListWithNonProductionExtensionIndicators.count)
                                    $controlResult.AddMessage("`nExtension details (non-production extensions (based on name)):  ")
                                    $controlResult.AddMessage( ($extensionListWithNonProductionExtensionIndicators | FT ExtensionName, PublisherId, PublisherName -AutoSize | Out-String -Width $ftWidth))
                                }

                            if($nonProdExtensions.count -gt 0)
                            {   
                                $controlResult.AddMessage([Constants]::HashLine) 
                                $controlResult.AddMessage([Constants]::SingleDashLine+"`nLooking for extensions that are marked 'Preview' via Gallery flags...`n"+[Constants]::SingleDashLine)
                                $controlResult.AddMessage("`nNo. of installed extensions marked as 'Preview' via Gallery flags: "+ $nonProdExtensions.count);
                                $controlResult.AddMessage("`nExtension details (installed extensions which are marked as 'Preview' via Gallery flags): ")
                                $controlResult.AddMessage(($nonProdExtensions | FT ExtensionName, PublisherId, PublisherName -AutoSize | Out-String -Width $ftWidth));
                            } 
    
                            if($topPublisherExtensions.count -gt 0)
                            {   
                                $controlResult.AddMessage([Constants]::HashLine)
                                $controlResult.AddMessage([Constants]::SingleDashLine+"`nLooking for extensions that are from publishers with a 'Top Publisher' certification...`n"+[Constants]::SingleDashLine);
                                $controlResult.AddMessage("`nNo. of installed extensions from 'Top Publishers': "+$topPublisherExtensions.count);
                                $controlResult.AddMessage("`nExtension details (installed extensions from 'Top Publishers'): ")
                                $controlResult.AddMessage(($topPublisherExtensions | FT ExtensionName, PublisherId, PublisherName -AutoSize | Out-String -Width $ftWidth) );
                            }
                                
                            if($privateExtensions.count -gt 0)
                            {   
                                $controlResult.AddMessage([Constants]::HashLine)
                                $controlResult.AddMessage([Constants]::SingleDashLine+"`nLooking for extensions that have 'private' visibility for the org...`n"+[Constants]::SingleDashLine);
                                $controlResult.AddMessage("`nNo. of installed extensions with 'private' visibility: "+$privateExtensions.count);
                                $controlResult.AddMessage("`nExtension details (installed extensions with 'private' visibility): ")
                                $controlResult.AddMessage(($privateExtensions | FT ExtensionName, PublisherId, PublisherName -AutoSize | Out-String -Width $ftWidth));
                            }                            
                            [Organization]::InstalledExtensionInfo = $combinedTable   
                                                  
                        }                                                                      
                    }                                        
                    ## end Deep scan
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No installed extensions found.");
                }
            }#>
            else 
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "No installed extensions found.");
            }

        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of installed extensions.");
        }

        return $controlResult
    }

    hidden [ControlResult] ValidateSharedExtensions([ControlResult] $controlResult)
    {        
        try
        {
            if($null -eq $this.allExtensionsObj)
            {
                $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $($this.OrganizationContext.OrganizationName);
                $orgURL="https://dev.azure.com/{0}/_settings/extensions" -f $($this.OrganizationContext.OrganizationName);
                $inputbody =  "{'contributionIds':['ms.vss-extmgmt-web.ext-management-hub'],'dataProviderContext':{'properties':{'sourcePage':{'url':'$orgURL','routeId':'ms.vss-admin-web.collection-admin-hub-route','routeValues':{'adminPivot':'extensions','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json
                $this.allExtensionsObj = [WebRequestHelper]::InvokePostWebRequest($apiURL,$inputbody);
            }

            if([Helpers]::CheckMember($this.allExtensionsObj[0],"dataProviders") -and $this.allExtensionsObj.dataProviders.'ms.vss-extmgmt-web.extensionManagmentHub-collection-data-provider')
            {
                $sharedExtensions = $this.allExtensionsObj[0].dataProviders.'ms.vss-extmgmt-web.extensionManagmentHub-collection-data-provider'.sharedExtensions

                if(($sharedExtensions | Measure-Object).Count -gt 0)
                {
                    $controlResult.AddMessage("No. of shared extensions: " + $sharedExtensions.Count)
                    $controlResult.AdditionalInfo += "No. of shared extensions: " + ($sharedExtensions | Measure-Object).Count;
                    $extensionList = @();
                    $extensionList +=  ($sharedExtensions | Select-Object extensionName, publisherId, publisherName, version) 

                    $controlResult.AddMessage([VerificationResult]::Verify, "Review the below list of shared extensions: "); 
                    $ftWidth = 512 #To avoid "..." truncation
                    $display = ($extensionList |  FT ExtensionName, publisherId, publisherName, Version -AutoSize | Out-String -Width $ftWidth)                                
                    $controlResult.AddMessage($display)
                    $controlResult.SetStateData("List of shared extensions: ", $extensionList);
                    $controlResult.AdditionalInfo += "List of shared extensions: " + [JsonHelper]::ConvertToJsonCustomCompressed($extensionList);                               
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
        }
        return $controlResult
    }

    hidden [ControlResult] CheckGuestIdentities([ControlResult] $controlResult)
    {
        try 
        {
            $apiURL = "https://vsaex.dev.azure.com/{0}/_apis/UserEntitlements?%24filter=userType%20eq%20%27guest%27&%24orderBy=name%20Ascending&api-version=6.1-preview.3" -f $($this.OrganizationContext.OrganizationName);
            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL); # returns a maximum of 100 guest users
            $guestUsers = @()
            if(($responseObj -ne $null) -and $responseObj.Count -gt 0 -and ([Helpers]::CheckMember($responseObj[0], 'members')))
            {
                $guestUsers += $responseObj[0].members
                $continuationToken =  $responseObj[0].continuationToken # Use the continuationToken for pagination
                while ($continuationToken -ne $null){
                    $urlEncodedToken = [System.Web.HttpUtility]::UrlEncode($continuationToken)
                    $apiURL = "https://vsaex.dev.azure.com/{0}/_apis/UserEntitlements?continuationToken=$urlEncodedToken&%24filter=userType%20eq%20%27guest%27&%24orderBy=name%20Ascending&api-version=6.1-preview.3" -f $($this.OrganizationContext.OrganizationName);
                    try{
                        $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
                        $guestUsers += $responseObj[0].members
                        $continuationToken =  $responseObj[0].continuationToken
                    }
                    catch
                    {
                        # Eating the exception here as we could not fetch the further guest users
                        $continuationToken = $null
                    }
                }
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
        } 

        return $controlResult
    }

    hidden [ControlResult] CheckExtensionManagers([ControlResult] $controlResult)
    {

        $apiURL = "https://extmgmt.dev.azure.com/{0}/_apis/securityroles/scopes/ems.manage.ui/roleassignments/resources/ems-ui" -f $($this.OrganizationContext.OrganizationName);
        
        try 
        {
            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
        
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
                $controlResult.AddMessage("No. of extension managers present: " + $responseObj.Count)
                $controlResult.AdditionalInfo += "No. of extension managers present: " + ($responseObj | Measure-Object).Count;
                $extensionManagerList = @();
                $extensionManagerList +=  ($responseObj | Select-Object @{Name="IdentityName"; Expression = {$_.identity.displayName}},@{Name="Role"; Expression = {$_.role.displayName}})
                $controlResult.AddMessage([VerificationResult]::Verify, "Review the below list of extension managers: ",$extensionManagerList);        
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
        }
        return $controlResult
    }

    hidden [ControlResult] CheckInactiveUsers([ControlResult] $controlResult)
    {
        try {
            $topInactiveUsers = $this.ControlSettings.Organization.TopInactiveUserCount 
            $apiURL = "https://vsaex.dev.azure.com/{0}/_apis/UserEntitlements?top={1}&filter=&sortOption=lastAccessDate+ascending&api-version=6.1-preview.3" -f $($this.OrganizationContext.OrganizationName), $topInActiveUsers;
            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);

            if($responseObj.Count -gt 0)
            {
                $inactiveUsers =  @()
                $responseObj[0].items | ForEach-Object { 
                    if([datetime]::Parse($_.lastAccessedDate) -lt ((Get-Date).AddDays(-$($this.ControlSettings.Organization.InActiveUserActivityLogsPeriodInDays))))
                    {
                        $inactiveUsers+= $_
                    }                
                }
                if(($inactiveUsers | Measure-Object).Count -gt 0)
                {
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
                        $controlResult.AdditionalInfo += "Total number of users who were never active: " + $neverActiveUsersCount;
                        $controlResult.AdditionalInfo += "List of users who were never active: " + [JsonHelper]::ConvertToJsonCustomCompressed($neverActiveUsers);
                    } 
                    
                    $inactiveUsersWithDaysCount = ($inactiveUsersWithDays | Measure-Object).Count
                    if($inactiveUsersWithDaysCount -gt 0) {
                        $controlResult.AddMessage("`nTotal number of users who are inactive from last $($this.ControlSettings.Organization.InActiveUserActivityLogsPeriodInDays) days: $($inactiveUsersWithDaysCount)");                
                        $controlResult.AddMessage("Review users present in the organization who are inactive from last $($this.ControlSettings.Organization.InActiveUserActivityLogsPeriodInDays) days: ",$inactiveUsersWithDays);
                        $controlResult.AdditionalInfo += "Total number of users who are inactive from last $($this.ControlSettings.Organization.InActiveUserActivityLogsPeriodInDays) days: " + $inactiveUsersWithDaysCount;
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No inactive users found.")   
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "No inactive users found.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of users in the organization.");
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckDisconnectedIdentities([ControlResult] $controlResult)
    {
        try 
        {
            $apiURL = "https://dev.azure.com/{0}/_apis/OrganizationSettings/DisconnectedUser" -f $($this.OrganizationContext.OrganizationName);
            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
            
            #disabling null check to CheckMember because if there are no disconnected users - it will return null.
            if ([Helpers]::CheckMember($responseObj[0], "users",$false)) 
            {
                if (($responseObj[0].users | Measure-Object).Count -gt 0 ) 
                {
        
                    $userNames = @();   
                    $userNames += ($responseObj[0].users | Select-Object -Property @{Name = "Name"; Expression = { $_.displayName } }, @{Name = "mailAddress"; Expression = { $_.preferredEmailAddress } })
                    $controlResult.AddMessage("Total number of disconnected users: ", ($userNames | Measure-Object).Count);
                    $controlResult.AddMessage([VerificationResult]::Failed, "Remove access for below disconnected users: ", $userNames);  
                    $controlResult.SetStateData("Disconnected users list: ", $userNames);
                    $controlResult.AdditionalInfo += "Total number of disconnected users: " + ($userNames | Measure-Object).Count;
                    $controlResult.AdditionalInfo += "List of disconnected users: " + [JsonHelper]::ConvertToJsonCustomCompressed($userNames);
                }
                else 
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No disconnected users found.");
                }   
            } 
        }
        catch 
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of disconnected users.");
        }
       
        return $controlResult;
    }

    hidden [ControlResult] CheckRBACAccess([ControlResult] $controlResult)
    {
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
       if($this.PipelineSettingsObj)
       {
            
            if($this.PipelineSettingsObj.enforceSettableVar -eq $true )
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Only limited variables can be set at queue time.");
            }
            else{
                $controlResult.AddMessage([VerificationResult]::Failed, "All variables can be set at queue time.");
            }       
       }
       else{
            $controlResult.AddMessage([VerificationResult]::Manual, "Pipeline settings could not be fetched due to insufficient permissions at organization scope.");
        }
        return $controlResult
    }

    hidden [ControlResult] CheckJobAuthZScope([ControlResult] $controlResult)
    {
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
        try
        {
            $url ="https://extmgmt.dev.azure.com/{0}/_apis/extensionmanagement/installedextensions?api-version=6.0-preview.1" -f $($this.OrganizationContext.OrganizationName);
            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($url);     
            $autoInjExt = @();
            
            foreach($extension in $responseObj)
            {
                foreach($cont in $extension.contributions)
                {
                    if([Helpers]::CheckMember($cont,"type"))
                    {
                        if($cont.type -eq "ms.azure-pipelines.pipeline-decorator")
                        {
                            $autoInjExt +=  ($extension | Select-Object -Property @{Name="Name"; Expression = {$_.extensionName}},@{Name="Publisher"; Expression = {$_.PublisherName}},@{Name="Version"; Expression = {$_.version}})
                            break;
                        }
                    }  
                }     
            }

            if (($autoInjExt | Measure-Object).Count -gt 0)
            {
                $controlResult.AddMessage([VerificationResult]::Verify,"Verify the below auto-injected tasks at organization level: ", $autoInjExt);
                $controlResult.SetStateData("Auto-injected tasks list: ", $autoInjExt); 
                $controlResult.AdditionalInfo += "Total number of auto-injected extensions: " + ($autoInjExt | Measure-Object).Count;
                $controlResult.AdditionalInfo += "List of auto-injected extensions: " + [JsonHelper]::ConvertToJsonCustomCompressed($autoInjExt);
            }
            else 
            {
                $controlResult.AddMessage([VerificationResult]::Passed,"No auto-injected tasks found at organization level");
            }
        }
        catch 
        {
            $controlResult.AddMessage([VerificationResult]::Error,"Couldn't fetch the list of installed extensions in the organization.");     
        }

        return $controlResult
    }

    hidden [ControlResult] CheckMinPCACount([ControlResult] $controlResult)
    {
        $TotalPCAMembers=0
        $PCAMembers = @()
        $PCAMembers += [AdministratorHelper]::GetTotalPCAMembers($this.OrganizationContext.OrganizationName)
        $TotalPCAMembers = ($PCAMembers| Measure-Object).Count
        $PCAMembers = $PCAMembers | Select-Object displayName,mailAddress
        $controlResult.AddMessage("There are a total of $TotalPCAMembers Project Collection Administrators in your organization")
        if($TotalPCAMembers -lt $this.ControlSettings.Organization.MinPCAMembersPermissible){
            $controlResult.AddMessage([VerificationResult]::Failed,"Number of administrators configured are less than the minimum required administrators count: $($this.ControlSettings.Organization.MinPCAMembersPermissible)");
        }
        else{
            $controlResult.AddMessage([VerificationResult]::Passed,"Number of administrators configured are more than the minimum required administrators count: $($this.ControlSettings.Organization.MinPCAMembersPermissible)");
        }
        if($TotalPCAMembers -gt 0){
            $controlResult.AddMessage("Verify the following Project Collection Administrators: ",$PCAMembers)
            $controlResult.SetStateData("List of Project Collection Administrators: ",$PCAMembers)
            $controlResult.AdditionalInfo += "Total number of Project Collection Administrators: " + $TotalPCAMembers;
        }        
        return $controlResult
}

    hidden [ControlResult] CheckMaxPCACount([ControlResult] $controlResult)
    {
        
        $TotalPCAMembers=0
        $PCAMembers = @()
        $PCAMembers += [AdministratorHelper]::GetTotalPCAMembers($this.OrganizationContext.OrganizationName)
        $TotalPCAMembers = ($PCAMembers| Measure-Object).Count
        $PCAMembers = $PCAMembers | Select-Object displayName,mailAddress
        $controlResult.AddMessage("There are a total of $TotalPCAMembers Project Collection Administrators in your organization")
        if($TotalPCAMembers -gt $this.ControlSettings.Organization.MaxPCAMembersPermissible){
            $controlResult.AddMessage([VerificationResult]::Failed,"Number of administrators configured are more than the approved limit: $($this.ControlSettings.Organization.MaxPCAMembersPermissible)");
        }
        else{
            $controlResult.AddMessage([VerificationResult]::Passed,"Number of administrators configured are within than the approved limit: $($this.ControlSettings.Organization.MaxPCAMembersPermissible)");
        }
        if($TotalPCAMembers -gt 0){
            $controlResult.AddMessage("Verify the following Project Collection Administrators: ",$PCAMembers)
            $controlResult.SetStateData("List of Project Collection Administrators: ",$PCAMembers)
            $controlResult.AdditionalInfo += "Total number of Project Collection Administrators: " + $TotalPCAMembers;
        }
    
        return $controlResult
    }

    hidden [ControlResult] CheckAuditStream([ControlResult] $controlResult)
    {
        
        try
        {
            $url ="https://auditservice.dev.azure.com/{0}/_apis/audit/streams?api-version=6.0-preview.1" -f $($this.OrganizationContext.OrganizationName);
            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($url);  
            
            # If no audit streams are configured, 'count' property is available for $responseObj[0] and its value is 0. 
            # If audit streams are configured, 'count' property is not available for $responseObj[0]. 
            #'Count' is a PSObject property and 'count' is response object property. Notice the case sensitivity here.
            
            # TODO: When there are no audit streams configured, CheckMember in the below condition returns false when checknull flag [third param in CheckMember] is not specified (default value is $true). Assiging it $false. Need to revisit.
            if(([Helpers]::CheckMember($responseObj[0],"count",$false)) -and ($responseObj[0].count -eq 0))
            {
                $controlResult.AddMessage([VerificationResult]::Failed, "No audit stream has been configured on the organization.");
            }
             # When audit streams are configured - the below condition will be true.
            elseif((-not ([Helpers]::CheckMember($responseObj[0],"count"))) -and ($responseObj.Count -gt 0)) 
            {
                $enabledStreams = $responseObj | Where-Object {$_.status -eq 'enabled'}
                $enabledStreams = $enabledStreams | Select-Object consumerType,displayName,status
                $enabledStreamsCount = ($enabledStreams | Measure-Object).Count
                $totalStreamsCount = ($responseObj | Measure-Object).Count
                $controlResult.AddMessage("`nTotal number of configured audit streams: $($totalStreamsCount)");
                $controlResult.AdditionalInfo += "Total number of configured audit streams: " + $totalStreamsCount;
                if(($enabledStreams | Measure-Object).Count -gt 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "One or more audit streams configured on the organization are currently enabled.");
                    $controlResult.AddMessage("`nTotal number of configured audit streams that are enabled: $($enabledStreamsCount)", $enabledStreams);
                    $controlResult.AdditionalInfo += "Total number of configured audit streams that are enabled: " + $enabledStreamsCount;
                    $controlResult.AdditionalInfo += "List of configured audit streams that are enabled: " + [JsonHelper]::ConvertToJsonCustomCompressed($enabledStreams);
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
        }
        return $controlResult
    }

    hidden [ControlResult] ValidateRequestedExtensions([ControlResult] $controlResult)
    {
        $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $($this.OrganizationContext.OrganizationName);
        $orgURL="https://dev.azure.com/{0}/_settings/extensions" -f $($this.OrganizationContext.OrganizationName);
        $inputbody =  "{'contributionIds':['ms.vss-extmgmt-web.ext-management-hub'],'dataProviderContext':{'properties':{'sourcePage':{'url':'$orgURL','routeId':'ms.vss-admin-web.collection-admin-hub-route','routeValues':{'adminPivot':'extensions','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json
        
        try
        {
            $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL,$inputbody);

            if([Helpers]::CheckMember($responseObj[0],"dataProviders") -and $responseObj[0].dataProviders.'ms.vss-extmgmt-web.extensionManagmentHub-collection-data-provider')
            {
                $requestedExtensions = $responseObj[0].dataProviders.'ms.vss-extmgmt-web.extensionManagmentHub-collection-data-provider'.requestedExtensions

                $ApprovedExtensions = $requestedExtensions | Where-Object { $_.requestState -eq "1" }
                $PendingExtensionsForApproval = $requestedExtensions | Where-Object { $_.requestState -eq "0" }
                $RejectedExtensions = $requestedExtensions | Where-Object { $_.requestState -eq "2" }

                if(($PendingExtensionsForApproval| Measure-Object).Count -gt 0)
                {
                    $extensionList = @();
                    $extensionList +=  ($PendingExtensionsForApproval | Select-Object extensionID, publisherId,@{Name="Requested By";Expression={requests.userName}})                                         

                    $ftWidth = 512 #To avoid "..." truncation
                    <#if(($ApprovedExtensions | Measure-Object).Count -gt 0)
                    {
                        $controlResult.AddMessage("No. of requested extensions that are approved: " + $ApprovedExtensions.Count)
                        $controlResult.AddMessage("`nExtension details")
                        $display = ($ApprovedExtensions |  FT extensionID, publisherId,@{Name="Requested By";Expression={$_.requests.userName}} -AutoSize | Out-String -Width $ftWidth)                                
                        $controlResult.AddMessage($display)
                    } 
                    
                    if(($RejectedExtensions| Measure-Object).Count -gt 0)
                    {
                        $controlResult.AddMessage("No. of requested extensions that are rejected: " + $RejectedExtensions.Count)
                        $controlResult.AddMessage("`nExtension details")
                        $display = ($RejectedExtensions |  FT extensionID, publisherId,@{Name="Requested By";Expression={$_.requests.userName}} -AutoSize | Out-String -Width $ftWidth)                                
                        $controlResult.AddMessage($display)
                    }                    
                    #>              
                    $controlResult.AddMessage([VerificationResult]::Verify, "`nReview the below list of pending requested extensions: ");
                    $controlResult.AddMessage("No. of requested extensions that are pending for approval: " + $PendingExtensionsForApproval.Count)
                    $controlResult.AddMessage("`nExtension details")
                    $display = ($PendingExtensionsForApproval |  FT extensionID, publisherId,@{Name="Requested By";Expression={$_.requests.userName}} -AutoSize | Out-String -Width $ftWidth)                                
                    $controlResult.AddMessage($display)
                    
                    $controlResult.SetStateData("List of requested extensions: ", $extensionList);
                    $controlResult.AdditionalInfo += "No. of pending requested extensions: " + ($PendingExtensionsForApproval | Measure-Object).Count;
                    $controlResult.AdditionalInfo += "List of requested extensions: " + [JsonHelper]::ConvertToJsonCustomCompressed($extensionList);                               
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
        }
        return $controlResult
    }

}
