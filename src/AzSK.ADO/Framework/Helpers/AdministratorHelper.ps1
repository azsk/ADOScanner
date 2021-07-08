class AdministratorHelper{
    static [bool] $isCurrentUserPCA=$false;
    static [bool] $isCurrentUserPA=$false;
    static $AllPCAMembers = @()
    static $AllPAMembers = @()
    static $ProjectAdminObject = @{}


    #Check whether uesr is PCA and subgroups member
    static [bool] isUserOrgAdminMember($organizationName, [PSObject] $allowedAdminGrp)
    {
        try 
        {
            $rmContext = [ContextHelper]::GetCurrentContext();
		    $user = "";
            $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))

            $url = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.1-preview.1" -f $($organizationName);
            $body=@'
            {"contributionIds":["ms.vss-admin-web.org-admin-groups-data-provider"],"dataProviderContext":{"properties":{"sourcePage":{"url":"https://dev.azure.com/{0}/_settings/groups","routeId":"ms.vss-admin-web.collection-admin-hub-route","routeValues":{"adminPivot":"groups","controller":"ContributedPage","action":"Execute"}}}}}
'@ 
            $body = $body.Replace("{0}",$organizationName)
            $groupsOrgObj = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $body

            if ($allowedAdminGrp) {
                $groupsOrgObj = $groupsOrgObj.dataProviders.'ms.vss-admin-web.org-admin-groups-data-provider'.identities | where { $allowedAdminGrp.GroupNames -contains $_.displayName }
            }
            #else condition if 'AllowAdminControlScanForGroups' propertry not foud in orgpolicy. Then check using default group PA 
            else {
                $groupsOrgObj = $groupsOrgObj.dataProviders.'ms.vss-admin-web.org-admin-groups-data-provider'.identities | where { "Project Collection Administrators" -eq $_.displayName }
            }
            foreach ($group in $groupsOrgObj)
	        {
                #if user found in group return true
                if ([AdministratorHelper]::GetIsCurrentUserPCA($group.descriptor, $organizationName)) {
                    return $true;
                }
            }
            return $false;
        }
        catch
        {
            return $false;
        }
    }

    static [bool] isUserProjectAdminMember($organizationName, $project, [PSObject] $allowedAdminGrp)
    {
        try 
        {
            $rmContext = [ContextHelper]::GetCurrentContext();
		    $user = "";
            $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))
            
            $url= "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.1-preview.1" -f $($organizationName);
            $body=@'
            {"contributionIds":["ms.vss-admin-web.org-admin-groups-data-provider"],"dataProviderContext":{"properties":{"sourcePage":{"url":"https://dev.azure.com/{0}/{1}/_settings/permissions","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"{1}","adminPivot":"permissions","controller":"ContributedPage","action":"Execute"}}}}}
'@     
            $body=$body.Replace("{0}",$organizationName)
            $body=$body.Replace("{1}",$project)
            $groupsObj = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $body
            
            if ($allowedAdminGrp) {
                $groupsObj = $groupsObj.dataProviders."ms.vss-admin-web.org-admin-groups-data-provider".identities | where { $allowedAdminGrp.GroupNames -contains $_.displayName }
            }
            #else condition if 'AllowAdminControlScanForGroups' propertry not foud in orgpolicy. Then check using default group PA 
            else {
                $groupsObj = $groupsObj.dataProviders."ms.vss-admin-web.org-admin-groups-data-provider".identities | where { "Project Administrators" -eq $_.displayName }
            }
		    
            foreach ($group in $groupsObj)
	        { 
                #if user found in group return true
                if([AdministratorHelper]::GetIsCurrentUserPA($groupsObj.descriptor,$organizationName, $project))
                {
		    	    return $true;
		        }	
		    }
            return $false;
        }
        catch
        {
            return $false;
        }
    }

    static [void] GetPCADescriptorAndMembers([string] $OrgName){
        
        $url= "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.1-preview.1" -f $($OrgName);
        $body=@'
        {"contributionIds":["ms.vss-admin-web.org-admin-groups-data-provider"],"dataProviderContext":{"properties":{"sourcePage":{"url":"https://dev.azure.com/{0}/_settings/groups","routeId":"ms.vss-admin-web.collection-admin-hub-route","routeValues":{"adminPivot":"groups","controller":"ContributedPage","action":"Execute"}}}}}
'@ 
        $body=$body.Replace("{0}",$OrgName)
        $rmContext = [ContextHelper]::GetCurrentContext();
		$user = "";
        $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))
        try{
        $responseObj = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $body

        $accname = "Project Collection Administrators"; 
        $prcollobj = $responseObj.dataProviders.'ms.vss-admin-web.org-admin-groups-data-provider'.identities | where {$_.displayName -eq $accname}
        
        

        if(($prcollobj | Measure-Object).Count -gt 0){
            [AdministratorHelper]::FindPCAMembers($prcollobj.descriptor,$OrgName)
        }
    }
    catch {
        Write-Host $_

    }
    }

    static [void] GetPADescriptorAndMembers([string] $OrgName,[string] $projName){
        
        $url= "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.1-preview.1" -f $($OrgName);
        $body=@'
        {"contributionIds":["ms.vss-admin-web.org-admin-groups-data-provider"],"dataProviderContext":{"properties":{"sourcePage":{"url":"https://dev.azure.com/{0}/{1}/_settings/permissions","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"{1}","adminPivot":"permissions","controller":"ContributedPage","action":"Execute"}}}}}
'@ 
        $body=$body.Replace("{0}",$OrgName)
        $body=$body.Replace("{1}",$projName)
        $rmContext = [ContextHelper]::GetCurrentContext();
		$user = "";
        $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))
        try{
        $responseObj = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $body

        $accname = "Project Administrators"; 
        $prcollobj = $responseObj.dataProviders.'ms.vss-admin-web.org-admin-groups-data-provider'.identities | where {$_.displayName -eq $accname}
        
        

        if(($prcollobj | Measure-Object).Count -gt 0){
            [AdministratorHelper]::FindPAMembers($prcollobj.descriptor,$OrgName,$projName)
        }
    }
    catch {
        Write-Host $_
    }
    }


    static [void] FindPCAMembers([string]$descriptor,[string] $OrgName){
        try {
            if ($null -eq [AdministratorHelper]::AllPCAMembers -or [AdministratorHelper]::AllPCAMembers.Count -eq 0)
            {
                [ControlHelper]::FindGroupMembers($descriptor,$orgName,"")
                [AdministratorHelper]::AllPCAMembers = [ControlHelper]::groupMembersResolutionObj[$descriptor]
            }
            $currentUser = [ContextHelper]::GetCurrentSessionUser();

            if([AdministratorHelper]::isCurrentUserPCA -eq $false -and $currentUser -in [AdministratorHelper]::AllPCAMembers.mailAddress){
                [AdministratorHelper]::isCurrentUserPCA=$true;
            }
        }
        catch {
            Write-Host $_
        }
    }

    static [void] FindPAMembers([string]$descriptor,[string] $OrgName,[string] $projName){
        try {
            if ($null -eq [AdministratorHelper]::AllPAMembers -or [AdministratorHelper]::AllPAMembers.Count -eq 0)
            {
                [ControlHelper]::FindGroupMembers($descriptor,$orgName,$projName)
                [AdministratorHelper]::AllPAMembers = [ControlHelper]::groupMembersResolutionObj[$descriptor]
            }
            $currentUser = [ContextHelper]::GetCurrentSessionUser();

            if([AdministratorHelper]::isCurrentUserPA -eq $false -and $currentUser -in [AdministratorHelper]::AllPAMembers.mailAddress){
                [AdministratorHelper]::isCurrentUserPA=$true;
                [AdministratorHelper]::ProjectAdminObject[$projName] = $true
            }
        }
        catch {
            Write-Host $_
        }
    }

    static [object] GetIdentitiesFromAADGroup([string] $OrgName, [String] $EntityId, [String] $groupName)
    {
        $members = @()
        $AllUsers = @()
        $rmContext = [ContextHelper]::GetCurrentContext();
		$user = "";
        $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))
        try {
            $apiUrl = 'https://dev.azure.com/{0}/_apis/IdentityPicker/Identities/{1}/connections?identityTypes=user&identityTypes=group&operationScopes=ims&operationScopes=source&connectionTypes=successors&depth=1&properties=DisplayName&properties=SubjectDescriptor&properties=SignInAddress' -f $($OrgName), $($EntityId)
            $responseObj = @(Invoke-RestMethod -Method Get -Uri $apiURL -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -UseBasicParsing)
            # successors property will not be available if there are no users added to group.
            if ([Helpers]::CheckMember($responseObj[0], "successors"))
            {
                $members = @($responseObj.successors | Select-Object originId, displayName, @{Name="subjectKind"; Expression = {$_.entityType}}, @{Name="mailAddress"; Expression = {$_.signInAddress}}, @{Name="descriptor"; Expression = {$_.subjectDescriptor}}, @{Name="groupName"; Expression = {$groupName}})
            }

            $members | ForEach-Object{
                if ($_.subjectKind -eq 'User')
                {
                    $AllUsers += $_
                }
            }
            return $AllUsers
        }
        catch
        {
            Write-Host $_
            return $AllUsers
        }
    }

    static [object] GetTotalPCAMembers([string] $OrgName){

        #TODO: Need to reinitialize as PS ISE caches this list. It will be inappropriate if you switch org names from one scan to another in the same session.
        [AdministratorHelper]::AllPCAMembers = @();
        [AdministratorHelper]::isCurrentUserPCA = $false;
        
        [AdministratorHelper]::GetPCADescriptorAndMembers($OrgName)

        #get unique pca based on display name and mail address
        [AdministratorHelper]::AllPCAMembers = @([AdministratorHelper]::AllPCAMembers | Sort-Object -Unique 'mailAddress')
        return [AdministratorHelper]::AllPCAMembers
    }
    static [object] GetTotalPAMembers([string] $OrgName,[string] $projName){
        #Always reinitialize PA member list. Needed when trying to scan multiple projects
        
        [AdministratorHelper]::AllPAMembers = @();
        [AdministratorHelper]::GetPADescriptorAndMembers($OrgName,$projName)

        [AdministratorHelper]::AllPAMembers = @([AdministratorHelper]::AllPAMembers | Sort-Object -Unique 'mailAddress')
        return [AdministratorHelper]::AllPAMembers
    }
    static [bool] GetIsCurrentUserPCA([string] $descriptor,[string] $OrgName){
        #TODO: Need to reinitialize as PS ISE caches this list. It will be inappropriate if you switch org names from one scan to another in the same session.

        [AdministratorHelper]::FindPCAMembers($descriptor,$OrgName)
        return [AdministratorHelper]::isCurrentUserPCA
    }
    static [bool] GetIsCurrentUserPA([string] $descriptor,[string] $OrgName,[string] $projName){
        #Always reinitialize PA member list and its count. Needed when trying to scan multiple projects
        [AdministratorHelper]::isCurrentUserPA = $false;
        [AdministratorHelper]::FindPAMembers($descriptor,$OrgName,$projName)
        return [AdministratorHelper]::isCurrentUserPA
    }

    static [void] PopulatePCAResultsToControl($humanAccounts, $svcAccounts, $controlResult){
        $TotalPCAMembers=$humanAccounts.Count + $svcAccounts.Count
        if($TotalPCAMembers -gt 0){
            $controlResult.AddMessage("Current set of Project Collection Administrators: ")
            $controlResult.AdditionalInfo = "Count of Project Collection Administrators: " + $TotalPCAMembers;
        }

        if ($humanAccounts.Count -gt 0) {
            $display=($humanAccounts |  FT displayName, mailAddress -AutoSize | Out-String -Width 512)
            $controlResult.AddMessage("`nHuman administrators: $($humanAccounts.Count) `n", $display)
            $controlResult.SetStateData("List of human Project Collection Administrators: ",$humanAccounts)
        }

        if ($svcAccounts.Count -gt 0) {
            $display=($svcAccounts |  FT displayName, mailAddress -AutoSize | Out-String -Width 512)
            $controlResult.AddMessage("`nService accounts: $($svcAccounts.Count) `n", $display)
            $controlResult.SetStateData("List of service account Project Collection Administrators: ",$svcAccounts)
        }
        return ;
    }
}