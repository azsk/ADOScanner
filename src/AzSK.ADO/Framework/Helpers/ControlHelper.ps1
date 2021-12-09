# This class should contains method that would be required to filter/targer controls
class ControlHelper: EventBase{

    static [psobject] $ControlFixBackup = @()
    static $GroupMembersResolutionObj = @{} #Caching group resolution
    static $ResolvedBroaderGroups = @{} # Caching expanded broader groups
    static $GroupsWithNumerousMembers = @() # Groups which contains very large groups
    static $VeryLargeGroups = @() # Very large groups (fetched from controlsettings)
    static $IsGroupDetailsFetchedFromPolicy = $false
    static $AllowedMemberCountPerBroadGroup = @() # Allowed member count (fetched from controlsettings)
    static $GroupsToExpand = @() # Groups for which meber counts need to check (fetched from controlsettings)
    static $GroupsWithDescriptor = @{} # All broder groups with descriptors
    static [string] $parentGroup = $null #used to store current broader group
    static $CurrentGroupResolutionLevel = -1 # used to define the level of group expansion. Negative value indicates all level.
    static $GroupResolutionLevel = 1 # used to define the level of group expansion. Negative value indicates all level.
      
    #Checks if the severities passed by user are valid and filter out invalid ones
   hidden static [string []] CheckValidSeverities([string []] $ParamSeverities)
   {
       $ValidSeverities = @();		
       $ValidSeverityValues = @();	
       $InvalidSeverities = @();		
       $ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
       if([Helpers]::CheckMember($ControlSettings, 'ControlSeverity'))
       {
                   $severityMapping = $ControlSettings.ControlSeverity
                   #Discard the severity values passed in parameter that do not have mapping in Org settings.
                   foreach($sev in $severityMapping.psobject.properties)
                   {                         
                       $ValidSeverities +=  $sev.value       
                   }
                   $ValidSeverityValues += $ParamSeverities | Where-Object { $_ -in $ValidSeverities}
                   $InvalidSeverities += $ParamSeverities | Where-Object { $_ -notin $ValidSeverities }		
       }
       else 
       {
           $ValidEnumSeverities = [Enum]::GetNames('ControlSeverity')
           $ValidSeverityValues += $ParamSeverities | Where-Object { $_ -in $ValidEnumSeverities}
           $InvalidSeverities += $ParamSeverities | Where-Object { $_ -notin $ValidEnumSeverities }	
          
       }
     
       if($InvalidSeverities)
       {
          [EventBase]:: PublishGenericCustomMessage("WARNING: No control severity corresponds to `"$($InvalidSeverities -join ', ')`" for your org.",[MessageType]::Warning)
       }
       
       return $ValidSeverityValues
   }


    static [object] GetIdentitiesFromAADGroup([string] $OrgName, [String] $EntityId, [String] $groupName)
    {
        $members = @()
        $AllUsers = @()
        $rmContext = [ContextHelper]::GetCurrentContext();
        $user = "";
        $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user, $rmContext.AccessToken)))
        try {
            $apiUrl = 'https://dev.azure.com/{0}/_apis/IdentityPicker/Identities/{1}/connections?identityTypes=user&identityTypes=group&operationScopes=ims&operationScopes=source&connectionTypes=successors&depth=1&properties=DisplayName&properties=SubjectDescriptor&properties=SignInAddress' -f $($OrgName), $($EntityId)
            $responseObj = @(Invoke-RestMethod -Method Get -Uri $apiURL -Headers @{Authorization = ("Basic {0}" -f $base64AuthInfo) } -UseBasicParsing)
            # successors property will not be available if there are no users added to group.
            if ([Helpers]::CheckMember($responseObj[0], "successors")) {
                $members = @($responseObj.successors | Select-Object originId, displayName, @{Name = "subjectKind"; Expression = { $_.entityType } }, @{Name = "mailAddress"; Expression = { $_.signInAddress } }, @{Name = "descriptor"; Expression = { $_.subjectDescriptor } }, @{Name = "groupName"; Expression = { $groupName } })
            }

            $members | ForEach-Object {
                if ($_.subjectKind -eq 'User') {
                    $AllUsers += $_
                }
            }
            return $AllUsers
        }
        catch {
            Write-Host $_
            return $AllUsers
        }
    }

    static [void] ResolveNestedGroupMembers([string]$descriptor,[string] $orgName,[string] $projName){

        [ControlHelper]::groupMembersResolutionObj[$descriptor] = @()
        $url="https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.1-preview" -f $($orgName);
        if ([string]::IsNullOrEmpty($projName)){
            $postbody=@'
            {"contributionIds":["ms.vss-admin-web.org-admin-members-data-provider"],"dataProviderContext":{"properties":{"subjectDescriptor":"{0}","sourcePage":{"url":"https://dev.azure.com/{2}/_settings/groups?subjectDescriptor={1}","routeId":"ms.vss-admin-web.collection-admin-hub-route","routeValues":{"adminPivot":"groups","controller":"ContributedPage","action":"Execute"}}}}}
'@
            $postbody=$postbody.Replace("{0}",$descriptor)
            $postbody=$postbody.Replace("{1}",$orgName)
        }
        else {
            $postbody=@'
            {"contributionIds":["ms.vss-admin-web.org-admin-members-data-provider"],"dataProviderContext":{"properties":{"subjectDescriptor":"{0}","sourcePage":{"url":"https://dev.azure.com/{1}/{2}/_settings/permissions?subjectDescriptor={0}","routeId":"ms.vss-admin-web.collection-admin-hub-route","routeValues":{"adminPivot":"groups","controller":"ContributedPage","action":"Execute"}}}}}
'@
            $postbody=$postbody.Replace("{0}",$descriptor)
            $postbody=$postbody.Replace("{1}",$orgName)
            $postbody=$postbody.Replace("{2}",$projName)
        }
        $rmContext = [ContextHelper]::GetCurrentContext();
        $user = "";
        $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))
        try
        {
            $response = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $postbody
            if([Helpers]::CheckMember($response.dataProviders.'ms.vss-admin-web.org-admin-members-data-provider', "identities"))
            {
                $data=$response.dataProviders.'ms.vss-admin-web.org-admin-members-data-provider'.identities
                $data | ForEach-Object{
                    if($_.subjectKind -eq "group")
                    {
                        if ([string]::IsNullOrWhiteSpace($_.descriptor) -and (-not [string]::IsNullOrWhiteSpace($_.entityId)))
                        {
                            $identities = @([ControlHelper]::GetIdentitiesFromAADGroup($orgName, $_.entityId, $_.displayName))
                            if ($identities.Count -gt 0)
                            {
                                #add the descriptor of group to denote the user is a direct member of this group and is not a part of the group due to nesting, to be used in auto fix
                                $identities | Add-Member -NotePropertyName "DirectMemberOfGroup" -NotePropertyValue $descriptor
                                [ControlHelper]::groupMembersResolutionObj[$descriptor] += $identities

                            }
                        }
                        else
                        {
                           [ControlHelper]::ResolveNestedGroupMembers($_.descriptor,$orgName,$projName)
                           [ControlHelper]::groupMembersResolutionObj[$descriptor] += [ControlHelper]::groupMembersResolutionObj[$_.descriptor]
                        }
                    }
                    else
                    {
                        #add the descriptor of group to denote the user is a direct member of this group and is not a part of the group due to nesting, to be used in auto fix
                        $_ | Add-Member -NotePropertyName "DirectMemberOfGroup" -NotePropertyValue $descriptor
                        [ControlHelper]::groupMembersResolutionObj[$descriptor] += $_
                    }
                }
            }
        }
        catch {
            Write-Host $_
        }
    }

    static [void] FindGroupMembers([string]$descriptor,[string] $orgName,[string] $projName){
        if (-not [ControlHelper]::GroupMembersResolutionObj.ContainsKey("OrgName")) {
            [ControlHelper]::GroupMembersResolutionObj["OrgName"] = $orgName
        }

        [ControlHelper]::ResolveNestedGroupMembers($descriptor, $orgName, $projName)
    }

    static [PSObject] ResolveNestedBroaderGroupMembers([PSObject]$groupObj,[string] $orgName,[string] $projName)
    {
        $groupPrincipalName = $groupObj.principalName
        $members = @()
        [ControlHelper]::CurrentGroupResolutionLevel += 1
        if ([ControlHelper]::CurrentGroupResolutionLevel -le [ControlHelper]::GroupResolutionLevel) 
        {
            if ([ControlHelper]::ResolvedBroaderGroups.ContainsKey($groupPrincipalName))
            {
                $members += [ControlHelper]::ResolvedBroaderGroups[$_.principalName];
            }
            else
            {
                [ControlHelper]::ResolvedBroaderGroups[$groupPrincipalName] = @()
                $rmContext = [ContextHelper]::GetCurrentContext();
                $user = "";
                $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))
                $memberslist = @()
                if ([string]::IsNullOrWhiteSpace($groupObj.descriptor) -and (-not [string]::IsNullOrWhiteSpace($groupObj.entityId)))
                {
                    $apiUrl = 'https://dev.azure.com/{0}/_apis/IdentityPicker/Identities/{1}/connections?identityTypes=user&identityTypes=group&operationScopes=ims&operationScopes=source&connectionTypes=successors&depth=1&properties=DisplayName&properties=SubjectDescriptor&properties=SignInAddress' -f $($OrgName), $($groupObj.entityId)
                    $responseObj = @(Invoke-RestMethod -Method Get -Uri $apiURL -Headers @{Authorization = ("Basic {0}" -f $base64AuthInfo) } -UseBasicParsing)
                    # successors property will not be available if there are no users added to group.
                    if ([Helpers]::CheckMember($responseObj[0], "successors")) {
                        $memberslist = @($responseObj.successors | Select-Object entityId, originId, descriptor, @{Name = "principalName"; Expression = { $_.displayName } }, @{Name = "mailAddress"; Expression = { $_.signInAddress } }, @{Name = "subjectKind"; Expression = { $_.entityType } })
                    }
                    $members += [ControlHelper]::NestedGroupResolverHelper($memberslist)
                }
                else
                {
                    $descriptor = $groupObj.descriptor
                    $url="https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.1-preview" -f $($orgName);
                    $postbody=@'
                    {"contributionIds":["ms.vss-admin-web.org-admin-members-data-provider"],"dataProviderContext":{"properties":{"subjectDescriptor":"{0}","sourcePage":{"url":"https://dev.azure.com/{1}/{2}/_settings/permissions?subjectDescriptor={0}","routeId":"ms.vss-admin-web.collection-admin-hub-route","routeValues":{"adminPivot":"groups","controller":"ContributedPage","action":"Execute"}}}}}
'@
                    $postbody=$postbody.Replace("{0}",$descriptor)
                    $postbody=$postbody.Replace("{1}",$orgName)
                    $postbody=$postbody.Replace("{2}",$projName)
                    $response = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $postbody
                    if([Helpers]::CheckMember($response.dataProviders.'ms.vss-admin-web.org-admin-members-data-provider', "identities"))
                    {
                        $memberslist = @($response.dataProviders.'ms.vss-admin-web.org-admin-members-data-provider'.identities)
                    }
                    $members += [ControlHelper]::NestedGroupResolverHelper($memberslist)
                }

                [ControlHelper]::ResolvedBroaderGroups[$groupPrincipalName] = $members
            }
        }
        return $members
    }

    static [PSObject] NestedGroupResolverHelper($memberslist)
    {
        $members = @()
        if ($memberslist.Count -gt 0) 
        {
            $memberslist | ForEach-Object {
                if($_.subjectKind -eq "Group")
                {
                    if ([ControlHelper]::VeryLargeGroups -contains $_.principalName) {
                        [ControlHelper]::GroupsWithNumerousMembers += [ControlHelper]::parentGroup
                    }
                    else
                    {
                        $members += [ControlHelper]::ResolveNestedBroaderGroupMembers($_, $orgName, $projName)
                        [ControlHelper]::CurrentGroupResolutionLevel -= 1
                        # Uncomment the below code if member count needs to be displayed on console.
                        # Write-Host "Group: [$($_.principalName)]; MemberCount: $([ControlHelper]::ResolvedBroaderGroups[$_.principalName].Count)" -ForegroundColor Cyan
                    }
                }
                else
                {
                    $members += $_
                }
            }
        }
        return $members
    }

    static [PSObject] GetBroaderGroupDescriptorObj([string] $OrgName,[string] $groupName)
    {
        $groupObj = @()
        $projName = $groupName.Split("\")[0] -replace '[\[\]]'
        $rmContext = [ContextHelper]::GetCurrentContext();
		$user = "";
        $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))
        $url= "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.1-preview.1" -f $($OrgName);

        if ($projName -eq $OrgName) {
            $body=@'
            {"contributionIds":["ms.vss-admin-web.org-admin-groups-data-provider"],"dataProviderContext":{"properties":{"sourcePage":{"url":"https://dev.azure.com/{0}/_settings/groups","routeId":"ms.vss-admin-web.collection-admin-hub-route","routeValues":{"adminPivot":"groups","controller":"ContributedPage","action":"Execute"}}}}}
'@
            $body=$body.Replace("{0}",$OrgName)
        }
        else {
            $body=@'
            {"contributionIds":["ms.vss-admin-web.org-admin-groups-data-provider"],"dataProviderContext":{"properties":{"sourcePage":{"url":"https://dev.azure.com/{0}/{1}/_settings/permissions","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"{1}","adminPivot":"permissions","controller":"ContributedPage","action":"Execute"}}}}}
'@
            $body=$body.Replace("{0}",$OrgName)
            $body=$body.Replace("{1}",$projName)
        }
        
        try{
            $responseObj = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $body
            $groupObj = $responseObj.dataProviders.'ms.vss-admin-web.org-admin-groups-data-provider'.identities | Where-Object {$_.principalName -eq $groupName}
        }
        catch {
            Write-Host $_
        }
        return $groupObj
    }

    hidden static FetchControlSettingDetails()
    {
        $ControlSettingsObj = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
        [ControlHelper]::VeryLargeGroups = @($ControlSettingsObj.VeryLargeGroups)
        [ControlHelper]::AllowedMemberCountPerBroadGroup = @($ControlSettingsObj.AllowedMemberCountPerBroadGroup)
        [ControlHelper]::GroupsToExpand = @($ControlSettingsObj.BroaderGroupsToExpand)
        [ControlHelper]::IsGroupDetailsFetchedFromPolicy = $true
        [ControlHelper]::GroupResolutionLevel = $ControlSettingsObj.GroupResolution.GroupResolutionLevel
    }

    static [PSObject] FilterBroadGroupMembers([PSObject] $groupList, [bool] $fetchDescriptor)
    {
        $broaderGroupsWithExcessiveMembers = @()
        if ([ControlHelper]::IsGroupDetailsFetchedFromPolicy -eq $false) {
            [ControlHelper]::FetchControlSettingDetails()
        }
        # if the value is set to -1, it means all level of the groups needs be expaned.
        if ([ControlHelper]::GroupResolutionLevel -eq -1) {
            [ControlHelper]::GroupResolutionLevel = 1000 
        }
        # if environment variable is provided, it will override the policy configuration.
        if ($null -ne $env:GroupResolutionLevel) {
            [ControlHelper]::GroupResolutionLevel = $env:GroupResolutionLevel
        }
        [ControlHelper]::CurrentGroupResolutionLevel = 0
        $groupList | Foreach-Object {
            # In some cases, group object doesn't contains descriptor key which requires to expand the groups.
            if ($fetchDescriptor) {
                $groupName = $_.Name.split('\')[-1]
            }
            else {
                $groupName = $_.principalName.split('\')[-1]
            }
            if ([ControlHelper]::GroupsToExpand -contains $groupName) 
            {
                if ($fetchDescriptor) {
                    if (-not ([ControlHelper]::GroupsWithDescriptor.keys -contains $_.Name)) {
                        [ControlHelper]::GroupsWithDescriptor[$_.Name] += [ControlHelper]::GetBroaderGroupDescriptorObj($this.OrganizationContext.OrganizationName, $_.Name)
                    }
                    $groupObj = [ControlHelper]::GroupsWithDescriptor[$_.Name]
                }
                else {
                    $groupObj = $_
                }
                [ControlHelper]::parentGroup = $groupObj.principalName
                #Checking if group is prenet in the dictionary, if not then expand it, else fetch from dictionary
                if ([ControlHelper]::GroupMembersResolutionObj.ContainsKey($groupObj.descriptor)) {
                    $groupMembers = @([ControlHelper]::GroupMembersResolutionObj[$groupObj.descriptor])
                }
                elseif (-not [ControlHelper]::ResolvedBroaderGroups.ContainsKey($groupObj.principalName)) {
                    $groupMembers = @([ControlHelper]::ResolveNestedBroaderGroupMembers($groupObj, $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName))
                }
                else {
                    $groupMembers = @([ControlHelper]::ResolvedBroaderGroups[$groupObj.principalName])
                }
                $groupMembersCount = @($groupMembers | Select-Object -property mailAddress -Unique).Count

                # Checking the allowed member count for broader group
                # Fail only if member count is greater then allowed limit.
                if ([Helpers]::CheckMember([ControlHelper]::AllowedMemberCountPerBroadGroup, $groupName))
                {
                    $allowedMemberCount = [ControlHelper]::AllowedMemberCountPerBroadGroup.$groupName
                    if (($groupMembersCount -gt $allowedMemberCount) -or ([ControlHelper]::GroupsWithNumerousMembers -contains $groupObj.principalName))
                    {
                        $broaderGroupsWithExcessiveMembers += $groupObj.principalName
                    }
                }
                else {
                    $broaderGroupsWithExcessiveMembers += $groupObj.principalName
                }
            }
            else
            {
                if ($fetchDescriptor) {
                    $broaderGroupsWithExcessiveMembers += $_.Name
                }
                else {
                    $broaderGroupsWithExcessiveMembers += $_.principalName
                }
            }
        }
        return $broaderGroupsWithExcessiveMembers
    } 
}