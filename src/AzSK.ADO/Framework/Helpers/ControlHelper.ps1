# This class should contains method that would be required to filter/targer controls
class ControlHelper: EventBase{

    static $GroupMembersResolutionObj = @{} #Caching group resolution
      
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
}