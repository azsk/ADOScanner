using namespace System.Management.Automation
Set-StrictMode -Version Latest 

class AADGroupsInfo: CommandBase
{    
        
    hidden $organizationName;
    hidden $projectList;
    hidden [psobject] $aadGroupsList = @();
    
    AADGroupsInfo([string] $organizationName, [string] $projectNames, [InvocationInfo] $invocationContext): 
        Base($organizationName, $invocationContext) 
    { 
        $this.organizationName = $organizationName;
        if (-not [string]::IsNullOrWhiteSpace($ProjectNames)) {
            $this.projectList = $ProjectNames.split(",");
        }
	}
	
	[MessageData[]] GetAADGroupsList()
	{
        $settings = [ConfigurationManager]::GetAzSKSettings()

        #Get AAD Groups at organization level
        $this.GetAADGroupsListForOrg()

        #Get AAD groups at project level
        if (-not ([string]::IsNullOrEmpty($this.projectList)) -and $this.projectList.Count -gt 0)
        {
            foreach ($project in $this.projectList)
            {
                $this.GetAADGroupsListForProject($project.Trim())
            }
        }

        $groupCount = $this.aadGroupsList.Count
        if ($groupCount -gt 0)
        {
            $this.aadGroupsList = $this.aadGroupsList | sort-object -Property identityId -Unique 

            $AADgroupsCSV = New-Object -TypeName WriteCSVData
            $timestamp =(Get-Date -format "yyMMddHHmmss")
			$AADgroupsCSV.FileName = 'AAD_Groups_'+ $timestamp
			$AADgroupsCSV.FileExtension = 'csv'
			$AADgroupsCSV.FolderPath = ''
			$AADgroupsCSV.MessageData = $this.aadGroupsList | select-object -Property isCrossProject,domain,principalName,mailAddress,origin,originId,displayName,descriptor,IdentityId,DomainId
			#$AADgroupsCSV.MessageData = $this.aadGroupsList| Select-Object -Property IdentityId

            #publish to primary workspace
            if(-not [string]::IsNullOrWhiteSpace($settings.LAWSId) -and [LogAnalyticsHelper]::IsLAWSSettingValid -ne -1)
            {
                $laInventoryData = @()
                $AADgroupsCSV.MessageData | Add-Member -NotePropertyName OrganizationName -NotePropertyValue $this.organizationName
                $laInventoryData += $AADgroupsCSV.MessageData
                $body = $laInventoryData | ConvertTo-Json
                $lawsBodyByteArray = ([System.Text.Encoding]::UTF8.GetBytes($body))
                [LogAnalyticsHelper]::PostLAWSData($settings.LAWSId, $settings.LAWSSharedKey, $lawsBodyByteArray, 'AzSK_ADO_AAD_Groups', 'LAWS') 
            }
            
			$this.PublishAzSKRootEvent([AzSKRootEvent]::WriteCSV, $AADgroupsCSV);
            
			$this.PublishCustomMessage("Total number of AAD groups found: $groupCount", [MessageType]::Warning);
        }
        else {
			$this.PublishCustomMessage("No AAD Group has been found.");
        }

		[MessageData[]] $returnMsgs = @();
		$returnMsgs += [MessageData]::new("Total number of AAD groups found: $groupCount");
		return $returnMsgs
	}


    GetAADGroupsListForOrg() {
        $this.PublishCustomMessage("Fetching AAD groups at Organization [$($this.OrganizationName)] scope.");

        $url = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $($this.OrganizationName);
        $body = '{"contributionIds":["ms.vss-admin-web.org-admin-groups-data-provider"],"dataProviderContext":{"properties":{"sourcePage":{"url":"https://dev.azure.com/{0}/_settings/groups","routeId":"ms.vss-admin-web.collection-admin-hub-route","routeValues":{"adminPivot":"groups","controller":"ContributedPage","action":"Execute"}}}}}' 
        $body = ($body.Replace("{0}", $this.OrganizationName)) | ConvertFrom-Json
        $response = [WebRequestHelper]::InvokePostWebRequest($url,$body);  
        
        $allADOGroups = $response.dataProviders.'ms.vss-admin-web.org-admin-groups-data-provider'.identities
        $counter = 0

        #Loop to identify and fetch only AAD groups 
        foreach ($grp in $allADOGroups)
        {
            $counter++
            Write-Progress -Activity 'Groups evaluation progress..' -CurrentOperation $grp.DisplayName -PercentComplete (($counter / $allADOGroups.count) * 100)
            $descriptor = $grp.descriptor

            $url="https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.1-preview" -f $($this.OrganizationName);
            $postbody=@'
            {"contributionIds":["ms.vss-admin-web.org-admin-members-data-provider"],"dataProviderContext":{"properties":{"subjectDescriptor":"{0}","sourcePage":{"url":"https://dev.azure.com/{2}/_settings/groups?subjectDescriptor={1}","routeId":"ms.vss-admin-web.collection-admin-hub-route","routeValues":{"adminPivot":"groups","controller":"ContributedPage","action":"Execute"}}}}}
'@
            $postbody=$postbody.Replace("{0}",$descriptor)
            $postbody=$postbody.Replace("{1}",$this.OrganizationName)
            $rmContext = [ContextHelper]::GetCurrentContext();
            $user = "";
            $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))
            try {
                $response = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $postbody
                if([Helpers]::CheckMember($response.dataProviders.'ms.vss-admin-web.org-admin-members-data-provider', "identities"))
                {
                    $data = $response.dataProviders.'ms.vss-admin-web.org-admin-members-data-provider'.identities 
                    $data | ForEach-Object{
                        if($_.subjectKind -eq "group"){
                            if([Helpers]::CheckMember($_,"isAadGroup") -and $_.isAadGroup -eq $true){
                                #Get email id and origin id of the group which will then be used to create mapping with SIP database
                                $url=" https://vssps.dev.azure.com/{0}/_apis/Graph/SubjectQuery?api-version=5.2-preview.1" -f $($this.OrganizationName);
                                $postbody='{"query":"' + $($_.displayName) + '","subjectKind":["Group"]}'
                                $res = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $postbody
                                
                                if ([Helpers]::CheckMember($res,"value") -and $data.descriptor -eq $res.value[0].descriptor)
                                {
                                    $groupDetails = $res.value[0]
                                    $groupDetails | Add-Member -NotePropertyName IdentityId -NotePropertyValue $_.IdentityId
                                    $groupDetails | Add-Member -NotePropertyName DomainId -NotePropertyValue $_.Domain 

                                    $this.aadGroupsList += $groupDetails
                                }
                                
                            }
                        }
                    }
                }
            }
            catch {
                Write-Host $_
                start-sleep -Seconds 60 # delay added as there is limit on number of call every 5 mins
            }
        }
    }


    GetAADGroupsListForProject($projName) {
        $this.PublishCustomMessage("Fetching AAD groups at Project [$projName] scope.");

        $url= "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.1-preview.1" -f $($this.organizationName);
        $body=@'
        {"contributionIds":["ms.vss-admin-web.org-admin-groups-data-provider"],"dataProviderContext":{"properties":{"sourcePage":{"url":"https://dev.azure.com/{0}/{1}/_settings/permissions","routeId":"ms.vss-admin-web.project-admin-hub-route","routeValues":{"project":"{1}","adminPivot":"permissions","controller":"ContributedPage","action":"Execute"}}}}}
'@ 

        $body=$body.Replace("{0}",$this.organizationName)
        $body=$body.Replace("{1}",$projName)
        $rmContext = [ContextHelper]::GetCurrentContext();
		$user = "";
        $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))
        
        $responseObj = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $body
        $allADOGroups = $responseObj.dataProviders.'ms.vss-admin-web.org-admin-groups-data-provider'.identities #| where {$_.displayName -match "Administrators"}
        $counter = 0

        foreach ($grp in $allADOGroups)
        {
            $counter++
            Write-Progress -Activity 'Groups evaluation progress..' -CurrentOperation $grp.DisplayName -PercentComplete (($counter / $allADOGroups.count) * 100)

            $descriptor = $grp.descriptor
            $url="https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.1-preview" -f $($this.organizationName);
            $postbody=@'
            {"contributionIds":["ms.vss-admin-web.org-admin-members-data-provider"],"dataProviderContext":{"properties":{"subjectDescriptor":"{0}","sourcePage":{"url":"https://dev.azure.com/{2}/{1}/_settings/permissions?subjectDescriptor={0}","routeId":"ms.vss-admin-web.collection-admin-hub-route","routeValues":{"adminPivot":"groups","controller":"ContributedPage","action":"Execute"}}}}}
'@
            $postbody=$postbody.Replace("{0}",$descriptor)
            $postbody=$postbody.Replace("{2}",$this.organizationName)
            $postbody=$postbody.Replace("{1}",$projName)
            $rmContext = [ContextHelper]::GetCurrentContext();
            $user = "";
            $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))

            try{
                $response = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $postbody

                if([Helpers]::CheckMember($response.dataProviders.'ms.vss-admin-web.org-admin-members-data-provider', "identities")){
                    $data = $response.dataProviders.'ms.vss-admin-web.org-admin-members-data-provider'.identities 
                    $data | ForEach-Object{
                        if($_.subjectKind -eq "group"){
                            if([Helpers]::CheckMember($_,"isAadGroup") -and $_.isAadGroup -eq $true){
                                #Get email id and origin id of the group which will then be used to create mapping with SIP database
                                $url=" https://vssps.dev.azure.com/{0}/_apis/Graph/SubjectQuery?api-version=5.2-preview.1" -f $($this.OrganizationName);
                                $postbody='{"query":"' + $($_.displayName) + '","subjectKind":["Group"]}'
                                $res = Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $postbody
                                
                                if ([Helpers]::CheckMember($res,"value") -and $data.descriptor -eq $res.value[0].descriptor)
                                {
                                    $groupDetails = $res.value[0]
                                    $groupDetails | Add-Member -NotePropertyName IdentityId -NotePropertyValue $_.IdentityId
                                    $groupDetails | Add-Member -NotePropertyName DomainId -NotePropertyValue $_.Domain 

                                    $this.aadGroupsList += $groupDetails
                                }
                            }
                        }
                    }
                }
            }
            catch {
                Write-Host $_
                start-sleep -Seconds 60 # delay added as there is limit on number of call every 5 mins
            }
        }
    }
}

