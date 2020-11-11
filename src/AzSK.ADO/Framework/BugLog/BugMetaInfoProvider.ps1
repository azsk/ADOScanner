Set-StrictMode -Version Latest
class BugMetaInfoProvider {

    hidden [PSObject] $ControlSettingsBugLog
    hidden [string] $ServiceId

    BugMetaInfoProvider() {
    }

    hidden [string] GetAssignee([SVTEventContext[]] $ControlResult, $controlSettingsBugLog) {
        $this.ControlSettingsBugLog = $controlSettingsBugLog;
        #flag to check if pluggable bug logging interface (service tree)
        $isBugLogCustomFlow = $false;
        if ([Helpers]::CheckMember($this.ControlSettingsBugLog, "BugAssigneeAndPathCustomFlow", $null)) {
            $isBugLogCustomFlow = $this.ControlSettingsBugLog.BugAssigneeAndPathCustomFlow;
        }
        if ($isBugLogCustomFlow) {
            return $this.BugLogCustomFlow($ControlResult)
        }
        else {
            return $this.GetAssigneeFallback($ControlResult);
        }
    }

    hidden [string] BugLogCustomFlow($ControlResult)
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
                $assignee = $this.CalculateAssignee($rscId, $projectName, $resourceType);
                if (!$assignee) {
                    $assignee = $this.GetAssigneeFallback($ControlResult)
                }
            }            
        }
        catch {
            return "";
        }
        return $assignee;
    }

    hidden [string] CalculateAssignee($rscId, $projectName, $resourceType) 
    {
        $metaInfo = [MetaInfoProvider]::Instance;
        $assignee = "";
        try {
            $serviceTreeInfo = $metaInfo.FetchResourceMappingWithServiceData($rscId, $projectName, $resourceType);
            if($serviceTreeInfo)
            {
                $this.ServiceId = $serviceTreeInfo.serviceId;
                [BugLogPathManager]::AreaPath = $serviceTreeInfo.areaPath.Replace("\", "\\");
                $domainNameForAssignee = ""
                if([Helpers]::CheckMember($this.ControlSettingsBugLog, "DomainName"))
                {
                    $domainNameForAssignee = $this.ControlSettingsBugLog.DomainName;
                }
                $assignee = $serviceTreeInfo.devOwner.Split(";")[0] + "@"+ $domainNameForAssignee
            }
        }
        catch {
            Write-Host "Could not find service tree data file." -ForegroundColor Yellow
        }
        return $assignee;	
    }

    hidden [string] GetAssigneeFallback([SVTEventContext[]] $ControlResult) {
        $ResourceType = $ControlResult.ResourceContext.ResourceTypeName
        $ResourceName = $ControlResult.ResourceContext.ResourceName
        $organizationName = $ControlResult.SubscriptionContext.SubscriptionName;
        switch -regex ($ResourceType) {
            #assign to the creator of service connection
            'ServiceConnection' {
                return $ControlResult.ResourceContext.ResourceDetails.createdBy.uniqueName
            }
            #assign to the creator of agent pool
            'AgentPool' {
                $apiurl = "https://dev.azure.com/{0}/_apis/distributedtask/pools?poolName={1}&api-version=5.1" -f $organizationName, $ResourceName
                try {
                    $response = [WebRequestHelper]::InvokeGetWebRequest($apiurl)
                    return $response.createdBy.uniqueName
                }
                catch {
                    return "";
                }
            }
            #assign to the creator of variable group
            'VariableGroup' {
                return $ControlResult.ResourceContext.ResourceDetails.createdBy.uniqueName
            }
            #assign to the person who recently triggered the build pipeline, or if the pipeline is empty assign it to the creator
            'Build' {
                $definitionId = $ControlResult.ResourceContext.ResourceDetails.id;
    
                try {
                    $apiurl = "https://dev.azure.com/{0}/{1}/_apis/build/builds?definitions={2}&api-version=5.1" -f $organizationName, $ControlResult.ResourceContext.ResourceGroupName , $definitionId;
			    	
                    $response = [WebRequestHelper]::InvokeGetWebRequest($apiurl)
                    #check for recent trigger
                    if ([Helpers]::CheckMember($response, "requestedBy")) {
                        return $response[0].requestedBy.uniqueName
                    }
                    #if no triggers found assign to the creator
                    else {
                        $apiurl = "https://dev.azure.com/{0}/{1}/_apis/build/definitions/{2}?api-version=5.1" -f $organizationName, $ControlResult.ResourceContext.ResourceGroupName , $definitionId;
                        $response = [WebRequestHelper]::InvokeGetWebRequest($apiurl)
                        return $response.authoredBy.uniqueName
                    }
                }
                catch {
                    return "";
                }	
			    	
            }
            #assign to the person who recently triggered the release pipeline, or if the pipeline is empty assign it to the creator
            'Release' {
                $definitionId = ($ControlResult.ResourceContext.ResourceId -split "release/")[-1];
                try {
                    $apiurl = "https://vsrm.dev.azure.com/{0}/{1}/_apis/release/releases?definitionId={2}&api-version=5.1" -f $organizationName, $ControlResult.ResourceContext.ResourceGroupName , $definitionId;
                    $response = [WebRequestHelper]::InvokeGetWebRequest($apiurl)
                    #check for recent trigger
                    if ([Helpers]::CheckMember($response, "modifiedBy")) {
                        return $response[0].modifiedBy.uniqueName
                    }
                    #if no triggers found assign to the creator
                    else {
                        $apiurl = "https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions/{2}?&api-version=5.1" -f $organizationName, $ControlResult.ResourceContext.ResourceGroupName , $definitionId;
                        $response = [WebRequestHelper]::InvokeGetWebRequest($apiurl)
                        return $response.createdBy.uniqueName
                    }
                }
                catch {
                    return "";
                }
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

}
