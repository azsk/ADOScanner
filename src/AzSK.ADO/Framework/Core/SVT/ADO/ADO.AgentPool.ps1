Set-StrictMode -Version Latest
class AgentPool: ADOSVTBase
{

    hidden [PSObject] $AgentObj; # This is used for fetching agent pool details
    hidden [PSObject] $ProjectId;
    hidden [PSObject] $AgentPoolId;
    hidden [PSObject] $agentPool; # This is used to fetch agent details in pool
    hidden [PSObject] $agentPoolActivityDetail = @{isAgentPoolActive = $true; agentPoolLastRunDate = $null; agentPoolCreationDate = $null; message = $null; isComputed = $false; errorObject = $null};
    hidden [string] $checkInheritedPermissionsPerAgentPool = $false

    hidden static [PSObject] $regexListForSecrets;

    hidden [PSObject] $AgentPoolOrgObj; #This will contain org level agent pool details

    AgentPool([string] $organizationName, [SVTResource] $svtResource): Base($organizationName,$svtResource)
    {
        $this.AgentPoolId =  ($this.ResourceContext.ResourceId -split "agentpool/")[-1]
        $this.ProjectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
        $apiURL = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/_apis/securityroles/scopes/distributedtask.agentqueuerole/roleassignments/resources/$($this.ProjectId)_$($this.AgentPoolId)";
        $this.AgentObj = @([WebRequestHelper]::InvokeGetWebRequest($apiURL));

        # if agent pool activity check function is not computed, then first compute the function to get the correct status of agent pool.
        if($this.agentPoolActivityDetail.isComputed -eq $false)
        {
            $this.CheckActiveAgentPool()
        }

        # overiding the '$this.isResourceActive' global variable based on the current status of agent pool.
        if ($this.agentPoolActivityDetail.isAgentPoolActive)
        {
            $this.isResourceActive = $true
        }
        else
        {
            $this.isResourceActive = $false
        }

        # calculating the inactivity period in days for the agent pool. If there is no use history, then setting it with negative value.
        # This will ensure inactive period is always computed irrespective of whether inactive control is scanned or not.
        if ($null -ne $this.agentPoolActivityDetail.agentPoolLastRunDate)
        {
            $this.InactiveFromDays = ((Get-Date) - $this.agentPoolActivityDetail.agentPoolLastRunDate).Days
        }

        if ([Helpers]::CheckMember($this.ControlSettings, "Agentpool.CheckForInheritedPermissions") -and $this.ControlSettings.Agentpool.CheckForInheritedPermissions) {
            $this.checkInheritedPermissionsPerAgentPool = $true
        }

        [AgentPool]::regexListForSecrets = @($this.ControlSettings.Patterns | Where-Object {$_.RegexCode -eq "SecretsInBuild"} | Select-Object -Property RegexList);
    }

    hidden [ControlResult] CheckRBACAccess([ControlResult] $controlResult)
    {
        <#{
            "ControlID": "ADO_AgentPool_AuthZ_Grant_Min_RBAC_Access",
            "Description": "All teams/groups must be granted minimum required permissions on agent pool.",
            "Id": "AgentPool110",
            "ControlSeverity": "High",
            "Automated": "Yes",
            "MethodName": "CheckRBACAccess",
            "Rationale": "Granting minimum access by leveraging RBAC feature ensures that users are granted just enough permissions to perform their tasks. This minimizes exposure of the resources in case of user/service account compromise.",
            "Recommendation": "Refer: https://docs.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=vsts",
            "Tags": [
            "SDL",
            "TCP",
            "Automated",
            "AuthZ",
            "RBAC"
            ],
            "Enabled": true
        }#>
        if($this.AgentObj.Count -gt 0)
        {
            $roles = @();
            $roles +=   ($this.AgentObj  | Select-Object -Property @{Name="Name"; Expression = {$_.identity.displayName}},@{Name="Role"; Expression = {$_.role.displayName}});
            $controlResult.AddMessage("Total number of identities that have access to agent pool: ", ($roles | Measure-Object).Count);
            $controlResult.AddMessage([VerificationResult]::Verify,"Validate whether following identities have been provided with minimum RBAC access to agent pool.", $roles);
            $controlResult.SetStateData("Validate whether following identities have been provided with minimum RBAC access to agent pool.", $roles);
            $controlResult.AdditionalInfo += "Total number of identities that have access to agent pool: " + ($roles | Measure-Object).Count;
        }
        elseif($this.AgentObj.Count -eq 0)
        {
            $controlResult.AddMessage([VerificationResult]::Passed,"No role assignment found")
        }
        return $controlResult
    }

    hidden [ControlResult] CheckInheritedPermissions([ControlResult] $controlResult)
    {
        if($this.AgentObj.Count -gt 0)
        {
        $inheritedRoles = $this.AgentObj | Where-Object {$_.access -eq "inherited"}
            if( ($inheritedRoles | Measure-Object).Count -gt 0)
            {
                $roles = @();
                $roles +=   ($inheritedRoles  | Select-Object -Property @{Name="Name"; Expression = {$_.identity.displayName}},@{Name="Role"; Expression = {$_.role.displayName}});
                $controlResult.AddMessage("Total number of inherited role assignments on agent pool: ", ($roles | Measure-Object).Count);
                $controlResult.AddMessage([VerificationResult]::Failed,"Found inherited role assignments on agent pool.", $roles);
                $controlResult.SetStateData("Found inherited role assignments on agent pool.", $roles);
                $controlResult.AdditionalInfo += "Total number of inherited role assignments on agent pool: " + ($roles | Measure-Object).Count;
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed,"No inherited role assignments found.")
            }

        }
        elseif($this.AgentObj.Count -eq 0)
        {
            $controlResult.AddMessage([VerificationResult]::Passed,"No role assignment found.")
        }
        return $controlResult
    }

    hidden [ControlResult] CheckOrgAgtAutoProvisioning([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try {
            #Only agent pools created from org setting has this settings..
            if($null -eq $this.AgentPoolOrgObj)
            {
                $agentPoolsURL = "https://dev.azure.com/{0}/_apis/distributedtask/pools?poolName={1}&api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $this.ResourceContext.resourcename;
                $this.AgentPoolOrgObj = @([WebRequestHelper]::InvokeGetWebRequest($agentPoolsURL));
            }

            if($this.AgentPoolOrgObj.Count -gt 0)
            {
                if ($this.AgentPoolOrgObj.autoProvision -eq $true) {
                    $controlResult.AddMessage([VerificationResult]::Failed,"Auto-provisioning is enabled for the $($this.AgentPoolOrgObj.name) agent pool.");
                    $controlResult.AdditionalInfo = "Auto-provisioning is enabled for [$($this.AgentPoolOrgObj.name)] agent pool.";
                    $controlResult.AdditionalInfoInCSV += "NA";
                    if ($this.ControlFixBackupRequired) {
                        #Data object that will be required to fix the control
                        $controlResult.BackupControlState = $this.AgentPoolOrgObj;
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed,"Auto-provisioning is not enabled for the agent pool.");
                    $controlResult.AdditionalInfoInCSV += "NA";
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch auto-update details of agent pool.");
            }
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch agent pool details.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckOrgAgtAutoProvisioningAutomatedFix([ControlResult] $controlResult)
    {
        try 
        {
            #Backup data object is not required in this scenario.
            $RawDataObjForControlFix = @();
            $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject

            $body = ""

            if (-not $this.UndoFix)
            {                 
                if ($body.length -gt 1) {$body += ","}
                $body += @"
                {
                    "id": $($RawDataObjForControlFix.id),
                    "autoProvision": false
                }
"@;
            }
            else 
            {
                if ($body.length -gt 1) {$body += ","}
                $body += @"
                {
                    "id": $($RawDataObjForControlFix.id),
                    "autoProvision": true
                }
"@;

            }  
            $url = "https://dev.azure.com/{0}/_apis/distributedtask/pools/{1}?api-version=5.0-preview.1" -f $($this.OrganizationContext.OrganizationName),$($RawDataObjForControlFix.id);          
			$header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($url)
            $webRequestResult = Invoke-RestMethod -Uri $url -Method Patch -ContentType "application/json" -Headers $header -Body $body							    
            $controlResult.AddMessage([VerificationResult]::Fixed,  "Auto-provisioning setting for agent pool have been changed.");
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckAutoUpdate([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            if($null -eq $this.AgentPoolOrgObj)
            {
                #autoUpdate setting is available only at org level settings.
                $agentPoolsURL = "https://dev.azure.com/{0}/_apis/distributedtask/pools?poolName={1}&api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $this.ResourceContext.resourcename;
                $this.AgentPoolOrgObj = @([WebRequestHelper]::InvokeGetWebRequest($agentPoolsURL));
            }

            if($this.AgentPoolOrgObj.Count -gt 0)
            {
                if($this.AgentPoolOrgObj.autoUpdate -eq $true)
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,"Auto-update of agents is enabled for [$($this.AgentPoolOrgObj.name)] agent pool.");
                    $controlResult.AdditionalInfoInCSV = "NA";
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Failed,"Auto-update of agents is disabled for [$($this.AgentPoolOrgObj.name)] agent pool.");
                    if ($this.ControlFixBackupRequired) {
                        #Data object that will be required to fix the control
                        $controlResult.BackupControlState = $this.AgentPoolOrgObj.id;
                    }
                    $controlResult.AdditionalInfo = "Auto-update of agents is disabled for [$($this.AgentPoolOrgObj.name)] agent pool.";
                    $controlResult.AdditionalInfoInCSV = "NA";
                }

            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch auto-update details of agent pool.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch agent pool details.");
            $controlResult.LogException($_)
        }

        return $controlResult
    }

    hidden [ControlResult] CheckAutoUpdateAutomatedFix([ControlResult] $controlResult)
    {
        try 
        {
            #Backup data object is not required in this scenario.
            $RawDataObjForControlFix = @();
            $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject

            $body = ""
            if (-not $this.UndoFix)
            {                 
                $body += @"
                {
                    "id":$($RawDataObjForControlFix),
                    "autoUpdate":true
                }
"@;
            }
            else 
           {
               $body += @"
                {
                    "id":$($RawDataObjForControlFix),
                    "autoUpdate":false
                }
"@;

            }
            $url = " https://dev.azure.com/{0}/_apis/distributedtask/pools/{1}?api-version=5.0-preview.1" -f $($this.OrganizationContext.OrganizationName),$($RawDataObjForControlFix);          
			$header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($url)
            $webRequestResult = Invoke-RestMethod -Uri $url -Method Patch -ContentType "application/json" -Headers $header -Body $body							    
            $controlResult.AddMessage([VerificationResult]::Fixed,  "Auto-Update setting for agent pool has been changed.");
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckPrjAllPipelineAccess([ControlResult] $controlResult)
    {
        try {
            $controlResult.VerificationResult = [VerificationResult]::Failed
            $agentPoolsURL = "https://dev.azure.com/{0}/{1}/_apis/build/authorizedresources?type=queue&id={2}&api-version=6.0-preview.1" -f $($this.OrganizationContext.OrganizationName),$this.ProjectId ,$this.AgentPoolId;
            $agentPoolsObj = @([WebRequestHelper]::InvokeGetWebRequest($agentPoolsURL));

            if([Helpers]::CheckMember($agentPoolsObj[0],"authorized"))
            {
                $controlResult.AddMessage([VerificationResult]::Failed,"Agent pool is marked as accessible to all pipelines.");
                if ($this.ControlFixBackupRequired) {
                    #Data object that will be required to fix the control
                    $controlResult.BackupControlState = $agentPoolsObj;
                }
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed,"Agent pool is not marked as accessible to all pipelines.");
            }
            $controlResult.AdditionalInfoInCSV = "NA";
            $agentPoolsObj =$null;
        }
        catch{
            $controlResult.AddMessage($_);
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch agent pool details.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckPrjAllPipelineAccessAutomatedFix([ControlResult] $controlResult)
    {
        try 
        {
            #Backup data object is not required in this scenario.
            $RawDataObjForControlFix = @();
            $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject

            $body = "["

            if (-not $this.UndoFix)
            {                 
                if ($body.length -gt 1) {$body += ","}
                $body += @"
                {
                    "authorized": false,
                    "id": "$($RawDataObjForControlFix.id)",
                    "name": "$($RawDataObjForControlFix.name)",
                    "type": "queue"
                }
"@;
            }
            else 
            {
                if ($body.length -gt 1) {$body += ","}
                $body += @"
                {
                    "authorized": true,
                    "id": "$($RawDataObjForControlFix.id)",
                    "name": "$($RawDataObjForControlFix.name)",
                    "type": "queue"
                }
"@;

            }          
            $body += "]"  
            $url = "https://dev.azure.com/{0}/{1}/_apis/build/authorizedresources?api-version=6.0-preview.1" -f $($this.OrganizationContext.OrganizationName),$($this.projectId);          
			$header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($url)
            $webRequestResult = Invoke-RestMethod -Uri $url -Method Patch -ContentType "application/json" -Headers $header -Body $body							    
            $controlResult.AddMessage([VerificationResult]::Fixed,  "Pipeline permissions for agent pool have been changed.");
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckInactiveAgentPool([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            if ($this.agentPoolActivityDetail.message -eq 'Could not fetch agent pool details.')
            {
                $controlResult.AddMessage([VerificationResult]::Error, $this.agentPoolActivityDetail.message);
                if ($null -ne $this.agentPoolActivityDetail.errorObject)
                {
                    $controlResult.LogException($this.agentPoolActivityDetail.errorObject)
                }
            }
            elseif($this.agentPoolActivityDetail.isAgentPoolActive)
            {
                $controlResult.AddMessage([VerificationResult]::Passed, $this.agentPoolActivityDetail.message);
            }
            else
            {
                if ($null -ne $this.agentPoolActivityDetail.agentPoolCreationDate)
                {
                    $inactiveLimit = $this.ControlSettings.AgentPool.AgentPoolHistoryPeriodInDays
                    if ((((Get-Date) - $this.agentPoolActivityDetail.agentPoolCreationDate).Days) -lt $inactiveLimit)
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed, "Agent pool was created within last $inactiveLimit days but never queued.");
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Failed, "Agent pool has not been queued from last $inactiveLimit days.");
                    }
                    $formattedDate = $this.agentPoolActivityDetail.agentPoolCreationDate.ToString("d MMM yyyy")
                    $controlResult.AddMessage("The agent pool was created on: $($formattedDate)");
                    $controlResult.AdditionalInfo += "The agent pool was created on: " + $formattedDate;
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, $this.agentPoolActivityDetail.message);
                }
            }

            if ($null -ne $this.agentPoolActivityDetail.agentPoolLastRunDate)
            {
                $formattedDate = $this.agentPoolActivityDetail.agentPoolLastRunDate.ToString("d MMM yyyy")
                $controlResult.AddMessage("Last queue date of agent pool: $($formattedDate)");
                $controlResult.AdditionalInfo += "Last queue date of agent pool: " + $formattedDate;
                $agentPoolInactivePeriod = ((Get-Date) - $this.agentPoolActivityDetail.agentPoolLastRunDate).Days
                $controlResult.AddMessage("The agent pool has been inactive from last $($agentPoolInactivePeriod) days.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch agent pool details.");
            $controlResult.LogException($_)
        }
        #clearing memory space.
        $this.agentPool = $null;
        return $controlResult
    }

    hidden [ControlResult] CheckCredInEnvironmentVariables([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed;
        try
        {
            if($null -eq  $this.agentPool)
            {
                $agentPoolsURL = "https://dev.azure.com/{0}/{1}/_settings/agentqueues?queueId={2}&__rt=fps&__ver=2" -f $($this.OrganizationContext.OrganizationName), $this.ProjectId ,$this.AgentPoolId;
                $this.agentPool = [WebRequestHelper]::InvokeGetWebRequest($agentPoolsURL);
            }
            $patterns = [AgentPool]::regexListForSecrets
            if($patterns.RegexList.Count -gt 0)
            {
                $noOfCredFound = 0;
                $agentsWithSecretsInEnv=@()
                if (([Helpers]::CheckMember($this.agentPool[0],"fps.dataproviders.data") ) -and ($this.agentPool[0].fps.dataProviders.data."ms.vss-build-web.agent-pool-data-provider") -and [Helpers]::CheckMember($this.agentPool[0].fps.dataProviders.data."ms.vss-build-web.agent-pool-data-provider","agents") )
                {
                    $agents = $this.agentpool.fps.dataproviders.data."ms.vss-build-web.agent-pool-data-provider".agents
                    $agentDetails = @{}
                    $poolId = ($this.agentpool.fps.dataproviders.data.'ms.vss-build-web.agent-pool-data-provider'.selectedAgentPool.id).ToString()
                    $agents | ForEach-Object {
                        $currentAgent = "" | Select-Object "AgentName","Capabilities"
                        $currentAgent.AgentName = $_.name
                        $agentId = $_.id
                        $envVariablesContainingSecret=@()
                        $secretsFoundInCurrentAgent = $false
                        if([Helpers]::CheckMember($_,"userCapabilities"))
                        {
                            $userCapabilities=$_.userCapabilities
                            $secretsHashTable=@{}
                            $capabilitiesTable=@{}
                            $secretsCapabilitiesTable=@{}
                            $userCapabilities.PSObject.properties | ForEach-Object { $secretsHashTable[$_.Name] = $_.Value }
                            $secretsHashTable.Keys | ForEach-Object {
                                for ($i = 0; $i -lt $patterns.RegexList.Count; $i++)
                                {
                                    if($secretsHashTable.Item($_) -cmatch $patterns.RegexList[$i])
                                    {
                                        $noOfCredFound += 1
                                        $secretsFoundInCurrentAgent = $true
                                        $envVariablesContainingSecret += $_
                                        $secretsCapabilitiesTable.add($_, ($secretsHashTable.Item($_)| ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString))
                                        break
                                    }
                                }
                                if ($envVariablesContainingSecret -notcontains $_) {
                                    $capabilitiesTable.add($_, $secretsHashTable.Item($_))
                                }
                            }
                        }
                        $agentDetails.add($agentId,$($secretsCapabilitiesTable,$capabilitiesTable))
                        $currentAgent.Capabilities = $envVariablesContainingSecret
                        if ($secretsFoundInCurrentAgent -eq $true) {
                            $agentsWithSecretsInEnv += $currentAgent
                        }
                    }
                    
                    if($noOfCredFound -eq 0)
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed, "No secrets found in user-defined capabilities of agents.");
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Failed, "Found secrets in user-defined capabilities of agents.");
                        $count = $agentsWithSecretsInEnv.Count
                        $controlResult.AddMessage("`nCount of agents that contain secrets: $count")
                        $controlResult.AdditionalInfo += "Count of agents that contain secrets: "+ $count;
                        $controlResult.AddMessage("`nAgent-wise list of user-defined capabilities with secrets: ");
                        $display=($agentsWithSecretsInEnv | FT AgentName,Capabilities -AutoSize | Out-String -Width 512)
                        $controlResult.AddMessage($display)
                        $controlResult.SetStateData("Agent-wise list of user-defined capabilities with secrets: ", $agentsWithSecretsInEnv );
                        $backupDataObject= @()
                        @($agentDetails.Keys) | ForEach-Object {
                            $key = $_
                             $obj = '' | Select @{l="PoolId";e={$poolId}}, @{l="AgentId";e={$key}},@{l="UndoFixObj";e={($agentDetails.item($key))[0]}}, @{l="FixObj";e={($agentDetails.item($key))[1]}}
                            $backupDataObject += $obj
                        }
                        if ($this.ControlFixBackupRequired) {
                            $controlResult.BackupControlState = $backupDataObject;
                        }
                    }
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "There are no agents in the pool.");
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Error, "Regular expressions for detecting credentials in environment variables for agents are not defined in your organization.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch details of user-defined capabilities of agents.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckCredInEnvironmentVariablesAutomatedFix([ControlResult] $controlResult)
    {
        try 
        {     
            $RawDataObjForControlFix = @();
            $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject

            $RawDataObjForControlFix | ForEach-Object {
                $CurrentAgent= $_
                $undofixObj = $CurrentAgent.UndoFixObj | Get-Member -MemberType NoteProperty | foreach {
                    @{($_.Name) = ([Helpers]::ConvertToPlainText((($CurrentAgent.UndoFixObj.($_.Name))| ConvertTo-SecureString))) }
                    }
                if($undofixObj){
                    $display = $undofixObj.Keys |  FT -AutoSize | Out-String -Width 512
                }
                else{
                    return;
                }
                if (-not $this.UndoFix)
                {                 
                    $body =  $CurrentAgent.FixObj   |ConvertTo-Json                    
                    $controlResult.AddMessage([VerificationResult]::Fixed,  "Following user-defined capabilities for agent ID $($CurrentAgent.AgentId) have been removed:");      
                }
                else 
                {
                    
                    $undofixObj+=$CurrentAgent.FixObj | Get-Member -MemberType NoteProperty | foreach {
                        @{($_.Name) = $CurrentAgent.FixObj.($_.Name)}
                        }
                    $body = "{"
                    $i=0;
                    $undofixObj.Keys | foreach{
                        if($body.Length -gt 1){
                            $body+=","
                        }
                        $agentpool = '"{0}":"{1}"' -f $_,$undofixObj[$i][$_]
                        $body+=$agentPool
                        $i++;
                    }
                    $body+="}"
                    $controlResult.AddMessage([VerificationResult]::Fixed,  "Following user-defined capabilities for agent ID $($CurrentAgent.AgentId) have been added:");
                }  
                
                $url = "https://dev.azure.com/{0}/_apis/distributedtask/pools/{1}/agents/{2}/usercapabilities?api-version=5.0-preview.1" -f $this.OrganizationContext.OrganizationName,$CurrentAgent.PoolId, $CurrentAgent.AgentId;          
                $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($url)
                $webRequestResult = Invoke-RestMethod -Uri $url -Method Put -ContentType "application/json" -Headers $header -Body $body	              
                $controlResult.AddMessage("`n$display");
            }  						
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden CheckActiveAgentPool()
    {
        try
        {
            $agentPoolsURL = "https://dev.azure.com/{0}/{1}/_settings/agentqueues?queueId={2}&__rt=fps&__ver=2" -f $($this.OrganizationContext.OrganizationName), $this.ProjectId ,$this.AgentPoolId;
            $this.agentPool = [WebRequestHelper]::InvokeGetWebRequest($agentPoolsURL);
            if (([Helpers]::CheckMember($this.agentPool[0], "fps.dataProviders.data") ) -and ($this.agentPool[0].fps.dataProviders.data."ms.vss-build-web.agent-jobs-data-provider"))
            {
                # $inactiveLimit denotes the upper limit on number of days of inactivity before the agent pool is deemed inactive.
                $inactiveLimit = $this.ControlSettings.AgentPool.AgentPoolHistoryPeriodInDays
                #Filtering agent pool jobs specific to the current project.
                $agentPoolJobs = $this.agentPool[0].fps.dataProviders.data."ms.vss-build-web.agent-jobs-data-provider".jobs | Where-Object {$_.scopeId -eq $this.ProjectId};
                 #Arranging in descending order of run time.
                $agentPoolJobs = $agentPoolJobs | Sort-Object queueTime -Descending
                #If agent pool has been queued at least once
                if (($agentPoolJobs | Measure-Object).Count -gt 0)
                {
                        #Get the last queue timestamp of the agent pool
                        if ([Helpers]::CheckMember($agentPoolJobs[0], "finishTime"))
                        {
                            $agtPoolLastRunDate = $agentPoolJobs[0].finishTime;

                            if ((((Get-Date) - $agtPoolLastRunDate).Days) -gt $inactiveLimit)
                            {
                                $this.agentPoolActivityDetail.isAgentPoolActive = $false;
                                $this.agentPoolActivityDetail.message = "Agent pool has not been queued in the last $inactiveLimit days.";
                            }
                            else
                            {
                                $this.agentPoolActivityDetail.isAgentPoolActive = $true;
                                $this.agentPoolActivityDetail.message = "Agent pool has been queued in the last $inactiveLimit days.";
                            }
                            $this.agentPoolActivityDetail.agentPoolLastRunDate = $agtPoolLastRunDate;
                        }
                        else
                        {
                            $this.agentPoolActivityDetail.isAgentPoolActive = $true;
                            $this.agentPoolActivityDetail.message = "Agent pool was being queued during control evaluation.";
                        }
                }
                else
                {
                    #[else] Agent pool is created but nenver run, check creation date greated then 180
                    $this.agentPoolActivityDetail.isAgentPoolActive = $false;
                    if (([Helpers]::CheckMember($this.agentPool, "fps.dataProviders.data") ) -and ($this.agentPool.fps.dataProviders.data."ms.vss-build-web.agent-pool-data-provider"))
                    {
                        $agentPoolDetails = $this.agentPool.fps.dataProviders.data."ms.vss-build-web.agent-pool-data-provider"
                        $this.agentPoolActivityDetail.agentPoolCreationDate = $agentPoolDetails.selectedAgentPool.createdOn;
                    }
                    else
                    {
                        $this.agentPoolActivityDetail.message = "Could not fetch agent pool details.";
                    }
                }
            }
            else
            {
                $this.agentPoolActivityDetail.message = "Could not fetch agent pool details.";
            }
        }
        catch
        {
            $this.agentPoolActivityDetail.message = "Could not fetch agent pool details.";
            $this.agentPoolActivityDetail.errorObject = $_
        }
        $this.agentPoolActivityDetail.isComputed = $true
    }

    hidden [ControlResult] CheckBroaderGroupAccess ([ControlResult] $controlResult) {
        try {
            $controlResult.VerificationResult = [VerificationResult]::Failed
            $restrictedBroaderGroups = @{}
            $restrictedBroaderGroupsForAgentPool = $this.ControlSettings.AgentPool.RestrictedBroaderGroupsForAgentPool;
            $restrictedBroaderGroupsForAgentPool.psobject.properties | foreach { $restrictedBroaderGroups[$_.Name] = $_.Value }
            if (($this.AgentObj.Count -gt 0) -and [Helpers]::CheckMember($this.AgentObj, "identity")) {
                # match all the identities added on agentpool with defined restricted list
                $roleAssignmentsToCheck = $this.AgentObj
                $restrictedGroups = @()
                if ($this.checkInheritedPermissionsPerAgentPool -eq $false) {
                    $roleAssignmentsToCheck = @($this.AgentObj | where-object { $_.access -ne "inherited" })
                }
                $roleAssignments = @($roleAssignmentsToCheck | Select-Object -Property @{Name="Name"; Expression = {$_.identity.displayName}},@{Name="Id"; Expression = {$_.identity.id}}, @{Name="Role"; Expression = {$_.role.displayName}});
                # Checking whether the broader groups have User/Admin permissions
                $restrictedGroups = @($roleAssignments | Where-Object { $restrictedBroaderGroups.keys -contains $_.Name.split('\')[-1] -and ($_.Role -in $restrictedBroaderGroups[$_.Name.split('\')[-1]])})

                if ($this.ControlSettings.CheckForBroadGroupMemberCount -and $restrictedGroups.Count -gt 0)
                {
                    $broaderGroupsWithExcessiveMembers = @([ControlHelper]::FilterBroadGroupMembers($restrictedGroups, $true))
                    $restrictedGroups = @($restrictedGroups | Where-Object {$broaderGroupsWithExcessiveMembers -contains $_.Name})
                }
                $restrictedGroupsCount = $restrictedGroups.Count
                # fail the control if restricted group found on agentpool
                if ($restrictedGroupsCount -gt 0) {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Count of broader groups that have excessive permissions on agent pool: $($restrictedGroupsCount)");
                    $formattedGroupsData = $restrictedGroups | Select @{l = 'Group'; e = { $_.Name} }, @{l = 'Role'; e = { $_.Role } }
                    $backupDataObject = $restrictedGroups | Select @{l = 'Group'; e = { $_.Name} },@{l = 'Id'; e = { $_.Id } }, @{l = 'Role'; e = { $_.Role } }
                    $formattedGroupsTable = ($formattedGroupsData | FT -AutoSize | Out-String -width 512)
                    $controlResult.AddMessage("`nList of groups: `n$formattedGroupsTable")
                    $controlResult.SetStateData("List of groups: ", $restrictedGroups)
                    $controlResult.AdditionalInfo += "Count of broader groups that have excessive permissions on agent pool: $($restrictedGroupsCount)";
                    $groups = $restrictedGroups | ForEach-Object { $_.name + ': ' + $_.role } 
                        $controlResult.AdditionalInfoInCSV = $groups -join ' ; '

                    if ($this.ControlFixBackupRequired) {
                        #Data object that will be required to fix the control
                        $controlResult.BackupControlState = $backupDataObject;
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No broader groups have excessive permissions on agent pool.");
                        $controlResult.AdditionalInfoInCSV = "NA";
                }
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed, "No groups have given access to agent pool.");
                $controlResult.AdditionalInfoInCSV = "NA";
            }
            $displayObj = $restrictedBroaderGroups.Keys | Select-Object @{Name = "Broader Group"; Expression = {$_}}, @{Name = "Excessive Permissions"; Expression = {$restrictedBroaderGroups[$_] -join ', '}}
            $controlResult.AddMessage("Note:`nThe following groups are considered 'broad' which should not excessive permissions: `n$($displayObj | FT -AutoSize| out-string -width 512)");
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the agent pool permissions.");
            $controlResult.LogException($_)
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckBroaderGroupAccessAutomatedFix ([ControlResult] $controlResult) {
        try {
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
                $RawDataObjForControlFix = @($RawDataObjForControlFix  | Select-Object @{Name="DisplayName"; Expression={$_.group}}, @{Name="OldRole"; Expression={$_.Role}},@{Name="NewRole"; Expression={$_.NewRole}})
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
                $RawDataObjForControlFix = @($RawDataObjForControlFix  | Select-Object @{Name="DisplayName"; Expression={$_.group}}, @{Name="OldRole"; Expression={$_.OldRole}},@{Name="NewRole"; Expression={$_.Role}})
            }
            $body += "]"

            #Put request           
            $url = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/_apis/securityroles/scopes/distributedtask.agentqueuerole/roleassignments/resources/$($this.ProjectId)_$($this.AgentPoolId)?api-version=6.1-preview.1";  
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
        return $controlResult  
    }
}
