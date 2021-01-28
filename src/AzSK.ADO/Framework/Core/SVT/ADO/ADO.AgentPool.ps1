Set-StrictMode -Version Latest 
class AgentPool: ADOSVTBase
{    

    hidden [PSObject] $AgentObj; # This is used for fetching agent pool details
    hidden [PSObject] $ProjectId;
    hidden [PSObject] $AgentPoolId;
    hidden [PSObject] $agentPool; # This is used to fetch agent details in pool
    
    AgentPool([string] $organizationId, [SVTResource] $svtResource): Base($organizationId,$svtResource) 
    {
        $this.AgentPoolId =  ($this.ResourceContext.ResourceId -split "agentpool/")[-1]
        $this.ProjectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
        $apiURL = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/_apis/securityroles/scopes/distributedtask.agentqueuerole/roleassignments/resources/$($this.ProjectId)_$($this.AgentPoolId)";
        $this.AgentObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);

    }

    hidden [ControlResult] CheckRBACAccess([ControlResult] $controlResult)
    {
        if(($this.AgentObj | Measure-Object).Count -gt 0)
        {
            $roles = @();
            $roles +=   ($this.AgentObj  | Select-Object -Property @{Name="Name"; Expression = {$_.identity.displayName}},@{Name="Role"; Expression = {$_.role.displayName}});
            $controlResult.AddMessage("Total number of identities that have access to agent pool: ", ($roles | Measure-Object).Count);
            $controlResult.AddMessage([VerificationResult]::Verify,"Validate whether following identities have been provided with minimum RBAC access to agent pool.", $roles);
            $controlResult.SetStateData("Validate whether following identities have been provided with minimum RBAC access to agent pool.", $roles);
            $controlResult.AdditionalInfo += "Total number of identities that have access to agent pool: " + ($roles | Measure-Object).Count;
        }
        elseif(($this.AgentObj | Measure-Object).Count -eq 0)
        {
            $controlResult.AddMessage([VerificationResult]::Passed,"No role assignment found")
        }
        return $controlResult
    }

    hidden [ControlResult] CheckInheritedPermissions([ControlResult] $controlResult)
    {
        if(($this.AgentObj | Measure-Object).Count -gt 0)
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
        elseif(($this.AgentObj | Measure-Object).Count -eq 0)
        {
            $controlResult.AddMessage([VerificationResult]::Passed,"No role assignment found.")
        }
        return $controlResult
    }

    hidden [ControlResult] CheckOrgAgtAutoProvisioning([ControlResult] $controlResult)
    {
        try {
            #Only agent pools created from org setting has this settings..
            $agentPoolsURL = "https://dev.azure.com/{0}/_apis/distributedtask/pools?poolName={1}&api-version=5.1" -f $($this.OrganizationContext.OrganizationName), $this.ResourceContext.resourcename;
            $agentPoolsObj = [WebRequestHelper]::InvokeGetWebRequest($agentPoolsURL);
              
            if ((($agentPoolsObj | Measure-Object).Count -gt 0) -and $agentPoolsObj.autoProvision -eq $true) {
                $controlResult.AddMessage([VerificationResult]::Failed,"Auto-provisioning is enabled for the $($agentPoolsObj.name) agent pool.");
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed,"Auto-provisioning is not enabled for the agent pool.");
            }

            $agentPoolsObj =$null;
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Manual,"Could not fetch agent pool details.");
        }
        return $controlResult
    }

    hidden [ControlResult] CheckAutoUpdate([ControlResult] $controlResult)
    {
        try
        {
            #autoUpdate setting is available only at org level settings.
            $agentPoolsURL = "https://dev.azure.com/{0}/_apis/distributedtask/pools?poolName={1}&api-version=5.1" -f $($this.OrganizationContext.OrganizationName), $this.ResourceContext.resourcename;
            $agentPoolsObj = [WebRequestHelper]::InvokeGetWebRequest($agentPoolsURL);
              
            if([Helpers]::CheckMember($agentPoolsObj,"autoUpdate"))
            {
                if($agentPoolsObj.autoUpdate -eq $true)
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,"Auto-update of agents is enabled for [$($agentPoolsObj.name)] agent pool.");
                }
                else 
                {
                    $controlResult.AddMessage([VerificationResult]::Failed,"Auto-update of agents is disabled for [$($agentPoolsObj.name)] agent pool.");
                }
                
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch auto-update details of agent pool.");
            }

            $agentPoolsObj =$null;
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch agent pool details.");
        }
        
        return $controlResult
    }

    hidden [ControlResult] CheckPrjAllPipelineAccess([ControlResult] $controlResult)
    {
        try {
            $agentPoolsURL = "https://dev.azure.com/{0}/{1}/_apis/build/authorizedresources?type=queue&id={2}" -f $($this.OrganizationContext.OrganizationName),$this.ProjectId ,$this.AgentPoolId;
            $agentPoolsObj = [WebRequestHelper]::InvokeGetWebRequest($agentPoolsURL);
                                   
            if([Helpers]::CheckMember($agentPoolsObj,"authorized") -and $agentPoolsObj.authorized)
            {
                $controlResult.AddMessage([VerificationResult]::Failed,"Access permission to all pipeline is enabled for the agent pool.");
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed,"Access permission to all pipeline is not enabled for the agent pool.");
            }
            $agentPoolsObj =$null;
        }
        catch{
            $controlResult.AddMessage($_); 
            $controlResult.AddMessage([VerificationResult]::Manual,"Could not fetch agent pool details.");
        }
        return $controlResult
    }

    hidden [ControlResult] CheckInActiveAgentPool([ControlResult] $controlResult)
    {
        try 
        {   
            if($null -eq  $this.agentPool)
            {
                $agentPoolsURL = "https://dev.azure.com/{0}/{1}/_settings/agentqueues?queueId={2}&__rt=fps&__ver=2" -f $($this.OrganizationContext.OrganizationName), $this.ProjectId ,$this.AgentPoolId;
                $this.agentPool = [WebRequestHelper]::InvokeGetWebRequest($agentPoolsURL);
            }
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
                                $controlResult.AddMessage([VerificationResult]::Failed, "Agent pool has not been queued in the last $inactiveLimit days.");
                            }
                            else 
                            {
                                $controlResult.AddMessage([VerificationResult]::Passed,"Agent pool has been queued in the last $inactiveLimit days.");
                            }
                            $controlResult.AddMessage("Last queue date of agent pool: $($agtPoolLastRunDate)");
                            $controlResult.AdditionalInfo += "Last queue date of agent pool: " + $agtPoolLastRunDate;
                        }
                        else 
                        {
                            $controlResult.AddMessage([VerificationResult]::Passed,"Agent pool was being queued during control evaluation.");
                        }
                }
                else 
                {
                    #[else] Agent pool is created but nenver run, check creation date greated then 180
                    if (([Helpers]::CheckMember($this.agentPool, "fps.dataProviders.data") ) -and ($this.agentPool.fps.dataProviders.data."ms.vss-build-web.agent-pool-data-provider")) 
                    {
                        $agentPoolDetails = $this.agentPool.fps.dataProviders.data."ms.vss-build-web.agent-pool-data-provider"
                        
                        if ((((Get-Date) - $agentPoolDetails.selectedAgentPool.createdOn).Days) -lt $inactiveLimit)
                        {
                            $controlResult.AddMessage([VerificationResult]::Passed, "Agent pool was created within last $inactiveLimit days but never queued.");
                        }
                        else 
                        {
                            $controlResult.AddMessage([VerificationResult]::Failed, "Agent pool has not been queued from last $inactiveLimit days.");
                        }
                        $agtPoolCreationDate = $agentPoolDetails.selectedAgentPool.createdOn;
                        $controlResult.AddMessage("The agent pool was created on: $($agtPoolCreationDate)");
                        $controlResult.AdditionalInfo += "The agent pool was created on: " + $agtPoolCreationDate;
                    }
                    else 
                    {
                        $controlResult.AddMessage([VerificationResult]::Error, "Agent pool details not found. Verify agent pool manually.");
                    }                    
                } 
            }
            else 
            { 
                $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch agent pool queue history.");
            }
        }
        catch 
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch agent pool queue history.");
        }
        #clearing memory space.
        $this.agentPool = $null;
        return $controlResult
    }

    hidden [ControlResult] CheckCredInEnvironmentVariables([ControlResult] $controlResult)
    {
        try 
        {   
            if($null -eq  $this.agentPool)
            {
                $agentPoolsURL = "https://dev.azure.com/{0}/{1}/_settings/agentqueues?queueId={2}&__rt=fps&__ver=2" -f $($this.OrganizationContext.OrganizationName), $this.ProjectId ,$this.AgentPoolId;
                $this.agentPool = [WebRequestHelper]::InvokeGetWebRequest($agentPoolsURL);
            }                 
            
                $patterns = $this.ControlSettings.Patterns | Where-Object {$_.RegexCode -eq "SecretsInBuild"} | Select-Object -Property RegexList;
                if(($patterns | Measure-Object).Count -gt 0)
                { 
                    $noOfCredFound = 0; 
                    $AgentsWithSecretsInEnv=@()
                    if (([Helpers]::CheckMember($this.agentPool[0],"fps.dataproviders.data") ) -and ($this.agentPool[0].fps.dataProviders.data."ms.vss-build-web.agent-pool-data-provider") -and [Helpers]::CheckMember($this.agentPool[0].fps.dataProviders.data."ms.vss-build-web.agent-pool-data-provider","agents") )  
                    {
                        $Agents = $this.agentpool.fps.dataproviders.data."ms.vss-build-web.agent-pool-data-provider".agents
                        
                        $Agents | ForEach-Object {
                            $RefAgent = "" | Select-Object "AgentName","Capabilities"
                            $RefAgent.AgentName = $_.name                            
                            $EnvVariablesContainingSecret=@()
                            if([Helpers]::CheckMember($_,"userCapabilities"))
                            {
                                $EnvVariable=$_.userCapabilities
                                $refHashTable=@{}
                                $EnvVariable.PSObject.properties | ForEach-Object { $refHashTable[$_.Name] = $_.Value } 
                                $refHashTable.Keys | Where-Object {
                                    for ($i = 0; $i -lt $patterns.RegexList.Count; $i++) 
                                    {
                                        # Using -cmatch as same logic we had applied in build and release controls
                                        if($refHashTable.Item($_) -cmatch $patterns.RegexList[$i])
                                        {
                                            $noOfCredFound += 1
                                            $EnvVariablesContainingSecret += $_                                            
                                            break
                                        }
                                    }
                                }
                            }
                            $RefAgent.Capabilities = $EnvVariablesContainingSecret  
                            $AgentsWithSecretsInEnv += $RefAgent                          
                        }
                                                
                        if($noOfCredFound -eq 0) 
                        {
                            $controlResult.AddMessage([VerificationResult]::Passed, "No secrets found in user-defined capabilities of agents.");
                        }
                        else {
                            $controlResult.AddMessage([VerificationResult]::Failed, "Found secrets in user-defined capabilities of agents.");
                            
                            $count = ($AgentsWithSecretsInEnv | Measure-Object).Count
                            if($count -gt 0 )
                            {
                                #$varList = $EnvVariablesContainingSecret | select -Unique | Sort-object
                               # $stateData.AgentsWithCred += $AgentsWithSecretsInEnv.AgentName
                                $controlResult.AddMessage("`nTotal number of agents that contain secrets in user-defined capabilities: $count")
                                $controlResult.AdditionalInfo += "Total number of agents that contain secrets in user-defined capabilities: "+ $count;
                                $controlResult.AddMessage("`nAgent wise list of user-defined capabilities containing secret: ");
                                $display=($AgentsWithSecretsInEnv | FT AgentName,Capabilities -AutoSize | Out-String -Width 512)
                                $controlResult.AddMessage($display)
                                #$controlResult.AdditionalInfo += "Total number of variable(s) containing secret: " + ($varList | Measure-Object).Count;
                            }                    
                            $controlResult.SetStateData("Agent wise list of user-defined capabilities containing secret: ", $AgentsWithSecretsInEnv );
                        }
                    }            
                    else 
                    { 
                        $controlResult.AddMessage([VerificationResult]::Passed, "There are no agents in the pool.");
                    }                
                    $patterns = $null;
                }            
                else 
                {
                    $controlResult.AddMessage([VerificationResult]::Manual, "Regular expressions for detecting credentials in environment variables for agents are not defined in your organization.");    
                }   
            
                     
        }
        catch 
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch details of user-defined capabilities of agents.");
        }
        #clearing memory space.
        $this.agentPool = $null;
        return $controlResult
    }
}
