Set-StrictMode -Version Latest
class VariableGroup: ADOSVTBase
{

    hidden [PSObject] $VarGrp;
    hidden [PSObject] $ProjectId;
    hidden [PSObject] $VarGrpId;

    VariableGroup([string] $organizationName, [SVTResource] $svtResource): Base($organizationName,$svtResource)
    {
        $this.ProjectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0];
        $this.VarGrpId = $this.ResourceContext.ResourceDetails.id
        $apiURL = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ProjectId)/_apis/distributedtask/variablegroups/$($this.VarGrpId)?api-version=6.1-preview.2"
        $this.VarGrp = [WebRequestHelper]::InvokeGetWebRequest($apiURL);

    }
    hidden [ControlResult] CheckPipelineAccess([ControlResult] $controlResult)
    {
        try
        {
            $controlResult.VerificationResult = [VerificationResult]::Failed
            $url = 'https://dev.azure.com/{0}/{1}/_apis/build/authorizedresources?type=variablegroup&id={2}&api-version=6.0-preview.1' -f $($this.OrganizationContext.OrganizationName),$($this.ProjectId) ,$($this.VarGrpId);
            $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($url));
            #

            # When var grp is shared across all pipelines - the below condition will be true.
            if([Helpers]::CheckMember($responseObj[0],"authorized") -and $responseObj[0].authorized -eq $true )
            {
                $isSecretFound = $false

                # Check if variable group has any secret or linked to KV
                if ($this.VarGrp.Type -eq 'AzureKeyVault')
                {
                    $isSecretFound = $true
                }
                else
                {
                    Get-Member -InputObject $this.VarGrp.variables -MemberType Properties | ForEach-Object {
                        if([Helpers]::CheckMember($this.VarGrp.variables.$($_.Name),"isSecret") -and ($this.VarGrp.variables.$($_.Name).isSecret -eq $true))
                        {
                            $isSecretFound = $true
                        }
                    }
                }

                if ($isSecretFound -eq $true)
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Variable group contains secrets accessible to all pipelines.");
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "Variable group does not contain secret.");
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Variable group is not accessible to all pipelines.");
            }

        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch authorization details of variable group.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckInheritedPermissions([ControlResult] $controlResult)
    {
        $url = 'https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.variablegroup/roleassignments/resources/{1}%24{2}?api-version=6.1-preview.1' -f $($this.OrganizationContext.OrganizationName),$($this.ProjectId) ,$($this.VarGrpId);
        try
        {
            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($url);
            $inheritedRoles = $responseObj | Where-Object {$_.access -eq "inherited"}
            if(($inheritedRoles | Measure-Object).Count -gt 0)
            {
                $roles = @();
                $roles += ($inheritedRoles  | Select-Object -Property @{Name="Name"; Expression = {$_.identity.displayName}}, @{Name="Role"; Expression = {$_.role.displayName}});
                $controlResult.AddMessage("Total number of inherited role assignments on variable group: ", ($roles | Measure-Object).Count);
                $controlResult.AddMessage([VerificationResult]::Failed,"Review the list of inherited role assignments on variable group: ", $roles);
                $controlResult.SetStateData("List of inherited role assignments on variable group: ", $roles);
                $controlResult.AdditionalInfo += "Total number of inherited role assignments on variable group: " + ($roles | Measure-Object).Count;
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed,"No inherited role assignments found on variable group.")
            }

        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch permission details of variable group.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }
    hidden [ControlResult] CheckRBACAccess([ControlResult] $controlResult)
    {
        <#
        {
            "ControlID": "ADO_VariableGroup_AuthZ_Grant_Min_RBAC_Access",
            "Description": "All teams/groups must be granted minimum required permissions on variable group.",
            "Id": "VariableGroup110",
            "ControlSeverity": "High",
            "Automated": "Yes",
            "MethodName": "CheckRBACAccess",
            "Rationale": "Granting minimum access by leveraging RBAC feature ensures that users are granted just enough permissions to perform their tasks. This minimizes exposure of the resources in case of user/service account compromise.",
            "Recommendation": "Refer: https://docs.microsoft.com/en-us/azure/devops/pipelines/library/?view=azure-devops#security",
            "Tags": [
              "SDL",
              "TCP",
              "Automated",
              "AuthZ",
              "RBAC"
            ],
            "Enabled": true
          }
        #>

        $url = 'https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.variablegroup/roleassignments/resources/{1}%24{2}?api-version=6.1-preview.1' -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId), $($this.VarGrpId);
        try
        {
            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($url);
            if(($responseObj | Measure-Object).Count -gt 0)
            {
                $roles = @();
                $roles += ($responseObj  | Select-Object -Property @{Name="Name"; Expression = {$_.identity.displayName}}, @{Name="Role"; Expression = {$_.role.displayName}}, @{Name="AccessType"; Expression = {$_.access}});
                $controlResult.AddMessage("Total number of role assignments on variable group: ", ($roles | Measure-Object).Count);
                $controlResult.AddMessage([VerificationResult]::Verify,"Review the list of role assignments on variable group: ", $roles);
                $controlResult.SetStateData("List of role assignments on variable group: ", $roles);
                $controlResult.AdditionalInfo += "Total number of role assignments on variable group: " + ($roles | Measure-Object).Count;
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed,"No role assignments found on variable group.")
            }

        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch RBAC details of variable group.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }
    hidden [ControlResult] CheckCredInVarGrp([ControlResult] $controlResult)
	{
        if([Helpers]::CheckMember([ConfigurationManager]::GetAzSKSettings(),"SecretsScanToolFolder"))
        {
            $ToolFolderPath = [ConfigurationManager]::GetAzSKSettings().SecretsScanToolFolder
            $SecretsScanToolName = [ConfigurationManager]::GetAzSKSettings().SecretsScanToolName
            if((-not [string]::IsNullOrEmpty($ToolFolderPath)) -and (Test-Path $ToolFolderPath) -and (-not [string]::IsNullOrEmpty($SecretsScanToolName)))
            {
                $ToolPath = Get-ChildItem -Path $ToolFolderPath -File -Filter $SecretsScanToolName -Recurse
                if($ToolPath)
                {
                    if($this.VarGrp)
                    {
                        try
                        {
                            $varGrpDefFileName = $($this.ResourceContext.ResourceName).Replace(" ","")
                            $varGrpDefPath = [Constants]::AzSKTempFolderPath + "\VarGrps\"+ $varGrpDefFileName + "\";
                            if(-not (Test-Path -Path $varGrpDefPath))
                            {
                                New-Item -ItemType Directory -Path $varGrpDefPath -Force | Out-Null
                            }

                            $this.VarGrp | ConvertTo-Json -Depth 5 | Out-File "$varGrpDefPath\$varGrpDefFileName.json"
                            $searcherPath = Get-ChildItem -Path $($ToolPath.Directory.FullName) -Include "buildsearchers.xml" -Recurse
                            ."$($Toolpath.FullName)" -I $varGrpDefPath -S "$($searcherPath.FullName)" -f csv -Ve 1 -O "$varGrpDefPath\Scan"

                            $scanResultPath = Get-ChildItem -Path $varGrpDefPath -File -Include "*.csv"

                            if($scanResultPath -and (Test-Path $scanResultPath.FullName))
                            {
                                $credList = Get-Content -Path $scanResultPath.FullName | ConvertFrom-Csv
                                if(($credList | Measure-Object).Count -gt 0)
                                {
                                    $controlResult.AddMessage("No. of credentials found:" + ($credList | Measure-Object).Count )
                                    $controlResult.AddMessage([VerificationResult]::Failed,"Found credentials in variables.")
                                    $controlResult.AdditionalInfo += "No. of credentials found in variables: " + ($credList | Measure-Object).Count;
                                }
                                else {
                                    $controlResult.AddMessage([VerificationResult]::Passed,"No credentials found in variables.")
                                }
                            }
                        }
                        catch
                        {
                            #Publish Exception
                            $this.PublishException($_);
                            $controlResult.LogException($_)
                        }
                        finally
                        {
                            #Clean temp folders
                            Remove-ITem -Path $varGrpDefPath -Recurse
                        }
                    }
                }
            }
        }
        else {
            try {
                if([Helpers]::CheckMember($this.VarGrp[0],"variables"))
                {
                    $varList = @();
                    $noOfCredFound = 0;
                    $patterns = $this.ControlSettings.Patterns | where {$_.RegexCode -eq "SecretsInBuild"} | Select-Object -Property RegexList;
                    $exclusions = $this.ControlSettings.Build.ExcludeFromSecretsCheck;
                    if(($patterns | Measure-Object).Count -gt 0)
                    {
                        Get-Member -InputObject $this.VarGrp[0].variables -MemberType Properties | ForEach-Object {
                            if([Helpers]::CheckMember($this.VarGrp[0].variables.$($_.Name),"value") -and  (-not [Helpers]::CheckMember($this.VarGrp[0].variables.$($_.Name),"isSecret")))
                            {

                                $varName = $_.Name
                                $varValue = $this.VarGrp[0].variables.$varName.value
                                <# helper code to build a list of vars and counts
                                if ([Build]::BuildVarNames.Keys -contains $buildVarName)
                                {
                                        [Build]::BuildVarNames.$buildVarName++
                                }
                                else
                                {
                                    [Build]::BuildVarNames.$buildVarName = 1
                                }
                                #>
                                if ($exclusions -notcontains $varName)
                                {
                                    for ($i = 0; $i -lt $patterns.RegexList.Count; $i++) {
                                        #Note: We are using '-cmatch' here.
                                        #When we compile the regex, we don't specify ignoreCase flag.
                                        #If regex is in text form, the match will be case-sensitive.
                                        if ($varValue -cmatch $patterns.RegexList[$i]) {
                                            $noOfCredFound +=1
                                            $varList += " $varName";
                                            break
                                            }
                                        }
                                }
                            }
                        }
                        if($noOfCredFound -gt 0)
                        {
                            $varList = $varList | select -Unique
                            $controlResult.AddMessage([VerificationResult]::Failed, "Found secrets in variable group. Variables name: $varList" );
                            $controlResult.SetStateData("List of variable name containing secret: ", $varList);
                            $controlResult.AdditionalInfo += "Total number of variable(s) containing secret: " + ($varList | Measure-Object).Count;
                        }
                        else
                        {
                            $controlResult.AddMessage([VerificationResult]::Passed, "No credentials found in variable group.");
                        }
                        $patterns = $null;
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Manual, "Regular expressions for detecting credentials in variable groups are not defined in your organization.");
                    }
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No variables found in variable group.");
                }
            }
            catch {
                $controlResult.AddMessage([VerificationResult]::Manual, "Could not fetch the variable group definition.");
                $controlResult.AddMessage($_);
                $controlResult.LogException($_)
            }
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckBroaderGroupAccess ([ControlResult] $controlResult) {

        try {
            $controlResult.VerificationResult = [VerificationResult]::Failed
            if ($this.ControlSettings -and [Helpers]::CheckMember($this.ControlSettings, "VariableGroup.RestrictedBroaderGroupsForVariableGroup") -and [Helpers]::CheckMember($this.ControlSettings, "VariableGroup.RestrictedRolesForBroaderGroupsInVariableGroup")) {
                $restrictedBroaderGroupsForVarGrp = $this.ControlSettings.VariableGroup.RestrictedBroaderGroupsForVariableGroup;
                $restrictedRolesForBroaderGroupsInvarGrp = $this.ControlSettings.VariableGroup.RestrictedRolesForBroaderGroupsInVariableGroup;

                #Fetch variable group RBAC
                $roleAssignments = @();

                $url = 'https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.variablegroup/roleassignments/resources/{1}%24{2}?api-version=6.1-preview.1' -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId), $($this.VarGrpId);
                $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($url));
                if($responseObj.Count -gt 0)
                {
                    $roleAssignments += ($responseObj  | Select-Object -Property @{Name="Name"; Expression = {$_.identity.displayName}}, @{Name="Role"; Expression = {$_.role.displayName}});
                }

                # Checking whether the broader groups have User/Admin permissions
                $restrictedGroups = @($roleAssignments | Where-Object { ($restrictedBroaderGroupsForVarGrp -contains $_.Name.split('\')[-1]) -and  ($restrictedRolesForBroaderGroupsInvarGrp -contains $_.Role) })
                $restrictedGroupsCount = $restrictedGroups.Count

                # fail the control if restricted group found on variable group
                if ($restrictedGroupsCount -gt 0) {
                    $controlResult.AddMessage([VerificationResult]::Failed, "`nCount of broader groups that have user/administrator access to variable group: $($restrictedGroupsCount)");
                    $controlResult.AddMessage("`nList of groups: ")
                    $controlResult.AddMessage(($restrictedGroups | FT | Out-String));
                    $controlResult.SetStateData("List of groups: ", $restrictedGroups)
                    $controlResult.AdditionalInfo += "Count of broader groups that have user/administrator access to variable group: $($restrictedGroupsCount)";
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "`nBroader groups do not have user/administrator access to variable group.");
                }
                $controlResult.AddMessage("`nNote:`nFollowing groups are considered 'broad' and should not have user/administrator privileges: `n$($restrictedBroaderGroupsForVarGrp | FT | Out-String)");
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Error, "List of restricted broader groups and respective roles for variable group is not defined in the control settings for your organization policy.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the variable group permissions.");
            $controlResult.LogException($_)
        }

        return $controlResult;
    }

}
