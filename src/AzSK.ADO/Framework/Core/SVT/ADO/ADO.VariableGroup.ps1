Set-StrictMode -Version Latest
class VariableGroup: ADOSVTBase
{

    hidden [PSObject] $VarGrp;
    hidden [PSObject] $ProjectId;
    hidden [PSObject] $VarGrpId;
    hidden [string] $checkInheritedPermissionsPerVarGrp = $false
    hidden $pipelinePermission = $null
    hidden [PSObject] $variableGroupIdentities = $null    

    VariableGroup([string] $organizationName, [SVTResource] $svtResource): Base($organizationName,$svtResource)
    {
        $this.ProjectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0];
        $this.VarGrpId = $this.ResourceContext.ResourceDetails.id
        $apiURL = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ProjectId)/_apis/distributedtask/variablegroups/$($this.VarGrpId)?api-version=6.1-preview.2"
        $this.VarGrp = [WebRequestHelper]::InvokeGetWebRequest($apiURL);

        if ([Helpers]::CheckMember($this.ControlSettings, "VariableGroup.CheckForInheritedPermissions") -and $this.ControlSettings.VariableGroup.CheckForInheritedPermissions) {
            $this.checkInheritedPermissionsPerVarGrp = $true
        }
    }

    [ControlItem[]] ApplyServiceFilters([ControlItem[]] $controls)
	{
        $result = $controls;
        # Applying filter to exclude certain controls based on Tag
        if($this.OrganizationContext.OrganizationName -notin [Constants]::OrgsSupportingCMControls)
        {
            if($null -eq $env:OrgsSupportingCM -or $this.OrganizationContext.OrganizationName -ne $env:OrgsSupportingCM){
                $result = $controls | Where-Object { $_.Tags -notcontains "AutomatedFromCloudmine" };
            }
		}
		return $result;
	}

    hidden [ControlResult] CheckPipelineAccess([ControlResult] $controlResult)
    {
        try
        {
            $controlResult.VerificationResult = [VerificationResult]::Failed
            $url = "https://dev.azure.com/{0}/{1}/_apis/pipelines/pipelinePermissions/variablegroup/{2}" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName, $this.ResourceContext.ResourceDetails.Id;
            $variableGroupPipelinePermObj = @([WebRequestHelper]::InvokeGetWebRequest($url));
            
             # When var grp is shared across all pipelines - the below condition will be true.
            if($variableGroupPipelinePermObj.Count -gt 0 -and [Helpers]::CheckMember($variableGroupPipelinePermObj,"allPipelines") -and $variableGroupPipelinePermObj.allPipelines.authorized -eq $true)
            {
                $isSecretFound = $false
                $secretVarList = @();

                # Check if variable group has any secret or linked to KV
                if ($this.VarGrp.Type -eq 'AzureKeyVault')
                {
                    $isSecretFound = $true
                }
                else
                {
                    Get-Member -InputObject $this.VarGrp.variables -MemberType Properties | ForEach-Object {
                        #no need to check if isSecret val is true, as it will always be true if isSecret is present
                        if([Helpers]::CheckMember($this.VarGrp.variables.$($_.Name),"isSecret"))
                        {
                            $isSecretFound = $true
                            $secretVarList += $_.Name
                        }
                    }
                }
                if ($isSecretFound -eq $true)
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Variable group contains secrets accessible to all YAML pipelines.");
                    $controlResult.AdditionalInfoInCSV = "SecretVarsList: $($secretVarList -join '; ')";
                    $controlResult.AdditionalInfo += "SecretVarsList: $($secretVarList -join '; ')";
                    try {
                        $buildPipelineIds = @();
                        if ($variableGroupPipelinePermObj.Count -gt 0 -and $variableGroupPipelinePermObj.pipelines.Count -gt 0) {
                            $buildPipelineIds = $variableGroupPipelinePermObj.pipelines.id
                            $buildDefnURL = "https://{0}.visualstudio.com/{1}/_apis/build/definitions?definitionIds={2}&api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $this.ResourceContext.ResourceGroupName, ($buildPipelineIds -join ",");
                            $buildDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($buildDefnURL);
                            if (([Helpers]::CheckMember($buildDefnsObj,"name"))) {
                                $controlResult.AdditionalInfoInCSV += "; NumYAMLPipelineWithAccess: $($buildDefnsObj.Count)"
                                $controlResult.AdditionalInfoInCSV += "; List: " + ($buildDefnsObj.Name -join ",")
                            }
                        }
                    }
                    catch {
                    }
                    if ($this.ControlFixBackupRequired) {
                        #Data object that will be required to fix the control
                        $controlResult.BackupControlState = $variableGroupPipelinePermObj;
                    }
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "Variable group does not contain secret.");
                    $controlResult.AdditionalInfoInCSV += "NA"
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Variable group is not accessible to all YAML pipelines.");
                $controlResult.AdditionalInfoInCSV += "NA"
            }

        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch authorization details of variable group.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckPipelineAccessAutomatedFix ([ControlResult] $controlResult) 
    {
            # Backup data object is not required in this scenario.
            #$RawDataObjForControlFix = @();
            #$RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject     
            try
            {
                $this.PublishCustomMessage("Note: After changing the pipeline permission, YAML pipelines that need access on variable group needs to be granted permission explicitly.`n", [MessageType]::Warning);
                $RawDataObjForControlFix = @();
                $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject
    
                if (-not $this.UndoFix)
                {
                    $RawDataObjForControlFix.allPipelines.authorized = $false;
                    $RawDataObjForControlFix.allPipelines.authorizedBy = $null;
                    $RawDataObjForControlFix.allPipelines.authorizedOn = $null;
                    $body = $RawDataObjForControlFix | ConvertTo-Json -Depth 10;
                    $uri = "https://dev.azure.com/{0}/{1}/_apis/pipelines/pipelinePermissions/variablegroup/{2}?api-version=5.1-preview.1" -f ($this.OrganizationContext.OrganizationName), $($this.ProjectId), $this.ResourceContext.ResourceDetails.Id;
                    $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($uri)
                    $Result = Invoke-RestMethod -Uri $uri -Method Patch -ContentType "application/json" -Headers $header -Body $body
                
                    $controlResult.AddMessage([VerificationResult]::Fixed,  "Variable group is not accessible to all YAML pipelines.");
                }
                else {
                    $body = $RawDataObjForControlFix | ConvertTo-Json -Depth 10;
                    $uri = "https://dev.azure.com/{0}/{1}/_apis/pipelines/pipelinePermissions/variablegroup/{2}?api-version=5.1-preview.1" -f ($this.OrganizationContext.OrganizationName), $($this.ProjectId), $this.ResourceContext.ResourceDetails.Id;
                    $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($uri)
                    $Result = Invoke-RestMethod -Uri $uri -Method Patch -ContentType "application/json" -Headers $header -Body $body
                
                    $controlResult.AddMessage([VerificationResult]::Fixed,  "Variable group is accessible to all YAML pipelines.");
                }  
            }
            catch{
                $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
                $controlResult.LogException($_)
            }
            
            return $controlResult;
    }

    hidden [ControlResult] CheckInheritedPermissions([ControlResult] $controlResult)
    {
        try
        {
            if ($null -eq $this.variableGroupIdentities) 
            {
                $url = 'https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.variablegroup/roleassignments/resources/{1}%24{2}?api-version=6.1-preview.1' -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId), $($this.VarGrpId);
                $this.variableGroupIdentities = @([WebRequestHelper]::InvokeGetWebRequest($url));
            }
            $inheritedRoles = $this.variableGroupIdentities | Where-Object {$_.access -eq "inherited"}
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

        try
        {
            if ($null -eq $this.variableGroupIdentities) 
            {
                $url = 'https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.variablegroup/roleassignments/resources/{1}%24{2}?api-version=6.1-preview.1' -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId), $($this.VarGrpId);
                $this.variableGroupIdentities = @([WebRequestHelper]::InvokeGetWebRequest($url));
            }
            if($this.variableGroupIdentities.Count -gt 0)
            {
                $roles = @();
                $roles += ($this.variableGroupIdentities | Select-Object -Property @{Name="Name"; Expression = {$_.identity.displayName}}, @{Name="Role"; Expression = {$_.role.displayName}}, @{Name="AccessType"; Expression = {$_.access}});
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
        $controlResult.VerificationResult = [VerificationResult]::Failed

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
                    $variablesWithCreds=@{};
                    $noOfCredFound = 0;
                    $patterns = @($this.ControlSettings.Patterns | where-object {$_.RegexCode -eq "SecretsInVariables"} | Select-Object -Property RegexList);
                    $exclusions = $this.ControlSettings.Build.ExcludeFromSecretsCheck;
                    $exclusions += $this.ControlSettings.Release.ExcludeFromSecretsCheck; 
                    $exclusions = @($exclusions | select-object -unique)
                    if($patterns.Count -gt 0)
                    {
                        #Compare all non-secret variables with regex 
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
                                            $varList += $varName;
                                            #if auto fix is required save the variable value after encrypting it, will be needed during undofix
                                            if($this.ControlFixBackupRequired){
                                                $variablesWithCreds[$varName] = ($varValue  | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString)
                                            }
                                            break
                                            }
                                        }
                                }
                            }
                        }
                        if($noOfCredFound -gt 0)
                        {
                            $varList = @($varList | Select-Object -Unique)
                            if($this.ControlFixBackupRequired){
                                $controlResult.BackupControlState = $variablesWithCreds
                            }
                            $controlResult.AddMessage([VerificationResult]::Failed, "Found secrets in variable group.`nList of variables: ", $varList );
                            $controlResult.SetStateData("List of variable name containing secret: ", $varList);
                            $controlResult.AdditionalInfo += "Count of variable(s) containing secret: " + $varList.Count;
                            $controlResult.AdditionalInfoInCSV += "List of variable name containing secret:" + $varList ;
                        }
                        else
                        {
                            $controlResult.AddMessage([VerificationResult]::Passed, "No credentials found in variable group.");
                        }
                        $patterns = $null;
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Error, "Regular expressions for detecting credentials in variable groups are not defined in your organization.");
                    }
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No variables found in variable group.");
                }
            }
            catch {
                $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the variable group definition.");
                $controlResult.AddMessage($_);
                $controlResult.LogException($_)
            }
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckCredInVarGrpAutomatedFix([ControlResult] $controlResult){
        try{
            $RawDataObjForControlFix = @();
            $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject
            $varList = @();
            if (-not $this.UndoFix) {
                $RawDataObjForControlFix.PSObject.Properties | foreach {
                    #The api does not allow updating individual variables inside a var grp, all variables have to be a part of the body or else they will be removed from the grp.
                    #Hence using the global var grp object to store all variables details inside the post body and updating only the required variable.
                    $this.VarGrp.variables.($_.Name) | Add-Member NoteProperty -name "isSecret" -value $true                    
                    $varList+=$_.Name;
                    
                }
                $controlResult.AddMessage([VerificationResult]::Fixed,  "Following variables have been marked as secret: ");
               
            }
            else {
                $RawDataObjForControlFix.PSObject.Properties | foreach {  
                    #The api does not allow updating individual variables inside a var grp, all variables have to be a part of the body or else they will be removed from the grp.
                    #Hence using the global var grp object to store all variables details inside the post body and updating only the required variable.                  
                    $this.VarGrp.variables.($_.Name).isSecret = $false
                    #We do not get variable value in API response, if we do not set the value, the variable becomes null, thus decrypting the value from backup state
                    $secureVariableValue = $_.Value | ConvertTo-SecureString
                    $this.VarGrp.variables.($_.Name).value = [Helpers]::ConvertToPlainText($secureVariableValue);
                    $varList+=$_.Name;
                }
                $controlResult.AddMessage([VerificationResult]::Fixed,  "Following variables have been removed as secret: ");
            }
            $rmContext = [ContextHelper]::GetCurrentContext();
            $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f "", $rmContext.AccessToken)))
            $apiURL = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ProjectId)/_apis/distributedtask/variablegroups/$($this.VarGrpId)?api-version=6.1-preview.2"
            $body = @($this.VarGrp) | ConvertTo-JSON -depth 99;
            Invoke-RestMethod -Method Put -Uri $apiURL -Body $body  -ContentType "application/json" -Headers @{Authorization = ("Basic {0}" -f $base64AuthInfo) };
            $display = ($varList |  FT -AutoSize | Out-String -Width 512);
            $controlResult.AddMessage("`n$display");

        }   
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckBroaderGroupAccess ([ControlResult] $controlResult) {
    
        try {
            $controlResult.VerificationResult = [VerificationResult]::Failed
            $restrictedBroaderGroups = @{}
            $restrictedBroaderGroupsForVarGrp = $this.ControlSettings.VariableGroup.RestrictedBroaderGroupsForVariableGroup;
            if(@($restrictedBroaderGroupsForVarGrp.psobject.Properties).Count -gt 0){
                $restrictedBroaderGroupsForVarGrp.psobject.properties | foreach { $restrictedBroaderGroups[$_.Name] = $_.Value }

                #Fetch variable group RBAC
                $roleAssignments = @();
                if ($null -eq $this.variableGroupIdentities) 
                {
                    $url = 'https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.variablegroup/roleassignments/resources/{1}%24{2}?api-version=6.1-preview.1' -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId), $($this.VarGrpId);
                    $this.variableGroupIdentities = @([WebRequestHelper]::InvokeGetWebRequest($url));
                }
                if($this.variableGroupIdentities.Count -gt 0)
                {
                    if ($this.checkInheritedPermissionsPerVarGrp -eq $false) {
                        $roleAssignments = @($this.variableGroupIdentities  | where-object { $_.access -ne "inherited" })
                    }
                    $roleAssignments = @($roleAssignments  | Select-Object -Property @{Name="Name"; Expression = {$_.identity.displayName}},@{Name="Id"; Expression = {$_.identity.id}}, @{Name="Role"; Expression = {$_.role.displayName}});
                }

                # Checking whether the broader groups have User/Admin permissions
                $backupDataObject = @($roleAssignments | Where-Object { ($restrictedBroaderGroups.keys -contains $_.Name.split('\')[-1]) -and  ($_.Role -in $restrictedBroaderGroups[$_.Name.split('\')[-1]])})
                $restrictedGroups = @($backupDataObject | Select-Object Name,role)
                
                if ($this.ControlSettings.CheckForBroadGroupMemberCount -and $restrictedGroups.Count -gt 0)
                {
                    $broaderGroupsWithExcessiveMembers = @([ControlHelper]::FilterBroadGroupMembers($restrictedGroups, $true))
                    $restrictedGroups = @($restrictedGroups | Where-Object {$broaderGroupsWithExcessiveMembers -contains $_.Name})
                }

                $restrictedGroupsCount = $restrictedGroups.Count

                # fail the control if restricted group found on variable group
                if ($restrictedGroupsCount -gt 0) {
                    $controlResult.AddMessage([VerificationResult]::Failed, "`nCount of broader groups that have excessive permissions on variable group: $($restrictedGroupsCount)");
                    $controlResult.AddMessage("`nList of groups: ")
                    $controlResult.AddMessage(($restrictedGroups | FT Name,Role -AutoSize | Out-String -Width 512));
                    $controlResult.SetStateData("List of groups: ", $restrictedGroups)
                    $controlResult.AdditionalInfo += "Count of broader groups that have excessive permissions on variable group: $($restrictedGroupsCount)";
                    if ($this.ControlFixBackupRequired) {
                        #Data object that will be required to fix the control
                        $controlResult.BackupControlState = $backupDataObject;
                    }
                    $formatedRestrictedGroups = $restrictedGroups | ForEach-Object { $_.Name + ': ' + $_.Role }
                    $controlResult.AdditionalInfoInCSV = ($formatedRestrictedGroups -join '; ' )
                    $controlResult.AdditionalInfo += "List of groups: ", $($formatedRestrictedGroups -join '; ' )
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No broader groups have excessive permissions on variable group.");
                    $controlResult.AdditionalInfoInCSV += "NA"
                }
                $displayObj = $restrictedBroaderGroups.Keys | Select-Object @{Name = "Broader Group"; Expression = {$_}}, @{Name = "Excessive Permissions"; Expression = {$restrictedBroaderGroups[$_] -join ', '}}
                $controlResult.AddMessage("Note:`nThe following groups are considered 'broad' and should not have excessive permissions: `n$( $displayObj| FT | out-string)");
            }
            else{
                $controlResult.AddMessage([VerificationResult]::Error, "List of restricted broader groups and restricted roles for variable group is not defined in the control settings for your organization policy.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the variable group permissions.");
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
                $RawDataObjForControlFix = @($RawDataObjForControlFix  | Select-Object @{Name="DisplayName"; Expression={$_.Name}}, @{Name="OldRole"; Expression={$_.Role}},@{Name="NewRole"; Expression={$_.NewRole}})
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
                $RawDataObjForControlFix = @($RawDataObjForControlFix  | Select-Object @{Name="DisplayName"; Expression={$_.Name}}, @{Name="OldRole"; Expression={$_.OldRole}},@{Name="NewRole"; Expression={$_.Role}})
            }            
            $body += "]"
            #Put request

            $url = "https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.variablegroup/roleassignments/resources/{1}%24{2}?api-version=6.1-preview.1" -f $($this.OrganizationContext.OrganizationName),$($this.ProjectId),$($this.VarGrpId);          
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
        return $controlResult;
    }

    hidden [ControlResult] CheckBroaderGroupAccessForVarGrpWithSecrets([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed;
        try 
        {            
            
            $restrictedBroaderGroups = @{}
            $restrictedBroaderGroupsForVarGrp = $this.ControlSettings.VariableGroup.RestrictedBroaderGroupsForVariableGroup;
            $restrictedBroaderGroupsForVarGrp.psobject.properties | foreach { $restrictedBroaderGroups[$_.Name] = $_.Value }

            if([Helpers]::CheckMember($this.VarGrp[0],"variables"))
            {
                $secretVarList = @();
                $VGMembers = @(Get-Member -InputObject $this.VarGrp[0].variables -MemberType Properties)
                $patterns = @($this.ControlSettings.Patterns | Where-Object {$_.RegexCode -eq "SecretsInVariables"} | Select-Object -Property RegexList);
                $VGMembers | ForEach-Object {
                    $varName = $_.Name
                    if([Helpers]::CheckMember($this.VarGrp[0].variables.$varName,"value"))
                    {
                        $varValue = $this.VarGrp[0].variables.$varName.value
                        for ($i = 0; $i -lt $patterns.RegexList.Count; $i++)
                        {
                            #Note: We are using '-cmatch' here.
                            #When we compile the regex, we don't specify ignoreCase flag.
                            #If regex is in text form, the match will be case-sensitive.
                            if ($varValue -cmatch $patterns.RegexList[$i]) 
                            {
                                $secretVarList += $varName
                                break
                            }
                        }
                    }
                    elseif (([Helpers]::CheckMember($this.VarGrp[0].variables.$($_.Name),"isSecret"))) {
                        $secretVarList += $varName
                    }
                }

                if ($secretVarList.Count -gt 0)
                {
                    #Fetch variable group RBAC
                    $roleAssignments = @();

                    if ($null -eq $this.variableGroupIdentities) 
                    {
                        $url = 'https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.variablegroup/roleassignments/resources/{1}%24{2}?api-version=6.1-preview.1' -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId), $($this.VarGrpId);
                        $this.variableGroupIdentities = @([WebRequestHelper]::InvokeGetWebRequest($url));
                    } 
                    
                    if($this.variableGroupIdentities.Count -gt 0)
                    {
                        if ($this.checkInheritedPermissionsPerVarGrp -eq $false) {
                            $roleAssignments = @($this.variableGroupIdentities  | where-object { $_.access -ne "inherited" })
                        }
                        $roleAssignments = @($roleAssignments  | Select-Object -Property @{Name="Name"; Expression = {$_.identity.displayName}}, @{Name="Role"; Expression = {$_.role.displayName}}, @{Name="Id"; Expression = {$_.identity.id}});
                    }

                    # Checking whether the broader groups have User/Admin permissions
                    $restrictedGroups = @($roleAssignments | Where-Object { ($restrictedBroaderGroups.keys -contains $_.Name.split('\')[-1]) -and ($_.Role -in $restrictedBroaderGroups[$_.Name.split('\')[-1]])})

                    if ($this.ControlSettings.CheckForBroadGroupMemberCount -and $restrictedGroups.Count -gt 0)
                    {
                        $broaderGroupsWithExcessiveMembers = @([ControlHelper]::FilterBroadGroupMembers($restrictedGroups, $true))
                        $restrictedGroups = @($restrictedGroups | Where-Object {$broaderGroupsWithExcessiveMembers -contains $_.Name})
                    }

                    $restrictedGroupsCount = $restrictedGroups.Count

                    # fail the control if restricted group found on variable group which contains secrets
                    if ($restrictedGroupsCount -gt 0)
                    {
                        $controlResult.AddMessage([VerificationResult]::Failed, "Broader groups have excessive permissions on the variable group.");
                        $controlResult.AddMessage("`nCount of broader groups that have excessive permissions on the variable group:  $($restrictedGroupsCount)")
                        $controlResult.AdditionalInfo += "Count of broader groups that have excessive permissions on the variable group:  $($restrictedGroupsCount)";
                        $groups = $restrictedGroups | ForEach-Object { $_.name + ': ' + $_.role } 
                        $controlResult.AdditionalInfo += "List of broader groups: , $($groups -join ' ; ')"
                        $controlResult.AddMessage("`nList of broader groups: ",$($restrictedGroups | FT | Out-String))
                        $controlResult.AddMessage("`nList of variables with secret: ",$secretVarList)
                        $controlResult.SetStateData("List of broader groups: ", $restrictedGroups)

                        if ($this.ControlFixBackupRequired) {
                            #Data object that will be required to fix the control
                            $controlResult.BackupControlState = $restrictedGroups;
                        }


                        $groups = $restrictedGroups | ForEach-Object { $_.Name + ': ' + $_.Role } 
                        $controlResult.AdditionalInfoInCSV = $($groups -join '; ')+"; SecretVarsList: $($secretVarList -join '; ')";
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed, "No broader groups have excessive permissions on the variable group.");
                        $controlResult.AdditionalInfoInCSV += "NA"
                    }
                    $displayObj = $restrictedBroaderGroups.Keys | Select-Object @{Name = "Broader Group"; Expression = {$_}}, @{Name = "Excessive Permissions"; Expression = {$restrictedBroaderGroups[$_] -join ', '}}
                    $controlResult.AddMessage("`nNote:`nThe following groups are considered 'broad' and should not have excessive permissions: `n$( $displayObj| FT | out-string -Width 512)");
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No secrets found in variable group.");
                    $controlResult.AdditionalInfoInCSV += "NA"
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "No variables found in variable group.");
                $controlResult.AdditionalInfoInCSV += "NA"
            }
            
            
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the variable group permissions.");
            $controlResult.LogException($_)
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckBroaderGroupAccessForVarGrpWithSecretsAutomatedFix ([ControlResult] $controlResult) 
    {
        try 
        {
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
                $RawDataObjForControlFix = @($RawDataObjForControlFix  | Select-Object @{Name="DisplayName"; Expression={$_.Name}}, @{Name="OldRole"; Expression={$_.Role}},@{Name="NewRole"; Expression={$_.NewRole}})
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
                $RawDataObjForControlFix = @($RawDataObjForControlFix  | Select-Object @{Name="DisplayName"; Expression={$_.Name}}, @{Name="OldRole"; Expression={$_.OldRole}},@{Name="NewRole"; Expression={$_.Role}})
            }            
            $body += "]"
            #Put request

            $url = "https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.variablegroup/roleassignments/resources/{1}%24{2}?api-version=6.1-preview.1" -f $($this.OrganizationContext.OrganizationName),$($this.ProjectId),$($this.VarGrpId);          
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
        return $controlResult;
    }

    hidden [ControlResult] CheckBranchControlOnVariableGroup ([ControlResult] $controlResult) {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        $checkObj = $this.GetResourceApprovalCheck()
        try{
            #if resource is not accessible to any YAML pipeline, there is no need to add any branch control, hence passing the control
            if(!$this.CheckIfResourceAccessibleToPipeline()){
                $controlResult.AddMessage([VerificationResult]::Passed, "Variable group is not accessible to any YAML pipelines. Hence, branch control is not required.");
                return $controlResult;
            }
            if(!$checkObj.ApprovalCheckObj){
                $controlResult.AddMessage([VerificationResult]::Failed, "No approvals and checks have been defined for the variable group.");
                $controlResult.AdditionalInfo = "No approvals and checks have been defined for the variable group."
                $controlResult.AdditionalInfoInCsv = "No approvals and checks have been defined for the variable group."
            }
            else{
                #we need to check only for two kinds of approvals and checks: manual approvals and branch controls, hence filtering these two out from the list
                $branchControl = @()
                $approvalControl = @()
                try{
                    $approvalAndChecks = @($checkObj.value | Where-Object {$_.PSObject.Properties.Name -contains "settings"})
                    $branchControl = @($approvalAndChecks.settings | Where-Object {$_.PSObject.Properties.Name -contains "displayName" -and $_.displayName -eq "Branch Control"})
                    $approvalControl = @($approvalAndChecks | Where-Object {$_.PSObject.Properties.Name -contains "type" -and $_.type.name -eq "Approval"})                    
                }
                catch{
                    $branchControl = @()
                }
                #if branch control is not enabled, but manual approvers are added pass this control
                if($branchControl.Count -eq 0){
                    if($approvalControl.Count -gt 0){
                        $controlResult.AddMessage([VerificationResult]::Passed, "Branch control has not been defined for the variable group. However, manual approvals have been added to the variable group.");
                        $approvers = $approvalControl.settings.approvers | Select @{n='Approver name';e={$_.displayName}},@{n='Approver id';e = {$_.uniqueName}}
                        $formattedApproversTable = ($approvers| FT -AutoSize | Out-String -width 512)
                        $controlResult.AddMessage("`nList of approvers : `n$formattedApproversTable");
                        $controlResult.AdditionalInfo += "List of approvers on variable group  $($approvers).";
                    }
                    else{
                        $controlResult.AddMessage([VerificationResult]::Failed, "Branch control has not been defined for the variable group.");
                        $controlResult.AdditionalInfo = "Branch control has not been defined for the variable group."
                    }                    
                }
                else{
                    $branches = ($branchControl.inputs.allowedBranches).Split(",");
                    $branchesWithNoProtectionCheck = @($branchControl.inputs | where-object {$_.ensureProtectionOfBranch -eq $false})
                    if("*" -in $branches){
                        $controlResult.AddMessage([VerificationResult]::Failed, "All branches have been given access to the variable group.");
                        $controlResult.AdditionalInfo = "All branches have been given access to the variable group."
                    }
                    elseif ($branchesWithNoProtectionCheck.Count -gt 0) {
                        #check if branch protection is enabled on all the found branches depending upon the org policy
                        if($this.ControlSettings.VariableGroup.CheckForBranchProtection){
                            $controlResult.AddMessage([VerificationResult]::Failed, "Access to the variable group has not been granted to all branches. However, verification of branch protection has not been enabled for some branches.");
                            $branchesWithNoProtectionCheck = @(($branchesWithNoProtectionCheck.allowedBranches).Split(","));
                            $controlResult.AddMessage("List of branches granted access to the variable group without verification of branch protection: ")
                            $controlResult.AddMessage("$($branchesWithNoProtectionCheck | FT | Out-String)")
                            $branchesWithProtection = @($branches | where {$branchesWithNoProtectionCheck -notcontains $_})
                            if($branchesWithProtection.Count -gt 0){
                                $controlResult.AddMessage("List of branches granted access to the variable group with verification of branch protection: ");
                                $controlResult.AddMessage("$($branchesWithProtection | FT | Out-String)");
                            }
                            $controlResult.AdditionalInfo = "List of branches granted access to the variable group without verification of branch protection: $($branchesWithNoProtectionCheck)"
                        }
                        else{
                            $controlResult.AddMessage([VerificationResult]::Passed, "Access to the variable group has not been granted to all branches.");
                            $controlResult.AddMessage("List of branches granted access to the variable group: ");
                            $controlResult.AddMessage("$($branches | FT | Out-String)");
                        }
                    }
                    else{
                        $controlResult.AddMessage([VerificationResult]::Passed, "Access to the variable group has not been granted to all branches. Verification of branch protection has been enabled for all allowed branches.");
                        $controlResult.AddMessage("List of branches granted access to the variable group: ");
                        $controlResult.AddMessage("$($branches | FT | Out-String)");
                    }
                }
            }
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch variable group details.");
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckBroaderGroupApproversOnVarGrp ([ControlResult] $controlResult) {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        $checkObj = $this.GetResourceApprovalCheck()        
        try{              
            $restrictedGroups = @();
            $restrictedBroaderGroupsForVarGrp = $this.ControlSettings.VariableGroup.RestrictedBroaderGroupsForApprovers;

            if(!$checkObj.ApprovalCheckObj){
                $controlResult.AddMessage([VerificationResult]::Passed, "No approvals and checks have been defined for the VariableGroup.");
                $controlResult.AdditionalInfo = "No approvals and checks have been defined for the VariableGroup."
             }
             else
             {
                $approvalControl = @()
                try{
                    $approvalAndChecks = @($checkObj.ApprovalCheckObj | Where-Object {$_.PSObject.Properties.Name -contains "settings"})
                    $approvalControl = @($approvalAndChecks | Where-Object {$_.PSObject.Properties.Name -contains "type" -and $_.type.name -eq "Approval"})                    
                }
                catch{
                    $approvalControl = @()
                }

                 if($approvalControl.Count -gt 0)
                 {
                    $approvers = $approvalControl.settings.approvers | Select @{n='Approver name';e={$_.displayName}},@{n='Approver id';e = {$_.uniqueName}}
                    $formattedApproversTable = ($approvers| FT -AutoSize | Out-String -width 512)
                    # match all the identities added on variable group with defined restricted list
                     $restrictedGroups = $approvalControl.settings.approvers | Where-Object { $restrictedBroaderGroupsForVarGrp -contains $_.displayName.split('\')[-1] } | select displayName
                     
                    # fail the control if restricted group found on variable group
                    if($restrictedGroups)
                    {
                        $controlResult.AddMessage([VerificationResult]::Failed,"Broader groups have been added as approvers on variable group.");
                        $controlResult.AddMessage("Count of broader groups that have been added as approvers to variable group: ", @($restrictedGroups).Count)
                        $controlResult.AddMessage("List of broader groups that have been added as approvers to variable group: ",$restrictedGroups)
                        $controlResult.SetStateData("Broader groups have been added as approvers to variable group",$restrictedGroups)
                        $controlResult.AdditionalInfo += "Count of broader groups that have been added as approvers to variable group: " + @($restrictedGroups).Count;
                        $controlResult.AdditionalInfo += "List of broader groups added as approvers: "+ @($restrictedGroups)
                    }
                    else{
                        $controlResult.AddMessage([VerificationResult]::Passed,"No broader groups have been added as approvers to variable group.");
                        $controlResult.AddMessage("`nList of approvers : `n$formattedApproversTable");
                        $controlResult.AdditionalInfo += "List of approvers on variable group  $($approvers).";
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed,"No broader groups have been added as approvers to variable group.");
                }   
             }  
             $displayObj = $restrictedBroaderGroupsForVarGrp | Select-Object @{Name = "Broader Group"; Expression = {$_}}
             $controlResult.AddMessage("`nNote:`nThe following groups are considered 'broader' groups which should not be added as approvers: `n$($displayObj | FT | out-string -width 512)`n");                  
             $restrictedGroups = $null;
             $restrictedBroaderGroupsForVarGrp = $null;  
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch variable group details.");
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckTemplateBranchForVarGrp ([ControlResult] $controlResult) {
        try{            
            $checkObj = $this.GetResourceApprovalCheck()
            if(!$checkObj.ApprovalCheckObj){
                $controlResult.AddMessage([VerificationResult]::Passed, "No approvals and checks have been defined for the variable group.");
                $controlResult.AdditionalInfo = "No approvals and checks have been defined for the variable group."
            }
            else{                
                $yamlTemplateControl = @()
                try{
                    $yamlTemplateControl = @($checkObj.ApprovalCheckObj | Where-Object {$_.PSObject.Properties.Name -contains "settings"})
                    $yamlTemplateControl = @($yamlTemplateControl.settings | Where-Object {$_.PSObject.Properties.Name -contains "extendsChecks"})
                }
                catch{
                    $yamlTemplateControl = @()
                }
                if($yamlTemplateControl.Count -gt 0){
                    $yamlChecks = $yamlTemplateControl.extendsChecks
                    $unProtectedBranches = @() #for branches with no branch policy
                    $protectedBranches = @() #for branches with branch policy
                    $unknownBranches = @() #for branches from external sources
                    $yamlChecks | foreach {
                        $yamlCheck = $_
                        #skip for any external source repo objects
                        if($yamlCheck.repositoryType -ne 'git'){
                            $unknownBranches += (@{branch = ($yamlCheck.repositoryRef);repository = ($yamlCheck.repositoryName)})
                            return;
                        }
                        #repository name can be in two formats: "project/repo" OR for current project just "repo"
                        if($yamlCheck.repositoryName -like "*/*"){
                            $project = ($yamlCheck.repositoryName -split "/")[0]
                            $repository = ($yamlCheck.repositoryName -split "/")[1]
                        }
                        else{
                            $project = $this.ResourceContext.ResourceGroupName
                            $repository = $yamlCheck.repositoryName
                        }
                        
                        $branch = $yamlCheck.repositoryRef
                        #policy API accepts only repo ID. Need to extract repo ID beforehand.
                        $url = "https://dev.azure.com/{0}/{1}/_apis/git/repositories/{2}?api-version=6.0" -f $this.OrganizationContext.OrganizationName,$project,$repository
                        $repoId = $null;
                        try{
                            $response = @([WebRequestHelper]::InvokeGetWebRequest($url))
                            $repoId = $response.id
                        }
                        catch{
                            return;
                        }
                        
                        $url = "https://dev.azure.com/{0}/{1}/_apis/git/policy/configurations?repositoryId={2}&refName={3}&api-version=5.0-preview.1" -f $this.OrganizationContext.OrganizationName,$project,$repoId,$branch
                        $policyConfigResponse = @([WebRequestHelper]::InvokeGetWebRequest($url))
                        if([Helpers]::CheckMember($policyConfigResponse[0],"id")){
                            $branchPolicy = @($policyConfigResponse | Where-Object {$_.isEnabled -and $_.isBlocking})
                            #policyConfigResponse also contains repository policies, we need to filter out just branch policies
                            $branchPolicy = @($branchPolicy | Where-Object {[Helpers]::CheckMember($_.settings.scope[0],"refName")})
                            if($branchPolicy.Count -gt 0)
                            {
                                $protectedBranches += (@{branch = $branch;repository = ($project+"/"+$repository)})
                            }
                            else{
                                $unProtectedBranches += (@{branch = $branch;repository = ($project+"/"+$repository)})
                            }
                        }
                        else{
                            $unProtectedBranches += (@{branch = $branch;repository = ($project+"/"+$repository)})
                        }
                    } 
                    #if branches with no branch policy is found, fail the control  
                    if($unProtectedBranches.Count -gt 0){
                        $controlResult.AddMessage([VerificationResult]::Failed, "Required template on the variable group extends from unprotected branches.");
                        $unProtectedBranches =$unProtectedBranches | Select @{l="Repository";e={$_.repository}}, @{l="Branch";e={$_.branch}}
                        $formattedGroupsTable = ($unProtectedBranches | FT -AutoSize | Out-String -width 512)
                        $controlResult.AddMessage("`nList of unprotected branches: ", $formattedGroupsTable)
                        $controlResult.SetStateData("List of unprotected branches: ", $formattedGroupsTable)
                    }
                    #if branches from external sources are found, control needs to be evaluated manually
                    elseif($unknownBranches.Count -gt 0){
                        $controlResult.AddMessage([VerificationResult]::Manual, "Required template on the variable group extends from external sources.");
                        $unknownBranches =$unknownBranches | Select @{l="Repository";e={$_.repository}}, @{l="Branch";e={$_.branch}}
                        $formattedGroupsTable = ($unknownBranches | FT -AutoSize | Out-String -width 512)
                        $controlResult.AddMessage("`nList of branches from external sources: ", $formattedGroupsTable)
                        $controlResult.SetStateData("List of branches from external sources: ", $formattedGroupsTable)
                    }
                    #if all branches are protected, pass the control
                    elseif($protectedBranches.Count -gt 0){
                        $controlResult.AddMessage([VerificationResult]::Passed, "Required template on the variable group extends from protected branches.");
                    }  
                    else{
                        $controlResult.AddMessage([VerificationResult]::Manual, "Branch policies on required template on the variable group could not be determined.");

                    }
                    if($protectedBranches.Count -gt 0){
                        $protectedBranches =$protectedBranches | Select @{l="Repository";e={$_.repository}}, @{l="Branch";e={$_.branch}}
                        $formattedGroupsTable = ($protectedBranches | FT -AutoSize | Out-String -width 512)
                        $controlResult.AddMessage("`nList of protected branches: ", $formattedGroupsTable)
                        $controlResult.SetStateData("List of protected branches: ", $formattedGroupsTable)

                    }                                                      
                }
                else{
                    $controlResult.AddMessage([VerificationResult]::Passed, "No required template has been defined for the variable group.");

                }
            }
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch variable group details.");
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckInactiveVarGrp([ControlResult] $controlResult){
        try{
            $cloudmineResourceData = [ControlHelper]::GetInactiveControlDataFromCloudMine($this.OrganizationContext.OrganizationName,$this.ProjectId,$this.ResourceContext.ResourceDetails.Id,"VariableGroup")
            #if storage does not contain any data for the given org and project
            if($cloudmineResourceData.Count -gt 0 -and -not [Helpers]::CheckMember($cloudmineResourceData[0],"ResourceID") -and $cloudmineResourceData[0] -eq [Constants]::CMErrorMessage){
                $controlResult.AddMessage([VerificationResult]::Manual, "Variable group details are not found in the storage. Inactivity cannot be determined.");
                return $controlResult
            }
            
            if($cloudmineResourceData.Count -gt 0 -and -not([string]::IsNullOrEmpty($cloudmineResourceData.PipelineLastModified))){
                $lastActivity = $cloudmineResourceData.PipelineLastModified
                $inActivityDays = ((Get-Date) - [datetime] $lastActivity).Days
                $inactiveLimit = $this.ControlSettings.VariableGroup.VariableGroupHistoryPeriodInDays
                if ($inActivityDays -gt $inactiveLimit){
                    if($this.CheckIfResourceAccessibleToPipeline()){
                        $controlResult.AddMessage([VerificationResult]::Manual, "Variable group is accessible to one or more pipelines. Inactivity cannot be determined");
                    }
                    else{
                        $controlResult.AddMessage([VerificationResult]::Failed, "Variable group has not been used since $($inActivityDays) days.");                                      
                    }
                }
                else{
                    $controlResult.AddMessage([VerificationResult]::Passed, "Variable group has been used within last $($inactiveLimit) days.");
                }
                $formattedDate = ([datetime] $lastActivity).ToString("d MMM yyyy")
                $controlResult.AddMessage("Variable group was last used on $($formattedDate)");
                $controlResult.AddMessage("The variable group was last used by the pipeline: ")
                $pipelineDetails = $cloudmineResourceData | Select @{l="Pipeline ID"; e={$_.PipelineID}},@{l="Pipeline type";e={$_.PipelineType}}
                $controlResult.AddMessage($pipelineDetails)
                $controlResult.AdditionalInfo+="Variable group was last used on $($formattedDate)"
                $controlResult.AdditionalInfo+="The variable group was last used by the pipeline: $($pipelineDetails)"
            }
            else{            
                if($this.CheckIfResourceAccessibleToPipeline()){
                    $controlResult.AddMessage([VerificationResult]::Manual, "Variable group is accessible to one or more pipelines. Inactivity cannot be determined.");
                }
                else{
                    $controlResult.AddMessage([VerificationResult]::Failed, "Variable group has not been used within last 1500 days.");
                    $controlResult.AddMessage("Details of pipelines using the variable group is not available.")                
                }
            }
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch variable group details.");
            $controlResult.LogException($_);
        }

        return $controlResult;
    }

    hidden [bool] CheckIfResourceAccessibleToPipeline(){
        $isRsrcAccessibleToAnyPipeline = $false;
        if($null -eq $this.pipelinePermission){
            $apiURL = "https://dev.azure.com/{0}/{1}/_apis/pipelines/pipelinePermissions/variablegroup/{2}?api-version=6.1-preview.1" -f $($this.OrganizationContext.OrganizationName),$($this.ProjectId),$($this.VarGrpId)
            $this.pipelinePermission = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
        }
        if([Helpers]::CheckMember($this.pipelinePermission,"allPipelines") -and $this.pipelinePermission.allPipelines.authorized){
            $isRsrcAccessibleToAnyPipeline = $true;
        }
        if([Helpers]::CheckMember($this.pipelinePermission[0],"pipelines") -and $this.pipelinePermission[0].pipelines.Count -gt 0){
            $isRsrcAccessibleToAnyPipeline = $true;
        }
        return $isRsrcAccessibleToAnyPipeline
    }

}
