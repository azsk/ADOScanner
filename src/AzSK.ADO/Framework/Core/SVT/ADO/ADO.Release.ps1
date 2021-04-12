Set-StrictMode -Version Latest 
class Release: ADOSVTBase
{   

    hidden [PSObject] $ReleaseObj;
    hidden [string] $ProjectId;
    hidden static [PSObject] $ReleaseNamespacesObj= $null;
    hidden static [PSObject] $ReleaseNamespacesPermissionObj= $null;
    hidden static [PSObject] $TaskGroupNamespacesObj= $null;
    hidden static [PSObject] $TaskGroupNamespacePermissionObj= $null;
    hidden static [string] $securityNamespaceId = $null;
    hidden static [PSObject] $ReleaseVarNames = @{};
    hidden [PSObject] $releaseActivityDetail = @{isReleaseActive = $true; latestReleaseTriggerDate = $null; releaseCreationDate = $null; message = $null; isComputed = $false};
    
    Release([string] $organizationName, [SVTResource] $svtResource): Base($organizationName,$svtResource) 
    {
        [system.gc]::Collect();
        # Get release object
        $releaseId =  ($this.ResourceContext.ResourceId -split "release/")[-1]
        $this.ProjectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
        $apiURL = "https://vsrm.dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ProjectId)/_apis/Release/definitions/$($releaseId)?api-version=6.0"
        $this.ReleaseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
        # Get security namespace identifier of current release pipeline.
        if ([string]::IsNullOrEmpty([Release]::SecurityNamespaceId)) {
            $apiURL = "https://dev.azure.com/{0}/_apis/securitynamespaces?api-version=6.0" -f $($this.OrganizationContext.OrganizationName)
            $securityNamespacesObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
            [Release]::SecurityNamespaceId = ($securityNamespacesObj | Where-Object { ($_.Name -eq "ReleaseManagement") -and ($_.actions.name -contains "ViewReleaseDefinition")}).namespaceId
            $TaskGroupSecurityNamespace = ($securityNamespacesObj | Where-Object { ($_.Name -eq "MetaTask")}).namespaceId
            Remove-Variable securityNamespacesObj;
        }

        #Get ACL for all releases
        if ((-not [string]::IsNullOrEmpty([Release]::SecurityNamespaceId)) -and ($null -eq [Release]::ReleaseNamespacesObj)) {
            $apiURL = "https://dev.azure.com/{0}/_apis/accesscontrollists/{1}?includeExtendedInfo=True&recurse=True&api-version=6.0" -f $($this.OrganizationContext.OrganizationName),$([Release]::SecurityNamespaceId)
            [Release]::ReleaseNamespacesObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
        }

        #Get release permission and their bit using security namespace
        if ((-not [string]::IsNullOrEmpty([Release]::SecurityNamespaceId)) -and ($null -eq [Release]::ReleaseNamespacesPermissionObj)) {
            #Get permission and its bit for security namespaces
            $apiUrlNamespace =  "https://dev.azure.com/{0}/_apis/securitynamespaces/{1}?api-version=6.1-preview.1" -f $($this.OrganizationContext.OrganizationName),$([Release]::SecurityNamespaceId)
            [Release]::ReleaseNamespacesPermissionObj = [WebRequestHelper]::InvokeGetWebRequest($apiUrlNamespace);
        }

        # if release activity check function is not computed, then first compute the function to get the correct status of release.
        if($this.releaseActivityDetail.isComputed -eq $false)
        {
            $this.CheckActiveReleases()
        }

        # overiding the '$this.isResourceActive' global variable based on the current status of release.
        if ($this.releaseActivityDetail.isReleaseActive)
        {
            $this.isResourceActive = $true
        }
        else
        {
            $this.isResourceActive = $false
        }

        # calculating the inactivity period in days for the release. If there is no release history, then setting it with negative value.
        # This will ensure inactive period is always computed irrespective of whether inactive control is scanned or not.
        if ($null -ne $this.releaseActivityDetail.latestReleaseTriggerDate)
        {
            $this.InactiveFromDays = ((Get-Date) - $this.releaseActivityDetail.latestReleaseTriggerDate).Days
        }

        if (-not [string]::IsNullOrEmpty([Release]::SecurityNamespaceId) -and ($null -eq [Release]::TaskGroupNamespacesObj) ) {
            #Get acl for taskgroups. Its response contains descriptor of each ado group/user which have permission on the taskgroup
            $apiUrl = "https://dev.azure.com/{0}/_apis/accesscontrollists/{1}?includeExtendedInfo=True&recurse=True&api-version=6.0" -f $($this.OrganizationContext.OrganizationName),$TaskGroupSecurityNamespace
            [Release]::TaskGroupNamespacesObj = [WebRequestHelper]::InvokeGetWebRequest($apiUrl);
        }
        if (-not [string]::IsNullOrEmpty([Release]::SecurityNamespaceId) -and ($null -eq [Release]::TaskGroupNamespacePermissionObj) ) {
            #Get permission and its bit for security namespaces
            $apiUrlNamespace =  "https://dev.azure.com/{0}/_apis/securitynamespaces/{1}?api-version=6.1-preview.1" -f $($this.OrganizationContext.OrganizationName),$TaskGroupSecurityNamespace
            [Release]::TaskGroupNamespacePermissionObj = [WebRequestHelper]::InvokeGetWebRequest($apiUrlNamespace);
        }
    }

    hidden [ControlResult] CheckCredInReleaseVariables([ControlResult] $controlResult)
	{
        if([Helpers]::CheckMember([ConfigurationManager]::GetAzSKSettings(),"SecretsScanToolFolder"))
        {
            $ToolFolderPath =  [ConfigurationManager]::GetAzSKSettings().SecretsScanToolFolder
            $SecretsScanToolName = [ConfigurationManager]::GetAzSKSettings().SecretsScanToolName
            if((-not [string]::IsNullOrEmpty($ToolFolderPath)) -and (Test-Path $ToolFolderPath) -and (-not [string]::IsNullOrEmpty($SecretsScanToolName)))
            {
                $ToolPath = Get-ChildItem -Path $ToolFolderPath -File -Filter $SecretsScanToolName -Recurse 
                if($ToolPath)
                { 
                    if($this.ReleaseObj)
                    {
                        try
                        {
                            $releaseDefFileName = $($this.ResourceContext.ResourceName).Replace(" ","")
                            $releaseDefPath = [Constants]::AzSKTempFolderPath + "\Releases\"+ $releaseDefFileName + "\";
                            if(-not (Test-Path -Path $releaseDefPath))
                            {
                                New-Item -ItemType Directory -Path $releaseDefPath -Force | Out-Null
                            }

                            $this.ReleaseObj | ConvertTo-Json -Depth 5 | Out-File "$releaseDefPath\$releaseDefFileName.json"
                            $searcherPath = Get-ChildItem -Path $($ToolPath.Directory.FullName) -Include "buildsearchers.xml" -Recurse
                            ."$($Toolpath.FullName)" -I $releaseDefPath -S "$($searcherPath.FullName)" -f csv -Ve 1 -O "$releaseDefPath\Scan"    
                            
                            $scanResultPath = Get-ChildItem -Path $releaseDefPath -File -Include "*.csv"
                            
                            if($scanResultPath -and (Test-Path $scanResultPath.FullName))
                            {
                                $credList = Get-Content -Path $scanResultPath.FullName | ConvertFrom-Csv 
                                if(($credList | Measure-Object).Count -gt 0)
                                {
                                    $controlResult.AddMessage("No. of credentials found:" + ($credList | Measure-Object).Count )
                                    $controlResult.AddMessage([VerificationResult]::Failed,"Found credentials in variables")
                                    $controlResult.AdditionalInfo += "No. of credentials found: " + ($credList | Measure-Object).Count;
                                }
                                else {
                                    $controlResult.AddMessage([VerificationResult]::Passed,"No credentials found in variables")
                                }
                            }
                        }
                        catch {
                            #Publish Exception
                            $this.PublishException($_);
                        }
                        finally
                        {
                            #Clean temp folders 
                            Remove-ITem -Path $releaseDefPath -Recurse
                        }
                    }
                }
            }

        }
       else
       {
            try {    
                $patterns = $this.ControlSettings.Patterns | where {$_.RegexCode -eq "SecretsInRelease"} | Select-Object -Property RegexList;
                $exclusions = $this.ControlSettings.Release.ExcludeFromSecretsCheck;
                $varList = @();
                $varGrpList = @();
                $noOfCredFound = 0;  
                $restrictedVarGrp = $false;  

                if(($patterns | Measure-Object).Count -gt 0)
                {     
                    if([Helpers]::CheckMember($this.ReleaseObj,"variables")) 
                    {
                        Get-Member -InputObject $this.ReleaseObj.variables -MemberType Properties | ForEach-Object {
                            if([Helpers]::CheckMember($this.ReleaseObj.variables.$($_.Name),"value") -and  (-not [Helpers]::CheckMember($this.ReleaseObj.variables.$($_.Name),"isSecret")))
                            {
                                $releaseVarName = $_.Name
                                $releaseVarValue = $this.ReleaseObj[0].variables.$releaseVarName.value 
                                <# code to collect stats for var names
                                    if ([Release]::ReleaseVarNames.Keys -contains $releaseVarName)
                                    {
                                            [Release]::ReleaseVarNames.$releaseVarName++
                                    }
                                    else 
                                    {
                                        [Release]::ReleaseVarNames.$releaseVarName = 1
                                    }
                                #>
                                if ($exclusions -notcontains $releaseVarName)
                                {
                                    for ($i = 0; $i -lt $patterns.RegexList.Count; $i++) {
                                        #Note: We are using '-cmatch' here. 
                                        #When we compile the regex, we don't specify ignoreCase flag.
                                        #If regex is in text form, the match will be case-sensitive.
                                        if ($releaseVarValue -cmatch $patterns.RegexList[$i]) { 
                                            $noOfCredFound +=1
                                            $varList += "$releaseVarName";   
                                            break;  
                                        }
                                    }
                                }
                            } 
                        }
                    }

                    if([Helpers]::CheckMember($this.ReleaseObj[0],"variableGroups") -and (($this.ReleaseObj[0].variableGroups) | Measure-Object).Count -gt 0) 
                    {
                        $varGrps = @();
                        $varGrps += $this.ReleaseObj[0].variableGroups
                        $envCount = ($this.ReleaseObj[0].environments).Count

                        if ($envCount -gt 0) 
                        {
                            # Each release pipeline has atleast 1 env.
                            for($i=0; $i -lt $envCount; $i++)
                            {
                                if((($this.ReleaseObj[0].environments[$i].variableGroups) | Measure-Object).Count -gt 0)
                                {
                                    $varGrps += $this.ReleaseObj[0].environments[$i].variableGroups
                                }
                            }

                            $varGrpObj = @();
                            $varGrps | ForEach-Object {
                                try
                                {
                                    $varGrpURL = ("https://dev.azure.com/{0}/{1}/_apis/distributedtask/variablegroups/{2}?api-version=6.1-preview.2") -f $($this.OrganizationContext.OrganizationName), $this.ProjectId, $_;
                                    $varGrpObj += [WebRequestHelper]::InvokeGetWebRequest($varGrpURL);
                                }
                                catch
                                {
                                    #eat exception if api failure occurs
                                }
                            }

                            $varGrpObj| ForEach-Object {
                            $varGrp = $_
                            if([Helpers]::CheckMember($_ ,"variables")){
                                Get-Member -InputObject $_.variables -MemberType Properties | ForEach-Object {

                                    if([Helpers]::CheckMember($varGrp.variables.$($_.Name) ,"value") -and  (-not [Helpers]::CheckMember($varGrp.variables.$($_.Name) ,"isSecret")))
                                    {
                                        $varName = $_.Name
                                        $varValue = $varGrp.variables.$($_.Name).value 
                                        if ($exclusions -notcontains $varName)
                                        {
                                            for ($i = 0; $i -lt $patterns.RegexList.Count; $i++) {
                                                #Note: We are using '-cmatch' here. 
                                                #When we compile the regex, we don't specify ignoreCase flag.
                                                #If regex is in text form, the match will be case-sensitive.
                                                if ($varValue -cmatch $patterns.RegexList[$i]) { 
                                                    $noOfCredFound +=1
                                                    $varGrpList += "[$($varGrp.Name)]:$varName";   
                                                    break  
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                else{
                                    $restrictedVarGrp = $true;  
                                }
                            }
                        }
                    }
                    if($restrictedVarGrp -eq $true)
                    {
                        $controlResult.AddMessage([VerificationResult]::Manual, "Could not evaluate release definition as one or more variable group has restricted access.");
                    }
                    elseif($noOfCredFound -eq 0) 
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed, "No secrets found in release definition.");
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Failed, "Found secrets in release definition.");
                        $stateData = @{
                            VariableList = @();
                            VariableGroupList = @();
                        };
                        if(($varList | Measure-Object).Count -gt 0 )
                        {
                            $varList = $varList | select -Unique | Sort-object
                            $stateData.VariableList += $varList
                            $controlResult.AddMessage("`nTotal number of variable(s) containing secret: ", ($varList | Measure-Object).Count);
                            $controlResult.AddMessage("`nList of variable(s) containing secret: ", $varList);
                            $controlResult.AdditionalInfo += "Total number of variable(s) containing secret: " + ($varList | Measure-Object).Count;
                        }
                        if(($varGrpList | Measure-Object).Count -gt 0 )
                        {
                            $varGrpList = $varGrpList | select -Unique | Sort-object
                            $stateData.VariableGroupList += $varGrpList
                            $controlResult.AddMessage("`nTotal number of variable(s) containing secret in variable group(s): ", ($varGrpList | Measure-Object).Count);
                            $controlResult.AddMessage("`nList of variable(s) containing secret in variable group(s): ", $varGrpList);
                            $controlResult.AdditionalInfo += "Total number of variable(s) containing secret in variable group(s): " + ($varGrpList | Measure-Object).Count;
                        }
                        $controlResult.SetStateData("List of variable and variable group containing secret: ", $stateData );
                    }
                    $patterns = $null;
                }
                else 
                {
                    $controlResult.AddMessage([VerificationResult]::Manual, "Regular expressions for detecting credentials in pipeline variables are not defined in your organization.");    
                }
            }
            catch {
                $controlResult.AddMessage([VerificationResult]::Manual, "Could not evaluate release definition.");
                $controlResult.AddMessage($_);
            }    

         }
     
        return $controlResult;
    }

    hidden [ControlResult] CheckForInactiveReleases([ControlResult] $controlResult)
    {        
        try
        {
            if ($this.releaseActivityDetail.message -eq 'Could not fetch release details.')
            {
                $controlResult.AddMessage([VerificationResult]::Error, $this.releaseActivityDetail.message);
            }
            elseif ($this.releaseActivityDetail.isReleaseActive)
            {
                $controlResult.AddMessage([VerificationResult]::Passed, $this.releaseActivityDetail.message);
            }
            else
            {
                if ($null -ne $this.releaseActivityDetail.releaseCreationDate)
                {
                    $inactiveLimit = $this.ControlSettings.Release.ReleaseHistoryPeriodInDays
                    if ((((Get-Date) - $this.releaseActivityDetail.releaseCreationDate).Days) -lt $inactiveLimit)
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed, "Release was created within last $inactiveLimit days but never triggered.");
                    }
                    else 
                    {
                        $controlResult.AddMessage([VerificationResult]::Failed, $this.releaseActivityDetail.message);
                    }
                    $controlResult.AddMessage("The release pipeline was created on: $($this.releaseActivityDetail.releaseCreationDate)");
                    $controlResult.AdditionalInfo += "The release pipeline was created on: " + $this.releaseActivityDetail.releaseCreationDate;
                }
                else 
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, $this.releaseActivityDetail.message);
                }
            }

            if ($null -ne $this.releaseActivityDetail.latestReleaseTriggerDate)
            {
                $controlResult.AddMessage("Last release date of pipeline: $($this.releaseActivityDetail.latestReleaseTriggerDate)");
                $controlResult.AdditionalInfo += "Last release date of pipeline: " + $this.releaseActivityDetail.latestReleaseTriggerDate;
                $releaseInactivePeriod = ((Get-Date) - $this.releaseActivityDetail.latestReleaseTriggerDate).Days
                $controlResult.AddMessage("The release was inactive from last $($releaseInactivePeriod) days.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch release details.");
        }

        # below code provide the details of build artifacts associated with release pipeline
        if ($this.ReleaseObj)
        {
            if([Helpers]::CheckMember($this.ReleaseObj[0], "artifacts.definitionReference.definition"))
            {
                #$associatedBuildArtifacts = $this.ReleaseObj[0].artifacts | where-object {$_.type -eq "Build"}
                $allArtifacts = $this.ReleaseObj[0].artifacts | Select-Object @{Label="Type"; Expression={$_.type}},  @{Label="Id"; Expression={$_.definitionReference.definition.id}}, @{Label="Name"; Expression={$_.definitionReference.definition.name}}
                $buildArtifacts = $allArtifacts | where-object {$_.Type -eq "Build"}
                $otherArtifacts = $allArtifacts | where-object {$_.Type -ne "Build"}
                if(($null -ne $buildArtifacts) -and ($buildArtifacts | Measure-Object).Count -gt 0)
                {
                    $controlResult.AddMessage("Build artifacts associated with release pipeline: ", $buildArtifacts);
                    $controlResult.AdditionalInfo += "Build artifacts associated with release pipeline: " + [JsonHelper]::ConvertToJsonCustomCompressed($buildArtifacts);
                }
                if(($null -ne $otherArtifacts) -and ($otherArtifacts | Measure-Object).Count -gt 0)
                {
                    $controlResult.AddMessage("Other artifacts associated with release pipeline: ", $otherArtifacts);
                    $controlResult.AdditionalInfo += "Other artifacts associated with release pipeline: " + [JsonHelper]::ConvertToJsonCustomCompressed($otherArtifacts);
                }
            }
        }

        return $controlResult
    }

    hidden [ControlResult] CheckInheritedPermissions([ControlResult] $controlResult)
    {
        if($null -ne [Release]::ReleaseNamespacesObj -and [Helpers]::CheckMember([Release]::ReleaseNamespacesObj,"token"))
        {
            $resource = $this.projectid+ "/" + $this.ReleaseObj.id

            # Filter namespaceobj for current release
            $obj = [Release]::ReleaseNamespacesObj | where-object {$_.token -eq $resource}  
    
            # If current release object is not found, get project level obj. (Seperate release obj is not available if project level permissions are being used on pipeline)
            if(($obj | Measure-Object).Count -eq 0)
            {
                $obj = [Release]::ReleaseNamespacesObj | where-object {$_.token -eq $this.projectid}  
            }

            if((($obj | Measure-Object).Count -gt 0) -and $obj.inheritPermissions -eq $false)
            {
                $controlResult.AddMessage([VerificationResult]::Passed,"Inherited permissions are disabled on release pipeline.");
            }
            else 
            {
                $controlResult.AddMessage([VerificationResult]::Failed,"Inherited permissions are enabled on release pipeline.");
            }
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Manual,"Unable to fetch release pipeline details. $($_). Please verify from portal that permission inheritance is turned OFF.");
        }
        return $controlResult
    }

    hidden [ControlResult] CheckPreDeploymentApproval ([ControlResult] $controlResult)
    {
        $releaseStages = $this.ReleaseObj.environments;# | Where-Object { $this.ControlSettings.Release.RequirePreDeployApprovals -contains $_.name.Trim()}
        if($releaseStages)
        {
            $nonComplaintStages = $releaseStages | ForEach-Object { 
                $releaseStage = $_
                if([Helpers]::CheckMember($releaseStage,"preDeployApprovals.approvals.isAutomated") -and $releaseStage.preDeployApprovals.approvals.isAutomated -eq $true) 
                {
                    return $($releaseStage | Select-Object id,name, @{Name = "Owner"; Expression = {$_.owner.displayName}}) 
                }
            }

            if(($nonComplaintStages | Measure-Object).Count -gt 0)
            {
                $controlResult.AddMessage([VerificationResult]::Failed,"Pre-deployment approvals is not enabled for following release stages in [$($this.ReleaseObj.name)] pipeline.", $nonComplaintStages);
            }
            else 
            {
                $complaintStages = $releaseStages | ForEach-Object {
                    $releaseStage = $_
                    return  $($releaseStage | Select-Object id,name, @{Name = "Owner"; Expression = {$_.owner.displayName}})
                }
                $controlResult.AddMessage([VerificationResult]::Passed,"Pre-deployment approvals is enabled for following release stages.", $complaintStages);
                $complaintStages = $null;
            }
            $nonComplaintStages =$null;
        }
        else
        {
            $otherStages = $this.ReleaseObj.environments | ForEach-Object {
                $releaseStage = $_
                if([Helpers]::CheckMember($releaseStage,"preDeployApprovals.approvals.isAutomated") -and $releaseStage.preDeployApprovals.approvals.isAutomated -ne $true) 
                {
                    return $($releaseStage | Select-Object id,name, @{Name = "Owner"; Expression = {$_.owner.displayName}}) 
                }
            }
            
            if ($otherStages) {
                $controlResult.AddMessage([VerificationResult]::Verify,"No release stage found matching to $($this.ControlSettings.Release.RequirePreDeployApprovals -join ", ") in [$($this.ReleaseObj.name)] pipeline.  Verify that pre-deployment approval is enabled for below found environments.");
                $controlResult.AddMessage($otherStages)
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed,"No release stage found matching to $($this.ControlSettings.Release.RequirePreDeployApprovals -join ", ") in [$($this.ReleaseObj.name)] pipeline.  Found pre-deployment approval is enabled for present environments.");
            }
            $otherStages =$null;
        }
        $releaseStages = $null;
        return $controlResult
    }

    hidden [ControlResult] CheckPreDeploymentApprovers ([ControlResult] $controlResult)
    {
        $releaseStages = $this.ReleaseObj.environments | Where-Object { $this.ControlSettings.Release.RequirePreDeployApprovals -contains $_.name.Trim()}
        if($releaseStages)
        {
            $approversList = $releaseStages | ForEach-Object { 
                $releaseStage = $_
                if([Helpers]::CheckMember($releaseStage,"preDeployApprovals.approvals.isAutomated") -and $($releaseStage.preDeployApprovals.approvals.isAutomated -eq $false))
                {
                    if([Helpers]::CheckMember($releaseStage,"preDeployApprovals.approvals.approver"))
                    {
                        return @{ ReleaseStageName= $releaseStage.Name; Approvers = $releaseStage.preDeployApprovals.approvals.approver }
                    }
                }
            }
            if(($approversList | Measure-Object).Count -eq 0)
            {
                $controlResult.AddMessage([VerificationResult]::Failed,"No approvers found. Please ensure that pre-deployment approval is enabled for production release stages");
            }
            else
            {
                $stateData = @();
                $stateData += $approversList;
                $controlResult.AddMessage([VerificationResult]::Verify,"Validate users/groups added as approver within release pipeline.",$stateData);
                $controlResult.SetStateData("List of approvers for each release stage: ", $stateData);
            }
            $approversList = $null;
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,"No release stage found matching to $($this.ControlSettings.Release.RequirePreDeployApprovals -join ", ") in [$($this.ReleaseObj.name)] pipeline.");
        }
        $releaseStages = $null;
        return $controlResult
    }

    hidden [ControlResult] CheckRBACAccess([ControlResult] $controlResult)
    {
        $exemptedUserIdentities = $this.ReleaseObj.createdBy.id
        $exemptedUserIdentities += $this.ControlSettings.Release.ExemptedUserIdentities 

        $resource = $this.projectid+ "/" + $this.ReleaseObj.id

        # Filter namespaceobj for current release
        $obj = [Release]::ReleaseNamespacesObj | where-object {$_.token -eq $resource}  

        # If current release object is not found, get project level obj. (Seperate release obj is not available if project level permissions are being used on pipeline)
        if(($obj | Measure-Object).Count -eq 0)
        {
            $obj = [Release]::ReleaseNamespacesObj | where-object {$_.token -eq $this.projectid}  
        }

        if(($obj | Measure-Object).Count -gt 0)
        {
            $properties = $obj.acesDictionary | Get-Member -MemberType Properties
            #$permissionsInBit =0
            $editPerms= @();
            $accessList =@();

            try
            {
                #Use descriptors from acl to make identities call, using each descriptor see permissions mapped to Contributors
                $properties | ForEach-Object{
                    $AllowedPermissionsInBit = 0 #Explicitly allowed permissions
                    $InheritedAllowedPermissionsInBit = 0 #Inherited 

                    $apiUrlIdentity = "https://vssps.dev.azure.com/{0}/_apis/identities?descriptors={1}&api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $($obj.acesDictionary.$($_.Name).descriptor)
                    $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiUrlIdentity);

                    if([Helpers]::CheckMember($responseObj,"customDisplayName")) 
                    {
                        $displayName = $responseObj.customDisplayName  #For User isentity type
                    }
                    else{
                        $displayName = $responseObj.providerDisplayName
                    }

                    if($responseObj.providerDisplayName -notmatch  $exemptedUserIdentities)
                    {
                        $AllowedPermissionsInBit = $obj.acesDictionary.$($_.Name).allow
                        if([Helpers]::CheckMember($obj.acesDictionary.$($_.Name).extendedInfo,"inheritedAllow")) 
                        {
                            $InheritedAllowedPermissionsInBit = $obj.acesDictionary.$($_.Name).extendedInfo.inheritedAllow
                        }

                        $permissions = [Helpers]::ResolveAllPermissions($AllowedPermissionsInBit ,$InheritedAllowedPermissionsInBit, [Release]::ReleaseNamespacesPermissionObj.actions)
                        if(($permissions | Measure-Object).Count -ne 0)
                        {
                            $accessList += New-Object -TypeName psobject -Property @{IdentityName= $displayName ; IdentityType= $responseObj.properties.SchemaClassName.'$value'; Permissions = $permissions}
                        }
                    }
                }

                if(($accessList | Measure-Object).Count -ne 0)
                {
                    $accessList = $accessList | sort-object -Property IdentityName, IdentityType
                    $controlResult.AddMessage("Total number of identities that have access to release pipeline: ", ($accessList | Measure-Object).Count);
                    $controlResult.AddMessage([VerificationResult]::Verify,"Validate that the following identities have been provided with minimum RBAC access to [$($this.ResourceContext.ResourceName)] pipeline.", $accessList);
                    $controlResult.SetStateData("Release pipeline access list: ", $accessList);
                    $controlResult.AdditionalInfo += "Total number of identities that have access to release pipeline: " + ($accessList | Measure-Object).Count;
                    $controlResult.AdditionalInfo += "Total number of user identities that have access to release pipeline: " + (($accessList | Where-Object {$_.IdentityType -eq 'user'}) | Measure-Object).Count;
                    $controlResult.AdditionalInfo += "Total number of group identities that have access to release pipeline: " + (($accessList | Where-Object {$_.IdentityType -eq 'group'}) | Measure-Object).Count;
  
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,"No identities have been explicitly provided with RBAC access to [$($this.ResourceContext.ResourceName)] other than release pipeline owner and default groups");
                    $controlResult.AddMessage("Total number of exempted user identities:",($exemptedUserIdentities | Measure-Object).Count);
                    $controlResult.AddMessage("List of exempted user identities:",$exemptedUserIdentities)
                    $controlResult.AdditionalInfo += "Total number of exempted user identities: " + ($exemptedUserIdentities | Measure-Object).Count;
                }   
                
            }
            catch
            {
                $controlResult.AddMessage([VerificationResult]::Manual,"Could not fetch RBAC details of the pipeline. $($_) Please verify from portal all teams/groups are granted minimum required permissions on build definition.");
            }
        }
        else {
            $controlResult.AddMessage([VerificationResult]::Manual,"Could not fetch RBAC details of the pipeline.");
        }

#to here



        return $controlResult
    }

    hidden [ControlResult] CheckExternalSources([ControlResult] $controlResult)
    {
        if(($this.ReleaseObj | Measure-Object).Count -gt 0)
        {
            if( [Helpers]::CheckMember($this.ReleaseObj[0],"artifacts") -and ($this.ReleaseObj[0].artifacts | Measure-Object).Count -gt 0){
               # $sourcetypes = @();
                $sourcetypes = $this.ReleaseObj[0].artifacts;
                $nonadoresource = $sourcetypes | Where-Object { $_.type -ne 'Git'} ;
               
               if( ($nonadoresource | Measure-Object).Count -gt 0){
                   $nonadoresource = $nonadoresource | Select-Object -Property @{Name="alias"; Expression = {$_.alias}},@{Name="Type"; Expression = {$_.type}}
                   $stateData = @();
                   $stateData += $nonadoresource;
                   $controlResult.AddMessage([VerificationResult]::Verify,"Pipeline contains artifacts from below external sources.", $stateData);    
                   $controlResult.SetStateData("Pipeline contains artifacts from below external sources.", $stateData);  
                   $controlResult.AdditionalInfo += "Pipeline contains artifacts from these external sources: " + [JsonHelper]::ConvertToJsonCustomCompressed($stateData);
               }
               else {
                $controlResult.AddMessage([VerificationResult]::Passed,"Pipeline does not contain artifacts from external sources");   
               }
               $sourcetypes = $null;
               $nonadoresource = $null;
           }
           else {
            $controlResult.AddMessage([VerificationResult]::Passed,"Pipeline does not contain any source repositories");   
           } 
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckSettableAtReleaseTime([ControlResult] $controlResult)
	{
      try { 
        
        if([Helpers]::CheckMember($this.ReleaseObj[0],"variables")) 
        {
           $setablevar =@();
           $nonsetablevar =@();
          
           Get-Member -InputObject $this.ReleaseObj[0].variables -MemberType Properties | ForEach-Object {
            if([Helpers]::CheckMember($this.ReleaseObj[0].variables.$($_.Name),"allowOverride") )
            {
                $setablevar +=  $_.Name;
            }
            else {
                $nonsetablevar +=$_.Name;  
            }
           } 
           if(($setablevar | Measure-Object).Count -gt 0){
                $controlResult.AddMessage("Total number of variables that are settable at release time: ", ($setablevar | Measure-Object).Count);
                $controlResult.AddMessage([VerificationResult]::Verify,"The below variables are settable at release time: ",$setablevar);
                $controlResult.AdditionalInfo += "Total number of variables that are settable at release time: " + ($setablevar | Measure-Object).Count;
                $controlResult.SetStateData("Variables settable at release time: ", $setablevar);
                if ($nonsetablevar) {
                    $controlResult.AddMessage("The below variables are not settable at release time: ",$nonsetablevar);      
                } 
           }
           else 
           {
                $controlResult.AddMessage([VerificationResult]::Passed, "No variables were found in the release pipeline that are settable at release time.");   
           }
                 
        }
        else {
            $controlResult.AddMessage([VerificationResult]::Passed,"No variables were found in the release pipeline");   
        }
       }  
       catch {
           $controlResult.AddMessage([VerificationResult]::Manual,"Could not fetch release pipeline variables.");   
       }
     return $controlResult;
    }

    hidden [ControlResult] CheckSettableAtReleaseTimeForURL([ControlResult] $controlResult) 
    {
        try 
        { 
            if ([Helpers]::CheckMember($this.ReleaseObj[0], "variables")) 
            {
                $settableURLVars = @();
                $count = 0;
                $patterns = $this.ControlSettings.Patterns | where {$_.RegexCode -eq "URLs"} | Select-Object -Property RegexList;

                if(($patterns | Measure-Object).Count -gt 0){                
                    Get-Member -InputObject $this.ReleaseObj[0].variables -MemberType Properties | ForEach-Object {
                        if ([Helpers]::CheckMember($this.ReleaseObj[0].variables.$($_.Name), "allowOverride") )
                        {
                            $varName = $_.Name;
                            $varValue = $this.ReleaseObj[0].variables.$($varName).value;
                            for ($i = 0; $i -lt $patterns.RegexList.Count; $i++) {
                                if ($varValue -match $patterns.RegexList[$i]) { 
                                    $count +=1
                                    $settableURLVars += @( [PSCustomObject] @{ Name = $varName; Value = $varValue } )  
                                    break  
                                }
                            }
                        }
                    } 
                    if ($count -gt 0) 
                    {
                        $controlResult.AddMessage("Total number of variables that are settable at release time and contain URL value: ", ($settableURLVars | Measure-Object).Count);
                        $controlResult.AddMessage([VerificationResult]::Failed, "Found variables that are settable at release time and contain URL value: ", $settableURLVars);
                        $controlResult.AdditionalInfo += "Total number of variables that are settable at release time and contain URL value: " + ($settableURLVars | Measure-Object).Count;
                        $controlResult.SetStateData("List of variables settable at release time and containing URL value: ", $settableURLVars);
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Passed, "No variables were found in the release pipeline that are settable at release time and contain URL value.");   
                    }
                }
                else 
                {
                    $controlResult.AddMessage([VerificationResult]::Manual, "Regular expressions for detecting URLs in pipeline variables are not defined in your organization.");    
                }
            }
            else 
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "No variables were found in the release pipeline.");   
            }
        }  
        catch 
        {
            $controlResult.AddMessage([VerificationResult]::Manual, "Could not fetch variables of the release pipeline.");   
        }
        return $controlResult;
    }
    hidden [ControlResult] CheckTaskGroupEditPermission([ControlResult] $controlResult)
    {
        $taskGroups = @();
        $projectName = $this.ResourceContext.ResourceGroupName

        #fetch all envs of pipeline.
        $releaseEnv = $this.ReleaseObj[0].environments

        #filter task groups in each such env.
        $releaseEnv | ForEach-Object {
            #Task groups have type 'metaTask' whereas individual tasks have type 'task'
            $_.deployPhases[0].workflowTasks | ForEach-Object { 
                if(([Helpers]::CheckMember($_ ,"definitiontype")) -and ($_.definitiontype -eq 'metaTask'))
                {
                    $taskGroups += $_
                }              
            }
        } 
        #Filtering unique task groups used in release pipeline.
        $taskGroups = $taskGroups | Sort-Object -Property taskId -Unique

        $editableTaskGroups = @();
        
        if(($taskGroups | Measure-Object).Count -gt 0)
        {   
            try
            {
                $taskGroups | ForEach-Object {
                    $taskGrpId = $_.taskId
                    $permissionsInBit = 0

                    #Get acl for your taskgroup
                    $resource = $this.projectid  + "/" + $taskGrpId
                    $obj = [Release]::TaskGroupNamespacesObj | where-object {$_.token -eq $resource}  
                    $properties = $obj.acesDictionary | Get-Member -MemberType Properties

                    #Use descriptors from acl to make identities call, using each descriptor see permissions mapped to Contributors
                    $properties | ForEach-Object{
                        $apiUrlIdentity = "https://vssps.dev.azure.com/{0}/_apis/identities?descriptors={1}&api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $($obj.acesDictionary.$($_.Name).descriptor)
                        $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiUrlIdentity);
                        if ($responseObj.providerDisplayName -eq "[$($projectName)]\Contributors")
                        {
                            $permissionsInBit = $obj.acesDictionary.$($_.Name).extendedInfo.effectiveAllow
                        }
                    }

                    # ResolvePermissions method returns object if 'Edit task group' is allowed
                    $obj = [Helpers]::ResolvePermissions($permissionsInBit, [Release]::TaskGroupNamespacePermissionObj.actions, 'Edit task group')
                    if (($obj | Measure-Object).Count -gt 0){
                        $editableTaskGroups += $_.name
                    }
                }

                if(($editableTaskGroups | Measure-Object).Count -gt 0)
                {
                    $controlResult.AddMessage("Total number of task groups on which contributors have edit permissions in release definition: ", ($editableTaskGroups | Measure-Object).Count);
                    $controlResult.AdditionalInfo += "Total number of task groups on which contributors have edit permissions in release definition: " + ($editableTaskGroups | Measure-Object).Count;
                    $controlResult.AddMessage([VerificationResult]::Failed,"Contributors have edit permissions on the below task groups used in release definition: ", $editableTaskGroups);
                    $controlResult.SetStateData("List of task groups used in release definition that contributors can edit: ", $editableTaskGroups); 
                }
                else 
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,"Contributors do not have edit permissions on any task groups used in release definition.");    
                }
            }
            catch
            {
                $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch the RBAC details of task groups used in the pipeline.");
            }

        }
        else 
        {
            $controlResult.AddMessage([VerificationResult]::Passed,"No task groups found in release definition.");
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckVariableGroupEditPermission([ControlResult] $controlResult)
    {
        
        $varGrps = @();
        $projectName = $this.ResourceContext.ResourceGroupName
        $editableVarGrps = @();

        #add var groups scoped at release scope.
        if((($this.ReleaseObj[0].variableGroups) | Measure-Object).Count -gt 0)
        {
            $varGrps += $this.ReleaseObj[0].variableGroups
        }

        # Each release pipeline has atleast 1 env.
        $envCount = ($this.ReleaseObj[0].environments).Count

        for($i=0; $i -lt $envCount; $i++)
        {
            if((($this.ReleaseObj[0].environments[$i].variableGroups) | Measure-Object).Count -gt 0)
            {
                $varGrps += $this.ReleaseObj[0].environments[$i].variableGroups
            }
        }
        
        if(($varGrps | Measure-Object).Count -gt 0)
        {
            try
            {   
                $varGrps | ForEach-Object{
                    $url = 'https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.variablegroup/roleassignments/resources/{1}%24{2}?api-version=6.1-preview.1' -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId), $($_);
                    $responseObj = [WebRequestHelper]::InvokeGetWebRequest($url);
                    if(($responseObj | Measure-Object).Count -gt 0)
                    {
                        $contributorsObj = $responseObj | Where-Object {$_.identity.uniqueName -eq "[$projectName]\Contributors"}
                        if((-not [string]::IsNullOrEmpty($contributorsObj)) -and ($contributorsObj.role.name -ne 'Reader')){
                            
                            #Release object doesn't capture variable group name. We need to explicitly look up for its name via a separate web request.
                            $varGrpURL = ("https://dev.azure.com/{0}/{1}/_apis/distributedtask/variablegroups/{2}?api-version=6.1-preview.2") -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId), $($_);
                            $varGrpObj = [WebRequestHelper]::InvokeGetWebRequest($varGrpURL);
                            
                            $editableVarGrps += $varGrpObj[0].name
                        } 
                    }
                }

                if(($editableVarGrps | Measure-Object).Count -gt 0)
                {
                    $controlResult.AddMessage("Total number of variable groups on which contributors have edit permissions in release definition: ", ($editableVarGrps | Measure-Object).Count);
                    $controlResult.AdditionalInfo += "Total number of variable groups on which contributors have edit permissions in release definition: " + ($editableVarGrps | Measure-Object).Count;
                    $controlResult.AddMessage([VerificationResult]::Failed,"Contributors have edit permissions on the below variable groups used in release definition: ", $editableVarGrps);
                    $controlResult.SetStateData("List of variable groups used in release definition that contributors can edit: ", $editableVarGrps); 
                }
                else 
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,"Contributors do not have edit permissions on any variable groups used in release definition.");    
                }
            }
            catch
            {
                $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch the RBAC details of variable groups used in the pipeline.");
            }
             
        }
        else 
        {
            $controlResult.AddMessage([VerificationResult]::Passed,"No variable groups found in release definition.");
        }

        return $controlResult
    }
    hidden [ControlResult] CheckPipelineEditPermission([ControlResult] $controlResult)
    {
        $projectName = $this.ResourceContext.ResourceGroupName
        $resource = $this.projectid+ "/" + $this.ReleaseObj.id

        # Filter namespaceobj for current release
        $obj = [Release]::ReleaseNamespacesObj | where-object {$_.token -eq $resource}  

        # If current release object is not found, get project level obj. (Seperate release obj is not available if project level permissions are being used on pipeline)
        if(($obj | Measure-Object).Count -eq 0)
        {
            $obj = [Release]::ReleaseNamespacesObj | where-object {$_.token -eq $this.projectid}  
        }

        if(($obj | Measure-Object).Count -gt 0)
        {
            $properties = $obj.acesDictionary | Get-Member -MemberType Properties
            $permissionsInBit =0
            $editPerms= @()

            try
            {
                #Use descriptors from acl to make identities call, using each descriptor see permissions mapped to Contributors
                $properties | ForEach-Object{
                    if ($permissionsInBit -eq 0) {
                        $apiUrlIdentity = "https://vssps.dev.azure.com/{0}/_apis/identities?descriptors={1}&api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $($obj.acesDictionary.$($_.Name).descriptor)
                        $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiUrlIdentity);
                        if ($responseObj.providerDisplayName -eq "[$($projectName)]\Contributors")
                        {
                            $permissionsInBit = $obj.acesDictionary.$($_.Name).extendedInfo.effectiveAllow
                        }
                    }
                }
                
                # ResolvePermissions method returns object if 'Edit release pipeline' is allowed
                $editPerms = [Helpers]::ResolvePermissions($permissionsInBit, [Release]::ReleaseNamespacesPermissionObj.actions, 'Edit release pipeline')

                if(($editPerms | Measure-Object).Count -gt 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Failed,"Contributors have edit permissions on the release pipeline.");
                }
                else 
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,"Contributors do not have edit permissions on the release pipeline.");    
                }   
            }
            catch
            {
                $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch RBAC details of the pipeline.");
            }
        }
        else {
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch RBAC details of the pipeline.");
        }

        return $controlResult;
    }

    hidden CheckActiveReleases()
    {
        try
        {
            if($this.ReleaseObj)
            {
                if([Helpers]::CheckMember($this.ReleaseObj ,"lastrelease"))
                {
                    $recentReleases = @()
                    $release = $this.ReleaseObj.lastrelease
                    $this.releaseActivityDetail.releaseCreationDate = [datetime]::Parse($this.ReleaseObj.createdOn);

                    if([datetime]::Parse( $release.createdOn) -gt (Get-Date).AddDays(-$($this.ControlSettings.Release.ReleaseHistoryPeriodInDays)))
                    {
                        $recentReleases = $release
                    }
                    
                    if(($recentReleases | Measure-Object).Count -gt 0 )
                    {
                        $this.releaseActivityDetail.isReleaseActive = $true;
                        $this.releaseActivityDetail.message = "Found recent releases triggered within $($this.ControlSettings.Release.ReleaseHistoryPeriodInDays) days";
                        $latestReleaseTriggerDate = [datetime]::Parse($recentReleases.createdOn);
                        $this.releaseActivityDetail.latestReleaseTriggerDate = $latestReleaseTriggerDate;

                    }
                    else
                    {
                        $this.releaseActivityDetail.isReleaseActive = $false;
                        $this.releaseActivityDetail.message = "No recent release history found in last $($this.ControlSettings.Release.ReleaseHistoryPeriodInDays) days";
                    }
                }
                else
                {
                    $this.releaseActivityDetail.isReleaseActive = $false;
                    $this.releaseActivityDetail.message = "No release history found. Release is inactive.";
                }

                $responseObj = $null;
            }
        }
        catch
        {
            $this.releaseActivityDetail.message = "Could not fetch release details.";
        }
        $this.releaseActivityDetail.isComputed = $true
    }
}
