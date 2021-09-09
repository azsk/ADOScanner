Set-StrictMode -Version Latest
class Release: ADOSVTBase
{

    hidden [PSObject] $ReleaseObj;
    hidden [string] $ProjectId;
    hidden static [PSObject] $ReleaseNamespacesObj= $null;
    hidden static [PSObject] $ReleaseNamespacesPermissionObj= $null;
    hidden static [PSObject] $TaskGroupNamespacesObj= $null;
    hidden static [PSObject] $TaskGroupNamespacePermissionObj= $null;
    hidden static $IsOAuthScan = $false;
    hidden static [string] $securityNamespaceId = $null;
    hidden static [PSObject] $ReleaseVarNames = @{};
    hidden [PSObject] $releaseActivityDetail = @{isReleaseActive = $true; latestReleaseTriggerDate = $null; releaseCreationDate = $null; message = $null; isComputed = $false; errorObject = $null};
    hidden [PSObject] $excessivePermissionBits = @(1)
    hidden static [PSObject] $RegexForURL = $null;
    hidden static $isInheritedPermissionCheckEnabled = $false
    hidden static $SecretsInReleaseRegexList = $null;
    hidden static $SecretsScanToolEnabled = $null;
    hidden [string] $BackupFolderPath = (Join-Path $([Constants]::AzSKAppFolderPath) "TempState" | Join-Path -ChildPath "BackupControlState" )
    hidden [string] $BackupFilePath;
    hidden static [bool] $IsPathValidated = $false;
    hidden static $TaskGroupSecurityNamespace = $null;

    Release([string] $organizationName, [SVTResource] $svtResource): Base($organizationName,$svtResource)
    {
        [system.gc]::Collect();

        #This denotes that command to undo control fix of inactive release is called. 
        #In this case api calls to populate $this.ReleaseObj will not work as resource has already been deleted
        if([Helpers]::CheckMember($_.ResourceDetails, "deletedOn")) 
        {
            return;
        }

        if(-not [string]::IsNullOrWhiteSpace($env:RefreshToken) -and -not [string]::IsNullOrWhiteSpace($env:ClientSecret))  # this if block will be executed for OAuth based scan
        {
            [Release]::IsOAuthScan = $true
        }

        # Get release object
        $releaseId =  ($this.ResourceContext.ResourceId -split "release/")[-1]
        $this.ProjectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
        $apiURL = "https://vsrm.dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ProjectId)/_apis/Release/definitions/$($releaseId)?api-version=6.0"
        $this.ReleaseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);

        $this.BackupFilePath = $this.BackupFolderPath | Join-Path -ChildPath $this.OrganizationContext.OrganizationName | Join-Path -ChildPath $this.ResourceContext.ResourceGroupName | Join-Path -ChildPath "ReleaseBackupFiles"

        # Get security namespace identifier of current release pipeline.
        if ([string]::IsNullOrEmpty([Release]::SecurityNamespaceId)) {
            $apiURL = "https://dev.azure.com/{0}/_apis/securitynamespaces?api-version=6.0" -f $($this.OrganizationContext.OrganizationName)
            $securityNamespacesObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
            [Release]::SecurityNamespaceId = ($securityNamespacesObj | Where-Object { ($_.Name -eq "ReleaseManagement") -and ($_.actions.name -contains "ViewReleaseDefinition")}).namespaceId
            
            [Release]::TaskGroupSecurityNamespace = ($securityNamespacesObj | Where-Object { ($_.Name -eq "MetaTask")}).namespaceId
            $securityNamespacesObj = $null;
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

        if ([Release]::IsOAuthScan -eq $true)
        {
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
            if (-not [string]::IsNullOrEmpty([Release]::SecurityNamespaceId) -and ($null -eq [Release]::TaskGroupNamespacesObj) ) {
                #Get acl for taskgroups. Its response contains descriptor of each ado group/user which have permission on the taskgroup
                $apiUrl = "https://dev.azure.com/{0}/_apis/accesscontrollists/{1}?includeExtendedInfo=True&recurse=True&api-version=6.0" -f $($this.OrganizationContext.OrganizationName), [Release]::TaskGroupSecurityNamespace
                [Release]::TaskGroupNamespacesObj = [WebRequestHelper]::InvokeGetWebRequest($apiUrl);
            }
            if (-not [string]::IsNullOrEmpty([Release]::SecurityNamespaceId) -and ($null -eq [Release]::TaskGroupNamespacePermissionObj) ) {
                #Get permission and its bit for security namespaces
                $apiUrlNamespace =  "https://dev.azure.com/{0}/_apis/securitynamespaces/{1}?api-version=6.1-preview.1" -f $($this.OrganizationContext.OrganizationName), [Release]::TaskGroupSecurityNamespace
                [Release]::TaskGroupNamespacePermissionObj = [WebRequestHelper]::InvokeGetWebRequest($apiUrlNamespace);
            }

            if(-not [Release]::isInheritedPermissionCheckEnabled)
            {
                if(([Helpers]::CheckMember($this.ControlSettings, "Release.CheckForInheritedPermissions") -and $this.ControlSettings.Build.CheckForInheritedPermissions))
                {
                    [Release]::isInheritedPermissionCheckEnabled = $true
                }
            }
        }

        if ([Helpers]::CheckMember($this.ControlSettings.Release, "CheckForInheritedPermissions") -and $this.ControlSettings.Release.CheckForInheritedPermissions) {
            #allow permission bit for inherited permission is '3'
            $this.excessivePermissionBits = @(1, 3)
        }

        if (![Release]::SecretsInReleaseRegexList) {
            [Release]::SecretsInReleaseRegexList = $this.ControlSettings.Patterns | where {$_.RegexCode -eq "SecretsInRelease"} | Select-Object -Property RegexList; 
        }
        if ([Release]::SecretsScanToolEnabled -eq $null) {
            [Release]::SecretsScanToolEnabled = [Helpers]::CheckMember([ConfigurationManager]::GetAzSKSettings(),"SecretsScanToolFolder")
        }
    }

    hidden [ControlResult] CheckCredInReleaseVariables([ControlResult] $controlResult)
	{
        $controlResult.VerificationResult = [VerificationResult]::Failed
        if([Release]::SecretsScanToolEnabled -eq $true)
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
                            $controlResult.LogException($_)
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
                #$patterns = $this.ControlSettings.Patterns | where {$_.RegexCode -eq "SecretsInRelease"} | Select-Object -Property RegexList;
                $exclusions = $this.ControlSettings.Release.ExcludeFromSecretsCheck;
                $varList = @();
                $varGrpList = @();
                $noOfCredFound = 0;
                $restrictedVarGrp = $false;

                if([Release]::SecretsInReleaseRegexList.RegexList.Count -gt 0)
                {
                    if([Helpers]::CheckMember($this.ReleaseObj,"variables"))
                    {
                        Get-Member -InputObject $this.ReleaseObj.variables -MemberType Properties | ForEach-Object {
                            if([Helpers]::CheckMember($this.ReleaseObj.variables.$($_.Name),"value") -and  (-not [Helpers]::CheckMember($this.ReleaseObj.variables.$($_.Name),"isSecret")))
                            {
                                $releaseVarName = $_.Name
                                $releaseVarValue = $this.ReleaseObj[0].variables.$releaseVarName.value
                                if ($exclusions -notcontains $releaseVarName)
                                {
                                    for ($i = 0; $i -lt [Release]::SecretsInReleaseRegexList.RegexList.Count; $i++) {
                                        #Note: We are using '-cmatch' here.
                                        #When we compile the regex, we don't specify ignoreCase flag.
                                        #If regex is in text form, the match will be case-sensitive.
                                        if ($releaseVarValue -cmatch [Release]::SecretsInReleaseRegexList.RegexList[$i]) {
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
                                    $varGrpURL = ("https://dev.azure.com/{0}/{1}/_apis/distributedtask/variablegroups?groupIds={2}&api-version=6.1-preview.2") -f $($this.OrganizationContext.OrganizationName), $this.ProjectId, $_;
                                    $varGrpObj += [WebRequestHelper]::InvokeGetWebRequest($varGrpURL);
                                }
                                catch
                                {
                                    $controlResult.LogException($_)
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
                                            for ($i = 0; $i -lt [Release]::SecretsInReleaseRegexList.RegexList.Count; $i++) {
                                                #Note: We are using '-cmatch' here.
                                                #When we compile the regex, we don't specify ignoreCase flag.
                                                #If regex is in text form, the match will be case-sensitive.
                                                if ($varValue -cmatch [Release]::SecretsInReleaseRegexList.RegexList[$i]) {
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

                        $varContaningSecretCount = $varList.Count
                        if($varContaningSecretCount -gt 0 )
                        {
                            $varList = $varList | select -Unique | Sort-object
                            $stateData.VariableList += $varList
                            $controlResult.AddMessage("`nCount of variable(s) containing secret: $($varContaningSecretCount)");
                            $formattedVarList = $($varList | FT | out-string )
                            $controlResult.AddMessage("`nList of variable(s) containing secret: ", $formattedVarList);
                            $controlResult.AdditionalInfo += "Count of variable(s) containing secret: " + $varContaningSecretCount;
                        }

                        $varGrpContaningSecretCount = $varGrpList.Count; 
                        if($varGrpContaningSecretCount -gt 0 )
                        {
                            $varGrpList = $varGrpList | select -Unique | Sort-object
                            $stateData.VariableGroupList += $varGrpList
                            $controlResult.AddMessage("`nCount of variable(s) containing secret in variable group(s): $($varGrpContaningSecretCount)");
                            $formattedVarGrpList = $($varGrpList | FT | out-string )
                            $controlResult.AddMessage("`nList of variable(s) containing secret in variable group(s): ", $formattedVarGrpList);
                            $controlResult.AdditionalInfo += "Count of variable(s) containing secret in variable group(s): " + $varGrpContaningSecretCount;
                        }
                        $controlResult.SetStateData("List of variable and variable group containing secret: ", $stateData );
                    }
                    $patterns = $null;
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Error, "Regular expressions for detecting credentials in pipeline variables are not defined in your organization.");
                }
            }
            catch {
                $controlResult.AddMessage([VerificationResult]::Error, "Could not evaluate release definition.");
                $controlResult.AddMessage($_);
                $controlResult.LogException($_)
            }

         }

        return $controlResult;
    }

    hidden [ControlResult] CheckForInactiveReleases([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            if ($this.releaseActivityDetail.message -eq 'Could not fetch release details.')
            {
                $controlResult.AddMessage([VerificationResult]::Error, $this.releaseActivityDetail.message);
                if ($null -ne $this.releaseActivityDetail.errorObject)
                {
                    $controlResult.LogException($this.releaseActivityDetail.errorObject)
                }
            }
            elseif ($this.releaseActivityDetail.isReleaseActive)
            {
                $controlResult.AddMessage([VerificationResult]::Passed, $this.releaseActivityDetail.message);
            }
            else
            {
                if (-not [string]::IsNullOrEmpty($this.releaseActivityDetail.releaseCreationDate))
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
                    $formattedDate = $this.releaseActivityDetail.releaseCreationDate.ToString("d MMM yyyy")
                    $controlResult.AddMessage("The release pipeline was created on: $($formattedDate)");
                    $controlResult.AdditionalInfo += "The release pipeline was created on: " + $formattedDate;
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, $this.releaseActivityDetail.message);
                }
            }

            if (-not [string]::IsNullOrEmpty($this.releaseActivityDetail.latestReleaseTriggerDate))
            {
                $formattedDate = $this.releaseActivityDetail.latestReleaseTriggerDate.ToString("d MMM yyyy")
                $controlResult.AddMessage("Last release date of pipeline: $($formattedDate)");
                $controlResult.AdditionalInfo += "Last release date of pipeline: " + $formattedDate;
                $releaseInactivePeriod = ((Get-Date) - $this.releaseActivityDetail.latestReleaseTriggerDate).Days
                $controlResult.AddMessage("The release was inactive from last $($releaseInactivePeriod) days.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch release details.");
            $controlResult.LogException($_)
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

        try {
            if ($this.ControlFixBackupRequired -and $controlResult.VerificationResult -eq "Failed")
            {
                #Create folders if not already present
                if(-not [Release]::IsPathValidated)
                {
                    if (-not (Test-Path $this.BackupFilePath))
                    {
                        New-Item -ItemType Directory -Force -Path $this.BackupFilePath
                    }
                    [Release]::IsPathValidated = $true
                }

                #Generate json of release
                $apiURL = "https://vsrm.dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.projectid)/_apis/release/Definitions/$($this.ReleaseObj.id)?api-version=6.0";
        
                $rmContext = [ContextHelper]::GetCurrentContext();
                $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f "",$rmContext.AccessToken)))
                $headers = @{
                                "Authorization"= ("Basic " + $base64AuthInfo); 
                                "Accept"="application/json;api-version=6.0;excludeUrls=true;enumsAsNumbers=true;msDateFormat=true;noArrayWrap=true"
                            };

                $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL, $headers);
                $this.BackupFilePath = $this.BackupFilePath | Join-Path -ChildPath "$($this.ReleaseObj.name)-$($this.ReleaseObj.Id).json"
                $responseObj | ConvertTo-Json -Depth 10 | Out-File $this.BackupFilePath

                $obj = New-Object -TypeName psobject -Property @{BackupPath= $this.BackupFilePath}
                $controlResult.BackupControlState = $obj 
            }
        }
        catch
        {
            $controlResult.AddMessage("Error generating backup of release pipeline. ");
            $controlResult.LogException($_)
        }

        return $controlResult
    }

    hidden [ControlResult] CheckForInactiveReleasesAutomatedFix([ControlResult] $controlResult)
    {
        try{
            $RawDataObjForControlFix = @();
            $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject

            if (-not $this.UndoFix)
            {
                if(Test-Path $RawDataObjForControlFix.BackupPath)
                {
                    $rmContext = [ContextHelper]::GetCurrentContext();
                    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f "",$rmContext.AccessToken)))
                    $uri = "https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions/{2}?api-version=6.0" -f ($this.OrganizationContext.OrganizationName), $($this.projectid), $($this.ReleaseObj.id) 
                    Invoke-RestMethod -Method DELETE -Uri $uri -Headers @{Authorization = ("Basic {0}" -f $base64AuthInfo) }  -ContentType "application/json"

                    $controlResult.AddMessage([VerificationResult]::Fixed,  "Release pipeline has been deleted.`nBackup is stored locally at: $($RawDataObjForControlFix.BackupPath)");
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Error,  "Backup of release not found.");
                }
            }
            else {
                $uri = "https://vsrm.dev.azure.com/{0}/{1}/_apis/release/definitions/{2}?api-version=6.0" -f ($this.OrganizationContext.OrganizationName), $($this.ResourceContext.ResourceGroupName), $($this.ResourceContext.ResourceDetails.id) 
                $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($uri)
                $body = '{"comment":"Restored release via ADOScanner"}'
                Invoke-RestMethod -Uri $uri -Method Patch -ContentType "application/json" -Headers $header -Body $body

                $pipelineUrl = "https://dev.azure.com/{0}/{1}/_release?definitionId={2}" -f ($this.OrganizationContext.OrganizationName), $($this.ResourceContext.ResourceGroupName), $($this.ResourceContext.ResourceDetails.id) 
                $controlResult.AddMessage([VerificationResult]::Fixed,  "Release pipeline has been restored.`nUrl: $pipelineUrl");
            }
            
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckInheritedPermissions([ControlResult] $controlResult)
    {
        if ([Release]::IsOAuthScan -eq $true)
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
        }
        else{
            # Here 'permissionSet' = security namespace identifier, 'token' = project id
            $apiURL = "https://dev.azure.com/{0}/{1}/_admin/_security/index?useApiUrl=true&permissionSet={2}&token={3}%2F{4}&style=min" -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId), $([Release]::SecurityNamespaceId), $($this.ProjectId), $($this.ReleaseObj.id);
            $header = [WebRequestHelper]::GetAuthHeaderFromUri($apiURL);
            $responseObj = Invoke-RestMethod -Method Get -Uri $apiURL -Headers $header -UseBasicParsing
            $responseObj = ($responseObj.SelectNodes("//script") | Where-Object { $_.class -eq "permissions-context" }).InnerXML | ConvertFrom-Json;
            if($responseObj.inheritPermissions -eq $true)
            {
                $controlResult.AddMessage([VerificationResult]::Failed,"Inherited permissions are enabled on release pipeline.");
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed,"Inherited permissions are disabled on release pipeline.");
            }
            $header = $null;
            $responseObj = $null;
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

    hidden [ControlResult] CheckRBACAccess ([ControlResult] $controlResult)
    {
        <#
        {
            "ControlID": "ADO_Release_AuthZ_Grant_Min_RBAC_Access",
            "Description": "All teams/groups must be granted minimum required permissions on release definition.",
            "Id": "Release110",
            "ControlSeverity": "High",
            "Automated": "Yes",
            "MethodName": "CheckRBACAccess",
            "Rationale": "Granting minimum access by leveraging RBAC feature ensures that users are granted just enough permissions to perform their tasks. This minimizes exposure of the resources in case of user/service account compromise.",
            "Recommendation": "Refer: https://docs.microsoft.com/en-us/azure/devops/pipelines/policies/permissions?view=vsts and https://dev.azure.com/microsoftit/OneITVSO/_wiki/wikis/OneITVSO.wiki?wikiVersion=GBwikiMaster&pagePath=%2FEngineering%20Guide%2FOneITVSO%2FDevelopment%2FRelease%2FHow%20To%20Secure%20Your%20Release%20Definition&pageId=2419&anchor=desired-state",
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
        if ([Release]::IsOAuthScan -eq $true)
        {
            if([AzSKRoot]::IsDetailedScanRequired -eq $true)
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
                            $controlResult.AddMessage([VerificationResult]::Passed,"No identities have been explicitly provided with RBAC access to [$($this.ResourceContext.ResourceName)] pipeline other than release pipeline owner and default groups");
                            $controlResult.AddMessage("Total number of exempted user identities:",($exemptedUserIdentities | Measure-Object).Count);
                            $controlResult.AddMessage("List of exempted user identities:",$exemptedUserIdentities)
                            $controlResult.AdditionalInfo += "Total number of exempted user identities: " + ($exemptedUserIdentities | Measure-Object).Count;
                        }

                    }
                    catch
                    {
                        $controlResult.AddMessage([VerificationResult]::Manual,"Could not fetch RBAC details of the pipeline. $($_) Please verify from portal all teams/groups are granted minimum required permissions on build definition.");
                        $controlResult.LogException($_)
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Manual,"Could not fetch RBAC details of the pipeline.");
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Verify,"Validate that all the identities have been provided with minimum RBAC access to [$($this.ResourceContext.ResourceName)] pipeline.");
            }
        }
        else {

            $failMsg = $null
            try
            {
                # This functions is to check users permissions on release definition. Groups' permissions check is not added here.
                $releaseDefinitionPath = $this.ReleaseObj.Path.Trim("\").Replace(" ","+").Replace("\","%2F")
                $apiURL = "https://dev.azure.com/{0}/{1}/_api/_security/ReadExplicitIdentitiesJson?__v=5&permissionSetId={2}&permissionSetToken={3}%2F{4}%2F{5}" -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId), $([Release]::SecurityNamespaceId), $($this.ProjectId), $($releaseDefinitionPath) ,$($this.ReleaseObj.id);

                $sw = [System.Diagnostics.Stopwatch]::StartNew();
                $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
                $sw.Stop()

                $accessList = @()
                $exemptedUserIdentities = @()

                #Below code added to send perf telemtry
                if ($this.IsAIEnabled)
                {
                    $properties =  @{
                        TimeTakenInMs = $sw.ElapsedMilliseconds;
                        ApiUrl = $apiURL;
                        Resourcename = $this.ResourceContext.ResourceName;
                        ResourceType = $this.ResourceContext.ResourceType;
                        PartialScanIdentifier = $this.PartialScanIdentifier;
                        CalledBy = "CheckRBACAccess";
                    }
                    [AIOrgTelemetryHelper]::PublishEvent( "Api Call Trace",$properties, @{})
                }

                # Fetch detailed permissions of each of group/user from above api call
                # To be evaluated only when -DetailedScan flag is used in GADS command along with control ids  or when controls are to be attested
                if([AzSKRoot]::IsDetailedScanRequired -eq $true)
                {
                    # exclude release owner
                    $exemptedUserIdentities += $this.ReleaseObj.createdBy.id
                    if([Helpers]::CheckMember($responseObj,"identities") -and ($responseObj.identities|Measure-Object).Count -gt 0)
                    {
                        $exemptedUserIdentities += $responseObj.identities | Where-Object { $_.IdentityType -eq "user" }| ForEach-Object {
                            $identity = $_
                            $exemptedIdentity = $this.ControlSettings.Release.ExemptedUserIdentities | Where-Object { $_.Domain -eq $identity.Domain -and $_.DisplayName -eq $identity.DisplayName }
                            if(($exemptedIdentity | Measure-Object).Count -gt 0)
                            {
                                return $identity.TeamFoundationId
                            }
                        }

                        $accessList += $responseObj.identities | Where-Object { $_.IdentityType -eq "user" } | ForEach-Object {
                            $identity = $_
                            if($exemptedUserIdentities -notcontains $identity.TeamFoundationId)
                            {
                                $apiURL = "https://dev.azure.com/{0}/{1}/_api/_security/DisplayPermissions?__v=5&tfid={2}&permissionSetId={3}&permissionSetToken={4}%2F{5}%2F{6}" -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId), $($identity.TeamFoundationId) ,$([Release]::SecurityNamespaceId), $($this.ProjectId), $($releaseDefinitionPath), $($this.ReleaseObj.id);
                                $identityPermissions = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
                                $configuredPermissions = $identityPermissions.Permissions | Where-Object {$_.permissionDisplayString -ne 'Not set'}
                                return @{ IdentityName = $identity.DisplayName; IdentityType = $identity.IdentityType; Permissions = ($configuredPermissions | Select-Object @{Name="Name"; Expression = {$_.displayName}},@{Name="Permission"; Expression = {$_.permissionDisplayString}}) }
                            }
                        }

                        $accessList += $responseObj.identities | Where-Object { $_.IdentityType -eq "group" } | ForEach-Object {
                            $identity = $_
                            $apiURL = "https://dev.azure.com/{0}/{1}/_api/_security/DisplayPermissions?__v=5&tfid={2}&permissionSetId={3}&permissionSetToken={4}%2F{5}%2F{6}" -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId), $($identity.TeamFoundationId) ,$([Release]::SecurityNamespaceId), $($this.ProjectId), $($releaseDefinitionPath), $($this.ReleaseObj.id);
                            $identityPermissions = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
                            $configuredPermissions = $identityPermissions.Permissions | Where-Object {$_.permissionDisplayString -ne 'Not set'}
                            return @{ IdentityName = $identity.DisplayName; IdentityType = $identity.IdentityType; IsAadGroup = $identity.IsAadGroup ;Permissions = ($configuredPermissions | Select-Object @{Name="Name"; Expression = {$_.displayName}},@{Name="Permission"; Expression = {$_.permissionDisplayString}}) }
                        }
                    }

                    if(($accessList | Measure-Object).Count -ne 0)
                    {
                        $accessList= $accessList | Select-Object -Property @{Name="IdentityName"; Expression = {$_.IdentityName}},@{Name="IdentityType"; Expression = {$_.IdentityType}},@{Name="Permissions"; Expression = {$_.Permissions}}
                        $controlResult.AddMessage("Total number of identities that have access to release pipeline: ", ($accessList | Measure-Object).Count);
                        $controlResult.AddMessage([VerificationResult]::Verify,"Validate that the following identities have been provided with minimum RBAC access to [$($this.ResourceContext.ResourceName)] pipeline", $accessList);
                        $controlResult.SetStateData("Release pipeline access list: ", ($responseObj.identities | Select-Object -Property @{Name="IdentityName"; Expression = {$_.FriendlyDisplayName}},@{Name="IdentityType"; Expression = {$_.IdentityType}},@{Name="Scope"; Expression = {$_.Scope}}));
                        $controlResult.AdditionalInfo += "Total number of identities that have access to release pipeline: " + ($accessList | Measure-Object).Count;
                        $controlResult.AdditionalInfo += "Total number of user identities that have access to release pipeline: " + (($accessList | Where-Object {$_.IdentityType -eq 'user'}) | Measure-Object).Count;
                        $controlResult.AdditionalInfo += "Total number of group identities that have access to release pipeline: " + (($accessList | Where-Object {$_.IdentityType -eq 'group'}) | Measure-Object).Count;
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed,"No identities have been explicitly provided with RBAC access to [$($this.ResourceContext.ResourceName)] pipeline other than release pipeline owner and default groups");
                        $controlResult.AddMessage("Total number of exempted user identities:",($exemptedUserIdentities | Measure-Object).Count);
                        $controlResult.AddMessage("List of exempted user identities:",$exemptedUserIdentities)
                        $controlResult.AdditionalInfo += "Total number of exempted user identities: " + ($exemptedUserIdentities | Measure-Object).Count;
                    }
                }
                else{
                    # Non detailed scan results
                    if(($responseObj.identities|Measure-Object).Count -gt 0)
                    {
                        $accessList= $responseObj.identities | Select-Object -Property @{Name="IdentityName"; Expression = {$_.FriendlyDisplayName}},@{Name="IdentityType"; Expression = {$_.IdentityType}},@{Name="Scope"; Expression = {$_.Scope}}
                        $controlResult.AddMessage("Total number of identities that have access to release pipeline: ", ($accessList | Measure-Object).Count);
                        $controlResult.AddMessage([VerificationResult]::Verify,"Validate that the following identities have been provided with minimum RBAC access to [$($this.ResourceContext.ResourceName)] pipeline.", $accessList);
                        $controlResult.SetStateData("Release pipeline access list: ", $accessList);
                        $controlResult.AdditionalInfo += "Total number of identities that have access to release pipeline: " + ($accessList | Measure-Object).Count;
                        $controlResult.AdditionalInfo += "Total number of user identities that have access to release pipeline: " + (($accessList | Where-Object {$_.IdentityType -eq 'user'}) | Measure-Object).Count;
                        $controlResult.AdditionalInfo += "Total number of group identities that have access to release pipeline: " + (($accessList | Where-Object {$_.IdentityType -eq 'group'}) | Measure-Object).Count;
                    }
                }

                $accessList = $null;
                $exemptedUserIdentities =$null;
                $responseObj = $null;
            }
            catch
            {
                $failMsg = $_
                $controlResult.LogException($_)
            }
            if(![string]::IsNullOrEmpty($failMsg))
            {
                $controlResult.AddMessage([VerificationResult]::Manual,"Unable to fetch release pipeline details. $($failMsg)Please verify from portal all teams/groups are granted minimum required permissions on release definition.");
            }
        }
        return $controlResult
    }

    hidden [ControlResult] CheckExternalSources([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Verify
        if(($this.ReleaseObj | Measure-Object).Count -gt 0)
        {
            if([Helpers]::CheckMember($this.ReleaseObj[0],"artifacts") -and ($this.ReleaseObj[0].artifacts | Measure-Object).Count -gt 0){
                $sourceObj = @($this.ReleaseObj[0].artifacts);
                $nonAdoResource = @($sourceObj | Where-Object { ($_.type -ne 'Git' -and $_.type -ne 'Build')}) ;
                $adoResource = @($sourceObj | Where-Object { $_.type -eq 'Git' -or $_.type -eq 'Build'}) ;

               if($nonAdoResource.Count -gt 0){
                    $nonAdoResource = $nonAdoResource | Select-Object -Property @{Name="ArtifactSourceAlias"; Expression = {$_.alias}},@{Name="ArtifactSourceType"; Expression = {$_.type}}
                    $stateData = @();
                    $stateData += $nonAdoResource;
                    $controlResult.AddMessage([VerificationResult]::Verify,"Pipeline contains following artifacts from external sources: ");
                    $display = ($stateData|FT  -AutoSize | Out-String -Width 512)
                    $controlResult.AddMessage($display)
                    $controlResult.SetStateData("Pipeline contains following artifacts from external sources: ", $stateData);
               }
               else {
                    $adoResource = $adoResource | Select-Object -Property @{Name="ArtifactSourceAlias"; Expression = {$_.alias}},@{Name="ArtifactSourceType"; Expression = {$_.type}}
                    $stateData = @();
                    $stateData += $adoResource;
                    $controlResult.AddMessage([VerificationResult]::Passed,"Pipeline contains artifacts from trusted sources: ");
                    $display = ($stateData|FT  -AutoSize | Out-String -Width 512)
                    $controlResult.AddMessage($display)
                    $controlResult.SetStateData("Pipeline contains artifacts from trusted sources: ", $stateData);
               }
               $resource = $stateData | ForEach-Object { $_.ArtifactSourceAlias + ': ' + $_.ArtifactSourceType } 
                $controlResult.AdditionalInfoInCSV = $resource -join ' ; '
                $controlResult.AdditionalInfo = $resource -join ' ; '
               
               $sourceObj = $null;
               $nonAdoResource = $null;
           }
           else {

            $controlResult.AdditionalInfoInCSV = "No source repository found."
            $controlResult.AddMessage([VerificationResult]::Passed,"Pipeline does not contain any source repositories.");
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
           $controlResult.LogException($_)
       }
     return $controlResult;
    }

    hidden [ControlResult] CheckSettableAtReleaseTimeForURL([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Verify
        try
        {
            if ([Helpers]::CheckMember($this.ReleaseObj[0], "variables"))
            {
                if ([Helpers]::CheckMember($this.ControlSettings, "Patterns"))
                {
                    $settableURLVars = @();
                    if($null -eq [Release]::RegexForURL)
                    {
                        $this.FetchRegexForURL()
                    }
                    $regexForURLs = [Release]::RegexForURL;
                    $allVars = Get-Member -InputObject $this.ReleaseObj[0].variables -MemberType Properties

                    $allVars | ForEach-Object {
                        if ([Helpers]::CheckMember($this.ReleaseObj[0].variables.$($_.Name), "allowOverride") )
                        {
                            $varName = $_.Name;
                            $varValue = $this.ReleaseObj[0].variables.$($varName).value;
                            for ($i = 0; $i -lt $regexForURLs.RegexList.Count; $i++) {
                                if ($varValue -match $regexForURLs.RegexList[$i]) {
                                    $settableURLVars += @( [PSCustomObject] @{ Name = $varName; Value = $varValue } )
                                    break
                                }
                            }
                        }
                    }
                    $varCount = $settableURLVars.Count
                    if ($varCount -gt 0)
                    {
                        $controlResult.AddMessage("Count of variables that are settable at release time and contain URL value: $($varCount)");
                        $controlResult.AddMessage([VerificationResult]::Verify, "List of variables settable at release time and containing URL value: `n", $($settableURLVars | FT | Out-String));
                        $controlResult.AdditionalInfo += "Count of variables that are settable at release time and contain URL value: " + $varCount;
                        $controlResult.SetStateData("List of variables settable at release time and containing URL value: ", $settableURLVars);
                    }
                    else 
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed, "No variables were found in the release pipeline that are settable at release time and contain URL value.");
                    }
                }
                else 
                {
                    $controlResult.AddMessage([VerificationResult]::Error, "Regular expressions for detecting URLs in pipeline variables are not defined in control settings for your organization.");
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "No variables were found in the release pipeline.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch variables of the release pipeline.");
            $controlResult.LogException($_)
        }
        return $controlResult;
    }
    hidden [ControlResult] CheckTaskGroupEditPermission([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        $taskGroups = @();

        if ([Release]::IsOAuthScan -eq $true)
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
                            if ($permissionsInBit -eq 0) {
                                $apiUrlIdentity = "https://vssps.dev.azure.com/{0}/_apis/identities?descriptors={1}&api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $($obj.acesDictionary.$($_.Name).descriptor)
                                $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiUrlIdentity);
                                if ($responseObj.providerDisplayName -eq "[$($projectName)]\Contributors")
                                {
                                    $permissionsInBit = $obj.acesDictionary.$($_.Name).extendedInfo.effectiveAllow
                                }
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
                        $editableTaskGroupsCount = ($editableTaskGroups | Measure-Object).Count;
                        $controlResult.AddMessage("Total number of task groups on which contributors have edit permissions in release definition: ", $editableTaskGroupsCount);
                        #$controlResult.AdditionalInfo += "Total number of task groups on which contributors have edit permissions in release definition: " + $editableTaskGroupsCount;
                        $formatedTaskGroups = $editableTaskGroups | ForEach-Object { $_.DisplayName }
                        $addInfo = "NumTaskGroups: $editableTaskGroupsCount; List: $($formatedTaskGroups -join ';')"
                        $controlResult.AdditionalInfo += $addInfo;
                        $controlResult.AdditionalInfoInCSV = $addInfo;
                        $controlResult.AddMessage([VerificationResult]::Failed,"Contributors have edit permissions on the below task groups used in release definition: ", $editableTaskGroups);
                        $controlResult.SetStateData("List of task groups used in release definition that contributors can edit: ", $editableTaskGroups);
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed,"Contributors do not have edit permissions on any task groups used in release definition.");
                        $controlResult.AdditionalInfoInCSV = "NA"
                        $controlResult.AdditionalInfo = "NA"
                    }
                }
                catch
                {
                    $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch the RBAC details of task groups used in the pipeline.");
                    $controlResult.LogException($_)
                }

            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed,"No task groups found in release definition.");
                $controlResult.AdditionalInfoInCSV += "NA";
            }
        }
        else
        {
            #fetch all envs of pipeline.
            $releaseEnv = $this.ReleaseObj[0].environments

            #filter task groups in each such env.
            $releaseEnv | ForEach-Object {
                #Task groups have type 'metaTask' whereas individual tasks have type 'task'
                $_.deployPhases[0].workflowTasks | ForEach-Object {
                    if(([Helpers]::CheckMember($_ ,"definitiontype")) -and ($_.definitiontype -eq 'metaTask') -and $_.enabled -eq $true)
                    {
                        $taskGroups += $_
                    }
                }
            }
            #Filtering unique task groups used in release pipeline.
            $taskGroups = $taskGroups | Sort-Object -Property taskId -Unique

            $editableTaskGroups = @();
            $groupsWithExcessivePermissionsList = @();
            if(($taskGroups | Measure-Object).Count -gt 0)
            {
                $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $($this.OrganizationContext.OrganizationName)
                $projectName = $this.ResourceContext.ResourceGroupName

                try
                {
                    $taskGroups | ForEach-Object {
                        $taskGrpId = $_.taskId
                        $taskGrpURL="https://dev.azure.com/{0}/{1}/_taskgroup/{2}" -f $($this.OrganizationContext.OrganizationName), $($projectName), $($taskGrpId)
                        $permissionSetToken = "$($this.projectId)/$taskGrpId"

                        #permissionSetId = 'f6a4de49-dbe2-4704-86dc-f8ec1a294436' is the std. namespaceID. Refer: https://docs.microsoft.com/en-us/azure/devops/organizations/security/manage-tokens-namespaces?view=azure-devops#namespaces-and-their-ids
                        $inputbody = "{
                            'contributionIds': [
                                'ms.vss-admin-web.security-view-members-data-provider'
                            ],
                            'dataProviderContext': {
                                'properties': {
                                    'permissionSetId': 'f6a4de49-dbe2-4704-86dc-f8ec1a294436',
                                    'permissionSetToken': '$permissionSetToken',
                                    'sourcePage': {
                                        'url': '$taskGrpURL',
                                        'routeId':'ms.vss-distributed-task.hub-task-group-edit-route',
                                        'routeValues': {
                                            'project': '$projectName',
                                            'taskGroupId': '$taskGrpId',
                                            'controller':'Apps',
                                            'action':'ContributedHub',
                                            'viewname':'task-groups-edit'
                                        }
                                    }
                                }
                            }
                        }" | ConvertFrom-Json

                        # This web request is made to fetch all identities having access to task group - it will contain descriptor for each of them.
                        # We need contributor's descriptor to fetch its permissions on task group.
                        $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL,$inputbody);

                        #Filtering out Contributors group.
                        if([Helpers]::CheckMember($responseObj[0],"dataProviders") -and ($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider') -and ([Helpers]::CheckMember($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider',"identities")))
                        {

                            $contributorObj = @($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider'.identities | Where-Object {$_.subjectKind -eq 'group' -and $_.principalName -like "*\Contributors"})
                            # $contributorObj would be null if none of its permissions are set i.e. all perms are 'Not Set'.
                            foreach($obj in $contributorObj)
                            {
                                $contributorInputbody = "{
                                    'contributionIds': [
                                        'ms.vss-admin-web.security-view-permissions-data-provider'
                                    ],
                                    'dataProviderContext': {
                                        'properties': {
                                            'subjectDescriptor': '$($obj.descriptor)',
                                            'permissionSetId': 'f6a4de49-dbe2-4704-86dc-f8ec1a294436',
                                            'permissionSetToken': '$permissionSetToken',
                                            'accountName': '$(($obj.principalName).Replace('\','\\'))',
                                            'sourcePage': {
                                                'url': '$taskGrpURL',
                                                'routeId':'ms.vss-distributed-task.hub-task-group-edit-route',
                                                'routeValues': {
                                                    'project': '$projectName',
                                                    'taskGroupId': '$taskGrpId',
                                                    'controller':'Apps',
                                                    'action':'ContributedHub',
                                                    'viewname':'task-groups-edit'
                                                }
                                            }
                                        }
                                    }
                                }" | ConvertFrom-Json

                                #Web request to fetch RBAC permissions of Contributors group on task group.
                                $contributorResponseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL,$contributorInputbody);
                                $contributorRBACObj = $contributorResponseObj[0].dataProviders.'ms.vss-admin-web.security-view-permissions-data-provider'.subjectPermissions
                                $editPerms = $contributorRBACObj | Where-Object {$_.displayName -eq 'Edit task group'}
                                #effectivePermissionValue equals to 1 implies edit task group perms is set to 'Allow'. Its value is 3 if it is set to Allow (inherited). This param is not available if it is 'Not Set'.
                                if([Helpers]::CheckMember($editPerms,"effectivePermissionValue") -and (($editPerms.effectivePermissionValue -eq 1) -or ($editPerms.effectivePermissionValue -eq 3)))
                                {
                                    $editableTaskGroups += New-Object -TypeName psobject -Property @{DisplayName = $_.name; PrincipalName=$obj.principalName}

                                    $excessivePermissionsGroupObj = @{}
                                    $excessivePermissionsGroupObj['TaskGroupId'] = $taskGrpId
                                    $excessivePermissionsGroupObj['TaskGroupName'] = $_.Name
                                    $excessivePermissionsGroupObj['Group'] = $obj.principalName
                                    #$excessivePermissionsGroupObj['ExcessivePermissions'] = $($excessivePermissionsPerGroup.displayName -join ', ')
                                    $excessivePermissionsGroupObj['ExcessivePermissions'] =  "Edit task group" #$($editableTaskGroups.displayName -join ', ')
                                    $excessivePermissionsGroupObj['Descriptor'] = $obj.sid
                                    $excessivePermissionsGroupObj['PermissionSetToken'] = $permissionSetToken
                                    $excessivePermissionsGroupObj['PermissionSetId'] = [Release]::TaskGroupSecurityNamespace
                                    $groupsWithExcessivePermissionsList += $excessivePermissionsGroupObj
                                }
                            }
                        }
                    }
                    $editableTaskGroupsCount = $editableTaskGroups.Count
                    if($editableTaskGroupsCount -gt 0)
                    {
                        $controlResult.AddMessage("Count of task groups on which contributors have edit permissions in release definition: $editableTaskGroupsCount");
                        #$controlResult.AdditionalInfo += "Count of task groups on which contributors have edit permissions in release definition: " + $editableTaskGroupsCount;                                                
                        $groups = $editableTaskGroups | ForEach-Object { $_.DisplayName } 

                        $addInfo = "NumTaskGroups: $(($taskGroups | Measure-Object).Count); NumTaskGroupWithEditPerm: $($editableTaskGroupsCount); List: $($groups -join '; ')"
                        $controlResult.AdditionalInfo += $addInfo;
                        $controlResult.AdditionalInfoInCSV += $addInfo;
                        
                        $controlResult.AddMessage([VerificationResult]::Failed,"Contributors have edit permissions on the below task groups used in release definition: ");
                        $display = $editableTaskGroups|FT  -AutoSize | Out-String -Width 512
                        $controlResult.AddMessage($display)
                        $controlResult.SetStateData("List of task groups used in release definition that contributors can edit: ", $editableTaskGroups);
                        if ($this.ControlFixBackupRequired) {
                            #Data object that will be required to fix the control
                            $controlResult.BackupControlState = $groupsWithExcessivePermissionsList;
                        }
                    }
                    else
                    {
                        $controlResult.AdditionalInfoInCSV += "NA"
                        $controlResult.AdditionalInfo += "NA"
                        $controlResult.AddMessage([VerificationResult]::Passed,"Contributors do not have edit permissions on any task groups used in release definition.");
                    }
                    if(($taskGroups | Measure-Object).Count -ne $editableTaskGroups.Count)
                    {
                        if ($editableTaskGroups.Count -gt 0)
                        {                            
                            $nonEditableTaskGroups = $taskGroups | where-object {$editableTaskGroups.DisplayName -notcontains $_.name}
                        }
                        else
                        {
                            $nonEditableTaskGroups = $taskGroups
                        }                        
                        $groups = $nonEditableTaskGroups | ForEach-Object { $_.name } 
                        $controlResult.AdditionalInfoInCSV += "NonEditableTaskGroupsList: $($groups -join ' ; ') ; "
                        $controlResult.AdditionalInfo += "NonEditableTaskGroupsList: $($groups -join '; '); "
                    }
                }
                catch
                {
                    $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch the RBAC details of task groups used in the pipeline.");
                    $controlResult.LogException($_)
                }

            }
            else
            {
                $controlResult.AdditionalInfoInCSV += "NA"
                $controlResult.AdditionalInfo += "NA";
                $controlResult.AddMessage([VerificationResult]::Passed,"No task groups found in release definition.");
            }
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckTaskGroupEditPermissionAutomatedFix([ControlResult] $controlResult)
    {
        try {
            $RawDataObjForControlFix = @();
            $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject
            
            if (-not $this.UndoFix)
            {
                foreach ($identity in $RawDataObjForControlFix) 
                {
                    $excessivePermissions = $identity.ExcessivePermissions -split ","
                    foreach ($excessivePermission in $excessivePermissions) {
                        #$roleId = [int][BuildPermissions] $excessivePermission.Replace(" ","");
                        #need to invoke a post request which does not accept all permissions added in the body at once
                        #hence need to call invoke seperately for each permission
                         $body = "{
                            'token': '$($identity.PermissionSetToken)',
                            'merge': true,
                            'accessControlEntries' : [{
                                'descriptor' : 'Microsoft.TeamFoundation.Identity;$($identity.Descriptor)',
                                'allow':0,
                                'deny':2                             
                            }]
                        }" | ConvertFrom-Json
                        $url = "https://dev.azure.com/{0}/_apis/AccessControlEntries/{1}?api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $RawDataObjForControlFix[0].PermissionSetId

                        [WebRequestHelper]:: InvokePostWebRequest($url,$body)

                    }
                    $identity | Add-Member -NotePropertyName OldPermission -NotePropertyValue "Allow"
                    $identity | Add-Member -NotePropertyName NewPermission -NotePropertyValue "Deny"

                }              
                
            }
            else {
                foreach ($identity in $RawDataObjForControlFix) 
                {
                   
                    $excessivePermissions = $identity.ExcessivePermissions -split ","
                    foreach ($excessivePermission in $excessivePermissions) {
                        #$roleId = [int][BuildPermissions] $excessivePermission.Replace(" ","");
                        
                         $body = "{
                            'token': '$($identity.PermissionSetToken)',
                            'merge': true,
                            'accessControlEntries' : [{
                                'descriptor' : 'Microsoft.TeamFoundation.Identity;$($identity.Descriptor)',
                                'allow':2,
                                'deny':0                              
                            }]
                        }" | ConvertFrom-Json
                        $url = "https://dev.azure.com/{0}/_apis/AccessControlEntries/{1}?api-version=6.0" -f $($this.OrganizationContext.OrganizationName),$RawDataObjForControlFix[0].PermissionSetId

                        [WebRequestHelper]:: InvokePostWebRequest($url,$body)

                    }
                    $identity | Add-Member -NotePropertyName OldPermission -NotePropertyValue "Deny"
                    $identity | Add-Member -NotePropertyName NewPermission -NotePropertyValue "Allow"
                }

            }
            $controlResult.AddMessage([VerificationResult]::Fixed,  "Permissions for broader groups have been changed as below: ");
            $formattedGroupsData = $RawDataObjForControlFix | Select @{l = 'TaskGroupName'; e = { $_.TaskGroupName }}, @{l = 'Group'; e = { $_.Group } }, @{l = 'ExcessivePermissions'; e = { $_.ExcessivePermissions }}, @{l = 'OldPermission'; e = { $_.OldPermission }}, @{l = 'NewPermission'; e = { $_.NewPermission } }
            $display = ($formattedGroupsData |  FT -AutoSize | Out-String -Width 512)

            $controlResult.AddMessage("`n$display");
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckVariableGroupEditPermission([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        $varGrpIds = @();
        $editableVarGrps = @();

        #add var groups scoped at release scope.
        $releaseVarGrps = @($this.ReleaseObj[0].variableGroups)
        if($releaseVarGrps.Count -gt 0)
        {
            $varGrpIds += $releaseVarGrps
        }

        # Each release pipeline has atleast 1 env.
        $envCount = ($this.ReleaseObj[0].environments).Count

        for($i=0; $i -lt $envCount; $i++)
        {
            $environmentVarGrps = @($this.ReleaseObj[0].environments[$i].variableGroups);
            if($environmentVarGrps.Count -gt 0)
            {
                $varGrpIds += $environmentVarGrps
            }
        }

        if($varGrpIds.Count -gt 0)
        {
            try
            {
                foreach($vgId in $varGrpIds){
                    #Fetch the security role assignments for variable group
                    $url = 'https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.variablegroup/roleassignments/resources/{1}%24{2}?api-version=6.1-preview.1' -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId), $($vgId);
                    $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($url));
                    if($responseObj.Count -gt 0)
                    {                                       
                        if([Release]::isInheritedPermissionCheckEnabled)
                        {
                            $contributorsObj = @($responseObj | Where-Object {$_.identity.uniqueName -match "\\Contributors$"})    # Filter both inherited and assigned                     
                        }
                        else {
                            $contributorsObj = @($responseObj | Where-Object {($_.identity.uniqueName -match "\\Contributors$") -and ($_.access -eq "assigned")})                        
                        }

                        if($contributorsObj.Count -gt 0)
                        {   
                            foreach($obj in $contributorsObj){
                                if($obj.role.name -ne 'Reader')
                                {
                                    #Release object doesn't capture variable group name. We need to explicitly look up for its name via a separate web request.
                                    $varGrpURL = ("https://dev.azure.com/{0}/{1}/_apis/distributedtask/variablegroups?groupIds={2}&api-version=6.1-preview.2") -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId), $($vgId);
                                    $varGrpObj = [WebRequestHelper]::InvokeGetWebRequest($varGrpURL);
                                    if ((-not ([Helpers]::CheckMember($varGrpObj[0],"count"))) -and ($varGrpObj.Count -gt 0) -and ([Helpers]::CheckMember($varGrpObj[0],"name"))) {
                                    $editableVarGrps += $varGrpObj[0].name
                                    break;
                                    }
                                }
                            }                            
                        }
                    }
                }

                $editableVarGrpsCount = $editableVarGrps.Count
                if($editableVarGrpsCount -gt 0)
                {
                    $controlResult.AddMessage("`nCount of variable groups on which contributors have edit permissions: $editableVarGrpsCount `n");
                    $controlResult.AdditionalInfo += "`nCount of variable groups on which contributors have edit permissions: $editableVarGrpsCount";                    
                    $controlResult.AdditionalInfoInCSV = "NumVGs: $editableVarGrpsCount; List: $($editableVarGrps -join '; ')";
                    $controlResult.AddMessage([VerificationResult]::Failed,"Variable groups list: `n$($editableVarGrps | FT | Out-String)");
                    $controlResult.SetStateData("Variable groups list: ", $editableVarGrps);
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,"`nContributors do not have edit permissions on variable groups used in release definition.");
                    $controlResult.AdditionalInfoInCSV += "NA"
                }
            }
            catch
            {
                $controlResult.AddMessage([VerificationResult]::Error,"`nCould not fetch the RBAC details of variable groups used in the pipeline.");
                $controlResult.LogException($_)
            }

        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,"`nNo variable groups found in release definition.");
            $controlResult.AdditionalInfoInCSV += "NA"
        }

        return $controlResult
    }
    hidden [ControlResult] CheckBroaderGroupAccess([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        if ([Release]::IsOAuthScan -eq $true)
        {
            $projectName = $this.ResourceContext.ResourceGroupName
            $resource = $this.projectid+ "/" + $this.ReleaseObj.id

            # Filter namespaceobj for current release
            $obj = @([Release]::ReleaseNamespacesObj | where-object {$_.token -eq $resource})

            # If current release object is not found, get project level obj. (Seperate release obj is not available if project level permissions are being used on pipeline)
            if($obj.Count -eq 0)
            {
                $obj = @([Release]::ReleaseNamespacesObj | where-object {$_.token -eq $this.projectid})
            }

            if($obj.Count -gt 0)
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
                    $editPerms = @([Helpers]::ResolvePermissions($permissionsInBit, [Release]::ReleaseNamespacesPermissionObj.actions, 'Edit release pipeline'))

                    if($editPerms.Count -gt 0)
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
                    $controlResult.LogException($_)
                }
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch RBAC details of the pipeline.");
            }
        }
        else {
            try
            {
                $orgName = $($this.OrganizationContext.OrganizationName)
                $projectName = $this.ResourceContext.ResourceGroupName
                $releaseId = $this.ReleaseObj.id
                $permissionSetToken = "$($this.projectId)/$releaseId"
                if ([Helpers]::CheckMember($this.ControlSettings.Release, "RestrictedBroaderGroupsForRelease")) {
                    $restrictedBroaderGroups = @{}
                    $broaderGroups = $this.ControlSettings.Release.RestrictedBroaderGroupsForRelease
                    $broaderGroups.psobject.properties | foreach { $restrictedBroaderGroups[$_.Name] = $_.Value }
                    $releaseURL = "https://dev.azure.com/$orgName/$projectName/_release?_a=releases&view=mine&definitionId=$releaseId"

                    $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery/project/{1}?api-version=5.0-preview.1" -f $orgName, $($this.projectId)
                    $inputbody = "{
                        'contributionIds': [
                            'ms.vss-admin-web.security-view-members-data-provider'
                        ],
                        'dataProviderContext': {
                            'properties': {
                                'permissionSetId': '$([Release]::SecurityNamespaceId)',
                                'permissionSetToken': '$permissionSetToken',
                                'sourcePage': {
                                    'url': '$releaseURL',
                                    'routeId': 'ms.vss-releaseManagement-web.hub-explorer-3-default-route',
                                    'routeValues': {
                                        'project': '$projectName',
                                        'viewname': 'details',
                                        'controller': 'ContributedPage',
                                        'action': 'Execute'
                                    }
                                }
                            }
                        }
                    }" | ConvertFrom-Json

                    # Web request to fetch the group details for a release definition
                    $responseObj = @([WebRequestHelper]::InvokePostWebRequest($apiURL,$inputbody));
                    if([Helpers]::CheckMember($responseObj[0],"dataProviders") -and ($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider') -and ([Helpers]::CheckMember($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider',"identities")))
                    {

                        $broaderGroupsList = @($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider'.identities | Where-Object { $_.subjectKind -eq 'group' -and $restrictedBroaderGroups.keys -contains $_.displayName })

                        <#
                        #Check if inheritance is disabled on release pipeline, if disabled, inherited permissions should be considered irrespective of control settings

                        $apiURLForInheritedPerms = "https://dev.azure.com/{0}/{1}/_admin/_security/index?useApiUrl=true&permissionSet={2}&token={3}%2F{4}&style=min" -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId), $([Release]::SecurityNamespaceId), $($this.ProjectId), $($this.ReleaseObj.id);
                        $header = [WebRequestHelper]::GetAuthHeaderFromUri($apiURLForInheritedPerms);
                        $responseObj = Invoke-RestMethod -Method Get -Uri $apiURLForInheritedPerms -Headers $header -UseBasicParsing
                        $responseObj = ($responseObj.SelectNodes("//script") | Where-Object { $_.class -eq "permissions-context" }).InnerXML | ConvertFrom-Json;
                        if($responseObj -and -not [Helpers]::CheckMember($responseObj,"inheritPermissions"))
                        {
                            $this.excessivePermissionBits = @(1, 3)
                        }
                        #>

                        # $broaderGroupsList would be null if none of its permissions are set i.e. all perms are 'Not Set'.

                        if ($broaderGroupsList.Count -gt 0)
                        {
                            $groupsWithExcessivePermissionsList = @()
                            $filteredBroaderGroupList = @()
                            foreach ($broderGroup in $broaderGroupsList) {
                                $contributorInputbody = "{
                                    'contributionIds': [
                                        'ms.vss-admin-web.security-view-permissions-data-provider'
                                    ],
                                    'dataProviderContext': {
                                        'properties': {
                                            'subjectDescriptor': '$($broderGroup.descriptor)',
                                            'permissionSetId': '$([Release]::SecurityNamespaceId)',
                                            'permissionSetToken': '$permissionSetToken',
                                            'accountName': '$(($broderGroup.principalName).Replace('\','\\'))',
                                            'sourcePage': {
                                                'url': '$releaseURL',
                                                'routeId': 'ms.vss-releaseManagement-web.hub-explorer-3-default-route',
                                                'routeValues': {
                                                    'project': '$projectName',
                                                    'viewname': 'details',
                                                    'controller': 'ContributedPage',
                                                    'action': 'Execute'
                                                }
                                            }
                                        }
                                    }
                                }" | ConvertFrom-Json

                                #Web request to fetch RBAC permissions of Contributors group on release.
                                $broaderGroupResponseObj = @([WebRequestHelper]::InvokePostWebRequest($apiURL, $contributorInputbody));
                                $broaderGroupRBACObj = @($broaderGroupResponseObj[0].dataProviders.'ms.vss-admin-web.security-view-permissions-data-provider'.subjectPermissions)
                                $excessivePermissionList = $broaderGroupRBACObj | Where-Object { $_.displayName -in $restrictedBroaderGroups[$broderGroup.displayName] }
                                $excessivePermissionsPerGroup = @()
                                $excessivePermissionList | ForEach-Object {
                                    #effectivePermissionValue equals to 1 implies edit release pipeline perms is set to 'Allow'. Its value is 3 if it is set to Allow (inherited). This param is not available if it is 'Not Set'.
                                    if ([Helpers]::CheckMember($_, "effectivePermissionValue")) {
                                        if ($this.excessivePermissionBits -contains $_.effectivePermissionValue) {
                                            $excessivePermissionsPerGroup += $_
                                        }
                                    }
                                }
                                if ($excessivePermissionsPerGroup.Count -gt 0) {
                                    $excessivePermissionsGroupObj = @{}
                                    $excessivePermissionsGroupObj['Group'] = $broderGroup.principalName
                                    $excessivePermissionsGroupObj['ExcessivePermissions'] = $($excessivePermissionsPerGroup.displayName -join ', ')
                                    $excessivePermissionsGroupObj['Descriptor'] = $broderGroup.sid
                                    $excessivePermissionsGroupObj['PermissionSetToken'] = $permissionSetToken
                                    $excessivePermissionsGroupObj['PermissionSetId'] = [Release]::SecurityNamespaceId
                                    $groupsWithExcessivePermissionsList += $excessivePermissionsGroupObj
                                    $filteredBroaderGroupList += $broderGroup
                                }
                            }

                            if ($this.ControlSettings.CheckForBroadGroupMemberCount -and $filteredBroaderGroupList.Count -gt 0)
                            {
                                $broaderGroupsWithExcessiveMembers = @([ControlHelper]::FilterBroadGroupMembers($filteredBroaderGroupList, $false))
                                $groupsWithExcessivePermissionsList = @($groupsWithExcessivePermissionsList | Where-Object {$broaderGroupsWithExcessiveMembers -contains $_.Group})
                            }

                            if ($groupsWithExcessivePermissionsList.count -gt 0) {
                                $controlResult.AddMessage([VerificationResult]::Failed, "Broader groups have excessive permissions on the release pipeline.");
                                $formattedGroupsData = $groupsWithExcessivePermissionsList | Select @{l = 'Group'; e = { $_.Group } }, @{l = 'ExcessivePermissions'; e = { $_.ExcessivePermissions } }
                                $formattedBroaderGrpTable = ($formattedGroupsData | Out-String)
                                $controlResult.AddMessage("`nList of groups : `n$formattedBroaderGrpTable");
                                $controlResult.AdditionalInfo += "List of excessive permissions on which broader groups have access:  $($groupsWithExcessivePermissionsList.Group).";
                                $groups = $formattedGroupsData | ForEach-Object { $_.Group + ': ' + $_.ExcessivePermissions }
                                $controlResult.AdditionalInfoInCSV = $groups -join ';'
                                
                                if ($this.ControlFixBackupRequired)
                                {
                                    #Data object that will be required to fix the control
                                    
                                    $controlResult.BackupControlState = $groupsWithExcessivePermissionsList;
                                }
                            }
                            else {
                                $controlResult.AddMessage([VerificationResult]::Passed, "Broader Groups do not have excessive permissions on the release pipeline.");
                                $controlResult.AdditionalInfoInCSV += "NA"
                            }
                        }
                        else
                        {
                            $controlResult.AddMessage([VerificationResult]::Passed,"Broader groups do not have access to the release pipeline.");
                        }
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch RBAC details of the pipeline.");
                    }
                    $displayObj = $restrictedBroaderGroups.Keys | Select-Object @{Name = "Broader Group"; Expression = {$_}}, @{Name = "Excessive Permissions"; Expression = {$restrictedBroaderGroups[$_] -join ', '}}
                    $controlResult.AddMessage("`nNote:`nFollowing groups are considered 'broad groups':`n$($displayObj | FT -AutoSize | Out-String -width 512)");
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Error, "Broader groups or excessive permissions are not defined in control settings for your organization.");
                }
            }
            catch
            {
                $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch RBAC details of the pipeline.");
                $controlResult.LogException($_)
            }
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckBroaderGroupAccessAutomatedFix([ControlResult] $controlResult)
    {
        try {
            $RawDataObjForControlFix = @();
            $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject
                       
            if (-not $this.UndoFix)
            {
                foreach ($identity in $RawDataObjForControlFix) 
                {
                    
                    $excessivePermissions = $identity.ExcessivePermissions -split ","
                    foreach ($excessivePermission in $excessivePermissions) {
                        $roleId = [int][ReleasePermissions] $excessivePermission.Replace(" ","");
                        
                        #need to invoke a post request which does not accept all permissions added in the body at once
                        #hence need to call invoke seperately for each permission
                         $body = "{
                            'token': '$($identity.PermissionSetToken)',
                            'merge': true,
                            'accessControlEntries' : [{
                                'descriptor' : 'Microsoft.TeamFoundation.Identity;$($identity.Descriptor)',
                                'allow':0,
                                'deny':$($roleId)                              
                            }]
                        }" | ConvertFrom-Json
                        $url = "https://dev.azure.com/{0}/_apis/AccessControlEntries/{1}?api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $RawDataObjForControlFix[0].PermissionSetId

                        [WebRequestHelper]:: InvokePostWebRequest($url,$body)

                    }
                    $identity | Add-Member -NotePropertyName OldPermission -NotePropertyValue "Allow"
                    $identity | Add-Member -NotePropertyName NewPermission -NotePropertyValue "Deny"

                }              
                
            }
            else {
                foreach ($identity in $RawDataObjForControlFix) 
                {
                   
                    $excessivePermissions = $identity.ExcessivePermissions -split ","
                    foreach ($excessivePermission in $excessivePermissions) {
                        $roleId = [int][ReleasePermissions] $excessivePermission.Replace(" ","");
                        
                         $body = "{
                            'token': '$($identity.PermissionSetToken)',
                            'merge': true,
                            'accessControlEntries' : [{
                                'descriptor' : 'Microsoft.TeamFoundation.Identity;$($identity.Descriptor)',
                                'allow':$($roleId),
                                'deny':0                              
                            }]
                        }" | ConvertFrom-Json
                        $url = "https://dev.azure.com/{0}/_apis/AccessControlEntries/{1}?api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $RawDataObjForControlFix[0].PermissionSetId

                        [WebRequestHelper]:: InvokePostWebRequest($url,$body)

                    }
                    $identity | Add-Member -NotePropertyName OldPermission -NotePropertyValue "Deny"
                    $identity | Add-Member -NotePropertyName NewPermission -NotePropertyValue "Allow"
                }

            }
            $controlResult.AddMessage([VerificationResult]::Fixed,  "Permissions for broader groups have been changed as below: ");
            $formattedGroupsData = $RawDataObjForControlFix | Select @{l = 'Group'; e = { $_.Group } }, @{l = 'ExcessivePermissions'; e = { $_.ExcessivePermissions }}, @{l = 'OldPermission'; e = { $_.OldPermission }}, @{l = 'NewPermission'; e = { $_.NewPermission } }
            $display = ($formattedGroupsData |  FT -AutoSize | Out-String -Width 512)

            $controlResult.AddMessage("`n$display");
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }


    hidden CheckActiveReleases()
    {
        try
        {
            if ([Release]::IsOAuthScan -eq $true)
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
                        $latestReleaseTriggerDate = [datetime]::Parse($release.createdOn);
                        $this.releaseActivityDetail.latestReleaseTriggerDate = $latestReleaseTriggerDate;
                    }
                    else
                    {
                        $this.releaseActivityDetail.isReleaseActive = $false;
                        $this.releaseActivityDetail.message = "No release history found. Release is inactive.";
                        [datetime] $createdDate = $this.ReleaseObj.createdOn
                        $this.releaseActivityDetail.releaseCreationDate = $createdDate
                    }

                    $responseObj = $null;
                }
            }
            else {
                if($this.ReleaseObj)
                {
                    $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery/project/{1}?api-version=5.0-preview.1" -f $($this.OrganizationContext.OrganizationName),$this.ProjectId;
                    $inputbody =  "{
                        'contributionIds': [
                            'ms.vss-releaseManagement-web.releases-list-data-provider'
                        ],
                        'dataProviderContext': {
                            'properties': {
                                'definitionIds': '$($this.ReleaseObj.id)',
                                'definitionId': '$($this.ReleaseObj.id)',
                                'fetchAllReleases': true,
                                'sourcePage': {
                                    'url': 'https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.ResourceContext.ResourceGroupName)/_release?_a=releases&view=mine&definitionId=$($this.ReleaseObj.id)',
                                    'routeId': 'ms.vss-releaseManagement-web.hub-explorer-3-default-route',
                                    'routeValues': {
                                        'project': '$($this.ResourceContext.ResourceGroupName)',
                                        'viewname': 'hub-explorer-3-view',
                                        'controller': 'ContributedPage',
                                        'action': 'Execute'
                                    }
                                }
                            }
                        }
                    }"  | ConvertFrom-Json

                $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL,$inputbody);

                if([Helpers]::CheckMember($responseObj,"dataProviders") -and ($responseObj.dataProviders | Get-Member 'ms.vss-releaseManagement-web.releases-list-data-provider') -and [Helpers]::CheckMember($responseObj.dataProviders.'ms.vss-releaseManagement-web.releases-list-data-provider', 'releases'))
                {

                    $releases = @($responseObj.dataProviders.'ms.vss-releaseManagement-web.releases-list-data-provider'.releases)

                    if($releases.Count -gt 0 )
                    {
                        $this.releaseActivityDetail.releaseCreationDate = [datetime]::Parse($this.ReleaseObj.createdOn);
                        $recentReleases = @()
                        $releases | ForEach-Object {
                            if([datetime]::Parse( $_.createdOn) -gt (Get-Date).AddDays(-$($this.ControlSettings.Release.ReleaseHistoryPeriodInDays)))
                            {
                                $recentReleases+=$_
                            }
                        }

                        if(($recentReleases | Measure-Object).Count -gt 0 )
                        {
                            $this.releaseActivityDetail.isReleaseActive = $true;
                            $this.releaseActivityDetail.message = "Found recent releases triggered within $($this.ControlSettings.Release.ReleaseHistoryPeriodInDays) days";
                        }
                        else
                        {
                            $this.releaseActivityDetail.isReleaseActive = $false;
                            $this.releaseActivityDetail.message = "No recent release history found in last $($this.ControlSettings.Release.ReleaseHistoryPeriodInDays) days";
                        }
                        $latestReleaseTriggerDate = [datetime]::Parse($releases[0].createdOn);
                        $this.releaseActivityDetail.latestReleaseTriggerDate = $latestReleaseTriggerDate;
                    }
                    else
                    {
                        # no release history ever.
                        $this.releaseActivityDetail.isReleaseActive = $false;
                        $this.releaseActivityDetail.releaseCreationDate = [datetime]::Parse($this.ReleaseObj.createdOn);
                        $this.releaseActivityDetail.message = "No release history found.";
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
        }
        catch
        {
            $this.releaseActivityDetail.message = "Could not fetch release details.";
            $this.releaseActivityDetail.errorObject = $_
        }
        $this.releaseActivityDetail.isComputed = $true
    }

    hidden FetchRegexForURL()
    {
        [Release]::RegexForURL = @($this.ControlSettings.Patterns | where {$_.RegexCode -eq "URLs"} | Select-Object -Property RegexList);
    }

    hidden [ControlResult] CheckAccessToOAuthToken([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        if(($this.ReleaseObj | Measure-Object).Count -gt 0)
        {
            if([Helpers]::CheckMember($this.ReleaseObj,"environments"))
            {
                $stages = @($this.ReleaseObj.environments)
                if($stages.Count -gt 0)
                {
                    $resultObj = @()
                    $stages | Where-Object {
                        $currentStage = $_
                        $stageWithJobDetails = "" | Select-Object StageName,JobName
                        if([Helpers]::CheckMember($currentStage,"deployPhases"))
                        {                            
                            $agentlessjobs = @()
                            $AgentjobsOAuthAccessTokenDisabled = @()
                            $jobs = @($currentStage.deployPhases)
                            $stageWithJobDetails.JobName = @()
                            $jobs | Where-Object {
                                $currentJob = $_
                                if([Helpers]::CheckMember($currentJob,"phaseType") -and (($currentJob.phaseType -eq "agentBasedDeployment") -or ($currentJob.phaseType -eq "machineGroupBasedDeployment")))
                                {
                                    if([Helpers]::CheckMember($currentJob,"deploymentInput") -and [Helpers]::CheckMember($currentJob.deploymentInput,"enableAccessToken",$false))
                                    {
                                        if($currentJob.deploymentInput.enableAccessToken-eq $true)
                                        {
                                            $stageWithJobDetails.StageName = $currentStage.name
                                            $stageWithJobDetails.JobName += $currentJob.name
                                        }
                                        else {
                                            $AgentjobsOAuthAccessTokenDisabled += $currentJob 
                                        }
                                    }
                                    else {
                                        $controlResult.AddMessage([VerificationResult]::Error,"Not able to fetch OAuth Access token details for stage: $($currentStage.name)");
                                    }
                                }
                                else {
                                    ## it will be the case of "Agentless job"
                                    $agentlessjobs += $_                                  
                                }
                            }
                        }
                        else {
                            $controlResult.AddMessage([VerificationResult]::Passed,"No job found in release.");                            
                        }
                        if( -not ([string]::IsNullOrWhiteSpace($stageWithJobDetails.StageName) -and [string]::IsNullOrWhiteSpace($stageWithJobDetails.JobName)))
                        {
                            $resultObj += $stageWithJobDetails
                        }                                        
                    }

                    if($resultObj.count -gt 0)
                    {
                        $display = $resultObj | FT -AutoSize | Out-String -Width 512
                        $controlResult.AddMessage([VerificationResult]::Verify,"Accessing OAuth token is enabled for the following stages and jobs:");
                        $controlResult.AddMessage($display)
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Passed,"Accessing OAuth token is not enabled for agent job(s) in any stage.");
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed,"No stage found in release.");
                }
                
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Error,"Not able to fetch release environment details.");
            }
            
        }
        else {
            $controlResult.AddMessage([VerificationResult]::Error,"Not able to fetch release details.");
        }

        return $controlResult;
    }
}
