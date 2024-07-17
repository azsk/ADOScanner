Set-StrictMode -Version Latest
class Build: ADOSVTBase
{

    hidden [PSObject] $BuildObj;
    hidden static [PSObject] $BuildNamespacesObj = $null;
    hidden static [PSObject] $BuildNamespacesPermissionObj = $null;
    hidden static [PSObject] $TaskGroupNamespacesObj = $null;
    hidden static [PSObject] $TaskGroupNamespacePermissionObj = $null;
    hidden static $IsOAuthScan = $false;
    hidden static [string] $SecurityNamespaceId = $null;
    hidden static [PSObject] $BuildVarNames = @{};
    hidden [PSObject] $buildActivityDetail = @{isBuildActive = $true; buildLastRunDate = $null; buildCreationDate = $null; message = $null; isComputed = $false; errorObject = $null};
    hidden [PSObject] $excessivePermissionBits = @(1)
    hidden static [PSObject] $RegexForURL = $null;
    hidden static $isInheritedPermissionCheckEnabled = $false
    hidden static $SecretsInBuildRegexList = $null;
    hidden static $SecretsScanToolEnabled = $null;
    hidden [string] $BackupFolderPath = (Join-Path $([Constants]::AzSKAppFolderPath) "TempState" | Join-Path -ChildPath "BackupControlState" )
    hidden [string] $BackupFilePath;
    hidden static [bool] $IsPathValidated = $false;
    hidden static $TaskGroupSecurityNamespace = $null
    hidden static $broadlyEditableVG = @{}
    hidden static $YamlBranchPolicies = @()
    Build([string] $organizationName, [SVTResource] $svtResource): Base($organizationName,$svtResource)
    {
        [system.gc]::Collect();

        #This denotes that command to undo control fix of inactive build is called. 
        #In this case api calls to populate $this.BuildObj will not work as resource has already been deleted
        if([Helpers]::CheckMember($_.ResourceDetails, "deletedDate")) 
        {
            $this.BuildObj = New-Object -TypeName psobject -Property @{ process = $null }
            return;
        }

        if(-not [string]::IsNullOrWhiteSpace($env:RefreshToken) -and -not [string]::IsNullOrWhiteSpace($env:ClientSecret))  # this if block will be executed for OAuth based scan
        {
            [Build]::IsOAuthScan = $true
        }

        # Get security namespace identifier of current build.
        if ([string]::IsNullOrEmpty([Build]::SecurityNamespaceId) ) {
            $apiURL = "https://dev.azure.com/{0}/_apis/securitynamespaces?api-version=6.0" -f $($this.OrganizationContext.OrganizationName)
            $securityNamespacesObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
            [Build]::SecurityNamespaceId = ($securityNamespacesObj | Where-Object { ($_.Name -eq "Build") -and ($_.actions.name -contains "ViewBuilds")}).namespaceId
            [Build]::TaskGroupSecurityNamespace = ($securityNamespacesObj | Where-Object { ($_.Name -eq "MetaTask")}).namespaceId
            Remove-Variable securityNamespacesObj;
        }

        $buildId = $this.ResourceContext.ResourceDetails.id
        $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
        # Get build object
        $apiURL = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$projectId/_apis/build/Definitions/$($buildId)?includeAllProperties=True&includeLatestBuilds=True&api-version=6.0";
        $this.BuildObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);

        if(($this.BuildObj | Measure-Object).Count -eq 0)
        {
            throw [SuppressedException] "Unable to find build pipeline in [Organization: $($this.OrganizationContext.OrganizationName)] [Project: $($this.ResourceContext.ResourceGroupName)]."
        }

        $this.BackupFilePath = $this.BackupFolderPath | Join-Path -ChildPath $this.OrganizationContext.OrganizationName | Join-Path -ChildPath $this.BuildObj.project.name | Join-Path -ChildPath "BuildBackupFiles"

        # if build activity check function is not computed, then first compute the function to get the correct status of build.
        if($this.buildActivityDetail.isComputed -eq $false)
        {
            $this.CheckActiveBuilds()
        }

        # overiding the '$this.isResourceActive' global variable based on the current status of build.
        if ($this.buildActivityDetail.isBuildActive)
        {
            $this.isResourceActive = $true
        }
        else
        {
            $this.isResourceActive = $false
        }

        # calculating the inactivity period in days for the build. If there is no build history, then setting it with negative value.
        # This will ensure inactive period is always computed irrespective of whether inactive control is scanned or not.
        if ($null -ne $this.buildActivityDetail.buildLastRunDate)
        {
            $this.InactiveFromDays = ((Get-Date) - $this.buildActivityDetail.buildLastRunDate).Days
        }

        if ([Build]::IsOAuthScan -eq $true)
        {
            #Get ACL for all builds
            if ((-not [string]::IsNullOrEmpty([Build]::SecurityNamespaceId)) -and ($null -eq [Build]::BuildNamespacesObj)) {
                $apiURL = "https://dev.azure.com/{0}/_apis/accesscontrollists/{1}?includeExtendedInfo=True&recurse=True&api-version=6.0" -f $($this.OrganizationContext.OrganizationName),$([Build]::SecurityNamespaceId)
                [Build]::BuildNamespacesObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
            }

            #Get build permission and their bit using security namespace
            if ((-not [string]::IsNullOrEmpty([Build]::SecurityNamespaceId)) -and ($null -eq [Build]::BuildNamespacesPermissionObj)) {
                $apiUrlNamespace =  "https://dev.azure.com/{0}/_apis/securitynamespaces/{1}?api-version=6.1-preview.1" -f $($this.OrganizationContext.OrganizationName),$([Build]::SecurityNamespaceId)
                [Build]::BuildNamespacesPermissionObj = [WebRequestHelper]::InvokeGetWebRequest($apiUrlNamespace);
            }

            if (-not [string]::IsNullOrEmpty([Build]::SecurityNamespaceId) -and ($null -eq [Build]::TaskGroupNamespacesObj) ) {
                #Get acl for taskgroups. Its response contains descriptor of each ado group/user which have permission on the taskgroup
                $apiUrl = "https://dev.azure.com/{0}/_apis/accesscontrollists/{1}?includeExtendedInfo=True&recurse=True&api-version=6.0" -f $($this.OrganizationContext.OrganizationName),[Build]::TaskGroupSecurityNamespace
                [Build]::TaskGroupNamespacesObj = [WebRequestHelper]::InvokeGetWebRequest($apiUrl);
            }

            if (-not [string]::IsNullOrEmpty([Build]::SecurityNamespaceId) -and ($null -eq [Build]::TaskGroupNamespacePermissionObj)) {
                #Get permission and its bit for security namespaces
                $apiUrlNamespace =  "https://dev.azure.com/{0}/_apis/securitynamespaces/{1}?api-version=6.1-preview.1" -f $($this.OrganizationContext.OrganizationName),[Build]::TaskGroupSecurityNamespace
                [Build]::TaskGroupNamespacePermissionObj = [WebRequestHelper]::InvokeGetWebRequest($apiUrlNamespace);
            }
        }

        if ([Helpers]::CheckMember($this.ControlSettings, "Build.CheckForInheritedPermissions") -and $this.ControlSettings.Build.CheckForInheritedPermissions) {
            #allow permission bit for inherited permission is '3'
            $this.excessivePermissionBits = @(1,3)
        }

        if(-not [Build]::isInheritedPermissionCheckEnabled)
        {
            if(([Helpers]::CheckMember($this.ControlSettings, "Build.CheckForInheritedPermissions") -and $this.ControlSettings.Build.CheckForInheritedPermissions))
            {
                [Build]::isInheritedPermissionCheckEnabled = $true
            }
        }
        
        if (![Build]::SecretsInBuildRegexList) {
            [Build]::SecretsInBuildRegexList = $this.ControlSettings.Patterns | where {$_.RegexCode -eq "SecretsInBuild"} | Select-Object -Property RegexList;
            
        }
        if ($null -eq [Build]::SecretsScanToolEnabled) {
            [Build]::SecretsScanToolEnabled = [Helpers]::CheckMember([ConfigurationManager]::GetAzSKSettings(),"SecretsScanToolFolder")
        }
    }

    [ControlItem[]] ApplyServiceFilters([ControlItem[]] $controls)
	{
        $result = $controls;
        # Applying filter to exclude certain controls based on Tag
        if([Helpers]::CheckMember($this.BuildObj[0].process,"yamlFilename"))
        {
            $result = $controls | Where-Object { $_.Tags -notcontains "SkipYAML" };
		}
        # exclude controls meant only for YAML pipelines incase this pipeline is a classic one
        if(-not [Helpers]::CheckMember($this.BuildObj[0].process,"yamlFilename"))
        {
            $result = $controls | Where-Object { $_.Tags -notcontains "SkipClassic" };
		}
		return $result;
	}

    hidden [ControlResult] CheckCredInBuildVariables([ControlResult] $controlResult)
	{
        $controlResult.VerificationResult = [VerificationResult]::Failed
        
        if([Build]::SecretsScanToolEnabled -eq $true)
        {
            $ToolFolderPath =  [ConfigurationManager]::GetAzSKSettings().SecretsScanToolFolder
            $SecretsScanToolName = [ConfigurationManager]::GetAzSKSettings().SecretsScanToolName
            if((-not [string]::IsNullOrEmpty($ToolFolderPath)) -and (Test-Path $ToolFolderPath) -and (-not [string]::IsNullOrEmpty($SecretsScanToolName)))
            {
            $ToolPath = Get-ChildItem -Path $ToolFolderPath -File -Filter $SecretsScanToolName -Recurse
            if($ToolPath)
            {
                if($this.BuildObj)
                {
                    try
                    {
                        $buildDefFileName = $($this.ResourceContext.ResourceName).Replace(" ","")
                        $buildDefPath = [Constants]::AzSKTempFolderPath + "\Builds\"+ $buildDefFileName + "\";
                        if(-not (Test-Path -Path $buildDefPath))
                        {
                            New-Item -ItemType Directory -Path $buildDefPath -Force | Out-Null
                        }

                        $this.BuildObj | ConvertTo-Json -Depth 5 | Out-File "$buildDefPath\$buildDefFileName.json"
                        $searcherPath = Get-ChildItem -Path $($ToolPath.Directory.FullName) -Include "buildsearchers.xml" -Recurse
                        ."$($Toolpath.FullName)" -I $buildDefPath -S "$($searcherPath.FullName)" -f csv -Ve 1 -O "$buildDefPath\Scan"

                        $scanResultPath = Get-ChildItem -Path $buildDefPath -File -Include "*.csv"

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
                        Remove-ITem -Path $buildDefPath -Recurse
                    }
                }
            }
             }
        }
        else {
          try {
            #$patterns = $this.ControlSettings.Patterns | where {$_.RegexCode -eq "SecretsInBuild"} | Select-Object -Property RegexList;
            $exclusions = $this.ControlSettings.Build.ExcludeFromSecretsCheck;
            if([Build]::SecretsInBuildRegexList.RegexList.Count -gt 0)
            {
                $varList = @();
                $varGrpList = @();
                $noOfCredFound = 0;
                if([Helpers]::CheckMember($this.BuildObj[0],"variables"))
                {
                    Get-Member -InputObject $this.BuildObj[0].variables -MemberType Properties | ForEach-Object {
                        if([Helpers]::CheckMember($this.BuildObj[0].variables.$($_.Name),"value") -and  (-not [Helpers]::CheckMember($this.BuildObj[0].variables.$($_.Name),"isSecret")))
                        {

                            $buildVarName = $_.Name
                            $buildVarValue = $this.BuildObj[0].variables.$buildVarName.value
                            if ($exclusions -notcontains $buildVarName)
                            {
                                for ($i = 0; $i -lt [Build]::SecretsInBuildRegexList.RegexList.Count; $i++) {
                                    #Note: We are using '-cmatch' here.
                                    #When we compile the regex, we don't specify ignoreCase flag.
                                    #If regex is in text form, the match will be case-sensitive.
                                    if ($buildVarValue -cmatch [Build]::SecretsInBuildRegexList.RegexList[$i]) {
                                        $noOfCredFound +=1
                                        $varList += "$buildVarName";
                                        break
                                    }
                                }
                            }
                        }
                    }
                }
                if(([Helpers]::CheckMember($this.BuildObj[0],"variableGroups")))
                {
                    $this.BuildObj[0].variableGroups| ForEach-Object {
                        $varGrp = $_
                        if (([Helpers]::CheckMember($varGrp,"variables")))
                        {
                            Get-Member -InputObject $_.variables -MemberType Properties | ForEach-Object {

                                if([Helpers]::CheckMember($varGrp.variables.$($_.Name) ,"value") -and  (-not [Helpers]::CheckMember($varGrp.variables.$($_.Name) ,"isSecret")))
                                {
                                    $varName = $_.Name
                                    $varValue = $varGrp.variables.$($_.Name).value
                                    if ($exclusions -notcontains $varName)
                                    {
                                        for ($i = 0; $i -lt [Build]::SecretsInBuildRegexList.RegexList.Count; $i++) {
                                            #Note: We are using '-cmatch' here.
                                            #When we compile the regex, we don't specify ignoreCase flag.
                                            #If regex is in text form, the match will be case-sensitive.
                                            if ($varValue -cmatch [Build]::SecretsInBuildRegexList.RegexList[$i]) {
                                                $noOfCredFound +=1
                                                $varGrpList += "[$($varGrp.Name)]:$varName";
                                                break
                                                }
                                            }
                                    }
                                }
                            }
                        }
                    }
                }
                if($noOfCredFound -eq 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No secrets found in build definition.");
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Found secrets in build definition.");
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
                        $controlResult.AdditionalInfo += "Count number of variable(s) containing secret: " + $varContaningSecretCount;
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
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the build definition.");
            $controlResult.AddMessage($_);
            $controlResult.LogException($_)
        }
      }
     return $controlResult;
    }

    hidden [ControlResult] CheckForInactiveBuilds([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            if ($this.buildActivityDetail.message -eq 'Could not fetch build details.')
            {
                $controlResult.AddMessage([VerificationResult]::Error, $this.buildActivityDetail.message);
                if ($null -ne $this.buildActivityDetail.errorObject)
                {
                    $controlResult.LogException($this.buildActivityDetail.errorObject)
                }
            }
            elseif($this.buildActivityDetail.isBuildActive)
            {
                $controlResult.AddMessage([VerificationResult]::Passed, $this.buildActivityDetail.message);
            }
            else
            {
                if (-not [string]::IsNullOrEmpty($this.buildActivityDetail.buildCreationDate))
                {
                    $inactiveLimit = $this.ControlSettings.Build.BuildHistoryPeriodInDays
                    if ((((Get-Date) - $this.buildActivityDetail.buildCreationDate).Days) -lt $inactiveLimit)
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed, "Build was created within last $($inactiveLimit) days but never queued.");
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Failed, "No build history found in last $($inactiveLimit) days.");
                    }
                    $formattedDate = $this.buildActivityDetail.buildCreationDate.ToString("d MMM yyyy")
                    $controlResult.AddMessage("The build pipeline was created on: $($formattedDate)");
                    $controlResult.AdditionalInfo += "The build pipeline was created on: " + $formattedDate;
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, $this.buildActivityDetail.message);
                }
            }

            if (-not [string]::IsNullOrEmpty($this.buildActivityDetail.buildLastRunDate))
            {
                $formattedDate = $this.buildActivityDetail.buildLastRunDate.ToString("d MMM yyyy")
                $controlResult.AddMessage("Last run date of build pipeline: $($formattedDate)");
                $controlResult.AdditionalInfo += "Last run date of build pipeline: " + $formattedDate;
                $buildInactivePeriod = ((Get-Date) - $this.buildActivityDetail.buildLastRunDate).Days
                $controlResult.AddMessage("The build was inactive from last $($buildInactivePeriod) days.");
                $controlResult.AddMessage("`nNote: Restored pipeline although retain run history but are considered as a new pipeline in ADO.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch build details.");
            $controlResult.LogException($_)
        }
        
        try{
            if ($this.ControlFixBackupRequired -and $controlResult.VerificationResult -eq "Failed")
            {
                #Create folders if not already present
                if(-not [Build]::IsPathValidated)
                {
                    if (-not (Test-Path $this.BackupFilePath))
                    {
                        New-Item -ItemType Directory -Force -Path $this.BackupFilePath
                    }
                    [Build]::IsPathValidated = $true
                }

                if(-not [Helpers]::CheckMember($this.BuildObj[0].process,"yamlFilename"))
                {
                    #Generate json of classic build
                    $apiURL = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.BuildObj.project.id)/_apis/build/Definitions/$($this.BuildObj.id)?api-version=6.0";
        
                    $rmContext = [ContextHelper]::GetCurrentContext();
                    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f "",$rmContext.AccessToken)))
                    $headers = @{
                                    "Authorization"= ("Basic " + $base64AuthInfo); 
                                    "Accept"="application/json;api-version=6.0;excludeUrls=true;enumsAsNumbers=true;msDateFormat=true;noArrayWrap=true"
                                };
        
                    $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL, $headers);
                    $this.BackupFilePath = $this.BackupFilePath | Join-Path -ChildPath "$($this.buildObj.name)-$($this.buildObj.Id).json"
                    $responseObj | ConvertTo-Json -Depth 10 | Out-File $this.BackupFilePath

                    $obj = New-Object -TypeName psobject -Property @{BackupPath= $this.BackupFilePath ; Type="Classic"}
                    $controlResult.BackupControlState = $obj 
                }
                else
                {
                    #For YAML build
                    $apiURL = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$($this.BuildObj.project.id)/_apps/hub/ms.vss-build-web.ci-designer-hub?pipelineId=$($this.BuildObj.id)&__rt=fps&__ver=2"
                    $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($apiURL));
                    if([Helpers]::CheckMember($responseObj,"fps.dataProviders.data") -and $responseObj.fps.dataProviders.data.'ms.vss-build-web.pipeline-editor-data-provider' -and [Helpers]::CheckMember($responseObj.fps.dataProviders.data.'ms.vss-build-web.pipeline-editor-data-provider',"content") -and  $responseObj.fps.dataProviders.data.'ms.vss-build-web.pipeline-editor-data-provider'.content)
                    {
                        $yamlContent = $responseObj.fps.dataProviders.data."ms.vss-build-web.pipeline-editor-data-provider".content;

                        $this.BackupFilePath = $this.BackupFilePath | Join-Path -ChildPath "$($this.buildObj.name)-$($this.buildObj.id).yml"
                        $yamlContent | Out-File $this.BackupFilePath
                        $obj = New-Object -TypeName psobject -Property @{BackupPath= $this.BackupFilePath ; Type="YAML"}
                        $controlResult.BackupControlState = $obj 
                    }
                }
            }
        }
        catch
        {
            $controlResult.AddMessage("Error generating backup of build pipeline. ");
            $controlResult.LogException($_)
        }

        return $controlResult
    }

    hidden [ControlResult] CheckForInactiveBuildsAutomatedFix([ControlResult] $controlResult)
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
                    $uri = "https://dev.azure.com/{0}/{1}/_apis/build/definitions/{2}?api-version=6.0" -f ($this.OrganizationContext.OrganizationName), $($this.BuildObj.project.id), $($this.BuildObj.id) 
                    Invoke-RestMethod -Method DELETE -Uri $uri -Headers @{Authorization = ("Basic {0}" -f $base64AuthInfo) }  -ContentType "application/json"

                    $controlResult.AddMessage([VerificationResult]::Fixed,  "Build pipeline has been deleted.`nBackup is stored locally at: $($RawDataObjForControlFix.BackupPath)");
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Error,  "Backup of build not found.");
                }
            }
            else {
                $uri = "https://dev.azure.com/{0}/{1}/_apis/build/definitions/{2}?deleted=false&api-version=6.0" -f ($this.OrganizationContext.OrganizationName), $($this.ResourceContext.ResourceGroupName), $($this.ResourceContext.ResourceDetails.id) 
                $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($uri)
                Invoke-RestMethod -Uri $uri -Method Patch -ContentType "application/json" -Headers $header

                $pipelineUrl = "https://dev.azure.com/{0}/{1}/_build?definitionId={2}" -f ($this.OrganizationContext.OrganizationName), $($this.ResourceContext.ResourceGroupName), $($this.ResourceContext.ResourceDetails.id) 
                $controlResult.AddMessage([VerificationResult]::Fixed,  "Build pipeline has been restored.`nUrl: $pipelineUrl");
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
        try
        {
            if ([Build]::IsOAuthScan -eq $true)
            {
                if($null -ne [Build]::BuildNamespacesObj -and [Helpers]::CheckMember([Build]::BuildNamespacesObj,"token"))
                {
                    $resource = $this.BuildObj.project.id+ "/" + $this.BuildObj.Id

                    # Filter namespaceobj for current build
                    $obj = [Build]::BuildNamespacesObj | where-object {$_.token -eq $resource}

                    # If current build object is not found, get project level obj. (Seperate build obj is not available if project level permissions are being used on pipeline)
                    if(($obj | Measure-Object).Count -eq 0)
                    {
                        $obj = [Build]::BuildNamespacesObj | where-object {$_.token -eq $this.BuildObj.project.id}
                    }

                    if((($obj | Measure-Object).Count -gt 0) -and $obj.inheritPermissions -eq $false)
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed,"Inherited permissions are disabled on build pipeline.");
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Failed,"Inherited permissions are enabled on build pipeline.");
                    }
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Manual,"Unable to fetch build pipeline details. $($_). Please verify from portal that permission inheritance is turned OFF.");
                }
            }
            else {
                if([Build]::SecurityNamespaceId -and $this.BuildObj.project.id)
                {
                    # Here 'permissionSet' = security namespace identifier, 'token' = project id and 'tokenDisplayVal' = build name
                    $apiURL = "https://dev.azure.com/{0}/{1}/_admin/_security/index?useApiUrl=true&permissionSet={2}&token={3}%2F{4}&tokenDisplayVal={5}&style=min" -f $($this.OrganizationContext.OrganizationName), $($this.BuildObj.project.id), $([Build]::SecurityNamespaceId), $($this.BuildObj.project.id), $($this.BuildObj.id), $($this.BuildObj.name) ;

                    $sw = [System.Diagnostics.Stopwatch]::StartNew();
                    $header = [WebRequestHelper]::GetAuthHeaderFromUri($apiURL);
                    $responseObj = Invoke-RestMethod -Method Get -Uri $apiURL -Headers $header -UseBasicParsing
                    $sw.Stop()

                    #Below code added to send perf telemtry
                    if ($this.IsAIEnabled)
                    {
                        $properties =  @{
                            TimeTakenInMs = $sw.ElapsedMilliseconds;
                            ApiUrl = $apiURL;
                            Resourcename = $this.ResourceContext.ResourceName;
                            ResourceType = $this.ResourceContext.ResourceType;
                            PartialScanIdentifier = $this.PartialScanIdentifier;
                            CalledBy = "CheckInheritedPermissions";
                        }
                        [AIOrgTelemetryHelper]::PublishEvent( "Api Call Trace",$properties, @{})
                    }

                    $responseObj = ($responseObj.SelectNodes("//script") | Where-Object { $_.class -eq "permissions-context" }).InnerXML | ConvertFrom-Json;
                    if($responseObj -and [Helpers]::CheckMember($responseObj,"inheritPermissions") -and $responseObj.inheritPermissions -eq $true)
                    {
                        $controlResult.AddMessage([VerificationResult]::Failed,"Inherited permissions are enabled on build pipeline.");
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed,"Inherited permissions are disabled on build pipeline.");
                    }
                    $header = $null;
                    $responseObj = $null;

                }
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Manual,"Unable to fetch build pipeline details. $($_). Please verify from portal that permission inheritance is turned OFF.");
            $controlResult.LogException($_)
        }

        return $controlResult
    }

    hidden [ControlResult] CheckRBACAccess([ControlResult] $controlResult)
    {
        <#
        {
            "ControlID": "ADO_Build_AuthZ_Grant_Min_RBAC_Access",
            "Description": "All teams/groups must be granted minimum required permissions on build definition.",
            "Id": "Build110",
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
        }
        #>
        if ([Build]::IsOAuthScan -eq $true)
        {
            if([AzSKRoot]::IsDetailedScanRequired -eq $true)
            {
                $exemptedUserIdentities = $this.BuildObj.authoredBy.id
                $exemptedUserIdentities += $this.ControlSettings.Build.ExemptedUserIdentities

                $resource = $this.BuildObj.project.id+ "/" + $this.BuildObj.Id

                # Filter namespaceobj for current build
                $obj = [Build]::BuildNamespacesObj | where-object {$_.token -eq $resource}

                # If current build object is not found, get project level obj. (Seperate build obj is not available if project level permissions are being used on pipeline)
                if(($obj | Measure-Object).Count -eq 0)
                {
                    $obj = [Build]::BuildNamespacesObj | where-object {$_.token -eq $this.BuildObj.project.id}
                }

                if(($obj | Measure-Object).Count -gt 0)
                {
                    $properties = $obj.acesDictionary | Get-Member -MemberType Properties
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
                                $displayName = $responseObj.customDisplayName  #For User identity type
                            }
                            else{
                                $displayName = $responseObj.providerDisplayName
                            }

                            if($responseObj.providerDisplayName -notmatch  $exemptedUserIdentities)
                            {
                                $AllowedPermissionsInBit = $obj.acesDictionary.$($_.Name).extendedInfo.allow
                                if([Helpers]::CheckMember($obj.acesDictionary.$($_.Name).extendedInfo,"inheritedAllow"))
                                {
                                    $InheritedAllowedPermissionsInBit = $obj.acesDictionary.$($_.Name).extendedInfo.inheritedAllow
                                }

                                $permissions = [Helpers]::ResolveAllPermissions($AllowedPermissionsInBit ,$InheritedAllowedPermissionsInBit, [Build]::BuildNamespacesPermissionObj.actions)
                                if(($permissions | Measure-Object).Count -ne 0)
                                {
                                    $accessList += New-Object -TypeName psobject -Property @{IdentityName= $displayName ; IdentityType= $responseObj.properties.SchemaClassName.'$value'; Permissions = $permissions}
                                }
                            }
                        }

                        if(($accessList | Measure-Object).Count -ne 0)
                        {
                            $accessList = $accessList | sort-object -Property IdentityName, IdentityType
                            $controlResult.AddMessage("Total number of identities that have access to build pipeline: ", ($accessList | Measure-Object).Count);
                            $controlResult.AddMessage([VerificationResult]::Verify,"Validate that the following identities have been provided with minimum RBAC access to [$($this.ResourceContext.ResourceName)] pipeline.", $accessList);
                            $controlResult.SetStateData("Build pipeline access list: ", $accessList);
                            $controlResult.AdditionalInfo += "Total number of identities that have access to build pipeline: " + ($accessList | Measure-Object).Count;
                            $controlResult.AdditionalInfo += "Total number of user identities that have access to build pipeline: " + (($accessList | Where-Object {$_.IdentityType -eq 'user'}) | Measure-Object).Count;
                            $controlResult.AdditionalInfo += "Total number of group identities that have access to build pipeline: " + (($accessList | Where-Object {$_.IdentityType -eq 'group'}) | Measure-Object).Count;

                        }
                        else
                        {
                            $controlResult.AddMessage([VerificationResult]::Passed,"No identities have been explicitly provided with RBAC access to [$($this.ResourceContext.ResourceName)] other than build pipeline owner and default groups");
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
                # Step 1: Fetch list of all groups/users with access to this build
                # Here 'permissionSet' = security namespace identifier, 'token' = project id and 'tokenDisplayVal' = build name
                $buildDefinitionPath = $this.BuildObj.Path.Trim("\").Replace(" ","+").Replace("\","%2F")
                $apiURL = "https://dev.azure.com/{0}/{1}/_api/_security/ReadExplicitIdentitiesJson?__v=5&permissionSetId={2}&permissionSetToken={3}%2F{4}%2F{5}" -f $($this.OrganizationContext.OrganizationName), $($this.BuildObj.project.id), $([Build]::SecurityNamespaceId), $($this.BuildObj.project.id), $($buildDefinitionPath), $($this.BuildObj.id);

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

                # Step2: Fetch detailed permissions of each of group/user from above api call
                # To be evaluated only when -DetailedScan flag is used in GADS command along with control ids  or when controls are to be attested
                if([AzSKRoot]::IsDetailedScanRequired -eq $true)
                {
                    # build owner
                    $exemptedUserIdentities += $this.BuildObj.authoredBy.id
                    if(($responseObj.identities|Measure-Object).Count -gt 0)
                    {
                        $exemptedUserIdentities += $responseObj.identities | Where-Object { $_.IdentityType -eq "user" }| ForEach-Object {
                            $identity = $_
                            $exemptedIdentity = $this.ControlSettings.Build.ExemptedUserIdentities | Where-Object { $_.Domain -eq $identity.Domain -and $_.DisplayName -eq $identity.DisplayName }
                            if(($exemptedIdentity | Measure-Object).Count -gt 0)
                            {
                                return $identity.TeamFoundationId
                            }
                        }

                        $accessList += $responseObj.identities | Where-Object { $_.IdentityType -eq "user" } | ForEach-Object {
                            $identity = $_
                            if($exemptedUserIdentities -notcontains $identity.TeamFoundationId)
                            {
                                $apiURL = "https://dev.azure.com/{0}/{1}/_api/_security/DisplayPermissions?__v=5&tfid={2}&permissionSetId={3}&permissionSetToken={4}%2F{5}%2F{6}" -f $($this.OrganizationContext.OrganizationName), $($this.BuildObj.project.id), $($identity.TeamFoundationId) ,$([Build]::SecurityNamespaceId),$($this.BuildObj.project.id), $($buildDefinitionPath), $($this.BuildObj.id);
                                $identityPermissions = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
                                $configuredPermissions = $identityPermissions.Permissions | Where-Object {$_.permissionDisplayString -ne 'Not set'}
                                return @{ IdentityName = $identity.DisplayName; IdentityType = $identity.IdentityType; Permissions = ($configuredPermissions | Select-Object @{Name="Name"; Expression = {$_.displayName}},@{Name="Permission"; Expression = {$_.permissionDisplayString}}) }
                            }
                        }

                        $accessList += $responseObj.identities | Where-Object { $_.IdentityType -eq "group" } | ForEach-Object {
                            $identity = $_
                            $apiURL = "https://dev.azure.com/{0}/{1}/_api/_security/DisplayPermissions?__v=5&tfid={2}&permissionSetId={3}&permissionSetToken={4}%2F{5}%2F{6}" -f $($this.OrganizationContext.OrganizationName), $($this.BuildObj.project.id), $($identity.TeamFoundationId) ,$([Build]::SecurityNamespaceId),$($this.BuildObj.project.id), $($buildDefinitionPath), $($this.BuildObj.id);
                            $identityPermissions = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
                            $configuredPermissions = $identityPermissions.Permissions | Where-Object {$_.permissionDisplayString -ne 'Not set'}
                            return @{ IdentityName = $identity.DisplayName; IdentityType = $identity.IdentityType; IsAadGroup = $identity.IsAadGroup ;Permissions = ($configuredPermissions | Select-Object @{Name="Name"; Expression = {$_.displayName}},@{Name="Permission"; Expression = {$_.permissionDisplayString}}) }
                        }
                    }
                    if(($accessList | Measure-Object).Count -ne 0)
                    {
                        $accessList= $accessList | Select-Object -Property @{Name="IdentityName"; Expression = {$_.IdentityName}},@{Name="IdentityType"; Expression = {$_.IdentityType}},@{Name="Permissions"; Expression = {$_.Permissions}}
                        $controlResult.AddMessage("Total number of identities that have access to build pipeline: ", ($accessList | Measure-Object).Count);
                        $controlResult.AddMessage([VerificationResult]::Verify,"Validate that the following identities have been provided with minimum RBAC access to [$($this.ResourceContext.ResourceName)] pipeline.", $accessList);
                        $controlResult.SetStateData("Build pipeline access list: ", ($responseObj.identities | Select-Object -Property @{Name="IdentityName"; Expression = {$_.FriendlyDisplayName}},@{Name="IdentityType"; Expression = {$_.IdentityType}},@{Name="Scope"; Expression = {$_.Scope}}));
                        $controlResult.AdditionalInfo += "Total number of identities that have access to build pipeline: " + ($accessList | Measure-Object).Count;
                        $controlResult.AdditionalInfo += "Total number of user identities that have access to build pipeline: " + (($accessList | Where-Object {$_.IdentityType -eq 'user'}) | Measure-Object).Count;
                        $controlResult.AdditionalInfo += "Total number of group identities that have access to build pipeline: " + (($accessList | Where-Object {$_.IdentityType -eq 'group'}) | Measure-Object).Count;
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed,"No identities have been explicitly provided with RBAC access to [$($this.ResourceContext.ResourceName)] other than build pipeline owner and default groups");
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
                        $controlResult.AddMessage("Total number of identities that have access to build pipeline: ", ($accessList | Measure-Object).Count);
                        $controlResult.AddMessage([VerificationResult]::Verify,"Validate that the following identities have been provided with minimum RBAC access to [$($this.ResourceContext.ResourceName)] pipeline.", $accessList);
                        $controlResult.SetStateData("Build pipeline access list: ", $accessList);
                        $controlResult.AdditionalInfo += "Total number of identities that have access to build pipeline: " + ($accessList | Measure-Object).Count;
                        $controlResult.AdditionalInfo += "Total number of user identities that have access to build pipeline: " + (($accessList | Where-Object {$_.IdentityType -eq 'user'}) | Measure-Object).Count;
                        $controlResult.AdditionalInfo += "Total number of group identities that have access to build pipeline: " + (($accessList | Where-Object {$_.IdentityType -eq 'group'}) | Measure-Object).Count;
                    }
                }

            # $accessList = $null;
                $responseObj = $null;
            }
            catch
            {
                $failMsg = $_
                $controlResult.LogException($_)
            }

            if(![string]::IsNullOrEmpty($failMsg))
            {
                $controlResult.AddMessage([VerificationResult]::Manual,"Unable to fetch build pipeline details. $($failMsg)Please verify from portal all teams/groups are granted minimum required permissions on build definition.");
            }
        }

        return $controlResult
    }

    hidden [ControlResult] CheckSettableAtQueueTime([ControlResult] $controlResult)
	{
      try {

        if([Helpers]::CheckMember($this.BuildObj[0],"variables"))
        {
           $setablevar =@();
           $nonsetablevar =@();

           Get-Member -InputObject $this.BuildObj[0].variables -MemberType Properties | ForEach-Object {
            if([Helpers]::CheckMember($this.BuildObj[0].variables.$($_.Name),"allowOverride") )
            {
                $setablevar +=  $_.Name;
            }
            else {
                $nonsetablevar +=$_.Name;
            }
           }
           if(($setablevar | Measure-Object).Count -gt 0){
                $controlResult.AddMessage("Total number of variables that are settable at queue time: ", ($setablevar | Measure-Object).Count);
                $controlResult.AddMessage([VerificationResult]::Verify,"The below variables are settable at queue time: ",$setablevar);
                $controlResult.AdditionalInfo += "Total number of variables that are settable at queue time: " + ($setablevar | Measure-Object).Count;
                $controlResult.SetStateData("Variables settable at queue time: ", $setablevar);
                if ($nonsetablevar) {
                    $controlResult.AddMessage("The below variables are not settable at queue time: ",$nonsetablevar);
                }
           }
           else
           {
                $controlResult.AddMessage([VerificationResult]::Passed, "No variables were found in the build pipeline that are settable at queue time.");
           }

        }
        else {
            $controlResult.AddMessage([VerificationResult]::Passed,"No variables were found in the build pipeline");
        }
       }
       catch {
           $controlResult.AddMessage([VerificationResult]::Manual,"Could not fetch build pipeline variables.");
           $controlResult.LogException($_)
       }
     return $controlResult;
    }

    hidden [ControlResult] CheckSettableAtQueueTimeForURL([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Verify
        try
        {
            if ([Helpers]::CheckMember($this.BuildObj[0], "variables"))
            {
                $settableURLVars = @();
                $settableURLbackup = @();
                if($null -eq [Build]::RegexForURL)
                {
                    $this.FetchRegexForURL()
                }
                $regexForURLs = [Build]::RegexForURL;
                $allVars = Get-Member -InputObject $this.BuildObj[0].variables -MemberType Properties

                $allVars | ForEach-Object {
                    if ([Helpers]::CheckMember($this.BuildObj[0].variables.$($_.Name), "allowOverride") )
                    {
                        $varName = $_.Name;
                        $varValue = $this.BuildObj[0].variables.$($varName).value;
                        $override= $this.BuildObj[0].variables.$($varName).allowOverride;
                        for ($i = 0; $i -lt $regexForURLs.RegexList.Count; $i++) {
                            if ($varValue -match $regexForURLs.RegexList[$i]) {
                                $settableURLVars += @( [PSCustomObject] @{ Name = $varName; Value = $varValue; Allowoverride = $override  })
                                $settableURLbackup += @( [PSCustomObject] @{ Name = $varName; Allowoverride = $override  } ) 
                                break
                            }
                        }
                    }
                }
                
                $varCount = $settableURLVars.Count
                if ($varCount -gt 0)
                {
                    $controlResult.AddMessage("Count of variables that are settable at queue time and contain URL value: $($varCount)");
                    $controlResult.AddMessage([VerificationResult]::Verify, "List of variables settable at queue time and containing URL value: `n", $($settableURLVars | FT | Out-String));
                    $controlResult.AdditionalInfo += "Count of variables that are settable at queue time and contain URL value: " + $varCount;
                    $controlResult.SetStateData("List of variables settable at queue time and containing URL value: ", $settableURLVars);
                    if ($this.ControlFixBackupRequired -or $this.BaselineConfigurationRequired)
                            {
                                #Data object that will be required to fix the control
                                $controlResult.BackupControlState = $settableURLbackup;
                            }
                            if($this.BaselineConfigurationRequired){
                                $controlResult.AddMessage([Constants]::BaselineConfigurationMsg -f $this.ResourceContext.ResourceName);
                                $this.CheckSettableAtQueueTimeForURLAutomatedFix($controlResult);
                                
                            }
                    
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No variables were found in the build pipeline that are settable at queue time and contain URL value.");
                }        
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "No variables were found in the build pipeline.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch variables of the build pipeline.");
            $controlResult.LogException($_)
        }
        return $controlResult;
    }
    hidden [ControlResult] CheckSettableAtQueueTimeForURLAutomatedFix([ControlResult] $controlResult){
        try {
            $RawDataObjForControlFix = @();
            if($this.BaselineConfigurationRequired){
                $RawDataObjForControlFix = $controlResult.BackupControlState;
            }
            else{
                $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject
            }

            $uri = "https://dev.azure.com/{0}/{1}/_apis/build/definitions/{2}?api-version=5.0-preview.6" -f ($this.OrganizationContext.OrganizationName), $($this.BuildObj.project.id), $($this.BuildObj.id) 
            $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($uri)
            if (-not $this.UndoFix) {
                $RawDataObjForControlFix | ForEach-Object {
                if ([Helpers]::CheckMember($this.BuildObj[0].variables.$($_.Name), "allowOverride")  ){ $this.BuildObj[0].variables.$($_.Name).allowOverride = $false;}  }
                $body = $this.BuildObj[0] | ConvertTo-Json -Depth 10
                $buildDefnsObj = Invoke-RestMethod -Uri $uri -Method PUT -ContentType "application/json" -Headers $header -Body $body
                $controlResult.AddMessage([VerificationResult]::Fixed,"The following pipeline variables unmarked settable at queue time and containing URLs :");
                $display = ($RawDataObjForControlFix.Name |  FT -AutoSize | Out-String -Width 512)
                $controlResult.AddMessage("$display"); 
            }
            else {
                $allVars = Get-Member -InputObject $this.BuildObj[0].variables -MemberType Properties
                $allVars | ForEach-Object {
                    
                if (-not [Helpers]::CheckMember($this.BuildObj[0].variables.$($_.Name), "allowOverride")) {
                    $new_name = $($_.Name)
                    $filteredName = $RawDataObjForControlFix | Where-Object { $_.Name -eq $new_name } 
                    if($filteredName -ne $null){
                    $this.BuildObj[0].variables.$($filteredName.Name)  |  Add-Member -Name 'allowoverride' -Type NoteProperty -Value $true
                    }
                }
            
            }
                $body = $this.BuildObj[0] | ConvertTo-Json -Depth 10
                $buildDefnsObj = Invoke-RestMethod -Uri $uri -Method PUT -ContentType "application/json" -Headers $header -Body $body
                $controlResult.AddMessage([VerificationResult]::Fixed,"The following pipeline variables marked settable at queue time and containing URLs:");
                $display = ($RawDataObjForControlFix.Name |  FT -AutoSize | Out-String -Width 512)
                $controlResult.AddMessage("$display");  
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }
    <#$this.BuildObj[0].variables | ForEach-Object {
                $_ | ForEach-Object { 
                $new_name = $_ 
                $RawDataObjForControlFix | Where-Object { $_ -eq $new_name } |Add-Member -Name 'allowoverride' -Type NoteProperty -Value $true } } #>

    hidden [ControlResult] CheckExternalSources([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Verify
        $sourceObj = $this.BuildObj[0].repository | Select-Object -Property @{Name="RepositoryName"; Expression = {$_.Name}},@{Name="RepositorySourceType"; Expression = {$_.type}}
        $checkforPipelineRepo = $true
        #check if pipeline is yaml
        if([Helpers]::CheckMember($this.BuildObj[0].process,"yamlFilename")){

            #repos checked inside the yaml file are available only when build id is present, if it present we check for repos checked inside yaml
            if([Helpers]::CheckMember($this.BuildObj[0],"latestBuild") -and [Helpers]::CheckMember($this.BuildObj[0].latestBuild, "id")){
                $latestBuildId = $this.BuildObj[0].latestBuild.id
                $checkforPipelineRepo = $false
                $url = "https://dev.azure.com/{0}/{1}/_traceability/runview/changes?currentRunId={2}&__rt=fps&__ver=2" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName, $latestBuildId
                
                try{
                    $response = [WebRequestHelper]::InvokeGetWebRequest($url);
                    $externalSourceObj = @()
                    $repoSource = $this.BuildObj[0].repository.type
                    #check if multiple repos are defined, it will also contain pipeline source repo
                    if([Helpers]::CheckMember($response,"fps.dataProviders.data") -and $response.fps.dataProviders.data.'ms.vss-traceability-web.traceability-run-changes-data-provider' -and [Helpers]::CheckMember($response.fps.dataProviders.data.'ms.vss-traceability-web.traceability-run-changes-data-provider','artifactsData')){                        
                        $externalSourceObj  =  @($response.fps.dataProviders.data.'ms.vss-traceability-web.traceability-run-changes-data-provider'.artifactsData.repository | Where-Object {$_. type -ne 'TfsGit' -and $_. type -ne 'TfsVersionControl' -and $_.id -ne $this.BuildObj[0].repository.id  })
                    }
                    if($externalSourceObj.count -gt 0){
                        $externalSourceObj = $externalSourceObj | Select-Object -Property @{Name="RepositoryName"; Expression = {$_.Name}},@{Name="RepositorySourceType"; Expression = {$_.type}}
                        $display = @()
                        $display+=$externalSourceObj
                        #if pipeline source is trusted but yaml contains repos from untrusted sources
                        if(($repoSource -eq 'TfsGit') -or ($repoSource -eq 'TfsVersionControl')){
                            $controlResult.AddMessage([VerificationResult]::Verify,"Pipeline code is built from trusted repository but contains untrusted sources as well: ");
                        }
                        #pipeline source is untrusted and yaml checks out other untrusted sources as well
                        else{
                            $controlResult.AddMessage([VerificationResult]::Verify,"Pipeline code is built from untrusted repository as well as contains untrusted sources: ");
                            $display += $sourceObj
                            
                        }
                        $display = ($display | FT -AutoSize | Out-String -Width 512) 
                        $controlResult.AddMessage($display)                                              
                        $controlResult.SetStateData("Pipeline code is built from external repository: ",$display)
                        $controlResult.AdditionalInfo += $externalSourceObj
                        $controlResult.AdditionalInfo += $sourceObj
                        $controlResult.AdditionalInfoInCSV += $externalSourceObj
                        $controlResult.AdditionalInfoInCSV += $sourceObj
                    }
                    #no other repos have been defined in yaml
                    else{
                        #check pipeline sources
                        $checkforPipelineRepo = $true
                    }
                    
                    
                }
                catch{
                    $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch pipeline details");
                }
            }
                     
        }
        #if pipeline is classic or if build id not present (in yaml pipeline) we check for pipeline source repo type   
        if($checkforPipelineRepo -eq $true){
            if( ($this.BuildObj[0].repository.type -eq 'TfsGit') -or ($this.BuildObj[0].repository.type -eq 'TfsVersionControl'))
            {
                    $controlResult.AddMessage([VerificationResult]::Passed,"Pipeline code is built from trusted repository: ");
                    $display = ($sourceObj|FT  -AutoSize | Out-String -Width 512)
                    $controlResult.AddMessage($display)
                    $controlResult.SetStateData("Pipeline code is built from trusted repository: ",$sourceObj)                
            }
            else
            {
                    $controlResult.AddMessage([VerificationResult]::Verify,"Pipeline code is built from external repository: ");
                    $display = ($sourceObj|FT  -AutoSize | Out-String -Width 512)
                    $controlResult.AddMessage($display)
                    $controlResult.SetStateData("Pipeline code is built from external repository: ",$sourceObj)
            }
            $controlResult.AdditionalInfo = "$($sourceObj.repositoryName) : $($this.BuildObj[0].repository.type)";
            $controlResult.AdditionalInfoInCSV = "$($sourceObj.repositoryName) : $($this.BuildObj[0].repository.type)"
        }

        $sourceObj = $null;
        

        return $controlResult;
    }

    hidden [ControlResult] CheckTaskGroupEditPermission([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed

        #Task groups have type 'metaTask' whereas individual tasks have type 'task'
        $taskGroups = @();

        if ([Build]::IsOAuthScan -eq $true)
        {
            if([Helpers]::CheckMember($this.BuildObj[0].process,"phases")) #phases is not available for YAML-based pipelines.
            {
                if([Helpers]::CheckMember($this.BuildObj[0].process.phases[0],"steps"))
                {
                    $taskGroups += $this.BuildObj[0].process.phases[0].steps | Where-Object {$_.task.definitiontype -eq 'metaTask'}
                }
                $editableTaskGroups = @();
                if(($taskGroups | Measure-Object).Count -gt 0  -and ([Build]::TaskGroupNamespacesObj | Measure-Object).Count -gt 0 -and ([Build]::TaskGroupNamespacePermissionObj | Measure-Object).Count -gt 0 )
                {
                    try
                    {
                        $taskGroups | ForEach-Object {
                            $taskGrpId = $_.task.id
                            $permissionsInBit = 0

                            #Get ACL for this taskgroup
                            $resource = $this.BuildObj.project.id+ "/" + $taskGrpId
                            $obj = [Build]::TaskGroupNamespacesObj | where-object {$_.token -eq $resource}
                            $properties = $obj.acesDictionary | Get-Member -MemberType Properties

                            #Use descriptors from acl to make identities call, using each descriptor see permissions mapped to Contributors
                            $properties | ForEach-Object{
                                if ($permissionsInBit -eq 0) {
                                    $apiUrlIdentity = "https://vssps.dev.azure.com/{0}/_apis/identities?descriptors={1}&api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $($obj.acesDictionary.$($_.Name).descriptor)
                                    $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiUrlIdentity);
                                    if ($responseObj.providerDisplayName -eq "[$($this.BuildObj.project.name)]\Contributors")
                                    {
                                        $permissionsInBit = $obj.acesDictionary.$($_.Name).extendedInfo.effectiveAllow
                                    }
                                }
                            }

                            # ResolvePermissions method returns object if 'Edit task group' is allowed
                            $obj = [Helpers]::ResolvePermissions($permissionsInBit, [Build]::TaskGroupNamespacePermissionObj.actions, 'Edit task group')
                            if (($obj | Measure-Object).Count -gt 0){
                                $TGActualName ="";
                                try {
                                    $tgURL = "https://dev.azure.com/{0}/{1}/_apis/distributedtask/taskgroups/{2}?api-version=6.0-preview.1" -f $($this.OrganizationContext.OrganizationName), $projectName, $taskGrpId ;
                                    $tgDetails = [WebRequestHelper]::InvokeGetWebRequest($tgURL);

                                    if([Helpers]::CheckMember($tgDetails,"name")) {
                                        $TGActualName= $tgDetails.name;
                                    }
                                }
                                catch {
                                }
                                $editableTaskGroups += New-Object -TypeName psobject -Property @{DisplayName = $_.displayName; TGActualName = $TGActualName;}
                            }
                        }
                        if(($editableTaskGroups | Measure-Object).Count -gt 0)
                        {
                            $controlResult.AddMessage("Total number of task groups on which contributors have edit permissions in build definition: ", ($editableTaskGroups | Measure-Object).Count);
                            #$controlResult.AdditionalInfo += "Total number of task groups on which contributors have edit permissions in build definition: " + ($editableTaskGroups | Measure-Object).Count;
                            $controlResult.AddMessage([VerificationResult]::Failed,"Contributors have edit permissions on the below task groups used in build definition: ", $editableTaskGroups);
                            $controlResult.SetStateData("List of task groups used in build definition that contributors can edit: ", $editableTaskGroups);

                            $groups = $editableTaskGroups | ForEach-Object {"TGName:"+ $_.DisplayName + ",TGActualName:" +$_.TGActualName } 
                            $addInfo = "NumTG: $($taskGroups.Count); List: $($groups -join '; ')"
                            $controlResult.AdditionalInfo += $addInfo;
                            $controlResult.AdditionalInfoInCSV += $addInfo;
                        }
                        else
                        {
                            $controlResult.AddMessage([VerificationResult]::Passed,"Contributors do not have edit permissions on any task groups used in build definition.");
                            $controlResult.AdditionalInfoInCSV = "NA";
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
                    $controlResult.AddMessage([VerificationResult]::Passed,"No task groups found in build definition.");
                    $controlResult.AdditionalInfoInCSV = "NA";
                }
            }
            else
            {
                if([Helpers]::CheckMember($this.BuildObj[0].process,"yamlFilename")) #if the pipeline is YAML-based - control should pass as task groups are not supported for YAML pipelines.
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,"Task groups are not supported in YAML pipelines.");
                    $controlResult.AdditionalInfoInCSV = "NA";
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch the list of task groups used in the pipeline.");
                }
            }
        }
        else {

                if([Helpers]::CheckMember($this.BuildObj[0].process.phases[0],"steps"))
                {
                    $taskGroups += $this.BuildObj[0].process.phases[0].steps | Where-Object {$_.task.definitiontype -eq 'metaTask' -and $_.enabled -eq $true}
                }
                $editableTaskGroups = @();
                $groupsWithExcessivePermissionsList = @();
                if(($taskGroups | Measure-Object).Count -gt 0)
                {
                    $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1" -f $($this.OrganizationContext.OrganizationName)
                    $projectId = $this.BuildObj.project.id
                    $projectName = $this.BuildObj.project.name

                    try
                    {
                        $taskGroups | ForEach-Object {
                            $taskGrpId = $_.task.id
                            $taskGrpURL="https://dev.azure.com/{0}/{1}/_taskgroup/{2}" -f $($this.OrganizationContext.OrganizationName), $($projectName), $($taskGrpId)
                            $permissionSetToken = "$projectId/$taskGrpId"

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
                                foreach($broadGroupObj in $contributorObj)
                                {
                                    $contributorInputbody = "{
                                        'contributionIds': [
                                            'ms.vss-admin-web.security-view-permissions-data-provider'
                                        ],
                                        'dataProviderContext': {
                                            'properties': {
                                                'subjectDescriptor': '$($broadGroupObj.descriptor)',
                                                'permissionSetId': 'f6a4de49-dbe2-4704-86dc-f8ec1a294436',
                                                'permissionSetToken': '$permissionSetToken',
                                                'accountName': '$(($broadGroupObj.principalName).Replace('\','\\'))',
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
                                        $TGActualName ="";
                                        try {
                                            $tgURL = "https://dev.azure.com/{0}/{1}/_apis/distributedtask/taskgroups/{2}?api-version=6.0-preview.1" -f $($this.OrganizationContext.OrganizationName), $projectName, $taskGrpId ;
                                            $tgDetails = [WebRequestHelper]::InvokeGetWebRequest($tgURL);

                                            if([Helpers]::CheckMember($tgDetails,"name")) {
                                                $TGActualName= $tgDetails.name;
                                            }
                                        }
                                        catch {
                                        }
                                        $editableTaskGroups += New-Object -TypeName psobject -Property @{DisplayName = $_.displayName; TGActualName = $TGActualName; GroupName = $broadGroupObj.principalName}
                                        
                                        $excessivePermissionsGroupObj = @{}
                                        $excessivePermissionsGroupObj['TaskGroupId'] = $taskGrpId
                                        $excessivePermissionsGroupObj['TaskGroupName'] = $_.displayName
                                        $excessivePermissionsGroupObj['Group'] = $broadGroupObj.principalName
                                        #$excessivePermissionsGroupObj['ExcessivePermissions'] = $($excessivePermissionsPerGroup.displayName -join ', ')
                                        $excessivePermissionsGroupObj['ExcessivePermissions'] =  "Edit task group" #$($editableTaskGroups.displayName -join ', ')
                                        $excessivePermissionsGroupObj['Descriptor'] = $broadGroupObj.sid
                                        $excessivePermissionsGroupObj['PermissionSetToken'] = $permissionSetToken
                                        $excessivePermissionsGroupObj['PermissionSetId'] = [Build]::TaskGroupSecurityNamespace
                                        $groupsWithExcessivePermissionsList += $excessivePermissionsGroupObj
                                    }
                                }
                            }
                        }
                        $editableTaskGroupsCount = $editableTaskGroups.Count
                        if($editableTaskGroupsCount -gt 0)
                        {
                            $controlResult.AddMessage("Count of task groups on which contributors have edit permissions in build definition: $editableTaskGroupsCount");
                            #$controlResult.AdditionalInfo += "Count of task groups on which contributors have edit permissions in build definition: " + $editableTaskGroupsCount;
                            $controlResult.AddMessage([VerificationResult]::Failed,"Contributors have edit permissions on the below task groups used in build definition: ");
                            $display = $editableTaskGroups|FT  -AutoSize | Out-String -Width 512
                            $controlResult.AddMessage($display)
                            $controlResult.SetStateData("List of task groups used in build definition that contributors can edit: ", $editableTaskGroups);
                            
                            $groups = $editableTaskGroups | ForEach-Object {"TGName:"+ $_.DisplayName + ",TGActualName:" +$_.TGActualName }  
                            $addInfo = "NumTG: $($taskGroups.Count); NumTGWithEditPerm: $($editableTaskGroupsCount); List: $($groups -join '; ')"
                            $controlResult.AdditionalInfo += $addInfo;
                            $controlResult.AdditionalInfoInCSV += $addInfo;

                            if ($this.ControlFixBackupRequired -or $this.BaselineConfigurationRequired)
                            {
                                #Data object that will be required to fix the control
                                $controlResult.BackupControlState = $groupsWithExcessivePermissionsList;
                            }
                            if($this.BaselineConfigurationRequired){
                                $controlResult.AddMessage([Constants]::BaselineConfigurationMsg -f $this.ResourceContext.ResourceName);
                                $this.CheckTaskGroupEditPermissionAutomatedFix($controlResult);
                                
                            }
                        }
                        else
                        {
                            $controlResult.AdditionalInfoInCSV = "NA"
                            $controlResult.AdditionalInfo += "Contributors do not have edit permissions on any task groups used in build definition."
                            $controlResult.AddMessage([VerificationResult]::Passed,"Contributors do not have edit permissions on any task groups used in build definition.");
                        }
                        if($taskGroups.Count -ne $editableTaskGroups.Count)
                        {
                            if ($editableTaskGroups.Count -gt 0)
                            {
                                $nonEditableTaskGroups = $taskGroups | where-object {$editableTaskGroups.DisplayName -notcontains $_.DisplayName}
                            }
                            else
                            {
                                $nonEditableTaskGroups = $taskGroups
                            }
                            $groups = $nonEditableTaskGroups | ForEach-Object { $_.DisplayName } 
                            if ($controlResult.AdditionalInfoInCSV -eq "NA") {
                                $controlResult.AdditionalInfoInCSV = "NonEditableTGList: $($groups -join '; ');"
                            }
                            else {
                                $controlResult.AdditionalInfoInCSV += "NonEditableTGList: $($groups -join '; ');"
                            }
                            $controlResult.AdditionalInfo += "NonEditableTGList: $($groups -join '; ');"
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
                    $controlResult.AdditionalInfo += "No task groups found in build definition.";
                    $controlResult.AddMessage([VerificationResult]::Passed,"No task groups found in build definition.");
                }
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckTaskGroupEditPermissionAutomatedFix([ControlResult] $controlResult)
    {
        try {
            $RawDataObjForControlFix = @();
            if($this.BaselineConfigurationRequired){
                $RawDataObjForControlFix = $controlResult.BackupControlState;
            }
            else{
                $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject
            }

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

        if([Helpers]::CheckMember($this.BuildObj[0],"variableGroups"))
        {
            $varGrps = $this.BuildObj[0].variableGroups
            $projectId = $this.BuildObj.project.id
            $editableVarGrps = @();
            try
            {
                $failedCount = 0
                $erroredCount = 0
                foreach($currentVarGrp in $varGrps)
                {
                    if([Helpers]::CheckMember($currentVarGrp,"name"))  ## Deleted VGs do not contain "name" property thats why ignoring them
                    {
                        if ([Build]::broadlyEditableVG.keys -notcontains $currentVarGrp.name)
                        {
                            try {
                                $url = 'https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.variablegroup/roleassignments/resources/{1}%24{2}?api-version=6.1-preview.1' -f $($this.OrganizationContext.OrganizationName), $($projectId), $($currentVarGrp.Id);
                                $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($url));
                                if($responseObj.Count -gt 0)
                                {                        
                                    if([Build]::isInheritedPermissionCheckEnabled)
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
                                                $failedCount = $failedCount +1
                                                $editableVarGrps += $currentVarGrp.name
                                                
                                                $formattedVarGroupsData = $obj | Select @{l = 'displayName'; e = { $_.identity.displayName } }, @{l = 'userid'; e = { $_.identity.id } }, @{l = 'role'; e = { $_.role.name } }, @{l = 'vargrpid'; e = { $currentVarGrp.id } } , @{l = 'vargrpname'; e = { $currentVarGrp.name } }                                     
                                            
                                                if ($this.ControlFixBackupRequired -or $this.BaselineConfigurationRequired) {
                                                    #Data object that will be required to fix the control                                            
                                                    $controlResult.BackupControlState += $formattedVarGroupsData;
                                                }     
                                                if($this.BaselineConfigurationRequired){
                                                    $controlResult.AddMessage([Constants]::BaselineConfigurationMsg -f $this.ResourceContext.ResourceName);
                                                    $this.CheckVariableGroupEditPermissionAutomatedFix($controlResult);
                                                    
                                                }                                        
                                            }
                                        }                            
                                    }
                                }
    
                                if ($currentVarGrp.name -in $editableVarGrps) {
                                    [Build]::broadlyEditableVG[$currentVarGrp.name] = $true
                                }
                                else {
                                    [Build]::broadlyEditableVG[$currentVarGrp.name] = $false
                                }
                            }
                            catch {
                                $erroredCount = $erroredCount+1
                            }
                        }
                        else
                        {
                            if ([Build]::broadlyEditableVG[$currentVarGrp.name]) {
                                $editableVarGrps += $currentVarGrp.name
                            }
                        }
                    }
                    
                }
                 if($editableVarGrps.Count -gt 0){
                    $editableVarGrpsCount = (($editableVarGrps | Get-Unique) | Measure-Object).Count
                }
                else{
                    $editableVarGrpsCount = 0;
                }
		
                if($editableVarGrpsCount -gt 0)
                {
                    $controlResult.AddMessage("Count of variable groups on which contributors have edit permissions: $($editableVarGrpsCount)");
                    $controlResult.AdditionalInfo += "Count of variable groups on which contributors have edit permissions: " + $editableVarGrpsCount;
                    $controlResult.AddMessage([VerificationResult]::Failed, "`nVariable groups list: `n$($editableVarGrps | FT | Out-String)");
                    $controlResult.SetStateData("Variable groups list: ", $editableVarGrps);
                    $controlResult.AdditionalInfoInCSV = "NumVGs: $editableVarGrpsCount; List: $($editableVarGrps -join '; ')";
                }
                elseif($erroredCount -gt 0) {
                    $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch the RBAC details of variable groups used in the pipeline.");
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,"Contributors do not have edit permissions on any variable groups used in build definition.");
                    $controlResult.AdditionalInfoInCSV += "NA"
                }
            }
            catch
            {
                $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch the RBAC details of variable groups used in the pipeline.");
                $controlResult.LogException($_)
            }

        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Passed,"No variable groups found in build definition.");
            $controlResult.AdditionalInfoInCSV += "NA"
        }

        return $controlResult
    }

    hidden [ControlResult] CheckVariableGroupEditPermissionAutomatedFix([ControlResult] $controlResult)
    {
        try {
            $RawDataObjForControlFix = @();
            $RawDataObjForControlFixTemp = @();
            if($this.BaselineConfigurationRequired){
                $RawDataObjForControlFix = $controlResult.BackupControlState;
            }
            else{
                $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject 
            }
            $RawDataObjForControlFixTemp = $RawDataObjForControlFix
            $projectId = $this.BuildObj.project.id
            $varGrpIds = $RawDataObjForControlFix | Select-Object vargrpid -Unique
            foreach ($vgId in $varGrpIds) {
                $body = "["

                if (-not $this.UndoFix)
                {
                    foreach ($identity in $RawDataObjForControlFix) 
                    {                    
                        if ($body.length -gt 1) {$body += ","}
                        if ($identity.vargrpid -eq $vgId.vargrpid){
                        $body += @"
                            {
                                "userid":"$($identity.userid)",
                                "roleName": "Reader"
                            }
                            
"@;
                        }
                    }
                    $RawDataObjForControlFixTemp | Add-Member -NotePropertyName NewRole -NotePropertyValue "Reader"
                    $RawDataObjForControlFixTemp = @($RawDataObjForControlFix  | Select-Object @{Name="UserName"; Expression={$_.displayName}},@{Name="VarGrpName"; Expression={$_.vargrpname}}, @{Name="OldRole"; Expression={$_.Role}},@{Name="NewRole"; Expression={$_.NewRole}})
                }
                else {
                    foreach ($identity in $RawDataObjForControlFix) 
                    {                    
                        if ($body.length -gt 1) {$body += ","}
                        if ($identity.vargrpid -eq $vgId.vargrpid){
                        $body += @"
                            {
                                "userid": "$($identity.userid)",
                                "roleName": "$($identity.role)"                          
                            }
"@;
                        }
                    }
                    $RawDataObjForControlFixTemp | Add-Member -NotePropertyName OldRole -NotePropertyValue "Reader"
                    $RawDataObjForControlFixTemp = @($RawDataObjForControlFix  | Select-Object @{Name="UserName"; Expression={$_.displayName}},@{Name="VarGrpName"; Expression={$_.vargrpname}}, @{Name="OldRole"; Expression={$_.OldRole}}, @{Name="NewRole"; Expression={$_.Role}})
                }
                $body += "]"  

                #Put request                
                $url = 'https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.variablegroup/roleassignments/resources/{1}%24{2}?api-version=6.1-preview.1' -f $($this.OrganizationContext.OrganizationName),$($projectId) ,$($vgId.vargrpid);
                $rmContext = [ContextHelper]::GetCurrentContext();
                $user = "";
                $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))
                $webRequestResult = Invoke-RestMethod -Uri $url -Method Put -ContentType "application/json" -Headers @{Authorization = ("Basic {0}" -f $base64AuthInfo) } -Body $body	
            }						    
                $controlResult.AddMessage([VerificationResult]::Fixed,  "Contributors edit permissions for variable groups have been changed as below: ");
                $display = ($RawDataObjForControlFixTemp |  FT -AutoSize | Out-String -Width 512)
                $controlResult.AddMessage("`n$display");                                     
    }
    catch {
        $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
        $controlResult.LogException($_)
    }
    return $controlResult
    }

    hidden [ControlResult] CheckBuildAuthZScope([ControlResult] $controlResult)
    {   
        $controlResult.VerificationResult = [VerificationResult]::Failed

        if([Helpers]::CheckMember($this.BuildObj[0],"jobAuthorizationScope"))
        {
            $jobAuthorizationScope = $this.BuildObj[0].jobAuthorizationScope
            if ($jobAuthorizationScope -eq "projectCollection") {
                $controlResult.AddMessage([VerificationResult]::Failed,"Access token of build pipeline is scoped to project collection.");
                if ($this.ControlFixBackupRequired)
                {
                    #Data object that will be required to fix the control
                    $controlResult.BackupControlState = $jobAuthorizationScope;
                }
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed,"Access token of build pipeline is scoped to current project.");
            }
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch pipeline authorization details.");
        }

        return  $controlResult
    }
    hidden [ControlResult] CheckBuildAuthZScopeAutomatedFix([ControlResult] $controlResult)
    {   
        try {
            $RawDataObjForControlFix = @();
            $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject
            
            $uri = "https://dev.azure.com/{0}/{1}/_apis/build/definitions/{2}?api-version=5.0-preview.6" -f ($this.OrganizationContext.OrganizationName), $($this.BuildObj.project.id), $($this.BuildObj.id) 
            $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($uri)
            if (-not $this.UndoFix) {
                $this.BuildObj[0].jobAuthorizationScope = 2;
                $body = $this.BuildObj[0] | ConvertTo-Json -Depth 10
                $buildDefnsObj = Invoke-RestMethod -Uri $uri -Method PUT -ContentType "application/json" -Headers $header -Body $body
                $controlResult.AddMessage([VerificationResult]::Fixed,"Access token of build pipeline has been changed to current project.");
            }
            else {
                $this.BuildObj[0].jobAuthorizationScope = 1;
                $body = $this.BuildObj[0] | ConvertTo-Json -Depth 10
                $buildDefnsObj = Invoke-RestMethod -Uri $uri -Method PUT -ContentType "application/json" -Headers $header -Body $body
                $controlResult.AddMessage([VerificationResult]::Fixed,"Access token of build pipeline has been changed to project collection.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }
    hidden [ControlResult] CheckBroaderGroupAccess([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed

        if ([Build]::IsOAuthScan -eq $true)
        {
            $resource = $this.BuildObj.project.id+ "/" + $this.BuildObj.Id

            # Filter namespaceobj for current build
            $obj = @([Build]::BuildNamespacesObj | where-object {$_.token -eq $resource})

            # If current build object is not found, get project level obj. (Seperate build obj is not available if project level permissions are being used on pipeline)
            if($obj.Count -eq 0)
            {
                $obj = @([Build]::BuildNamespacesObj | where-object {$_.token -eq $this.BuildObj.project.id})
            }

            if($obj.Count -gt 0)
            {
                $properties = $obj.acesDictionary | Get-Member -MemberType Properties
                $permissionsInBit =0
                $editPerms= @();

                try
                {
                    #Use descriptors from acl to make identities call, using each descriptor see permissions mapped to Contributors
                    $properties | ForEach-Object{
                        if ($permissionsInBit -eq 0) {
                            $apiUrlIdentity = "https://vssps.dev.azure.com/{0}/_apis/identities?descriptors={1}&api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $($obj.acesDictionary.$($_.Name).descriptor)
                            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiUrlIdentity);
                            if ($responseObj.providerDisplayName -eq "[$($this.BuildObj.project.name)]\Contributors")
                            {
                                $permissionsInBit = $obj.acesDictionary.$($_.Name).extendedInfo.effectiveAllow
                            }
                        }
                    }

                    # ResolvePermissions method returns object if 'Edit build pipeline' is allowed
                    $editPerms = @([Helpers]::ResolvePermissions($permissionsInBit, [Build]::BuildNamespacesPermissionObj.actions, 'Edit build pipeline'))

                    if($editPerms.Count -gt 0)
                    {
                        $controlResult.AddMessage([VerificationResult]::Failed,"Contributors have edit permissions on the build pipeline.");
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed,"Contributors do not have edit permissions on the build pipeline.");
                        $controlResult.AdditionalInfoInCSV += "NA"
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
        else{
            try
            {
                $orgName = $($this.OrganizationContext.OrganizationName)
                $projectId = $this.BuildObj.project.id
                $projectName = $this.BuildObj.project.name
                $buildId = $this.BuildObj.id
                if ([Helpers]::CheckMember($this.BuildObj, "path") -and ($this.BuildObj.path -ne "\")) {
                    $path = $this.BuildObj.path.Replace('\','/')
                    $permissionSetToken = "$projectId" + "$path/$buildId"
                }
                else {
                    $permissionSetToken = "$projectId/$buildId"
                }
                $restrictedBroaderGroups = @{}
                $broaderGroups = $this.ControlSettings.Build.RestrictedBroaderGroupsForBuild
                if(@($broaderGroups.psobject.Properties).Count -gt 0) {
                    $broaderGroups.psobject.properties | foreach { $restrictedBroaderGroups[$_.Name] = $_.Value }
                    $buildURL = "https://dev.azure.com/$orgName/$projectName/_build?definitionId=$buildId"

                    $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery/project/{1}?api-version=5.0-preview.1" -f $orgName, $projectId
                    $inputbody = "{
                    'contributionIds': [
                        'ms.vss-admin-web.security-view-members-data-provider'
                    ],
                    'dataProviderContext': {
                        'properties': {
                            'permissionSetId': '$([Build]::SecurityNamespaceId)',
                            'permissionSetToken': '$permissionSetToken',
                            'sourcePage': {
                                'url': '$buildURL',
                                'routeId': 'ms.vss-build-web.pipeline-details-route',
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

                    # Web request to fetch the group details for a build definition
                    $responseObj = @([WebRequestHelper]::InvokePostWebRequest($apiURL, $inputbody));
                    if ([Helpers]::CheckMember($responseObj[0], "dataProviders") -and ($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider') -and ([Helpers]::CheckMember($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider', "identities"))) {

                        $broaderGroupsList = @($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider'.identities | Where-Object { $_.subjectKind -eq 'group' -and $restrictedBroaderGroups.keys -contains $_.displayName })

                        <#
                        #Check if inheritance is disabled on build pipeline, if disabled, inherited permissions should be considered irrespective of control settings
                        # Here 'permissionSet' = security namespace identifier, 'token' = project id and 'tokenDisplayVal' = build name
                        $apiURLForInheritedPerms = "https://dev.azure.com/{0}/{1}/_admin/_security/index?useApiUrl=true&permissionSet={2}&token={3}%2F{4}&tokenDisplayVal={5}&style=min" -f $($this.OrganizationContext.OrganizationName), $($this.BuildObj.project.id), $([Build]::SecurityNamespaceId), $($this.BuildObj.project.id), $($this.BuildObj.id), $($this.BuildObj.name) ;
                        $header = [WebRequestHelper]::GetAuthHeaderFromUri($apiURLForInheritedPerms);
                        $responseObj = Invoke-RestMethod -Method Get -Uri $apiURLForInheritedPerms -Headers $header -UseBasicParsing
                        $responseObj = ($responseObj.SelectNodes("//script") | Where-Object { $_.class -eq "permissions-context" }).InnerXML | ConvertFrom-Json;
                        if($responseObj -and [Helpers]::CheckMember($responseObj,"inheritPermissions") -and $responseObj.inheritPermissions -ne $true)
                        {
                            $this.excessivePermissionBits = @(1, 3)
                        }
                        #>

                        # $broaderGroupsList would be empty if none of its permissions are set i.e. all perms are 'Not Set'.

                        if ($broaderGroupsList.Count) {
                            $groupsWithExcessivePermissionsList = @()
                            $filteredBroaderGroupList = @()
                            foreach ($broderGroup in $broaderGroupsList) {
                                $broaderGroupInputbody = "{
                                    'contributionIds': [
                                        'ms.vss-admin-web.security-view-permissions-data-provider'
                                    ],
                                    'dataProviderContext': {
                                        'properties': {
                                            'subjectDescriptor': '$($broderGroup.descriptor)',
                                            'permissionSetId': '$([Build]::SecurityNamespaceId)',
                                            'permissionSetToken': '$permissionSetToken',
                                            'accountName': '$(($broderGroup.principalName).Replace('\','\\'))',
                                            'sourcePage': {
                                                'url': '$buildURL',
                                                'routeId': 'ms.vss-build-web.pipeline-details-route',
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

                                #Web request to fetch RBAC permissions of broader groups on build.
                                $broaderGroupResponseObj = @([WebRequestHelper]::InvokePostWebRequest($apiURL, $broaderGroupInputbody));
                                $broaderGroupRBACObj = @($broaderGroupResponseObj[0].dataProviders.'ms.vss-admin-web.security-view-permissions-data-provider'.subjectPermissions)
                                $excessivePermissionList = $broaderGroupRBACObj | Where-Object { $_.displayName -in $restrictedBroaderGroups[$broderGroup.displayName] }
                                $excessivePermissionsPerGroup = @()
                                $excessivePermissionList | ForEach-Object {
                                    #effectivePermissionValue equals to 1 implies edit build pipeline perms is set to 'Allow'. Its value is 3 if it is set to Allow (inherited). This param is not available if it is 'Not Set'.
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
                                    $excessivePermissionsGroupObj['PermissionSetId'] = [Build]::SecurityNamespaceId
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
                                $controlResult.AddMessage([VerificationResult]::Failed, "Broader groups have excessive permissions on the build pipeline.");
                                $formattedGroupsData = $groupsWithExcessivePermissionsList | Select @{l = 'Group'; e = { $_.Group} }, @{l = 'ExcessivePermissions'; e = { $_.ExcessivePermissions } }
                                $formattedBroaderGrpTable = ($formattedGroupsData | FT -AutoSize | Out-String -width 512)
                                $controlResult.AddMessage("`nList of groups : `n$formattedBroaderGrpTable");
                                $controlResult.AdditionalInfo += "List of excessive permissions on which contributors have access:  $($groupsWithExcessivePermissionsList.Group).";
                                $controlResult.SetStateData("List of groups: ", $formattedGroupsData)
                                $groups = $formattedGroupsData | ForEach-Object { $_.Group + ': ' + $_.ExcessivePermissions } 
                                $controlResult.AdditionalInfoInCSV = $groups -join ' ; '
                                
                                if ($this.ControlFixBackupRequired -or $this.BaselineConfigurationRequired)
                                {
                                    #Data object that will be required to fix the control
                                    
                                    $controlResult.BackupControlState = $groupsWithExcessivePermissionsList;
                                }
                                if($this.BaselineConfigurationRequired){
                                    $controlResult.AddMessage([Constants]::BaselineConfigurationMsg -f $this.ResourceContext.ResourceName);
                                    $this.CheckBroaderGroupAccessAutomatedFix($controlResult);
                                    
                                }
                            }
                            else {
                                $controlResult.AddMessage([VerificationResult]::Passed, "Broader Groups do not have excessive permissions on the build pipeline.");
                                $controlResult.AdditionalInfoInCSV += "NA"
                            }
                        }
                        else {
                            $controlResult.AddMessage([VerificationResult]::Passed, "Broader groups do not have access to the build pipeline.");
                            $controlResult.AdditionalInfoInCSV += "NA"
                        }
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch RBAC details of the pipeline.");
                    }
                    $displayObj = $restrictedBroaderGroups.Keys | Select-Object @{Name = "Broader Group"; Expression = {$_}}, @{Name = "Excessive Permissions"; Expression = {$restrictedBroaderGroups[$_] -join ', '}}
                    $controlResult.AddMessage("`nNote:`nFollowing groups are considered 'broad groups':`n$($displayObj | FT -AutoSize | Out-String -Width 512)");
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Error, "List of restricted broader groups and restricted roles for build is not defined in the control settings for your organization policy.");
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
            if($this.BaselineConfigurationRequired){
                $RawDataObjForControlFix = $controlResult.BackupControlState;
            }
            else{
                $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject
            }
            if (-not $this.UndoFix)
            {
                foreach ($identity in $RawDataObjForControlFix) 
                {
                    
                    $excessivePermissions = $identity.ExcessivePermissions -split ","
                    foreach ($excessivePermission in $excessivePermissions) {
                        $roleId = [int][BuildPermissions] $excessivePermission.Replace(" ","");
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
                        $roleId = [int][BuildPermissions] $excessivePermission.Replace(" ","");
                        
                         $body = "{
                            'token': '$($identity.PermissionSetToken)',
                            'merge': true,
                            'accessControlEntries' : [{
                                'descriptor' : 'Microsoft.TeamFoundation.Identity;$($identity.Descriptor)',
                                'allow':$($roleId),
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

    hidden [ControlResult] CheckForkedBuildTrigger([ControlResult] $controlResult) {
        # Start with initial failed status
        $controlResult.VerificationResult = [VerificationResult]::Failed
        $projectVisibilityCheck = @($this.ControlSettings.Project.ProjectVisibilitiesToCheck)

        if ($projectVisibilityCheck.Count -eq 0) {
            $controlResult.AddMessage([VerificationResult]::Error, "Project visibilities to check are not available in control settings");
            return $controlResult
        }

        if ($projectVisibilityCheck -notcontains $this.ResourceContext.ResourceDetails.project.visibility) {
            $controlResult.AddMessage([VerificationResult]:: Verify), "Project is of visibility: " + $this.ResourceContext.ResourceDetails.project.visibility + ". Current control scan is only applicable for private projects."
            return $controlResult
        }
        
        if ([Helpers]::CheckMember($this.BuildObj[0], "triggers")) {
            # Get triggers from build object
            $pullRequestTrigger = $this.BuildObj[0].triggers | Where-Object { $_.triggerType -eq "pullRequest" }

            if ($pullRequestTrigger) {
                # check fork protection is enabled or not (Limit building pull requests from forked GitHub repositories at project level)
                if ($pullRequestTrigger.pipelineTriggerSettings.forkProtectionEnabled -eq $true) {
                    if (!$pullRequestTrigger.pipelineTriggerSettings.buildsEnabledForForks) {
                        $controlResult.AddMessage([VerificationResult]::Passed, "Pipeline will not build pull requests from forked repositories.");
                    }
                    # Conditions for checking whether to securely build pull requests from forked repositories or not.
                    elseif ($pullRequestTrigger.pipelineTriggerSettings.enforceJobAuthScopeForForks -and $pullRequestTrigger.pipelineTriggerSettings.enforceNoAccessToSecretsFromForks) {
                        $controlResult.AddMessage([VerificationResult]::Passed, "Builds of pull requests from forked repositories do not have access to secrets or have the same permissions as regular builds.");
                    }
                    # check pipeline will build PRs from forked GitHub repos or not.
                    else {
                        if ($pullRequestTrigger.pipelineTriggerSettings.enforceNoAccessToSecretsFromForks) {
                            $controlResult.AddMessage([VerificationResult]::Passed, "Secrets of this pipeline are not available to pipelines triggered by pull requests from public forks of the repository at project level.");
                        }
                        else {
                            $this.CheckBuildLevelPRTriggerSecretSettings($pullRequestTrigger, $controlResult)
                        }
                    }
                }
                else {
                    $this.CheckBuildLevelPRTriggerSecretSettings($pullRequestTrigger, $controlResult)
                }
            }
            else {
                # Pull request trigger is disabled for build pipeline.
                $controlResult.AddMessage([VerificationResult]::Verify, "Pull request validation trigger is not enabled for build pipeline.");
            }
        }
        else {
            # No trigger is enabled for build pipeline
            $controlResult.AddMessage([VerificationResult]::Verify, "No trigger is enabled for build pipeline.");
        }
        return  $controlResult
    }

    hidden [ControlResult] CheckBuildLevelPRTriggerSecretSettings([PSObject] $pullRequestTrigger,[ControlResult] $controlResult){
        # initializing $isRepoPrivate = $true as visibility setting is not available for ADO repositories.
        $isRepoPrivate = $true
        if ([Helpers]::CheckMember($this.BuildObj[0], "repository.properties.IsPrivate")) {
            $isRepoPrivate = $this.BuildObj[0].repository.properties.IsPrivate
        }
        # Check if repo is not private, and pipeline is forked and it allow secrets
        if (($isRepoPrivate -eq $false) -and [Helpers]::CheckMember($pullRequestTrigger, "forks")) {
            if (($pullRequestTrigger.forks.enabled -eq $true) -and ($pullRequestTrigger.forks.allowSecrets -eq $true)) {
                $controlResult.AddMessage([VerificationResult]::Failed, "Pipeline secrets are marked as available to pull request validations of public repo forks.");
                if ($this.ControlFixBackupRequired -or $this.BaselineConfigurationRequired) {
                    #Data object that will be required to fix the control
                    $controlResult.BackupControlState = $pullRequestTrigger.forks.allowSecrets;
                }
                if ($this.BaselineConfigurationRequired) {
                    $controlResult.AddMessage([Constants]::BaselineConfigurationMsg -f $this.ResourceContext.ResourceName);
                    $this.CheckForkedBuildTriggerAutomatedFix($controlResult);           
                }
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed, "Pipeline secrets are not  marked as available to pull request validations of public repo forks.");
            }
        }
        else {
            # This condition means that if pull request trigger is null or repository referred by build is private.
            $controlResult.AddMessage([VerificationResult]::Passed, "Pipeline secrets are not marked as available to pull request validations of public repo forks.");
        }  
        return  $controlResult  
    }

    hidden [ControlResult] CheckForkedBuildTriggerAutomatedFix([ControlResult] $controlResult)
    {   
        try {
            $RawDataObjForControlFix = @();
            if($this.BaselineConfigurationRequired){
                $RawDataObjForControlFix = $controlResult.BackupControlState;
            }
            else{
                $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject
            }

            $uri = "https://dev.azure.com/{0}/{1}/_apis/build/definitions/{2}?api-version=5.0-preview.6" -f ($this.OrganizationContext.OrganizationName), $($this.BuildObj.project.id), $($this.BuildObj.id) 
            $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($uri)
            if (-not $this.UndoFix) {
                $this.BuildObj[0].triggers | foreach {if($_.triggerType -eq "pullRequest" -and [Helpers]::CheckMember($_,"forks") -and  $_.forks.allowSecrets -eq $true){$_.forks.allowSecrets = $false;}}
                $body = $this.BuildObj[0] | ConvertTo-Json -Depth 10
                $buildDefnsObj = Invoke-RestMethod -Uri $uri -Method PUT -ContentType "application/json" -Headers $header -Body $body
                $controlResult.AddMessage([VerificationResult]::Fixed,"Pipeline secrets are marked as unavailable to pull request validations of public repo forks.");
            }
            else {
                $this.BuildObj[0].triggers | foreach {if($_.triggerType -eq "pullRequest" -and [Helpers]::CheckMember($_,"forks") -and $_.forks.allowSecrets -eq $false){$_.forks.allowSecrets = $true;}}
                $body = $this.BuildObj[0] | ConvertTo-Json -Depth 10
                $buildDefnsObj = Invoke-RestMethod -Uri $uri -Method PUT -ContentType "application/json" -Headers $header -Body $body
                $controlResult.AddMessage([VerificationResult]::Fixed,"Pipeline secrets are marked as available to pull request validations of public repo forks.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
            $controlResult.LogException($_)
        }
        return $controlResult
    }

    hidden [ControlResult] CheckForkedRepoOnSHAgent([ControlResult] $controlResult)
    {
        try {
            #If repo made by fork then only 'isFork' property comes.
            if ([Helpers]::CheckMember($this.BuildObj.repository, "properties.isFork") -and $this.BuildObj.repository.properties.isFork -eq $true) {
                #If agent pool is hosted then only 'isHosted' property comes, 'isHosted' property does not comes if pool is non-hosted
                if ([Helpers]::CheckMember($this.BuildObj, "queue.pool") -and !([Helpers]::CheckMember($this.BuildObj.queue.pool,"isHosted") -and $this.BuildObj.queue.pool.isHosted -eq $true ) ) {
                    #https://dev.azure.com/{0}/_apis/distributedtask/pools?poolIds={1}&api-version=6.0
                    $controlResult.AddMessage([VerificationResult]::Failed,"Pipeline builds code from forked repository [$($this.BuildObj.repository.name)] on self-hosted agent [$($this.BuildObj.queue.pool.name)].");
                    $controlResult.AdditionalInfo += "Pipeline builds code from forked repository [$($this.BuildObj.repository.name)] on self-hosted agent [$($this.BuildObj.queue.pool.name)].";
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed,"Pipeline builds code from forked repository [$($this.BuildObj.repository.name)] on hosted agent [$($this.BuildObj.queue.pool.name)].");
                    $controlResult.AdditionalInfo += "Pipeline builds code from forked repository [$($this.BuildObj.repository.name)] on hosted agent [$($this.BuildObj.queue.pool.name)].";
                }
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed,"Pipeline does not build code from forked repository.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch the pipeline details.");
            $controlResult.LogException($_)
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckCIScheduledBuildTrigger([ControlResult] $controlResult)
    {
        if(($this.BuildObj | Measure-Object).Count -gt 0)
        {
            $sourceobj = $this.BuildObj[0].repository | Select-Object -Property @{Name="Name"; Expression = {$_.Name}},@{Name="Type"; Expression = {$_.type}}
            if( ($this.BuildObj[0].repository.type -eq 'TfsGit') -or ($this.BuildObj[0].repository.type -eq 'TfsVersionControl'))
            {
                $controlResult.AddMessage([VerificationResult]::Passed,"Pipeline code is built from trusted repository.",  $sourceobj);
                $controlResult.AdditionalInfo += "Pipeline code is built from trusted repository: " + [JsonHelper]::ConvertToJsonCustomCompressed($sourceobj);
            }
            else {
                $controlResult.AddMessage("Pipeline code is built from untrusted external repository.",  $sourceobj);
                $controlResult.AdditionalInfo += "Pipeline code is built from untrusted external repository: " + [JsonHelper]::ConvertToJsonCustomCompressed($sourceobj);

                if ([Helpers]::CheckMember($this.BuildObj[0], "triggers"))
                {
                    $CITrigger = $this.BuildObj[0].triggers | Where-Object { $_.triggerType -eq "continuousIntegration"}
                    $ScheduledTrigger = $this.BuildObj[0].triggers | Where-Object { $_.triggerType -eq "schedule" }

                    if ($CITrigger -or $ScheduledTrigger)
                    {
                        $flag = $false;

                        if ($CITrigger)
                        {
                            $controlResult.AddMessage([VerificationResult]::Failed, "Continuous integration is enabled for build pipeline.");
                            $flag = $true;
                        }
                        if ($ScheduledTrigger)
                        {
                            if($flag)
                            {
                                $controlResult.AddMessage("Scheduled build is enabled for build pipeline.");
                            }
                            else
                            {
                                $controlResult.AddMessage([VerificationResult]::Failed,"Scheduled build is enabled for build pipeline.");
                            }

                        }

                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed, "Neither continuous integration nor scheduled build are enabled for build pipeline.");
                    }
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No trigger is enabled for build pipeline.");
                }
            }
        }

        return $controlResult;
    }

    hidden FetchRegexForURL()
    {
        [Build]::RegexForURL = @($this.ControlSettings.Patterns | where {$_.RegexCode -eq "URLs"} | Select-Object -Property RegexList);
    }

    hidden CheckActiveBuilds()
    {
        try
        {
                if($this.BuildObj)
                {
                    $inactiveLimit = $this.ControlSettings.Build.BuildHistoryPeriodInDays

                    $this.buildActivityDetail.buildCreationDate = ([datetime] $this.BuildObj.createdDate)

                    if([Helpers]::CheckMember($this.BuildObj[0],"latestBuild") -and $null -ne $this.BuildObj[0].latestBuild)
                    {
                        [datetime] $queueTime = ([datetime] $this.BuildObj[0].latestBuild.queueTime)
                        if ($queueTime -gt (Get-Date).AddDays( - $($this.ControlSettings.Build.BuildHistoryPeriodInDays)))
                        {
                            $this.buildActivityDetail.isBuildActive = $true;
                            $this.buildActivityDetail.message = "Found recent builds triggered within $($this.ControlSettings.Build.BuildHistoryPeriodInDays) days";
                        }
                        else
                        {
                            $this.buildActivityDetail.isBuildActive = $false;
                            $this.buildActivityDetail.message = "No recent build history found in last $inactiveLimit days.";
                        }

                        if([Helpers]::CheckMember($this.BuildObj[0].latestBuild,"finishTime"))
                        {
                            $this.buildActivityDetail.buildLastRunDate = ([datetime] $this.BuildObj[0].latestBuild.finishTime)
                        }
                    }
                    else
                    {
                        #no build history ever.
                        $this.buildActivityDetail.isBuildActive = $false;
                        $this.buildActivityDetail.message = "No build history found.";
                    }

                    $responseObj = $null;
                }

        }
        catch
        {
            $this.buildActivityDetail.message = "Could not fetch build details.";
            $this.buildActivityDetail.errorObject = $_
        }
        $this.buildActivityDetail.isComputed = $true
    }

    hidden [ControlResult] CheckAccessToOAuthToken([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        if(($this.BuildObj | Measure-Object).Count -gt 0)
        {
            if([Helpers]::CheckMember($this.BuildObj[0].process,"yamlFilename"))
            {
                ## In case it is YAML build
                if([Helpers]::CheckMember($this.ControlSettings,"Build.RegexForOAuthTokenInYAMLScript"))
                {
                    $orgName = $this.OrganizationContext.OrganizationName
                    $projectName = $this.BuildObj.project.name
                    $projectId = $this.BuildObj.project.id
                    $buildId = $this.BuildObj.id
                    $repoid = $this.BuildObj.repository.id
                    $resultObj = @()
                    $regex = $this.ControlSettings.Build.RegexForOAuthTokenInYAMLScript
                    $branchesToCheckForYAMLScript = @()

                    try{
                        $url = "https://dev.azure.com/{0}/{1}/_apis/git/repositories/{2}/refs?api-version=6.0" -f $orgName,$projectName,$repoid
                        $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($url));
                        $branches = @($responseObj.name | Foreach-Object { $_.split("/")[-1]})
                        if([Helpers]::CheckMember($this.ControlSettings,"Build.BranchesToCheckForYAMLScript"))
                        {
                            $branchesToCheckForYAMLScript += $this.ControlSettings.Build.BranchesToCheckForYAMLScript
                        }
                        else {
                            $branchesToCheckForYAMLScript += "master"  ## default branch to check
                        }
                        $branches = @($branches | Where-Object {$_ -in $branchesToCheckForYAMLScript})
                        if($branches.count -gt 0)
                        {
                            $branches | where-object {
                                $currentBranch = $_    
                                $refobj = "" | Select-Object branch,fileName
                                $refobj.branch = $currentBranch
                                #in case pipeline repo is azure repo, get file contents from the repo, else use the portal API
                                if ($this.BuildObj[0].repository.type -eq 'TfsGit'){
                                    try{
                                        $yamlFile = ($this.BuildObj[0].process.yamlFilename).Replace("/","%2F");
                                        $url = "https://dev.azure.com/{0}/{1}/_apis/git/repositories/{2}/Items?path=%2F{3}&recursionLevel=0&includeContentMetadata=true&versionDescriptor.version={4}&versionDescriptor.versionOptions=0&versionDescriptor.versionType=0&includeContent=true&resolveLfs=true&api-version=6.0" -f $orgName, $projectName, ($this.BuildObj[0].repository.name), $yamlFile, $currentBranch
                                        #need to get the raw response as file contents are returned in bytes
                                        $responseObj = @([WebRequestHelper]::InvokeGetWebRequestRaw($url));
                                        #convert byte response to string
                                        $yamlFileContent = [System.Text.Encoding]::ASCII.GetString($responseObj.Content)
                                        if($yamlFileContent -match $regex)
                                        {
                                            $refobj.fileName = $this.BuildObj[0].process.yamlFilename
                                            $resultObj += $refobj
                                        }
                                    }
                                    catch{
                                        #eat exception as yml file not found in branch being scanned
                                    }
                                }
                                else{
                                    try{
                                        $url = 'https://dev.azure.com/{0}/{1}/_apps/hub/ms.vss-build-web.ci-designer-hub?pipelineId={2}&branch={3}&__rt=fps&__ver=2' -f $orgName, $projectId , $buildId, $currentBranch;
                                        $responseObj = @([WebRequestHelper]::InvokeGetWebRequest($url));
                                        if([Helpers]::CheckMember($responseObj,"fps.dataProviders.data") -and $responseObj.fps.dataProviders.data.'ms.vss-build-web.pipeline-editor-data-provider' -and [Helpers]::CheckMember($responseObj.fps.dataProviders.data.'ms.vss-build-web.pipeline-editor-data-provider',"content") -and  $responseObj.fps.dataProviders.data.'ms.vss-build-web.pipeline-editor-data-provider'.content)
                                        {
                                            $dataprovider = $responseObj.fps.dataProviders.data.'ms.vss-build-web.pipeline-editor-data-provider'
                                            $yamlFileContent = $dataprovider.content
                                            if($yamlFileContent -match $regex)
                                            {
                                                $refobj.fileName = $dataprovider.definition.process.yamlFilename
                                                $resultObj += $refobj
                                            }
                                        }
                                    }
                                    catch
                                    {
                                        $controlResult.AddMessage([VerificationResult]::Error,"Not able to fetch YAML file for the branch: $($currentBranch)");
                                        $controlResult.LogException($_)
                                    }
                                }
                                                        
                            }
                            if($resultObj.Count -gt 0)
                            {
                                $controlResult.AddMessage([VerificationResult]::Verify,"OAuth token is used in YAML file for the following repo: $($this.BuildObj.repository.name)")
                                $display = $resultObj | FT -AutoSize | Out-String -Width 512
                                $controlResult.AddMessage($display)
                            }
                            else {
                                if($controlResult.VerificationResult -ne [VerificationResult]::Error)
                                {
                                    $controlResult.AddMessage([VerificationResult]::Passed,"OAuth token is not being accessed in YAML file.");
                                }
                            }
                        }
                        else {
                            $controlResult.AddMessage([VerificationResult]::Passed,"The pipeline is not assoaciated with a YAML file of any branch.");
                        }                    
                    }
                    catch
                    {
                        $controlResult.AddMessage([VerificationResult]::Verify,"Not able to fetch branches associated with build."); 
                        #This could occour in case pipeline's YAML is hosted on bitbucket etc, or if referenced repo no longer exists
                        $controlResult.LogException($_)
                    }  
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Error, "Regular expression for detecting OAuth access token is not defined in control settings for your organization.");
                }
                      
            }
            else {
                if([Helpers]::CheckMember($this.BuildObj,"process.phases"))
                {
                    # In case it is classic build
                    $jobs = @($this.BuildObj.process.phases)
                    $agentlessjobs = @()
                    $AgentjobsWithOAuthAccessTokenEnabled = @()
                    $AgentjobsWithOAuthAccessTokenDisabled = @()
                    $jobs | Where-Object {
                        if([Helpers]::CheckMember($_,"target") -and [Helpers]::CheckMember($_.target,"allowScriptsAuthAccessOption",$false))
                        {
                            if($_.target.allowScriptsAuthAccessOption -eq $true)
                            {
                                $AgentjobsWithOAuthAccessTokenEnabled += $_
                            }
                            else {
                                $AgentjobsWithOAuthAccessTokenDisabled += $_
                            }
                        }
                        else {
                            # it will be the case of "AgentLess" job
                            $agentlessjobs += $_
                        }
                    }
                    if($jobs.Count -eq $agentlessjobs.count)  # All jobs are agentless jobs
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed,"No agent job(s) found in build.");
                    }
                    elseif ($AgentjobsWithOAuthAccessTokenEnabled.count -gt 0) {
                        # Accessing OAuth token is enabled for one or more agent jobs 
                        $controlResult.AddMessage([VerificationResult]::Verify,"Accessing OAuth token is enabled for agent job(s): `n`t $($AgentjobsWithOAuthAccessTokenEnabled.name -join ", ")");
                    }
                    elseif($AgentjobsWithOAuthAccessTokenDisabled.count -gt 0) {
                        # ACcessing OAuth token is not enabled for agent jobs
                        $controlResult.AddMessage([VerificationResult]::Passed,"Accessing OAuth token is not enabled for agent job(s).");
                    }                    
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed,"No job found in build.");
                }
            }     
        }
        else {
            $controlResult.AddMessage([VerificationResult]::Error,"Not able to fetch build details.");
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckYAMLCITrigger([ControlResult] $controlResult){
        $branchesToCheckForCI = $this.ControlSettings.Build.BranchesToCheckForYAMLScript
        try{
            if([Helpers]::CheckMember($this.BuildObj[0],"triggers"))
            {
                $CITrigger = $this.BuildObj[0].triggers | Where-Object {$_.triggerType -eq "continuousIntegration"}
                if($CITrigger){
                    #for YAML CI settingsSourceType property has a value of 2, fail the control in case of YAML CI
                    if([Helpers]::CheckMember($CITrigger,"settingsSourceType") -and $CITrigger.settingsSourceType -eq 2){
                        $controlResult.AddMessage([VerificationResult]::Failed,"YAML CI trigger is enabled for the build pipeline.");
                    }
                    else{
                        <#branches can have naming conventions as following:
                            +refs/heads/.. -> include this branch
                            -refs/heads/.. -> exclude this branch
                        We need to filter out only those branches that are being included in CI
                        #>
                        $branchFilters = $CITrigger.branchFilters | where {$_ -like "+refs/heads/*"};
                        #extract the branch name
                        $branchFilters = $branchFilters | foreach {($_ -split "\+refs/heads/")[1]};
                        $nonPermissibleBranchesFound = $false;
                        $nonPermissibleBranches = @();
                        foreach ($branch in $branchFilters){
                            if ($branch -notin $branchesToCheckForCI) {
                                $nonPermissibleBranchesFound = $true;
                                $nonPermissibleBranches+=$branch
                            }
                        }
                        if($nonPermissibleBranchesFound){
                            $controlResult.AddMessage([VerificationResult]::Failed,"YAML CI trigger is disabled for the build pipeline. However, CI is enabled on non permissible branches.");
                            $controlResult.AddMessage("CI has been enabled on the following non-permissible branches: ");
                            $controlResult.AddMessage($($nonPermissibleBranches| FT | Out-String));
                        }
                        else{
                            $controlResult.AddMessage([VerificationResult]::Passed,"YAML CI trigger is disabled for the build pipeline. CI is enabled only on allowed branches.");
                        }
                        
                    }
                }
                else{
                    $controlResult.AddMessage([VerificationResult]::Passed,"No CI triggers are enabled for the build pipeline.");
                }
                
            }
            else{
                $controlResult.AddMessage([VerificationResult]::Passed,"No triggers are enabled for the build pipeline.");
            }
            $controlResult.AddMessage("`nNote:`nFollowing branches are considered permissible branches for CI trigger: ");
            $controlResult.AddMessage("$($branchesToCheckForCI | FT | Out-String)")
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch build pipeline details.");
        }
        
        return $controlResult;
    }
    hidden [ControlResult] CheckYAMLDefaultBranch([ControlResult] $controlResult){
        try{
            $defaultBranch = $this.buildObj[0].repository.defaultBranch; 
            $controlResult.AddMessage("The default branch for the YAML pipeline is: "+$defaultBranch);
            $controlResult.AdditionalInfo+="The default branch for the YAML pipeline is: "+$defaultBranch
            #if YAML file is in external source, branch protection cannot be determined, needs to be checked manually
            if( ($this.BuildObj[0].repository.type -ne 'TfsGit') -and ($this.BuildObj[0].repository.type -ne 'TfsVersionControl')){
                $controlResult.AddMessage([VerificationResult]::Manual,"Pipeline is build on an external source. Branch protection cannot be verified.");
                return $controlResult;
            }
            $repoId = $this.buildObj[0].repository.id;
            #the API may have inconsistent naming structure where branches may not be preceded with refs/heads. In such cases branch protection results may be incorrect
            #add this prefix in such cases
            if($defaultBranch -notlike "refs/*"){
                $defaultBranch = "refs/heads/{0}" -f $defaultBranch
            }
            #multiple pipelines may use the same repo and branch, cache the result in these cases
            $cachedBranchPolicy = [Build]::YamlBranchPolicies | Where-Object {$_.repo -eq $repoId -and $_.branch -eq $defaultBranch}
            if($cachedBranchPolicy -ne $null)
            {
                if($cachedBranchPolicy.isProtected){
                    $controlResult.AddMessage([VerificationResult]::Passed,$cachedBranchPolicy.controlMessage);
                }
                else{
                    $controlResult.AddMessage([VerificationResult]::Failed,$cachedBranchPolicy.controlMessage);
                }
                return $controlResult;
            }
            $url = "https://dev.azure.com/{0}/{1}/_apis/git/policy/configurations?repositoryId={2}&refName={3}&api-version=5.0-preview.1" -f $this.OrganizationContext.OrganizationName,$this.ResourceContext.ResourceGroupName,$repoId,$defaultBranch
            $policyConfigResponse = @([WebRequestHelper]::InvokeGetWebRequest($url))
            if([Helpers]::CheckMember($policyConfigResponse[0],"id")){
                $branchPolicy = @($policyConfigResponse | Where-Object {$_.isEnabled -and $_.isBlocking})
                #policyConfigResponse also contains repository policies, we need to filter out just branch policies
                $branchPolicy = @($branchPolicy | Where-Object {[Helpers]::CheckMember($_.settings.scope[0],"refName")})
                if($branchPolicy.Count -gt 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,"Branch policies have been enabled on the default branch.");
                    [Build]::YamlBranchPolicies += (@{repo = $repoId;branch = $defaultBranch; isProtected = $true;controlMessage = "Branch policies have been enabled on the default branch."})
                }
                else{
                    $controlResult.AddMessage([VerificationResult]::Failed,"No active branch policies have been enabled on the default branch.");
                    [Build]::YamlBranchPolicies += (@{repo = $repoId;branch = $defaultBranch; isProtected = $false;controlMessage ="No active branch policies have been enabled on the default branch." })
                }
            }
            else{
                $controlResult.AddMessage([VerificationResult]::Failed,"No branch policies have been enabled on the default branch.");
                [Build]::YamlBranchPolicies += (@{repo = $repoId;branch = $defaultBranch; isProtected = $false;controlMessage = "No branch policies have been enabled on the default branch."})

            }
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch build pipeline details.");
            
        }
        
        return $controlResult;
    }

    hidden [ControlResult] CheckForkedBuildTriggerForPvtProject([ControlResult] $controlResult) {
        # Start with initial failed status
        $controlResult.VerificationResult = [VerificationResult]::Failed
        $projectVisibilityCheck = @($this.ControlSettings.Project.ProjectVisibilitiesToCheck)

        if ($projectVisibilityCheck.Count -eq 0) {
            $controlResult.AddMessage([VerificationResult]::Error, "Project visibilities to check are not available in control settings.");
            return $controlResult
        }

        if ($projectVisibilityCheck -notcontains $this.ResourceContext.ResourceDetails.project.visibility) {
            $controlResult.AddMessage([VerificationResult]:: Verify), "Project is of visibility: " + $this.ResourceContext.ResourceDetails.project.visibility + ". Scan is not configured to check for such projects."
            return $controlResult
        }

        if ([Helpers]::CheckMember($this.BuildObj[0], "triggers")) {
            # Get triggers from build object
            $pullRequestTrigger = $this.BuildObj[0].triggers | Where-Object { $_.triggerType -eq "pullRequest" }

            if ($pullRequestTrigger) {
                # check fork protection is enabled or not (Limit building pull requests from forked GitHub repositories at project level)
                if ($pullRequestTrigger.pipelineTriggerSettings.forkProtectionEnabled -eq $true) {
                    # check pipeline will build PRs from forked GitHub repos or not.
                    if (!$pullRequestTrigger.pipelineTriggerSettings.buildsEnabledForForks) {
                        $controlResult.AddMessage([VerificationResult]::Passed, "Pipeline will not build pull requests from forked repositories at project level.");
                    }
                    else {
                        $this.CheckBuildLevelPRTriggerForkSettings($pullRequestTrigger, $controlResult)
                    }
                }
                else {
                    $this.CheckBuildLevelPRTriggerForkSettings($pullRequestTrigger, $controlResult)
                }
            }
            else {
                # Pull request trigger is disabled for build pipeline.
                $controlResult.AddMessage([VerificationResult]::Verify, "Pull request trigger is disabled for build pipeline.");
            }
        }
        else {
            # No trigger is enabled for build pipeline
            $controlResult.AddMessage([VerificationResult]::Verify, "No trigger is enabled for build pipeline.");
        }
        return  $controlResult
    }
    
    hidden [ControlResult] CheckBuildLevelPRTriggerForkSettings([PSObject] $pullRequestTrigger,[ControlResult] $controlResult){
        # initializing $isRepoPrivate = $true as visibility setting is not available for ADO repositories.
        $isRepoPrivate = $true
        if ([Helpers]::CheckMember($this.BuildObj[0], "repository.properties.IsPrivate")) {
            $isRepoPrivate = $this.BuildObj[0].repository.properties.IsPrivate
        }
        # Check if repo is not private, pipeline is forked
        if (($isRepoPrivate -eq $false) -and [Helpers]::CheckMember($pullRequestTrigger, "forks")) {
            if ($pullRequestTrigger.forks.enabled -eq $true) {
                $controlResult.AddMessage([VerificationResult]::Failed, "Pull request trigger is enabled on private/internal project build definition referring to public repository.");
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed, "Forks are disabled for the repository referred by the build.");
            }
        }
        else {
            # This condition means that if pull request trigger is null or repository referred by build is private
            $controlResult.AddMessage([VerificationResult]::Passed, "Repository referred by build is private.");
        }  
        return  $controlResult  
    }

    hidden [ControlResult] CheckForkedBuildTriggerWithFullAccessToken([ControlResult] $controlResult) {
        # Start with initial failed status
        $controlResult.VerificationResult = [VerificationResult]::Failed
        $projectVisibilityCheck = @($this.ControlSettings.Project.ProjectVisibilitiesToCheck)

        if ($projectVisibilityCheck.Count -eq 0) {
            $controlResult.AddMessage([VerificationResult]::Error, "Project visibilities to check are not available in control settings.");
            return $controlResult
        }

        if ($projectVisibilityCheck -notcontains $this.ResourceContext.ResourceDetails.project.visibility) {
            $controlResult.AddMessage([VerificationResult]:: Verify), "Project is of visibility: " + $this.ResourceContext.ResourceDetails.project.visibility + ". Current control scan is only applicable for private projects."
            return $controlResult
        }

        if ([Helpers]::CheckMember($this.BuildObj[0], "triggers")) {
            # Get triggers from build object
            $pullRequestTrigger = $this.BuildObj[0].triggers | Where-Object { $_.triggerType -eq "pullRequest" }

            if ($pullRequestTrigger) {
                # check fork protection is enabled or not
                if ($pullRequestTrigger.pipelineTriggerSettings.forkProtectionEnabled -eq $true) {
                    if (!$pullRequestTrigger.pipelineTriggerSettings.buildsEnabledForForks) {
                        $controlResult.AddMessage([VerificationResult]::Passed, "Pipeline will not build pull requests from forked repositories.");
                    }
                    # Conditions for checking whether to securely build pull requests from forked repositories or not.
                    elseif ($pullRequestTrigger.pipelineTriggerSettings.enforceJobAuthScopeForForks -and $pullRequestTrigger.pipelineTriggerSettings.enforceNoAccessToSecretsFromForks) {
                        $controlResult.AddMessage([VerificationResult]::Passed, "Builds of pull requests from forked repositories do not have access to secrets or have the same permissions as regular builds.");
                    }
                    # check pipeline will build PRs from forked GitHub repos or not.
                    else {
                        if ($pullRequestTrigger.pipelineTriggerSettings.enforceJobAuthScopeForForks) {
                            $controlResult.AddMessage([VerificationResult]::Passed, "Forked builds running as regular builds is disabled in a public GitHub repository at project level.");
                        }
                        else {
                            $this.CheckBuildLevelPRTriggerForFullAccessTokenSettings($pullRequestTrigger, $controlResult)
                        }
                    }
                }
                else {
                    $this.CheckBuildLevelPRTriggerForFullAccessTokenSettings($pullRequestTrigger, $controlResult)
                }
            }
            else {
                # This condition means that if pull request trigger is disabled for build pipeline
                $controlResult.AddMessage([VerificationResult]::Verify, "Pull request validation trigger is not enabled on build pipeline.");
            }
        }
        else {
            # This condition means that if no trigger is enabled for build pipeline
            $controlResult.AddMessage([VerificationResult]::Verify, "No trigger is enabled for build pipeline.");
        }
        return  $controlResult
    }
    
    hidden [ControlResult] CheckBuildLevelPRTriggerForFullAccessTokenSettings([PSObject] $pullRequestTrigger,[ControlResult] $controlResult){
        # initializing $isRepoPrivate = $true as visibility setting is not available for ADO repositories.
        $isRepoPrivate = $true
        if ([Helpers]::CheckMember($this.BuildObj[0], "repository.properties.IsPrivate")) {
            $isRepoPrivate = $this.BuildObj[0].repository.properties.IsPrivate
        }
        # Check if repo is not private, pipeline is forked
        if (($isRepoPrivate -eq $false) -and [Helpers]::CheckMember($pullRequestTrigger, "forks")) {
            if ($pullRequestTrigger.forks.enabled -and $pullRequestTrigger.forks.allowFullAccessToken) {
                # Control fails if fork builds have the same permissions as regular builds
                $controlResult.AddMessage([VerificationResult]::Failed, "Pull request trigger along with forked builds running as regular builds is enabled on build definition referring to public GitHub repository.");
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed, "Forked builds running as regular builds is disabled in a public GitHub repository.");
            }
        }
        else {
            # This condition means that if pull request trigger is null or repository referred by build is private
            $controlResult.AddMessage([VerificationResult]::Passed, "Repository referred by build is private.");
        }  
        return  $controlResult  
    }    
}
