Set-StrictMode -Version Latest 
class Build: ADOSVTBase
{    

    hidden [PSObject] $BuildObj;
    hidden static [string] $SecurityNamespaceId = $null;
    hidden static [PSObject] $BuildVarNames = @{};
    hidden [PSObject] $buildActivityDetail = @{isBuildActive = $true; buildLastRunDate = $null; buildCreationDate = $null; message = $null; isComputed = $false};
    
    Build([string] $organizationName, [SVTResource] $svtResource): Base($organizationName,$svtResource) 
    {
        # Get security namespace identifier of current build.
        if ([string]::IsNullOrEmpty([Build]::SecurityNamespaceId) ) {
            $apiURL = "https://dev.azure.com/{0}/_apis/securitynamespaces?api-version=5.0" -f $($this.OrganizationContext.OrganizationName)
            $securityNamespacesObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
            [Build]::SecurityNamespaceId = ($securityNamespacesObj | Where-Object { ($_.Name -eq "Build") -and ($_.actions.name -contains "ViewBuilds")}).namespaceId
        }
        $buildId = $this.ResourceContext.ResourceDetails.id
        $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
        # Get build object
        $apiURL = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/$projectId/_apis/build/Definitions/$buildId";
        $this.BuildObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);

        if(($this.BuildObj | Measure-Object).Count -eq 0)
        {
            throw [SuppressedException] "Unable to find build pipeline in [Organization: $($this.OrganizationContext.OrganizationName)] [Project: $($this.ResourceContext.ResourceGroupName)]."
        }

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
    }

    [ControlItem[]] ApplyServiceFilters([ControlItem[]] $controls)
	{
        $result = $controls;
        # Applying filter to exclude certain controls based on Tag 
        if([Helpers]::CheckMember($this.BuildObj[0].process,"yamlFilename"))
        {
            $result = $controls | Where-Object { $_.Tags -notcontains "SkipYAML" };
		}
		return $result;
	}

    hidden [ControlResult] CheckCredInBuildVariables([ControlResult] $controlResult)
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
            $patterns = $this.ControlSettings.Patterns | where {$_.RegexCode -eq "SecretsInBuild"} | Select-Object -Property RegexList;
            $exclusions = $this.ControlSettings.Build.ExcludeFromSecretsCheck;
            if(($patterns | Measure-Object).Count -gt 0)
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
                            if ($exclusions -notcontains $buildVarName)
                            {
                                for ($i = 0; $i -lt $patterns.RegexList.Count; $i++) {
                                    #Note: We are using '-cmatch' here. 
                                    #When we compile the regex, we don't specify ignoreCase flag.
                                    #If regex is in text form, the match will be case-sensitive.
                                    if ($buildVarValue -cmatch $patterns.RegexList[$i]) { 
                                        $noOfCredFound +=1
                                        $varList += "$buildVarName";   
                                        break  
                                        }
                                    }
                            }
                        } 
                    }
                }
                if(([Helpers]::CheckMember($this.BuildObj[0],"variableGroups")) -and ([Helpers]::CheckMember($this.BuildObj[0],"variableGroups.variables"))) 
                {
                    $this.BuildObj[0].variableGroups| ForEach-Object {
                       $varGrp = $_
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
            $controlResult.AddMessage([VerificationResult]::Manual, "Could not fetch the build definition.");
            $controlResult.AddMessage($_);
        }    
      } 
     return $controlResult;
    }

    hidden [ControlResult] CheckForInactiveBuilds([ControlResult] $controlResult)
    {
        try
        {
            if ($this.buildActivityDetail.message -eq 'Could not fetch build details.')
            {
                $controlResult.AddMessage([VerificationResult]::Error, $this.buildActivityDetail.message);
            }
            elseif($this.buildActivityDetail.isBuildActive)
            {
                $controlResult.AddMessage([VerificationResult]::Passed, $this.buildActivityDetail.message);
            }
            else
            {
                if ($null -ne $this.buildActivityDetail.buildCreationDate)
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
                    $controlResult.AddMessage("The build pipeline was created on: $($this.buildActivityDetail.buildCreationDate)");
                    $controlResult.AdditionalInfo += "The build pipeline was created on: " + $this.buildActivityDetail.buildCreationDate;
                }
                else 
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, $this.buildActivityDetail.message);
                }
            }

            if ($null -ne $this.buildActivityDetail.buildLastRunDate)
            {
                $controlResult.AddMessage("Last run date of build pipeline: $($this.buildActivityDetail.buildLastRunDate)");
                $controlResult.AdditionalInfo += "Last run date of build pipeline: " + $this.buildActivityDetail.buildLastRunDate;
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch build details.");
        }
        return $controlResult
    }

    hidden [ControlResult] CheckInheritedPermissions([ControlResult] $controlResult)
    {
        try
        {
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
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Manual,"Unable to fetch build pipeline details. $($_). Please verify from portal that permission inheritance is turned OFF.");
        }

        return $controlResult
    }

    hidden [ControlResult] CheckRBACAccess([ControlResult] $controlResult)
    {
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
        }

        if(![string]::IsNullOrEmpty($failMsg))
        {
            $controlResult.AddMessage([VerificationResult]::Manual,"Unable to fetch build pipeline details. $($failMsg)Please verify from portal all teams/groups are granted minimum required permissions on build definition.");
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
       }
     return $controlResult;
    }

    hidden [ControlResult] CheckSettableAtQueueTimeForURL([ControlResult] $controlResult) 
    {
        try 
        { 
            if ([Helpers]::CheckMember($this.BuildObj[0], "variables")) 
            {
                $settableURLVars = @();
                $count = 0;
                $patterns = $this.ControlSettings.Patterns | where {$_.RegexCode -eq "URLs"} | Select-Object -Property RegexList;

                if(($patterns | Measure-Object).Count -gt 0){                
                    Get-Member -InputObject $this.BuildObj[0].variables -MemberType Properties | ForEach-Object {
                        if ([Helpers]::CheckMember($this.BuildObj[0].variables.$($_.Name), "allowOverride") )
                        {
                            $varName = $_.Name;
                            $varValue = $this.BuildObj[0].variables.$($varName).value;
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
                        $controlResult.AddMessage("Total number of variables that are settable at queue time and contain URL value: ", ($settableURLVars | Measure-Object).Count);
                        $controlResult.AddMessage([VerificationResult]::Failed, "Found variables that are settable at queue time and contain URL value: ", $settableURLVars);
                        $controlResult.AdditionalInfo += "Total number of variables that are settable at queue time and contain URL value: " + ($settableURLVars | Measure-Object).Count;
                        $controlResult.SetStateData("List of variables settable at queue time and containing URL value: ", $settableURLVars);
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Passed, "No variables were found in the build pipeline that are settable at queue time and contain URL value.");   
                    }
                }
                else 
                {
                    $controlResult.AddMessage([VerificationResult]::Manual, "Regular expressions for detecting URLs in pipeline variables are not defined in your organization.");    
                }
            }
            else 
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "No variables were found in the build pipeline.");   
            }
        }  
        catch 
        {
            $controlResult.AddMessage([VerificationResult]::Manual, "Could not fetch variables of the build pipeline.");   
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckExternalSources([ControlResult] $controlResult)
    {
        if(($this.BuildObj | Measure-Object).Count -gt 0)
        {
            $sourceobj = $this.BuildObj[0].repository | Select-Object -Property @{Name="Name"; Expression = {$_.Name}},@{Name="Type"; Expression = {$_.type}}
           if( ($this.BuildObj[0].repository.type -eq 'TfsGit') -or ($this.BuildObj[0].repository.type -eq 'TfsVersionControl'))
           {
                $controlResult.AddMessage([VerificationResult]::Passed,"Pipeline code is built from trusted repository.",  $sourceobj);
                $controlResult.AdditionalInfo += "Pipeline code is built from trusted repository: " + [JsonHelper]::ConvertToJsonCustomCompressed($sourceobj); 
                $sourceobj = $null;
           }
           else {
                $controlResult.AddMessage([VerificationResult]::Verify,"Pipeline code is built from external repository.", $sourceobj); 
                $controlResult.AdditionalInfo += "Pipeline code is built from external repository: " + [JsonHelper]::ConvertToJsonCustomCompressed($sourceobj);  
           }
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckTaskGroupEditPermission([ControlResult] $controlResult)
    {
        #Task groups have type 'metaTask' whereas individual tasks have type 'task'
        $taskGroups = @();
        if([Helpers]::CheckMember($this.BuildObj[0].process,"phases")) #phases is not available for YAML-based pipelines.
        {
            if([Helpers]::CheckMember($this.BuildObj[0].process.phases[0],"steps"))
            {
                $taskGroups += $this.BuildObj[0].process.phases[0].steps | Where-Object {$_.task.definitiontype -eq 'metaTask'}
            }
            $editableTaskGroups = @();
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

                            $contributorObj = $responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider'.identities | Where-Object {$_.subjectKind -eq 'group' -and $_.principalName -eq "[$projectName]\Contributors"}
                            # $contributorObj would be null if none of its permissions are set i.e. all perms are 'Not Set'.
                            if($contributorObj)
                            {
                                $contributorInputbody = "{
                                    'contributionIds': [
                                        'ms.vss-admin-web.security-view-permissions-data-provider'
                                    ],
                                    'dataProviderContext': {
                                        'properties': {
                                            'subjectDescriptor': '$($contributorObj.descriptor)',
                                            'permissionSetId': 'f6a4de49-dbe2-4704-86dc-f8ec1a294436',
                                            'permissionSetToken': '$permissionSetToken',
                                            'accountName': '$(($contributorObj.principalName).Replace('\','\\'))',
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
                                    $editableTaskGroups += $_.displayName
                                }
                            }
                        }
                    }
                    if(($editableTaskGroups | Measure-Object).Count -gt 0)
                    {
                        $controlResult.AddMessage("Total number of task groups on which contributors have edit permissions in build definition: ", ($editableTaskGroups | Measure-Object).Count);
                        $controlResult.AdditionalInfo += "Total number of task groups on which contributors have edit permissions in build definition: " + ($editableTaskGroups | Measure-Object).Count;
                        $controlResult.AddMessage([VerificationResult]::Failed,"Contributors have edit permissions on the below task groups used in build definition: ", $editableTaskGroups);
                        $controlResult.SetStateData("List of task groups used in build definition that contributors can edit: ", $editableTaskGroups); 
                    }
                    else 
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed,"Contributors do not have edit permissions on any task groups used in build definition.");    
                    }
                }
                catch
                {
                    $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch the RBAC details of task groups used in the pipeline.");
                }

            }
            else 
            {
                $controlResult.AddMessage([VerificationResult]::Passed,"No task groups found in build definition.");
            }
        }
        else 
        {
            if([Helpers]::CheckMember($this.BuildObj[0].process,"yamlFilename")) #if the pipeline is YAML-based - control should pass as task groups are not supported for YAML pipelines.
            {
                $controlResult.AddMessage([VerificationResult]::Passed,"Task groups are not supported in YAML pipelines.");
            }   
            else 
            {
                $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch the list of task groups used in the pipeline.");    
            }
        }
        return $controlResult;
    }
    
    hidden [ControlResult] CheckVariableGroupEditPermission([ControlResult] $controlResult)
    {
        if([Helpers]::CheckMember($this.BuildObj[0],"variableGroups"))
        {
            $varGrps = $this.BuildObj[0].variableGroups
            $projectId = $this.BuildObj.project.id
            $projectName = $this.BuildObj.project.name
            $editableVarGrps = @();
            try
            {   
                $varGrps | ForEach-Object{
                    $url = 'https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.variablegroup/roleassignments/resources/{1}%24{2}?api-version=6.1-preview.1' -f $($this.OrganizationContext.OrganizationName), $($projectId), $($_.Id);
                    $responseObj = [WebRequestHelper]::InvokeGetWebRequest($url);
                    if(($responseObj | Measure-Object).Count -gt 0)
                    {
                        $contributorsObj = $responseObj | Where-Object {$_.identity.uniqueName -eq "[$projectName]\Contributors"}
                        if((-not [string]::IsNullOrEmpty($contributorsObj)) -and ($contributorsObj.role.name -ne 'Reader')){
                            $editableVarGrps += $_.name
                        } 
                    }
                }

                if(($editableVarGrps | Measure-Object).Count -gt 0)
                {
                    $controlResult.AddMessage("Total number of variable groups on which contributors have edit permissions in build definition: ", ($editableVarGrps | Measure-Object).Count);
                    $controlResult.AdditionalInfo += "Total number of variable groups on which contributors have edit permissions in build definition: " + ($editableVarGrps | Measure-Object).Count;
                    $controlResult.AddMessage([VerificationResult]::Failed,"Contributors have edit permissions on the below variable groups used in build definition: ", $editableVarGrps);
                    $controlResult.SetStateData("List of variable groups used in build definition that contributors can edit: ", $editableVarGrps); 
                }
                else 
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,"Contributors do not have edit permissions on any variable groups used in build definition.");    
                }
            }
            catch
            {
                $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch the RBAC details of variable groups used in the pipeline.");
            }
             
        }
        else 
        {
            $controlResult.AddMessage([VerificationResult]::Passed,"No variable groups found in build definition.");
        }

        return $controlResult
    }

    hidden [ControlResult] CheckBuildAuthZScope([ControlResult] $controlResult)
    {

        if([Helpers]::CheckMember($this.BuildObj[0],"jobAuthorizationScope"))
        {
            $jobAuthorizationScope = $this.BuildObj[0].jobAuthorizationScope
            if ($jobAuthorizationScope -eq "projectCollection") {
                $controlResult.AddMessage([VerificationResult]::Failed,"Access token of build pipeline is scoped to project collection.");               
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
    hidden [ControlResult] CheckPipelineEditPermission([ControlResult] $controlResult)
    {

        $orgName = $($this.OrganizationContext.OrganizationName)
        $projectId = $this.BuildObj.project.id
        $projectName = $this.BuildObj.project.name
        $buildId = $this.BuildObj.id
        $permissionSetToken = "$projectId/$buildId"
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

        try
        {
            $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL,$inputbody);
            if([Helpers]::CheckMember($responseObj[0],"dataProviders") -and ($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider') -and ([Helpers]::CheckMember($responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider',"identities")))
            {
    
                $contributorObj = $responseObj[0].dataProviders.'ms.vss-admin-web.security-view-members-data-provider'.identities | Where-Object {$_.subjectKind -eq 'group' -and $_.principalName -eq "[$projectName]\Contributors"}
                # $contributorObj would be null if none of its permissions are set i.e. all perms are 'Not Set'.

                if($contributorObj)
                {
                    $contributorInputbody = "{
                        'contributionIds': [
                            'ms.vss-admin-web.security-view-permissions-data-provider'
                        ],
                        'dataProviderContext': {
                            'properties': {
                                'subjectDescriptor': '$($contributorObj.descriptor)',
                                'permissionSetId': '$([Build]::SecurityNamespaceId)',
                                'permissionSetToken': '$permissionSetToken',
                                'accountName': '$(($contributorObj.principalName).Replace('\','\\'))',
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
                
                    #Web request to fetch RBAC permissions of Contributors group on task group.
                    $contributorResponseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL,$contributorInputbody);
                    $contributorRBACObj = $contributorResponseObj[0].dataProviders.'ms.vss-admin-web.security-view-permissions-data-provider'.subjectPermissions
                    $editPerms = $contributorRBACObj | Where-Object {$_.displayName -eq 'Edit build pipeline'}
                   
                    if([Helpers]::CheckMember($editPerms,"effectivePermissionValue"))
                    {
                        #effectivePermissionValue equals to 1 implies edit build pipeline perms is set to 'Allow'. Its value is 3 if it is set to Allow (inherited). This param is not available if it is 'Not Set'.
                        if(($editPerms.effectivePermissionValue -eq 1) -or ($editPerms.effectivePermissionValue -eq 3))
                        {
                            $controlResult.AddMessage([VerificationResult]::Failed,"Contributors have edit permissions on the build pipeline.");
                        }
                        else 
                        {
                            $controlResult.AddMessage([VerificationResult]::Passed,"Contributors do not have edit permissions on the build pipeline.");    
                        }   
                    }
                    else 
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed,"Contributors do not have edit permissions on the build pipeline.");
                    }
                }
                else 
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,"Contributors do not have access to the build pipeline.");
                }
            }
            else 
            {
                $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch RBAC details of the pipeline.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch RBAC details of the pipeline.");
        }

        return $controlResult;
    }
    
    hidden [ControlResult] CheckForkedBuildTrigger([ControlResult] $controlResult)
    {

        if([Helpers]::CheckMember($this.BuildObj[0],"triggers"))
        {
            $pullRequestTrigger = $this.BuildObj[0].triggers | Where-Object {$_.triggerType -eq "pullRequest"}

            if($pullRequestTrigger) 
            {
                if([Helpers]::CheckMember($pullRequestTrigger,"forks"))
                {

                    if(($pullRequestTrigger.forks.enabled -eq $true) -and ($pullRequestTrigger.forks.allowSecrets -eq $true))
                    {
                        $controlResult.AddMessage([VerificationResult]::Failed,"Secrets are available to builds of forked repository.");
                    }
                    else 
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed,"Secrets are not available to builds of forked repository.");  
                    }
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed,"Secrets are not available to builds of forked repository."); 
                }               
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed,"Pull request validation trigger is not enabled for build pipeline.");                    
            }
        }
        else 
        {
            $controlResult.AddMessage([VerificationResult]::Passed,"No trigger is enabled for build pipeline.");
        }
        
        return  $controlResult
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

    hidden CheckActiveBuilds()
    {
        try
        {
            if($this.BuildObj)
            {
                $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/HierarchyQuery/project/{1}?api-version=5.0-preview.1" -f $($this.OrganizationContext.OrganizationName),$($this.BuildObj.project.id);
                $orgURL='https://dev.azure.com/{0}/{1}/_build?view=folders' -f $($this.OrganizationContext.OrganizationName),$($this.BuildObj.project.name)
                $inputbody="{'contributionIds':['ms.vss-build-web.pipelines-data-provider'],'dataProviderContext':{'properties':{'definitionIds':'$($this.BuildObj.id)','sourcePage':{'url':'$orgURL','routeId':'ms.vss-build-web.pipelines-hub-route','routeValues':{'project':'$($this.BuildObj.project.name)','viewname':'pipelines','controller':'ContributedPage','action':'Execute'}}}}}" | ConvertFrom-Json

                $sw = [System.Diagnostics.Stopwatch]::StartNew();
                $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL,$inputbody);
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
                        CalledBy = "CheckForInactiveBuilds";
                    }
                    [AIOrgTelemetryHelper]::PublishEvent( "Api Call Trace",$properties, @{})
                }

                if([Helpers]::CheckMember($responseObj,"dataProviders") -and $responseObj.dataProviders.'ms.vss-build-web.pipelines-data-provider' -and [Helpers]::CheckMember($responseObj.dataProviders.'ms.vss-build-web.pipelines-data-provider',"pipelines") -and  $responseObj.dataProviders.'ms.vss-build-web.pipelines-data-provider'.pipelines)
                {

                    $builds = $responseObj.dataProviders.'ms.vss-build-web.pipelines-data-provider'.pipelines

                    if(($builds | Measure-Object).Count -gt 0 )
                    {
                        $inactiveLimit = $this.ControlSettings.Build.BuildHistoryPeriodInDays
                        [datetime]$createdDate = $this.BuildObj.createdDate
                        $this.buildActivityDetail.buildCreationDate = $createdDate;
                        if([Helpers]::CheckMember($builds[0],"latestRun") -and $null -ne $builds[0].latestRun)
                        {
                            if ([datetime]::Parse( $builds[0].latestRun.queueTime) -gt (Get-Date).AddDays( - $($this.ControlSettings.Build.BuildHistoryPeriodInDays))) 
                            {
                                $this.buildActivityDetail.isBuildActive = $true;
                                $this.buildActivityDetail.message = "Found recent builds triggered within $($this.ControlSettings.Build.BuildHistoryPeriodInDays) days";
                            }               
                            else 
                            {
                                $this.buildActivityDetail.isBuildActive = $false;
                                $this.buildActivityDetail.message = "No recent build history found in last $inactiveLimit days.";
                            }

                            if([Helpers]::CheckMember($builds[0].latestRun,"finishTime"))
                            {
                                $this.buildActivityDetail.buildLastRunDate = [datetime]::Parse($builds[0].latestRun.finishTime);
                            }
                        }
                        else 
                        { 
                            #no build history ever. 
                            $this.buildActivityDetail.isBuildActive = $false;
                            $this.buildActivityDetail.message = "No build history found.";
                        }
                    }
                    else
                    {
                        $this.buildActivityDetail.isBuildActive = $false;
                        $this.buildActivityDetail.message = "No build history found.";
                    }
                    $builds = $null;
                    $responseObj = $null;
                }
                else
                {
                    $this.buildActivityDetail.isBuildActive = $false;
                    $this.buildActivityDetail.message = "No build history found. Build is inactive.";
                }
            }
        }
        catch
        {
            $this.buildActivityDetail.message = "Could not fetch build details.";
        }
        
        $this.buildActivityDetail.isComputed = $true
    }
}
