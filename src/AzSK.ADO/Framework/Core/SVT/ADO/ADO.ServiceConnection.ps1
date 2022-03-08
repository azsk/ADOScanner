Set-StrictMode -Version Latest
class ServiceConnection: ADOSVTBase
{
    hidden [PSObject] $ServiceEndpointsObj = $null;
    hidden static [string] $SecurityNamespaceId = $null;
    hidden [PSObject] $ProjectId;
    hidden [PSObject] $ServiceConnEndPointDetail = $null;
    hidden [PSObject] $pipelinePermission = $null;
    hidden [PSObject] $serviceEndPointIdentity = $null;
    hidden [PSObject] $SvcConnActivityDetail = @{isSvcConnActive = $true; svcConnLastRunDate = $null; message = $null; isComputed = $false; errorObject = $null};
    hidden static $IsOAuthScan = $false;
    hidden [string] $checkInheritedPermissionsPerSvcConn = $false
    hidden [PSObject] $approvalsAndChecksObj = $null;
    ServiceConnection([string] $organizationName, [SVTResource] $svtResource): Base($organizationName,$svtResource)
    {
        if(-not [string]::IsNullOrWhiteSpace($env:RefreshToken) -and -not [string]::IsNullOrWhiteSpace($env:ClientSecret))  # this if block will be executed for OAuth based scan
        {
            [ServiceConnection]::IsOAuthScan = $true
        }

        # Get project id
        $this.ProjectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
        # Get security namespace identifier of service endpoints.
        if([string]::IsNullOrEmpty([ServiceConnection]::SecurityNamespaceId))
        {
            $apiURL = "https://dev.azure.com/{0}/_apis/securitynamespaces?api-version=6.0" -f $($this.OrganizationContext.OrganizationName)
            $securityNamespacesObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
            [ServiceConnection]::SecurityNamespaceId = ($securityNamespacesObj | Where-Object { ($_.Name -eq "ServiceEndpoints")}).namespaceId

            $securityNamespacesObj = $null;
        }

        # Get service connection details https://dev.azure.com/{organization}/{project}/_admin/_services
        $this.ServiceEndpointsObj = $this.ResourceContext.ResourceDetails

        if(($this.ServiceEndpointsObj | Measure-Object).Count -eq 0)
        {
            throw [SuppressedException] "Unable to find active service connection(s) under [$($this.ResourceContext.ResourceGroupName)] project."
        }

        # if service connection activity check function is not computed, then first compute the function to get the correct status of service connection.
        if($this.SvcConnActivityDetail.isComputed -eq $false)
        {
            $this.CheckActiveConnection()
        }

        # overiding the '$this.isResourceActive' global variable based on the current status of service connection .
        if ($this.SvcConnActivityDetail.isSvcConnActive)
        {
            $this.isResourceActive = $true
        }
        else
        {
            $this.isResourceActive = $false
        }

        # calculating the inactivity period in days for the service connection. If there is no usage history, then setting it with negative value.
        # This will ensure inactive period is always computed irrespective of whether inactive control is scanned or not.
        if ($null -ne $this.SvcConnActivityDetail.svcConnLastRunDate)
        {
            $this.InactiveFromDays = ((Get-Date) - $this.SvcConnActivityDetail.svcConnLastRunDate).Days
        }

        if ([Helpers]::CheckMember($this.ControlSettings, "ServiceConnection.CheckForInheritedPermissions") -and $this.ControlSettings.ServiceConnection.CheckForInheritedPermissions) {
            $this.checkInheritedPermissionsPerSvcConn = $true
        }

    }

    [ControlItem[]] ApplyServiceFilters([ControlItem[]] $controls)
	{
        $result = $controls;
        # Applying filter to exclude certain controls based on Tag
        #For non azurerm svc conn - filter out all controls that are specific to azurerm
        if($this.ServiceEndpointsObj.type -ne "azurerm")
        {
            $result = $result | Where-Object { $_.Tags -notcontains "AzureRM" };
        }

        #For non azure svc conn - filter out all controls that are specific to azure
        if($this.ServiceEndpointsObj.type -ne "azure")
        {
            $result = $result | Where-Object { $_.Tags -notcontains "Azure" };
        }

        #if svc conn is either azure/azurerm - some controls that are specific and common to both azure/azurerm should be readded as they might have been filtered out in one of the previous two if conditions.
        if(($this.ServiceEndpointsObj.type -eq "azurerm") -or ($this.ServiceEndpointsObj.type -eq "azure"))
        {
            $result += $controls | Where-Object { ($_.Tags -contains "AzureRM") -and ($_.Tags -contains "Azure") };
        }

		return $result;
	}

    hidden [ControlResult] CheckServiceConnectionAccess([ControlResult] $controlResult)
	{
        $controlResult.VerificationResult = [VerificationResult]::Failed

        if ($this.ServiceEndpointsObj.type -eq "azurerm")
        {
            try {
                if([Helpers]::CheckMember($this.ServiceEndpointsObj, "data") )
                {
                    $message = "Service connection has access at [{0}] {1} scope in the subscription [{2}] .";
                    $serviceEndPoint = $this.ServiceEndpointsObj
                    # 'scopeLevel' and 'creationMode' properties are required to determine whether a svc conn is automatic or manual.
                    # irrespective of creationMode - pass the control for conn authorized at MLWorkspace and PublishProfile (app service) scope as such conn are granted access at resource level.
                    if(([Helpers]::CheckMember($serviceEndPoint, "data.scopeLevel") -and ([Helpers]::CheckMember($serviceEndPoint.data, "creationMode")) ))
                    {
                        #If Service connection creation mode is 'automatic' and scopeLevel is subscription and no resource group is defined in its access definition -> conn has subscription level access -> fail the control,
                        #else pass the control if scopeLevel is 'Subscription' and 'scope' is RG  (note scope property is visible, only if conn is authorized to an RG)
                        #Fail the control if it has access to management group (last condition)
                        if(($serviceEndPoint.data.scopeLevel -eq "Subscription" -and $serviceEndPoint.data.creationMode -eq "Automatic" -and !([Helpers]::CheckMember($serviceEndPoint.authorization,"parameters.scope") )) -or ($serviceEndPoint.data.scopeLevel -eq "ManagementGroup"))
                        {
                            $controlFailedMsg = '';
                            if ($serviceEndPoint.data.scopeLevel -eq "Subscription") {
                                $controlFailedMsg = "Service connection has access at [$($serviceEndPoint.data.subscriptionName)] subscription scope."
                            }
                            elseif ($serviceEndPoint.data.scopeLevel -eq "ManagementGroup") {
                                $controlFailedMsg = "Service connection has access at [$($serviceEndPoint.data.managementGroupName)] management group scope."
                            }
                            $controlResult.AddMessage([VerificationResult]::Failed, $controlFailedMsg);
                            $controlResult.AdditionalInfo += $controlFailedMsg;
                        }
                        else{ # else gets executed when svc is scoped at RG and not at sub or MG
                            if ([Helpers]::CheckMember($serviceEndPoint.authorization.parameters, "scope")) {
                                $message =  $message -f $serviceEndPoint.authorization.parameters.scope.split('/')[-1], 'resource group', $serviceEndPoint.data.subscriptionName
                            }
                            else {
                                $message = "Service connection is not configured at subscription scope."
                            }
                            $controlResult.AddMessage([VerificationResult]::Passed, $message);
                            $controlResult.AdditionalInfo += $message;
                        }
                    }
                    #elseif gets executed when scoped at AzureMLWorkspace
                    elseif(([Helpers]::CheckMember($serviceEndPoint, "data.scopeLevel") -and $serviceEndPoint.data.scopeLevel -eq "AzureMLWorkspace"))
                    {
                        $message =  $message -f $serviceEndPoint.data.mlWorkspaceName, 'ML workspace', $serviceEndPoint.data.subscriptionName
                        $controlResult.AddMessage([VerificationResult]::Passed, $message);
                        $controlResult.AdditionalInfo += $message;
                    }
                    #elseif gets executed when scoped at PublishProfile
                    elseif(([Helpers]::CheckMember($serviceEndPoint, "authorization.scheme") -and $serviceEndPoint.authorization.scheme -eq "PublishProfile"))
                    {
                        $message =  $message -f $serviceEndPoint.data.resourceId.split('/')[-1], 'app service', $serviceEndPoint.data.subscriptionName
                        $controlResult.AddMessage([VerificationResult]::Passed, $message);
                        $controlResult.AdditionalInfo += $message;
                    }
                    else  # if creation mode is manual and type is other (eg. managed identity) then verify the control
                    {
                        $controlResult.AddMessage([VerificationResult]::Verify, "Access scope of service connection can not be verified as it is not an 'automatic' service prinicipal.");
                    }
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the service connection details.");
                }
            }
            catch {
                $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the service connection details.");
                $controlResult.LogException($_)
            }
        }
        else {
            $controlResult.AddMessage([VerificationResult]::Manual,"Access scope of service connections of type other than 'Azure Resource Manager' can not be verified.");
        }
 
        return $controlResult;
    }

    hidden [ControlResult] CheckClassicConnection([ControlResult] $controlResult)
	{
        $controlResult.VerificationResult = [VerificationResult]::Failed
       
        if($this.ServiceEndpointsObj.type -eq "azure")
        {
                $controlResult.AddMessage([VerificationResult]::Failed,
                                            "Classic service connection detected.");
        }
        else {
            $controlResult.AddMessage([VerificationResult]::Passed,
                                            "Classic service connection not detected.");
        }      
        return $controlResult;
    }


    hidden [ControlResult] CheckSPNAuthenticationCertificate([ControlResult] $controlResult)
	{
        if([Helpers]::CheckMember($this.ServiceEndpointsObj, "authorization.parameters.authenticationType"))
        {
            if( $this.ServiceEndpointsObj.authorization.parameters.authenticationType -eq "spnKey")
            {
                $controlResult.AddMessage([VerificationResult]::Failed,
                                        "Service endpoint is authenticated using secret.");
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed,
                                            "Service endpoint is authenticated using certificate.");
            }
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckInheritedPermissions ([ControlResult] $controlResult)
	{
        $failMsg = $null
        try
        {
            $Endpoint = $this.ServiceEndpointsObj
            $apiURL = "https://dev.azure.com/{0}/_apis/accesscontrollists/{1}?token=endpoints/{2}/{3}&api-version=6.0" -f $($this.OrganizationContext.OrganizationName),$([ServiceConnection]::SecurityNamespaceId),$($this.ProjectId),$($Endpoint.id);
            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
            if(($responseObj | Measure-Object).Count -eq 0)
            {
                $inheritPermissionsEnabled += @{EndPointName= $Endpoint.Name; Creator = $Endpoint.createdBy.displayName; inheritPermissions="Unable to fetch permissions inheritance details." }
            }
            elseif([Helpers]::CheckMember($responseObj,"inheritPermissions") -and $responseObj.inheritPermissions -eq $true)
            {
                $controlResult.AddMessage([VerificationResult]::Failed,"Inherited permissions are enabled on service connection.");
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed,"Inherited permissions are disabled on service connection.");
            }

            $Endpoint = $null;
            $responseObj = $null;
        }
        catch {
            $failMsg = $_
            $controlResult.LogException($_)
        }

        if(![string]::IsNullOrEmpty($failMsg))
        {
            $controlResult.AddMessage([VerificationResult]::Manual,"Unable to fetch service connections details. $($failMsg)Please verify from portal that permission inheritance is turned OFF for all the service connections");
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckGlobalGroupsAddedToServiceConnections ([ControlResult] $controlResult)
	{
        # Any identity other than teams identity needs to be verified manually as it's details cannot be retrived using API
        $controlResult.VerificationResult = [VerificationResult]::Failed        
        try
        {
            if ($null -eq $this.serviceEndPointIdentity) {
                $apiURL = "https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.serviceendpointrole/roleassignments/resources/{1}_{2}" -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId),$($this.ServiceEndpointsObj.id);
                $this.serviceEndPointIdentity = @([WebRequestHelper]::InvokeGetWebRequest($apiURL));                
            }
            $restrictedGroups = @();
           
            $restrictedGlobalGroupsForSerConn = $this.ControlSettings.ServiceConnection.RestrictedGlobalGroupsForSerConn;
            if([Helpers]::CheckMember($this.serviceEndPointIdentity,"identity"))
            {
                # match all the identities added on service connection with defined restricted list
                $restrictedGroups = $this.serviceEndPointIdentity.identity | Where-Object { $restrictedGlobalGroupsForSerConn -contains $_.displayName.split('\')[-1] } | select displayName

                # fail the control if restricted group found on service connection
                if($restrictedGroups)
                {
                    $controlResult.AddMessage("Count of global groups that have access to service connection: ", @($restrictedGroups).Count)
                    $controlResult.AddMessage([VerificationResult]::Failed,"Do not grant global groups access to service connections. Granting elevated permissions to these groups can risk exposure of service connections to unwarranted individuals.");
                    $controlResult.AddMessage("Global groups that have access to service connection.",$restrictedGroups)
                    $controlResult.SetStateData("Global groups that have access to service connection",$restrictedGroups)
                    $controlResult.AdditionalInfo += "Count of global groups that have access to service connection: " + @($restrictedGroups).Count;
                    $groups = $restrictedGroups.displayname -join ' ; '
                    $controlResult.AdditionalInfoInCSV = "List of global groups: $($groups)" 
                }
                else{
                    $controlResult.AddMessage([VerificationResult]::Passed,"No global groups have access to service connection.");
                }
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed,"No global groups have access to service connection.");
            }                   

            $restrictedGroups = $null;
            $restrictedGlobalGroupsForSerConn = $null;
        }
        catch {        
            $controlResult.AddMessage([VerificationResult]::Error,"Unable to fetch service connections details.")    
            $controlResult.LogException($_)
        }       
        return $controlResult;
    }

    hidden [ControlResult] CheckBuildServiceAccountAccess([ControlResult] $controlResult)
	{
        $controlResult.VerificationResult = [VerificationResult]::Failed
        $failMsg = $null

        try
        {
            #$isBuildSvcAccGrpFound = $false
            $buildServieAccountOnSvc = @();
            if ($null -eq $this.serviceEndPointIdentity) {
                $apiURL = "https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.serviceendpointrole/roleassignments/resources/{1}_{2}" -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId),$($this.ServiceEndpointsObj.id);
                $this.serviceEndPointIdentity = @([WebRequestHelper]::InvokeGetWebRequest($apiURL));
            }
            if(($this.serviceEndPointIdentity.Count -gt 0) -and [Helpers]::CheckMember($this.serviceEndPointIdentity[0],"identity"))
            {
                foreach ($endPointidentity in $this.serviceEndPointIdentity)
                {
                    if ($endPointidentity.identity.displayName -like '*Project Collection Build Service Accounts' -or $endPointidentity.identity.displayName -like "*Build Service ($($this.OrganizationContext.OrganizationName))")
                    {
                        $buildServieAccountOnSvc += $endPointidentity;
                        #$isBuildSvcAccGrpFound = $true;
                        #break;
                    }
                }
                #Faile the control if prj coll Buil Ser Acc Group Found added on serv conn
                $restrictedBuildSVCAcctCount = $buildServieAccountOnSvc.Count;
                if($restrictedBuildSVCAcctCount -gt 0)
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Count of restricted Build Service groups that have access to service connection: $($restrictedBuildSVCAcctCount)")
                    $formattedBSAData = $($buildServieAccountOnSvc.identity.displayName | FT | out-string )
                    #$formattedGroupsTable = ($formattedGroupsData | Out-String)
                    $controlResult.AddMessage("`nList of 'Build Service' Accounts: ", $formattedBSAData)
                    $controlResult.SetStateData("List of 'Build Service' Accounts: ", $formattedBSAData)
                    $controlResult.AdditionalInfo += "Count of restricted Build Service groups that have access to service connection: $($restrictedBuildSVCAcctCount)";
                    $formatedMembers = $buildServieAccountOnSvc | ForEach-Object { $_.identity.displayName + ': ' + $_.role.displayName }
                    $controlResult.AdditionalInfoInCSV = $(($formatedMembers) -join '; ')
                    if ($this.ControlFixBackupRequired){
                        $buildServiceAccountId = @($buildServieAccountOnSvc | Select-Object -property @{name= "Id";expression = {$_.identity.id}}, @{name = "Group"; expression = {$_.identity.displayName}}, @{name = "Role"; expression ={$_.role.name}})
                        $controlResult.BackupControlState = $buildServiceAccountId
                    }
                }
                else{
                    $controlResult.AddMessage([VerificationResult]::Passed,"Build Service accounts are not granted access to the service connection.");
                    $controlResult.AdditionalInfoInCSV = "NA";
                }

                $controlResult.AddMessage("`nNote:`nThe following 'Build Service' accounts should not have access to service connection: `nProject Collection Build Service Account`n$($this.ResourceContext.ResourceGroupName) Build Service ($($this.OrganizationContext.OrganizationName))");
            }
            else{
                $controlResult.AddMessage([VerificationResult]::Verify,"Unable to fetch service endpoint group identity.");
                # Will occur if no user permission exists on the svc
            }
        }
        catch {
            $failMsg = $_
            $controlResult.LogException($_)
        }

        if(![string]::IsNullOrEmpty($failMsg))
        {
            $controlResult.AddMessage([VerificationResult]::Error,"Unable to fetch service connections details. $($failMsg)Please verify from portal that you are not granting global security groups access to service connections");
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckBuildServiceAccountAccessAutomatedFix([ControlResult] $controlResult){
        try {
            $RawDataObjForControlFix = @();
            $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject
            $body = "["
            #method name will be different in undofix
            $MethodName = "Patch"
            if (-not $this.UndoFix){
                Foreach($_ in $RawDataObjForControlFix){
                    if ($body.length -gt 1) {$body += ","}
                    $body += '"'+$($_.Id)+'"'
                }
            }
            else{
                Foreach($_ in $RawDataObjForControlFix){
                    if ($body.length -gt 1) {$body += ","}
                    $body += @"
                    {
                        "roleName": "$($_.Role)",
                        "userId": "$($_.Id)"
                    }
"@
                }
                $MethodName = "Put"
            }
            $body+="]"
            $url = "https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.serviceendpointrole/roleassignments/resources/{1}_{2}?api-version=6.1-preview.1" -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId),$($this.ServiceEndpointsObj.id);
            $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($url)
            Invoke-RestMethod -Uri $url -Method $MethodName -ContentType "application/json" -Headers $header -Body $body
            if (-not $this.UndoFix){
                $controlResult.AddMessage([VerificationResult]::Fixed,  "Following Build Service accounts have been removed from user permissions: ");
            }
            else{
                $controlResult.AddMessage([VerificationResult]::Fixed,  "Following Build Service accounts have been added in user permissions: ");
            }
            
            $display = ($RawDataObjForControlFix | Select-Object -property @{name="Group"; expression ={$_.Group}}, @{name = 'Role'; expression = {$_.Role}} |  FT -AutoSize | Out-String -Width 512)

            $controlResult.AddMessage("`n$display");
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
            $controlResult.LogException($_)
        }
        return $controlResult
    } 

    hidden [ControlResult] CheckServiceConnectionBuildAccess([ControlResult] $controlResult)
    {
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            if ($null -eq $this.pipelinePermission) {
                $apiURL = "https://dev.azure.com/{0}/{1}/_apis/pipelines/pipelinePermissions/endpoint/{2}?api-version=6.1-preview.1" -f $($this.OrganizationContext.OrganizationName),$($this.ProjectId),$($this.ServiceEndpointsObj.id) ;
                $this.pipelinePermission = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
            }
            if([Helpers]::CheckMember($this.pipelinePermission,"allPipelines")) {
                if($this.pipelinePermission.allPipelines.authorized){
                    $controlResult.AddMessage([VerificationResult]::Failed,"Service connection is accessible to all YAML pipelines.");

                    if ($this.ControlFixBackupRequired){
                        $controlResult.BackupControlState = $this.pipelinePermission;
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed,"Service connection is not accessible to all YAML pipelines.");
                }
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed, "Service connection is not accessible to all YAML pipelines.");
            }
            $controlResult.AdditionalInfoInCSV = "NA";
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error,"Unable to fetch service connection details. $($_) Please verify from portal that you are not granting all pipeline access to service connections");
            $controlResult.LogException($_)
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckServiceConnectionBuildAccessAutomatedFix([ControlResult] $controlResult)
    {
        try{
            $this.PublishCustomMessage( "`nAfter applying this fix, any YAML pipelines using this service connection will lose access. You will have to explicitly add them.", [MessageType]::Warning);
            $RawDataObjForControlFix = @();
            $RawDataObjForControlFix = ([ControlHelper]::ControlFixBackup | where-object {$_.ResourceId -eq $this.ResourceId}).DataObject

            if (-not $this.UndoFix)
            {
                $RawDataObjForControlFix.allPipelines.authorized = $false;
                $RawDataObjForControlFix.allPipelines.authorizedBy = $null;
                $RawDataObjForControlFix.allPipelines.authorizedOn = $null;
                $body = $RawDataObjForControlFix | ConvertTo-Json -Depth 10;
                $uri = "https://dev.azure.com/{0}/{1}/_apis/pipelines/pipelinePermissions/endpoint/{2}?api-version=5.1-preview.1" -f ($this.OrganizationContext.OrganizationName), $($this.ProjectId), $($this.ServiceEndpointsObj.id);
                $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($uri)
                $Result = Invoke-RestMethod -Uri $uri -Method Patch -ContentType "application/json" -Headers $header -Body $body
            
                $controlResult.AddMessage([VerificationResult]::Fixed,  "Service connection is not accessible to all YAML pipelines.");
            }
            else {
                $body = $RawDataObjForControlFix | ConvertTo-Json -Depth 10;
                $uri = "https://dev.azure.com/{0}/{1}/_apis/pipelines/pipelinePermissions/endpoint/{2}?api-version=5.1-preview.1" -f ($this.OrganizationContext.OrganizationName), $($this.ProjectId), $($this.ServiceEndpointsObj.id);
                $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($uri)
                $Result = Invoke-RestMethod -Uri $uri -Method Patch -ContentType "application/json" -Headers $header -Body $body
            
                $controlResult.AddMessage([VerificationResult]::Fixed,  "Service connection is accessible to all YAML pipelines.");
            }
            
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error,  "Could not apply fix.");
            $controlResult.LogException($_)
        }
        
        return $controlResult
    }

    hidden [ControlResult] CheckSecureAuthN([ControlResult] $controlResult)
    {
        if([Helpers]::CheckMember($this.ServiceEndpointsObj, "authorization.scheme"))
        {
            if($this.ServiceEndpointsObj.type -eq "github")
            {
                #Nov 2020 - Currently, authorizing using OAuth, permissions are fixed (high privileges by default) and can not be modified. If authorized using PAT, we can not determine whether it is a full scope or custom access scope token.
                if( $this.ServiceEndpointsObj.authorization.scheme -eq "OAuth")
                {
                    $controlResult.AddMessage([VerificationResult]::Verify, "Service connection [$($this.ServiceEndpointsObj.name)] is authenticated via $($this.ServiceEndpointsObj.authorization.scheme).");
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Verify, "Service connection [$($this.ServiceEndpointsObj.name)] is authenticated via $($this.ServiceEndpointsObj.authorization.scheme).");
                }
            }
            elseif($this.ServiceEndpointsObj.type -eq "azure")
            {
                if( $this.ServiceEndpointsObj.authorization.scheme -eq "Certificate")
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "Service connection [$($this.ServiceEndpointsObj.name)] is authenticated via $($this.ServiceEndpointsObj.authorization.scheme).");
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Service connection [$($this.ServiceEndpointsObj.name)] is authenticated via $($this.ServiceEndpointsObj.authorization.scheme).");
                    $controlResult.AddMessage("Certificate based authentication should be used for Azure Classic service connection.")
                }
            }
            elseif($this.ServiceEndpointsObj.type -eq "azurerm")
            {
                $controlResult.AddMessage([VerificationResult]::Verify, "Service connection [$($this.ServiceEndpointsObj.name)] is authenticated via $($this.ServiceEndpointsObj.authorization.scheme).");
            }
            elseif($this.ServiceEndpointsObj.type -eq "externalnpmregistry")
            {
                if( $this.ServiceEndpointsObj.authorization.scheme -eq "Token")
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "Service connection [$($this.ServiceEndpointsObj.name)] is authenticated via $($this.ServiceEndpointsObj.authorization.scheme).");
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Service connection [$($this.ServiceEndpointsObj.name)] is authenticated via $($this.ServiceEndpointsObj.authorization.scheme).");
                    $controlResult.AddMessage("Token based authentication should be used for NPM service connection.")
                }
            }
            elseif($this.ServiceEndpointsObj.type -eq "externalnugetfeed")
            {
                if( $this.ServiceEndpointsObj.authorization.scheme -eq "None") #APIKey
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "Service connection [$($this.ServiceEndpointsObj.name)] is authenticated via $($this.ServiceEndpointsObj.authorization.scheme).");
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Service connection [$($this.ServiceEndpointsObj.name)] is authenticated via $($this.ServiceEndpointsObj.authorization.scheme).");
                    $controlResult.AddMessage("ApiKey based authentication should be used for NuGet service connection.")
                }
            }
            elseif($this.ServiceEndpointsObj.type -eq "externaltfs")
            {
                if( $this.ServiceEndpointsObj.authorization.scheme -eq "Token")
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "Service connection [$($this.ServiceEndpointsObj.name)] is authenticated via $($this.ServiceEndpointsObj.authorization.scheme).");
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Service connection [$($this.ServiceEndpointsObj.name)] is authenticated via $($this.ServiceEndpointsObj.authorization.scheme).");
                    $controlResult.AddMessage("Token based authentication should be used for Azure Repos/Team Foundation Server service connection.")
                }
            }
            elseif($this.ServiceEndpointsObj.type -eq "MicrosoftSwagger")
            {
                if( $this.ServiceEndpointsObj.authorization.scheme -eq "Token")
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "Service connection [$($this.ServiceEndpointsObj.name)] is authenticated via $($this.ServiceEndpointsObj.authorization.scheme).");
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Service connection [$($this.ServiceEndpointsObj.name)] is authenticated via $($this.ServiceEndpointsObj.authorization.scheme).");
                    $controlResult.AddMessage("Token based authentication should be used for Microsoft Swagger service connection.")
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::NotScanned,"Control is not applicable to [$($this.ServiceEndpointsObj.name)] service connection.");
            }
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckInactiveConnection([ControlResult] $controlResult)
	{
        $controlResult.VerificationResult = [VerificationResult]::Failed
        try
        {
            if ($this.SvcConnActivityDetail.message -eq 'Could not fetch the service connection details.') {
                $controlResult.AddMessage([VerificationResult]::Error, $this.SvcConnActivityDetail.message);
                if ($null -ne $this.SvcConnActivityDetail.errorObject)
                {
                    $controlResult.LogException($this.SvcConnActivityDetail.errorObject)
                }
            }
            elseif ($null -ne $this.SvcConnActivityDetail.svcConnLastRunDate)
            {
                if ($this.SvcConnActivityDetail.isSvcConnActive) {
                    $controlResult.AddMessage([VerificationResult]::Passed, $this.SvcConnActivityDetail.message);
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Failed, $this.SvcConnActivityDetail.message);
                }
                $formattedDate = $this.SvcConnActivityDetail.svcConnLastRunDate.ToString("d MMM yyyy")
                $controlResult.AddMessage("Last usage date of service connection: $($formattedDate )");
                $controlResult.AdditionalInfo += "Last usage date of service connection: " + $formattedDate ;
                $SvcConnInactivePeriod = ((Get-Date) - $this.SvcConnActivityDetail.svcConnLastRunDate).Days
                $controlResult.AdditionalInfoInCSV += "InactiveDays: $($SvcConnInactivePeriod)";                               
                $controlResult.AddMessage("The service connection was inactive from last $($SvcConnInactivePeriod) days.");
            }
            elseif ($this.SvcConnActivityDetail.isSvcConnActive)
            {
                $controlResult.AddMessage([VerificationResult]::Passed, $this.SvcConnActivityDetail.message);
                $controlResult.AdditionalInfoInCSV = "NA";
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Failed, $this.SvcConnActivityDetail.message);
                $controlResult.AdditionalInfoInCSV += "Serivce connection last run date not found.";
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,"Could not fetch the service connection details.");
            $controlResult.LogException($_)
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckCrossProjectSharing([ControlResult] $controlResult)
	{
        $controlResult.VerificationResult = [VerificationResult]::Failed

        if($this.serviceendpointsobj -and [Helpers]::CheckMember($this.serviceendpointsobj, "serviceEndpointProjectReferences") )
        {
            #Get the project list which are accessible to the service connection.
            $svcProjectReferences = $this.serviceendpointsobj.serviceEndpointProjectReferences
            if (($svcProjectReferences | Measure-Object).Count -gt 1)
            {
                $stateData = @();
                $stateData += $svcProjectReferences | Select-Object name, projectReference

                $controlResult.AddMessage("`nCount of projects that have access to the service connection: $($stateData.Count)") ;
                $display = $stateData.projectReference | FT @{l='ProjectId';e={$_.id}},@{l='ProjectName';e={$_.name}}  -AutoSize | Out-String -Width 512
                $controlResult.AddMessage([VerificationResult]::Failed, "Review the list of projects that have access to the service connection: ", $display);
                $controlResult.SetStateData("List of projects that have access to the service connection: ", $stateData);
                $controlResult.AdditionalInfo += "Count of projects that have access to the service connection: $($stateData.Count)";
                $controlResult.AdditionalInfo += "List of projects that have access to the service connection: " + [JsonHelper]::ConvertToJsonCustomCompressed($stateData);
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Service connection is not shared with multiple projects.");
            }
        }
        else
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Service connection details could not be fetched.");
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckCrossPipelineSharing([ControlResult] $controlResult)
    {
        try
        {
            if ($null -eq $this.pipelinePermission) {
                #Get pipeline access on svc conn
                $apiURL = "https://dev.azure.com/{0}/{1}/_apis/pipelines/pipelinePermissions/endpoint/{2}?api-version=6.1-preview.1" -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId), $($this.ServiceEndpointsObj.id) ;
                $this.pipelinePermission = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
            }

            #check if svc conn is set to "Grant access permission to all pipelines"
            if ([Helpers]::CheckMember($this.pipelinePermission[0], "allPipelines.authorized") -and $this.pipelinePermission[0].allPipelines.authorized -eq $true)
            {
                $controlResult.AddMessage([VerificationResult]::Failed, "Service connection is accessible to all pipelines in the project.");
            }
            elseif ([Helpers]::CheckMember($this.pipelinePermission[0], "pipelines") -and ($this.pipelinePermission[0].pipelines | Measure-Object).Count -gt 1) #Atleast one pipeline has access to svvc conn
            {
                #get the pipelines ids in comma separated string to pass in api to get the pipeline name
                $pipelinesIds = $this.pipelinePermission[0].pipelines.id -join ","
                #api call to get the pipeline name
                $apiURL = "https://dev.azure.com/{0}/{1}/_apis/build/definitions?definitionIds={2}&api-version=6.0" -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId), $pipelinesIds;
                $pipelineObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);

                # We are fixing the control status here and the state data info will be done as shown below. This is done in case we are not able to fetch the pipeline names. Although, we have the pipeline ids as shown above.
                $controlResult.AddMessage([VerificationResult]::Verify, "");
                $pipelines = @();

                if ($pipelineObj -and ($pipelineObj | Measure-Object).Count -gt 0)
                {
                    $pipelines += $pipelineObj.name
                    $controlResult.AddMessage("Total number of pipelines that have access to the service connection: ", ($pipelines | Measure-Object).Count);
                    $controlResult.AddMessage("Review the list of pipelines that have access to the service connection: ", $pipelines);
                    $controlResult.SetStateData("List of pipelines that have access to the service connection: ", $pipelines);
                    $controlResult.AdditionalInfo += "Total number of pipelines that have access to the service connection: " + ($pipelines | Measure-Object).Count;
                }
            }
            else
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "Service connection is not shared with multiple pipelines.");
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch pipeline permission details for the service connection.");
            $controlResult.LogException($_)
        }

        return $controlResult;
    }

    hidden [ControlResult] CheckRBACAccess([ControlResult] $controlResult)
    {
        <#
        {
            "ControlID": "ADO_ServiceConnection_AuthZ_Grant_Min_RBAC_Access",
            "Description": "Justify all users/groups that have access to the service connection.",
            "Id": "ServiceConnection130",
            "ControlSeverity": "High",
            "Automated": "Yes",
            "MethodName": "CheckRBACAccess",
            "Rationale": "Granting minimum access by leveraging RBAC feature ensures that users/groups are granted just enough permissions on service connection to perform their tasks. This minimizes exposure of the resources in case of user/service account compromise.",
            "Recommendation": "Go to Project Settings --> Pipelines --> Service Connections --> Select Service Connection --> Select three dots on top right --> Select Security --> Under user permissions verify role assignments",
            "Tags": [
              "SDL",
              "TCP",
              "Manual",
              "AuthZ"
            ],
            "Enabled": true
          }
        #>

        try
        {
            if ($null -eq $this.serviceEndPointIdentity) {
                $apiURL = "https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.serviceendpointrole/roleassignments/resources/{1}_{2}" -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId),$($this.ServiceEndpointsObj.id);
                $this.serviceEndPointIdentity = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
            }
            if((($this.serviceEndPointIdentity | Measure-Object).Count -gt 0) -and [Helpers]::CheckMember($this.serviceEndPointIdentity[0],"identity"))
            {
                $roles = @();
                $roles +=   ($this.serviceEndPointIdentity | Select-Object -Property @{Name="Name"; Expression = {$_.identity.displayName}},@{Name="Role"; Expression = {$_.role.displayName}});
                $rolesCount = ($roles | Measure-Object).Count;
                $controlResult.AddMessage("Total number of identities that have access to service connection: $($rolesCount)");
                $controlResult.AddMessage([VerificationResult]::Verify,"Verify whether following identities have been provided with minimum RBAC access to service connection: ", $roles);
                $controlResult.SetStateData("List of identities having access to service connection: ", $roles);
                $controlResult.AdditionalInfo += "Total number of identities that have access to service connection: " + $rolesCount;
            }
            elseif(($this.ServiceEndpointsObj | Measure-Object).Count -eq 0)
            {
                $controlResult.AddMessage([VerificationResult]::Passed,"No role assignments found on service connection.")
            }
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error,"Unable to fetch role assignments.")
            $controlResult.LogException($_)
        }

        return $controlResult
    }

    hidden CheckActiveConnection()
    {
        try
        {
            
            $apiURL = "https://dev.azure.com/{0}/{1}/_apis/serviceendpoint/{2}/executionhistory?top=1&api-version=6.0-preview.1" -f $($this.OrganizationContext.OrganizationName), $($this.ResourceContext.ResourceGroupName), $($this.serviceendpointsobj.id);
            $serviceEndpointExecutionHistory = [WebRequestHelper]::InvokeGetWebRequest($apiURL);

            if (($serviceEndpointExecutionHistory | Measure-Object).Count -gt 0 -and ([Helpers]::CheckMember($serviceEndpointExecutionHistory[0],"data")))
            {
                #if this job is still running then finishTime is not available. pass the control
                if ([Helpers]::CheckMember($serviceEndpointExecutionHistory[0].data, "finishTime"))
                {
                    #Get the last known usage (job) timestamp of the service connection
                    $svcLastRunDate = $serviceEndpointExecutionHistory[0].data.finishTime;

                    #format date
                    $formatLastRunTimeSpan = New-TimeSpan -Start (Get-Date $svcLastRunDate)

                    # $inactiveLimit denotes the upper limit on number of days of inactivity before the svc conn is deemed inactive.
                    if ($this.ControlSettings -and [Helpers]::CheckMember($this.ControlSettings, "ServiceConnection.ServiceConnectionHistoryPeriodInDays") )
                    {
                        $inactiveLimit = $this.ControlSettings.ServiceConnection.ServiceConnectionHistoryPeriodInDays
                        if ($formatLastRunTimeSpan.Days -gt $inactiveLimit)
                        {
                            $this.SvcConnActivityDetail.isSvcConnActive = $false;
                            $this.SvcConnActivityDetail.message = "Service connection has not been used in the last $inactiveLimit days.";
                        }
                        else
                        {
                            $this.SvcConnActivityDetail.isSvcConnActive = $true;
                            $this.SvcConnActivityDetail.message =  "Service connection has been used in the last $inactiveLimit days.";
                        }
                    }
                    else {
                        $this.SvcConnActivityDetail.isSvcConnActive = $false;
                        $this.SvcConnActivityDetail.message = "Could not fetch the inactive days limit for service connection.";
                    }
                    if([ContextHelper]::PSVersion -gt 5) {
                        $this.SvcConnActivityDetail.svcConnLastRunDate = [datetime]::Parse($svcLastRunDate.tostring("MM/dd/yyyy"));
                    }
                    else {
                        $this.SvcConnActivityDetail.svcConnLastRunDate = [datetime]::Parse($svcLastRunDate);
                    }
                }
                else
                {
                    $this.SvcConnActivityDetail.isSvcConnActive = $true;
                    $this.SvcConnActivityDetail.message = "Service connection was under use during the control scan.";
                }
            }
            else #service connection was created but never used. (Fail for now)
            {
                $this.SvcConnActivityDetail.isSvcConnActive = $false;
                $this.SvcConnActivityDetail.message = "Service connection has never been used.";
            }
            
        }
        catch
        {
            $this.SvcConnActivityDetail.message = "Could not fetch the service connection details.";
            $this.SvcConnActivityDetail.errorObject = $_
        }
        $this.SvcConnActivityDetail.isComputed = $true
    }


    hidden [ControlResult] CheckBroaderGroupAccess ([ControlResult] $controlResult) {
        $controlResult.VerificationResult = [VerificationResult]::Failed

        try {
            if ($null -eq $this.serviceEndPointIdentity) {
                $apiURL = "https://dev.azure.com/{0}/_apis/securityroles/scopes/distributedtask.serviceendpointrole/roleassignments/resources/{1}_{2}" -f $($this.OrganizationContext.OrganizationName), $($this.ProjectId), $($this.ServiceEndpointsObj.id);
                $this.serviceEndPointIdentity = @([WebRequestHelper]::InvokeGetWebRequest($apiURL));
            }
            $restrictedGroups = @();
            $restrictedBroaderGroups = @{}
            $restrictedBroaderGroupsForSvcConn = $this.ControlSettings.ServiceConnection.RestrictedBroaderGroupsForSvcConn;
            #Converting controlsettings broader groups into a hashtable.
            $restrictedBroaderGroupsForSvcConn.psobject.properties | foreach { $restrictedBroaderGroups[$_.Name] = $_.Value }

            if (($this.serviceEndPointIdentity.Count -gt 0) -and [Helpers]::CheckMember($this.serviceEndPointIdentity, "identity")) {
                # match all the identities added on service connection with defined restricted list
                $roleAssignments = @();
                $roleAssignmentsToCheck = $this.serviceEndPointIdentity
                if ($this.checkInheritedPermissionsPerSvcConn -eq $false) {
                    $roleAssignmentsToCheck = $this.serviceEndPointIdentity | where-object { $_.access -ne "inherited" }
                }
                $roleAssignments = @($roleAssignmentsToCheck | Select-Object -Property @{Name="Name"; Expression = {$_.identity.displayName}},@{Name="Id"; Expression = {$_.identity.id}},@{Name="AccessDisplayName"; Expression = {$_.accessDisplayName}},@{Name="Role"; Expression = {$_.role.displayName}});
                #Checking where broader groups have excessive permission on service connection
                $restrictedGroups += @($roleAssignments | Where-Object { $restrictedBroaderGroups.keys -contains $_.Name.split('\')[-1] -and ($_.Role -in $restrictedBroaderGroups[$_.Name.split('\')[-1]])})
                
                if ($this.ControlSettings.CheckForBroadGroupMemberCount -and $restrictedGroups.Count -gt 0)
                {
                    $broaderGroupsWithExcessiveMembers = @([ControlHelper]::FilterBroadGroupMembers($restrictedGroups, $true))
                    $restrictedGroups = @($restrictedGroups | Where-Object {$broaderGroupsWithExcessiveMembers -contains $_.Name})
                }

                $restrictedGroupsCount = $restrictedGroups.Count

                # fail the control if restricted group found on service connection
                if ($restrictedGroupsCount -gt 0) {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Count of broader groups that have excessive permissions on service connection: $($restrictedGroupsCount)")
                    $backupDataObject = $restrictedGroups | Select @{l = 'Group'; e = { $_.Name} },@{l = 'Id'; e = { $_.Id} }, @{l = 'Role'; e = { $_.Role } },@{l = 'AccessDisplayName'; e = { $_.AccessDisplayName } }
                    $formattedGroupsData = $restrictedGroups | Select @{l = 'Group'; e = { $_.Name} }, @{l = 'Role'; e = { $_.Role } },@{l = 'AccessDisplayName'; e = { $_.AccessDisplayName } }
                    $formattedGroupsTable = ($formattedGroupsData | FT -AutoSize | Out-String -width 512)
                    $controlResult.AddMessage("`nList of groups: ", $formattedGroupsTable)
                    $controlResult.SetStateData("List of groups: ", $formattedGroupsTable)
                    $controlResult.AdditionalInfo += "Count of broader groups that have excessive permissions on service connection:  $($restrictedGroupsCount)";
                    if ($this.ControlFixBackupRequired) {
                        #Data object that will be required to fix the control
                        $controlResult.BackupControlState = $backupDataObject;
                    }
                    $restrictedGroupsAccess = $restrictedGroups | ForEach-Object { $_.Name + ': ' + $_.Role }
                    $controlResult.AdditionalInfoInCSV = $restrictedGroupsAccess -join '; '
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No broader groups have excessive permissions on service connection.");
                    $controlResult.AdditionalInfoInCSV = "NA";
                }
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed, "No broader groups have excessive permissions on service connection.");
                $controlResult.AdditionalInfoInCSV = "NA";
            }
            $displayObj = $restrictedBroaderGroups.Keys | Select-Object @{Name = "Broader Group"; Expression = {$_}}, @{Name = "Excessive Permissions"; Expression = {$restrictedBroaderGroups[$_] -join ', '}}
            $controlResult.AddMessage("`nNote:`nThe following groups are considered 'broad' which should not have excessive permissions: `n$($displayObj | FT | out-string -width 512)`n");
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Unable to fetch service connections details. Please verify from portal that you are not granting global security groups access to service connections");
            $controlResult.LogException($_)
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckBroaderGroupAccessAutomatedFix ([ControlResult] $controlResult) 
    {        
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
                            "roleName": "Reader",
                            "uniqueName": "$($identity.accessDisplayName)"                          
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
                            "roleName": "$($identity.role)",
                            "uniqueName": "$($identity.accessDisplayName)"
                        }
"@;
                }
                $RawDataObjForControlFix | Add-Member -NotePropertyName OldRole -NotePropertyValue "Reader"
                $RawDataObjForControlFix = @($RawDataObjForControlFix  | Select-Object @{Name="DisplayName"; Expression={$_.group}}, @{Name="OldRole"; Expression={$_.OldRole}},@{Name="NewRole"; Expression={$_.Role}})
            }
            $body += "]"

            #Put request           
            $url = "https://dev.azure.com/$($this.OrganizationContext.OrganizationName)/_apis/securityroles/scopes/distributedtask.serviceendpointrole/roleassignments/resources/$($this.ProjectId)_$($this.ServiceEndpointsObj.id)?api-version=5.0-preview.1";  
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

    hidden [ControlResult] CheckRestricedCloudEnvironment ([ControlResult] $controlResult) {
        $disallowedEnvironments = @()
        if ($this.ControlSettings -and [Helpers]::CheckMember($this.ControlSettings, "Organization.DisallowedEnvironments") ) {
            $disallowedEnvironments =  $this.ControlSettings.Organization.DisallowedEnvironments
        }
        if($disallowedEnvironments.Length -ne 0) {
            $controlResult.AddMessage( "List of disallowed cloud environments.", $disallowedEnvironments);
            if ((-not [Helpers]::CheckMember($this.ServiceEndpointsObj, "data")) -or [string]::IsNullOrEmpty($this.ServiceEndpointsObj.data) -or (-not[Helpers]::CheckMember($this.ServiceEndpointsObj.data, "environment"))) {
                $controlResult.AddMessage([VerificationResult]::Passed, "Unable to determine the cloud environment for the service connection.");
            }
            else {
            $serviceConnectionEnvironment = $this.ServiceEndpointsObj.data.environment
            #check if the current environment is in list of restricted environments
            if ($disallowedEnvironments -contains $serviceConnectionEnvironment) {
                    $controlResult.AddMessage([VerificationResult]::Failed, "Service connection is connected to restricted cloud environment: $serviceConnectionEnvironment");
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed, "Service connection is not connected to restricted cloud environments.");
                }
            }
        }
        else {
            $controlResult.AddMessage([VerificationResult]::Passed, "No restricted cloud environments were configured in control settings.");
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckBranchControlForSvcConn ([ControlResult] $controlResult) {
        try{
            #check if resources is accessible even to a single pipeline
            $isRsrcAccessibleToAnyPipeline = $false;
            if ($null -eq $this.pipelinePermission) {
                $apiURL = "https://dev.azure.com/{0}/{1}/_apis/pipelines/pipelinePermissions/endpoint/{2}?api-version=6.1-preview.1" -f $($this.OrganizationContext.OrganizationName),$($this.ProjectId),$($this.ServiceEndpointsObj.id) ;
                $this.pipelinePermission = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
            }
            if([Helpers]::CheckMember($this.pipelinePermission,"allPipelines") -and $this.pipelinePermission.allPipelines.authorized){
                $isRsrcAccessibleToAnyPipeline = $true;
            }
            if([Helpers]::CheckMember($this.pipelinePermission[0],"pipelines") -and $this.pipelinePermission[0].pipelines.Count -gt 0){
                $isRsrcAccessibleToAnyPipeline = $true;
            }
            #if resource is not accessible to any YAML pipeline, there is no need to add any branch control, hence passing the control
            if($isRsrcAccessibleToAnyPipeline -eq $false){
                $controlResult.AddMessage([VerificationResult]::Passed, "Service connection is not accessible to any YAML pipelines. Hence, branch control is not required.");
                return $controlResult;
            }
            if ($null -eq $this.approvalsAndChecksObj) 
            {
            $url = "https://dev.azure.com/{0}/{1}/_apis/pipelines/checks/queryconfigurations?`$expand=settings&api-version=6.1-preview.1" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName;
            #using ps invoke web request instead of helper method, as post body (json array) not supported in helper method
            $rmContext = [ContextHelper]::GetCurrentContext();
            $user = "";
            $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))  
            $body = "[{'name':  '$($this.ResourceContext.ResourceDetails.Name)','id':  '$($this.ResourceContext.ResourceDetails.Id)','type':  'endpoint'}]"
            $this.approvalsAndChecksObj = @(Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $body)
            }
            if([Helpers]::CheckMember($this.approvalsAndChecksObj, "count") -and $this.approvalsAndChecksObj[0].count -eq 0){
                $controlResult.AddMessage([VerificationResult]::Failed, "No approvals and checks have been defined for the service connection.");
                $controlResult.AdditionalInfo = "No approvals and checks have been defined for the service connection."
                $controlResult.AdditionalInfoInCsv = "No approvals and checks have been defined for the service connection."
            }
            else{
                #we need to check only for two kinds of approvals and checks: manual approvals and branch controls, hence filtering these two out from the list
                $branchControl = @()
                $approvalControl = @()
                try{
                    $approvalAndChecks = @($this.approvalsAndChecksObj.value | Where-Object {$_.PSObject.Properties.Name -contains "settings"})
                    $branchControl = @($approvalAndChecks.settings | Where-Object {$_.PSObject.Properties.Name -contains "displayName" -and $_.displayName -eq "Branch Control"})
                    $approvalControl = @($approvalAndChecks | Where-Object {$_.PSObject.Properties.Name -contains "type" -and $_.type.name -eq "Approval"})                    
                }
                catch{
                    $branchControl = @()
                }
                if($branchControl.Count -eq 0){
                    #if branch control is not enabled, but manual approvers are added pass this control
                    if($approvalControl.Count -gt 0){
                        $controlResult.AddMessage([VerificationResult]::Passed, "Branch control has not been defined for the service connection. However, manual approvals have been added to the service connection.");
                        $approvers = $approvalControl.settings.approvers | Select @{n='Approver name';e={$_.displayName}},@{n='Approver id';e = {$_.uniqueName}}
                        $formattedApproversTable = ($approvers| FT -AutoSize | Out-String -width 512)
                        $controlResult.AddMessage("`nList of approvers : `n$formattedApproversTable");
                        $controlResult.AdditionalInfo += "List of approvers on service connection  $($approvers).";
                    }
                    else{
                        $controlResult.AddMessage([VerificationResult]::Failed, "Branch control has not been defined for the service connection.");
                        $controlResult.AdditionalInfo = "Branch control has not been defined for the service connection."
                    }                    
                }
                else{
                    $branches = ($branchControl.inputs.allowedBranches).Split(",");
                    $branchesWithNoProtectionCheck = @($branchControl.inputs | where-object {$_.ensureProtectionOfBranch -eq $false})
                    if("*" -in $branches){
                        $controlResult.AddMessage([VerificationResult]::Failed, "All branches have been given access to the service connection.");
                        $controlResult.AdditionalInfo = "All branches have been given access to the service connection."
                        $controlResult.AdditionalInfoInCsv = "All branches have been given access to the service connection."
                    }
                    elseif ($branchesWithNoProtectionCheck.Count -gt 0) {
                        #check if branch protection is enabled on all the found branches depending upon the org policy
                        if($this.ControlSettings.ServiceConnection.CheckForBranchProtection){
                            $controlResult.AddMessage([VerificationResult]::Failed, "Access to the service connection has not been granted to all branches. However, verification of branch protection has not been enabled for some branches.");
                            $branchesWithNoProtectionCheck = @(($branchesWithNoProtectionCheck.allowedBranches).Split(","));
                            $controlResult.AddMessage("List of branches granted access to the service connection without verification of branch protection: ")
                            $controlResult.AddMessage("$($branchesWithNoProtectionCheck | FT | Out-String)")
                            $branchesWithProtection = @($branches | where {$branchesWithNoProtectionCheck -notcontains $_})
                            if($branchesWithProtection.Count -gt 0){
                                $controlResult.AddMessage("List of branches granted access to the service connection with verification of branch protection: ");
                                $controlResult.AddMessage("$($branchesWithProtection | FT | Out-String)");
                            }
                            $controlResult.AdditionalInfo = "List of branches granted access to the service connection without verification of branch protection: $($branchesWithNoProtectionCheck)"
                        }
                        else{
                            $controlResult.AddMessage([VerificationResult]::Passed, "Access to the service connection has not been granted to all branches.");
                            $controlResult.AddMessage("List of branches granted access to the service connection: ");
                            $controlResult.AddMessage("$($branches | FT | Out-String)");
                        }
                    }
                    else{
                        $controlResult.AddMessage([VerificationResult]::Passed, "Access to the service connection has not been granted to all branches. Verification of branch protection has been enabled for all allowed branches.");
                        $controlResult.AddMessage("List of branches granted access to the service connection: ");
                        $controlResult.AddMessage("$($branches | FT | Out-String)");
                    }
                }
            }
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch service connection details.");
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckBroaderGroupApproversOnSvcConn ([ControlResult] $controlResult) {
        try{
            $controlResult.VerificationResult = [VerificationResult]::Failed
            if ($null -eq $this.approvalsAndChecksObj) 
            {
                $url = "https://dev.azure.com/{0}/{1}/_apis/pipelines/checks/queryconfigurations?`$expand=settings&api-version=6.1-preview.1" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName;
                #using ps invoke web request instead of helper method, as post body (json array) not supported in helper method
                $rmContext = [ContextHelper]::GetCurrentContext();
                $user = "";
                $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))  
                $body = "[{'name':  '$($this.ResourceContext.ResourceDetails.Name)','id':  '$($this.ResourceContext.ResourceDetails.Id)','type':  'endpoint'}]"
                $this.approvalsAndChecksObj = @(Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $body)
            }
            $restrictedGroups = @();
            $restrictedBroaderGroupsForSerConn = $this.ControlSettings.ServiceConnection.RestrictedBroaderGroupsForApprovers;

            if([Helpers]::CheckMember($this.approvalsAndChecksObj, "count") -and  $this.approvalsAndChecksObj[0].count -eq 0){
                $controlResult.AddMessage([VerificationResult]::Passed, "No approvals and checks have been defined for the service connection.");
                $controlResult.AdditionalInfo = "No approvals and checks have been defined for the service connection."
             }
             else
             {
             #we need to check for manual approvals and checks
                $approvalControl = @()
                try{
                    $approvalAndChecks = @($this.approvalsAndChecksObj.value | Where-Object {$_.PSObject.Properties.Name -contains "settings"})
                    $approvalControl = @($approvalAndChecks | Where-Object {$_.PSObject.Properties.Name -contains "type" -and $_.type.name -eq "Approval"})                    
                }
                catch{
                    $approvalControl = @()
                }
                 
                 if($approvalControl.Count -gt 0)
                 {
                    $approvers = $approvalControl.settings.approvers | Select @{n='Approver name';e={$_.displayName}},@{n='Approver id';e = {$_.uniqueName}}
                    $formattedApproversTable = ($approvers| FT -AutoSize | Out-String -width 512)
                    # match all the identities added on service connection with defined restricted list
                     $restrictedGroups = $approvalControl.settings.approvers | Where-Object { $restrictedBroaderGroupsForSerConn -contains $_.displayName.split('\')[-1] } | select displayName
                     
                    # fail the control if restricted group found on service connection
                    if($restrictedGroups)
                    {
                        $controlResult.AddMessage("Count of broader groups that have been added as approvers to service connection: ", @($restrictedGroups).Count)
                        $controlResult.AddMessage([VerificationResult]::Failed,"Broader groups have been added as approvers on service connection.");
                        $controlResult.AddMessage("Broader groups have been added as approvers to service connection.",$restrictedGroups)
                        $controlResult.SetStateData("Broader groups have been added as approvers to service connection",$restrictedGroups)
                        $controlResult.AdditionalInfo += "Count of broader groups that have been added as approvers to service connection: " + @($restrictedGroups).Count;
                        $controlResult.AdditionalInfo += "List of broader groups added as approvers"+ @($restrictedGroups)
                    }
                    else{
                        $controlResult.AddMessage([VerificationResult]::Passed,"No broader groups have been added as approvers to service connection.");
                        $controlResult.AddMessage("`nList of approvers : `n$formattedApproversTable");
                        $controlResult.AdditionalInfo += "List of approvers on service connection  $($approvers).";
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed,"No broader groups have been added as approvers to service connection.");
                }   
            }  
            $displayObj = $restrictedBroaderGroupsForSerConn | Select-Object @{Name = "Broader Group"; Expression = {$_}}
            $controlResult.AddMessage("`nNote:`nThe following groups are considered 'broader' groups which should not be added as approvers: `n$($displayObj | FT | out-string -width 512)`n");                  
            $restrictedGroups = $null;
            $restrictedBroaderGroupsForSerConn = $null;  
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch service connection details.");
        }
        return $controlResult;
    }

    hidden [ControlResult] CheckTemplateBranchForSvcConn ([ControlResult] $controlResult) {
        try{            
            if ($null -eq $this.approvalsAndChecksObj) 
            {
                $url = "https://dev.azure.com/{0}/{1}/_apis/pipelines/checks/queryconfigurations?`$expand=settings&api-version=6.1-preview.1" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName;
                #using ps invoke web request instead of helper method, as post body (json array) not supported in helper method
                $rmContext = [ContextHelper]::GetCurrentContext();
                $user = "";
                $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken)))  
                $body = "[{'name':  '$($this.ResourceContext.ResourceDetails.Name)','id':  '$($this.ResourceContext.ResourceDetails.Id)','type':  'endpoint'}]"
                $this.approvalsAndChecksObj = @(Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $body)
            }
            if($this.approvalsAndChecksObj[0].count -eq 0){
                $controlResult.AddMessage([VerificationResult]::Passed, "No approvals and checks have been defined for the service connection.");
                $controlResult.AdditionalInfo = "No approvals and checks have been defined for the service connection."
            }
            else{                
                $yamlTemplateControl = @()
                try{
                    $yamlTemplateControl = @($this.approvalsAndChecksObj.value | Where-Object {$_.PSObject.Properties.Name -contains "settings"})
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
                        $project = ($yamlCheck.repositoryName -split "/")[0]
                        $repository = ($yamlCheck.repositoryName -split "/")[1]
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
                        $controlResult.AddMessage([VerificationResult]::Failed, "Required template on the service connection extends from unprotected branches.");
                        $unProtectedBranches =$unProtectedBranches | Select @{l="Repository";e={$_.repository}}, @{l="Branch";e={$_.branch}}
                        $formattedGroupsTable = ($unProtectedBranches | FT -AutoSize | Out-String -width 512)
                        $controlResult.AddMessage("`nList of unprotected branches: ", $formattedGroupsTable)
                        $controlResult.SetStateData("List of unprotected branches: ", $formattedGroupsTable)
                    }
                    #if branches from external sources are found, control needs to be evaluated manually
                    elseif($unknownBranches.Count -gt 0){
                        $controlResult.AddMessage([VerificationResult]::Manual, "Required template on the service connection extends from external sources.");
                        $unknownBranches =$unknownBranches | Select @{l="Repository";e={$_.repository}}, @{l="Branch";e={$_.branch}}
                        $formattedGroupsTable = ($unknownBranches | FT -AutoSize | Out-String -width 512)
                        $controlResult.AddMessage("`nList of branches from external sources: ", $formattedGroupsTable)
                        $controlResult.SetStateData("List of branches from external sources: ", $formattedGroupsTable)
                    }
                    #if all branches are protected, pass the control
                    elseif($protectedBranches.Count -gt 0){
                        $controlResult.AddMessage([VerificationResult]::Passed, "Required template on the service connection extends from protected branches.");
                    }  
                    else{
                        $controlResult.AddMessage([VerificationResult]::Manual, "Branch policies on required template on the service connection could not be determined.");

                    }  
                    if($protectedBranches.Count -gt 0){
                        $protectedBranches =$protectedBranches | Select @{l="Repository";e={$_.repository}}, @{l="Branch";e={$_.branch}}
                        $formattedGroupsTable = ($protectedBranches | FT -AutoSize | Out-String -width 512)
                        $controlResult.AddMessage("`nList of protected branches: ", $formattedGroupsTable)
                        $controlResult.SetStateData("List of protected branches: ", $formattedGroupsTable)

                    }                                                      
                }
                else{
                    $controlResult.AddMessage([VerificationResult]::Passed, "No required template has been defined for the service connection.");

                }
            }
        }
        catch{
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch service connection details.");
        }

        return $controlResult;
    }
}