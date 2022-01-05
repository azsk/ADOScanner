<#
.Description
# Context class for indenity details. 
# Provides functionality to login, create context, get token for api calls
#>
using namespace Microsoft.IdentityModel.Clients.ActiveDirectory

class ContextHelper {
    
    static hidden [Context] $currentContext;
    static hidden [bool] $IsOAuthScan;
    static hidden [bool] $PromptForLogin;
    #This will be used to carry current org under current context.
    static hidden [string] $orgName;
    static hidden [bool] $IsBatchScan;
    static hidden [int] $PSVersion = $null;
    static hidden $appObj = $null;
    static hidden $Account = $null;
    static hidden $IsPATUsed = $false;

    ContextHelper()
    {
        if(-not [string]::IsNullOrWhiteSpace($env:RefreshToken) -and -not [string]::IsNullOrWhiteSpace($env:ClientSecret))  # this if block will be executed for OAuth based scan
        {
            [ContextHelper]::IsOAuthScan = $true
        }
        if (![ContextHelper]::PSVersion) {
            [ContextHelper]::PSVersion = ($global:PSVersionTable).PSVersion.major 
        }
    }

    ContextHelper([bool] $IsBatchScan)
    {
        if(-not [string]::IsNullOrWhiteSpace($env:RefreshToken) -and -not [string]::IsNullOrWhiteSpace($env:ClientSecret))  # this if block will be executed for OAuth based scan
        {
            [ContextHelper]::IsOAuthScan = $true
        }
        [ContextHelper]::IsBatchScan=$true;
        if (![ContextHelper]::PSVersion) {
            [ContextHelper]::PSVersion = ($global:PSVersionTable).PSVersion.major 
        }
    }

    hidden static [PSObject] GetCurrentContext()
    {
        return [ContextHelper]::GetCurrentContext($false);
    }

    hidden static [PSObject] GetCurrentContext([bool]$authNRefresh)
    {
        if( (-not [ContextHelper]::currentContext) -or $authNRefresh -or [ContextHelper]::PromptForLogin)
        {
            [ContextHelper]::IsPATUsed = $false
            $clientId = [Constants]::DefaultClientId ;          
            $replyUri = [Constants]::DefaultReplyUri; 
            $adoResourceId = [Constants]::DefaultADOResourceId;
            [AuthenticationContext] $ctx = $null;

            $ctx = [AuthenticationContext]::new("https://login.windows.net/common");

            $result = $null;

            if([ContextHelper]::IsOAuthScan) { # this if block will be executed for OAuth based scan
                $tokenInfo = [ContextHelper]::GetOAuthAccessToken()
                [ContextHelper]::ConvertToContextObject($tokenInfo)
            }
            else {
                if ([ContextHelper]::PSVersion -gt 5) {
                    [string[]] $Scopes = "$adoResourceId/.default";
                    [Microsoft.Identity.Client.IPublicClientApplication] $app = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($ClientId).Build();
                    if(![ContextHelper]::appObj) {
                        [ContextHelper]::appObj = $app
                    }

                    if (![ContextHelper]::Account) {
                        [ContextHelper]::Account = $app.GetAccountsAsync().GetAwaiter().GetResult() | Select-Object -First 1
                    }
                    $tokenSource = New-Object System.Threading.CancellationTokenSource
                    $taskAuthenticationResult=$null
                    try {
                        if ( !$authNRefresh -and [ContextHelper]::PromptForLogin)
                        {
                            if ([ContextHelper]::PromptForLogin)
                            {
                                $AquireTokenParameters = $app.AcquireTokenInteractive($Scopes)
                                $taskAuthenticationResult = $AquireTokenParameters.ExecuteAsync($tokenSource.Token)
                            }
                            else {
                                $AquireTokenParameters = $app.AcquireTokenSilent($Scopes, [ContextHelper]::Account)
                                $taskAuthenticationResult = $AquireTokenParameters.ExecuteAsync($tokenSource.Token)
                                if ($taskAuthenticationResult.exception.message -like "*errors occurred*") {
                                    $AquireTokenParameters = $app.AcquireTokenInteractive($Scopes)
                                    $taskAuthenticationResult = $AquireTokenParameters.ExecuteAsync($tokenSource.Token)
                                }
                            }
                        }
                        else {
                            if ([ContextHelper]::appObj) {
                                $AquireTokenParameters = [ContextHelper]::appObj.AcquireTokenSilent($Scopes, [ContextHelper]::Account)
                            }
                            else {
                                $AquireTokenParameters = $app.AcquireTokenSilent($Scopes, [ContextHelper]::Account) 
                            }
                            $taskAuthenticationResult = $AquireTokenParameters.ExecuteAsync($tokenSource.Token)
                            if ($taskAuthenticationResult.exception.message -like "*errors occurred*") {
                                $AquireTokenParameters = $app.AcquireTokenInteractive($Scopes)
                                $taskAuthenticationResult = $AquireTokenParameters.ExecuteAsync($tokenSource.Token)
                            }
                        }
                    }
                    catch {
                        $AquireTokenParameters = $app.AcquireTokenInteractive($Scopes)
                        $taskAuthenticationResult = $AquireTokenParameters.ExecuteAsync($tokenSource.Token)
                    }
                    if ($taskAuthenticationResult.Result) {
                        $result = $taskAuthenticationResult.Result;
                    }
                    
                    if (![ContextHelper]::Account) {
                        [ContextHelper]::Account = $app.GetAccountsAsync().GetAwaiter().GetResult() | Select-Object -First 1
                    }
                    [ContextHelper]::appObj = $app;
                }
                else {
                    if ( !$authNRefresh -and [ContextHelper]::PromptForLogin) {
                        if ([ContextHelper]::PromptForLogin) {
                        $PromptBehavior = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Always
                        $PlatformParameters = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters -ArgumentList $PromptBehavior
                        $result = $ctx.AcquireTokenAsync($adoResourceId, $clientId, [Uri]::new($replyUri),$PlatformParameters).Result;
                        [ContextHelper]::PromptForLogin = $false
                        }
                        else {
                        $PromptBehavior = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto
                        $PlatformParameters = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters -ArgumentList $PromptBehavior
                        $result = $ctx.AcquireTokenAsync($adoResourceId, $clientId, [Uri]::new($replyUri),$PlatformParameters).Result;
                        }
                    }
                    else {
                        $PromptBehavior = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto
                        $PlatformParameters = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters -ArgumentList $PromptBehavior
                        $result = $ctx.AcquireTokenAsync($adoResourceId, $clientId, [Uri]::new($replyUri),$PlatformParameters).Result;
                    }
                }
                [ContextHelper]::ConvertToContextObject($result)
            }
        }
        return [ContextHelper]::currentContext
    }
    
    hidden static [PSObject] GetCurrentContext([System.Security.SecureString] $PATToken)
    {
        if(-not [ContextHelper]::currentContext)
        {
            [ContextHelper]::IsPATUsed = $true;
            [ContextHelper]::ConvertToContextObject($PATToken)
        }
        return [ContextHelper]::currentContext
    }

    hidden static [PSObject] GetOAuthAccessToken() {
        $tokenInfo = @{};
        try{
            $url = "https://app.vssps.visualstudio.com/oauth2/token"
            # exchange refresh token with new access token
            $body = "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer&client_assertion=$($env:ClientSecret)&grant_type=refresh_token&assertion=$($env:RefreshToken)&redirect_uri=https://localhost/"
        
            $res = Invoke-WebRequest -Uri $url -ContentType "application/x-www-form-urlencoded" -Method POST -Body $body
            $response = $res.Content | ConvertFrom-Json

            $tokenInfo['AccessToken'] = $response.access_token
            $expiry = $response.expires_in
            $request_time = get-date
            $tokenInfo['ExpiresOn'] = $request_time.AddSeconds($expiry)
            $refreshToken = ConvertTo-SecureString  $response.refresh_token -AsPlainText -Force

            #Update refresh token if it is expiring in next 1 day 
            $updateTokenInKV = $false
            $secretName = "RefreshTokenForADOScan"
            $tokenSecret = Get-AzKeyVaultSecret -VaultName $env:KeyVaultName -Name $secretName
            if (-not [string]::IsNullOrEmpty($tokenSecret) -and [Helpers]::CheckMember($tokenSecret,"Expires")) {
                if ($tokenSecret.Expires -le [DateTime]::Now.AddDays(1))
                {
                    $updateTokenInKV = $true
                }
            }
            else {
                $updateTokenInKV = $true
            }
            if ($updateTokenInKV -eq $true)
            {
                $RefreshTokenExpiresInDays = [Constants]::RefreshTokenExpiresInDays;
                $ExpiryDate = [DateTime]::Now.AddDays($RefreshTokenExpiresInDays)
                Set-AzKeyVaultSecret -VaultName $env:KeyVaultName -Name $secretName -SecretValue $refreshToken -Expires $ExpiryDate | out-null
            }
        }
        catch{
            write-Host "Error fetching OAuth access token"
            Write-Host $_
            return $null
        }
        return $tokenInfo
    }

    static [string] GetAccessToken([string] $resourceAppIdUri) {
            return [ContextHelper]::GetAccessToken()   
    }

    static [string] GetAccessToken()
    {
        if([ContextHelper]::currentContext)
        {
            # Validate if token is PAT using lenght (PAT has lengh of 52), if PAT dont go to refresh login session.
            #TODO: Change code to find token type supplied PAT or login session token
            #if token expiry is within 2 min, refresh. ([ContextHelper]::currentContext.AccessToken.length -ne 52)
            if ( [ContextHelper]::IsPATUsed -eq $false -and ([ContextHelper]::currentContext.TokenExpireTimeLocal -le [DateTime]::Now.AddMinutes(2)))
            {
                [ContextHelper]::GetCurrentContext($true);
            }
            return  [ContextHelper]::currentContext.AccessToken
        }
        else
        {
            return $null
        }
    }
    
    static [string] GetAccessToken([string] $Uri, [string] $tenantId) 
    {
        $rmContext = Get-AzContext
        if (-not $rmContext) {
            throw ([SuppressedException]::new(("No Azure login found"), [SuppressedExceptionType]::InvalidOperation))
        }
        
        if ([string]::IsNullOrEmpty($tenantId) -and [Helpers]::CheckMember($rmContext,"Tenant")) {
            $tenantId = $rmContext.Tenant.Id
        }
        
        $authResult = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
        $rmContext.Account,
        $rmContext.Environment,
        $tenantId,
        [System.Security.SecureString] $null,
        "Never",
        $null,
        $Uri);
        
        if (-not ($authResult -and (-not [string]::IsNullOrWhiteSpace($authResult.AccessToken)))) {
          throw ([SuppressedException]::new(("Unable to get access token. Authentication Failed."), [SuppressedExceptionType]::Generic))
        }
        return $authResult.AccessToken;
    }

    
    static [string] GetGraphAccessToken($useAzContext)
	{
        $accessToken = ''
        try
        {   
            Write-Host "Graph access is required to evaluate some controls. Attempting to acquire graph token." -ForegroundColor Cyan
            # In CA mode, we use azure context to fetch the graph access token.
            if ($useAzContext)
            {
                #getting azure context because graph access token requires azure environment details.
                $Context = @(Get-AzContext -ErrorAction SilentlyContinue )
                if ($Context.count -eq 0)  
                {
                    
                    Connect-AzAccount -ErrorAction Stop
                    $Context = @(Get-AzContext -ErrorAction SilentlyContinue)
                }

                if ($null -eq $Context)  
                {
                    throw "Unable to acquire Graph token. The signed-in account may not have Graph permission. Control results for controls that depend on AAD group expansion may not be accurate."
                }
                else
                {
                    $graphUri = "https://graph.microsoft.com"
                    $authResult = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
                    $Context.Account,
                    $Context.Environment,
                    $Context.Tenant.Id,
                    [System.Security.SecureString] $null,
                    "Never",
                    $null,
                    $graphUri);

                    if (-not ($authResult -and (-not [string]::IsNullOrWhiteSpace($authResult.AccessToken))))
                    {
                        throw ([SuppressedException]::new(("Unable to acquire Graph token. The signed-in account may not have Graph permission. Control results for controls that depend on AAD group expansion may not be accurate."), [SuppressedExceptionType]::Generic))
                    }

                    $accessToken = $authResult.AccessToken;
                }
            }
            else 
            {
                # generating graph access token using default VSTS client.
                $clientId = [Constants]::DefaultClientId;          
                $replyUri = [Constants]::DefaultReplyUri; 
                $adoResourceId = "https://graph.microsoft.com/";
                                         
                if ([ContextHelper]::PSVersion -gt 5) {
                    $result = [ContextHelper]::GetGraphAccess()
                }
                else {
                    [AuthenticationContext] $ctx = [AuthenticationContext]::new("https://login.windows.net/common");
                    [AuthenticationResult] $result = $null;
                    $PromptBehavior = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto
                    $PlatformParameters = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters -ArgumentList $PromptBehavior
                    $result = $ctx.AcquireTokenAsync($adoResourceId, $clientId, [Uri]::new($replyUri),$PlatformParameters).Result;
                }
                $accessToken = $result.AccessToken
            }
            Write-Host "Successfully acquired graph access token." -ForegroundColor Cyan
        }
        catch
        {
            Write-Host "Unable to acquire Graph token. The signed-in account may not have Graph permission. Control results for controls that depend on AAD group expansion may not be accurate." -ForegroundColor Red
            Write-Host "Continuing without graph access." -ForegroundColor Yellow
            return $null
        }

		return $accessToken;
	}

    static [string] GetDataExplorerAccessToken($useAzContext)
	{
        $accessToken = ''
        try
        {   
            if ($useAzContext)
            {
                #Using managed identity context to fetch data explorer token for CA.
                $Context = @(Get-AzContext -ErrorAction SilentlyContinue )
                if ($Context.count -eq 0)  
                {
                    Connect-AzAccount -ErrorAction Stop
                    $Context = @(Get-AzContext -ErrorAction SilentlyContinue)
                }

                if ($null -eq $Context)  
                {
                    throw "Unable to acquire data explorer token. The signed-in account may not have permission on data explorer. Control results for controls that depend on AAD group expansion may not be accurate."
                }
                else
                {
                    $kustoUri = "https://help.kusto.windows.net"
                    $authResult = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
                    $Context.Account,
                    $Context.Environment,
                    $Context.Tenant.Id,
                    [System.Security.SecureString] $null,
                    "Never",
                    $null,
                    $kustoUri);

                    if (-not ($authResult -and (-not [string]::IsNullOrWhiteSpace($authResult.AccessToken))))
                    {
                        throw ([SuppressedException]::new(("Unable to data explorer token. The signed-in account may not have permission on data explorer. Control results for controls that depend on AAD group expansion may not be accurate."), [SuppressedExceptionType]::Generic))
                    }

                    $accessToken = $authResult.AccessToken;
                }
            }
            else 
            {
                # generating data explorer token using default VSTS client.
                $clientId = [Constants]::DefaultClientId;          
                $replyUri = [Constants]::DefaultReplyUri; 
                $adoResourceId = "https://help.kusto.windows.net";                                         
                if ([ContextHelper]::PSVersion -gt 5) {
                    $result = [ContextHelper]::GetGraphAccess()
                }
                else {
                    [AuthenticationContext] $ctx = [AuthenticationContext]::new("https://login.windows.net/common");
                    [AuthenticationResult] $result = $null;
                    $PromptBehavior = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Auto
                    $PlatformParameters = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters -ArgumentList $PromptBehavior
                    $result = $ctx.AcquireTokenAsync($adoResourceId, $clientId, [Uri]::new($replyUri),$PlatformParameters).Result;
                }
                $accessToken = $result.AccessToken
            }
        }
        catch
        {
            return $null
        }

		return $accessToken;
	}

    static [string] GetLAWSAccessToken()
	{
        $accessToken = ''
        try
        {              
            #getting azure context because graph access token requires azure environment details.
            $Context = @(Get-AzContext -ErrorAction SilentlyContinue )
            if ($Context.count -eq 0)  
            {                    
                Connect-AzAccount -ErrorAction Stop
                $Context = @(Get-AzContext -ErrorAction SilentlyContinue)
            }

            if ($null -eq $Context)  
            {
                throw "Unable to acquire Graph token. The signed-in account may not have Graph permission. Control results for controls that depend on AAD group expansion may not be accurate."
            }
            else
            {                
                $authResult = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
                $Context.Account,
                $Context.Environment,
                $Context.Tenant.Id,
                [System.Security.SecureString] $null,
                "Never",
                $null,
                "https://api.loganalytics.io/");

                if (-not ($authResult -and (-not [string]::IsNullOrWhiteSpace($authResult.AccessToken))))
                {
                    throw ([SuppressedException]::new(("Unable to acquire Graph token. The signed-in account may not have Graph permission. Control results for controls that depend on AAD group expansion may not be accurate."), [SuppressedExceptionType]::Generic))
                }

                $accessToken = $authResult.AccessToken;
            }                                  
        }
        catch
        {
            Write-Host "Unable to acquire Graph token. The signed-in account may not have Graph permission. Control results for controls that depend on AAD group expansion may not be accurate." -ForegroundColor Red
            Write-Host "Continuing without graph access." -ForegroundColor Yellow
            return $null
        }

		return $accessToken;        
	}

    hidden static [PSobject] GetGraphAccess()
    {
        $rootConfigPath = [Constants]::AzSKAppFolderPath;
        $azskSettings = (Get-Content -Raw -Path (Join-Path $rootConfigPath "AzSKSettings.json")) | ConvertFrom-Json
        if ([ContextHelper]::IsPATUsed -and $azskSettings -and $azskSettings.LASource -ne "CICD") {
            $Context = @(Get-AzContext -ErrorAction SilentlyContinue)
            if ($null -eq $Context -or $Context.count -eq 0) {
                Connect-AzAccount -ErrorAction Stop
                $Context = @(Get-AzContext -ErrorAction SilentlyContinue)
            }
            if ($null -eq $Context) {
                throw 
            }
            else {
                $graphUri = "https://graph.microsoft.com"
                $authResult = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
                $Context.Account,
                $Context.Environment,
                $Context.Tenant.Id,
                [System.Security.SecureString] $null,
                "Never",
                $null,
                $graphUri);

                return $authResult;
            }
        }
        else {
            $ClientId = [Constants]::DefaultClientId
            [Microsoft.Identity.Client.IPublicClientApplication] $appGrapth = [Microsoft.Identity.Client.PublicClientApplicationBuilder]::Create($ClientId).Build();
            if (![ContextHelper]::Account) {
                [ContextHelper]::Account = $appGrapth.GetAccountsAsync().GetAwaiter().GetResult() | Select-Object -First 1
            }
            $tokenSource = New-Object System.Threading.CancellationTokenSource
            $taskAuthenticationResult=$null
            $AquireTokenParameters = $null;
            [string[]] $Scopes = "https://graph.microsoft.com/.default";

            $AquireTokenParameters = [ContextHelper]::appObj.AcquireTokenSilent($Scopes, [ContextHelper]::Account)
            try {
                $taskAuthenticationResult = $AquireTokenParameters.ExecuteAsync($tokenSource.Token)
                if ( [Helpers]::CheckMember($taskAuthenticationResult, "exception.message") -and ($taskAuthenticationResult.exception.message -like "*errors occurred*")) {
                    $AquireTokenParameters = $appGrapth.AcquireTokenInteractive($Scopes)
                    $taskAuthenticationResult = $AquireTokenParameters.ExecuteAsync($tokenSource.Token)
                }
            }
            catch {
                $AquireTokenParameters = $appGrapth.AcquireTokenInteractive($Scopes)
                $taskAuthenticationResult = $AquireTokenParameters.ExecuteAsync($tokenSource.Token)
            }
        }
        
        return $taskAuthenticationResult.result;
    }

    hidden [OrganizationContext] SetContext([string] $organizationName)
    {
        if((-not [string]::IsNullOrEmpty($organizationName)))
              {
                     $OrganizationContext = [OrganizationContext]@{
                           OrganizationId = $organizationName;
                           Scope = "/Organization/$organizationName";
                           OrganizationName = $organizationName;
                     };
                     # $organizationId contains the organization name (due to framework).
                     [ContextHelper]::orgName = $organizationName;
                     [ContextHelper]::GetCurrentContext()                  
              }
              else
              {
                     throw [SuppressedException] ("OrganizationName name [$organizationName] is either malformed or incorrect.")
        }
        return $OrganizationContext;
    }

    hidden [OrganizationContext] SetContext([string] $organizationName, [System.Security.SecureString] $PATToken)
    {
        if((-not [string]::IsNullOrEmpty($organizationName)))
              {
                     $OrganizationContext = [OrganizationContext]@{
                           OrganizationId = $organizationName;
                           Scope = "/Organization/$organizationName";
                           OrganizationName = $organizationName;
                     };
                     # $organizationId contains the organization name (due to framework).
                     [ContextHelper]::orgName = $organizationName;
                     [ContextHelper]::GetCurrentContext($PATToken)         
              }
              else
              {
                     throw [SuppressedException] ("OrganizationName name [$organizationName] is either malformed or incorrect.")
        }
        return $OrganizationContext;
    }

    static [void] ResetCurrentContext()
    {
        
    }

    hidden static ConvertToContextObject([PSObject] $context)
    {
        $contextObj = [Context]::new()
        # We do not get ADO organization id as part of current context. Hence appending org name to both id and name param.
        $contextObj.Organization = [Organization]::new()
        $contextObj.Organization.Id = [ContextHelper]::orgName
        $contextObj.Organization.Name = [ContextHelper]::orgName

        if([ContextHelper]::IsOAuthScan) { # this if block will be executed for OAuth based scan
            $contextObj.Account.Id = [ContextHelper]::GetOAuthUserIdentity($context.AccessToken, $contextObj.Organization.Name)
            $contextObj.AccessToken = $context.AccessToken
            $contextObj.TokenExpireTimeLocal = $context.ExpiresOn
        }
        else {
            if ([ContextHelper]::PSVersion -gt 5) {
                $contextObj.Account.Id = $context.Account.username
            }
            else {
                $contextObj.Account.Id = $context.UserInfo.DisplayableId
            }
            $contextObj.Tenant.Id = $context.TenantId
            $contextObj.AccessToken = $context.AccessToken

            $contextObj.TokenExpireTimeLocal = $context.ExpiresOn.LocalDateTime
            #$contextObj.AccessToken =  ConvertTo-SecureString -String $context.AccessToken -asplaintext -Force
        }
        [ContextHelper]::currentContext = $contextObj
    }
    
    hidden static [string] GetOAuthUserIdentity($accessToken, $orgName)
    {
        $apiURL = "https://dev.azure.com/{0}/_apis/connectionData" -f $orgName
        $headers =@{
            Authorization = "Bearer $accesstoken";
            "Content-Type"="application/json"
        };
        try{
            $responseObj = Invoke-RestMethod -Method Get -Uri $apiURL -Headers $headers -UseBasicParsing
            $descriptor = $responseObj.authenticatedUser.descriptor
            $userId = ($descriptor -split '\\')[-1]
            return $userId
        }
        catch{
            return ""
        }
    }

    hidden static ConvertToContextObject([System.Security.SecureString] $patToken)
    {
        $contextObj = [Context]::new()
        $contextObj.Account.Id = [string]::Empty
        $contextObj.Tenant.Id =  [string]::Empty
        $contextObj.AccessToken = [System.Net.NetworkCredential]::new("", $patToken).Password
        
        # We do not get ADO organization Id as part of current context. Hence appending org name to both Id and Name param.
        $contextObj.Organization = [Organization]::new()
        $contextObj.Organization.Id = [ContextHelper]::orgName
        $contextObj.Organization.Name = [ContextHelper]::orgName 

        #$contextObj.AccessToken = $patToken
        #$contextObj.AccessToken =  ConvertTo-SecureString -String $context.AccessToken -asplaintext -Force
        [ContextHelper]::currentContext = $contextObj


        $apiURL = "https://dev.azure.com/{0}/_apis/connectionData" -f [ContextHelper]::orgName
        #Note: cannot use this WRH method below due to ordering constraints during load in Framework.ps1
        #$header = [WebRequestHelper]::GetAuthHeaderFromUri($apiURL);
        $user = ""
        $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user, $contextObj.AccessToken)))
        $headers = @{
                        "Authorization"= ("Basic " + $base64AuthInfo); 
                        "Content-Type"="application/json"
                    };
        $responseObj = Invoke-RestMethod -Method Get -Uri $apiURL -Headers $headers -UseBasicParsing

        #If the token is valid, we get: "descriptor"="Microsoft.IdentityModel.Claims.ClaimsIdentity;72f988bf-86f1-41af-91ab-2d7cd011db47\xyz@microsoft.com"
        #Note that even for guest users, we get the host tenant (and not their native tenantId). E.g., "descriptor...;72f...47\pqr@live.com"
        #If the token is invalid, we get a diff object: "descriptor":"System:PublicAccess;aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        $authNUserInfo = @(($responseObj.authenticatedUser.descriptor -split ';') -split '\\')
    
        #Check if the above split resulted in 3 elements (valid token case)
        if ($authNUserInfo.Count -eq 3)
        {
            $contextObj.Tenant.Id = $authNUserInfo[1]
            $contextObj.Account.Id = $authNUserInfo[2]
        }
        elseif ([Helpers]::CheckMember($responseObj.authenticatedUser,"customDisplayName")) {
            $contextObj.Account.Id = $responseObj.authenticatedUser.customDisplayName;
        }
    }

    static [string] GetCurrentSessionUser() {
        $context = [ContextHelper]::GetCurrentContext()
        if ($null -ne $context) {
            return $context.Account.Id
        }
        else {
            return "NO_ACTIVE_SESSION"
        }
    }    

}