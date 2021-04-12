<#
.Description
# Context class for indenity details. 
# Provides functionality to login, create context, get token for api calls
#>
using namespace Microsoft.IdentityModel.Clients.ActiveDirectory

class ContextHelper {
    
    static hidden [Context] $currentContext;
    
    #This will be used to carry current org under current context.
    static hidden [string] $orgName;
    hidden static [PSObject] GetCurrentContext()
    {
        return [ContextHelper]::GetCurrentContext($false);
    }

    hidden static [PSObject] GetCurrentContext([bool]$authNRefresh)
    {
        if( (-not [ContextHelper]::currentContext) -or $authNRefresh)
        {
            $clientId = [Constants]::DefaultClientId ;          
            $replyUri = [Constants]::DefaultReplyUri; 
            $adoResourceId = [Constants]::DefaultADOResourceId;
            [AuthenticationContext] $ctx = $null;

            $ctx = [AuthenticationContext]::new("https://login.windows.net/common");

            [AuthenticationResult] $result = $null;

            $azSKUI = $null;
            if(-not [string]::IsNullOrWhiteSpace($env:RefreshToken) -and -not [string]::IsNullOrWhiteSpace($env:ClientSecret)) { # this if block will be executed for OAuth based scan
                $tokenInfo = [ContextHelper]::GetOAuthAccessToken()
                [ContextHelper]::ConvertToContextObject($tokenInfo)
            }
            else {
                if ( !$authNRefresh -and ($azSKUI = Get-Variable 'AzSKADOLoginUI' -Scope Global -ErrorAction 'Ignore')) {
                    if ($azSKUI.Value -eq 1) {
                        $PromptBehavior = [Microsoft.IdentityModel.Clients.ActiveDirectory.PromptBehavior]::Always
                        $PlatformParameters = New-Object Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters -ArgumentList $PromptBehavior
                        $result = $ctx.AcquireTokenAsync($adoResourceId, $clientId, [Uri]::new($replyUri),$PlatformParameters).Result;
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

                [ContextHelper]::ConvertToContextObject($result)
            }
        }
        return [ContextHelper]::currentContext
    }
    
    hidden static [PSObject] GetCurrentContext([System.Security.SecureString] $PATToken)
    {
        if(-not [ContextHelper]::currentContext)
        {
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
            Set-AzKeyVaultSecret -VaultName $env:KeyVaultName -Name "RefreshTokenForADOScan" -SecretValue $refreshToken | out-null
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
            #if token expiry is within 2 min, refresh.
            if (([ContextHelper]::currentContext.AccessToken.length -ne 52) -and ([ContextHelper]::currentContext.TokenExpireTimeLocal -le [DateTime]::Now.AddMinutes(2)))
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

        if(-not [string]::IsNullOrWhiteSpace($env:RefreshToken) -and -not [string]::IsNullOrWhiteSpace($env:ClientSecret)) { # this if block will be executed for OAuth based scan
            $contextObj.Account.Id = [ContextHelper]::GetOAuthUserIdentity($context.AccessToken, $contextObj.Organization.Name)
            $contextObj.AccessToken = $context.AccessToken
            $contextObj.TokenExpireTimeLocal = $context.ExpiresOn
        }
        else {
            $contextObj.Account.Id = $context.UserInfo.DisplayableId
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