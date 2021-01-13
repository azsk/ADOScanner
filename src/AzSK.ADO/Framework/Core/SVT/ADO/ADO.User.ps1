Set-StrictMode -Version Latest 
class User: ADOSVTBase {    

    User([string] $subscriptionId, [SVTResource] $svtResource): Base($subscriptionId, $svtResource) {

    }

    hidden [ControlResult] CheckPATAccessLevel([ControlResult] $controlResult) {
        $apiURL = "https://vssps.dev.azure.com/{0}/_apis/Token/SessionTokens?displayFilterOption=1&createdByOption=3&sortByOption=3&isSortAscending=false&startRowNumber=1&pageSize=100&api-version=5.0-preview.1" -f $($this.SubscriptionContext.SubscriptionName);
        $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
        $controlResult.AddMessage("Currently this control evaluates PATs for all the organizations the user has access to.")
        try {
            if ($responseObj.Count -gt 0) {
                $AccessPATList = $responseObj | Where-Object { $_.validto -gt $(Get-Date -Format "yyyy-MM-dd") }
                $AccessPATListCount = ($AccessPATList | Measure-Object).Count
                if ($AccessPATListCount -gt 0) {
                    $controlResult.AddMessage("Total number of active user PATs: $($AccessPATListCount)");
                    $controlResult.AdditionalInfo += "Total number of active user PATs: " + $AccessPATListCount;
                    $statusSet = $false # Use this variable to check whether scanStaus is already set

                    $fullAccessPATList = $AccessPATList | Where-Object { $_.scope -eq "app_token" }
                    $fullAccessPATListCount = ($fullAccessPATList | Measure-Object).Count 
                    if ($fullAccessPATListCount -gt 0) {
                        $controlResult.AddMessage("`nTotal number of PATs configured with full access: $($fullAccessPATListCount)");
                        $controlResult.AdditionalInfo += "Total number of PATs configured with full access: " + $fullAccessPATListCount;
                        $fullAccessPATNames = $fullAccessPATList | Select-Object displayName, scope 
                        $controlResult.AddMessage([VerificationResult]::Failed,
                            "The following PATs have been configured with full access: ", $fullAccessPATNames);
                        $statusSet = $true
                    }

                    $remainingPATList = $AccessPATList | Where-Object { $_.scope -ne "app_token" }
                    $remainingPATListCount = ($remainingPATList | Measure-Object).Count
                    if ($remainingPATListCount -gt 0){
                        $controlResult.AddMessage("`nTotal number of PATs configured with custom defined access: $remainingPATListCount");
                        $controlResult.AdditionalInfo += "Total number of PATs configured with custom defined access: " + $remainingPATListCount;
                        $remainingAccessPATNames = $remainingPATList | Select-Object displayName, scope 
                        if ($statusSet) {
                            $controlResult.AddMessage("The following PATs have been configured with custom defined access: ", $remainingAccessPATNames)
                        }   
                        else {
                            $controlResult.AddMessage([VerificationResult]::Verify, "Verify that the following PATs have minimum required permissions: ", $remainingAccessPATNames)                        
                        }
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed,
                        "No active PATs found");
                }
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed,
                    "No PATs found");
            }
                    
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error,
                "Could not fetch the list of PATs");
        }
        
        return $controlResult;
    }

    hidden [ControlResult] CheckAltCred([ControlResult] $controlResult) {

        $apiURL = "https://dev.azure.com/{0}/_apis/Contribution/dataProviders/query?api-version=5.1-preview.1" -f $($this.SubscriptionContext.SubscriptionName);
        $inputbody = '{"contributionIds": ["ms.vss-admin-web.alternate-credentials-data-provider","ms.vss-admin-web.action-url-data-provider"]}' | ConvertFrom-Json
        $responseObj = [WebRequestHelper]::InvokePostWebRequest($apiURL, $inputbody);

        if ([Helpers]::CheckMember($responseObj, "data"), $responseObj.data.'ms.vss-admin-web.alternate-credentials-data-provider') {
            if ((-not $responseObj.data.'ms.vss-admin-web.alternate-credentials-data-provider'.alternateCredentialsModel.basicAuthenticationDisabled) -or (-not $responseObj.data.'ms.vss-admin-web.alternate-credentials-data-provider'.alternateCredentialsModel.basicAuthenticationDisabledOnAccount)) {
                $controlResult.AddMessage([VerificationResult]::Passed,
                    "Alt credential is disabled");
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed,
                    "Alt credential is enabled");
            }
        }
        else {
            $controlResult.AddMessage([VerificationResult]::Manual,
                "Alt credential not found");
        }
        return $controlResult
    }

    hidden [ControlResult] ValidatePATExpiryPeriod([ControlResult] $controlResult) {
        $controlResult.AddMessage("Currently this control evaluates PATs for all the organizations the user has access to.")  
        try {

            $apiURL = "https://vssps.dev.azure.com/{0}/_apis/Token/SessionTokens?displayFilterOption=1&createdByOption=3&sortByOption=3&isSortAscending=false&startRowNumber=1&pageSize=100&api-version=5.0-preview.1" -f $($this.SubscriptionContext.SubscriptionName);
            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);

            if ($responseObj.Count -gt 0) { 
                $AccessPATList = $responseObj | Where-Object { $_.validto -gt $(Get-Date -Format "yyyy-MM-dd") }
           
                if (($AccessPATList | Measure-Object).Count -gt 0) {
                    $res = $AccessPATList | Where-Object {(New-Timespan -Start $_.ValidFrom -End $_.ValidTo).Days -gt 180 }
                
                    if (($res | Measure-Object).Count -gt 0) {
                        $PATList = ($res | Select-Object -Property @{Name = "Name"; Expression = { $_.displayName } }, @{Name = "ValidFrom"; Expression = { $_.validfrom } }, @{Name = "ValidTo"; Expression = { $_.validto } }, @{Name = "ValidationPeriod"; Expression = { (New-Timespan -Start $_.ValidFrom -End $_.ValidTo).Days } });    
                        $controlResult.AddMessage([VerificationResult]::Failed, "The following PATs have validity period of more than 180 days: ", $PATList)
                        $PATListCount = ($PATList | Measure-Object).Count  
                        $controlResult.AdditionalInfo += "Total number of PATs that have validity period of more than 180 days: " + $PATListCount;
                        $controlResult.AdditionalInfo += "List of PATs that have validity period of more than 180 days: " + [JsonHelper]::ConvertToJsonCustomCompressed($PATList);
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Passed,
                            "No PATs have been found with validity period of more than 180 days.") 
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed,
                        "No active PATs have been found.")  
                }
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed,
                    "No PATs have been found.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error,
                "Could not fetch the list of PATs.");
        }
        
        return $controlResult;
    }
    hidden [ControlResult] CheckPATExpiration([ControlResult] $controlResult) {
        $controlResult.AddMessage("Currently this control evaluates PATs for all the organizations the user has access to.")
        try {

            $apiURL = "https://vssps.dev.azure.com/{0}/_apis/Token/SessionTokens?displayFilterOption=1&createdByOption=3&sortByOption=3&isSortAscending=false&startRowNumber=1&pageSize=100&api-version=5.0-preview.1" -f $($this.SubscriptionContext.SubscriptionName);
            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);

            if ($responseObj.Count -gt 0) { 
                $date = Get-Date;
                $AccessPATList = $responseObj | Where-Object { $_.validto -gt $(Get-Date -Format "yyyy-MM-dd") }
           
                if (($AccessPATList | Measure-Object).Count -gt 0) {
                    $PATExpri7Days = $AccessPATList | Where-Object { (New-Timespan -Start $date -End $_.validto ).Days  -lt 8 };
                    $PATExpri30Days = $AccessPATList | Where-Object { ((New-Timespan -Start $date -End $_.validto).Days -gt 7) -and ((New-Timespan -Start $date -End $_.validto).Days -lt 31) };
                    $PATOther = $AccessPATList | Where-Object { ((New-Timespan -Start $date -End $_.validto).Days -gt 30) };

                    if (($PATExpri7Days | Measure-Object).Count -gt 0) {
                        $PAT7List = ($PATExpri7Days | Select-Object -Property @{Name = "Name"; Expression = { $_.displayName } }, @{Name = "ValidFrom"; Expression = { $_.validfrom } }, @{Name = "ValidTo"; Expression = { $_.validto } }, @{Name = "Remaining"; Expression = { (New-Timespan -Start $date -End $_.validto).Days } });    
                        $controlResult.AddMessage("The following PATs expire within 7 days: ", $PAT7List )
                        $controlResult.AdditionalInfo += "Total number of PATs that will expire within 7 days: " + ($PAT7List | Measure-Object).Count;
                    }
                    if (($PATExpri30Days | Measure-Object).Count -gt 0) {
                        $PAT30List = ($PATExpri30Days | Select-Object -Property @{Name = "Name"; Expression = { $_.displayName } }, @{Name = "ValidFrom"; Expression = { $_.validfrom } }, @{Name = "ValidTo"; Expression = { $_.validto } }, @{Name = "Remaining"; Expression = { (New-Timespan -Start $date -End $_.validto).Days } });    
                        $controlResult.AddMessage("The following PATs expire after 7 days but within 30 days: ", $PAT30List )
                        $controlResult.AdditionalInfo += "Total number of PATs that will expire after 7 days but within 30 days: " + ($PAT30List | Measure-Object).Count;
                    }
              
                    if (($PATOther | Measure-Object).Count -gt 0) {
                        $PATOList = ($PATOther | Select-Object -Property @{Name = "Name"; Expression = { $_.displayName } }, @{Name = "ValidFrom"; Expression = { $_.validfrom } }, @{Name = "ValidTo"; Expression = { $_.validto } }, @{Name = "Remaining"; Expression = { (New-Timespan -Start $date -End $_.validto).Days } });    
                        $controlResult.AddMessage("The following PATs expire after 30 days: ", $PATOList )
                        $controlResult.AdditionalInfo += "Total number of PATs that will expire after 30 days: " + ($PATOList | Measure-Object).Count;
                    }
                    if (($PATExpri7Days | Measure-Object).Count -gt 0) {
                        $controlResult.VerificationResult = [VerificationResult]::Failed
                    }
                    elseif (($PATExpri30Days | Measure-Object).Count -gt 0) {
                        $controlResult.VerificationResult = [VerificationResult]::Verify
                    }
                    else {
                        $controlResult.AddMessage([VerificationResult]::Passed, "No PATs have been found which expire within 30 days.")
                    }
                }
                else {
                    $controlResult.AddMessage([VerificationResult]::Passed,
                        "No active PATs have been found.")  
                }
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed,
                    "No PATs have been found.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error,
                "Could not fetch the list of PATs.");
        }
        
        return $controlResult;
    }

    hidden [ControlResult] CheckPATOrgAccess([ControlResult] $controlResult) {
        $apiURL = "https://{0}.vssps.visualstudio.com/_apis/Token/SessionTokens?displayFilterOption=1&createdByOption=3&sortByOption=3&isSortAscending=false&startRowNumber=1&pageSize=100&api-version=5.0-preview.1" -f $($this.SubscriptionContext.SubscriptionName);
        $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
        $controlResult.AddMessage("Currently this control evaluates PATs for all the organizations the user has access to.")
        try {
            if ($responseObj.Count -gt 0) {
                $AccessPATList = $responseObj | Where-Object { $_.validto -gt $(Get-Date -Format "yyyy-MM-dd") }
                $AccessPATListCount = ($AccessPATList | Measure-Object).Count
                $allOrgPATCount = 0; #counter to store number of PATs that are accessible to all orgs.
                $allOrgPAT = @() #list to capture PAts accessible to all orgs.

                if ($AccessPATListCount -gt 0) {
                    $controlResult.AddMessage("Total number of active user PATs: $($AccessPATListCount)");
                    $AccessPATList | ForEach-Object{
                        if([string]::IsNullOrWhiteSpace($_.targetAccounts)) #if a PAT is tied to a single org, value of targetAccounts is equal to org id. If its accessible to all orgs, this value is null.
                        {
                            $allOrgPATCount ++;
                            $allOrgPAT += $_.DisplayName
                        }
                    }
                    if($allOrgPATCount -gt 0)
                    {   
                        $controlResult.AddMessage("Total number of active PATs accessible to all organizations: $($allOrgPATCount)");
                        $controlResult.AddMessage([VerificationResult]::Failed, "The below active PATs are accessible to all organizations: ", $allOrgPAT);
                        $controlResult.AdditionalInfo += "Total number of active PATs accessible to all organizations: " + $allOrgPATCount;
                        $controlResult.AdditionalInfo += "List of active PATs accessible to all organizations: " + [JsonHelper]::ConvertToJsonCustomCompressed($allOrgPAT);
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed, "No active PATs are accessible to all organizations.");
                    }
                }
                else 
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No active PATs found.");
                }
            }
            else 
            {
                $controlResult.AddMessage([VerificationResult]::Passed, "No PATs found.");
            }
                    
        }
        catch 
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of PATs");
        }
        
        return $controlResult;
    }

    hidden [ControlResult] CheckPATCriticalPermissions([ControlResult] $controlResult) {
        $controlResult.AddMessage("Currently this control evaluates PATs for all the organizations the user has access to.")
        try
        {
            $apiURL = "https://vssps.dev.azure.com/{0}/_apis/Token/SessionTokens?displayFilterOption=1&createdByOption=3&sortByOption=3&isSortAscending=false&startRowNumber=1&pageSize=100&api-version=5.0-preview.1" -f $($this.SubscriptionContext.SubscriptionName);
            $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
            if(($null -ne $this.ControlSettings) -and [Helpers]::CheckMember($this.ControlSettings, "CriticalPATPermissions"))
            {
                $patterns = $this.ControlSettings.CriticalPATPermissions
                if ($responseObj.Count -gt 0)
                {
                    $AccessPATList = $responseObj | Where-Object { $_.validto -gt $(Get-Date -Format "yyyy-MM-dd") }
                    $AccessPATListCount = ($AccessPATList | Measure-Object).Count
                    if ($AccessPATListCount -gt 0)
                    {
                        $fullAccessPATList = $AccessPATList | Where-Object { $_.scope -eq "app_token" }
                        $customAccessPATList = $AccessPATList | Where-Object { $_.scope -ne "app_token" }
                        $fullAccessPATListCount = ($fullAccessPATList | Measure-Object).Count
                        $PATWithCriticalAccess = @();
                        if(($patterns | Measure-Object).Count -gt 0)
                        {
                            $controlResult.AddMessage("`nNote: The following permission scopes are considered as 'critical': `n`t[$($patterns -join ', ')]");
                            foreach ($pat in $customAccessPATList) 
                            {
                                foreach ($item in $patterns)
                                {
                                    if($pat.scope.contains($item))
                                    {
                                        $PATWithCriticalAccess += $pat
                                        break;
                                    }
                                }
                            }
                        }
                        $PATWithCriticalAccessCount = ($PATWithCriticalAccess | Measure-Object).Count
                        if (($PATWithCriticalAccessCount -gt 0) -or ($fullAccessPATListCount -gt 0))
                        {
                            $controlResult.AddMessage([VerificationResult]::Failed, "`nUser has PATs that are configured with critical permissions.");
                            if ($PATWithCriticalAccessCount -gt 0)
                            {
                                $controlResult.AddMessage("`nTotal number of PATs configured with critical permissions: $($PATWithCriticalAccessCount)");                        
                                $controlResult.AdditionalInfo += "Total number of PATs configured with critical permissions: " + $PATWithCriticalAccessCount;
                                $criticalPAT = $PATWithCriticalAccess | Select-Object displayName, scope 
                                $controlResult.AddMessage("List of PATs configured with critical permissions: ", $criticalPAT);
                            }
                            if ($fullAccessPATListCount -gt 0)
                            {
                                $controlResult.AddMessage([VerificationResult]::Failed, "`nTotal number of PATs configured with full access: $($fullAccessPATListCount)");                        
                                $controlResult.AdditionalInfo += "Total number of PATs configured with full access: " + $fullAccessPATListCount;
                                $fullAccessPAT = $fullAccessPATList | Select-Object displayName, scope 
                                $controlResult.AddMessage("List of PATs configured with full access: ", $fullAccessPAT);
                            }
                        }
                        else
                        {
                            $controlResult.AddMessage([VerificationResult]::Passed, "No PATs are configured with critical permissions.");
                            $controlResult.AdditionalInfo += "No PATs are configured with critical permissionss.";
                        }
                    }
                    else
                    {
                        $controlResult.AddMessage([VerificationResult]::Passed, "No active PATs found.");
                    }
                }
                else
                {
                    $controlResult.AddMessage([VerificationResult]::Passed, "No PATs found.");
                }
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Manual, "Critical permission scopes for PAT are not defined in your organization.");
            }      
        }
        catch
        {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of PATs.");
        }
        
        return $controlResult;
    }

}