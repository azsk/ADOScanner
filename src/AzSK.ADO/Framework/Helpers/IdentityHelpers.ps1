Set-StrictMode -Version Latest 

class IdentityHelpers
{
	static hidden [bool] $hasGraphAccess = $false
	static hidden [string] $graphAccessToken = $null
	static hidden [string] $ALTControlEvaluationMethod
	static hidden [bool] $hasSIPAccess = $false
	static hidden [string] $dataExplorerAccessToken = $null

	hidden static [bool] IsAltAccount($SignInName, $graphToken)
	{
		$isAltAccount = $false
		$headers = @{"Authorization"= ("Bearer " + $graphToken); "Content-Type"="application/json"}
		$uri=""
		$graphURI = [WebRequestHelper]::GetGraphUrl()

		if (-not [string]::IsNullOrWhiteSpace($SignInName))
		{
			$uri = [string]::Format('{0}/v1.0/users/{1}?$select=onPremisesExtensionAttributes', $graphURI, $SignInName)
		}
		else
		{
			return $false
		}


		try
		{ 
			$responseObj = [WebRequestHelper]::InvokeGetWebRequest($uri, $headers);
			if ($null -ne $responseObj -and ($responseObj | Measure-Object).Count -gt 0)
			{
				# extensionAttribute contains 15 different values which define unique properties for users.
				$extensionAttributes = $responseObj.onPremisesExtensionAttributes
				#"extensionAttribute2" contains the integer values which represents the different types of users.
				#"extensionAttribute2: -10" => SC-ALT Accounts
				if($extensionAttributes.extensionAttribute2 -eq "-10")
				{
					$isAltAccount = $true
				}
			}
		} 
		catch
		{ 
			return $false;
		}
		return $isAltAccount
	}

	hidden static [bool] IsServiceAccount($SignInName, $subjectKind, $graphToken)
	{
		$isServiceAccount = $false
		$headers = @{"Authorization"= ("Bearer " + $graphToken); "Content-Type"="application/json"}
		$uri=""
		$graphURI = [WebRequestHelper]::GetGraphUrl()
		if($subjectKind -eq "User")
		{
			if (-not [string]::IsNullOrWhiteSpace($SignInName))
			{
				$uri = [string]::Format('{0}/v1.0/users/{1}?$select=onPremisesImmutableId,onPremisesExtensionAttributes', $graphURI, $SignInName)
			}
			else
			{
				return $false
			}
		}
		else
		{
			return $false
		}

		try
		{ 
			$responseObj = [WebRequestHelper]::InvokeGetWebRequest($uri, $headers);
			if ($null -ne $responseObj -and ($responseObj | Measure-Object).Count -gt 0)
			{
				# extensionAttribute contains 15 different values which define unique properties for users.
				$extensionAttributes = $responseObj.onPremisesExtensionAttributes
				#"extensionAttribute2" contains the integer values which represents the different types of users.
				#"extensionAttribute2: -9" => Service Accounts
				if($extensionAttributes.extensionAttribute2 -eq "-9")
				{
					$isServiceAccount = $true
				}
			}
		} 
		catch
		{ 
			return $false;
		}
		return $isServiceAccount
	}


	hidden static [bool] IsADObjectGUID($immutableId){        
		try {
			$decodedII = [system.convert]::frombase64string($immutableId)
			$guid = [GUID]$decodedII    
		}
		catch {
			return $false
		}
		return $true
	}

	static CheckGraphAccess()
	{
		# In CA mode, we use azure context to fetch the graph access token, because VSTS authentication is not supported in CA.
		$useAzContext = $false
		$scanSource = [AzSKSettings]::GetInstance().GetScanSource();
		if ($scanSource -eq 'CICD') {
			[IdentityHelpers]::hasGraphAccess = $false
		}
		else
		{
			if ($scanSource -eq "CA") {
				$useAzContext = $true
			}
			$graphUri = [WebRequestHelper]::GetGraphUrl()
			$uri = $GraphUri + "/v1.0/users?`$top=1"
			[IdentityHelpers]::graphAccessToken = [ContextHelper]::GetGraphAccessToken($useAzContext)
			if (-not [string]::IsNullOrWhiteSpace([IdentityHelpers]::graphAccessToken))
			{
				$header = @{
					"Authorization"= ("Bearer " + [IdentityHelpers]::graphAccessToken); 
					"Content-Type"="application/json"
				};
				try
				{
					$webResponse = [WebRequestHelper]::InvokeGetWebRequest($uri, $header);
					[IdentityHelpers]::hasGraphAccess = $true;
				}
				catch
				{
					[IdentityHelpers]::hasGraphAccess = $false;
				}
			}
		}
	}

	static CheckSIPAccess()
	{
		# In CA mode, we use azure context to fetch the data explorer access token, because VSTS authentication is not supported in CA.
		$useAzContext = $false
		$scanSource = [AzSKSettings]::GetInstance().GetScanSource();
		if ($scanSource -eq 'CICD') {
			[IdentityHelpers]::hasSIPAccess = $false
		}
		else
		{
			if ($scanSource -eq "CA") {
				$useAzContext = $true
			}
			
			[IdentityHelpers]::dataExplorerAccessToken = [ContextHelper]::GetDataExplorerAccessToken($useAzContext)
			if (-not [string]::IsNullOrWhiteSpace([IdentityHelpers]::dataExplorerAccessToken))
			{
				$header = @{
					"Authorization" = "Bearer " + [IdentityHelpers]::dataExplorerAccessToken
				}
				$apiURL = "https://dsresip.kusto.windows.net/v2/rest/query" 
				# making a samlple api call, just to check if user has access to required SIP database.                                                                   
            	$inputbody = "{`"db`": `"AADUsersData`",`"csl`": `"UsersInfo | take 1`"}"
				try
				{
					$kustoResponse = Invoke-RestMethod -Uri $apiURL -Method Post  -ContentType "application/json; charset=utf-8" -Headers $header -Body $inputbody; 
					[IdentityHelpers]::hasSIPAccess = $true;
				}
				catch
				{
					[IdentityHelpers]::hasSIPAccess = $false;
				}
			}
		}
	}

	#This method differentiate human accounts and service account from the list.
	hidden static [PSObject] DistinguishHumanAndServiceAccount([PSObject] $allMembers, $orgName)
	{
		$humanAccount = @(); 
		$serviceAccount = @();
		$defaultSvcAcc = @(); #"Account Service ($orgName)" # This is default service account automatically added by ADO.
		$allMembers | ForEach-Object{
			if (-not [string]::IsNullOrEmpty($_.mailAddress)) 
			{
				$isServiceAccount = [IdentityHelpers]::IsServiceAccount($_.mailAddress, $_.subjectKind, [IdentityHelpers]::graphAccessToken)
				if ($isServiceAccount)
				{
					$serviceAccount += $_
				}
				else
				{
					$humanAccount += $_
				}
			}
			else {
				$defaultSvcAcc += $_
			}
		}
		if ($null -ne $defaultSvcAcc -and $defaultSvcAcc.Count -gt 0) {
			$serviceAccount += $defaultSvcAcc
		}
		$adminMembers = @{serviceAccount = $serviceAccount; humanAccount = $humanAccount;};
		return $adminMembers
	}

	#This method differentiate alt accounts and non-alt account from the list.
	hidden static [PSObject] DistinguishAltAndNonAltAccount([PSObject] $allMembers)
	{
		$altAccount = @(); 
		$nonAltAccount = @();
		$allMembers | ForEach-Object{
			$isAltAccount = [IdentityHelpers]::IsAltAccount($_.mailAddress, [IdentityHelpers]::graphAccessToken)
			if ($isAltAccount)
			{
				$altAccount += $_
			}
			else
			{
				$nonAltAccount += $_
			}
		}
		$adminMembers = @{altAccount = $altAccount; nonAltAccount = $nonAltAccount;};
		return $adminMembers
	}
}
