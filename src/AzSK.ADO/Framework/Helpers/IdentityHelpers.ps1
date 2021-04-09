Set-StrictMode -Version Latest 

class IdentityHelpers
{

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
				#"extension attribute = -9" => Service Accounts
				$extensionAttributes = $responseObj.onPremisesExtensionAttributes
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

	hidden static [bool] HasGraphAccess()
	{
		$hasAccess = $false;
	    $graphUri = [WebRequestHelper]::GetGraphUrl()
		$uri = $GraphUri + "/v1.0/users?`$top=1"
		$token = [ContextHelper]::GetGraphAccessToken()
		$header = @{
			"Authorization"= ("Bearer " + $token); 
			"Content-Type"="application/json"
		};
		try
		{
			$webResponse = [WebRequestHelper]::InvokeGetWebRequest($uri, $header);
			$hasAccess = $true;
		}
		catch
		{
			$hasAccess = $false;
		}
		return $hasAccess;
	}
}
