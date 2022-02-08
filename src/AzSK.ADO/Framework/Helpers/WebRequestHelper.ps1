Set-StrictMode -Version Latest 
class WebRequestHelper {
   
	hidden static [string] $AzureManagementUri = "https://management.azure.com/";
	hidden static [string] $GraphApiUri = "https://graph.microsoft.com";
	hidden static [string] $ClassicManagementUri = "https://management.core.windows.net/";

    static [System.Object[]] InvokeGetWebRequest([string] $uri, [Hashtable] $headers) 
	{
        return [WebRequestHelper]::InvokeWebRequest([Microsoft.PowerShell.Commands.WebRequestMethod]::Get, $uri, $headers, $null);
    }

	static [System.Object[]] InvokeGetWebRequest([string] $uri) 
	{	
        return [WebRequestHelper]::InvokeGetWebRequest($uri, [WebRequestHelper]::GetAuthHeaderFromUri($uri));
	}
	
	hidden static [string] GetApplicationInsightsEndPoint()
	{
		$rmContext = [ContextHelper]::GetCurrentContext();
		$azureEnv= $rmContext.Environment.Name 
		if($azureEnv -eq "AzureUSGovernment")
		{
            return "https://dc.applicationinsights.us/v2/track"
		}
		elseif ($azureEnv -eq "AzureChinaCloud" ) {
			return "https://dc.applicationinsights.azure.cn/v2/track"
		}
		else {
			return "https://dc.services.visualstudio.com/v2/track"
		}
	}

	hidden static [string] GetLADataCollectorAPI()
	{
		$rmContext = [ContextHelper]::GetCurrentContext();
		$azureEnv= $rmContext.Environment.Name 
		if($azureEnv -eq "AzureUSGovernment")
		{
            return ".ods.opinsights.azure.us"
		}
		elseif ($azureEnv -eq "AzureChinaCloud" ) {
			return ".ods.opinsights.azure.cn"
		}
		else {
			return ".ods.opinsights.azure.com"
		}
	}

	hidden static [string] GetGraphUrl()
	{
		$rmContext = [ContextHelper]::GetCurrentContext();
		$azureEnv= $rmContext.Environment.Name 
		if(-not [string]::IsNullOrWhiteSpace($azureEnv) -and ($azureEnv -ne [Constants]::DefaultAzureEnvironment))
		{
		return [ContextHelper]::GetCurrentContext().Environment.GraphUrl
		}
		return "https://graph.microsoft.com"
	}

	hidden static [string] GetResourceManagerUrl()
	{
		$rmContext = [ContextHelper]::GetCurrentContext();
		$azureEnv= $rmContext.Environment.Name 
		if(-not [string]::IsNullOrWhiteSpace($azureEnv) -and ($azureEnv -ne [Constants]::DefaultAzureEnvironment))
		{
		return [ContextHelper]::GetCurrentContext().Environment.ResourceManagerUrl
		}
		return "https://management.azure.com/"
	}

	hidden static [string] GetServiceManagementUrl()
	{
		$rmContext = [ContextHelper]::GetCurrentContext();
		$azureEnv= $rmContext.Environment.Name 
		if(-not [string]::IsNullOrWhiteSpace($azureEnv) -and ($azureEnv -ne [Constants]::DefaultAzureEnvironment))
		{
		return [ContextHelper]::GetCurrentContext().Environment.ServiceManagementUrl
		}
		return "https://management.core.windows.net/"
	}

	hidden static [Hashtable] GetAuthHeaderFromUri([string] $uri)
	{
		[System.Uri] $validatedUri = $null;
        if([System.Uri]::TryCreate($uri, [System.UriKind]::Absolute, [ref] $validatedUri))
		{

			$token = [ContextHelper]::GetAccessToken($validatedUri.GetLeftPart([System.UriPartial]::Authority));

			# Validate if token is PAT using lenght (PAT has lengh of 52) else go with default bearer token
			if($token.length -eq 52)
			{
				$user = ""
				$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$token)))
				return @{
					"Authorization"= ("Basic " + $base64AuthInfo); 
					"Content-Type"="application/json"
				};
			}
			else {
				return @{
					"Authorization"= ("Bearer " + $token); 
					"Content-Type"="application/json"
				};
			}
			
		}
		
		return @{ "Content-Type"="application/json" };
	}

	hidden static [Hashtable] GetAuthHeaderFromUri([string] $uri, [bool] $isPatTokenGiven)
	{
		[System.Uri] $validatedUri = $null;
        if([System.Uri]::TryCreate($uri, [System.UriKind]::Absolute, [ref] $validatedUri))
		{

			$token = [ContextHelper]::GetAccessToken();

			# Validate if token is PAT using lenght (PAT has lengh of 52) else go with default bearer token
			if($token.length -eq 52)
			{
				$user = ""
				$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$token)))
				return @{
					"Authorization"= ("Basic " + $base64AuthInfo); 
					"Content-Type"="application/json"
				};
			}
			else {
				return @{
					"Authorization"= ("Bearer " + $token); 
					"Content-Type"="application/json"
				};
			}
			
		}
		
		return @{ "Content-Type"="application/json" };
	}

	hidden static [Hashtable] GetAuthHeaderFromUriPatch([string] $uri) {
        [System.Uri] $validatedUri = $null;
        if ([System.Uri]::TryCreate($uri, [System.UriKind]::Absolute, [ref] $validatedUri)) {

            $token = [ContextHelper]::GetAccessToken($validatedUri.GetLeftPart([System.UriPartial]::Authority));

            $user = ""
            $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user, $token)))
            return @{
				"Authorization" = ("Basic " + $base64AuthInfo)
				
            };
        }
		return @{};
	}

	static [System.Object[]] InvokePostWebRequest([string] $uri, [Hashtable] $headers, [System.Object] $body) 
	{
        return [WebRequestHelper]::InvokeWebRequest([Microsoft.PowerShell.Commands.WebRequestMethod]::Post, $uri, $headers, $body);
	}

	static [System.Object[]] InvokePostWebRequest([string] $uri, [System.Object] $body) 
	{
        return [WebRequestHelper]::InvokePostWebRequest($uri, [WebRequestHelper]::GetAuthHeaderFromUri($uri), $body);
	}

	static [System.Object[]] InvokeWebRequest([Microsoft.PowerShell.Commands.WebRequestMethod] $method, [string] $uri, [System.Object] $body) 
	{
        return [WebRequestHelper]::InvokeWebRequest($method, $uri, [WebRequestHelper]::GetAuthHeaderFromUri($uri), $body);
	}
	static [System.Object[]] InvokeWebRequest([Microsoft.PowerShell.Commands.WebRequestMethod] $method, [string] $uri, [Hashtable] $headers, [System.Object] $body) 
	{
		return [WebRequestHelper]::InvokeWebRequest($method, $uri, $headers, $body, $Null);
	}
    static [System.Object[]] InvokeWebRequest([Microsoft.PowerShell.Commands.WebRequestMethod] $method, [string] $uri, [Hashtable] $headers, [System.Object] $body, [string] $contentType) 
	{
        return [WebRequestHelper]::InvokeWebRequest($method, $uri, $headers, $body, $contentType, $false, $false) 
	}
	
	static [System.Object[]] InvokeWebRequest([Microsoft.PowerShell.Commands.WebRequestMethod] $method, [string] $uri, [Hashtable] $headers, [System.Object] $body, [string] $contentType, [Hashtable] $propertiesToReplace) 
	{
        $outputValues = @();
		[System.Uri] $validatedUri = $null;
		$orginalUri = "";
        while ([System.Uri]::TryCreate($uri, [System.UriKind]::Absolute, [ref] $validatedUri)) 
		{
			if([string]::IsNullOrWhiteSpace($orginalUri))
			{
				$orginalUri = $validatedUri.AbsoluteUri;
			}
			[int] $retryCount = 3
			$success = $false;
			while($retryCount -gt 0 -and -not $success)
			{
				$retryCount = $retryCount -1;
				try
				{
					$requestResult = $null;
			
					if ($method -eq [Microsoft.PowerShell.Commands.WebRequestMethod]::Get) 
					{
						$requestResult = Invoke-WebRequest -Method $method -Uri $validatedUri -Headers $headers -UseBasicParsing
					}
					elseif ($method -eq [Microsoft.PowerShell.Commands.WebRequestMethod]::Post -or $method -eq [Microsoft.PowerShell.Commands.WebRequestMethod]::Put) 
					{
						if($uri.EndsWith("`$batch"))
						{
							$requestResult = Invoke-WebRequest -Method $method -Uri $validatedUri -Headers $headers -Body $body -ContentType $contentType -UseBasicParsing
                            $success = $true
                            $uri = [string]::Empty
						}
						else
						{
							$requestResult = Invoke-WebRequest -Method $method -Uri $validatedUri -Headers $headers -Body ($body | ConvertTo-Json -Depth 10 -Compress) -UseBasicParsing
						}
					}	
					else 
					{
						throw [System.ArgumentException] ("The web request method type '$method' is not supported.")
					}		
			
					if ($null -ne $requestResult -and $requestResult.StatusCode -ge 200 -and $requestResult.StatusCode -le 399) {
						if (!$success -and $null -ne $requestResult.Content) {
							$resultContent = $requestResult.Content
							if($propertiesToReplace.Keys.Count -gt 0)
							{
								$propertiesToReplace.Keys  | Foreach-Object {
									$resultContent = $resultContent.ToString().Replace($_, $propertiesToReplace[$_])
								}
							}
							$json = ConvertFrom-Json $resultContent
							if ($null -ne $json) {
								if (($json | Get-Member -Name "value") -and $json.value) {
									$outputValues += $json.value;
								}
								else {
									$outputValues += $json;
								}
						
								if (($json | Get-Member -Name "nextLink") -and $json.nextLink) {
									$uri = $json.nextLink
								}
								elseif (($json | Get-Member -Name "@odata.nextLink") -and $json."@odata.nextLink")
								{
									$uri = $json."@odata.nextLink"
								}
								elseif($requestResult.Headers.ContainsKey('x-ms-continuation-NextPartitionKey'))
								{
									$nPKey = $requestResult.Headers["x-ms-continuation-NextPartitionKey"]
									$uri= $orginalUri + "&NextPartitionKey=$nPKey"
								}
								else {
									$uri = [string]::Empty;
								}
							}
						}
					}
					$success = $true;
				}
				catch
				{
					#eat the exception until it is in retry mode and throw once the retry is done
					if($retryCount -eq 0)
					{
						if([Helpers]::CheckMember($_,"Exception.Response.StatusCode") -and  $_.Exception.Response.StatusCode -eq "Forbidden"){
							throw ([SuppressedException]::new(("You do not have permission to view the requested resource."), [SuppressedExceptionType]::InvalidOperation))
						}
						elseif ([Helpers]::CheckMember($_,"Exception.Message")){
							throw ([SuppressedException]::new(($_.Exception.Message.ToString()), [SuppressedExceptionType]::InvalidOperation))
						}
						else {
							throw;
						}
					}					
				}
			}
        }

        return $outputValues;
	}

	#method to get the raw response in a GET method
	static [System.Object[]] InvokeGetWebRequestRaw($url){
		return [WebRequestHelper]::InvokeWebRequest([Microsoft.PowerShell.Commands.WebRequestMethod]::Get, $url, [WebRequestHelper]::GetAuthHeaderFromUri($url), $null, $null, $false, $true); 
	}

	static [System.Object[]] InvokeWebRequest([Microsoft.PowerShell.Commands.WebRequestMethod] $method, [string] $uri, [Hashtable] $headers, [System.Object] $body, [string] $contentType, [bool] $isRetryRequired, [bool] $returnRawResponse) 
	{
        $outputValues = @();
		[System.Uri] $validatedUri = $null;
		$orginalUri = "";
		$skipCount = 0
        while ([System.Uri]::TryCreate($uri, [System.UriKind]::Absolute, [ref] $validatedUri)) 
		{
			[int] $retryCount = 1
			if($isRetryRequired)
			{
				$retryCount = 3
			}
			if([string]::IsNullOrWhiteSpace($orginalUri))
			{
				$orginalUri = $validatedUri.AbsoluteUri;
			}
			
			$success = $false;
			while($retryCount -gt 0 -and -not $success)
			{
				$retryCount = $retryCount -1;
				try
				{
					$requestResult = $null;

					#before making API call, check if previous API call was throttled and if we have any retry after value. Wait before making any new API call if required
					[RateLimitHelper]::WaitIfNeeded($validatedUri);
			
					if ($method -eq [Microsoft.PowerShell.Commands.WebRequestMethod]::Get) 
					{
						$requestResult = Invoke-WebRequest -Method $method -Uri $validatedUri -Headers $headers -UseBasicParsing
					}
					elseif ($method -eq [Microsoft.PowerShell.Commands.WebRequestMethod]::Post -or $method -eq [Microsoft.PowerShell.Commands.WebRequestMethod]::Put -or [Microsoft.PowerShell.Commands.WebRequestMethod]::Patch) 
					{
						if($uri.EndsWith("`$batch"))
						{
							$requestResult = Invoke-WebRequest -Method $method -Uri $validatedUri -Headers $headers -Body $body -ContentType $contentType -UseBasicParsing
                            $success = $true
                            $uri = [string]::Empty
						}
						elseif($uri.Contains("mspim") -or $uri.Contains("genevareference") -or $uri.Contains("loganalytics.io") -or $uri.Contains("1es.kusto.windows"))
						{
							$requestResult = Invoke-WebRequest -Method $method -Uri $validatedUri -Headers $headers -Body $body -ContentType $contentType -UseBasicParsing
                        }
						else
						{
							$requestResult = Invoke-WebRequest -Method $method -Uri $validatedUri -Headers $headers -Body ($body | ConvertTo-Json -Depth 10 -Compress) -UseBasicParsing
						}
					}	
					else 
					{
						throw [System.ArgumentException] ("The web request method type '$method' is not supported.")
					}
					
					if($returnRawResponse)
					{
						return $requestResult
					}
			
					if ($null -ne $requestResult -and $requestResult.StatusCode -ge 200 -and $requestResult.StatusCode -le 399) {
						if (!$success -and $null -ne $requestResult.Content) {
							#check if this API call was throttled, store any appropriate headers for rate limiting for next API calls
							[RateLimitHelper]::UpdateRateLimitEntity($requestResult, $validatedUri);
							$json = ConvertFrom-Json $requestResult.Content
							if ($null -ne $json) {
								if (($json | Get-Member -Name "value") -and $json.value) {
									$outputValues += $json.value;
								}
								else {
									$outputValues += $json;
								}
						
								if (($json | Get-Member -Name "nextLink") -and $json.nextLink) {
									$uri = $json.nextLink
								}
								elseif($requestResult.Headers.ContainsKey('x-ms-continuation-NextPartitionKey'))
								{
									$nPKey = $requestResult.Headers["x-ms-continuation-NextPartitionKey"]
									$uri= $orginalUri + "&NextPartitionKey=$nPKey"
								}
								elseif($requestResult.Headers.ContainsKey('x-ms-continuationtoken'))
								{
									$nPKey = $requestResult.Headers["x-ms-continuationtoken"]
									#Azure devops API calls for different resource behave independently w.r.t continuationToken, we need to handle them separately
									# Pagination for build definitions always contains queryOrder
									if ($uri.Contains("build/definitions") -and $uri.Contains('queryOrder')) {
										# Handle the pagination for builds
										$skipCount = $skipCount+10000
										$uri= $orginalUri +"&%24skip="+$skipCount+ "&continuationToken="+$nPKey
									} 
									# Pagination for release definitions don't need queryOrder for pagination
									# $uri with $top returns continuation token, it should not continue further
									elseif ($uri.Contains("release/definitions") -and -not $uri.Contains('$top')){
										$uri= $orginalUri + "&continuationToken="+$nPKey
									}
									elseif ($uri.Contains("projects")){
										$uri= $orginalUri + "&continuationToken="+$nPKey
									}
									elseif($uri.Contains("auditservice")){
										$uri = $orginalUri+"&continuationToken="+$json.continuationToken
									}
									elseif($uri.Contains("testplan/plans") -or $uri.Contains("distributedtask/environments")){
										$uri = $orginalUri+"&continuationToken="+$nPKey
									}
									else {
										$uri = [string]::Empty;
									}
								}
								else {
									$uri = [string]::Empty;
								}
							}
						}
					}
					$success = $true;
				}
				catch
				{
					#eat the exception until it is in retry mode and throw once the retry is done
					if($retryCount -eq 0)
					{
						if ($uri.Contains("mspim") -and [Helpers]::CheckMember($_,"ErrorDetails.Message"))
						{
							if( -not $returnRawResponse)
							{
								
									$err = $_.ErrorDetails.Message| ConvertFrom-Json
									throw ([SuppressedException]::new(($err), [SuppressedExceptionType]::Generic))
									
								
							}
							else 
							{				
								throw $_;		
							}
							
						}
						elseif([Helpers]::CheckMember($_,"Exception.Response.StatusCode") -and  $_.Exception.Response.StatusCode -eq "Forbidden"){
							if($uri.Contains("auditservice") -and $PSCmdlet.MyInvocation.BoundParameters.ContainsKey('IncrementalScan')){
								Write-Host "You do not have the permissions to view audit logs. Results from incremental scan may not be accurate." -ForegroundColor Yellow
							}
							throw ([SuppressedException]::new(("You do not have permission to view the requested resource."), [SuppressedExceptionType]::InvalidOperation))
						}
						elseif ([Helpers]::CheckMember($_,"Exception.Message")){
							throw ([SuppressedException]::new(($_.Exception.Message.ToString()), [SuppressedExceptionType]::InvalidOperation))
						}
						
						else {
							throw;
						}
					}					
				}
			}
        }

        return $outputValues;
	}	
	
	#only for builds and releases as of now
	static [System.Object[]] InvokeWebRequestForResourcesInBatch([string] $validatedUri,[string]$originalUri,[int] $skipCount,[string] $resourceType){
		$outputValues = @();
		$success = $false;
		[int] $retryCount=3;
		while($retryCount -gt 0 -and -not $success){
			$retryCount=$retryCount-1;
		
		try{
			
			$headers=[WebRequestHelper]::GetAuthHeaderFromUri($validatedUri)
			$requestResult = Invoke-WebRequest -Method Get -Uri $validatedUri -Headers $headers -UseBasicParsing
			
			if ($null -ne $requestResult -and $requestResult.StatusCode -ge 200 -and $requestResult.StatusCode -le 399) {
				if ($null -ne $requestResult.Content) {
					$json = ConvertFrom-Json $requestResult.Content
					if ($null -ne $json) {
						if (($json | Get-Member -Name "value") -and $json.value) {
							$outputValues += $json.value;
						}
						else {
							$outputValues += $json;
						}
						if($requestResult.Headers.ContainsKey('x-ms-continuationtoken')){
							$nPKey = $requestResult.Headers["x-ms-continuationtoken"]
							if($resourceType -eq "build"){
								$originalUri= $originalUri +"&%24skip="+$skipCount+ "&continuationToken="+$nPKey
							}
							else {
								$originalUri= $originalUri +"&continuationToken="+$nPKey
							
							}												
							
						}
						else {
							$originalUri = [string]::Empty;
						}
					}
				}
			}
			$success=$true;
		}
		catch{
			if ($originalUri.Contains("mspim") -and [Helpers]::CheckMember($_, "ErrorDetails.Message")) {		
				$err = $_.ErrorDetails.Message | ConvertFrom-Json
				throw ([SuppressedException]::new(($err), [SuppressedExceptionType]::Generic))				
			}
			elseif ([Helpers]::CheckMember($_, "Exception.Response.StatusCode") -and $_.Exception.Response.StatusCode -eq "Forbidden") {
				throw ([SuppressedException]::new(("You do not have permission to view the requested resource."), [SuppressedExceptionType]::InvalidOperation))
			}
			elseif ([Helpers]::CheckMember($_, "Exception.Message")) {
				throw ([SuppressedException]::new(($_.Exception.Message.ToString()), [SuppressedExceptionType]::InvalidOperation))
			}				
			else {
				throw;
			}
		}	
	    }				
			return $outputValues,$originalUri;
	}
	static [System.Object[]] InvokeWebRequestForContinuationToken([string] $validatedUri,[string] $originalUri,$skipCount,$resourceType){
		
		$success = $false;
		[int] $retryCount=3;
		$continuationToken=$null;
		$outputValues=@();
		while($retryCount -gt 0 -and -not $success){
			$retryCount=$retryCount-1;
		
		try{
			
			$headers=[WebRequestHelper]::GetAuthHeaderFromUri($validatedUri,$true)
			$requestResult = Invoke-WebRequest -Method Get -Uri $validatedUri -Headers $headers -UseBasicParsing
			
			if ($null -ne $requestResult -and $requestResult.StatusCode -ge 200 -and $requestResult.StatusCode -le 399) {
				if ($null -ne $requestResult.Content) {
					$json = ConvertFrom-Json $requestResult.Content
					if ($null -ne $json) {
						if( $null -eq $skipCount){
						if (($json | Get-Member -Name "value") -and $json.value) {
							$outputValues += $json.value;
						}
						else {
							$outputValues += $json;
						}
					}
					if($requestResult.Headers.ContainsKey('x-ms-continuationtoken')){
						$nPKey = $requestResult.Headers["x-ms-continuationtoken"]
						$continuationToken=$nPKey;
						if($resourceType -eq "build" -and $null -ne $skipCount ){
							$originalUri= $originalUri +"&%24skip="+$skipCount+ "&continuationToken="+$nPKey
						}
						elseif($resourceType -eq "release") {
							$originalUri= $originalUri +"&continuationToken="+$nPKey
						
						}
						
								
					}
					else {
						$originalUri = [string]::Empty;
						$continuationToken="";
					}
				}
				}
			}
		$success=$true;
		}
		catch{
			if ($originalUri.Contains("mspim") -and [Helpers]::CheckMember($_, "ErrorDetails.Message")) {		
				$err = $_.ErrorDetails.Message | ConvertFrom-Json
				throw ([SuppressedException]::new(($err), [SuppressedExceptionType]::Generic))				
			}
			elseif ([Helpers]::CheckMember($_, "Exception.Response.StatusCode") -and $_.Exception.Response.StatusCode -eq "Forbidden") {
				throw ([SuppressedException]::new(("You do not have permission to view the requested resource."), [SuppressedExceptionType]::InvalidOperation))
			}
			elseif ([Helpers]::CheckMember($_, "Exception.Message")) {
				throw ([SuppressedException]::new(($_.Exception.Message.ToString()), [SuppressedExceptionType]::InvalidOperation))
			}				
			else {
				throw;
			}
		}	
	    }				
			return $continuationToken,$originalUri,$outputValues;
	}

}
