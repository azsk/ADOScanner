Set-StrictMode -Version Latest

class ResourceHelper: EventBase{


	static [void] RegisterResourceProviderIfNotRegistered([string] $provideNamespace)
	{
		if([string]::IsNullOrWhiteSpace($provideNamespace))
		{
			throw [System.ArgumentException] "The argument '$provideNamespace' is null or empty";
		}

		# Check if provider is registered or not
		if(-not [ResourceHelper]::IsProviderRegistered($provideNamespace))
		{
			[EventBase]::PublishGenericCustomMessage(" `r`nThe resource provider: [$provideNamespace] is not registered on the subscription. `r`nRegistering resource provider, this can take up to a minute...", [MessageType]::Warning);

			Register-AzResourceProvider -ProviderNamespace $provideNamespace

			$retryCount = 10;
			while($retryCount -ne 0 -and (-not [ResourceHelper]::IsProviderRegistered($provideNamespace)))
			{
				$timeout = 10
				Start-Sleep -Seconds $timeout
				$retryCount--;
			}

			if(-not [ResourceHelper]::IsProviderRegistered($provideNamespace))
			{
				throw ([SuppressedException]::new(("Resource provider: [$provideNamespace] registration failed. `r`nTry registering the resource provider from Azure Portal --> your Subscription --> Resource Providers --> $provideNamespace --> Register"), [SuppressedExceptionType]::Generic))
			}
			else
			{
				[EventBase]::PublishGenericCustomMessage("Resource provider: [$provideNamespace] registration successful.`r`n ", [MessageType]::Update);
			}
		}
	}

	hidden static [bool] IsProviderRegistered([string] $provideNamespace)
	{
		return ((Get-AzResourceProvider -ProviderNamespace $provideNamespace | Where-Object { $_.RegistrationState -ne "Registered" } | Measure-Object).Count -eq 0);
	}

}


