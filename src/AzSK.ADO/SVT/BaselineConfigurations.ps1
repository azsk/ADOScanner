Set-StrictMode -Version Latest

function Set-AzSKADOBaselineConfigurations {
    [OutputType([String])]
    Param
    (
        [string]
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias("oz")]
        $OrganizationName,

        [string]
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [Alias("pn")]
        $ProjectName,

        [System.Security.SecureString]
        [Parameter()]
        [Alias("tk")]
        $PATToken,

        [switch]
        [Parameter()]
        [Alias("pfp")]
        $PromptForPAT,

        [string]
        [Parameter()]
        [Alias("ptu")]
        $PATTokenURL,

        [ResourceTypeName]
		[Alias("rtn")]
		$ResourceTypeName = [ResourceTypeName]::All,

        [switch]
        [Parameter()]
        [Alias("f")]
        $Force



    )

    Begin
    {
        [CommandHelper]::BeginCommand($PSCmdlet.MyInvocation);
        [ListenerHelper]::RegisterListeners();
    }

    Process
    {
        try
        {
            if($PromptForPAT -eq $true)
			{
				if($null -ne $PATToken)
				{
					throw [SuppressedException] "Parameters '-PromptForPAT' and '-PATToken' can not be used simultaneously in the scan command." 
				}
				else
				{
					$PATToken = Read-Host "Provide PAT for [$OrganizationName] org:" -AsSecureString
				}

			}

			if (-not [String]::IsNullOrWhitespace($PATTokenURL))
			{
				#Parse the key-vault-URL to determine vaultname, secretname, version
				if ($PATTokenURL -match "^https://(?<kv>[\w]+)(?:[\.\w+]*)/secrets/(?<sn>[\w]+)/?(?<sv>[\w]*)")
				{
					$kvName = $Matches["kv"]
					$secretName = $Matches["sn"]
					$secretVersion = $Matches["sv"]

					if (-not [String]::IsNullOrWhitespace($secretVersion))
					{
						$kvSecret = Get-AzKeyVaultSecret -VaultName $kvName -SecretName $secretName -Version $secretVersion
					}
					else
					{
						$kvSecret = Get-AzKeyVaultSecret -VaultName $kvName -SecretName $secretName
					}

					if ($null -eq $kvSecret)
					{
                        throw [SuppressedException] "Could not extract PATToken from the given key vault URL.`r`nStopping scan command." 
                    }
					$PATToken = $kvSecret.SecretValue;
				}
				else {
					throw [SuppressedException] "Could not extract PATToken from the given key vault URL.`r`nStopping scan command." 
				}
			}
            
            $resolver = [SVTResourceResolver]::new($OrganizationName, $ProjectName,$ResourceTypeName,$PATToken,$Force);
            $secStatus = [ServicesSecurityStatus]::new($OrganizationName, $PSCmdlet.MyInvocation, $resolver);
            
            if ($secStatus)
			{
				if ($null -ne $secStatus.Resolver.SVTResources) {	
					return $secStatus.EvaluateControlStatus();
				}
            }
        }
        catch
        {
            [EventBase]::PublishGenericException($_);
        }
    }

    End
    {
    [ListenerHelper]::UnregisterListeners();
    }

}