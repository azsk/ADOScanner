Set-StrictMode -Version Latest

function Set-AzSKADOSecurityStatus
{
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

        [string]
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [Alias("rn")]
        $ResourceNames,

        [string]
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [Alias("ern")]
        $ExcludeResourceNames,

        [string]
        [Parameter(Mandatory = $true)]
        [Alias("cid")]
        [AllowEmptyString()]
        $ControlId,

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

        [string]
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [Alias("pp")]
        $PolicyProject,

        [switch]
        [Parameter()]
        [Alias("uf")]
        $UndoFix = $false,

        [switch]
        [Parameter()]
		[Alias("upc")]
		$UsePartialCommits
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
            if (-not [string]::IsNullOrEmpty($ResourceNames) -and -not [string]::IsNullOrEmpty($ExcludeResourceNames))
            {
                throw [SuppressedException] "'ResourceNames' and 'ExcludeResourceNames' are exclusive parameters. Please use only one of them in the command"   
            }
            if ($ProjectName -match ','){
                throw [SuppressedException] "Set-AzSKADOSecurityStatus command supports fix for one project at a time."
            }
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

			if (-not [String]::IsNullOrEmpty($PATTokenURL))
			{
				#Parse the key-vault-URL to determine vaultname, secretname, version
				if ($PATTokenURL -match "^https://(?<kv>[\w]+)(?:[\.\w+]*)/secrets/(?<sn>[\w]+)/?(?<sv>[\w]*)")
				{
					$kvName = $Matches["kv"]
					$secretName = $Matches["sn"]
					$secretVersion = $Matches["sv"]

					if (-not [String]::IsNullOrEmpty($secretVersion))
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

            #Fetching resource type name based on control id 
            $ResourceTypeName =$ControlId.Split("_")[1]

            $resolver = [SVTResourceResolver]::new($OrganizationName, $ProjectName, $ResourceNames, $ExcludeResourceNames, $PATToken, $ResourceTypeName);
            $secStatus = [ServicesSecurityStatus]::new($OrganizationName,$ProjectName, $PSCmdlet.MyInvocation, $resolver, $ControlId);
            
            if ($secStatus)
			{
				return $secStatus.EvaluateControlStatus();
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
