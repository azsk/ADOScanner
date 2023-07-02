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

        [string]
        [Parameter(HelpMessage = "Control id to be fixed")]
        [Alias("cids")]
        $ControlIds,

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

        [string]
		[Parameter(HelpMessage="Build names for which the security evaluation has to be performed.")]
		[ValidateNotNullOrEmpty()]
		[Alias("bns", "BuildName","bn")]
		$BuildNames,

        [string]
		[Parameter(HelpMessage="Release names for which the security evaluation has to be performed.")]
		[ValidateNotNullOrEmpty()]
		[Alias("rns", "ReleaseName","rn")]
		$ReleaseNames,

        [string]
		[Parameter(HelpMessage="Service connection names for which the security evaluation has to be performed.")]
		[ValidateNotNullOrEmpty()]
		[Alias("sc", "ServiceConnectionName", "scs")]
		$ServiceConnectionNames,

        [string]
		[Parameter(HelpMessage="Agent Pool names for which the security evaluation has to be performed.")]
		[ValidateNotNullOrEmpty()]
		[Alias("aps", "AgentPoolName","ap")]
		$AgentPoolNames,


		[string]
		[Parameter(HelpMessage="Variable group names for which the security evaluation has to be performed.")]
		[ValidateNotNullOrEmpty()]
		[Alias("vg", "VariableGroupName", "vgs")]
		$VariableGroupNames,

		[string]
		[Parameter(HelpMessage="Repo name for which the security evaluation has to be perform.")]
		[ValidateNotNullOrEmpty()]
		[Alias("rpn", "RepoName","rp")]
		$RepoNames,

		[string]
		[Parameter(HelpMessage="Secure file name for which the security evaluation has to be perform.")]
		[ValidateNotNullOrEmpty()]
		[Alias("sfn", "SecureFileName","sf")]
		$SecureFileNames,

		[string]
		[Parameter(HelpMessage="Feed name for which the security evaluation has to be perform.")]
		[ValidateNotNullOrEmpty()]
		[Alias("fd", "FeedName","fdn")]
		$FeedNames,

		[string]
		[Parameter(HelpMessage="Environment name for which the security evaluation has to be perform.")]
		[ValidateNotNullOrEmpty()]
		[Alias("en", "EnvironmentName","env")]
		$EnvironmentNames,

		[switch]
        [Parameter()]
        [Alias("f")]
        $Force,

        #Boolean Variable for resolving the conflict on constructor.
        [switch]
        $IsSabc = $true


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
            
            $resolver = [SVTResourceResolver]::new($OrganizationName, $ProjectName,$BuildNames,$ReleaseNames,$ServiceConnectionNames,$RepoNames, $SecureFileNames, $FeedNames, $EnvironmentNames,$AgentPoolNames, $VariableGroupNames,$ResourceTypeName,$PATToken,$Force, $IsSabc);
            $secStatus = [ServicesSecurityStatus]::new($OrganizationName, $PSCmdlet.MyInvocation, $resolver);
            
            if ($secStatus)
			{
				if ($null -ne $secStatus.Resolver.SVTResources) {	
                    $secStatus.ControlIdString = $ControlIds;
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