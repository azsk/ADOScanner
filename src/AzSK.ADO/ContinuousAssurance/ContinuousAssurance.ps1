Set-StrictMode -Version Latest
function Install-AzSKADOContinuousAssurance 
{
	<#
	.SYNOPSIS
	This command would help in setting up Continuous Assurance feature of AzSK.ADO in your subscription
	.DESCRIPTION
	This command will create a resource group (Name: ADOScannerRG) which runs security scan on organization and projects which are specified during installation.
	Security scan results will be populated in Log Analytics workspace which is configured during installation. Also, detailed logs will be stored in storage account (Name: adoscannersayyMMddHHmmss format).  
	
	.PARAMETER SubscriptionId
		Subscription id in which CA setup needs to be done.
	.PARAMETER Location
		Location in which all resources need to be setup. 
	.PARAMETER ResourceGroupName
		Resource group name where CA setup need to be done. (Default : ADOScannerRG)
	.PARAMETER LAWSId
		Workspace ID of Log Analytics workspace where security scan results will be sent
	.PARAMETER LAWSSharedKey
		Shared key of Log Analytics workspace which is used to monitor security scan results.
	.PARAMETER OrganizationName
		Organization name for which scan will be performed.
	.PARAMETER PATToken
		PAT token secure string for organization to be scanned.
	.PARAMETER PATTokenURL
		KeyVault URL for PATToken.
	.PARAMETER IdentityResourceId
		Resource id of user assigned managed identity to be used to access KeyVault for PATToken.
	.PARAMETER ProjectName
		Project to be scanned within the organization.
	.PARAMETER ExtendedCommand
		Extended command to narrow down the scans.
	.PARAMETER ScanIntervalInHours
		Overrides the default scan interval (24hrs) with the custom provided value.
	.PARAMETER CreateLAWorkspace
		Switch to create and map new log analytics workspace with CA setup.
	.NOTES
	This command helps the application team to verify whether their ADO resources are compliant with the security guidance or not 


	#>
	Param(
		[Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="Subscription id in which CA setup needs to be done.")]
        [Parameter(Mandatory = $true, ParameterSetName = "CentralCA")]
		[Parameter(Mandatory = $true, ParameterSetName = "OAuthBasedCA")]
		[string]
		[Alias("sid")]
		$SubscriptionId ,

		[Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage = "Organization name for which scan will be performed.")]
        [Parameter(Mandatory = $true, ParameterSetName = "CentralCA")]
		[Parameter(Mandatory = $true, ParameterSetName = "OAuthBasedCA")]
		[ValidateNotNullOrEmpty()]
		[Alias("oz")]
		[string]
		$OrganizationName,

		[Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage = "Project to be scanned within the organization.")]
        [Parameter(Mandatory = $true, ParameterSetName = "CentralCA")]
		[Parameter(Mandatory = $true, ParameterSetName = "OAuthBasedCA")]
		[Alias("pns", "ProjectNames","pn")]
		[string]
		$ProjectName,

		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "PAT token secure string for organization to be scanned.")]
		[ValidateNotNullOrEmpty()]
		[Alias("pat","tkn")]
		[System.Security.SecureString]
		$PATToken,
        
		[Parameter(Mandatory = $true, ParameterSetName = "CentralCA", HelpMessage = "KeyVault URL for PATToken")]
		[ValidateNotNullOrEmpty()]
		[Alias("ptu")]
		[string]
		$PATTokenURL,
        
		[Parameter(Mandatory = $true, ParameterSetName = "CentralCA", HelpMessage = "Resource id of user assigned managed identity")]
		[ValidateNotNullOrEmpty()]
		[Alias("ici")]
		[string]
		$IdentityResourceId,

		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Resource group name where CA setup needs to be done")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralCA")]
		[Parameter(Mandatory = $false, ParameterSetName = "OAuthBasedCA")]
		[string]
		[ValidateNotNullOrEmpty()]
		[Alias("rgn")]
		$ResourceGroupName,       

		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Location in which all resources need to be setup.")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralCA")]
		[Parameter(Mandatory = $false, ParameterSetName = "OAuthBasedCA")]
		[string]
		[ValidateNotNullOrEmpty()]
		[Alias("loc")]
		$Location, 

		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Workspace ID of Log Analytics workspace which is used to monitor security scan results.")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralCA")]
		[Parameter(Mandatory = $false, ParameterSetName = "OAuthBasedCA")]
		[string]
		[ValidateNotNullOrEmpty()]
		[Alias("lwid","wid")]
		$LAWSId,

		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Shared key of Log Analytics workspace which is used to monitor security scan results.")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralCA")]
		[Parameter(Mandatory = $false, ParameterSetName = "OAuthBasedCA")]
		[string]
		[ValidateNotNullOrEmpty()]
		[Alias("lwkey","wkey")]
		$LAWSSharedKey,

		[switch]
		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Switch to create and map new Log Analytics workspace with CA setup.")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralCA")]
		[Parameter(Mandatory = $false, ParameterSetName = "OAuthBasedCA")]
		[Alias("cws")]
		$CreateLAWorkspace,

		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Use extended command to narrow down the target scan.")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralCA")]
		[Parameter(Mandatory = $false, ParameterSetName = "OAuthBasedCA")]
		[Alias("ex")]
		[string]
		$ExtendedCommand,

		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Overrides the default scan interval (24hrs) with the custom provided value.")]
        [Parameter(Mandatory = $false, ParameterSetName = "CentralCA")]
		[Parameter(Mandatory = $false, ParameterSetName = "OAuthBasedCA")]
		[Alias("si")]
		[int]
        $ScanIntervalInHours,
        
        [Parameter(Mandatory = $true, ParameterSetName = "OAuthBasedCA")]
        [Alias("oai")]
		[string]
        $OAuthAppId,

        [Parameter(Mandatory = $false, ParameterSetName = "OAuthBasedCA")]
        [ValidateNotNullOrEmpty()]
		[Alias("csec")]
		[string]
        $ClientSecret,

        [Parameter(Mandatory = $true, ParameterSetName = "OAuthBasedCA")]
        [Alias("ausc")]
		[string]
        $AuthorizedScopes


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
            if ([string]::IsNullOrWhiteSpace($PATToken) -and [string]::IsNullOrWhiteSpace($PATTokenURL) -and $PSCmdlet.ParameterSetName -ne 'OAuthBasedCA' )
            {
                $PATToken = Read-Host "Provide PAT for [$OrganizationName] org:" -AsSecureString
            }

            if ([string]::IsNullOrWhiteSpace($ClientSecret) -and $PSCmdlet.ParameterSetName -eq 'OAuthBasedCA' )
            {
                $ClientSecret = Read-Host "Provide ClientSecret for OAuth application" #-AsSecureString
            }

            $resolver = [Resolver]::new($OrganizationName)

            $caAccount = [CAAutomation]::new($SubscriptionId, $Location,`
                                            $OrganizationName, $PATToken, $PATTokenURL, $ResourceGroupName, $LAWSId,`
                                            $LAWSSharedKey, $ProjectName, $IdentityResourceId,`
                                            $ExtendedCommand,  $ScanIntervalInHours, $PSCmdlet.MyInvocation, $CreateLAWorkspace,`
                                            $OAuthAppId, $ClientSecret, $AuthorizedScopes);

            if ($PSCmdlet.ParameterSetName -eq 'Default') {
                $caAccount.InvokeFunction($caAccount.InstallAzSKADOContinuousAssurance)
            }
            elseif ($PSCmdlet.ParameterSetName -eq 'CentralCA')
            {
                $caAccount.InvokeFunction($caAccount.InstallAzSKADOCentralContinuousAssurance)
            }
            else {
                $caAccount.InvokeFunction($caAccount.InstallAzSKADOOAuthBasedContinuousAssurance)
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

function Update-AzSKADOContinuousAssurance 
{
	<#
	.SYNOPSIS
	This command would help in updating user configurable properties of Continuous Assurance in your subscription
	.DESCRIPTION
	This command will update configurations of existing AzSK.ADO CA setup in your subscription.
	Security scan results will be populated in Log Analytics workspace which is configured during installation. Also, detailed logs will be stored in storage account (Name: adoscannersayyMMddHHmmss format).  
	
	.PARAMETER SubscriptionId
		Subscription id in which CA setup is present.
	.PARAMETER ResourceGroupName
		Resource group name where CA setup is available (Default : ADOScannerRG).
	.PARAMETER LAWSId
		Workspace ID of Log Analytics workspace which is used to monitor security scan results.
	.PARAMETER LAWSSharedKey
		Shared key of Log Analytics workspace which is used to monitor security scan results.
	.PARAMETER AltLAWSId
		Alternate workspace ID of Log Analytics workspace where security scan results will be sent
	.PARAMETER AltLAWSSharedKey
		Alternate shared key of Log Analytics workspace which is used to monitor security scan results.
	.PARAMETER OrganizationName
		Organization name for which scan will be performed.
	.PARAMETER PATToken
		PAT token secure string for organization to be scanned.
	.PARAMETER PATTokenURL
		KeyVault URL for PATToken.
	.PARAMETER ProjectName
		Project to be scanned within the organization.
	.PARAMETER ExtendedCommand
		Extended command to narrow down the target scan.
	.PARAMETER ScanIntervalInHours
		Overrides the default scan interval (24hrs) with the custom provided value.
	.PARAMETER ClearExtendedCommand
		Use to clear extended command.
	.PARAMETER WebhookUrl
		Provide webhook url to enable it in CA setup.
	.PARAMETER WebhookAuthZHeaderName
		Provide webhook header name.
	.PARAMETER WebhookAuthZHeaderValue
		Provide webhook header value.
	.PARAMETER AllowSelfSignedWebhookCertificate
		Use this switch to allow self signed webhook certificate.
	#>
	Param(
		[Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="Subscription id in which CA setup is present.")]
        [string]
		[Alias("sid")]
		$SubscriptionId ,

		[Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage = "Orgnanization name for which scan will be performed.")]
		[Alias("oz")]
		[string]
		$OrganizationName,

		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Project to be scanned within the organization.")]
		[Alias("pns", "ProjectNames", "pn")]
		[string]
		$ProjectName,
		
		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "PAT token secure string for organization to be scanned.")]
		[Alias("pat")]
		[System.Security.SecureString]
		$PATToken,
        
		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "KeyVault URL for PATToken")]
		[Alias("ptu")]
		[string]
		$PATTokenURL,

		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Resource group name where CA setup is available. (Default : ADOScannerRG)")]
		[string]
		[Alias("rgn")]
		$ResourceGroupName,       

        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Workspace ID of Log Analytics workspace where security scan results will be populated.")]
        [string]
		[Alias("lwid","wid","WorkspaceId")]
		$LAWSId,

        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Shared key of Log Analytics workspace which is used to monitor security scan results.")]
        [string]
		[Alias("lwkey","wkey","SharedKey")]
		$LAWSSharedKey,

		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Alternate workspace ID of Log Analytics workspace which is used to monitor security scan results.")]
        [string]
		[ValidateNotNullOrEmpty()]
		[Alias("alwid","awid")]
		$AltLAWSId,

        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Alternate shared key of Log Analytics workspace which is used to monitor security scan results.")]
        [string]
		[ValidateNotNullOrEmpty()]
		[Alias("alwkey","awkey")]
		$AltLAWSSharedKey,

		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Use extended command to narrow down the scans.")]
		[Alias("ex")]
		[string]
		$ExtendedCommand,

		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Overrides the default scan interval (24hrs) with the custom provided value.")]
		[Alias("si")]
		[int]
		$ScanIntervalInHours,

		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Use to clear extended command.")]
		[Alias("cec")]
		[switch]
		$ClearExtendedCommand,
		
		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Provide webhook url to enable it in CA setup.")]
		[Alias("wu")]
		[string]
		$WebhookUrl,
        
		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Provide webhook header name.")]
		[Alias("wan")]
		[string]
		$WebhookAuthZHeaderName,
        
		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Provide webhook header value.")]
		[Alias("wav")]
		[string]
		$WebhookAuthZHeaderValue,
        
		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Use this switch to allow self signed webhook certificate.")]
		[Alias("awc")]
		[switch]
		$AllowSelfSignedWebhookCertificate,

		#Dev-Test support params below this
		[string] $RsrcTimeStamp, 
		[string] $ContainerImageName, 
		[string] $ModuleEnv, 
		[bool] $UseDevTestImage, 
		[int] $TriggerNextScanInMin
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
            if (-not [string]::IsNullOrEmpty($PATToken) -and -not [string]::IsNullOrEmpty($PATTokenURL))
            {
                throw [SuppressedException] "'PATToken' and 'PATTokenURL' are exclusive parameters. Please use only one of them in the command"   
            }
            if (-not [string]::IsNullOrEmpty($ExtendedCommand) -and $ClearExtendedCommand -eq $true)
            {
                throw [SuppressedException] "'ExtendedCommand' and 'ClearExtendedCommand' are exclusive parameters. Please use only one of them in the command"   
            }
            else 
            {
                
                    $resolver = [Resolver]::new($OrganizationName)
                    $caAccount = [CAAutomation]::new($SubscriptionId, $OrganizationName, $PATToken, $PATTokenURL, `
                                                    $ResourceGroupName, $LAWSId, $LAWSSharedKey, `
                                                    $AltLAWSId, $AltLAWSSharedKey, $ProjectName, $ExtendedCommand, `
                                                    $WebhookUrl, $WebhookAuthZHeaderName, $WebhookAuthZHeaderValue, $AllowSelfSignedWebhookCertificate, `
                                                    $RsrcTimeStamp, $ContainerImageName, $ModuleEnv, $UseDevTestImage, $TriggerNextScanInMin, `
                                                    $ScanIntervalInHours, $ClearExtendedCommand, $PSCmdlet.MyInvocation);
            
                    return $caAccount.InvokeFunction($caAccount.UpdateAzSKADOContinuousAssurance);
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
function Get-AzSKADOContinuousAssurance 
{
	<#
	.SYNOPSIS
	This command would help in getting details of Continuous Assurance Setup
		
	.PARAMETER SubscriptionId
		Subscription id in which CA setup is present.
	.PARAMETER OrganizationName
		Organization name for which CA is setup.
	.PARAMETER ResourceGroupName
		Resource group name where CA setup is available (Default : ADOScannerRG).
	.PARAMETER RsrcTimeStamp
		Timestamp of function app if multiple CA are setup in same resource group.
	#>
	Param(
		[Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage="Subscription id in which CA setup is present.")]
        [string]
		[Alias("sid")]
		$SubscriptionId ,
		
		[Parameter(Mandatory = $true, ParameterSetName = "Default", HelpMessage = "Orgnanization name for which scan will be performed.")]
		[Alias("oz")]
		[string]
		$OrganizationName,

		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Resource group name where CA setup is available. (Default : ADOScannerRG)")]
        [string]
		[Alias("rg")]
		$ResourceGroupName ,
		
		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Timestamp of function app if multiple CA are setup in same resource group.")]
        [string]
		[Alias("rts")]
		$RsrcTimeStamp    

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
			$resolver = [Resolver]::new($OrganizationName)
			$caAccount = [CAAutomation]::new($SubscriptionId, $OrganizationName, $ResourceGroupName, $RsrcTimeStamp, $PSCmdlet.MyInvocation);
            
			return $caAccount.InvokeFunction($caAccount.GetAzSKADOContinuousAssurance);
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

