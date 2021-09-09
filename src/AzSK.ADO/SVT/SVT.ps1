﻿Set-StrictMode -Version Latest

function Get-AzSKADOSecurityStatus
{
	<#
	.SYNOPSIS
	This command would help in validating the security controls for the Azure resources meeting the specified input criteria.
	.DESCRIPTION
	This command will execute the security controls and will validate their status as 'Success' or 'Failure' based on the security guidance. Refer https://aka.ms/azskossdocs for more information

	.PARAMETER OrganizationName
		Organization name for which the security evaluation has to be performed.

	.PARAMETER ProjectNames
		Project name for which the security evaluation has to be performed.

	.PARAMETER BuildNames
		Build name for which the security evaluation has to be performed.

	.PARAMETER ReleaseNames
		Release name for which the security evaluation has to be performed.

	.PARAMETER AgentPoolNames
	   Agent name for which the security evaluation has to be performed.

	.PARAMETER DetailedScan
		Print detailed scan logs for controls.

	.NOTES
	This command helps the application team to verify whether their Azure resources are compliant with the security guidance or not

	.LINK
	https://aka.ms/azskossdocs

	#>

	[OutputType([String])]
	[Alias("Get-AzSKAzureDevOpsSecurityStatus")]
	Param
	(

		[string]
		[Parameter(Position = 0, Mandatory = $true, HelpMessage="OrganizationName for which the security evaluation has to be performed.")]
		[ValidateNotNullOrEmpty()]
		[Alias("oz")]
		$OrganizationName,

		[string]
		[Parameter( HelpMessage="Project names for which the security evaluation has to be performed.")]
		[ValidateNotNullOrEmpty()]
		[Alias("pns", "ProjectName", "pn")]
		$ProjectNames,

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
		[Parameter(HelpMessage="Agent Pool names for which the security evaluation has to be performed.")]
		[ValidateNotNullOrEmpty()]
		[Alias("aps", "AgentPoolName","ap")]
		$AgentPoolNames,


		[string]
		[Parameter(HelpMessage="Service connection names for which the security evaluation has to be performed.")]
		[ValidateNotNullOrEmpty()]
		[Alias("sc", "ServiceConnectionName", "scs")]
		$ServiceConnectionNames,

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
		[Parameter(HelpMessage="Scan all supported resource types present under organization like build, release, projects etc.")]
		[Alias("sar", "saa" , "ScanAllArtifacts", "sat", "ScanAllResourceTypes")]
		$ScanAllResources,

		[string]
		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Comma separated control ids to filter the security controls. e.g.: ADO_Organization_AuthN_Use_AAD_Auth, ADO_Organization_SI_Review_InActive_Users etc.")]
		[Parameter(Mandatory = $true, ParameterSetName = "BulkAttestation", HelpMessage="Comma separated control ids to filter the security controls. e.g.: ADO_Organization_AuthN_Use_AAD_Auth, ADO_Organization_SI_Review_InActive_Users etc.")]
		[Parameter(Mandatory = $true, ParameterSetName = "BulkAttestationClear", HelpMessage="Comma separated control ids to filter the security controls. e.g.: ADO_Organization_AuthN_Use_AAD_Auth, ADO_Organization_SI_Review_InActive_Users etc.")]
		[Alias("BulkAttestControlId","cids","bacid")]
		[AllowEmptyString()]
		$ControlIds,

		[string]
		[Parameter(Mandatory = $false)]
		[Alias("ft")]
		$FilterTags,

		[string]
		[Parameter(Mandatory = $false)]
		[Alias("xt")]
		$ExcludeTags,

		[string]
		[Parameter(Mandatory = $false)]
		[Alias("xcids")]
		[AllowEmptyString()]
		$ExcludeControlIds,

		[switch]
		[Parameter(Mandatory = $false)]
		[Alias("ubc")]
		$UseBaselineControls,

		[switch]
		[Parameter(Mandatory = $false)]
		[Alias("upbc")]
		$UsePreviewBaselineControls,

		[string]
		[Parameter(Mandatory = $false, HelpMessage="Specify the severity of controls to be scanned. Example `"High, Medium`"")]
		[Alias("ControlSeverity")]
		$Severity,

		[int]
		[Parameter(Mandatory = $false, HelpMessage="Max # of objects to check. Default is 0 which means scan all.")]
		[Alias("mo")]
		$MaxObj = 0,

		[System.Security.SecureString]
		[Parameter(HelpMessage="Token to run scan in non-interactive mode")]
		[Alias("tk")]
		$PATToken,

		[switch]
		[Parameter(HelpMessage = "Switch to provide personal access token (PAT) using UI.")]
		[Alias("pfp")]
		$PromptForPAT,

		[string]
		[Parameter(Mandatory=$false, HelpMessage="KeyVault URL for PATToken")]
		[Alias("ptu")]
		$PATTokenURL,

		[ResourceTypeName]
		[Alias("rtn")]
		$ResourceTypeName = [ResourceTypeName]::All,

        [switch]
        [Parameter(Mandatory = $false)]
		[Alias("upc")]
		$UsePartialCommits,

		[switch]
        [Parameter(Mandatory = $false)]
		[Alias("dnrr")]
		$DoNotRefetchResources,

		[switch]
        [Parameter(Mandatory = $false)]
		[Alias("dnof")]
		$DoNotOpenOutputFolder,

		[ValidateSet("All","AlreadyAttested","NotAttested","None")]
        [Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage="Using this switch,  AzSK.ADO enters 'attest' mode immediately after a scan is completed. This ensures that attestation is done on the basis of the most current control statuses.")]
        [Parameter(Mandatory = $true, ParameterSetName = "BulkAttestation", HelpMessage="Using this switch,  AzSK.ADO enters 'attest' mode immediately after a scan is completed. This ensures that attestation is done on the basis of the most current control statuses.")]
        [Parameter(Mandatory = $true, ParameterSetName = "BulkAttestationClear", HelpMessage="Using this switch,  AzSK.ADO enters 'attest' mode immediately after a scan is completed. This ensures that attestation is done on the basis of the most current control statuses.")]
		[Alias("AttestControls","cta")]
		$ControlsToAttest = [AttestControls]::None,

		[switch]
		[Parameter(Mandatory = $true, ParameterSetName = "BulkAttestationClear", HelpMessage="Use this option if you want to clear the attestation for multiple resources in bulk, for a specified controlId.")]
		[Alias("bc")]
		$BulkClear,

		[string]
        [Parameter(Mandatory = $true, ParameterSetName = "BulkAttestation", HelpMessage="Use this option to provide an apt justification with proper business reason.")]
		[Alias("jt")]
		$JustificationText,

		[ValidateSet("NotAnIssue", "WillNotFix", "WillFixLater","NotApplicable","StateConfirmed","ApprovedException")]
        [Parameter(Mandatory = $true, ParameterSetName = "BulkAttestation", HelpMessage="Attester must select one of the attestation reasons (NotAnIssue, WillNotFix, WillFixLater, NotApplicable, StateConfirmed(if valid for the control))")]
		[Alias("as")]
		$AttestationStatus = [AttestationStatus]::None,

		[switch]
		[Parameter(Mandatory = $false, HelpMessage = "Switch to add approved exceptions.")]
		[Alias("aex")]
		$AddException,

		[Datetime]
		[Parameter(Mandatory = $false, HelpMessage = "Expiry date of approved exception.")]
		[Alias("aee")]
		$ApprovedExceptionExpiryDate,

		[string]
		[Parameter(Mandatory = $false, HelpMessage = "ID of approved exception.")]
		[Alias("aei")]
		$ApprovedExceptionID,

		[string]
		[Parameter(HelpMessage="Project name to store attestation details for organization-specific controls.")]
		[ValidateNotNullOrEmpty()]
		[Alias("atp","HostProjectName")]
		$AttestationHostProjectName,


		[ValidateSet("All","BaselineControls","PreviewBaselineControls", "Custom")]
		[Parameter(Mandatory = $false)]
		[Alias("abl")]
		[string] $AutoBugLog = [BugLogForControls]::All,


		[switch]
		[Parameter(HelpMessage = "Switch to auto-close bugs after the scan.")]
		[Alias("acb")]
		$AutoCloseBugs,

		[string]
		[Parameter(Mandatory=$false)]
		[Alias("apt")]
		$AreaPath,

		[string]
		[Parameter(Mandatory=$false)]
		[Alias("ipt")]
		$IterationPath,

		[string]
		[Parameter(Mandatory = $false, HelpMessage = "Specify the security severity of bugs to be logged.")]
		[Alias("ssv")]
		$SecuritySeverity,

		[string]
		[Parameter(HelpMessage="Specify the custom field reference name for bug description.")]
		[ValidateNotNullOrEmpty()]
		[Alias("bdf")]
		$BugDescriptionField,

		[switch]
		[Parameter(HelpMessage="Allow long running scan.")]
		[Alias("als, alrs")]
		$AllowLongRunningScan,

		[string]
		[Parameter(Mandatory = $false, HelpMessage="Name of the project hosting organization policy with which the scan should run.")]
		[ValidateNotNullOrEmpty()]
		[Alias("pp")]
		$PolicyProject,

		[switch]
		[Parameter(HelpMessage="Print detailed scan logs for controls.")]
		[Alias("ds")]
		$DetailedScan,

		[string]
		[Parameter(HelpMessage="Service id for which the security evaluation has to be performed.")]
		[ValidateNotNullOrEmpty()]
		[Alias("svcid")]
		$ServiceIds,

		[switch]
		[Parameter(HelpMessage="Include admin controls (organization and project specific controls) in scan.")]
		[Alias("iac")]
		$IncludeAdminControls,

		[switch]
		[Parameter(HelpMessage="Skip organization and user controls.")]
		[Alias("souc")]
		$SkipOrgUserControls,

		[string]
		[Parameter(Mandatory = $false, HelpMessage="Name of the repository containing org policy endpoint.")]
		[ValidateNotNullOrEmpty()]
		[Alias("prn")]
		$PolicyRepoName,

		[ValidateSet("Graph", "RegEx", "GraphThenRegEx")]
    	[Parameter(Mandatory = $false, HelpMessage="Evaluation method to evaluate SC-ALT admin controls.")]
		[Alias("acem")]
    	[string] $ALTControlEvaluationMethod,
        
    	[string]
		[Parameter(Mandatory = $false, HelpMessage="Folder path of builds to be scanned.")]
		[ValidateNotNullOrEmpty()]
		[Alias("bp")]
		$BuildsFolderPath,

		[string]
		[Parameter(Mandatory = $false, HelpMessage="Folder path of releases to be scanned.")]
		[ValidateNotNullOrEmpty()]
		[Alias("rfp")]
		$ReleasesFolderPath,

    
		[switch]
    	[Parameter(HelpMessage="Print SARIF logs for the scan.")]
    	[Alias("gsl")]
    	$GenerateSarifLogs,

		[switch]
		[Parameter(HelpMessage="Switch to reset default logged in user.")]
		[Alias("rc")]
		$ResetCredentials,
        
    	[switch]
		[Parameter(HelpMessage="Switch to copy current data object in local folder to facilitate control fix.")]
		[Alias("pcf")]
		$PrepareForControlFix,
	
		[switch]
        [Parameter(Mandatory = $false, HelpMessage="Scan only those resource objects modified after immediately previous scan.")]
		[Alias("inc", "ScanIncrementally")]
		$IncrementalScan,

		[switch]
		[Parameter()]
		[Alias("bs")]
		$BatchScan,

		[switch]
		[switch]
		[Parameter()]
		[Alias("bsmp")]
		$BatchScanMultipleProjects,

		[string]
		[Parameter()]
		[Alias("fn")]
		$FolderName,

		[DateTime]
		[Parameter(Mandatory = $false, HelpMessage="Date to use as threshold for incremental scanning.")]
		[ValidateNotNullOrEmpty()]
		[Alias("dt", "IncrementDate")]
		$IncrementalDate

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
			[ConfigurationHelper]::PolicyCacheContent = @()
			[ConfigurationHelper]::OnlinePolicyEnabled = $false
			[ConfigurationHelper]::OssPolicyUrl = ""
			[ConfigurationHelper]::OssPolicyEnabled = $false
			[ConfigurationHelper]::LocalPolicyEnabled = $false
			[ConfigurationHelper]::ConfigVersion = ""
			[AzSKSettings]::Instance = $null
			[AzSKConfig]::Instance = $null
			[ConfigurationHelper]::ServerConfigMetadata = $null
			#Refresh singlton in different gads commands. (Powershell session keep cach object of the class, so need to make it null befor command run)
      
      [AutoBugLog]::AutoBugInstance = $null
      #Clear the cache of nested groups if the org name is not matching from previous scan in same session
			if ([ControlHelper]::GroupMembersResolutionObj.ContainsKey("OrgName") -and [ControlHelper]::GroupMembersResolutionObj["OrgName"] -ne $OrganizationName) {
				[ControlHelper]::GroupMembersResolutionObj = @{}
				[AdministratorHelper]::isCurrentUserPCA = $false
				[AdministratorHelper]::isCurrentUserPA= $false
                [AdministratorHelper]::AllPCAMembers = @()
				[AdministratorHelper]::AllPAMembers = @()
			}
      
      if ($PrepareForControlFix -eq $true)  {
          if ($UsePartialCommits -ne $true)  {
              Write-Host "PrepareForControlFix switch requires -UsePartialCommits switch." -ForegroundColor Red
              return;
          }
          elseif ([String]::IsNullOrEmpty($ControlIds) -or $ControlIds -match ','){
              Write-Host "PrepareForControlFix switch requires one controlid. Use -ControlIds parameter to provide it." -ForegroundColor Red
              return;
          }
      }

			if($PromptForPAT -eq $true)
			{
				if($null -ne $PATToken)
				{
					Write-Host "Parameters '-PromptForPAT' and '-PATToken' can not be used simultaneously in the scan command." -ForegroundColor Red
					return;
				}
				else
				{
					$PATToken = Read-Host "Provide PAT for [$OrganizationName] org:" -AsSecureString
				}

			}

			if (-not [String]::IsNullOrEmpty($PATTokenURL))
			{
				# For now, if PAT URL is specified we will trigger an Azure login.
				$Context = @(Get-AzContext -ErrorAction SilentlyContinue )
				if ($Context.count -eq 0)  {
					Write-Host "No active Azure login session found.`r`nPlease login to Azure tenant hosting the key vault..." -ForegroundColor Yellow
					Connect-AzAccount -ErrorAction Stop
					$Context = @(Get-AzContext -ErrorAction SilentlyContinue)
				}

				if ($null -eq $Context)  {
					Write-Host "Login failed. Azure login context is required to use a key vault-based PAT token.`r`nStopping scan command." -ForegroundColor Red
					return;
				}
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
						Write-Host "Could not extract PATToken from the given key vault URL.`r`nStopping scan command." -ForegroundColor Red
						return;
					}
					$PATToken = $kvSecret.SecretValue;
				}
				else {
					Write-Host "Could not extract PATToken from the given key vault URL.`r`nStopping scan command." -ForegroundColor Red
					return;
				}
			}


			if ($ResetCredentials)
			{
				[ContextHelper]::PromptForLogin = $true
			}
			else
			{
				[ContextHelper]::PromptForLogin =$false
			}

			if(![string]::IsNullOrEmpty($BuildsFolderPath))
			{
				if($ResourceTypeName -notin([ResourceTypeName]::All,[ResourceTypeName]::Build))
				{
					Write-Host "Parameters '-BuildsFolderPath' and '-rtn'(values except 'All','Build') can not be used simultaneously in the scan command." -ForegroundColor Red
					return;
				}
			}

			if(![string]::IsNullOrEmpty($ReleasesFolderPath))
			{
				if($ResourceTypeName -notin([ResourceTypeName]::All,[ResourceTypeName]::Release))
				{
					Write-Host "Parameters '-ReleasesFolderPath' and '-rtn'(values except 'All','Release') can not be used simultaneously in the scan command." -ForegroundColor Red
					return;
				}
			}

			$resolver = [SVTResourceResolver]::new($OrganizationName,$ProjectNames,$BuildNames,$ReleaseNames,$AgentPoolNames, $ServiceConnectionNames, $VariableGroupNames, $MaxObj, $ScanAllResources, $PATToken,$ResourceTypeName, $AllowLongRunningScan, $ServiceIds, $IncludeAdminControls, $SkipOrgUserControls, $RepoNames, $SecureFileNames, $FeedNames, $EnvironmentNames, $BuildsFolderPath,$ReleasesFolderPath,$UsePartialCommits,$DoNotRefetchResources,$BatchScan, $IncrementalScan, $IncrementalDate);

			$secStatus = [ServicesSecurityStatus]::new($OrganizationName, $PSCmdlet.MyInvocation, $resolver);
			if ($secStatus)
			{
				if ($null -ne $secStatus.Resolver.SVTResources) {

					$secStatus.ControlIdString = $ControlIds;
					$secStatus.Severity = $Severity;
					$secStatus.UseBaselineControls = $UseBaselineControls;
					$secStatus.UsePreviewBaselineControls = $UsePreviewBaselineControls;

					$secStatus.FilterTags = $FilterTags;
					$secStatus.ExcludeTags = $ExcludeTags;

					$secStatus.ExcludeControlIdString = $ExcludeControlIds

					#build the attestation options object
					[AttestationOptions] $attestationOptions = [AttestationOptions]::new();
					$attestationOptions.AttestControls = $ControlsToAttest
					$attestationOptions.JustificationText = $JustificationText
					$attestationOptions.AttestationStatus = $AttestationStatus
					$attestationOptions.IsBulkClearModeOn = $BulkClear
					$attestationOptions.IsExemptModeOn = $AddException
					$attestationOptions.ApprovedExceptionExpiryDate =  $ApprovedExceptionExpiryDate
					$attestationOptions.ApprovedExceptionID = $ApprovedExceptionID
					$secStatus.AttestationOptions = $attestationOptions;

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
