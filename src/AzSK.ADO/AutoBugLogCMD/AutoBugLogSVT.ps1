Set-StrictMode -Version Latest

function Start-AzSKADOBugLogging
{
	<#
	.SYNOPSIS
	This command would help in logging the bugs for failed resources meeting the specified input criteria.
	.DESCRIPTION
	This command will execute the bug logging for security controls.

	.PARAMETER OrganizationName
		Organization name for which the bug logging evaluation has to be performed.

	.PARAMETER ProjectNames
		Bug log project name under which the bug logging evaluation has to be performed.
	#>

	[Alias("Run-AzSKADOBugLogging")]
	Param
	(

		[string]
		[Parameter(Mandatory = $true, HelpMessage="Organization name to log bugs.")]
		[ValidateNotNullOrEmpty()]
		[Alias("oz")]
		$OrganizationName,

		[string]
		[Parameter(Mandatory = $true, HelpMessage="Project name in which the bug logging has to be performed.")]
		[ValidateNotNullOrEmpty()]
		[Alias("blpns", "blpn")]
		$BugLogProjectName,


		[ValidateSet("All","BaselineControls","PreviewBaselineControls", "Custom")]
		[Parameter(Mandatory = $false)]
		[Alias("abl")]
		[string] $AutoBugLog,


		[switch]
		[Parameter(HelpMessage = "Switch to auto-close bugs.")]
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
		[Parameter(Mandatory = $true, HelpMessage="Full path of scan result csv file for bug logging.")]
		[ValidateNotNullOrEmpty()]
		[Alias("fp", "sfp")]
		$ScanResultFilePath,

		[string]
		[Parameter(Mandatory = $false, HelpMessage="Full path of bug template file for bug logging.")]
		[ValidateNotNullOrEmpty()]
		[Alias("btfp", "btp")]
		$BugTemplateFilePath,

		[string]
		[Parameter(Mandatory = $false, HelpMessage="Folder path of ST mapping file for bug logging.")]
		[ValidateNotNullOrEmpty()]
		[Alias("stmfp", "stmp")]
		$STMappingFilePath,
		
		[ResourceTypeName]
		[Alias("rtn")]
		$ResourceTypeName = [ResourceTypeName]::All,

		[string]
		[Parameter(Mandatory = $false, ParameterSetName = "Default", HelpMessage = "Comma separated control ids to filter the security controls. e.g.: ADO_Organization_AuthN_Use_AAD_Auth, ADO_Organization_SI_Review_InActive_Users etc.")]
		[Alias("cids","cid")]
		[AllowEmptyString()]
		$ControlIds,

		[int]
		[Parameter(Mandatory = $false, HelpMessage="Max # of bugs to log. Default is 0 which means run bug logging for all.")]
		[Alias("mbl")]
		$MaxBugsToLog = 0,

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

		[string]
		[Parameter(Mandatory = $false, HelpMessage="Full path of HTML Template for bug description for bug logging.")]
		[ValidateNotNullOrEmpty()]
		[Alias("bdfp")]
		$BugDescriptionFilePath,

		[string]
		[Parameter(Mandatory = $false, HelpMessage="Full path of bug template for auto closing bugs.")]
		[ValidateNotNullOrEmpty()]
		[Alias("cbtfp","cbt")]
		$ClosedBugTemplateFilePath

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
			#Refresh singleton in different commands. (Powershell session keep cach object of the class, so need to make it null befor command run)
      		[AutoBugLog]::AutoBugInstance = $null
			[BugLogHelper]::BugLogHelperInstance = $null
            [BugMetaInfoProvider]::OrgMappingObj = @{}
      
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

			
			if(!$AutoBugLog -and !$AutoCloseBugs) {
				Write-Host 'Please supply bug log parameters [AutoBugLog or AutoCloseBugs]' -ForegroundColor Red;
				return;
			}

			if(![string]::IsNullOrWhiteSpace($ScanResultFilePath) -and(Test-Path $ScanResultFilePath)) {
				Write-Host 'Loading scan result file data.....' -ForegroundColor Cyan
				$ScanResult = @(Get-content $ScanResultFilePath | ConvertFrom-Csv);
			}
			else {
				Write-Host "Scan result file is not found. Please supply correct full path of scan result file." -ForegroundColor Red
				return;
			}

			$isValidBugTemplate = $false;
			if($AutoBugLog -and [string]::IsNullOrWhiteSpace($BugTemplateFilePath)){
				Write-Host 'Bug template file path is mandatory with AutoBugLog. Please provide correct value in [BugTemplateFilePath] command parameter.' -ForegroundColor Red;
				return;
			}
			if(![string]::IsNullOrWhiteSpace($BugTemplateFilePath) -and (Test-Path $BugTemplateFilePath)) {
				Write-Host 'Validating bug template.....' -ForegroundColor Cyan
				$BugTemplate = Get-content $BugTemplateFilePath | ConvertFrom-Json;
				$isValidBugTemplate = ValidateBugTemplate $BugTemplate
				if (!$isValidBugTemplate) {
					return;
				}
			}
			$BugDescription = $null;
			if(![string]::IsNullOrWhiteSpace($BugDescriptionFilePath) -and (Test-Path $BugDescriptionFilePath)) {
				$BugDescription = Get-Content $BugDescriptionFilePath -raw
			}
			if(![string]::IsNullOrWhiteSpace($ClosedBugTemplateFilePath) -and !(Test-Path $ClosedBugTemplateFilePath)) {
				Write-Host "Closed bug template file path seems to be invalid. Please check again."
				return;

			}
			$Organization = $OrganizationName;
			$IsLAFile = $false;
			if ($ScanResult.count -gt 0) {
				#if org is not supplied then take it from csv.
				if (!$OrganizationName -and [Helpers]::CheckMember($ScanResult, "ResourceLink")) {
					$Organization = $ScanResult[0].ResourceLink.Split('/')[3];
				}
				if ([Helpers]::CheckMember($ScanResult, "ResourceLink_s")) { #In case of LA files property name will be ResourceLink_s
					if ($ScanResult[0].ResourceLink_s) {
						if (!$OrganizationName) {
							$Organization = $ScanResult[0].ResourceLink_s.Split('/')[3];
						}
						$IsLAFile = $true;
					}
					else {
						Write-Host "Scan result file is not in correct format. Please remove [Tags] column if it is there in the file." -ForegroundColor Red
						return;
					}
				}
			}
				$resolver = [Resolver]::new($Organization, $PATToken);

				#Validating access on bug log project, default value is false if user has access then assigning it to true.
				$bugLogProjectAccess = $false;
				if ($BugLogProjectName) {
					Write-Host "Validating access on bug log project [$BugLogProjectName]....." -ForegroundColor Cyan
					$bugLogProjectAccess = CheckProjectAccess $BugLogProjectName $Organization
				}

				if ($bugLogProjectAccess -or !$BugLogProjectName) {
					if ($AutoBugLog) {
						$secStatus = [AzSKADOAutoBugLogging]::new($Organization, $BugLogProjectName, $AutoBugLog, $ResourceTypeName, $ControlIds, $ScanResult,$BugTemplate, $PSCmdlet.MyInvocation, $IsLAFile, $STMappingFilePath, $BugDescription, $MaxBugsToLog);
						
						if($secStatus.ScanResult){
							return $secStatus.InvokeFunction($secStatus.StartBugLogging);
						}
						else{
							Write-Host "No failed control found to run bug logging." -ForegroundColor Cyan;
							return;
						}	
					}
					elseif ($AutoCloseBugs) {
						$secStatus = [AzSKADOAutoBugLogging]::new($Organization, $BugLogProjectName, $ResourceTypeName, $ControlIds, $ScanResult, $PSCmdlet.MyInvocation, $IsLAFile, $MaxBugsToLog);
						if($secStatus.ScanResult) {
							return $secStatus.InvokeFunction($secStatus.ClosingLoggedBugs);	
						}
						else{
							Write-Host "No passed control found to run bug logging." -ForegroundColor Cyan;
							return;
						}
					}
					
				}
				else {
					Write-Host 'The remote server returned an error: (401) Unauthorized.' -ForegroundColor Red 
				}
		}
		catch
		{
			if ([Helpers]::CheckMember($_.Exception, "Response.StatusCode") -and $_.Exception.Response.StatusCode -eq 'Unauthorized') {
				Write-Host 'The remote server returned an error: (401) Unauthorized.' -ForegroundColor Red 
			}
			else {
				[EventBase]::PublishGenericException($_);
				
			}
		}
	}

	End
	{
		[ListenerHelper]::UnregisterListeners();
	}
}

function CheckProjectAccess {
	param (
		$projectName,
		$orgName
	)

	try {
		$url = 'https://dev.azure.com/{0}/_apis/projects/{1}?api-version=6.0' -f $orgName, $projectName;
    	$header = [WebRequestHelper]::GetAuthHeaderFromUri($url)                                                                     
    	$ObjProject  = Invoke-WebRequest -Uri $url -Headers $header	
	return $true;

	}
	catch {
		return $false;
	}
	
}

function ValidateBugTemplate {
	param (
		$BugTemplate
	)

	$mandatorytemplateItems = @("/fields/System.Title", "/fields/System.AreaPath", "/fields/System.IterationPath", "/fields/System.Tags", "/fields/System.AssignedTo")
	try {
		foreach ($templateItem in $mandatorytemplateItems) {
			if($templateItem -notin $BugTemplate.path) {
				Write-Host "Bug template format is not correct. Mandatory fields are not supplied in the template." -ForegroundColor Red
				return $false;
			}	
		}
		
		return $true;
	}
	catch {
		Write-Host "Could not parse bug template. Please validate the template format." -ForegroundColor Red
		return $false;
	}	
}
