Set-StrictMode -Version Latest
function Get-AzSKADOInfo
{

	<#
	.SYNOPSIS
	This command would help users to get details of various components of AzSK.ADO.

	.DESCRIPTION
	This command will fetch details of AzSK.ADO components and help user to provide details of different component using single command. Refer https://aka.ms/adoscanner/docs for more information

	.PARAMETER InfoType
		InfoType for which type of information required by user.
	.PARAMETER ResourceTypeName
		Friendly name of resource type. e.g.: Build, Release, etc. (combo types e.g., Build_Release are not currently supported).
	.PARAMETER DoNotOpenOutputFolder
		Switch to specify whether to open output folder containing all security evaluation report or not.
	.PARAMETER UseBaselineControls
		This switch would scan only for baseline controls defined at org level
	.PARAMETER ControlIds
		Comma-separated control ids to filter the security controls. e.g.: ADO_Release_AuthZ_Disable_Inherited_Permissions, ADO_ServiceConnection_AuthZ_Dont_Grant_All_Pipelines_Access
	.PARAMETER ControlSeverity
		Select one of the control severity (Critical, High, Low, Medium)
	.PARAMETER ControlIdContains
		The list of control ids for which fixes should be applied.

	.NOTES
	This command helps the application team to verify whether their ADO resources are compliant with the security guidance or not

	.LINK
	https://aka.ms/ADOScanner

	#>
	Param(
		[Parameter(Mandatory = $false)]
		[ValidateSet("OrganizationInfo", "ControlInfo", "HostInfo", "UserInfo", "AADGroupsInfo")] 
		[Alias("it")]
		$InfoType,

		[string]
		[Parameter(Mandatory = $true)]
		[Alias("oz")]
		$OrganizationName,

		[string]
		[Parameter( HelpMessage="Project names for which the security evaluation has to be performed.")]
		[ValidateNotNullOrEmpty()]
		[Alias("pns", "ProjectName", "pn")]
		$ProjectNames,

		[string]
		[Parameter(Mandatory = $false, HelpMessage="Name of the project hosting organization policy with which the scan should run.")]
		[ValidateNotNullOrEmpty()]
		[Alias("pp")]
		$PolicyProject,

		[ResourceTypeName]
		[Alias("rtn")]
		$ResourceTypeName = [ResourceTypeName]::All,

		[string]
		[Alias("cids")]
        $ControlIds,

		[switch]
		[Alias("ubc")]
		$UseBaselineControls,

		[switch]
		[Alias("upbc")]
        $UsePreviewBaselineControls,

		[Alias("cs")]
		$ControlSeverity,

		[string]
		[Alias("ft")]
		$FilterTags,

		[string]
		[Alias("cidc")]
		$ControlIdContains,

		[switch]
		[Parameter(Mandatory = $false, HelpMessage = "Switch to specify whether to open output folder.")]
		[Alias("dnof")]
		$DoNotOpenOutputFolder,

		[string]
		[Parameter(Mandatory = $false, HelpMessage="User email/principal name for which permissions information is requested.")]
		[ValidateNotNullOrEmpty()]
		[Alias("email", "UserEmail")]
		$PrincipalName,

		[System.Security.SecureString]
		[Parameter(HelpMessage = "Token to run scan in non-interactive mode")]
		[Alias("tk")]
		$PATToken,

		[switch]
		[Parameter(HelpMessage = "Switch to provide personal access token (PAT) using UI.")]
		[Alias("pfp")]
		$PromptForPAT
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
			$unsupported = $false
			if([string]::IsNullOrWhiteSpace($ResourceTypeName))
			{
				$ResourceTypeName = [ResourceTypeName]::All
			}
			elseif ($ResourceTypeName -match "_")
			{
				$unsupported = $true
				Write-Host -ForegroundColor Yellow "Combo ResourceTypeNames are not supported in this command.`r`nUse individual names or run use All and apply filter in CSV."
			}


			if(-not ([string]::IsNullOrEmpty($InfoType) -or $unsupported))
			{
				#Set empty, so org-policy get refreshed in every gadi run in same PS session.
				[ConfigurationHelper]::PolicyCacheContent = @()
				[AzSKSettings]::Instance = $null
				[AzSKConfig]::Instance = $null
				[ConfigurationHelper]::ServerConfigMetadata = $null

				switch ($InfoType.ToString())
				{
					OrganizationInfo {
						#Initialize context
						$ContextHelper = [ContextHelper]::new()
						if ($PromptForPAT -eq $true) {
							if ($null -ne $PATToken) {
								Write-Host "Parameters '-PromptForPAT' and '-PATToken' can not be used simultaneously in the scan command." -ForegroundColor Red
								return;
							}
							else {
								$PATToken = Read-Host "Provide PAT for [$OrganizationName] org:" -AsSecureString
							}

						}
						if (-not [String]::IsNullOrEmpty($PATToken)) {
							$ContextHelper.SetContext($organizationName, $PATToken)
						}
						else {
							$ContextHelper.SetContext($organizationName)
						}
						$apiURL = 'https://dev.azure.com/{0}/_apis/projects?$top=1000&api-version=6.0' -f $($OrganizationName);
						$responseObj = "";
						try {
							$responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL) ;
							if (([Helpers]::CheckMember($responseObj, "count") -and $responseObj[0].count -gt 0) -or (($responseObj | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($responseObj[0], "name"))) {
								if ([string]::IsNullOrWhiteSpace($ProjectNames) -or $ProjectNames -eq "*") {
									$projects = $responseObj
								}
								else {
									$projectList = $ProjectNames.trim().Split(',');
									$projects = $responseObj | Where-Object { $projectList -contains $_.name }
								}
								if (($projects | Measure-Object).count -eq 0) {
									throw [SuppressedException] "Projects not found: Incorrect organization name or you do not have necessary permission to access the project."
								}
								$organizationInfo = [OrganizationInfo]::new($OrganizationName, $projects, $PSCmdlet.MyInvocation);
								if ($organizationInfo) {
									return $organizationInfo.InvokeFunction($organizationInfo.GetResourceInventory);
								}
							}
							else {
								Write-Host 'Projects not found: Incorrect organization name or you do not have necessary permission to access the project.' -ForegroundColor Red
								throw;
							}
						}
						catch {
							Write-Host 'Unable to fetch resource inventory details : Incorrect organization name or you do not have necessary permission to access the project.' -ForegroundColor Red
							throw;
						}
					}
					ControlInfo
					{
						If($PSCmdlet.MyInvocation.BoundParameters["Verbose"] -and $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent)
						{
							$Full = $true
						}
						else
						{
							$Full = $false
						}

						$controlsInfo = [ControlsInfo]::new($OrganizationName, $PSCmdlet.MyInvocation, $ResourceTypeName, $ControlIds, $UseBaselineControls, $UsePreviewBaselineControls, $FilterTags, $Full, $ControlSeverity, $ControlIdContains);
						if ($controlsInfo)
						{
							return $controlsInfo.InvokeFunction($controlsInfo.GetControlDetails);
						}
					}
					HostInfo
					{
						$hInfo = [HostInfo]::new($OrganizationName, $PSCmdlet.MyInvocation);
						if ($hInfo)
						{
							return $hInfo.InvokeFunction($hInfo.GetHostInfo);
						}
					}
					AttestationInfo
					{
						Write-Host -ForegroundColor Yellow "AttestationInfo support is yet to be implemented."
					}
					UserInfo
					{
						if($ProjectNames -eq "*" -or $ProjectNames -match "\,") {
							Write-Host "This command currently supports user permission information for a single project. Please provide a single project name." -ForegroundColor Red
						}
						elseif ([string]::IsNullOrWhiteSpace($PrincipalName)) {
							$currentUser = [ContextHelper]::GetCurrentSessionUser();
							# Write-Host "InfoType 'UserInfo' requires principal name parameter to scan. If not provided, it'll take the context of current logged in user." -ForegroundColor Yellow
							$userInfo = [UserInfo]::new($OrganizationName, $currentUser, $ProjectNames, $PSCmdlet.MyInvocation);
							return $userInfo.InvokeFunction($userInfo.GetPermissionDetails);
						}
						else {
							$userInfo = [UserInfo]::new($OrganizationName, $PrincipalName, $ProjectNames, $PSCmdlet.MyInvocation);
							return $userInfo.InvokeFunction($userInfo.GetPermissionDetails);
						}
                    }
					AADGroupsInfo
					{
						$AADGroupsInfo = [AADGroupsInfo]::new($OrganizationName, $ProjectNames, $PSCmdlet.MyInvocation);
						return $AADGroupsInfo.InvokeFunction($AADGroupsInfo.GetAADGroupsList);
					}
					Default
					{
						Write-Host $([Constants]::DefaultInfoCmdMsg)
					}
				}
			}
			else
			{
				Write-Host $([Constants]::DefaultInfoCmdMsg)
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
