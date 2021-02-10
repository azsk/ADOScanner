Set-StrictMode -Version Latest
function Get-AzSKADOUserPermissions {
	<#
		.SYNOPSIS
		This command would help in getting the user permissions and group access.
		.DESCRIPTION
		This command would help in getting the user permissions and group access.
		.PARAMETER OrganizationName
			Organization name for which the security evaluation has to be performed.
		.PARAMETER UserMail
			User for which we need to check the permissions.
		.NOTES
		This command helps the application team to verify whether their Azure resources are compliant with the security guidance or not 
		.LINK
		https://aka.ms/azskossdocs
	#>

	Param (
		[string]		 
		[Parameter(Position = 0, Mandatory = $true, HelpMessage="OrganizationName for which the security evaluation has to be performed.")]
		[ValidateNotNullOrEmpty()]
		[Alias("oz")]
		$OrganizationName,

		[string]
		[Parameter(Position = 1, Mandatory = $true, HelpMessage="User email for which the permission evaluation has to be performed.")]
		[ValidateNotNullOrEmpty()]
		[Alias("email", "UserEmail")]
		$PrincipalName,

		[string]
		[Parameter( HelpMessage="Project names for which the permission evaluation has to be performed.")]
		[ValidateNotNullOrEmpty()]
		[Alias("project", "pn")]
		$ProjectName
	)
	Begin {
		[CommandHelper]::BeginCommand($PSCmdlet.MyInvocation);
		[ListenerHelper]::RegisterListeners();
	}

	Process {
		try {
            $mapping = [ADOUserPermissions]::new($OrganizationName, $PrincipalName, $ProjectName, $PSCmdlet.MyInvocation);
            return $mapping.InvokeFunction($mapping.GetPermissionDetails);
		}
		catch {
			[EventBase]::PublishGenericException($_);
		}  
	}
	
	End {
		[ListenerHelper]::UnregisterListeners();
	}
}