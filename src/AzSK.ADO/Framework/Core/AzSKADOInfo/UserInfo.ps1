using namespace System.Management.Automation
Set-StrictMode -Version Latest 

class UserInfo: CommandBase {
    
    hidden [string] $organizationName;
	hidden [string] $userMail;
	hidden [string] $projectName;
	hidden $principal_flag;

	UserInfo([string] $organizationName, [string] $userMail, $principal_flag, [string] $ProjectName, [InvocationInfo] $invocationContext):
	Base($organizationName, $invocationContext) {
        $this.organizationName = $organizationName;
		$this.userMail = $userMail;
		$this.principal_flag = $principal_flag;
		$this.projectName = $ProjectName;
	}

	[string] GetUserDescriptor() {
		# fetching the users list to get the user descriptor mapped against user email id
		$url = "https://vssps.dev.azure.com/$($this.organizationName)/_apis/graph/users?api-version=6.0-preview.1"
		[PSObject] $allUsers = $null;
		try {
			$response = [WebRequestHelper]::InvokeGetWebRequest($url);
			if($response.count -gt 0) {
				$allUsers = $response;
			}
			else {
				$allUsers = $null;
			}
		}
		catch {
			$this.PublishCustomMessage("Could not fetch the list of users in the organization.", [MessageType]::Error)
            # [EventBase]::PublishGenericException($_);
		}
		$userDescriptor = ""
		$user = $allUsers | Where-Object { $_.mailAddress -eq $this.userMail }
		if([Helpers]::CheckMember($user, "descriptor")) {
			$userDescriptor = $user.descriptor;
		}
		return $userDescriptor;
	}
	
	[MessageData[]] GetPermissionDetails() {
		[MessageData[]] $returnMsgs = @();
		# getting the selected users descriptor
		$userDescriptor = $this.GetUserDescriptor()
		
		if([string]::IsNullOrWhiteSpace($userDescriptor)) {
			$this.PublishCustomMessage("Could not find the user in the organization. Please validate the principal name of the user.");
		}
		else {
			# fetching membership details
			$url = "https://vssps.dev.azure.com/$($this.organizationName)/_apis/Graph/Memberships/$($userDescriptor)?api-version=6.0-preview.1"
			try {
				$response = [WebRequestHelper]::InvokeGetWebRequest($url);
				$formattedData = @()
				$count = 0
				foreach ($obj in $response) {
					$url = "https://vssps.dev.azure.com/$($this.organizationName)/_apis/graph/groups/$($obj.containerDescriptor)?api-version=6.0-preview.1";
					$res = [WebRequestHelper]::InvokeGetWebRequest($url);
					$data = $res.principalName.Split("\");
					$formattedData += @{
						Group = $data[1];
						Scope = $data[0];
					}
					$count += 1;
				}
				$returnMsgs += [MessageData]::new("Total number of groups user is a member of: $($count)")
				$this.PublishCustomMessage("Total number of groups user is a member of: $($count) `n")
				$formattedData = $formattedData | select-object @{Name="Group Name"; Expression={$_.Group}}, @{Name="User or scope"; Expression={$_.Scope}} | Out-String
				$returnMsgs += $formattedData
				$this.PublishCustomMessage($formattedData)
			}
			catch {
				$this.PublishCustomMessage("Could not fetch the membership details for the user.", [MessageType]::Error)
				# [EventBase]::PublishGenericException($_);
			}
			$this.PublishCustomMessage([Constants]::DoubleDashLine)
			$returnMsgs += [Constants]::DoubleDashLine;
			# fetching permission details based on project names parameter
			if ([string]::IsNullOrWhiteSpace($this.projectName)) {
				# if there are no project names provided, permissions details of org level needs to be displayed
				$url = "https://dev.azure.com/$($this.organizationName)/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1";
				$body = "{
					'contributionIds':[
						'ms.vss-admin-web.org-admin-groups-permissions-pivot-data-provider'
					],
					'dataProviderContext':{
						'properties':{
							'subjectDescriptor':'',
							'sourcePage':{
								'url':'',
								'routeId':'ms.vss-admin-web.collection-admin-hub-route',
								'routeValues':{
									'adminPivot':'groups',
									'controller':'ContributedPage',
									'action':'Execute',
									'serviceHost':''
								}
							}
						}
					}
				}" | ConvertFrom-Json;
				$body.dataProviderContext.properties.subjectDescriptor = $userDescriptor;
				$body.dataProviderContext.properties.sourcePage.url = "https://dev.azure.com/$($this.organizationName)/_settings/groups?subjectDescriptor=$($userDescriptor)";
				$response = ""
                try {
					$response = [WebRequestHelper]::InvokePostWebRequest($url, $body);
					$returnMsgs += [MessageData]::new("User permissions (organization level):")
					$this.PublishCustomMessage("User permissions (organization level): `n")
					if ([Helpers]::CheckMember($response, "dataProviders") -and $response.dataProviders.'ms.vss-admin-web.org-admin-groups-permissions-pivot-data-provider' -and [Helpers]::CheckMember($response.dataProviders.'ms.vss-admin-web.org-admin-groups-permissions-pivot-data-provider', "subjectPermissions")) {
						$permissions = $response.dataProviders.'ms.vss-admin-web.org-admin-groups-permissions-pivot-data-provider'.subjectPermissions
						$formattedData = $permissions | select-object @{Name="DisplayName"; Expression = {$_.displayName}}, @{Name="Permissions"; Expression = {$_.permissionDisplayString}} | Out-String
						$returnMsgs += $formattedData
						$this.PublishCustomMessage($formattedData)
					}
				}
				catch {
					$this.PublishCustomMessage("Could not fetch the user permissions for the organization [$($this.organizationName)].", [MessageType]::Error)
					# [EventBase]::PublishGenericException($_);
				}
			}
			else {
				# if project names are provided, permissions details of project level needs to be displayed
				$url = "https://dev.azure.com/$($this.organizationName)/_apis/Contribution/HierarchyQuery?api-version=5.0-preview.1"
				$body = "{
					'contributionIds':[
						'ms.vss-admin-web.org-admin-groups-permissions-pivot-data-provider'
					],
					'dataProviderContext':{
						'properties':{
							'subjectDescriptor':'',
							'sourcePage':{
								'url':'',
								'routeId':'ms.vss-admin-web.project-admin-hub-route',
								'routeValues':{
									'project':'',
									'adminPivot':'permissions',
									'controller':'ContributedPage',
									'action':'Execute',
									'serviceHost':''
								}
							}
						}
					}
				}" | ConvertFrom-Json;
				$body.dataProviderContext.properties.subjectDescriptor = $userDescriptor;
				$body.dataProviderContext.properties.sourcePage.url = "https://dev.azure.com/$($this.organizationName)/$($this.projectName)/_settings/permissions";
				$body.dataProviderContext.properties.sourcePage.routeValues.project = $this.projectName
				$response = ""
				try {
					$response = [WebRequestHelper]::InvokePostWebRequest($url, $body);
					$returnMsgs += [MessageData]::new("User permissions for project [$($this.projectName)]:")
					$this.PublishCustomMessage("User permissions for project [$($this.projectName)]: `n")
					if ([Helpers]::CheckMember($response, "dataProviders") -and $response.dataProviders.'ms.vss-admin-web.org-admin-groups-permissions-pivot-data-provider' -and [Helpers]::CheckMember($response.dataProviders.'ms.vss-admin-web.org-admin-groups-permissions-pivot-data-provider', "subjectPermissions")) {
						$permissions = $response.dataProviders.'ms.vss-admin-web.org-admin-groups-permissions-pivot-data-provider'.subjectPermissions
						$formattedData = $permissions | select-object @{Name="DisplayName"; Expression = {$_.displayName}}, @{Name="Permissions"; Expression = {$_.permissionDisplayString}} | Out-String
						$returnMsgs += $formattedData
						$this.PublishCustomMessage($formattedData)
					}
				}
				catch {
					$this.PublishCustomMessage("Could not fetch the user permissions for project [$($this.projectName)]. Please validate the project name.", [MessageType]::Error)
					# [EventBase]::PublishGenericException($_);
				}
			}
			$this.PublishCustomMessage([Constants]::DoubleDashLine)
			$returnMsgs += [Constants]::DoubleDashLine;
			if($this.principal_flag) {
				# fetching list of all pat tokens
				$response = $null
				$url = "https://vssps.dev.azure.com/$($this.organizationName)/_apis/tokenadmin/personalaccesstokens/$($userDescriptor)?api-version=6.0-preview.1"
				try {
					$response = [WebRequestHelper]::InvokeGetWebRequest($url);
					$formattedData = @()
					$count = 0
					foreach ($obj in $response) {
						$formattedData += @{
							DisplayName = $obj.displayName;
							Scope = $obj.scope;
							ValidFrom = $obj.validFrom;
							ValidTo = $obj.validTo;
							IsValid = $obj.isValid;
							IsPublic = $obj.isPublic;
						}
						$count += 1;
					}
					$returnMsgs += [MessageData]::new("Total number of PAT Tokens of user [$($this.userMail)]: $($count)")
					$this.PublishCustomMessage("Total number of PAT Tokens of user [$($this.userMail)]: $($count)")
					$formattedData = $formattedData | select-object @{Name="Display Name"; Expression={$_.DisplayName}}, @{Name="Scope"; Expression={$_.Scope}} | Out-String
					$returnMsgs += $formattedData
					$this.PublishCustomMessage($formattedData)
				}
				catch {
					$this.PublishCustomMessage("Could not fetch the PAT tokens for the user [$($this.userMail)].", [MessageType]::Error)
					# [EventBase]::PublishGenericException($_);
				}
				$this.PublishCustomMessage([Constants]::DoubleDashLine)
				$returnMsgs += [Constants]::DoubleDashLine;
				# fetching list of all authorized oauth apps
				$url = "https://dev.azure.com/SafetiTestVSO/_usersSettings/authorizations?__rt=fps&__ver=2"
				try {
					$response = [WebRequestHelper]::InvokeGetWebRequest($url);
					if ([Helpers]::CheckMember($response, "fps") -and [Helpers]::CheckMember($response.fps, "dataProviders") -and [Helpers]::CheckMember($response.fps.dataProviders, "data") -and $response.fps.dataProviders.data."ms.vss-admin-web.authorizations-view-data-provider" -and [Helpers]::CheckMember($response.fps.dataProviders.data."ms.vss-admin-web.authorizations-view-data-provider", "authorizations")) {
						$authorizations = $response.fps.dataProviders.data."ms.vss-admin-web.authorizations-view-data-provider".authorizations;
						$formattedData = @()
						$count = 0
						foreach ($obj in $authorizations) {
							$formattedData += @{
								RegistrationName = $obj.authorization.clientRegistration.registrationName;
								RegistrationLocation = $obj.authorization.clientRegistration.registrationLocation;
								OrganizationName = $obj.authorization.clientRegistration.organizationName;
								Scopes = $obj.authorization.clientRegistration.scopes;
								IsValid = $obj.authorization.clientRegistration.isValid;
							}
							$count += 1;
						}
						$returnMsgs += [MessageData]::new("Total number of authorized oauth apps of user [$($this.userMail)]: $($count)")
						$this.PublishCustomMessage("Total number of authorized oauth apps of user [$($this.userMail)]: $($count)")
						$formattedData = $formattedData | select-object @{Name="Registration Name"; Expression={$_.RegistrationName}}, @{Name="Registration Location"; Expression={$_.RegistrationLocation}}, @{Name="Organization Name"; Expression={$_.OrganizationName}}, @{Name="Scopes"; Expression={$_.Scopes}} | Out-String
						$returnMsgs += $formattedData
						$this.PublishCustomMessage($formattedData)
					}
					else {
						$this.PublishCustomMessage("Could not fetch the list of authorized oauth apps for the user [$($this.userMail)].", [MessageType]::Error)
					}
				}
				catch {
					$this.PublishCustomMessage("Could not fetch the list of authorized oauth apps for the user [$($this.userMail)].", [MessageType]::Error)
					# [EventBase]::PublishGenericException($_);
				}
			}
		}
		$this.PublishCustomMessage([Constants]::DoubleDashLine)
		$returnMsgs += [Constants]::DoubleDashLine;
		return $returnMsgs
	}
}