using namespace System.Management.Automation
Set-StrictMode -Version Latest 

class UserInfo: CommandBase {
    
    hidden [string] $organizationName;
	hidden [string] $userMail;
	hidden [string] $projectName;

	UserInfo([string] $organizationName, [string] $userMail, [string] $ProjectName, [InvocationInfo] $invocationContext):
	Base($organizationName, $invocationContext) {
        $this.organizationName = $organizationName;
		$this.userMail = $userMail;
		$this.projectName = $ProjectName;
	}

	[PSObject] GetUserList() {
		# fetching the users list to get the user descriptor mapped against user email id
		$url = "https://vssps.dev.azure.com/$($this.organizationName)/_apis/graph/users?api-version=6.0-preview.1"
		[PSObject] $users = $null;
		try {
			$response = [WebRequestHelper]::InvokeGetWebRequest($url);
			if($response.count -gt 0) {
				$users = $response;
				[EventBase]::PublishGenericCustomMessage("Successfully fetched users list.");
			}
			else {
				$users = $null;
				[EventBase]::PublishGenericCustomMessage("Problem fetching users list.");
			}
		}
		catch {
            [EventBase]::PublishGenericException($_);
		}
		return $users;
	} 
	
	[MessageData[]] GetPermissionDetails() {
		[MessageData[]] $returnMsgs = @();
		# getting the user descriptor
		$users = $this.GetUserList()
		# extracting selected users descriptor
		$userDescriptor = ""
		foreach ($user in $users) {
			if([Helpers]::CheckMember($user, "mailAddress") -and $user.mailAddress -eq $this.userMail -and [Helpers]::CheckMember($user, "descriptor")) {
				$userDescriptor = $user.descriptor;
			}
		}
		if($userDescriptor -eq "") {
			[EventBase]::PublishGenericCustomMessage("Problem fetching user's descriptor.");
		}
		else {
			# fetching membership details
			$url = "https://vssps.dev.azure.com/$($this.organizationName)/_apis/Graph/Memberships/$($userDescriptor)"
			try {
				$response = [WebRequestHelper]::InvokeGetWebRequest($url);
				$returnMsgs += [MessageData]::new("User is a member of:")
				$this.PublishCustomMessage("User is a Member of:")
				$formattedData = @()
				foreach ($obj in $response) {
					$url = "https://vssps.dev.azure.com/$($this.organizationName)/_apis/graph/groups/$($obj.containerDescriptor)?api-version=6.0-preview.1";
					$res = [WebRequestHelper]::InvokeGetWebRequest($url);
					$data = $res.principalName.Split("\");
					$formattedData += @{
						Group = $data[1];
						Scope = $data[0];
					}
				}
				$formattedData = $formattedData | select-object @{Name="Group Name"; Expression={$_.Group}}, @{Name="User or scope"; Expression={$_.Scope}} | Out-String
				$returnMsgs += $formattedData
				$this.PublishCustomMessage($formattedData)
			}
			catch {
				[EventBase]::PublishGenericException($_);
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
					$this.PublishCustomMessage("User permissions (organization level):")
					if ([Helpers]::CheckMember($response, "dataProviders") -and $response.dataProviders.'ms.vss-admin-web.org-admin-groups-permissions-pivot-data-provider' -and [Helpers]::CheckMember($response.dataProviders.'ms.vss-admin-web.org-admin-groups-permissions-pivot-data-provider', "subjectPermissions")) {
						$permissions = $response.dataProviders.'ms.vss-admin-web.org-admin-groups-permissions-pivot-data-provider'.subjectPermissions
						$formattedData = $permissions | select-object @{Name="DisplayName"; Expression = {$_.displayName}}, @{Name="Permissions"; Expression = {$_.permissionDisplayString}} | Out-String
						$returnMsgs += $formattedData
						$this.PublishCustomMessage($formattedData)
					}
				}
				catch {
					[EventBase]::PublishGenericException($_);
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
					$this.PublishCustomMessage("User permissions for project [$($this.projectName)]:")
					if ([Helpers]::CheckMember($response, "dataProviders") -and $response.dataProviders.'ms.vss-admin-web.org-admin-groups-permissions-pivot-data-provider' -and [Helpers]::CheckMember($response.dataProviders.'ms.vss-admin-web.org-admin-groups-permissions-pivot-data-provider', "subjectPermissions")) {
						$permissions = $response.dataProviders.'ms.vss-admin-web.org-admin-groups-permissions-pivot-data-provider'.subjectPermissions
						$formattedData = $permissions | select-object @{Name="DisplayName"; Expression = {$_.displayName}}, @{Name="Permissions"; Expression = {$_.permissionDisplayString}} | Out-String
						$returnMsgs += $formattedData
						$this.PublishCustomMessage($formattedData)
					}
				}
				catch {
					[EventBase]::PublishGenericException($_);
				}
			}
		}
		$this.PublishCustomMessage([Constants]::DoubleDashLine)
		$returnMsgs += [Constants]::DoubleDashLine;
		return $returnMsgs
	}
}