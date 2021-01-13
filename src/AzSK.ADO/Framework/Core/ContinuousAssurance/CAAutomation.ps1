Set-StrictMode -Version Latest 
class CAAutomation : ADOSVTCommandBase
{ 
	hidden [string] $SubscriptionId
    hidden [string] $Location
    hidden [string] $OrganizationToScan
    hidden [System.Security.SecureString] $PATToken
    hidden [string] $PATTokenURL
    hidden [string] $IdentityId
    hidden [string] $TimeStamp #Use for new CA creation only.
    hidden [string] $StorageName
    hidden [string] $AppServicePlanName = "ADOScannerFAPlan"
	hidden [string] $FuncAppDefaultName = "ADOScannerFA"
    hidden [string] $KVDefaultName = "ADOScannerKV"
    hidden [string] $FuncAppName
    hidden [string] $AppInsightsName
    hidden [string] $KeyVaultName
    hidden [string] $ImageName
    hidden [datetime] $ScanTriggerTimeUTC
    hidden [datetime] $ScanTriggerLocalTime
    hidden [string] $SecretName = "PATForADOScan"
    hidden [string] $LASecretName = "LAKeyForADOScan"
    hidden [string] $AltLASecretName = "AltLAKeyForADOScan"
    hidden [string] $IdentitySecretName = "IdentityIdForADOScan"
    hidden [string] $StorageKind = "StorageV2"
    hidden [string] $StorageType = "Standard_LRS"
    hidden [string] $LAWSName = "ADOScannerLAWS"
    hidden [bool] $CreateLAWS 
    hidden [string] $ProjectNames 
    hidden [string] $ExtendedCommand 
    hidden [string] $CRONExp 
    hidden [bool] $ClearExtCmd 
    hidden [bool] $updateAppSettings = $false
    hidden [bool] $updateSecret = $false
    hidden [string] $CAScanLogsContainerName = [Constants]::CAScanLogsContainerName
    hidden [string] $WebhookUrl
    hidden [string] $WebhookAuthZHeaderName
    hidden [string] $WebhookAuthZHeaderValue
    hidden [bool] $AllowSelfSignedWebhookCertificate
	
	#UCA params for dev-test support
	hidden [string] $RsrcTimeStamp = $null  #We will apply UCA to function app with this timestamp, e.g., "200830092449"
	hidden [string] $NewImageName = $null	#Container image will be changed to this one. 
	hidden [string] $ModuleEnv = "Prod"		#Tell CA to use 'Staging' or 'Prod' or 'Preview' module
	hidden [bool] $UseDevTestImage = $false	#Tell CA to use dev-test (Staging) image packaged inside module
	hidden [int] $TriggerNextScanInMin = 0	#Scan trigger time will be updated to "Now + N" min

    hidden [string] $LAWSsku = "Standard"
	hidden [string[]] $CreatedResources = @();
	hidden [string[]] $updatedAppSettings = @();
	hidden [string] $RGName
    hidden [string] $LAWSId
	hidden [string] $LAWSSharedKey
	hidden [string] $AltLAWSId
	hidden [string] $AltLAWSSharedKey
	hidden [bool] $SetupComplete
	hidden [string] $messages
	hidden [string] $ScheduleMessage
	[PSObject] $ControlSettings;
	
	CAAutomation(
		[string] $SubId, `
		[string] $Loc, `
		[string] $OrgName, `
		[System.Security.SecureString] $PATToken, `
		[string] $PATTokenURL, `
		[string] $ResourceGroupName, `
		[string] $LAWorkspaceId, `
		[string] $LAWorkspaceKey, `
		[string] $Proj, `
		[string] $IdentityResourceId, `
		[string] $ExtCmd, `
		[int] $ScanIntervalInHours,
		[InvocationInfo] $invocationContext, `
		[bool] $CreateLAWS) : Base($OrgName, $invocationContext)
    {
		$this.SubscriptionId = $SubId
		$this.OrganizationToScan = $OrgName
		$this.PATToken = $PATToken
		$this.PATTokenURL = $PATTokenURL
		$this.IdentityId = $IdentityResourceId
		$this.ProjectNames = $Proj
		$this.ExtendedCommand = $ExtCmd
		$this.TimeStamp = (Get-Date -format "yyMMddHHmmss")
		$this.StorageName = "adoscannersa"+$this.TimeStamp 
		$this.FuncAppName = $this.FuncAppDefaultName + $this.TimeStamp 
		$this.KeyVaultName = $this.KVDefaultName+$this.TimeStamp 
		$this.AppInsightsName = $this.FuncAppName
        $this.SetupComplete = $false
        $this.ScanTriggerTimeUTC = [System.DateTime]::UtcNow.AddMinutes(20)
		$this.ScanTriggerLocalTime = $(Get-Date).AddMinutes(20)
		$this.ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
		$this.CreateLAWS = $CreateLAWS

		if ($null -ne $ScanIntervalInHours -and $ScanIntervalInHours -gt 0)
		{
			$this.GetCRONForScanInterval($ScanIntervalInHours);
		}
		else
		{
			$this.CRONExp = "0 $($this.ScanTriggerTimeUTC.Minute) $($this.ScanTriggerTimeUTC.Hour) * * *";
			$this.ScheduleMessage = "Scan will begin at $($this.ScanTriggerLocalTime)"
		}

		if (($null -ne $this.ControlSettings) -and [Helpers]::CheckMember($this.ControlSettings, "DockerImage.ImageName")) 
		{
			$this.ImageName = $this.ControlSettings.DockerImage.ImageName
		}

		if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) 
		{
			$this.RGName = [Constants]::AzSKADORGName
		}
		else{
			$this.RGName = $ResourceGroupName
		}
		
		if ([string]::IsNullOrWhiteSpace($Loc)) 
		{
			$this.Location =[Constants]::AzSKADORGLocation
		}
		else
		{
			$this.Location = $Loc
		}
	
		if ([string]::IsNullOrWhiteSpace($LAWorkspaceId) -or [string]::IsNullOrWhiteSpace($LAWorkspaceKey) ) 
		{
			if ($this.CreateLAWS -ne $true)
			{
				$this.messages = "Log Analytics Workspace details are missing. Use -CreateWorkspace switch to create a new workspace while setting up CA. Setup will continue...`r`n"
			}
			else{
				$this.LAWSName += $this.TimeStamp
			}
		}
		else
		{
			$this.LAWSId = $LAWorkspaceId
			$this.LAWSSharedKey = $LAWorkspaceKey
        }

		$ModuleName = $invocationContext.MyCommand.Module.Name 
		if(-not [string]::IsNullOrWhiteSpace($ModuleName))
		{
			switch($ModuleName.ToLower())
			{
				"azskpreview.ado" {
					$this.ModuleEnv = "preview";
					break;
				} 
				"azskstaging.ado" {
					$this.ModuleEnv = "staging"
					break;
				}
			}
		}
	}

	CAAutomation(
		[string] $SubId, `
		[string] $OrgName, `
		[System.Security.SecureString] $PATToken, `
		[string] $PATTokenURL, `
		[string] $ResourceGroupName, `
		[string] $LAWorkspaceId, `
		[string] $LAWorkspaceKey, `
		[string] $AltLAWorkspaceId, `
		[string] $AltLAWorkspaceKey, `
		[string] $Proj, `
		[string] $ExtCmd, `
		[string] $WebhookUrl, `
		[string] $WebhookHeaderName, `
		[string] $WebhookHeaderValue, `
		[bool] $AllowSelfSignedWebhookCert,
		[string] $RsrcTimeStamp, `
		[string] $ContainerImageName, `
		[string] $ModuleEnv, `
		[bool] $UseDevTestImage, `
		[int] $TriggerNextScanInMin, `
		[int] $ScanIntervalInHours, `
		[bool] $ClearExtendedCommand, `
		[InvocationInfo] $invocationContext) : Base($OrgName, $invocationContext)
		{
			$this.SubscriptionId = $SubId
			$this.OrganizationToScan = $OrgName
			$this.PATToken = $PATToken
			$this.PATTokenURL = $PATTokenURL
			$this.ProjectNames = $Proj
			$this.ExtendedCommand = $ExtCmd
			$this.SetupComplete = $false
			$this.LAWSId = $LAWorkspaceId
			$this.LAWSSharedKey = $LAWorkspaceKey
			$this.AltLAWSId = $AltLAWorkspaceId
			$this.AltLAWSSharedKey = $AltLAWorkspaceKey
			$this.ClearExtCmd = $ClearExtendedCommand
			$this.WebhookUrl = $WebhookUrl
			$this.WebhookAuthZHeaderName = $WebhookHeaderName
			$this.WebhookAuthZHeaderValue = $WebhookHeaderValue
			$this.AllowSelfSignedWebhookCertificate = $AllowSelfSignedWebhookCert

			#Some stuff for dev-test support
			$this.NewImageName = $ContainerImageName
			$this.RsrcTimeStamp = $RsrcTimeStamp   
			$this.ModuleEnv	= $ModuleEnv 
			$this.UseDevTestImage = $UseDevTestImage 
			$this.TriggerNextScanInMin = $TriggerNextScanInMin

			<#
			$this.ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");

			if (($null -ne $this.ControlSettings) -and [Helpers]::CheckMember($this.ControlSettings, "DockerImage.ImageName")) 
			{
				$this.ImageName = $this.ControlSettings.DockerImage.ImageName
			}
			#>

			if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) 
			{
				$this.RGName = [Constants]::AzSKADORGName
			}
			else{
				$this.RGName = $ResourceGroupName
			}

			if ($null -ne $ScanIntervalInHours -and $ScanIntervalInHours -gt 0)
			{
				$this.ScanTriggerLocalTime = $(Get-Date).AddMinutes(20)
				$this.ScanTriggerTimeUTC = [System.DateTime]::UtcNow.AddMinutes(20)
				$this.GetCRONForScanInterval($ScanIntervalInHours);
			}

			#Validate if app settings update is required based on input paramaeters. 
			$invocationContext.BoundParameters.GetEnumerator() | foreach-object {
				# If input param is other than below 3 then app settings update will be required
				if($_.Key -ne "SubscriptionId" -and $_.Key -ne "ResourceGroupName" -and $_.Key -ne "PATToken" )
				{
					$this.updateAppSettings = $true
				}
				if($_.Key -eq "PATToken" -or $_.Key -eq "AltLAWSSharedKey" -or $_.Key -eq "LAWSSharedKey")
				{
					$this.updateSecret = $true
				}
			}
		}

		CAAutomation(
		[string] $SubId, `
		[string] $OrgName, `
		[string] $ResourceGroupName, `
		[string] $RsrcTimeStamp, `
		[InvocationInfo] $invocationContext) : Base($OrgName, $invocationContext)
		{
			$this.SubscriptionId = $SubId
			$this.OrganizationToScan = $OrgName

			if ([string]::IsNullOrWhiteSpace($ResourceGroupName)) 
			{
				$this.RGName = [Constants]::AzSKADORGName
			}
			else{
				$this.RGName = $ResourceGroupName
			}

			if ([string]::IsNullOrWhiteSpace($RsrcTimeStamp)) 
			{
				$this.FuncAppName = $this.FuncAppDefaultName
			}
			else{
				$this.FuncAppName = $this.FuncAppDefaultName + $RsrcTimeStamp
			}

			$this.ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
			if (($null -ne $this.ControlSettings) -and [Helpers]::CheckMember($this.ControlSettings, "DockerImage.ImageName")) 
			{
				$this.ImageName = $this.ControlSettings.DockerImage.ImageName
			}
		}
    
    [void] RegisterResourceProvider()
    {
        if (($null -ne $this.ControlSettings) -and [Helpers]::CheckMember($this.ControlSettings, "ResourceProviders")) 
        {
            $resourceProvider = $this.ControlSettings.ResourceProviders
            $resourceProvider | foreach {
                [ResourceHelper]::RegisterResourceProviderIfNotRegistered($_);
            }
        }
    }

    [void] GetCRONForScanInterval($ScanIntervalInHours)
    {
        $minute = $this.ScanTriggerTimeUTC.Minute
        $hour = $this.ScanTriggerTimeUTC.Hour
        $list = New-Object Collections.Generic.List[Int]

        #between first scan time and 00:00 hrs get "hours" when scan should trigger based on scan interval
        while ($hour -lt 24)
        {
            $list.Add($hour)
            $hour += $ScanIntervalInHours
        }

        #between 00:00 hrs and first scan time get "hours" when scan should trigger based on scan interval
        $hour = $this.ScanTriggerTimeUTC.Hour
        while ($hour -ge 0)
        {
            $list.Add($hour)
            $hour -= $ScanIntervalInHours
        }

        $list =$list | sort-object -Unique
        $hoursExpression = $list -join ","
        $this.CRONExp = "0 $($minute) $($hoursExpression) * * *"
        $this.ScheduleMessage = "Scan will trigger every $($ScanIntervalInHours) hours starting from $($this.ScanTriggerLocalTime)"
    }

	[string] ValidateUserPermissions()
	{
		$output ='';
		try
		{
			#Step 1: Get context. Connect to account if required
			$Context = @(Get-AzContext -ErrorAction SilentlyContinue )
			if ($Context.count -eq 0)  {
				$this.PublishCustomMessage("No active Azure login session found. Initiating login flow...", [MessageType]::Info);
				Connect-AzAccount -ErrorAction Stop
				$Context = @(Get-AzContext -ErrorAction SilentlyContinue)
			}

			#Step 2 : Check if Owner or Contributor role is available at subscription scope.
			if ($null -eq $Context)  {
				$output = "No Azure login found. Azure login context is required to setup Continuous Assurance."
			}
			else
			{
				if($Context.Subscription.SubscriptionId -ne $this.SubscriptionId)
				{
					$Context = set-azcontext -Subscription $this.SubscriptionId -Force  
				}
				$RoleAssignment = @()
				$Scope = "/subscriptions/"+$this.SubscriptionId
				$RoleAssignmentSub = @(Get-AzRoleAssignment -Scope $Scope -SignInName $Context.Account.Id -IncludeClassicAdministrators -ErrorAction SilentlyContinue)
				if ($RoleAssignmentSub.Count -gt 0)
				{
					$RoleAssignment = @($RoleAssignmentSub | Where-Object {$_.RoleDefinitionName -eq "Owner" -or $_.RoleDefinitionName -eq "CoAdministrator" -or $_.RoleDefinitionName -match "ServiceAdministrator"} )
				}
				# If Sub level permissions are not adequate then check RG level permissions
				if ($RoleAssignment.Count -gt 0)
				{
					$output = 'OK'
				}
				else
				{
					#Step 3: Check if user has Owner permissions on provided RG name or ADOScannerRG
					$Scope = $Scope +"/resourceGroups/"+ $this.RGName
					$RoleAssignmentRG = @(Get-AzRoleAssignment -Scope $Scope -SignInName $Context.Account.Id -ErrorAction SilentlyContinue)
					$RoleAssignment = @($RoleAssignmentRG | Where-Object {$_.RoleDefinitionName -eq "Owner"} )

					if ($RoleAssignment.Count -eq 0)
					{
						$this.PublishCustomMessage("Please make sure you have Owner role on target subscription or resource group. If your permissions were elevated recently, please run the 'Disconnect-AzAccount' command to clear the Azure cache and try again.", [MessageType]::Info);
					}
					else {
						$output = 'OK'
					}
				}
            }
            #Resolve projectNames if * is used in command
            if ($this.ProjectNames -eq "*")
            {
                $apiURL = 'https://dev.azure.com/{0}/_apis/projects?$top=1000&api-version=5.1' -f $($this.SubscriptionContext.SubscriptionName);
                $responseObj = "";
                try { 
                    $responseObj = [WebRequestHelper]::InvokeGetWebRequest($apiURL);
                    if (-not [string]::IsNullOrEmpty($responseObj) -and ($responseObj | Measure-Object).Count -gt 0)
                    {
                        $this.Projectnames  = $ResponseObj.Name -join ","
                    }
                }
                catch {
                    $this.PublishCustomMessage("Project not found: Incorrect project name or you do not have neccessary permission to access the project.", [MessageType]::Error);
                    throw;
                }
            }
		}
		catch{
			$output += $_;
			$this.messages += $Error
		}
		return $output
	}

    #Create common resources applicable for both type of CA setups
    [void] CreateResources()
    {
        try
        {
            if([string]::IsNullOrWhiteSpace($this.ImageName))
            {
                $messageData += [MessageData]::new("If you are using customized org policy, please ensure DockerImageName is defined in your ControlSettings.json")
                $this.PublishCustomMessage($messageData.Message, [MessageType]::Error);
            }
            #Step 1: If RG does not exist then create new
            if((Get-AzResourceGroup -Name $this.RGname -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0)
            {
                $RG = @(New-AzResourceGroup -Name $this.RGname -Location $this.Location)
                if($RG.Count -eq 0) 
                {
                    $this.PublishCustomMessage("New resource group '$($this.RGname)' creation failed", [MessageType]::Error);
                }
                else
                {
                    $this.PublishCustomMessage("New resource group '$($this.RGname)' created", [MessageType]::Update);
                }
            }
            else
            {
                $this.PublishCustomMessage("Resource group [$($this.RGname)] already exists. Skipping RG creation.", [MessageType]::Update);
            }

            $this.PublishCustomMessage("Creating required resources in resource group [$($this.RGname)]....", [MessageType]::Info);

            #Step 2: Create app service plan "Elastic Premium"
            if ((($AppServPlan =Get-AzResource -ResourceGroupName $this.RGName -ResourceType 'Microsoft.web/serverfarms' -Name $this.AppServicePlanName) | Measure-Object).Count -eq 0)
            {
                $AppServPlan = New-AzResource -ResourceName $this.AppServicePlanName -ResourceGroupName $this.RGname -ResourceType Microsoft.web/serverfarms -ApiVersion "2018-02-01" -Location $this.Location -Kind Elastic -Properties @{"reserved"=$true;} -Sku @{name= "EP1";tier = "ElasticPremium";size= "EP1";family="EP";capacity= 1} -Force
                if($null -eq $AppServPlan) 
                {
                    $this.PublishCustomMessage("AppService plan [$($this.AppServicePlanName)] creation failed", [MessageType]::Error);
                }
                else
                {
                    $this.PublishCustomMessage("AppService plan [$($this.AppServicePlanName)] created", [MessageType]::Update);
                    $this.CreatedResources += $AppServPlan.ResourceId
                }
            }
            else 
            {
                $this.PublishCustomMessage("AppService Plan: [$($this.AppServicePlanName)] already exists. Skipping creation.", [MessageType]::Update);
            }

            #Step 3: Create storage account
            $StorageAcc = New-AzStorageAccount -ResourceGroupName $this.RGname -Name $this.StorageName -Type $this.StorageType -Location $this.Location -Kind $this.StorageKind -EnableHttpsTrafficOnly $true -ErrorAction Stop
            if($null -eq $StorageAcc) 
            {
                $this.PublishCustomMessage("Storage account [$($this.StorageName)] creation failed", [MessageType]::Error);
            }
            else
            {
                $this.PublishCustomMessage("Storage [$($this.StorageName)] created", [MessageType]::Update);
                $this.CreatedResources += $StorageAcc.Id

            }

            #Step 4: Create LAW if applicable
            if ($this.CreateLAWS -eq $true)
            {
                $LAWorkspace = @(New-AzOperationalInsightsWorkspace -Location $this.Location -Name $this.LAWSName -Sku $this.LAWSsku -ResourceGroupName $this.RGname)
                if($LAWorkspace -eq 0) 
                {
                    $this.PublishCustomMessage("Log Analytics Workspace [$($this.LAWSName)] creation failed", [MessageType]::Error);
                }
                else
                {
                    $this.LAWSId = $LAWorkspace.CustomerId.Guid.ToString()
                    $SharedKeys = Get-AzOperationalInsightsWorkspaceSharedKey -Name $this.LAWSName -ResourceGroupName $this.RGname -WarningAction silentlycontinue
                    $this.LAWSSharedKey = $SharedKeys.PrimarySharedKey
                    $this.PublishCustomMessage("Log Analytics Workspace [$($this.LAWSName)] created", [MessageType]::Update);
                    $this.CreatedResources += $LAWorkspace.ResourceId
                }
            }

            #Step 5: Create keyvault
            $KeyVault = New-AzKeyVault -Name $this.KeyVaultName -ResourceGroupName $this.RGname -Location $this.Location
            if($null -eq $KeyVault) 
            {
                $this.PublishCustomMessage("Azure key vault [$($this.KeyVaultName)] creation failed", [MessageType]::Error);
            }
            else
            {
                $this.PublishCustomMessage("Azure key vault [$($this.KeyVaultName)] created", [MessageType]::Update);
                $this.CreatedResources += $KeyVault.resourceid
            }
        }
        catch {
            $this.PublishCustomMessage("Error occured while creating resources", [MessageType]::Error);
            throw;
        }
    }
    
    # ICA to setup using PATToken, by storing it in created KV and access it using system assigned identity of function app
	[MessageData[]] InstallAzSKADOContinuousAssurance()
	{
		[MessageData[]] $messageData = @();
		$this.messages += ([Constants]::DoubleDashLine + "`r`nStarted setting up Continuous Assurance (CA)`r`n"+[Constants]::DoubleDashLine);
		$this.PublishCustomMessage($this.messages, [MessageType]::Info);
		try
		{
			$output = $this.ValidateUserPermissions();
			if($output -ne 'OK') # if there is some while validating permissions output will contain exception
			{
				$this.PublishCustomMessage("Error validating permissions on the subscription", [MessageType]::Error);
				$messageData += [MessageData]::new($output)
			}
			else 
			{
        $this.RegisterResourceProvider();
        $this.CreateResources(); #Step 1,2,3,4,5
        
        #Step 6: Create Function app
				$FuncApp = New-AzFunctionApp -DockerImageName $this.ImageName -SubscriptionId $this.SubscriptionId -Name $this.FuncAppName -ResourceGroupName $this.RGname -StorageAccountName $this.StorageName -IdentityType SystemAssigned -PlanName $this.AppServicePlanName
				if($null -eq $FuncApp) 
				{
					$this.PublishCustomMessage("Function app [$($this.FuncAppName)] creation failed", [MessageType]::Error);
				}
				else
				{
					$this.PublishCustomMessage("Function app [$($this.FuncAppName)] created", [MessageType]::Update);
					$this.CreatedResources += $FuncApp.Id
				}
				
				#Step 7: Validate if AI got created
				$AppInsight = Get-AzResource -Name $this.AppInsightsName -ResourceType Microsoft.Insights/components
				if($null -eq $AppInsight) 
				{
					$this.PublishCustomMessage("Application Insights [$($this.AppInsightsName)] creation failed", [MessageType]::Error);
				}
				else
				{
					$this.PublishCustomMessage("Application Insights [$($this.AppInsightsName)] created", [MessageType]::Update);
					$this.CreatedResources += $AppInsight.ResourceId
				}
		
				#Step 8a: Add PAT token secret to key vault
				$CreatedSecret = Set-AzKeyVaultSecret -VaultName $this.KeyVaultName -Name $this.SecretName -SecretValue $this.PATToken
				if($null -eq $CreatedSecret) 
				{
					$this.PublishCustomMessage("PAT Secret creation in Azure key vault failed", [MessageType]::Error);
				}
				else
				{
					$this.PublishCustomMessage("PAT Secret created in Azure key vault", [MessageType]::Update);
				}

				#Step 8b: Add LA Shared Key secret to key vault
				$CreatedLASecret = $null
				if (-not [string]::IsNullOrEmpty($this.LAWSSharedKey))
				{
					$secureStringKey = ConvertTo-SecureString $this.LAWSSharedKey -AsPlainText -Force
					$CreatedLASecret = Set-AzKeyVaultSecret -VaultName $this.KeyVaultName -Name $this.LASecretName -SecretValue $secureStringKey 
					if($null -eq $CreatedLASecret) 
					{
						$this.PublishCustomMessage("LA shared key secret creation in Azure key vault failed", [MessageType]::Error);
					}
					else
					{
						$this.PublishCustomMessage("LA shared key secret created in Azure key vault", [MessageType]::Update);
					}
				}

				#Step 9: Get Identity details of function app to provide access on keyvault and storage
				$FuncApp = Get-AzWebApp -Name $this.FuncAppName -ResourceGroupName $this.RGname		
				$FuncAppIdentity= $FuncApp.Identity.PrincipalId 						
				$MSIAccessToKV = Set-AzKeyVaultAccessPolicy -VaultName $this.KeyVaultName -ResourceGroupName $this.RGname -PermissionsToSecrets get,list -PassThru -ObjectId $FuncAppIdentity
				$IsMSIAccess = $MSIAccessToKV.AccessPolicies | ForEach-Object { if ($_.ObjectId -match $FuncAppIdentity ) {return $true }}
				if($IsMSIAccess -eq $true) 
				{
					$this.PublishCustomMessage("MSI access to Azure key vault provided", [MessageType]::Update);
				}
				else
				{
					$this.PublishCustomMessage("MSI access to Azure key vault failed", [MessageType]::Error);
				}
		
				$MSIAccessToSA = New-AzRoleAssignment -ObjectId $FuncAppIdentity  -RoleDefinitionName "Contributor" -ResourceName $this.StorageName -ResourceGroupName $this.RGname -ResourceType Microsoft.Storage/storageAccounts
				if($null -eq $MSIAccessToSA) 
				{
					$this.PublishCustomMessage("MSI access to storage failed", [MessageType]::Error);
				}
				else
				{
					$this.PublishCustomMessage("MSI access to storage provided", [MessageType]::Update);
				}
		
				#Step 10: Configure required env variables in function app for scan
				$uri = $CreatedSecret.Id
				$uri = $uri.Substring(0,$uri.LastIndexOf('/'))

				$sharedKeyUri = ""
				if (-not [string]::IsNullOrEmpty($CreatedLASecret))
				{
					$sharedKeyUri = $CreatedLASecret.Id
					$sharedKeyUri = $sharedKeyUri.Substring(0,$sharedKeyUri.LastIndexOf('/'))
					$sharedKeyUri = "@Microsoft.KeyVault(SecretUri=$sharedKeyUri)"
				}
				
				#Turn on "Always ON" for function app and also fetch existing app settings and append the required ones. This has to be done as appsettings get overwritten
				$WebApp = Get-AzWebApp -Name $this.FuncAppName -ResourceGroupName $this.RGname #-AlwaysOn $true
				$ExistingAppSettings = $WebApp.SiteConfig.AppSettings 
		
				#convert existing app settings from list to hashtable
				$AppSettingsHT = @{}
				foreach ($Setting in $ExistingAppSettings) 
				{
					$AppSettingsHT["$($Setting.Name)"] = "$($Setting.value)"
				}
		
				$NewAppSettings = @{
								"ScheduleTriggerTime" = $this.CRONExp;
								"SubscriptionId" = $this.SubscriptionId;
								"LAWSId" = $this.LAWSId;
								"LAWSSharedKey" = $sharedKeyUri;
								"OrgName" = $this.OrganizationToScan;
								"PATToken" = "@Microsoft.KeyVault(SecretUri=$uri)";
								"StorageRG" = $this.RGname;
								"ProjectNames" = $this.ProjectNames;
								"ExtendedCommand" = $this.ExtendedCommand;
								"StorageName" = $this.StorageName;
								"AzSKADOModuleEnv" = $this.ModuleEnv;
								"AzSKADOVersion" = "";
							}
				$AppSettings = $NewAppSettings + $AppSettingsHT 
		
				$updatedWebApp = Update-AzFunctionAppSetting -Name $this.FuncAppName -ResourceGroupName $this.RGname -AppSetting $AppSettings -Force
				if($updatedWebApp.Count -ne $AppSettings.Count) 
				{
					$this.PublishCustomMessage("App settings update failed", [MessageType]::Error);
				}
				else
				{
					$this.PublishCustomMessage("App settings updated", [MessageType]::Update);
				}
		
				$this.PublishCustomMessage("`r`nSetup Complete!", [MessageType]::Update);
				Restart-AzFunctionApp -name $this.FuncAppName -ResourceGroupName $this.RGname -SubscriptionId $this.SubscriptionId -Force
		
				$this.PublishCustomMessage($this.ScheduleMessage, [MessageType]::Update);
				$this.SetupComplete = $true
				$this.DoNotOpenOutputFolder = $true
				$messageData += [MessageData]::new("The following resources were created in resource group [$($this.RGName)] as part of AzSK.ADO Continuous Assurance", ($this.CreatedResources| Out-String))
			}
		}
		catch
		{
			$this.PublishCustomMessage("ADO Scanner CA setup failed!", [MessageType]::Error);
			$this.PublishCustomMessage($_, [MessageType]::Error);
			$messageData += [MessageData]::new($Error)
		}
		finally
		{
			if ($this.SetupComplete -eq $false)
			{
				$this.PublishCustomMessage("CA Setup could not be completed. Deleting created resources...", [MessageType]::Warning);
				if ($this.CreatedResources.Count -ne 0)
				{
					Foreach ($resourceId in $this.CreatedResources)
					{
						Remove-AzResource -ResourceId $resourceId -Force
						$Index = $resourceId.LastIndexOf('/') + 1 ;
						$ResourceName = $resourceId.Substring($Index)

						$this.PublishCustomMessage("Deleted resource: [$($ResourceName)]", [MessageType]::Info);
					}
				}
				else{
					$this.PublishCustomMessage("No resource was created.", [MessageType]::Info);
				}
			}
		}
		return $messageData
	}

    #ICA to setup using PATTokenURL and access it using user assigned identity.Here KV holding PAT is not directly accessible, it will be retrieved at runtime by the identity.
    [MessageData[]] InstallAzSKADOCentralContinuousAssurance()
    {
		[MessageData[]] $messageData = @();
		$this.messages += ([Constants]::DoubleDashLine + "`r`nStarted setting up Continuous Assurance (CA)`r`n"+[Constants]::DoubleDashLine);
		$this.PublishCustomMessage($this.messages, [MessageType]::Info);
		try
		{
			$output = $this.ValidateUserPermissions();
			if($output -ne 'OK') # if there is some while validating permissions output will contain exception
			{
				$this.PublishCustomMessage("Error validating permissions on the subscription", [MessageType]::Error);
				$messageData += [MessageData]::new($output)
			}
			else 
			{		
        $this.RegisterResourceProvider();
				$this.CreateResources(); #Step 1,2,3,4,5       

                #Step 6a: Create Function app
				$FuncApp = New-AzFunctionApp -DockerImageName $this.ImageName -SubscriptionId $this.SubscriptionId -Name $this.FuncAppName -ResourceGroupName $this.RGname -StorageAccountName $this.StorageName -IdentityType UserAssigned -IdentityID $this.IdentityId -PlanName $this.AppServicePlanName
               
				if($null -eq $FuncApp) 
				{
					$this.PublishCustomMessage("Function app [$($this.FuncAppName)] creation failed. Please validate permissions on Identity and try again (Minimum required permission is 'Managed identity operator').", [MessageType]::Error);
				}
				else
				{
					$this.PublishCustomMessage("Function app [$($this.FuncAppName)] created", [MessageType]::Update);
                    $this.CreatedResources += $FuncApp.Id
                    
                    #Step 6b: Enable system assigned identity. As powershell commands do not support enabling both identities together, therefore we are using api call here
                    $url = "https://management.azure.com/subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Web/sites/{2}?api-version=2018-11-01" -f $this.SubscriptionId, $this.RGname, $this.FuncAppName
                    $accessToken = [ContextHelper]::GetAccessToken("https://management.azure.com", "")
                    $header = @{
                        "Authorization" = "Bearer " + $accessToken
                    }
                    $bodyObject = [PSCustomObject]@{
                        'location' = $this.Location
                        'identity' = [PSCustomObject]@{
                            'type' = 'systemassigned,userassigned'
                        }
                    }
                    $bodyJson = @($bodyObject) | ConvertTo-Json
                            
                    try {
                        Invoke-WebRequest -Uri $url -Method Patch -ContentType "application/json"  -Headers $header -Body $bodyJson -UseBasicParsing
                    }
                    catch {
                        $this.PublishCustomMessage("System assigned managed identity creation failed for function app [$($this.FuncAppName)].", [MessageType]::Error);
                        throw;
                    }
				}
				
				#Step 7: Validate if AI got created
				$AppInsight = Get-AzResource -Name $this.AppInsightsName -ResourceType Microsoft.Insights/components
				if($null -eq $AppInsight) 
				{
					$this.PublishCustomMessage("Application Insights [$($this.AppInsightsName)] creation failed", [MessageType]::Error);
				}
				else
				{
					$this.PublishCustomMessage("Application Insights [$($this.AppInsightsName)] created", [MessageType]::Update);
					$this.CreatedResources += $AppInsight.ResourceId
                }
                
				#Step 8: Get Identity details of function app to provide access on keyvault and storage
				$FuncApp = Get-AzWebApp -Name $this.FuncAppName -ResourceGroupName $this.RGname		
                $FuncAppIdentity= $FuncApp.Identity.PrincipalId 
                $UserAssignedIdentityClientId = $FuncApp.Identity.UserAssignedIdentities.Values.Clientid						
				$MSIAccessToKV = Set-AzKeyVaultAccessPolicy -VaultName $this.KeyVaultName -ResourceGroupName $this.RGname -PermissionsToSecrets get,list -PassThru -ObjectId $FuncAppIdentity
				$IsMSIAccess = $MSIAccessToKV.AccessPolicies | ForEach-Object { if ($_.ObjectId -match $FuncAppIdentity ) {return $true }}
				if($IsMSIAccess -eq $true) 
				{
					$this.PublishCustomMessage("MSI access to Azure key vault provided", [MessageType]::Update);
				}
				else
				{
					$this.PublishCustomMessage("MSI access to Azure key vault failed", [MessageType]::Error);
				}
		
				$MSIAccessToSA = New-AzRoleAssignment -ObjectId $FuncAppIdentity  -RoleDefinitionName "Contributor" -ResourceName $this.StorageName -ResourceGroupName $this.RGname -ResourceType Microsoft.Storage/storageAccounts
				if($null -eq $MSIAccessToSA) 
				{
					$this.PublishCustomMessage("MSI access to storage failed", [MessageType]::Error);
				}
				else
				{
					$this.PublishCustomMessage("MSI access to storage provided", [MessageType]::Update);
				}
        
                
                #Step 9a: Add identity Client id to key vault secret
                $clientId = ConvertTo-SecureString $UserAssignedIdentityClientId -AsPlainText -Force
                $CreatedSecret = Set-AzKeyVaultSecret -VaultName $this.KeyVaultName -Name $this.IdentitySecretName -SecretValue $clientId 
                if($null -eq $CreatedSecret) 
                {
                    $this.PublishCustomMessage("Identity secret creation in Azure key vault failed", [MessageType]::Error);
                }
                else
                {
                    $this.PublishCustomMessage("Identity secret created in Azure key vault", [MessageType]::Update);
                }


                #Step 9b: Add LA Shared Key to key vault secret
                $CreatedLASecret = $null
                if (-not [string]::IsNullOrEmpty($this.LAWSSharedKey))
                {
                    $secureStringKey = ConvertTo-SecureString $this.LAWSSharedKey -AsPlainText -Force
                    $CreatedLASecret = Set-AzKeyVaultSecret -VaultName $this.KeyVaultName -Name $this.LASecretName -SecretValue $secureStringKey 
                    if($null -eq $CreatedLASecret) 
                    {
                        $this.PublishCustomMessage("LA shared key secret creation in Azure key vault failed", [MessageType]::Error);
                    }
                    else
                    {
                        $this.PublishCustomMessage("LA shared key secret created in Azure key vault", [MessageType]::Update);
                    }
                }

				#Step 10: Configure required env variables in function app for scan
                $identitySecretUri = $CreatedSecret.Id
                $identitySecretUri = $identitySecretUri.Substring(0,$identitySecretUri.LastIndexOf('/'))
                $identitySecretUri = "@Microsoft.KeyVault(SecretUri=$identitySecretUri)"

				$sharedKeyUri = ""
				if (-not [string]::IsNullOrEmpty($CreatedLASecret))
				{
					$sharedKeyUri = $CreatedLASecret.Id
					$sharedKeyUri = $sharedKeyUri.Substring(0,$sharedKeyUri.LastIndexOf('/'))
					$sharedKeyUri = "@Microsoft.KeyVault(SecretUri=$sharedKeyUri)"
				}

				
				#Turn on "Always ON" for function app and also fetch existing app settings and append the required ones. This has to be done as appsettings get overwritten
				$WebApp = Get-AzWebApp -Name $this.FuncAppName -ResourceGroupName $this.RGname #-AlwaysOn $true
				$ExistingAppSettings = $WebApp.SiteConfig.AppSettings 
		
				#convert existing app settings from list to hashtable
				$AppSettingsHT = @{}
				foreach ($Setting in $ExistingAppSettings) 
				{
					$AppSettingsHT["$($Setting.Name)"] = "$($Setting.value)"
				}
		
				$NewAppSettings = @{
								"ScheduleTriggerTime" = $this.CRONExp;
								"SubscriptionId" = $this.SubscriptionId;
								"LAWSId" = $this.LAWSId;
								"LAWSSharedKey" = $sharedKeyUri;
								"OrgName" = $this.OrganizationToScan;
								"PATTokenUrl" = $this.PATTokenURL;
								"StorageRG" = $this.RGname;
								"ProjectNames" = $this.ProjectNames;
								"ExtendedCommand" = $this.ExtendedCommand;
								"StorageName" = $this.StorageName;
								"AzSKADOModuleEnv" = $this.ModuleEnv;
                                "AzSKADOVersion" = "";
                                "ClientId" = $identitySecretUri;
							}
				$AppSettings = $NewAppSettings + $AppSettingsHT 
		
				$updatedWebApp = Update-AzFunctionAppSetting -Name $this.FuncAppName -ResourceGroupName $this.RGname -AppSetting $AppSettings -Force
				if($updatedWebApp.Count -ne $AppSettings.Count) 
				{
					$this.PublishCustomMessage("App settings update failed", [MessageType]::Error);
				}
				else
				{
					$this.PublishCustomMessage("App settings updated", [MessageType]::Update);
				}
		
                $this.PublishCustomMessage("`r`nSetup Complete!", [MessageType]::Update);
				Restart-AzFunctionApp -name $this.FuncAppName -ResourceGroupName $this.RGname -SubscriptionId $this.SubscriptionId -Force

				$this.PublishCustomMessage($this.ScheduleMessage, [MessageType]::Update);
				$this.SetupComplete = $true
				$this.DoNotOpenOutputFolder = $true
				$messageData += [MessageData]::new("The following resources were created in resource group [$($this.RGName)] as part of AzSK.ADO Continuous Assurance", ($this.CreatedResources| Out-String))
			}
		}
		catch
		{
			$this.PublishCustomMessage("ADO Scanner CA setup failed!", [MessageType]::Error);
			$this.PublishCustomMessage($_, [MessageType]::Error);
			$messageData += [MessageData]::new($Error)
		}
		finally
		{
			if ($this.SetupComplete -eq $false)
			{
				$this.PublishCustomMessage("CA Setup could not be completed. Deleting created resources...", [MessageType]::Warning);
				if ($this.CreatedResources.Count -ne 0)
				{
					Foreach ($resourceId in $this.CreatedResources)
					{
						Remove-AzResource -ResourceId $resourceId -Force
						$Index = $resourceId.LastIndexOf('/') + 1 ;
						$ResourceName = $resourceId.Substring($Index)

						$this.PublishCustomMessage("Deleted resource: [$($ResourceName)]", [MessageType]::Info);
					}
				}
				else{
					$this.PublishCustomMessage("No resource was created.", [MessageType]::Info);
				}
            }
            else
            {
                $this.PublishCustomMessage([Constants]::SingleDashLine);
                $this.PublishCustomMessage([Constants]::CentralCAMsg);
            }
		}
		return $messageData
	}

	
	[MessageData[]] UpdateAzSKADOContinuousAssurance()
    {
		[MessageData[]] $messageData = @();
		$CreatedSecret = $null
		$CreatedLASecret = $null
		$CreatedAltLASecret = $null
		$ExistingAppSettings = @()
		$appServResource = @()

		$this.messages += ([Constants]::DoubleDashLine + "`r`nStarted updating Continuous Assurance (CA)`r`n"+[Constants]::DoubleDashLine);
		$this.PublishCustomMessage($this.messages, [MessageType]::Info);
		try
		{
			#Step 1: Validate permissions of user on subscription
			$output = $this.ValidateUserPermissions();
			if($output -ne 'OK') # if there is some while validating permissions output will contain exception
			{
				$this.PublishCustomMessage("Error validating permissions on the subscription", [MessageType]::Error);
				$messageData += [MessageData]::new($output)
			}
			else 
			{
				#Step 2: Validate if RG exists.
				if (-not [string]::IsNullOrEmpty($this.RGname))
                {
                     $RG = Get-AzResourceGroup -Name $this.RGname -ErrorAction SilentlyContinue
                     if ($null -eq $RG)
                     {
						$messageData += [MessageData]::new("Resource group [$($this.RGname)] not found. Please validate the resource group name." )
						$this.PublishCustomMessage($messageData.Message, [MessageType]::Error);
		                return $messageData
                     }
				}
				
				#Step 3: If only subid and/or RG name params are used then display below message
				if ($this.updateAppSettings -eq $false -and $this.updateSecret -eq $false)
				{
					$this.PublishCustomMessage("Please use additonal parameters to perform update on LAWSId, LAWSSharedKey, OrganizationName, PATToken, PATTokenURL, ProjectNames, ExtendedCommand", [MessageType]::Info);
                }
                
                #Step 3.1: Get function app resource from RG to get existing app settings details 
                $funcAppToUpdate = $this.FuncAppDefaultName + $this.RsrcTimeStamp
                $appServResource = @((Get-AzResource -ResourceGroupName $this.RGname -ResourceType "Microsoft.Web/Sites").Name | where {$_ -match $funcAppToUpdate})
                if($appServResource.Count -eq 0)
                {
                    $this.PublishCustomMessage("ADOScanner function app not found in resource group [$($this.RGname)]. Update failed!", [MessageType]::Error);
                    return $messageData
                }
                elseif ($appServResource.Count -gt 1)
                {
                    $this.PublishCustomMessage("More than one ADOScanner app service found in resource group [$($this.RGname)]. Update failed!)", [MessageType]::Error);
                    $this.PublishCustomMessage("Consider using the '-RsrcTimeStamp' param. (E.g., to update values corresponding to 'ADOScannerFA200915172817' use '-RsrcTimeStamp 200915172817'.)", [MessageType]::Warning);						
                    return $messageData
                }
                else 
                {
                    $WebApp = Get-AzWebApp -Name $appServResource[0] -ResourceGroupName $this.RGname
                    $ExistingAppSettings = $WebApp.SiteConfig.AppSettings 
                    
                    # Check if CA setup is federated or centralized, and are the paramters provided in UCA compatible with it.
                    if (-not [string]::IsNullOrEmpty($this.PATTokenURL) -or -not [string]::IsNullOrEmpty($this.PATToken))
                    {
                        if(($ExistingAppSettings.Name -contains "PATTokenURL" -and [string]::IsNullOrEmpty($this.PATTokenURL)) -or  ($ExistingAppSettings.Name -contains "PATToken" -and [string]::IsNullOrEmpty($this.PATToken)) )
                        {
                            $paramUsed = [string]::Empty
                            if ([string]::IsNullOrEmpty($this.PATTokenURL)) 
                            {
                                $paramUsed = "PATToken"
                            }
                            else { 
                                $paramUsed = "PATTokenURL"
                            }
                            $messageData += [MessageData]::new("CA setup is not compatible with [$paramUsed]. Update failed!" )
                            $this.PublishCustomMessage($messageData.Message, [MessageType]::Error);
                            return $messageData
                        }
                    }
                }

				#Step 4: Update PATToken in KV (if applicable)
				if ($this.updateSecret -eq $true)
				{

					$kvToUpdate = $this.KVDefaultName + $this.RsrcTimeStamp

					#Get key vault resource from RG
					$keyVaultResource = @((Get-AzResource -ResourceGroupName $this.RGname -ResourceType "Microsoft.KeyVault/vaults").Name | where {$_ -match $kvToUpdate})
					if($keyVaultResource.Count -eq 0)
					{
						$this.PublishCustomMessage("ADOScanner key vault not found in resource group [$($this.RGname)]. Update failed!", [MessageType]::Error);
					}
					elseif ($keyVaultResource.Count -gt 1)
					{
						$this.PublishCustomMessage("More than one ADOScanner key vault found in resource group [$($this.RGname)]. Update failed!", [MessageType]::Error);
						$this.PublishCustomMessage("Consider using the '-RsrcTimeStamp' param. (E.g., to update values corresponding to 'ADOScannerFA200915172817' use '-RsrcTimeStamp 200915172817'.)", [MessageType]::Warning);											
					}
					else {
						if (-not [string]::IsNullOrEmpty($this.PATToken))
						{
							$CreatedSecret = Set-AzKeyVaultSecret -VaultName $keyVaultResource[0] -Name $this.SecretName -SecretValue $this.PATToken
							if($null -eq $CreatedSecret) 
							{
								$this.PublishCustomMessage("Unable to update PATToken. Please validate your permissions in access policy of the Azure key vault [$($keyVaultResource[0])]", [MessageType]::Error);
							}
							else
							{
								$this.PublishCustomMessage("PAT secret updated in [$($keyVaultResource[0])] Azure key vault", [MessageType]::Update);
								$this.updateAppSettings -eq $true # So that app settings can also be updated with key vault URI
							}
						}
						if (-not [string]::IsNullOrEmpty($this.LAWSSharedKey))
						{
							$secureStringKey = ConvertTo-SecureString $this.LAWSSharedKey -AsPlainText -Force
							$CreatedLASecret = Set-AzKeyVaultSecret -VaultName $keyVaultResource[0] -Name $this.LASecretName -SecretValue $secureStringKey
							if($null -eq $CreatedLASecret) 
							{
								$this.PublishCustomMessage("Unable to update LA shared key. Please validate your permissions in access policy of the Azure key vault '$($keyVaultResource[0])'", [MessageType]::Error);
							}
							else
							{
								$this.PublishCustomMessage("LA shared key secret updated in [$($keyVaultResource[0])] Azure key vault", [MessageType]::Update);
								$this.updateAppSettings -eq $true
							}
						}
						if (-not [string]::IsNullOrEmpty($this.AltLAWSSharedKey))
						{
							$secureStringAltKey = ConvertTo-SecureString $this.AltLAWSSharedKey -AsPlainText -Force
							$CreatedAltLASecret = Set-AzKeyVaultSecret -VaultName $keyVaultResource[0] -Name $this.AltLASecretName -SecretValue $secureStringAltKey
							if($null -eq $CreatedAltLASecret) 
							{
								$this.PublishCustomMessage("Unable to update alternate LA shared key. Please validate your permissions in access policy of the Azure key vault '$($keyVaultResource[0])'", [MessageType]::Error);
							}
							else
							{
								$this.PublishCustomMessage("Alternate LA shared key secret updated in [$($keyVaultResource[0])] Azure key vault", [MessageType]::Update);
								$this.updateAppSettings -eq $true
							}
						}
					}
				}

				#Step 5: Update Function app settings (if applicable)
				if ($this.updateAppSettings -eq $true)
				{
                    #convert existing app settings from list to hashtable
                    $AppSettingsHT = @{}
                    foreach ($Setting in $ExistingAppSettings) 
                    {
                        $AppSettingsHT["$($Setting.Name)"] = "$($Setting.value)"
                    }

                    if(-not [string]::IsNullOrEmpty($this.OrganizationToScan))
                    {
                        $AppSettingsHT["OrgName"] = $this.OrganizationToScan
                    }
                    if((-not [string]::IsNullOrEmpty($this.PATToken)) -and (-not [string]::IsNullOrEmpty($CreatedSecret)))
                    {
                        $patUri = $CreatedSecret.Id
                        $patUri = $patUri.Substring(0,$patUri.LastIndexOf('/'))
                        $AppSettingsHT["PATToken"] = "@Microsoft.KeyVault(SecretUri=$patUri)";
                    }
                    if(-not [string]::IsNullOrEmpty($this.PATTokenURL))
                    {
                        $AppSettingsHT["PATTokenURL"] = $this.PATTokenURL
                    }
                    if(-not [string]::IsNullOrEmpty($this.LAWSId))
                    {
                        $AppSettingsHT["LAWSId"] = $this.LAWSId
                    }
                    if((-not [string]::IsNullOrEmpty($this.LAWSSharedKey)) -and (-not [string]::IsNullOrEmpty($CreatedLASecret)))
                    {
                        $sharedKeyUri = $CreatedLASecret.Id
                        $sharedKeyUri = $sharedKeyUri.Substring(0,$sharedKeyUri.LastIndexOf('/'))
                        $AppSettingsHT["LAWSSharedKey"] = "@Microsoft.KeyVault(SecretUri=$sharedKeyUri)";
                    }
                    if(-not [string]::IsNullOrEmpty($this.AltLAWSId))
                    {
                        $AppSettingsHT["AltLAWSId"] = $this.AltLAWSId
                    }
                    if((-not [string]::IsNullOrEmpty($this.AltLAWSSharedKey)) -and (-not [string]::IsNullOrEmpty($CreatedAltLASecret)))
                    {
                        $altSharedKeyUri = $CreatedAltLASecret.Id
                        $altSharedKeyUri = $altSharedKeyUri.Substring(0,$altSharedKeyUri.LastIndexOf('/'))
                        $AppSettingsHT["AltLAWSSharedKey"] = "@Microsoft.KeyVault(SecretUri=$altSharedKeyUri)";
                    }
                    if(-not [string]::IsNullOrEmpty( $this.ExtendedCommand ))
                    {
                        $AppSettingsHT["ExtendedCommand"] = $this.ExtendedCommand
                        $this.PublishCustomMessage("Updating ExtendedCommand overrides the default '-ScanAllArtifacts' behavior of CA.`r`nIf you need that, please specify '-saa' switch in your update CA '-ExtendedCommand'", [MessageType]::Info);
                    }
                    if(-not [string]::IsNullOrEmpty( $this.ProjectNames ))
                    {
                        $AppSettingsHT["ProjectNames"] = $this.ProjectNames
                    }
                    if(-not [string]::IsNullOrEmpty( $this.CRONExp ))
                    {
                        $AppSettingsHT["ScheduleTriggerTime"] = $this.CRONExp
                    }
                    if($this.ClearExtCmd -eq $true)
                    {
                        $AppSettingsHT["ExtendedCommand"] = ""
                    }
                    if(-not [string]::IsNullOrEmpty( $this.WebhookUrl ))
                    {
                        $AppSettingsHT["WebhookUrl"] = $this.WebhookUrl
                    }
                    if(-not [string]::IsNullOrEmpty( $this.WebhookAuthZHeaderName ))
                    {
                        $AppSettingsHT["WebhookAuthZHeaderName"] = $this.WebhookAuthZHeaderName
                    }
                    if(-not [string]::IsNullOrEmpty( $this.WebhookAuthZHeaderValue ))
                    {
                        $AppSettingsHT["WebhookAuthZHeaderValue"] = $this.WebhookAuthZHeaderValue
                    }
                    if($this.AllowSelfSignedWebhookCertificate -eq $true)
                    {
                        $AppSettingsHT["AllowSelfSignedWebhookCertificate"] = "True"
                    }

                    #------------- Begin: DEV-TEST support stuff ---------------
                    if(-not [string]::IsNullOrEmpty( $this.NewImageName ))
                    {
                        Set-AzWebApp -Name $appServResource[0] -ResourceGroupName $this.RGname -ContainerImageName $this.NewImageName
                    }
                    if(-not [string]::IsNullOrEmpty( $this.ModuleEnv ))
                    {
                        $AppSettingsHT["AzSKADOModuleEnv"] = $this.ModuleEnv
                    }
                    if(-not [string]::IsNullOrEmpty( $this.UseDevTestImage ))
                    {
                        $AppSettingsHT["UseDevTestImage"] = $this.UseDevTestImage
                    }
                    if($this.TriggerNextScanInMin -ne 0)
                    {					 
                        $startScanUTC = [System.DateTime]::UtcNow.AddMinutes($this.TriggerNextScanInMin)
                        $AppSettingsHT["ScheduleTriggerTime"] =  "0 $($startScanUTC.Minute) $($startScanUTC.Hour) * * *" #TODO: for dev-test, can we limit daily repetition?
                    }
                    #------------- End: DEV-TEST support stuff ---------------

                    $updatedWebApp = Update-AzFunctionAppSetting -Name $appServResource[0] -ResourceGroupName $this.RGname -AppSetting $AppSettingsHT -Force
                    if($null -eq $updatedWebApp) 
                    {
                        $this.PublishCustomMessage("App settings update failed in '$($appServResource[0])'", [MessageType]::Error);
                    }
                    else
                    {
                        $this.PublishCustomMessage("App settings updated in '$($appServResource[0])'", [MessageType]::Update);
                    }
				}
				$this.DoNotOpenOutputFolder = $true
			}
		}
		catch
		{
			$this.PublishCustomMessage("ADO Scanner CA update failed!", [MessageType]::Error);
			$this.PublishCustomMessage($_, [MessageType]::Error);
			$messageData += [MessageData]::new($Error)
		}
		return $messageData
	}

	[MessageData[]] GetAzSKADOContinuousAssurance()
    {
		[MessageData[]] $messageData = @();
		$this.messages += ([Constants]::DoubleDashLine + "`r`nStarted validating your AzSK.ADO Continuous Assurance (CA) setup for $($this.OrganizationToScan)`r`n"+[Constants]::DoubleDashLine);
		$this.PublishCustomMessage($this.messages, [MessageType]::Info);
		try
		{
			$output = $this.ValidateUserPermissions();
			if($output -ne 'OK') # if there is issue while validating permissions output will contain exception
			{
				$this.PublishCustomMessage("Error validating permissions on the subscription", [MessageType]::Error);
				$messageData += [MessageData]::new($output)
			}
			else 
			{
				#Step 1: Validate if RG exists.
				if (-not [string]::IsNullOrEmpty($this.RGname))
				{
					$RG = Get-AzResourceGroup -Name $this.RGname -ErrorAction SilentlyContinue
					if ($null -eq $RG)
					{
						$messageData += [MessageData]::new("Resource group [$($this.RGname)] not found. Please validate the resource group name." )
						$this.PublishCustomMessage($messageData.Message, [MessageType]::Error);
						return $messageData
					}
				}

				#Step 2: Validate if ADOScanner function app exists in the RG 
				$this.PublishCustomMessage("Check 01: Presence of Function app..", [MessageType]::Info);
				$appServResource = @((Get-AzResource -ResourceGroupName $this.RGname -ResourceType "Microsoft.Web/Sites").Name | where {$_ -match $this.FuncAppName})
				if($appServResource.Count -eq 0)
				{
					$this.PublishCustomMessage("Status:   ADOScanner function app not found in resource group [$($this.RGname)]. Update failed!", [MessageType]::Error);
					return $messageData
				}
				elseif ($appServResource.Count -gt 1)
				{
					$this.PublishCustomMessage("Status:   More than one ADOScanner app service found in resource group [$($this.RGname)].", [MessageType]::Error);
					$this.PublishCustomMessage("Consider using the '-RsrcTimeStamp' param. (E.g., For 'ADOScannerFA200915172817' use '-RsrcTimeStamp 200915172817'.)", [MessageType]::Warning);						

					return $messageData
				}
				else {
					$this.FuncAppName = $appServResource[0]
					$this.PublishCustomMessage("Status:   OK. Found the function app [$($this.FuncAppName)].", [MessageType]::Update);
					$this.TimeStamp = $this.FuncAppName.Replace($this.FuncAppDefaultName,"")
				}
				$this.PublishCustomMessage([Constants]::SingleDashLine, [MessageType]::Default);
				 
				#Step 3: Validate if ADOScanner function app is setup for the org provided in command
				$this.PublishCustomMessage("Check 02: Validating organization name..", [MessageType]::Info);
				$WebApp = Get-AzWebApp -Name $appServResource[0] -ResourceGroupName $this.RGname
				$ExistingAppSettings = $WebApp.SiteConfig.AppSettings 
				#convert existing app settings from list to hashtable
				$AppSettingsHT = @{}

				foreach ($Setting in $ExistingAppSettings) 
				{
					$AppSettingsHT["$($Setting.Name)"] = "$($Setting.value)"
				}

				if ($AppSettingsHT["OrgName"] -ne $this.OrganizationToScan)
				{
					$this.PublishCustomMessage("Status:   CA setup is configured for [$($AppSettingsHT["OrgName"])] organization and does not match with provided organization '$($this.OrganizationToScan)'.", [MessageType]::Error);
					return $messageData
				}
				else {
					$this.PublishCustomMessage("Status:   OK. CA is setup for organization [$($this.OrganizationToScan)].", [MessageType]::Update);
				}
				$this.PublishCustomMessage([Constants]::SingleDashLine, [MessageType]::Default);

				#Step 4: Validate app settings for additional app settings
				$this.PublishCustomMessage("Check 03: Validating other app settings..", [MessageType]::Info);
				if ([string]::IsNullOrEmpty($AppSettingsHT["PATToken"]) -and [string]::IsNullOrEmpty($AppSettingsHT["PATTokenURL"]))
				{
					$this.PublishCustomMessage("Status:   PAT token is not configured in the CA setup.", [MessageType]::Error);
				}
				else {
					$this.PublishCustomMessage("Status:   OK. PAT token is configured in the CA setup.", [MessageType]::Update);
				}
				if ([string]::IsNullOrEmpty($AppSettingsHT["ProjectNames"]))
				{
					$this.PublishCustomMessage("Status:   Project Name is not configured in the CA setup.", [MessageType]::Error);
				}
				else {
					$this.PublishCustomMessage("Status:   OK. Project name is configured in the CA setup.", [MessageType]::Update);
				}
				if ([string]::IsNullOrEmpty($AppSettingsHT["LAWSId"]) -or [string]::IsNullOrEmpty($AppSettingsHT["LAWSSharedKey"]))
				{
					$this.PublishCustomMessage("Status:   Log Analytics workspace is not configured in the CA setup.", [MessageType]::Info);
				}
				else {
					$this.PublishCustomMessage("Status:   OK. Log analytics is configured in the CA setup.", [MessageType]::Update);
				}
				if ([string]::IsNullOrEmpty($AppSettingsHT["AltLAWSId"]) -or [string]::IsNullOrEmpty($AppSettingsHT["AltLAWSSharedKey"]))
				{
					$this.PublishCustomMessage("Status:   (Info) Alternate Log Analytics workspace is not configured in the CA setup.", [MessageType]::Info);
				}
				else {
					$this.PublishCustomMessage("Status:   OK. Alternate Log Analytics workspace is configured in the CA setup.", [MessageType]::Update);
				}
				if ([string]::IsNullOrEmpty($AppSettingsHT["ExtendedCommand"]))
				{
					$this.PublishCustomMessage("Status:   (Info) Extended command is not configured in the CA setup.", [MessageType]::Info);
				}
				else {
					$this.PublishCustomMessage("Status:   OK. Extended command is configured in the CA setup.", [MessageType]::Update);
				}
				$this.PublishCustomMessage([Constants]::SingleDashLine, [MessageType]::Default);

				#Step 4: Validate if storage exists
				$this.PublishCustomMessage("Check 04: Validating Storage Account..", [MessageType]::Info);
				$this.StorageName = "adoscannersa"+$this.TimeStamp 
				$storageAccKey = Get-AzStorageAccountKey -ResourceGroupName $this.RGName -Name $this.StorageName
				if ($null -eq $storageAccKey)
				{
					$this.PublishCustomMessage("Status:   Storage account not found in the CA setup.", [MessageType]::Error);
				}
				else {
					$StorageContext = New-AzStorageContext -StorageAccountName $this.StorageName -StorageAccountKey $storageAccKey[0].Value -Protocol Https
					$containerObject = Get-AzStorageContainer -Context $StorageContext -Name $this.CAScanLogsContainerName -ErrorAction SilentlyContinue
					if($null -eq $containerObject)
					{
						$this.PublishCustomMessage("Status:   Scan logs not found in storage. (This is expected if you just setup CA as first scan may not have run yet.)", [MessageType]::Warning);
					}	
					else {
						$CAScanDataBlobObject = $this.GetScanLogsFromStorageAccount($this.CAScanLogsContainerName, "$($this.OrganizationToScan.ToLower())/", $StorageContext)
						if ($null -eq $CAScanDataBlobObject)
						{
							$this.PublishCustomMessage("Status:   Scan logs not found in storage for last 3 days.", [MessageType]::Error);
						}
						else {
							$this.PublishCustomMessage("Status:   OK. Storage account contains scan logs for recent jobs as expected.", [MessageType]::Update);
						}
					}
				}
				$this.PublishCustomMessage([Constants]::SingleDashLine, [MessageType]::Default);

				#Step 5: Validate image name
				$this.PublishCustomMessage("Check 05: Validating Image..", [MessageType]::Info);
				$image = "DOCKER|"+ $this.ImageName
				if ( $WebApp.SiteConfig.LinuxFxVersion -eq $image)
				{
					$this.PublishCustomMessage("Status:   OK. Docker image is correctly configured.", [MessageType]::Update);
				}
				else {
					$this.PublishCustomMessage("Status:   Docker image is not correctly configured.", [MessageType]::Error);
				}
				$this.PublishCustomMessage([Constants]::SingleDashLine, [MessageType]::Default);
				$this.PublishCustomMessage([Constants]::SingleDashLine, [MessageType]::Default);
				$this.PublishCustomMessage("You can use 'Update-AzSKADOContinuousAssurance' (UCA) command to modify AzSK ADO CA configurations/settings.", [MessageType]::Update);
			}
		}
		catch
		{
		}
		return $messageData
	}

	#get scan logs from storage 
	hidden [PSObject] GetScanLogsFromStorageAccount($containerName, $scanLogsPrefixPattern, $currentContext)
	{
		# Get AzSKADO storage of the current sub
		$recentCAScanDataBlobObject = $null
		$recentLogLimitInDays = 3
		$dayCounter = 0
		while($dayCounter -le $recentLogLimitInDays -and $recentCAScanDataBlobObject -eq $null){
			$date = [DateTime]::UtcNow.AddDays(-$dayCounter).ToString("yyyyMMdd")
			$recentLogsPath = $scanLogsPrefixPattern + "ADOCALogs_" + $date
			$recentCAScanDataBlobObject = Get-AzStorageBlob -Container $containerName -Prefix $recentLogsPath -Context $currentContext -ErrorAction SilentlyContinue
			$dayCounter += 1
			}
		return $recentCAScanDataBlobObject
	}
}
