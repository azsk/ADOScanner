Set-StrictMode -Version Latest 
class ContinuousAssurance:AzSKTestBase
{
	[string] $AutomationAccountName
	[string] $AutomationAccountRG
	[string] $AutomationCentralMultiAccountName
	[string] $AutomationCentralMultiAccountRG
	[string] $AutomationAccountLocation 
	[string] $AppResourceGroupName
	[string] $ConnectionName 
	[string] $StorgeContainerName
	[string] $CAScanType
	[string] $CertificateAssetName
	[PSObject] $ModuleContext

	ContinuousAssurance([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext)
	{
		
		$this.ModuleContext = [CATestContextHelper]::new([CommonHelper]::GetRootPath() + "\TestCases\"+$this.TestCase.Feature+"\TestData\"+"CA_Test_Endpoints.json")
		# TODO: Replace $testsettings with $moduleContext
		$this.AutomationAccountName = "AzSKContinuousAssurance" #$testsettings.CAAutomationAccountName
		$this.AutomationAccountRG = "AzSKRG" #$testsettings.AzSKResourceGroupName
		$this.AutomationCentralMultiAccountName = "AzSKContinuousAssuranceCentralMulti" #$testsettings.CAAutomationAccountName+'CentralMulti'
		$this.AutomationCentralMultiAccountRG = 'AzSKTestRGCentralMultiCA'
		$this.AutomationAccountLocation = 'southcentralus'
		$this.AppResourceGroupName = "AzSKTestRG" #This is the standard name used for testing resource in subscription.
		$this.ConnectionName = "AzureRunAsConnection" #$testsettings.CAConnectionName
		$this.CertificateAssetName = "AzureRunAsCertificate"
		$this.StorgeContainerName= "azskexecutionlogs"
		$this.CAScanType = 'Default'
	}
	[void] Execute()
	{
		switch ($this.testcase.TestMethod)
		{
			"TestICAInternalLatestModuleSolo"
			{
				$this.TestICAInternalLatestModule('Solo')
				break
			}
			"TestICAInternalRunbooksSolo"
			{
				$this.TestICAInternalRunbooks('Solo')
				break
			}
			"TestICAInternalSchedulesSolo"
			{
				$this.TestICAInternalSchedules('Solo')
				break
			}
			"TestICAInternalSPNAccessSolo"
			{
				$this.TestICAInternalSPNAccess('Solo')
				break
			}
			"TestCAFullFlowDefaultParams"
			{
				$this.TestCAFullFlowDefaultParams('Default')
				break
			}
			"TestCACentralMultiFullFlowDefaultParams"
			{
				$this.TestCAFullFlowDefaultParams('CentralMultiCA')
				break
			}
			"TestCAFullFlowAllParams"
			{
				$this.TestCAFullFlowAllParams()
				break
			}
			"TestRemoveCADefaultParams"
			{
				$this.TestRemoveCADefaultParams()
				break
			}
			"TestRemoveCAWithLogs"
			{
				$this.TestRemoveCAWithLogs()
				break
			}
			"TestUpdateCARenewCert"
			{
				$this.TestUpdateCARenewCert()
				break
			}
			"TestUpdateNewRunTimeAccount"
			{
				$this.TestUpdateNewRunTimeAccount()
				break
			}
			"TestUpdateFixRunTimeAccount"
			{
				$this.TestUpdateFixRunTimeAccount()
				break
			}
			"TestUpdateFixModules"
			{
				$this.TestUpdateFixModules()
				break
			}
			"TestUpdateAzureADAppName"
			{
				$this.TestUpdateAzureADAppName()
				break
			}
			Default 
			{					
			}
		}
	}

	[void] Initialize()
	{
		$this.testcase.PresetMethods.Split(";") | ForEach-Object {
			switch ($_)
			{
				"RunInstallCAInternalPrerequisiteSolo"
				{
					$this.ModuleContext.RunInstallCAInternalPrerequisite("Solo", $this.testContext, $false)
					break
				}
				"TriggerCAScanRunbookSolo"
				{
					$this.ModuleContext.TriggerCAScanRunbook("Solo", "Continuous_Assurance_Runbook", $false)
				}
				Default 
				{					
				}
			}
		}
        
	}
	
	[PSObject] GetExistingCA()
	{
		if($this.CAScanType -eq 'CentralMultiCA')
		{
			$CAAccount = Get-AzAutomationAccount -Name $this.AutomationCentralMultiAccountName -ResourceGroupName $this.AutomationCentralMultiAccountRG
		}
		else
		{
			$CAAccount = Get-AzAutomationAccount -Name $this.AutomationAccountName -ResourceGroupName $this.AutomationAccountRG
		}
		return $CAAccount
	}

	# [SOLO CA] Test AzSK module version on fresh installation
	[TestCaseResult] TestICAInternalLatestModule([String] $CAScanType)
	{
		$inputObject = $this.ModuleContext.GetInputObject("Solo")
		$this.ModuleContext.GetExistingCA("Solo")
		$result = $this.ModuleContext.WasAzSKModuleInstalled($inputObject.AutomationAccountName, $inputObject.AutomationAccountRGName, $($this.testContext.HarnessSettings.AzSKModule))
		if ($result.Status)
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,$result.Message)
		}
		else
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,$result.Message)
		}
		return $this.testcaseResult
	}

	# [SOLO CA] Test runbooks created in CA on fresh installation
	[TestCaseResult] TestICAInternalRunbooks([String] $CAScanType)
	{
		$inputObject = $this.ModuleContext.GetInputObject($CAScanType)
		$result = $this.ModuleContext.WereRunbooksCreated($inputObject.AutomationAccountName, $inputObject.AutomationAccountRGName, $inputObject.Runbooks)
		if ($result.Status)
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,$result.Message)
		}
		else
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,$result.Message)
		}
		return $this.testcaseResult
	}

	# [SOLO CA] Test schedules created in CA on fresh installation
	[TestCaseResult] TestICAInternalSchedules([String] $CAScanType)
	{
		$inputObject = $this.ModuleContext.GetInputObject($CAScanType)
		$result = $this.ModuleContext.WereAllSchedulesCreated($inputObject.AutomationAccountName, $inputObject.AutomationAccountRGName, $inputObject.Schedules)
		if ($result.Status)
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,$result.Message)
		}
		else
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,$result.Message)
		}
		return $this.testcaseResult	
	}

	# [SOLO CA] Test CA spn rbac access at subscription and rg level after fresh installation
	[TestCaseResult] TestICAInternalSPNAccess([String] $CAScanType)
	{
		$inputObject = $this.ModuleContext.GetInputObject($CAScanType)
		$result = $this.ModuleContext.WasCASPNGrantedRBACAccess($inputObject.AutomationAccountName, $inputObject.AutomationAccountRGName)
		if ($result.Status)
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,$result.Message)
		}
		else
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,$result.Message)
		}
		return $this.testcaseResult
	}

	[TestCaseResult] TestCAFullFlowDefaultParams([String] $CAScanType)
	{
		$CAOutput = @(0..3)
		$message = ""
		$this.CAScanType = $CAScanType
		# Get CA
		$CAOutput[0] = $this.GetCA()
		$message += $CAOutput[0].Message + "`n"
		# Remove CA
		$CAOutput[1] = $this.RemoveCA()
		$message+= $CAOutput[1].Message + "`n"
		#Install CA
		$CAOutput[2] = $this.InstallCA($false)
		$message+= $CAOutput[2].Message + "`n"
		if($CAOutput[2].TestStatus -eq [TestStatus]::Passed)
		{
			$existingaccount =	$this.GetExistingCA()
			$existingStorage = Get-AzResource -ResourceGroupName $this.AutomationAccountRG -Name "*azsk*" -ResourceType "Microsoft.Storage/storageAccounts"

			if(!($existingaccount -and $existingStorage))
			{
				$message += "Something went wrong while installing CA components. Automation account or Storage account not created."
			}
		}
		#Update CA
		$CAOutput[3] = $this.UpdateCA()
		$message += $CAOutput[3].Message + "`n"
		if(($CAOutput.TestStatus -contains [TestStatus]::ScanInterrupted) -or ($CAOutput.TestStatus -contains [TestStatus]::Failed))
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,$message + "`nCheck logs for more details.")
		}
		else
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed, $message + "`nSuccessfully tested CA flow with default params.")
		}
		return $this.testcaseResult
	}


	[TestCaseResult] TestCAFullFlowDefaultParams()
	{
		if($null -ne $this.GetExistingCA())
		{
			$this.Cleanup()
			Start-Sleep -Seconds 10
		}
		try
		{
			$failMsg = ""	
			$isInstallationSuccessful = $false
			try
			{
				Install-AzSKContinuousAssurance -SubscriptionId $this.testContext.TestResources.SubscriptionId `
				-ResourceGroupNames $this.AppResourceGroupName `
				-LAWSId $this.testContext.AzSKSettings.endpoints.LAWSId `
				-LAWSSharedKey $this.testContext.AzSKSettings.endpoints.LAWSSharedKey
				$isInstallationSuccessful = $true
			}
			catch
			{
				$failMsg+="Something went wrong while installing CA components. $($_.Exception)"
			}		
			if($isInstallationSuccessful)
			{
				$isUpdateSuccessful = $false
				$existingaccount =	$this.GetExistingCA()
				$existingStorage = Get-AzResource -ResourceGroupName $this.AutomationAccountRG -Name "*azsk*" -ResourceType "Microsoft.Storage/storageAccounts"
				if($existingaccount -and $existingStorage)
				{
					try
					{
						#Update CA
						Update-AzSKContinuousAssurance -SubscriptionId $this.testContext.TestResources.SubscriptionId
						$isUpdateSuccessful = $true
					}
					catch
					{
						$failMsg+="Something went wrong while updating CA components. $($_.Exception)"
					}
					if($isUpdateSuccessful)
					{
						#check if account is recently updated 
						$account = $this.GetExistingCA()	
						if(($(get-date).ToUniversalTime() - $account.LastModifiedTime.ToUniversalTime().DateTime).TotalSeconds -gt 50)
						{
							$failMsg+="Something went wrong while updating CA components."
						}
						else
						{
							#Remove CA
							try
							{
								$this.Cleanup()
								if($null -ne $this.GetExistingCA())
								{
									$failMsg+="Something went wrong while removing CA components."
								}
								else
								{
									$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully tested CA flow with default params.")
									return $this.testcaseResult
								}
							}
							catch
							{
								$failMsg+="Something went wrong while removing CA components. $($_.Exception)"
							}
						}
					}
				}
				else
				{
					$failMsg += "Something went wrong while installing CA components. Automation account or Storage account not created."
				}
			}
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,$failMsg)
		}
		catch
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Error occurred. $($_.Exception)")
		}
		return $this.testcaseResult
	}
	[TestCaseResult] TestCAFullFlowAllParams()
	{
		if($null -ne $this.GetExistingCA())
		{
			$this.Cleanup()
			Start-Sleep -Seconds 10
		}
		try
		{
			$failMsg = ""	
			$isInstallationSuccessful = $false
			try
			{
				Install-AzSKContinuousAssurance -SubscriptionId $this.testContext.TestResources.SubscriptionId `
				-ResourceGroupNames $this.AppResourceGroupName `
				-LAWSId $this.testContext.AzSKSettings.endpoints.LAWSId `
				-LAWSSharedKey $this.testContext.AzSKSettings.endpoints.LAWSSharedKey
				$isInstallationSuccessful = $true
			}
			catch
			{
				$failMsg+="Something went wrong while installing CA components. $($_.Exception)"
			}		
			if($isInstallationSuccessful)
			{
				$isUpdateSuccessful = $false
				$existingaccount =	$this.GetExistingCA()
				$existingStorage = Get-AzResource -ResourceGroupName $this.AutomationAccountRG -Name "*azsk*" -ResourceType "Microsoft.Storage/storageAccounts"
				if($existingaccount -and $existingStorage)
				{
					try
					{
						#remove automation module
						Remove-AzAutomationModule -Name "AzureRm.Automation" -ResourceGroupName $this.AutomationAccountRG -AutomationAccountName $this.AutomationAccountName -Force
				
						#remove SPN permission 
						$connection = Get-AzAutomationConnection -Name $this.ConnectionName -ResourceGroupName $this.AutomationAccountRG -AutomationAccountName $this.AutomationAccountName
						$servicePrincipal = Get-AzADServicePrincipal -ServicePrincipalName $connection.FieldDefinitionValues.ApplicationId
						Remove-AzRoleAssignment -serviceprincipalname $servicePrincipal.ServicePrincipalNames[0] -Scope "/subscriptions/$($this.testContext.TestResources.SubscriptionId)" -RoleDefinitionName reader
						
						#Update CA to fix issues
						Update-AzSKContinuousAssurance -SubscriptionId $this.testContext.TestResources.SubscriptionId `
						-ResourceGroupNames "*" -FixRuntimeAccount -FixModules
						
						#check if update is successful 
						$module = Get-AzAutomationModule -Name "AzureRm.Automation" -ResourceGroupName $this.AutomationAccountRG -AutomationAccountName $this.AutomationAccountName 
						$variable = Get-AzAutomationVariable -Name "AppResourcegroupNames" -ResourceGroupName $this.AutomationAccountRG -AutomationAccountName $this.AutomationAccountName
						$spnPermission = Get-AzRoleAssignment -ServicePrincipalName $servicePrincipal.ServicePrincipalNames[0] -Scope "/subscriptions/$($this.testContext.TestResources.SubscriptionId)"
						if($module -and ($module.ProvisioningState -eq "Succeeded") -and $variable -and ($variable.Value -eq "*") -and $spnPermission -and $spnPermission.RoleDefinitionName -eq "Reader")
						{
							$isUpdateSuccessful = $true
						}
					}
					catch
					{
						$failMsg+="Something went wrong while updating CA components. $($_.Exception)"
					}
					#Remove CA
					try
					{
						$this.Cleanup()
						if($null-ne $this.GetExistingCA())
						{
							$failMsg+="Something went wrong while removing CA components."
						}
						else
						{
							$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully tested CA flow with multiple params.")
							return $this.testcaseResult
						}
					}
					catch
					{
						$failMsg+="Something went wrong while removing CA components. $($_.Exception)"
					}
				}
				else
				{
					$failMsg += "Something went wrong while installing CA components. Automation account or Storage account not created."
				}
			}
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,$failMsg)
		}
		catch
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Error occurred. $($_.Exception)")
		}
		return $this.testcaseResult
	}
	[TestCaseResult] TestRemoveCADefaultParams()
	{
		if($null -eq $this.GetExistingCA())
		{
			Install-AzSKContinuousAssurance -SubscriptionId $this.testContext.TestResources.SubscriptionId `
									-ResourceGroupNames $this.AppResourceGroupName `
									-LAWSId $this.testContext.AzSKSettings.endpoints.LAWSId `
									-LAWSSharedKey $this.testContext.AzSKSettings.endpoints.LAWSSharedKey
		}
		if($this.GetExistingCA())
		{
			$this.Cleanup()
			if($this.GetExistingCA())
			{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Error while removing AzSK Continuous Assurance.")
			}	
			else
			{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully removed AzSK Continuous Assurance.")
			}		
		}
		else
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Error,"Error occurred while installing CA.")
		}
		return $this.testcaseResult
	}
	[TestCaseResult] TestRemoveCAWithLogs()
	{
		if($null -eq $this.GetExistingCA())
		{
			Install-AzSKContinuousAssurance -SubscriptionId $this.testContext.TestResources.SubscriptionId `
									-ResourceGroupNames $this.AppResourceGroupName `
									-LAWSId $this.testContext.AzSKSettings.endpoints.LAWSId `
									-LAWSSharedKey $this.testContext.AzSKSettings.endpoints.LAWSSharedKey
		}
		if($null -eq $this.GetAzSKStorageContainer())
		{
			#create container
			New-AzureStorageContainer -Name $this.StorgeContainerName -Context $this.GetAzSKStorageContext()
		}
		Remove-AzSKContinuousAssurance -SubscriptionId $this.testContext.TestResources.SubscriptionId  -DeleteStorageReports -Force
		if($null -eq $this.GetAzSKStorageContainer())
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully removed AzSK Continuous Assurance with storage logs.")
		}
		else
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Error while removing AzSK Continuous Assurance with storage logs.")
		}
		return $this.testcaseResult
	}

	[TestCaseResult] TestUpdateCARenewCert()
	{
		if($null -ne $this.GetExistingCA())
		{
			$currentCert = Get-AzAutomationCertificate -AutomationAccountName $this.AutomationAccountName -Name $this.CertificateAssetName -ResourceGroupName $this.AutomationAccountRG -ErrorAction SilentlyContinue
			Update-AzSKContinuousAssurance -SubscriptionId $this.testContext.TestResources.SubscriptionId -RenewCertificate
			$newCert = Get-AzAutomationCertificate -AutomationAccountName $this.AutomationAccountName -Name $this.CertificateAssetName -ResourceGroupName $this.AutomationAccountRG -ErrorAction SilentlyContinue

			if($newCert.Thumbprint -and ($newCert.Thumbprint -ne $currentCert.Thumbprint)){
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully renewed CA certificate.")
			}
			else{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Failed to renew CA certificate.")
			}
		}
		return $this.testcaseResult
	}

	[TestCaseResult] TestUpdateNewRunTimeAccount()
	{
		if($null -ne $this.GetExistingCA())
		{
			$currentConnection = Get-AzAutomationConnection -AutomationAccountName $this.AutomationAccountName -Name $this.ConnectionName -ResourceGroupName $this.AutomationAccountRG -ErrorAction SilentlyContinue
			$currentAzSKADAppName = (Get-AzADApplication -ApplicationId $currentConnection.FieldDefinitionValues.ApplicationId -ErrorAction stop).DisplayName
			
			Update-AzSKContinuousAssurance -SubscriptionId $this.testContext.TestResources.SubscriptionId -NewRuntimeAccount
			
			$newConnection = Get-AzAutomationConnection -AutomationAccountName $this.AutomationAccountName -Name $this.ConnectionName -ResourceGroupName $this.AutomationAccountRG -ErrorAction SilentlyContinue
			$newAzSKADAppName = (Get-AzADApplication -ApplicationId $newConnection.FieldDefinitionValues.ApplicationId -ErrorAction stop).DisplayName
			
			if($newAzSKADAppName -and ($newAzSKADAppName -ne $currentAzSKADAppName)){
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully created new CA runtime account.")
			}
			else{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Failed to create new CA runtime account.")
			}
		}
		return $this.testcaseResult
	}

	[TestCaseResult] TestUpdateFixRunTimeAccount()
	{
		if($null -ne $this.GetExistingCA())
		{
			$connection = Get-AzAutomationConnection -AutomationAccountName $this.AutomationAccountName -Name $this.ConnectionName -ResourceGroupName $this.AutomationAccountRG -ErrorAction SilentlyContinue
			$appId = $connection.FieldDefinitionValues.ApplicationId
			
			Remove-AzRoleAssignment -ServicePrincipalName $appId -RoleDefinitionName Reader
			Remove-AzRoleAssignment -ServicePrincipalName $appId -ResourceGroupName $this.AutomationAccountRG -RoleDefinitionName Contributor

			Update-AzSKContinuousAssurance -SubscriptionId $this.testContext.TestResources.SubscriptionId -FixRuntimeAccount
			
			$spPermissions = Get-AzRoleAssignment -serviceprincipalname $appId
			$haveSubscriptionAccess = $false
			$haveRGAccess = $false

			if(($spPermissions|measure-object).count -gt 0)
			{
				$haveSubscriptionAccess = ($spPermissions | Where-Object {$_.scope -eq "/subscriptions/$($this.testContext.TestResources.SubscriptionId)" -and $_.RoleDefinitionName -eq "Reader"}|Measure-Object).count -gt 0
				$haveRGAccess = ($spPermissions | Where-Object {$_.scope -eq (Get-AzResourceGroup -Name $this.AutomationAccountRG).ResourceId -and $_.RoleDefinitionName -eq "Contributor" }|measure-object).count -gt 0
			}
			if($haveSubscriptionAccess -and $haveRGAccess){
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully fixed missing SPN permissions.")
			}
			else{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Failed to fix missing SPN permissions.")
			}
		}
		return $this.testcaseResult
	}

	[TestCaseResult] TestUpdateFixModules()
	{
		if($null -ne $this.GetExistingCA())
		{
			$automationModule = Get-AzAutomationModule -AutomationAccountName $this.AutomationAccountName -Name 'Az.Automation' -ResourceGroupName $this.AutomationAccountRG -ErrorAction Ignore | Where-Object {($_.IsGlobal -ne $true) -and ($_.ProvisioningState -eq "Succeeded" -or $_.ProvisioningState -eq "Created")}

			if($automationModule){
				Write-Host 'Removing Az.Automation from CA account' -ForegroundColor Yellow
				Remove-AzAutomationModule -AutomationAccountName $this.AutomationAccountName -Name 'Az.Automation' -ResourceGroupName $this.AutomationAccountRG -Force
				$automationModule = Get-AzAutomationModule -AutomationAccountName $this.AutomationAccountName -Name 'Az.Automation' -ResourceGroupName $this.AutomationAccountRG -ErrorAction Ignore
				if(-not $automationModule){
					Write-Host 'Removed Az.Automation from CA account' 
				}
			}
			else{
				Write-Host 'Az.Automation module not found in CA account.' 
			}
			
			Update-AzSKContinuousAssurance -SubscriptionId $this.testContext.TestResources.SubscriptionId -FixModules

			$automationModule = Get-AzAutomationModule -AutomationAccountName $this.AutomationAccountName -Name 'Az.Automation' -ResourceGroupName $this.AutomationAccountRG -ErrorAction Ignore | Where-Object {($_.IsGlobal -ne $true) -and ($_.ProvisioningState -eq "Succeeded" -or $_.ProvisioningState -eq "Created")}
			
			if($automationModule){
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully fixed missing CA modules.")
			}
			else{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Failed to fix missing CA modules.")
			}
		}
		return $this.testcaseResult
	}

	[TestCaseResult] TestUpdateAzureADAppName()
	{
		if($null -ne $this.GetExistingCA())
		{
			$currentConnection = Get-AzAutomationConnection -AutomationAccountName $this.AutomationAccountName -Name $this.ConnectionName -ResourceGroupName $this.AutomationAccountRG -ErrorAction SilentlyContinue
			$currentAzSKADAppName = (Get-AzADApplication -ApplicationId $currentConnection.FieldDefinitionValues.ApplicationId -ErrorAction stop).DisplayName
			
			$name = 'TestAutomationAD_' + (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmss")
			
			Update-AzSKContinuousAssurance -SubscriptionId $this.testContext.TestResources.SubscriptionId -AzureADAppName $name
			
			$newConnection = Get-AzAutomationConnection -AutomationAccountName $this.AutomationAccountName -Name $this.ConnectionName -ResourceGroupName $this.AutomationAccountRG -ErrorAction SilentlyContinue
			$newAzSKADAppName = (Get-AzADApplication -ApplicationId $newConnection.FieldDefinitionValues.ApplicationId -ErrorAction stop).DisplayName
			
			if($newAzSKADAppName -and ($newAzSKADAppName -ne $currentAzSKADAppName) -and ($newAzSKADAppName -eq $name) ){
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully created new CA runtime account with custom AD App name.")
			}
			else{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Failed to create new CA runtime account with custom AD App name.")
			}
		}
		return $this.testcaseResult
	}

	[PSObject] GetCA()
	{
		$Result = "" | Select TestStatus, Message
		$Result.TestStatus = [TestStatus]::ScanInterrupted
		if($this.GetExistingCA())
		{
			$Command = "Get-AzSKContinuousAssurance -SubscriptionId '$($this.testContext.TestResources.SubscriptionId)'"
			$Description = "Run command 'Get-AzSKContinuousAssurance'."
			if($this.CAScanType -eq 'CentralMultiCA')
			{
				$Command += " -AutomationAccountRGName $($this.AutomationCentralMultiAccountRG) -AutomationAccountName $($this.AutomationCentralMultiAccountName)"
				$Description += " -AutomationAccountRGName $($this.AutomationCentralMultiAccountRG) -AutomationAccountName $($this.AutomationCentralMultiAccountName)"
			}
			$Result.TestStatus = [TestHelper]::RunAzSKCommand($Command , $("GCA_" + $($this.CAScanType)), $Description, $this.testcase.TestCaseID ,$this.testContext)
			$Result.Message = "GET CA: $($Result.TestStatus)"
		}
		else
		{
			$Result.Message = "GET CA: $($Result.TestStatus). Subscription does not contain CA automation account."
		}
		return $Result
	}

	[PSObject] InstallCA([bool] $ForceInstall)
	{
		$Result = "" | Select TestStatus, Message
		$Result.TestStatus = [TestStatus]::ScanInterrupted

		if($ForceInstall -and ($this.GetExistingCA() | Measure-Object).Count -gt 0)
		{
			$this.RemoveCA()
			Start-Sleep -Seconds 10
		}
		if($this.GetExistingCA() -eq $null)
		{
			$Description = "Run command 'Install-AzSKContinuousAssurance -ResourceGroupNames 'AzSKTestRG' -LAWSId *** -LAWSSharedKey ***'"
			$Command = "Install-AzSKContinuousAssurance -SubscriptionId '$($this.testContext.TestResources.SubscriptionId)' `
								  -ResourceGroupNames '$($this.AppResourceGroupName)' `
								  -LAWSId '$($this.testContext.AzSKSettings.endpoints.LAWSId)' `
								  -LAWSSharedKey '$($this.testContext.AzSKSettings.endpoints.LAWSSharedKey)'"
			
			if($this.CAScanType -eq 'CentralMultiCA')
			{
				if(-not (Get-AzResourceGroup -Name $this.AutomationCentralMultiAccountRG -ErrorAction SilentlyContinue))
				{
					New-AzResourceGroup -Name $this.AutomationCentralMultiAccountRG -Location $this.AutomationAccountLocation
				}
				$Command += " -TargetSubscriptionIds $($this.testContext.TestResources.SubscriptionId) -CentralScanMode -LoggingOption CentralSub -SkipTargetSubscriptionConfig `
							-AutomationAccountName $($this.AutomationCentralMultiAccountName) -AutomationAccountRGName $($this.AutomationCentralMultiAccountRG) -AutomationAccountLocation $($this.AutomationAccountLocation)"
				$Description = "Run command 'Install-AzSKContinuousAssurance -ResourceGroupNames 'AzSKTestRG' -LAWSId *** -LAWSSharedKey *** -TargetSubscriptionIds *** -CentralScanMode -LoggingOption CentralSub " +
							 "-SkipTargetSubscriptionConfig -AutomationAccountName *** -AutomationAccountRGName $($this.AutomationCentralMultiAccountRG) -AutomationAccountLocation $($this.AutomationAccountLocation)'"
			}
			$Result.TestStatus = [TestHelper]::RunAzSKCommand($Command , $("ICA_" + $($this.CAScanType)), $Description, $this.testcase.TestCaseID ,$this.testContext)
			$Result.Message = "INSTALL CA: $($Result.TestStatus)"
		}
		else
		{
			$Result.Message = "INSTALL CA: $($Result.TestStatus). Subscription already contains CA automation account."
		}
		return $Result
	}

	[PSObject] UpdateCA()
	{
		$Result = "" | Select TestStatus, Message
		$Result.TestStatus = [TestStatus]::ScanInterrupted

		if($this.GetExistingCA())
		{
			$Command = "Update-AzSKContinuousAssurance -SubscriptionId $($this.testContext.TestResources.SubscriptionId) -ScanIntervalInHours 12"
			$Description = "Run command 'Update-AzSKContinuousAssurance -SubscriptionId SubscriptionId -ScanIntervalInHours 12'."
			if($this.CAScanType -eq 'CentralMultiCA')
			{
				$Command += " -TargetSubscriptionIds $($this.testContext.TestResources.SubscriptionId) -CentralScanMode "
				$Description = "Run command 'Update-AzSKContinuousAssurance -SubscriptionId SubscriptionId -ScanIntervalInHours 12 -TargetSubscriptionIds *** -CentralScanMode'."
			}
			$Result.TestStatus = [TestHelper]::RunAzSKCommand($Command , $("UCA_" + $($this.CAScanType)), $Description, $this.testcase.TestCaseID ,$this.testContext)
			$Result.Message = "UPDATE CA: $($Result.TestStatus)"
		}
		else
		{
			$Result.Message = "UPDATE CA: $($Result.TestStatus). Subscription already contain CA automation account."
		}
		return $Result
	}

	[PSObject] RemoveCA()
	{
		$Result = "" | Select TestStatus, Message
		$Result.TestStatus = [TestStatus]::ScanInterrupted

		if($this.GetExistingCA())
		{
			$Command = "Remove-AzSKContinuousAssurance -SubscriptionId $($this.testContext.TestResources.SubscriptionId) -Force"
			$Description = "Run command 'Remove-AzSKContinuousAssurance -Force'"
			if($this.CAScanType -eq 'CentralMultiCA')
			{
				$Command += " -AutomationAccountRGName $($this.AutomationCentralMultiAccountRG) -AutomationAccountName $($this.AutomationCentralMultiAccountName ) -CentralScanMode "
				$Description = "Run command 'Remove-AzSKContinuousAssurance -AutomationAccountRGName $($this.AutomationCentralMultiAccountRG) -AutomationAccountName *** -CentralScanMode -Force'"
			}
			$Result.TestStatus = [TestHelper]::RunAzSKCommand($Command , $("RCA_" + $($this.CAScanType)), $Description, $this.testcase.TestCaseID, $this.testContext)
			Start-Sleep -Seconds 10
			if(($Result.TestStatus -eq [TestStatus]::Passed) -and ($null -ne $this.GetExistingCA()))
			{
				$Result.Message = "REMOVE CA: Failed"
			}
			else
			{
				$Result.Message = "REMOVE CA: $($Result.TestStatus)"
			}
		}
		else
		{
			$Result.Message = "REMOVE CA: $($Result.TestStatus). Subscription already contain CA automation account."
		}
		return $Result
	}

	[void] Cleanup()
	{
		#Remove-AzSKContinuousAssurance -SubscriptionId $this.testContext.TestResources.SubscriptionId -Force
	}

	[PSObject] GetAzSKStorageContainer()
	{
		$storageContext = $this.GetAzSKStorageContext()
		$existingContainer = Get-AzureStorageContainer -Name $this.StorgeContainerName -Context $storageContext -ErrorAction SilentlyContinue
		return $existingContainer
	}
	[PSObject] GetAzSKStorageContext()
	{
		$existingStorage = Get-AzResource -ResourceGroupName $this.AutomationAccountRG -Name "*azsk*" -ResourceType "Microsoft.Storage/storageAccounts"
		$keys = Get-AzStorageAccountKey -ResourceGroupName $this.AutomationAccountRG -Name $existingStorage.Name 
		$storageContext = New-AzureStorageContext -StorageAccountName $existingStorage.Name -StorageAccountKey $keys[0].Value -Protocol Https
		return $storageContext
	}
}