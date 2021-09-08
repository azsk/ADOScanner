Set-StrictMode -Version Latest 
class OMSTest: AzSKTestBase
{

	OMSTest([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext)
	{ }

	[string] $AzSKSettingsPath = $Env:LOCALAPPDATA + "\Microsoft\AzSK\AzSKSettings.json"
	[string] $OMSRG = "mms-sea";
	[string] $OMSWorkspaceName = "azskomstestbed";

	[void] Execute()
	{
		switch ($this.testcase.TestMethod)
		{
			"TestSetAzSKOMSSettings"{
				$this.TestSetAzSKOMSSettings()
				break
			}
			"TestSetAzSKOMSSettingsWithSource"{
				$this.TestSetAzSKOMSSettingsWithSource()
				break
			}
			"TestSetAzSKOMSSettingsDisable"{
				$this.TestSetAzSKOMSSettingsDisable()
				break
			}
			"TestInstallAzSKOMSSolutionAll"{
				$this.TestInstallAzSKOMSSolution("All")
				break
			}
			"TestInstallAzSKOMSSolutionQueries"{
				$this.TestInstallAzSKOMSSolution("Queries")
				break
			}
			"TestInstallAzSKOMSSolutionAlerts"{
				$this.TestInstallAzSKOMSSolution("Alerts")
				break
			}
			"TestInstallAzSKOMSSolutionSampleView"{
				$this.TestInstallAzSKOMSSolution("SampleView")
				break
			}
			"TestUninstallAzSKOMSetup"{
				$this.TestUninstallAzSKOMSetup()
				break
			}
		}
	}

	[TestCaseResult] TestSetAzSKOMSSettings()
	{
		try
		{
			Set-AzSKMonitoringSettings -LAWSId $this.testContext.AzSKSettings.endpoints.LAWSId -LAWSSharedKey $this.testContext.AzSKSettings.endpoints.LAWSSharedKey
			$fileContent = (Get-Content -Raw -Path $this.AzSKSettingsPath) | ConvertFrom-Json;

			$result = [TestStatus]::Passed;
			$message = "";
			if($fileContent.LAWSId -ne $this.testContext.AzSKSettings.endpoints.LAWSId)
			{
				$result = [TestStatus]::Failed;
				$message += "LAWSId doesn't match. ";
			}

			if($fileContent.LAWSSharedKey -ne $this.testContext.AzSKSettings.endpoints.LAWSSharedKey)
			{
				$result = [TestStatus]::Failed;
				$message += "LAWSSharedKey doesn't match. ";
			}

			if([string]::IsNullOrWhiteSpace($message))
			{
				$message = "Successfully updated the OMS data."
			}
			$this.testcaseResult = [TestCaseResult]::new($this.testCase, $result, $message)
		}
		catch
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase, [TestStatus]::Failed, "Error while setting OMS data.")
		}

		return $this.testcaseResult
	}

	[TestCaseResult] TestSetAzSKOMSSettingsWithSource()
	{
		try
		{
			$OMSSource = "AzSKTestSource-" + $(Get-Date -format "yyyyMMdd_HHmmss");
			Set-AzSKMonitoringSettings -LAWSId $this.testContext.AzSKSettings.endpoints.LAWSId -LAWSSharedKey $this.testContext.AzSKSettings.endpoints.LAWSSharedKey -Source $OMSSource
			$fileContent = (Get-Content -Raw -Path $this.AzSKSettingsPath) | ConvertFrom-Json;

			$result = [TestStatus]::Passed;
			$message = "";
			if($fileContent.LAWSId -ne $this.testContext.AzSKSettings.endpoints.LAWSId)
			{
				$result = [TestStatus]::Failed;
				$message += "LAWSId doesn't match. ";
			}

			if($fileContent.LAWSSharedKey -ne $this.testContext.AzSKSettings.endpoints.LAWSSharedKey)
			{
				$result = [TestStatus]::Failed;
				$message += "LAWSSharedKey doesn't match. ";
			}

			if($fileContent.OMSSource -ne $OMSSource)
			{
				$result = [TestStatus]::Failed;
				$message += "OMSSource doesn't match. ";
			}

			if([string]::IsNullOrWhiteSpace($message))
			{
				$message = "Successfully updated the OMS data with source. "
				Get-AzSKSubscriptionSecurityStatus -SubscriptionId $this.testContext.TestResources.SubscriptionId -ControlIds "Azure_Subscription_AuthZ_Custom_RBAC_Roles" -DoNotOpenOutputFolder
				$omsLogs = $null;
				for($retries = 6; $retries -ge 0; $retries--)
				{
					Write-Host "Fetching OMS logs in 5 seconds, Retries left: $retries"
					Start-Sleep -Seconds 10
					$omsLogs = Get-AzOperationalInsightsSearchResults -ResourceGroupName $this.OMSRG -WorkspaceName $this.OMSWorkspaceName -Query "Type=AzSK_CL Source_s=$OMSSource" -Top 1
					if($omsLogs -and ($omsLogs.Value | Measure-Object).Count -ne 0)
					{
						break;
					}
				}

				if($omsLogs -and ($omsLogs.Value | Measure-Object).Count -ne 0)
				{
					$message += "AzSK is able to post data in OMS. ";
				}
				else
				{
					$result = [TestStatus]::Failed;
					$message += "AzSK is UNABLE to post data in OMS. ";
				}
			}
			$this.testcaseResult = [TestCaseResult]::new($this.testCase, $result, $message)
		}
		catch
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase, [TestStatus]::Failed, "Error while setting OMS data.")
		}

		return $this.testcaseResult
	}	

	[TestCaseResult] TestSetAzSKOMSSettingsDisable()
	{
		try
		{
			Set-AzSKMonitoringSettings -Disable
			$fileContent = (Get-Content -Raw -Path $this.AzSKSettingsPath) | ConvertFrom-Json;

			$result = [TestStatus]::Passed;
			$message = "";
			if(-not [string]::IsNullOrWhiteSpace($fileContent.LAWSId))
			{
				$result = [TestStatus]::Failed;
				$message += "LAWSId is not reset. ";
			}

			if(-not [string]::IsNullOrWhiteSpace($fileContent.LAWSSharedKey))
			{
				$result = [TestStatus]::Failed;
				$message += "LAWSSharedKey is not reset. ";
			}
			
			if([string]::IsNullOrWhiteSpace($message))
			{
				$message = "Successfully disabled the OMS settings."
			}
			$this.testcaseResult = [TestCaseResult]::new($this.testCase, $result, $message)
		}
		catch
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase, [TestStatus]::Failed, "Error while setting OMS data.")
		}

		return $this.testcaseResult
	}	

	[TestCaseResult] TestInstallAzSKOMSSolution($installationOption)
	{
		try
		{
			Install-AzSKMonitoringSolution -ApplicationName AzSKTestRG -ApplicationResourceGroups AzSKTestRG -ApplicationSubscriptionId $this.testContext.TestResources.SubscriptionId -LAResourceGroup $this.OMSRG -LASubscriptionId $this.testContext.TestResources.SubscriptionId -OMSWorkspaceName $this.OMSWorkspaceName -SecurityContactEmails $this.settings.SecurityPOCEmail -OMSInstallationOption $installationOption
			$deploymentNamePrefix = "AzSK.AM.OMS.";
			$deploymentNames = @();

			switch($installationOption)
			{
				"All"
				{
					$deploymentNames += ($deploymentNamePrefix + "Alerts");
					$deploymentNames += ($deploymentNamePrefix + "Searches");
					$deploymentNames += ($deploymentNamePrefix + "SampleView");
				}
				"Queries"
				{
					$deploymentNames += ($deploymentNamePrefix + "Searches");
				}
				"Alerts"
				{
					$deploymentNames += ($deploymentNamePrefix + "Alerts");
				}
				"SampleView"
				{
					$deploymentNames += ($deploymentNamePrefix + "SampleView");
				}
				default
				{
					$deploymentNames += ($deploymentNamePrefix + "Alerts");
					$deploymentNames += ($deploymentNamePrefix + "Searches");
					$deploymentNames += ($deploymentNamePrefix + "SampleView");
				}
			}

			#Fetch resource group deployments
			$timeRange = [Datetime]::UtcNow.AddMinutes(-2);
			Start-Sleep -Seconds 10
			$allDeployments = Get-AzResourceGroupDeployment -ResourceGroupName $this.OMSRG

			$successDeployments = @();
			$selectedDeployments = @();
			$deploymentNames | ForEach-Object {
				$name = $_;
				$selectedDeployments += $allDeployments | Where-Object { $_.DeploymentName.StartsWith($name) -and $_.Timestamp -gt $timeRange } | Select-Object -First 1 
			}

			$successDeployments += $selectedDeployments | Where-Object { $_.ProvisioningState -eq "Succeeded" }

			if($successDeployments.Count -eq $deploymentNames.Count)
			{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase, [TestStatus]::Passed, "Successfully installed the OMS views with installation option - $installationOption.")
			}
			else
			{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase, [TestStatus]::Failed, "OMS installation failed - $installationOption.")
			}
		}
		catch
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase, [TestStatus]::Failed, "Error while installing OMS views with installation option - $installationOption. `r`n" + $_.ToString())
		}

		return $this.testcaseResult
	}	

	[TestCaseResult] TestUninstallAzSKOMSetup()
	{
		try
		{
			Uninstall-AzSKOMSetup -LAResourceGroup $this.OMSRG -LASubscriptionId $this.testContext.TestResources.SubscriptionId -OMSWorkspaceName $this.OMSWorkspaceName
			$savedSearches = Get-AzOperationalInsightsSavedSearch -ResourceGroupName $this.OMSRG -WorkspaceName $this.OMSWorkspaceName
			$azSkSearches = @()
			if($null -ne $savedSearches -and $null -ne $savedSearches.Value)
			{
				$savedSearches.Value | ForEach-Object {
					Set-Variable -Name savedSearch -Value $_
					if($null -ne $savedSearch.Properties -and $savedSearch.Properties.Category -like "*AzSK*")
					{
						$azSkSearches += $savedSearch
					}
				}
			}		

			if($azSkSearches.Count -eq 0)
			{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase, [TestStatus]::Passed, "Successfully uninstalled the OMS views.")
			}
			else
			{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase, [TestStatus]::Failed, "OMS queries are not uninstalled.")
			}
		}
		catch
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase, [TestStatus]::Failed, "Error while uninstalling OMS views.`r`n" + $_.ToString())
		}

		return $this.testcaseResult
	}	
}

