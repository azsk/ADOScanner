Set-StrictMode -Version Latest 
class SVTCommonTest:AzSKTestBase
{
	[string]$resourceName = "azskteststoragecommon"
	[string]$resourceGroupName = "AzSKTestRG"
	[string] $AzSKSettingsPath 
	[string] $OrgPolicyURL
	
	SVTCommonTest([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext, [string] $AzSKModule):Base($testcase, $testsettings, $testContext, $AzSKModule)
	{
		$this.OrgPolicyURL = $testContext.AzSKSettings.endpoints.OnlinePolicyStoreUrl
		switch($AzSKModule)
		{
			"Prod"{
				$AzSKModule = "AzSK"
				break
			}
			"Preview"{
				$AzSKModule="AzSKPreview"
				break
			}
			"Staging"{
				$AzSKModule = "AzSKStaging"
			}
		}
		$tempString = $testContext.AzSKSettings.AzSKSettingsFilePath
		$this.AzSKSettingsPath = $global:ExecutionContext.InvokeCommand.ExpandString($tempString)
	}
	[void] Execute()
	{
		switch ($this.testcase.TestMethod)
		{
			"TestSVTDefaultParams"{
				$this.TestSVTDefaultParams()
				break
			}
			"TestSVTTagParamSet"{
				$this.TestSVTTagParamSet()
				break
			}
			"TestSVTResourceParamSet"{
				$this.TestSVTResourceParamSet()
				break
			}
			"TestSVTSubscriptionCoreCommonCommand"{
				$this.TestSVTSubscriptionCoreCommonCommand()
				break
			}
			"TestSetOnlinePolicy"{
				$this.TestSetOnlinePolicy()
				break
			}
			"TestDisableOnlinePolicy"{
				$this.TestDisableOnlinePolicy()
				break
			}
			Default {}
		}
	}
	[TestCaseResult] TestSVTDefaultParams()
	{
		$result = [TestStatus]::Failed;
		$message = ""
		try
		{
			Get-AzSKAzureServicesSecurityStatus -SubscriptionId $this.testContext.TestResources.SubscriptionId -ResourceGroupNames $this.resourceGroupName -ExcludeTags "AzSKCfgControl" -DoNotOpenOutputFolder
			$result = [TestStatus]::Passed;
		}
		catch
		{
			$result = [TestStatus]::Failed;
			$message += "Error occurred while execution. $($_.Exception)";
		}
		$this.testcaseResult = [TestCaseResult]::new($this.testCase, $result, $message)
		return $this.testcaseResult
	}
	[TestCaseResult] TestSVTTagParamSet()
	{
		$result = [TestStatus]::Failed;
		$message = ""

		#add tag
		Set-AzStorageAccount -Name $this.resourceName -ResourceGroupName $this.resourceGroupName -Tag @{"bvtTest"="bvtTestValue"}
		try
		{
			$outputpath = Get-AzSKAzureServicesSecurityStatus -SubscriptionId $this.testContext.TestResources.SubscriptionId `
			-TagName "bvtTest" `
			-TagValue "bvtTestValue" `
			-ExcludeTags "RBAC" -ExcludeTags "AzSKCfgControl" -DoNotOpenOutputFolder
			$isPassed = $false
			if(![string]::IsNullOrEmpty($outputpath))
			{
				$OverallControlStatuscsv = Get-ChildItem -Path $outputpath -Include "SecurityReport-*.csv" -Recurse
				if($OverallControlStatuscsv)
				{
					$result=[TestStatus]::Passed
					$message = "Successfully checked SVT with tag name param set"
				}
			}
		}
		catch
		{
			$message = "Error occurred while running SVT with tag name param set. $($_.Exception)"
		}
		$this.testcaseResult = [TestCaseResult]::new($this.testCase,$result,$message)
		return $this.testcaseResult
	}
	[TestCaseResult] TestSVTResourceParamSet()
	{
		$result = [TestStatus]::Failed;
		$message = ""
		try
		{
			$outputpath = Get-AzSKAzureServicesSecurityStatus -SubscriptionId $this.testContext.TestResources.SubscriptionId `
			-ResourceGroupNames $this.resourceGroupName `
			-ResourceTypeName Storage `
			-ResourceName $this.resourceName `
			-FilterTags "SDL" `
			-ControlIds "Azure_Storage_DP_Encrypt_At_Rest_Blob" -ExcludeTags "AzSKCfgControl" -DoNotOpenOutputFolder
			if(![string]::IsNullOrEmpty($outputpath))
			{
				$OverallControlStatuscsv = Get-ChildItem -Path $outputpath -Include "SecurityReport-*.csv" -Recurse
				if($OverallControlStatuscsv)
				{
					$result = [TestStatus]::Passed
					$message = "Successfully checked SVT with resource filter param set"
				}
				else
				{
					$message = "Error occurred while running SVT with resource filter param set"
				}
			}
			else
			{
				$message = "Error occurred while running SVT with resource filter param set"
			}
		}
		catch
		{
			$message = "Error occurred while running SVT with resource filter param set. $($_.Exception)"
		}
		$this.testcaseResult = [TestCaseResult]::new($this.testCase,$result,$message)
		return $this.testcaseResult
	}
	[TestCaseResult] TestSVTSubscriptionCoreCommonCommand()
	{
		$result = [TestStatus]::Failed
		$message = ""
		$isPassed = $false
		try
		{
			$outputpath = Get-AzSKControlsStatus -SubscriptionId $this.testContext.TestResources.SubscriptionId `
			-ResourceGroupNames $this.resourceGroupName `
			-ResourceTypeName Storage `
			-ResourceName $this.resourceName `
			-FilterTags "SDL" `
			-DoNotOpenOutputFolder

			if(![string]::IsNullOrEmpty($outputpath))
			{
				$OverallControlStatuscsv = Get-ChildItem -Path $outputpath -Include "SecurityReport-*.csv" -Recurse
				if($OverallControlStatuscsv)
				{
					#check if featurename column contains SubscriptionCore and Storage  
					$resultCSV = Import-Csv $OverallControlStatuscsv.FullName
					$subcoreResult = $resultCSV | Where-Object { $_.FeatureName -contains "SubscriptionCore"}
					$resResult = $resultCSV | Where-Object { $_.FeatureName -contains "Storage"}
					if(($subcoreResult|Measure-Object).Count -gt 0 -and ($resResult|Measure-Object).Count -gt 0)
					{
						$result = [TestStatus]::Passed
						$message = "Successfully checked common command for SVT and Subscription Core"
						$isPassed = $true
					}
				}
			}
			if(!$isPassed)
			{
				$message = "Error occurred while running common command for SVT and Subscription Core"
			}	
		}
		catch
		{
			$message = "Error occurred while running common command for SVT and Subscription Core. $($_.Exception)"
		}
		$this.testcaseResult = [TestCaseResult]::new($this.testCase,$result,$message) 
		return $this.testcaseResult
	}
	[TestCaseResult] TestSetOnlinePolicy()
	{
		$result = [TestStatus]::Failed;
		$message = "";
		try
		{
			Set-AzSKPolicySettings -DisableOnlinePolicy
			Set-AzSKPolicySettings -OnlinePolicyStoreUrl $this.OrgPolicyURL -EnableOnlinePolicy
			$fileContent = (Get-Content -Path $this.AzSKSettingsPath) | ConvertFrom-Json;
			if($fileContent.OnlinePolicyStoreUrl -eq $this.OrgPolicyURL -and $fileContent.UseOnlinePolicyStore -eq $true)
			{
				$result = [TestStatus]::Passed;
				$message = "Policy settings have been changed successfully";
			}	
			else
			{
				$message = "Policy settings change was not successful";
			}
		}
		catch
		{
			$message = "Error occurred while setting online policy settings. $($_.Exception)"
		}
		$this.testcaseResult = [TestCaseResult]::new($this.testCase,$result,$message)
		return $this.testcaseResult
	}
	[TestCaseResult] TestDisableOnlinePolicy()
	{
		$result = [TestStatus]::Failed;
		$message = "";
		try
		{
			Set-AzSKPolicySettings -OnlinePolicyStoreUrl $this.OrgPolicyURL
			Set-AzSKPolicySettings -DisableOnlinePolicy
			$fileContent = (Get-Content -Path $this.AzSKSettingsPath) | ConvertFrom-Json;
			if($fileContent.UseOnlinePolicyStore -eq $false)
			{
				$result = [TestStatus]::Passed;
				$message = "Successfully disabled online policy";
			}	
			else
			{
				$message = "Online policy is not disabled";
			}
		}
		catch
		{
			$message = "Error occurred while disabling online policy. $($_.Exception)"
		}
		$this.testcaseResult = [TestCaseResult]::new($this.testCase, $result, $message)
		return $this.testcaseResult
	}
}