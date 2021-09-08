Set-StrictMode -Version Latest 
class SSProvisioningTest:AzSKTestBase{
	[string]$AlertsRGName = "AzSKRG" #This is the standard name used by AzSK for Alerts RG.
	SSProvisioningTest([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
     
    }

	[void] Execute(){

		switch ($this.testcase.TestMethod){
				"TestSetAzSKAlerts"{
					$this.TestSetAzSKAlerts()
					break
				}
				"TestRemoveAzSKAlertsJustOne"{
					$this.TestRemoveAzSKAlertsJustOne()
					break
				}
				"TestRemoveAzSKAlerts"{
					$this.TestRemoveAzSKAlerts()
					break
				}
				"TestSetAzSKARMPolicies"{
					$this.TestSetAzSKARMPolicies()
					break
				}
				"TestRemoveAzSKARMPolicies"{
					$this.TestRemoveAzSKARMPolicies()
					break
				}
				"TestSetAzSKRBAC"{
					$this.TestSetAzSKRBAC()
				}
				"TestRemoveAzSKRBAC"{
					$this.TestRemoveAzSKRBAC()
				}
				Default {
					
				}
		}
	}

	[TestCaseResult] TestSetAzSKAlerts(){
		try{		
			
			if($this.SetAzSKAlertTestPrerequisite([AlertPrerequisites]::RemoveAlerts))
			{
				Set-AzSKAlerts -SubscriptionId $this.testContext.TestResources.SubscriptionId -SecurityContactEmails "abc@microsoft.com" -DoNotOpenOutputFolder
				#Expected control status for id Azure_Subscription_Audit_Configure_Critical_Alerts should be Passed 
				$this.testcaseResult = $this.GetControlIdStatus("Azure_Subscription_Audit_Configure_Critical_Alerts",[TestStatus]::Passed)	
			}
			else
			{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Unable to set prerequisite for test case.")
			}
		}
		catch{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Error while setting AzSK Alerts.")
		}
		return $this.testcaseResult
	}

	[TestCaseResult] TestRemoveAzSKAlertsJustOne(){
		try{
			#Validate if alerts are present on subscriptions
			if($this.SetAzSKAlertTestPrerequisite([AlertPrerequisites]::SetAlerts))
			{
				Remove-AzSKAlerts -SubscriptionId $this.testContext.TestResources.SubscriptionId -AlertNames $this.settings.AlertName
				$alertResource = Get-AzResource -ResourceType "Microsoft.Insights/activityLogAlerts" -ResourceGroupName $this.AlertsRGName Get-AzResource -ResourceType "Microsoft.Insights/activityLogAlerts" -ResourceGroupName $this.AlertsRGName -ResourceName $this.settings.AlertName -ErrorAction Ignore
				if($null -eq $alertResource)
				{
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully removed only one alert.")
				}
				else{
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Remove-AzSKAlerts with alertName must remove just that alert.")
				}
			}
			else
			{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Unable to set prerequisite for test case.")
			}
		}
		catch{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Error while removing desired AzSK Alert.")
		}

		return $this.testcaseResult
	}

	[TestCaseResult] TestRemoveAzSKAlerts(){
		 
		try
		{ 			
			#Set prerequisite by setting alerts
			if($this.SetAzSKAlertTestPrerequisite([AlertPrerequisites]::SetAlerts))
			{
				Remove-AzSKAlerts -SubscriptionId $this.testContext.TestResources.SubscriptionId -Tags "Mandatory"
				$alertResource = $this.GetAzSKAlertsList()
				if($null -eq $alertResource)
				{
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully removed all alerts.")
				}
				else{
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Remove-AzSKAlerts not removed all alerts.")
				}
			}
			else
			{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Unable to set prerequisite for test case.")
			}
		}
		catch
		{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Error while removing AzSK Alerts.")
		}
		return $this.testcaseResult
	}




	[TestCaseResult] GetControlIdStatus([string] $ControlId,[TestStatus] $expectedStatus)
	{
		$testcaseResult = $null
		$subScanPath = Get-AzSKSubscriptionSecurityStatus -SubscriptionId $this.testContext.TestResources.SubscriptionId -ControlIds $ControlId  -DoNotOpenOutputFolder
		$securityReportFile = (Get-ChildItem $subScanPath  -Recurse -Include "SecurityReport*") | Select-Object -First 1 
		$testResult = [TestStatus]::Failed
		if($securityReportFile.FullName)
		{
			$testResult = Get-Content $securityReportFile.FullName | ConvertFrom-Csv | Where-Object ControlID -EQ $ControlId | Select-Object Status
			if($null -ne $testResult -and  $testResult.Status -eq $expectedStatus)
			{
				$testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully verified expected status '$expectedStatus' for control id $ControlId")
			}
			else{
				$testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Not able to verify expected status '$expectedStatus' for control id $ControlId")
			}			
		}
		else
		{
			$testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Not able to verify status as get scan not exported report")
		}
		return $testcaseResult
	}
	[bool] SetAzSKAlertTestPrerequisite([AlertPrerequisites] $alertPreq)
	{
		$IsPrerequisiteSet = $false
		$alertsRG = Get-AzResourceGroup -Name $this.AlertsRGName -ErrorAction Ignore
		$existingalerts= $null
		if($alertsRG)
		{
			$existingalerts = $this.GetAzSKAlertsList()
		}
		
		switch($alertPreq)
		{
			"RemoveAlerts" 
				{
					#Validate if AzSK alerts are already present and remove alerts if exists										
					if(($existingalerts | Measure-Object).Count -ne '0')
					{
						Remove-AzSKAlerts -SubscriptionId $this.testContext.TestResources.SubscriptionId -Tags 'Mandatory' -DoNotOpenOutputFolder
						#Validate if all alerts are removed
						$alerttlist = $this.GetAzSKAlertsList()
						if($null -eq $alerttlist -or ($alerttlist | Measure-Object) -eq 0)
						{
							return $true	
						}											
					}
					else
					{
						return $true
					}				
				}
			"SetAlerts"
				{
					if(($existingalerts | Measure-Object).Count -eq 0)
					{
						Set-AzSKAlerts -SubscriptionId $this.testContext.TestResources.SubscriptionId -SecurityContactEmails $this.settings.SecurityPOCEmail -DoNotOpenOutputFolder
						#Validate if all alerts are set
						if(($null -ne $this.GetAzSKAlertsList()) )
						{
							return $true	
						}	
					}
					else
					{
						return $true
					}
				}
			}
		return $IsPrerequisiteSet
	}

	[PSObject] GetAzSKAlertsList()
	{
		return Get-AzResource -ResourceType "Microsoft.Insights/activityLogAlerts" -ResourceGroupName $this.AlertsRGName  -ErrorAction Ignore
	}

	

	[TestCaseResult[]] TestSetAzSKARMPolicies(){
		try{
				$ExistingPolicy = [array](Get-AzPolicyAssignment -Name "AzSK_ARMPol_Deny_Classic_Resource_Create")
				
				if(($ExistingPolicy | Measure-Object ).count  -ge "1")
				{
					try{
						Remove-AzSKARMPolicies -SubscriptionId $this.testContext.TestResources.SubscriptionId -Tags 'Mandatory' -DoNotOpenOutputFolder
					}
					catch
					{
						#error while removing ARM policies
					}
				}
			    Set-AzSKARMPolicies -SubscriptionId $this.testContext.TestResources.SubscriptionId -DoNotOpenOutputFolder
				$tstPol = [array](Get-AzPolicyAssignment -Name "AzSK_ARMPol_Deny_Classic_Resource_Create")
				
				if(($tstPol | Measure-Object ).count  -ge "1"){
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully set the AzSK ARM policy.")
				}   
				else{
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Failed to set the AzSK ARM policy.")
				} 

		}
		catch{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Error while setting AzSK ARM policy.")
		}

		return $this.testcaseResult
	}

	[TestCaseResult[]] TestRemoveAzSKARMPolicies(){
		try{
			$ExistingPolicy = [array](Get-AzPolicyAssignment -Name "AzSK_ARMPol_Deny_Classic_Resource_Create") 
			if( ($ExistingPolicy | Measure-Object ).count  -eq "0")
				{
				try{
						Set-AzSKARMPolicies -SubscriptionId $this.testContext.TestResources.SubscriptionId -DoNotOpenOutputFolder
					}
					catch
					{
						#error while removing ARM policies
					}
				}
			Remove-AzSKARMPolicies -SubscriptionId $this.testContext.TestResources.SubscriptionId -Tags 'Mandatory' -DoNotOpenOutputFolder
			
			$tstPol = [array](Get-AzPolicyAssignment -Name "AzSK_ARMPol_Deny_Classic_Resource_Create")
			
			if(($tstPol | Measure-Object ).count  -eq "0"){
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully removed the AzSK ARM policy.")
				}   
				else{
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Failed to remove the AzSK ARM policy.")
				} 
		}
		catch{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Error while removing AzSK ARM policy.")
		}

		return $this.testcaseResult
	}

	[TestCaseResult[]] TestSetAzSKRBAC(){
		try{
			$ExistingPolicy = [array](Get-AzRoleAssignment -ObjectId "8bf9deaf-393c-47b4-805f-e4948428320d") 
			
			if( ($ExistingPolicy | Measure-Object ).count  -ge "1")
				{
				
					try{
						Remove-AzSKSubscriptionRBAC -SubscriptionId $this.testContext.TestResources.SubscriptionId -Tags 'Mandatory' -DoNotOpenOutputFolder -Tags 'Mandatory'	
					}
					catch
					{
						#error while removing ARM policies
					}

				}
				Set-AzSKSubscriptionRBAC -SubscriptionId $this.testContext.TestResources.SubscriptionId -DoNotOpenOutputFolder
				
			
			    $tstPol = [array](Get-AzRoleAssignment -ObjectId "8bf9deaf-393c-47b4-805f-e4948428320d")
			
			if(($tstPol| Measure-Object ).count  -ge "1"){
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully Set RBAC.")
				}   
				else{
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Failed to set RBAC")
				} 
		}
		catch{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Error while setting RBAC")
		}

		return $this.testcaseResult
	}

	[TestCaseResult[]] TestRemoveAzSKRBAC(){
		try{
			$ExistingPolicy = [array](Get-AzRoleAssignment -ObjectId "8bf9deaf-393c-47b4-805f-e4948428320d") 
			
			if( ($ExistingPolicy | Measure-Object ).count  -eq "0")
				{
				
					try{
						Set-AzSKSubscriptionRBAC -SubscriptionId $this.testContext.TestResources.SubscriptionId -DoNotOpenOutputFolder
					}
					catch
					{
						#error while removing ARM policies
					}

				}
				Remove-AzSKSubscriptionRBAC -SubscriptionId $this.testContext.TestResources.SubscriptionId -Tags 'Mandatory' -DoNotOpenOutputFolder
			
			    $tstPol = [array](Get-AzRoleAssignment -ObjectId "8bf9deaf-393c-47b4-805f-e4948428320d")
			
			if(($tstPol| Measure-Object ).count  -eq "0"){
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully Remove RBAC.")
				}   
				else{
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Failed to Remove RBAC")
				} 
		}
		catch{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Error while setting RBAC")
		}

		return $this.testcaseResult
	}


}

enum AlertPrerequisites{
		SetAlerts
		RemoveAlerts
	}