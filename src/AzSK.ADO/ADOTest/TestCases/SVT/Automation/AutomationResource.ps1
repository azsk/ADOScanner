Set-StrictMode -Version Latest 
class AutomationResource:SVTControlTestResource{
	[bool] $RetainResource = $false	
	[string] $RunbookName = "TestSuiteRunbook"
	AutomationResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
      }

	#Setting the properties as required by this resource type.
	[void]SetDerivedResourceProps()
	{
		#Set resource parameters
		$this.ResourceName	= "automationaccount" + $(get-date -f MMddyyHHmm) 
		$this.ResourceType = "Microsoft.Automation/automationAccounts" 
	}
	[void] InitializeResource()
	{
		$this.DeployAutomationRunbook()	
    }
	#Deploy Automation
	[void] DeployAutomationRunbook()
	{
		try
		{
			$automationAccount = New-AzAutomationAccount `
				 -ResourceGroupName $this.ResourceGroupName `
				 -Name $this.ResourceName `
				 -Location $this.Location `
				 -Plan Free -ErrorAction Stop
			$runbook = New-AzAutomationRunbook -AutomationAccountName $this.ResourceName -Name $this.RunbookName -ResourceGroupName $this.ResourceGroupName -Type PowerShell -ErrorAction Stop
			Publish-AzAutomationRunbook -AutomationAccountName $this.ResourceName -Name $this.RunbookName -ResourceGroupName $this.ResourceGroupName -ErrorAction Stop
			$this.ProvisioningState = "Succeeded"
			[CommonHelper]::Log("Automation account deployed successfully " + $this.ResourceName, [MessageType]::Information)
		}
		catch
		{
			$this.ProvisioningState = "Failed"
			[CommonHelper]::Log("Error while deploying Automation account: " + $this.ResourceName, [MessageType]::Error)
		}
	}
	#Set valid webhook
	[void] SetValidWebhook()
	{
		try{
			if($this.ProvisioningState -eq "Succeeded")
			{
				$AutomationResource = Get-AzResource -ResourceName $this.ResourceName -ResourceGroupName $this.ResourceGroupName -ErrorAction Stop
				
				 New-AzAutomationWebhook -AutomationAccountName $this.ResourceName -ExpiryTime $(get-date).AddDays(10) `
				-IsEnabled $true -Name "TestSuiteWebhook" -ResourceGroupName $this.ResourceGroupName `
				-RunbookName $this.RunbookName -Force -ErrorAction Stop
	    	}
		}
		catch
		{
			$this.ProvisioningState = "Failed"
			[CommonHelper]::Log("Error while setting the webhook for: " + $this.ResourceName, [MessageType]::Error)
		}
	}
	#Set encrypted variables
	[void] SetEncryptedVariables(){
		try{
			if($this.ProvisioningState -eq "Succeeded")
			{	
				New-AzAutomationVariable -Name "variable1" -Encrypted $true -Value "variable1" -ResourceGroupName $this.ResourceGroupName -AutomationAccountName $this.ResourceName -ErrorAction Stop
				New-AzAutomationVariable -Name "variable2" -Encrypted $true -Value "variable2" -ResourceGroupName $this.ResourceGroupName -AutomationAccountName $this.ResourceName 
			}
		}
		catch{
		$this.ProvisioningState = "Failed"
			[CommonHelper]::Log("Error while creating encrypted variables for: " + $this.ResourceName, [MessageType]::Error)
		}
	}
	#Set invalid webhook
	[void] SetInvalidWebhook()
	{
		try{
			if($this.ProvisioningState -eq "Succeeded")
			{
				$AutomationResource = Get-AzResource -ResourceName $this.ResourceName -ResourceGroupName $this.ResourceGroupName -ErrorAction Stop
				
				 New-AzAutomationWebhook -AutomationAccountName $this.ResourceName -ExpiryTime $(get-date).AddDays(90) `
				-IsEnabled $true -Name "TestSuiteWebhook" -ResourceGroupName $this.ResourceGroupName `
				-RunbookName $this.RunbookName -Force -ErrorAction Stop
	    	}
		}
		catch
		{
			$this.ProvisioningState = "Failed"
			[CommonHelper]::Log("Error while setting the webhook for: " + $this.ResourceName, [MessageType]::Error)
		}
	}
	#Set unencrypted variables
	[void] SetUnencryptedVariables()
	{
		try{
			if($this.ProvisioningState -eq "Succeeded")
			{	
				New-AzAutomationVariable -Name "variable1" -Encrypted $false -Value "variable1" -ResourceGroupName $this.ResourceGroupName -AutomationAccountName $this.ResourceName -ErrorAction Stop
				New-AzAutomationVariable -Name "variable2" -Encrypted $false -Value "variable2" -ResourceGroupName $this.ResourceGroupName -AutomationAccountName $this.ResourceName 
			}
		}
		catch{
		$this.ProvisioningState = "Failed"
			[CommonHelper]::Log("Error while creating encrypted variables for: " + $this.ResourceName, [MessageType]::Error)
		}
	}
}