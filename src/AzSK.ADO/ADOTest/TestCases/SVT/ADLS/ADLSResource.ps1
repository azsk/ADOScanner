Set-StrictMode -Version Latest 
class ADLSResource:SVTControlTestResource{
	[bool] $RetainResource = $false	
	[bool] $enryptionEnabled = $true
	ADLSResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
      }

	#Setting the properties as required by this resource type.
	[void]SetDerivedResourceProps(){
		#Set resource parameters
		$this.ResourceName	= "azskadlstest" + $(get-date -f MMddyyHHmm) 
		$this.ResourceType = "Microsoft.DataLakeStore/accounts" 
		if($this.TestCase.TestCaseID -eq "TC_ADLS_PossibleFailed")
		{
			$this.enryptionEnabled = $false
		}
		
	}
		#Deploys ADLS
	[void] InitializeResource(){
			$this.DeployADLS()	
    }
	#Deploy ADLS
	[void]DeployADLS(){
		try
		{
			$extraCommand = [string]::Empty
			if($this.enryptionEnabled -eq $false)
			{
				$extraCommand ="-DisableEncryption"
			}
			
			$adlsCreateCommand = "New-AzDataLakeStoreAccount "`
				 +"-ResourceGroupName $($this.ResourceGroupName) "`
				 +"-Name $($this.ResourceName) "`
				 +"-Location $($this.Location) "`
				 +$extraCommand`
				 +" -WarningAction SilentlyContinue"
				
			$adls = Invoke-Expression $adlsCreateCommand
			$this.ProvisioningState = $adls.ProvisioningState
		[CommonHelper]::Log("Data lake store deployed successfully " + $this.ResourceName, [MessageType]::Information)				
			
		}
		catch{
			[CommonHelper]::Log("Error while deploying Data Lake Store: " + $this.ResourceName, [MessageType]::Error)
		}
	}
	#Cleanup the resource
	#Set Diagnostics on
	[void]SetDiagnosticsOn(){
		try{
			if($this.ProvisioningState -eq "Succeeded"){
			$adlsresource = Get-AzResource -ResourceName $this.ResourceName -ResourceGroupName $this.ResourceGroupName
			Set-AzDiagnosticSetting -ResourceId $adlsresource.resourceid -Enabled $true -StorageAccountId $this.Settings.CommonStorageAcctId
			$this.ProvisioningState = "Succeeded"
		}
			}
		catch{
		$this.ProvisioningState = "Failed"
			[CommonHelper]::Log("Error while setting the diagnostics settings for: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Set firewall
	[void]EnableFirewall(){
		try{
			if($this.ProvisioningState -eq "Succeeded")
			{	
				Set-AzDataLakeStoreAccount -Name $this.ResourceName -FirewallState Enabled		
				$this.ProvisioningState = "Succeeded"
			}
		}
		catch{
		$this.ProvisioningState = "Failed"
			[CommonHelper]::Log("Error while setting firewall for: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#set firewall rule to verify

	[void]SetFirewallRule(){
		try{
			if($this.ProvisioningState -eq "Succeeded")
			{
				$this.EnableFirewall();				
				Add-AzDataLakeStoreFirewallRule -Account $this.ResourceName -Name rule1 -StartIpAddress "0.0.0.0" -EndIpAddress "0.0.0.0"
				$this.ProvisioningState = "Succeeded"
			}
		}
		catch{
		$this.ProvisioningState = "Failed"
			[CommonHelper]::Log("Error while setting firewall rule for: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Make ACL Entry
	[void]SetAclEntry(){
		try{
			Set-AzDataLakeStoreItemAclEntry -Account $this.ResourceName -Path "/" -Permissions All -AceType Other
			$this.ProvisioningState = "Succeeded"
		}
		catch{
		$this.ProvisioningState = "Failed"
			[CommonHelper]::Log("Error while setting the ACL Entry for: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Set Diagnostics off
	[void]SetDiagnosticsOff(){
		try{
			$adlsresource = Get-AzResource -ResourceName $this.ResourceName -ResourceGroupName $this.ResourceGroupName
			Set-AzDiagnosticSetting -ResourceId $adlsresource.resourceid -Enabled $false
			$this.ProvisioningState = "Succeeded"
		}
		catch{
		$this.ProvisioningState = "Failed"
			[CommonHelper]::Log("Error while setting the diagnostics off for: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	
	#Disable firewall 
	[void]DisableFirewall(){
		try{
			if($this.ProvisioningState -eq "Succeeded")
			{
				$PropertiesObject = @{"firewallState" = "Disabled"}			
				Set-AzResource -PropertyObject $PropertiesObject -ResourceGroupName $this.ResourceGroupName -ResourceName $this.ResourceName -Force
				$this.ProvisioningState = "Succeeded"
			}
		}	
		catch{
		$this.ProvisioningState = "Failed"
			[CommonHelper]::Log("Error while disabling firewall for : " + $this.ResourceName, [MessageType]::Error)
		}	
	}

	#Remove other ACL
	[void]RemoveACLOtherAccess(){
		try{
			if($this.ProvisioningState -eq "Succeeded")
			{
				Remove-AzDataLakeStoreItemAcl -Account $this.ResourceName -Path "/" -Force
				$this.ProvisioningState = "Succeeded"
			}
		}	
		catch{
		$this.ProvisioningState = "Failed"
			[CommonHelper]::Log("Error while disabling firewall for : " + $this.ResourceName, [MessageType]::Error)
		}	
	}

	

}