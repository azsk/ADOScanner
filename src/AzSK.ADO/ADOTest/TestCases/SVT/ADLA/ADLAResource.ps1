Set-StrictMode -Version Latest 
class ADLAResource:SVTControlTestResource{
	[bool] $RetainResource = $false
	[string] $defaultDataLakeStoreName = [string]::empty
	[string] $adlsResourceType = "Microsoft.DataLakeStore/accounts" 
	[bool] $enryptionEnabled = $true
	ADLAResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
     
    }

	#Setting the properties as required by this resource type.
	[void]SetDerivedResourceProps(){
		#Set resource parameters		
		$this.ResourceName = "azskadlatest"+$(get-date -f MMddHHmm) 
		$this.defaultDataLakeStoreName	= "azskadlstest" + $(get-date -f MMddyyHHmm) 
		$this.ResourceType = "Microsoft.DataLakeAnalytics/accounts" 
		if($this.TestCase.TestCaseID -eq "TC_ADLA_PossibleFailed")
		{
			$this.enryptionEnabled = $false
		}
	}
	#Deploys ADLA
	[void] InitializeResource( ){
			$this.DeployADLA()	
    }
	#Deploy ADLA
	[void]DeployADLA(){
		try
		{
			$extraCommand = [string]::Empty
			if($this.enryptionEnabled -eq $false)
			{
				$extraCommand ="-DisableEncryption"
			}
			
			$adlsCreateCommand = "New-AzDataLakeStoreAccount "`
				 +"-ResourceGroupName $($this.ResourceGroupName) "`
				 +"-Name $($this.defaultDataLakeStoreName) "`
				 +"-Location $($this.Location) "`
				 +$extraCommand`
				 +" -WarningAction SilentlyContinue"`
				 

			$adls = Invoke-Expression $adlsCreateCommand

			if($adls.ProvisioningState -eq "Succeeded")
			{
				[CommonHelper]::Log("Default data lake store deployed successfully " + $this.defaultDataLakeStoreName, [MessageType]::Information)
				
				$adla = New-AzDataLakeAnalyticsAccount `
				 -Name $this.ResourceName `
				 -ResourceGroupName $this.ResourceGroupName `
				 -Location $this.Location `
				 -DefaultDataLake $this.defaultDataLakeStoreName `
				 -WarningAction SilentlyContinue				 

				$this.ProvisioningState = $adla.ProvisioningState
				if($this.ProvisioningState -eq "Succeeded")
				{
					[CommonHelper]::Log("ADLA deployed successfully " + $this.ResourceName, [MessageType]::Information)
				}
			}
			else
			{
				throw
			}
		}
		catch{
			[CommonHelper]::Log("Error while deploying Data Lake Analytics: " + $this.ResourceName, [MessageType]::Error)
		}
	}
	
	#Set Diagnostics on
	[void]SetADLADiagnosticsOn(){
		try{
			if($this.ProvisioningState -eq "Succeeded"){
			$adlaresource = Get-AzResource -ResourceName $this.ResourceName -ResourceGroupName $this.ResourceGroupName
				$storageAccount=$this.IfCommonStorageExists()
                if(!$storageAccount){
                      $this.CreateCommonStorage()
                }  			
	

			Set-AzDiagnosticSetting -ResourceId $adlaresource.resourceid -Enabled $true -StorageAccountId $this.Settings.CommonStorageAcctId 
			$this.ProvisioningState = "Succeeded"
		}
			}
		catch{
		$this.ProvisioningState = "Failed"
			[CommonHelper]::Log("Error while setting the diagnostics on for: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Set Diagnostics off
	[void]SetADLADiagnosticsOff(){
		try{
			if($this.ProvisioningState -eq "Succeeded"){
			$adlaresource = Get-AzResource -ResourceName $this.ResourceName -ResourceGroupName $this.ResourceGroupName
			Set-AzDiagnosticSetting -ResourceId $adlaresource.resourceid -Enabled $false 
			$this.ProvisioningState = "Succeeded"
		}
			}
		catch{
		$this.ProvisioningState = "Failed"
			[CommonHelper]::Log("Error while setting the diagnostics on for: " + $this.ResourceName, [MessageType]::Error)
		}
	}

}
