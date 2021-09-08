Set-StrictMode -Version Latest 
class LogicAppsResource:SVTControlTestResource{
	LogicAppsResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
     
    }

	#Setting the properties as required by this resource type.
	[void]SetDerivedResourceProps(){
		#Pick the resource name from Params file if its not null		
		$this.ResourceName = $this.GetResourceNameFromARMJson($this.Params, "resourceName", "value")		
		$this.ResourceType = "Microsoft.Logic/workflows" 
	}

	
	#Set Diagnostics on
	[void]SetLogicAppDiagnosticsOn(){
		try{
			if($this.ProvisioningState -eq "Succeeded"){
			 $storageAccount=$this.IfCommonStorageExists()
                            if(!$storageAccount){
                                            $this.CreateCommonStorage()
								    }
			  $diagnosticStorageAccountId = (Get-AzResource -ResourceName $this.settings.CommonStorageAcctName -ResourceGroupName $this.ResourceGroupName).ResourceId

			$LogicAppResource = Get-AzResource -ResourceName $this.ResourceName -ResourceGroupName $this.ResourceGroupName
			Set-AzDiagnosticSetting -ResourceId $LogicAppResource.resourceid -Enabled $true -StorageAccountId $this.Settings.CommonStorageAcctId 
			$this.ProvisioningState = "Succeeded"
		}
			}
		catch{
			[CommonHelper]::Log("Error while setting the diagnostics on for: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Set Invalid access control for content and trigger
	[void]SetLogicAppInvalidAccessControl(){
		try{
			if($this.ProvisioningState -eq "Succeeded")
			{
				$propJson = @{"contents"= @{"allowedCallerIpAddresses"=@(@{
				"addressRange"="0.0.0.0-255.255.255.255"
				})};}
				$resource=Get-AzResource -ResourceGroupName $this.ResourceGroupName -Name $this.ResourceName -ResourceType $this.ResourceType
				$resource.properties | Add-Member -type NoteProperty -name accessControl -value $propJson
				
				Set-AzResource -PropertyObject $resource.properties -ResourceGroupName $this.ResourceGroupName -ResourceName $this.ResourceName -ResourceType $this.ResourceType -Force
				$this.ProvisioningState = "Succeeded"
				
			}
		}
		catch{
		$this.ProvisioningState = "Failed"
			[CommonHelper]::Log("Error while setting Access Control Triggers for: " + $this.ResourceName, [MessageType]::Error)
		}
				

			
	}
	#Set Valid access control for content and trigger
	[void]SetLogicAppValidAccessControl(){
		try{
			if($this.ProvisioningState -eq "Succeeded")
			{
				$propJson = @{"contents"= @{"allowedCallerIpAddresses"=@(@{
				"addressRange"="0.0.0.0-0.0.0.0"
				})};
				"triggers"= @{"allowedCallerIpAddresses"=@(@{
				"addressRange"="0.0.0.0-0.0.0.0"
				})};
				}
				$resource=Get-AzResource -ResourceGroupName $this.ResourceGroupName -Name $this.ResourceName -ResourceType $this.ResourceType
				$resource.properties | Add-Member -type NoteProperty -name accessControl -value $propJson
				
				Set-AzResource -PropertyObject $resource.properties -ResourceGroupName $this.ResourceGroupName -ResourceName $this.ResourceName -ResourceType $this.ResourceType -Force
				$this.ProvisioningState = "Succeeded"
				
			}
		}
		catch{
		$this.ProvisioningState = "Failed"
			[CommonHelper]::Log("Error while setting Access Control Triggers for: " + $this.ResourceName, [MessageType]::Error)
		}
				

			
	}
	#Set Diagnostics off
	[void]SetLogicAppDiagnosticsOff(){
		try{
			if($this.ProvisioningState -eq "Succeeded"){
			$LogicAppResource = Get-AzResource -ResourceName $this.ResourceName -ResourceGroupName $this.ResourceGroupName
			Set-AzDiagnosticSetting -ResourceId $LogicAppResource.resourceid -Enabled $false
			$this.ProvisioningState = "Succeeded"
			}
		}
		catch{
			[CommonHelper]::Log("Error while setting the diagnostics off for: " + $this.ResourceName, [MessageType]::Error)
		}
	}
	#clear access control
	[void]RemoveLogicAppAccessControl(){
		try{
			if($this.ProvisioningState -eq "Succeeded")
			{
				
				$resource=Get-AzResource -ResourceGroupName $this.ResourceGroupName -Name $this.ResourceName -ResourceType $this.ResourceType
				$resource.Properties=$resource.Properties | Select-Object -Property * -ExcludeProperty AccessControl
				
				Set-AzResource -PropertyObject $resource.properties -ResourceGroupName $this.ResourceGroupName -ResourceName $this.ResourceName -ResourceType $this.ResourceType -Force
				$this.ProvisioningState = "Succeeded"
				
			}
		}
		catch{
		$this.ProvisioningState = "Failed"
			[CommonHelper]::Log("Error while resetting Access Control for: " + $this.ResourceName, [MessageType]::Error)
		}
						
	}
	
}
