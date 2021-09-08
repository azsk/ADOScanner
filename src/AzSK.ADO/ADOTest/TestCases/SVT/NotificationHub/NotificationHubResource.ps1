Set-StrictMode -Version Latest 
class NotificationHubResource:SVTControlTestResource{
	NotificationHubResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
     
    }

	#Setting the properties as required by this resource type.
	[void]SetDerivedResourceProps(){
		#Pick the resource name from Params file if its not null
		if(![string]::IsNullOrEmpty($this.Params)){
				$this.ResourceName = $this.GetResourceNameFromARMJson($this.Params, "resourceName", "value")
			}
		else{
			$this.ResourceName = "azsktestnothubname/azsktestnothub" #Else set the default resource name
		}
		$this.ResourceType = "Microsoft.NotificationHubs/namespaces/notificationHubs" 
	}

	#Assign Default notification policy (without manage)
	[void]RemoveDefaultNotificationPolicy(){
		try{

			if(![string]::IsNullOrEmpty($this.Params)){
				$namespace = $this.GetResourceNameFromARMJson($this.Params, "NameSpace", "value")
			}
		else{
			$namespace = "azsktestnothubname" #Else set the default resource name
		}
			if($this.ProvisioningState -eq "Succeeded"){
					Remove-AzNotificationHubAuthorizationRules -AuthorizationRule DefaultFullSharedAccessSignature `
                                            -ResourceGroup $this.ResourceGroupName `
                                            -Namespace $namespace `
                                            -NotificationHub $this.ResourceName -Force
			}
			}
		catch{
	
			[CommonHelper]::Log("Error while removing default Notification hub policy: " + $this.ResourceName, [MessageType]::Error)
		}
	}
#Remove Notification hub
	[void]RemoveNotificationHubResource(){
		try{

			if(![string]::IsNullOrEmpty($this.Params)){
				$namespace = $this.GetResourceNameFromARMJson($this.Params, "NameSpace", "value")
			}
		else{
			$namespace = "azsktestnothubname" #Else set the default name
		}
			if($this.ProvisioningState -eq "Succeeded"){
				
				$notificationhub=Get-AzResource -ResourceName $this.ResourceName -ResourceGroupName $this.ResourceGroupName
				Remove-AzResource -ResourceId $notificationhub.ResourceId -force
				Remove-AzNotificationHubsNamespace -Namespace $namespace -ResourceGroup $this.ResourceGroupName -Force

			}
			}
		catch{
	
			[CommonHelper]::Log("Error while removing Notification hub resource " + $this.ResourceName, [MessageType]::Error)
		}
	}
	


}
