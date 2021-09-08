Set-StrictMode -Version Latest 
class EventHubResource:SVTControlTestResource{

	hidden [PSObject] $EventHubName = 'azsktestEventHub';
	hidden [PSObject] $EventHubAuthRule = 'ehSend';
	hidden [PSObject] $EventHubAuthRulePermission = 'Send';

	EventHubResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
     
    }

#Setting the properties as required by this resource type.
	[void]SetDerivedResourceProps(){
		$this.ResourceName = "azsktestEHNamespace" #Else set the default resource name
		$this.ResourceType = "Microsoft.Eventhub/namespaces" 
	}

	#Checks and deploys the service bus if it does not exist.
	[void] InitializeResource( ){
		if(!$this.IfResourceExists()){
			$this.DeployEventHub()	
		}
    }

	#Deploy the event hub
	[void]DeployEventHub()
	{
		try
		{
			$nameSpace = New-AzEventHubNamespace -Location "Southeast Asia" -ResourceGroupName $this.ResourceGroupName `
					-NamespaceName $this.ResourceName -SkuName Basic
			if($nameSpace.ProvisioningState -eq "Succeeded")
			{
				[CommonHelper]::Log("Event Hub NameSpace "+$this.ResourceName + " is successfully deployed", [MessageType]::Information)
				New-AzEventHub -Location "Southeast Asia" -ResourceGroupName $this.ResourceGroupName -NamespaceName $this.ResourceName -EventHubName $this.EventHubName
			}
		}
		catch{
			[CommonHelper]::Log("Error while deploying the Event Hub: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Set Service bus access policies
	[void]AddEventHubAccessPolicies()
	{
		try
		{
			New-AzEventHubAuthorizationRule -ResourceGroupName $this.ResourceGroupName -NamespaceName $this.ResourceName `
							-EventHubName $this.EventHubName -AuthorizationRuleName $this.EventHubAuthRule -Rights $this.EventHubAuthRulePermission
			[CommonHelper]::Log("Successfully set the authorization rules for Event Hub: "+$this.EventHubName, [MessageType]::Information)
		}
		catch
		{
			[CommonHelper]::Log("Error while setting authorization rules for Event Hub: " + $this.EventHubName, [MessageType]::Error)
		}
	}

	#Remove service bus access policies
	[void]RemoveEventHubAccessPolicies()
	{
		try
		{
			$ehPolicies = Get-AzEventHubAuthorizationRule -ResourceGroupName $this.ResourceGroupName `
										-NamespaceName $this.ResourceName -EventHubName $this.EventHubName
			if(($ehPolicies|Measure-Object).count -gt 0)
			{
				$ehPolicies | ForEach-Object{
						Remove-AzEventHubAuthorizationRule -ResourceGroupName $this.ResourceGroupName `
							-NamespaceName $this.ResourceName -EventHubName $this.EventHubName -AuthorizationRuleName $_.Name
				}
			}

			[CommonHelper]::Log("Successfully removed access policy from Event Hub: "+$this.EventHubName, [MessageType]::Information)
		}
		catch
		{
			[CommonHelper]::Log("Error while removing access policy from Event Hub: " + $this.EventHubName, [MessageType]::Error)
		}
	}
}