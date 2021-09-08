Set-StrictMode -Version Latest 
class ServiceBusResource:SVTControlTestResource{

	hidden [PSObject] $QueueName = 'azsktestqueue';
	hidden [PSObject] $QueueAuthRule = 'queueSend';
	hidden [PSObject] $QueueAuthRulePermission = 'Send';

	ServiceBusResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
     
    }

#Setting the properties as required by this resource type.
	[void]SetDerivedResourceProps(){
		$this.ResourceName = "azsktestservicebus" #Else set the default resource name
		$this.ResourceType = "Microsoft.ServiceBus/namespaces" 
	}

	#Checks and deploys the service bus if it does not exist.
	[void] InitializeResource( ){
		if(!$this.IfResourceExists()){
			$this.DeployServiceBus()	
		}
    }

	#Deploy the service bus
	[void]DeployServiceBus()
	{
		try
		{
			$nameSpace = New-AzServiceBusNamespace -Location "Southeast Asia" -ResourceGroupName $this.ResourceGroupName `
					-NamespaceName $this.ResourceName -SkuName Basic
			$this.ProvisioningState = $nameSpace.ProvisioningState
			if($nameSpace.ProvisioningState -eq "Succeeded")
			{
				[CommonHelper]::Log("NameSpace "+$this.ResourceName + " is successfully deployed", [MessageType]::Information)
				New-AzServiceBusQueue -ResourceGroup $this.ResourceGroupName -NamespaceName $this.ResourceName -QueueName $this.QueueName -EnablePartitioning $false
			}
		}
		catch{
			[CommonHelper]::Log("Error while deploying the Service Bus: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Set Service bus access policies
	[void]AddQueueAccessPolicies()
	{
		try
		{
			New-AzServiceBusAuthorizationRule -ResourceGroup $this.ResourceGroupName -NamespaceName $this.ResourceName `
							-Queue $this.QueueName -Rights $this.QueueAuthRulePermission
			[CommonHelper]::Log("Successfully set the authorization rules for queue: "+$this.QueueName, [MessageType]::Information)
		}
		catch
		{
			[CommonHelper]::Log("Error while setting authorization rules for queue: " + $this.QueueName, [MessageType]::Error)
		}
	}

	#Remove service bus access policies
	[void]RemoveQueueAccessPolicies()
	{
		try
		{
			$queuePolicies = Get-AzServiceBusAuthorizationRule -ResourceGroup $this.ResourceGroupName `
										-NamespaceName $this.ResourceName -Queue $this.QueueName
			if(($queuePolicies|Measure-Object).count -gt 0)
			{
				$queuePolicies | ForEach-Object{
						Remove-AzServiceBusAuthorizationRule -ResourceGroup $this.ResourceGroupName `
							-NamespaceName $this.ResourceName -Queue $this.QueueName
				}
			}

			[CommonHelper]::Log("Successfully removed access policy from queue: "+$this.QueueName, [MessageType]::Information)
		}
		catch
		{
			[CommonHelper]::Log("Error while removing access policy from queue: " + $this.QueueName, [MessageType]::Error)
		}
	}
}