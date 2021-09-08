Set-StrictMode -Version Latest 
class LoadBalancerResource:SVTControlTestResource{

	hidden [PSObject] $LBLocation = 'East US';

	hidden [PSObject] $SubnetName = 'AzSKTest-LB-Subnet';
	hidden [PSObject] $VirtualNetworkName = 'AzSKTest-LB-VNet';

	hidden [PSObject] $PublicIPName = 'AzSKTest-LB-PublicIP';
	hidden [PSObject] $PublicIPDNS = 'azsktestlbpublicip';

	hidden [PSObject] $FrontEndIPName = 'AzSKTest-LB-Frontend';
	hidden [PSObject] $BackEndIPName = 'AzSKTest-LB-backend';

	hidden [PSObject] $inboundNATRule1Name = 'AzSKTest-LB-RDP1';
	hidden [PSObject] $inboundNATRule2Name = 'AzSKTest-LB-RDP2';

	hidden [PSObject] $HealthProbName = 'AzSKTest-LB-HealthProbe';
	hidden [PSObject] $LBRuleName = 'AzSKTest-LB-HTTP';
	

	LoadBalancerResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
     
    }

#Setting the properties as required by this resource type.
	[void]SetDerivedResourceProps(){
		$this.ResourceName = "AzSKTest-LB" #Else set the default resource name
		$this.ResourceType = "Microsoft.Network/loadBalancers" 
	}

	#Checks and deploys the load balancer if it does not exist.
	[void] InitializeResource(){
		if(!$this.IfResourceExists()){
			$this.DeployLoadBalancer()	
		}
    }

	#Deploy the LoadBalancer
	[void]DeployLoadBalancer()
	{
		try
		{
			
			$publicIP = $this.DeployPublicIP()

			# Create a front-end IP pool and a back-end address pool
			$frontendIP = New-AzLoadBalancerFrontendIpConfig -Name $this.FrontEndIPName -PublicIpAddress $publicIP
			$beaddresspool = New-AzLoadBalancerBackendAddressPoolConfig -Name $this.BackEndIPName

			# Create the NAT rules.
			$inboundNATRule1= New-AzLoadBalancerInboundNatRuleConfig -Name $this.inboundNATRule1Name -FrontendIpConfiguration $frontendIP -Protocol TCP -FrontendPort 3441 -BackendPort 3389
			$inboundNATRule2= New-AzLoadBalancerInboundNatRuleConfig -Name $this.inboundNATRule2Name -FrontendIpConfiguration $frontendIP -Protocol TCP -FrontendPort 3442 -BackendPort 3389

			# Create a health probe. There are two ways to configure a probe:
			$healthProbe = New-AzLoadBalancerProbeConfig -Name $this.HealthProbName -RequestPath 'HealthProbe.aspx' -Protocol http -Port 80 -IntervalInSeconds 15 -ProbeCount 2

			# TCP Prob
			$healthProbe = New-AzLoadBalancerProbeConfig -Name $this.HealthProbName -Protocol Tcp -Port 80 -IntervalInSeconds 15 -ProbeCount 2


			# Create a load balancer rule.
			$lbrule = New-AzLoadBalancerRuleConfig -Name $this.LBRuleName -FrontendIpConfiguration $frontendIP -BackendAddressPool  $beAddressPool -Probe $healthProbe -Protocol Tcp -FrontendPort 80 -BackendPort 80


			# Create the load balancer by using the previously created objects.
			$lb = New-AzLoadBalancer -ResourceGroupName $this.ResourceGroupName -Name $this.ResourceName -Location $this.LBLocation -FrontendIpConfiguration $frontendIP -InboundNatRule $inboundNATRule1,$inboundNatRule2 -LoadBalancingRule $lbrule -BackendAddressPool $beAddressPool -Probe $healthProbe


			if($lb.ProvisioningState -eq "Succeeded")
			{
				[CommonHelper]::Log("Load balancer "+$this.ResourceName + " is successfully deployed", [MessageType]::Information)
			}
		}
		catch{
			[CommonHelper]::Log("Error while deploying the Load balancer: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Set Public IP Address for Load Balancer
	[void]AddPublicIpAddress()
	{
		$lb = Get-AzLoadBalancer -Name $this.ResourceName -ResourceGroupName $this.ResourceGroupName
		if($null -ne $lb)
		{
			# Remove existing Load Balancer
			Remove-AzLoadBalancer -Name $this.ResourceName -ResourceGroupName $this.ResourceGroupName -Confirm:$false -Force 

			# Deploy new Load Balancer with Public IP Configuration
			$this.DeployLoadBalancer()
			[CommonHelper]::Log("Successfully set the authorization rules for queue: "+$this.QueueName, [MessageType]::Information)

		}
	}

	# Remove Public IP Address for Load Balancer
	[void]RemovePublicIpAddress()
	{
		try
		{

			$lb = Get-AzLoadBalancer -Name $this.ResourceName -ResourceGroupName $this.ResourceGroupName
			if($null -ne $lb)
			{
				# Remove existing Load Balancer
				Remove-AzLoadBalancer -Name $this.ResourceName -ResourceGroupName $this.ResourceGroupName -Confirm:$false -Force 

				# Create new Load Balancer with no configuration
				New-AzLoadBalancer -Name $this.ResourceName -ResourceGroupName $this.ResourceGroupName -Location $this.LBLocation

				[CommonHelper]::Log("Successfully deployed Load Balancer without public ip configuration : "+ $lb.Name , [MessageType]::Information)
			}
			else
			{
				# Create new Load Balancer with no configuration
				New-AzLoadBalancer -Name $this.ResourceName -ResourceGroupName $this.ResourceGroupName -Location $this.LBLocation
				[CommonHelper]::Log("Successfully deployed Load Balancer without public ip configuration : "+ $lb.Name , [MessageType]::Information)
			}
		}
		catch
		{
			[CommonHelper]::Log("Error while removing Public IP Address steps in Load Balancer: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	# Deploy Public IP Address resource if not available
	[PSObject]DeployPublicIP()
	{
		# Check Public IP Address reource exist
		$publicIP = Get-AzPublicIpAddress -Name $this.PublicIPName -ResourceGroupName $this.ResourceGroupName
		if($null -eq $publicIP)
		{
			$publicIP = New-AzPublicIpAddress -Name $this.PublicIPName -ResourceGroupName $this.ResourceGroupName -Location $this.LBLocation -AllocationMethod Static -DomainNameLabel $this.PublicIPDNS
			[CommonHelper]::Log("Public IP "+ $this.PublicIPName + " is successfully deployed", [MessageType]::Information)
		}
		else 
		{
			[CommonHelper]::Log("Public IP "+ $this.PublicIPName + " is already available.", [MessageType]::Information)	
		}

		return $publicIP;
	}
}