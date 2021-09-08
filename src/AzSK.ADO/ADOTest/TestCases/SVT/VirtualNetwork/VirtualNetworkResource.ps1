Set-StrictMode -Version Latest 
class VirtualNetworkResource:SVTControlTestResource{
	VirtualNetworkResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
     
    }

		#Setting the properties as required by this resource type.
	[void]SetDerivedResourceProps(){
		$this.ResourceName = "azsktestvnet" #Else set the default resource name
		$this.ResourceType = "Microsoft.Network/virtualNetworks" 
	}

	#Checks and deploys the VNet if it does not exist.
	[void] InitializeResource( ){
		if(!$this.IfResourceExists()){
			$this.DeployVNet()	
		}
    }

	#Deploy the VNet
	[void]DeployVNet()
	{
		try
		{
			$Vnet = New-AzVirtualNetwork -Name $this.ResourceName -ResourceGroupName $this.ResourceGroupName `
					-Location "Southeast Asia" -AddressPrefix "192.168.0.0/16"
			$this.ProvisioningState = $Vnet.ProvisioningState
			if($Vnet.ProvisioningState -eq "Succeeded")
			{
				[CommonHelper]::Log("Resource "+$this.ResourceName + " is successfully deployed", [MessageType]::Information)
			}
			else
			{
				[CommonHelper]::Log("Error while deploying the Virtual Network: " + $this.ResourceName, [MessageType]::Error)
			}
		}
		catch{
			[CommonHelper]::Log("Error while deploying the Virtual Network: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	[Void]AddVnetPeer()
	{
		try
		{
			$VnetPeer = Get-AzVirtualNetwork -Name azsktestvnet-02 -ResourceGroupName $this.ResourceGroupName

			if($null -eq $VnetPeer)
			{
				$VnetPeer = New-AzVirtualNetwork -Name 'azsktestvnet-02' -ResourceGroupName $this.ResourceGroupName `
						-Location "Southeast Asia" -AddressPrefix '192.169.0.0/16' -Force
			}

			Add-AzVirtualNetworkPeering -Name 'azsknetPeering' -VirtualNetwork (Get-AzVirtualNetwork -Name $this.ResourceName `
				-ResourceGroupName $this.ResourceGroupName) -RemoteVirtualNetworkId $VnetPeer.Id -AllowForwardedTraffic -AllowGatewayTransit
		}
		catch{
			[CommonHelper]::Log("Error while deploying the Virtual Network: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	[Void]ResetConfigurationBase()
	{
		$vnetPeerings = Get-AzVirtualNetworkPeering -VirtualNetworkName $this.ResourceName -ResourceGroupName $this.ResourceGroupName
        if($null -ne $vnetPeerings -and ($vnetPeerings|Measure-Object).count -gt 0)
        {
			$vnetPeerings | ForEach-Object{
				Remove-AzVirtualNetworkPeering -Name $_.Name -ResourceGroupName $this.ResourceGroupName -VirtualNetworkName $this.ResourceName `
						-Force
			}
		}
	}
}