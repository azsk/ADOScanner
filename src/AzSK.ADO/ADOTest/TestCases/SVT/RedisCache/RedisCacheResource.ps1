Set-StrictMode -Version Latest 
class RedisCacheResource:SVTControlTestResource{
	[bool] $RetainResource = $false

	RedisCacheResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
     
    }

	#Setting the properties as required by this resource type.
	[void]SetDerivedResourceProps(){
		#Pick the resource name from Params file if its not null
		if(![string]::IsNullOrEmpty($this.Params)){
				$this.ResourceName = $this.GetResourceNameFromARMJson($this.Params, "ResName", "value")
			}
		else{
			$this.ResourceName = "azsktestrediscachepremium" #Else set the default resource name
		}
		$this.ResourceType = "Microsoft.Cache/Redis" 
	}

	#Enable Non-SSL Port
	[void] EnableNonSSLPort(){
		try{
			if($this.ProvisioningState -eq "Succeeded"){				
				Set-AzRedisCache -ResourceGroupName $this.ResourceGroupName -Name $this.ResourceName -EnableNonSslPort $true 
		    }
		}
		catch{
				[CommonHelper]::Log("Error while enabling non SSL ports for: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Enable Non-SSL Port
	[void] DisableNonSSLPort(){
		try{
			if($this.ProvisioningState -eq "Succeeded"){				
				Set-AzRedisCache -ResourceGroupName $this.ResourceGroupName -Name $this.ResourceName -EnableNonSslPort $false 
		    }
		}
		catch{
				[CommonHelper]::Log("Error while disabling non SSL ports for: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Enable Redis Back Up
	[void] EnableRedisBackUp(){
		try{
			if($this.ProvisioningState -eq "Succeeded"){	
				$storageAccount=$this.IfCommonStorageExists()
                if(!$storageAccount){
                            $this.CreateCommonStorage()
                }  			
				$stgName = $this.settings.CommonStorageAcctName
				$stgKey = (Get-AzStorageAccountKey -Name $stgName -ResourceGroupName $this.ResourceGroupName).Value[0]
				$stgConnectionString = "DefaultEndpointsProtocol=https;BlobEndpoint=https://$($stgName).blob.core.windows.net/;AccountName=$($stgName);AccountKey=$($stgKey)"

				Set-AzRedisCache -ResourceGroupName $this.ResourceGroupName -Name $this.ResourceName  `
									  -RedisConfiguration   @{ "rdb-backup-enabled" = "true"
															   "rdb-backup-frequency" = "60"
															   "rdb-backup-max-snapshot-count" ="1"
															   "rdb-storage-connection-string" = $($stgConnectionString)
															}
		    }
		}
		catch{
				[CommonHelper]::Log("Error while enabling non SSL ports for: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Disable Redis Back Up
	[void] DisableRedisBackUp(){
		try{
			if($this.ProvisioningState -eq "Succeeded"){				
				Set-AzRedisCache -ResourceGroupName $this.ResourceGroupName -Name $this.ResourceName -RedisConfiguration  @{"rdb-backup-enabled" = "false"}
		    }
		}
		catch{
				[CommonHelper]::Log("Error while disabling non SSL ports for: " + $this.ResourceName, [MessageType]::Error)
		}
	}
}
