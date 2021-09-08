Set-StrictMode -Version Latest 
class AppServiceResource:SVTControlTestResource{
	[bool] $RetainResource = $false	
	AppServiceResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
     
    }

	#Setting the properties as required by this resource type.
	[void]SetDerivedResourceProps(){
		#Fetch the resource name from Template file if its not null
		if(![string]::IsNullOrEmpty($this.Template)){
				$this.ResourceName = $this.GetResourceNameFromARMJson($this.Template, "ResourceName","defaultValue")
			}
		else{
			$this.ResourceName = "azsktestappservice" #Else set the default resource name
		}
		$this.ResourceType = "Microsoft.Web/sites" 
	}

	#Since app service is upgradable, ARM deploy it to assign new properties instead of running any other functions.
	[void] InitializeResource( ){
		$this.ARMDeployResource()	
    }

	#Set App backup
	[void] SetAppBackup(){
		try{
			$StorageAccountContainerName = "appservicebackup"
			$storageAccountKey = Get-AzStorageAccountKey -ResourceGroupName $this.ResourceGroupName -Name $this.Settings.CommonStorageAcctName
			$context = New-AzureStorageContext -StorageAccountName $this.Settings.CommonStorageAcctName -StorageAccountKey $storageAccountKey[0].Value
			$token = New-AzureStorageContainerSASToken -Name $StorageAccountContainerName -Permission rwdl -Context $context -ExpiryTime (Get-Date).AddMonths(1)
			$sasUrl = $context.BlobEndPoint + $StorageAccountContainerName + $token

			Edit-AzWebAppBackupConfiguration -FrequencyInterval 1 -FrequencyUnit "Day" -RetentionPeriodInDays "0" -StartTime $(Get-Date) -KeepAtLeastOneBackup -ResourceGroupName $this.ResourceGroupName -Name $this.ResourceName -StorageAccountUrl $sasUrl
		}
		catch{			
			$_
		}

	}

	#Add WEBSITE_LOAD_CERTIFICATES
	[void] AddWebsiteLoadCertificates(){
		try{
			$AppSettings = @{"WEBSITE_LOAD_CERTIFICATES" = "*"}
			Set-AzWebAppSlot -ResourceGroupName $this.ResourceGroupName -Name $this.ResourceName -Slot 'Production' -AppSettings $AppSettings
		}
		catch{			
			$_
		}
	}

	

}
