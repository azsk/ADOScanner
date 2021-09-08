Set-StrictMode -Version Latest 
class FunctionsResource:SVTControlTestResource{
	FunctionsResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext) {
    }

	#Setting the properties as required by this resource type.
	[void]SetDerivedResourceProps(){
		#Fetch the resource name from Template file if its not null
		if(![string]::IsNullOrEmpty($this.Template)){
				$this.ResourceName = $this.GetResourceNameFromARMJson($this.Template, "ResourceName", "defaultValue")
			}
		else{
			$this.ResourceName = "azsktestfunctions" #Else set the default resource name
		}
		$this.ResourceType = "Microsoft.Web/sites" 
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
	#Chnge functions edit mode
	[void] ChangeFunctionsEditMode(){
		try{
			$AppSettings = @{"FUNCTION_APP_EDIT_MODE" = "readonly"}
			Set-AzWebAppSlot -ResourceGroupName $this.ResourceGroupName -Name $this.ResourceName -Slot 'Production' -AppSettings $AppSettings
		}
		catch{			
			$_
		}
	}

}
