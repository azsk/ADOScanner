Set-StrictMode -Version Latest 
class CDNResource:SVTControlTestResource{
	CDNResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext) {
    }

	#Setting the properties as required by this resource type.
	[void]SetDerivedResourceProps(){
		#Fetch the resource name from Template file if its not null
		if(![string]::IsNullOrEmpty($this.Template)){
				$this.ResourceName = $this.GetResourceNameFromARMJson($this.Template, "ResourceName", "defaultValue")
			}
		else{
			$this.ResourceName = "azsktestcdn" #Else set the default resource name
		}
		$this.ResourceType = "Microsoft.Cdn/profiles" 
	}

	[void] InitializeResource( ){
		
		if(![string]::IsNullOrEmpty($this.Template)){
			$linkedResourceName = $this.GetResourceNameFromARMJson($this.Template, "storageAccountForCDN", "defaultValue")
			}
		else{
			$linkedResourceName = "azskteststoragecommon" #Else set the default resource name
		}
		$linkedResourceType = "Microsoft.Storage/storageAccounts" 
		$linkedResourceExists=$this.IfLinkedResourceExists($linkedResourceName,$linkedResourceType)
		if(!$linkedResourceExists){
				$this.CreateLinkedResource($linkedResourceName)
		}
			
		$this.ARMDeployResource()	
    }
}