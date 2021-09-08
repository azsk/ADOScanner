Set-StrictMode -Version Latest
class CosmosDbResource:SVTControlTestResource {
    CosmosDbResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext) {
    }

    #Setting the properties as required by this resource type.
    [void] SetDerivedResourceProps() {
        #Fetch the resource name from Template file if its not null
        if (![string]::IsNullOrEmpty($this.Template)) {
            $this.ResourceName = $this.GetResourceNameFromARMJson($this.Template, "ResourceName", "defaultValue")
        }
        else {
            $this.ResourceName = "azsdktestcosmosdb" #Else set the default resource name
        }
        $this.ResourceType = "Microsoft.DocumentDb/databaseAccounts"
    }

    [void] InitializeResource( ) {
        $this.ARMDeployResource()
    }
}
