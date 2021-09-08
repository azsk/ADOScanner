Set-StrictMode -Version Latest 
class VirtualMachineResource:SVTControlTestResource{
	[bool] $RetainResource = $false
	VirtualMachineResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
     
    }

	#Setting the properties as required by this resource type.
	[void]SetDerivedResourceProps(){
		}

}
