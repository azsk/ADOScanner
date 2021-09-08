Set-StrictMode -Version Latest 
class AzSKTestBase{
    [TestCase] $testcase
    [TestCaseResult] $testCaseResult 
    [TestSettings] $settings
    [TestContext] $testContext
	[string] $AzSKModule
	
    AzSKTestBase([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext) {
        $this.testcase = $testcase
        $this.testCaseResult = [TestCaseResult]::new($testcase)
        $this.settings = $testsettings
        $this.testContext = $testContext
    }
	AzSKTestBase([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext, [string]$AzSKModule) {
        $this.testcase = $testcase
        $this.testCaseResult = [TestCaseResult]::new($testcase)
        $this.settings = $testsettings
        $this.testContext = $testContext
		$this.AzSKModule = $AzSKModule
    }
    [void]Initialize(){

    }
    [void]Execute(){

    }
    [void]Cleanup(){

    }


}

