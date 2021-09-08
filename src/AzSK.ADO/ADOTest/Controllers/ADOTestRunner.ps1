Set-StrictMode -Version Latest
class ADOTestRunner{
    [ADOTestBase] $testbase
    [TestCase] $tcase
	[string]$Org= [string]::Empty
	[string]$AzSKModule = [string]::Empty

    ADOTestRunner([string]$Org,[TestCase]$testcase,[TestSettings]$testsettings,[TestContext] $testContext, [string]$AzSKModule) {
		$this.Org = $Org
        $this.AzSKModule = $AzSKModule
        $this.tcase = $testcase		
		$featureUC = $testcase.Feature.ToUpper()
		$moduleName = $testcase.ModuleName
		$moduleNameUC = $testcase.ModuleName.ToUpper()
        if($featureUC -eq "Scanning"){
			switch ($moduleName) {
				"GADS"{
					$this.testbase = [ADOScanning]::new($testcase, $testsettings, $testContext)
					break
				}
				Default {
					$this.testbase = [AzSKTestBase]::new($testcase, $testsettings, $testContext)
				}
			}            
		}
		elseif ($featureUC -eq "ControlCorrectness") {
			switch ($moduleName) {
				"GADS"{
					$this.testbase = [ADOControlCorrectness]::new($testcase, $testsettings, $testContext)
					break
				}
				Default {
					$this.testbase = [AzSKTestBase]::new($testcase, $testsettings, $testContext)
				}
			} 			
		}
		elseif ($featureUC -eq "BugLogging") {
			switch ($moduleName) {
				"GADS"{
					$this.testbase = [ADOBugLogging]::new($testcase, $testsettings, $testContext)
					break
				}
				Default {
					$this.testbase = [AzSKTestBase]::new($testcase, $testsettings, $testContext)
				}
			} 			
		}
		elseif ($featureUC -eq "PartialCommit") {
			switch ($moduleName) {
				"GADS"{
					$this.testbase = [ADOPartialCommit]::new($testcase, $testsettings, $testContext)
					break
				}
				Default {
					$this.testbase = [AzSKTestBase]::new($testcase, $testsettings, $testContext)
				}
			} 			
		}
    }

    [TestCaseResult] RunTestCase()
	{   
		$this.testbase.Initialize()
		$testCaseResult = [TestCaseResult]::new($this.tcase)
        $this.testbase.Execute()
		$testCaseResult =  $this.testbase.testCaseResult
        $this.testbase.Cleanup()
        return $testCaseResult
    }

}
