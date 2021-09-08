#Set-StrictMode -Version Latest 
#class InstallationTest:AzSKTestBase{
	#[string]$BaselineOutputPath = [string]::Empty
	#InstallationTest([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
	#	if(![string]::IsNullOrEmpty($testcase.BaselineOutput))
	#	{
	#		$this.BaselineOutputPath =[CommonHelper]::GetPath([PathList]::TestData,$testcase)+$testcase.BaselineOutput
	#	}
 #}

	#[void] Execute(){
		
	#		switch ($this.testcase.TestMethod){
	#		"TestInstallAzSKOSS"{
	#				$this.TestInstallAzSKOSS()
	#				break

	#		}
			
	#		}
	
	#}

	#[TestCaseResult] TestInstallAzSKOSS(){
	#	try{
	#		Install-Module AzSK -Scope CurrentUser
	#	}
	#	catch{

	#	}
	#}

#}