Set-StrictMode -Version Latest
class TestRunner{
    [AzSKTestBase] $testbase
    [TestCase] $tcase
	[string]$subscriptionId = [string]::Empty
	[string]$AzSKModule = [string]::Empty

    TestRunner([string]$subId,[TestCase]$testcase,[TestSettings]$testsettings,[TestContext] $testContext, [string]$AzSKModule) {
		$this.subscriptionId = $subId
        $this.AzSKModule = $AzSKModule
        $this.tcase = $testcase
		<#
		if($this.tcase.AzureLoginRequired){
			$this.SetAzureContext();
		}
		#>
		
		$featureUC = $testcase.Feature.ToUpper()
		$moduleName = $testcase.ModuleName
		$moduleNameUC = $testcase.ModuleName.ToUpper()
		if($featureUC -eq "SVT"){
			switch ($moduleNameUC) {
				<#
				"KEYVAULT" {
					$this.testbase = [KeyVaultTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"VIRTUALMACHINE" {
					$this.testbase = [VirtualMachineTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"APPSERVICE"{
					$this.testbase = [AppServiceTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"SEARCH"{
					$this.testbase = [SearchTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"BATCH"{
					$this.testbase = [BatchTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"ADLA"{
					$this.testbase = [ADLATest]::new($testcase, $testsettings, $testContext)
					break
				}
				"ADLS"{
					$this.testbase = [ADLSTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"LogicApps"{
					$this.testbase = [LogicAppsTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"SQLDB"{
					$this.testbase = [SQLDBTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"DATAFACTORY"{
					$this.testbase = [DataFactoryTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"STORAGE"{
					$this.testbase = [StorageTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"ANALYSISSERVICES"{
					$this.testbase = [AnalysisServicesTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"VIRTUALNETWORK"{
					$this.testbase = [VirtualNetworkTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"NOTIFICATIONHUB"{
					$this.testbase = [NotificationHubTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"LOADBALANCER"{
					$this.testbase = [LoadBalancerTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"SERVICEBUS"{
					$this.testbase = [ServiceBusTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"CDN"{
					$this.testbase = [CDNTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"COSMOSDB"{
					$this.testbase = [CosmosDbTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"TRAFFICMANAGER"{
					$this.testbase = [TrafficManagerTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"FUNCTIONS"{
					$this.testbase = [FunctionsTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"EVENTHUB"{
					$this.testbase = [EventHubTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"AUTOMATION"{
					$this.testbase = [AutomationTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"SVTCOMMON"{
					$this.testbase = [SVTCommonTest]::new($testcase, $testsettings, $testContext,$AzSKModule)
					break
				}
				#>
				"Common"{
					$this.testbase = [CommonTest]::new($testcase, $testsettings, $testContext)
					break
				}
				Default {
					$this.testbase = [SVTTestBase]::new($testcase, $testsettings, $testContext)
				}
			}
        }
		elseif($featureUC -eq "SUBSCRIPTIONSECURITY"){
			switch ($moduleName) {
				"SSProvisioning"{
					$this.testbase = [SSProvisioningTest]::new($testcase, $testsettings, $testContext)
					break
				}
				"SSHealth"{
					$this.testbase = [SSHealthTest]::new($testcase, $testsettings, $testContext)
					break
				}
				Default {
					$this.testbase = [AzSKTestBase]::new($testcase, $testsettings, $testContext)
				}
			}
		}
		elseif($featureUC -eq "ALERTMONITORING"){
			switch ($moduleName) {
				"OMS"{
					$this.testbase = [OMSTest]::new($testcase, $testsettings, $testContext)
					break
				}
				Default {
					$this.testbase = [AzSKTestBase]::new($testcase, $testsettings, $testContext)
				}
			}
		}
		elseif($featureUC -eq "SECURITYINTELLISENSE"){
			switch ($moduleName) {
				"SecIntel"{
					$this.testbase = [SecIntelTest]::new($testcase, $testsettings, $testContext)
					break
				}
				Default {
					$this.testbase = [AzSKTestBase]::new($testcase, $testsettings, $testContext)
				}
			}
		}
		elseif($featureUC -eq "CICDPIPELINE"){
			switch ($moduleName) {
				"CICD"{
					$this.testbase = [CICDTest]::new($testcase, $testsettings, $testContext)
					break
				}
				Default {
					$this.testbase = [AzSKTestBase]::new($testcase, $testsettings, $testContext)
				}
			}
		}
		elseif($featureUC -eq "CONTINUOUSASSURANCE"){
			switch ($moduleNameUC) {
				"CONTINUOUSASSURANCE"{
					$this.testbase = [ContinuousAssurance]::new($testcase, $testsettings, $testContext)
					break
				}
				Default {
					$this.testbase = [AzSKTestBase]::new($testcase, $testsettings, $testContext)
				}
			}

		}
		elseif($featureUC -eq "SVTCORE"){
			switch ($moduleName) {
				"GRS"{
					$this.testbase = [SVTCore]::new($testcase, $testsettings, $testContext)
					break
				}
				"GSS"{
					$this.testbase = [SVTCore]::new($testcase, $testsettings, $testContext)
					break
				}
				"GACS"{
					$this.testbase = [SVTCore]::new($testcase, $testsettings, $testContext)
					break
				}
				Default {
					$this.testbase = [AzSKTestBase]::new($testcase, $testsettings, $testContext)
				}
			}
		}
		elseif($featureUC  -eq "ARMCHECKER"){
			switch ($testcase.ModuleName.ToUpper().Trim()) {
				"ARMCHECKER"{
					$this.testbase = [ARMChecker]::new($testcase, $testsettings, $testContext)
					break
				}
				Default {
					$this.testbase = [AzSKTestBase]::new($testcase, $testsettings, $testContext)
				}
			}

		}
		elseif($featureUC -eq "AzSKInfo"){
			switch ($moduleName) {
				"GRS"{
					$this.testbase = [AzSKInfo]::new($testcase, $testsettings, $testContext)
					break
				}
				Default {
					$this.testbase = [AzSKTestBase]::new($testcase, $testsettings, $testContext)
				}
			}
		}
		elseif($featureUC -eq "AzSKInfo"){
			switch ($moduleName) {
				"ControlInfo"{
					$this.testbase = [AzSKInfo]::new($testcase, $testsettings, $testContext)
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
