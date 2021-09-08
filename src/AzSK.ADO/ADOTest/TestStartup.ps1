. $PSScriptRoot\Core\Models\TestScenario.ps1
. $PSScriptRoot\Core\Models\TestCase.ps1
. $PSScriptRoot\Core\Models\Enums.ps1
. $PSScriptRoot\Core\Models\ParamSet.ps1
. $PSScriptRoot\Core\Helpers\Constants.ps1
. $PSScriptRoot\Core\Helpers\CommonHelper.ps1
. $PSScriptRoot\Core\Helpers\ConfigurationHelper.ps1
. $PSScriptRoot\Core\Helpers\AzSKControlInfo.ps1
. $PSScriptRoot\Core\Helpers\ResourceInfo.ps1
. $PSScriptRoot\Core\Helpers\ADOResourceInfo.ps1
. $PSScriptRoot\Core\Helpers\AzSKScanResults.ps1
. $PSScriptRoot\Core\Settings\TestSettings.ps1
. $PSScriptRoot\Core\Models\HarnessSettings.ps1
. $PSScriptRoot\Core\Models\AzSKSettings.ps1
. $PSScriptRoot\Core\Models\TestResources.ps1
. $PSScriptRoot\Core\Models\ADOTestResources.ps1
. $PSScriptRoot\Core\Models\TestContext.ps1
#. $PSScriptRoot\Core\Models\ADOTestContext.ps1
. $PSScriptRoot\Core\Models\SVTControlTestResource.ps1
. $PSScriptRoot\TestCases\SVT\ADLA\ADLAResource.ps1
. $PSScriptRoot\TestCases\SVT\ADLS\ADLSResource.ps1
. $PSScriptRoot\TestCases\SVT\LogicApps\LogicAppsResource.ps1
. $PSScriptRoot\TestCases\SVT\AnalysisServices\AnalysisServicesResource.ps1
. $PSScriptRoot\TestCases\SVT\Storage\StorageResource.ps1
. $PSScriptRoot\TestCases\SVT\SQLDB\SQLDBResource.ps1
. $PSScriptRoot\TestCases\SVT\KeyVault\KeyVaultResource.ps1
. $PSScriptRoot\TestCases\SVT\AppService\AppServiceResource.ps1
. $PSScriptRoot\TestCases\SVT\Search\SearchResource.ps1
. $PSScriptRoot\TestCases\SVT\Batch\BatchResource.ps1
. $PSScriptRoot\TestCases\SVT\DataFactory\DataFactoryResource.ps1
. $PSScriptRoot\TestCases\SVT\VirtualNetwork\VirtualNetworkResource.ps1
. $PSScriptRoot\TestCases\SVT\NotificationHub\NotificationHubResource.ps1
. $PSScriptRoot\TestCases\SVT\LoadBalancer\LoadBalancerResource.ps1
. $PSScriptRoot\TestCases\SVT\ServiceBus\ServiceBusResource.ps1
. $PSScriptRoot\TestCases\SVT\EventHub\EventHubResource.ps1
. $PSScriptRoot\TestCases\SVT\CDN\CDNResource.ps1
. $PSScriptRoot\TestCases\SVT\CosmosDb\CosmosDbResource.ps1
. $PSScriptRoot\TestCases\SVT\TrafficManager\TrafficManagerResource.ps1
. $PSScriptRoot\TestCases\SVT\Functions\FunctionsResource.ps1
. $PSScriptRoot\TestCases\SVT\RedisCache\RedisCacheResource.ps1
. $PSScriptRoot\TestCases\SVT\Automation\AutomationResource.ps1
. $PSScriptRoot\Core\Models\TestCaseResult.ps1
. $PSScriptRoot\Core\Helpers\Assert.ps1
. $PSScriptRoot\Core\Helpers\TestHelper.ps1
. $PSScriptRoot\Core\Helpers\CATestContextHelper.ps1
. $PSScriptRoot\Core\Abstracts\AzSKTestBase.ps1
. $PSScriptRoot\Core\Abstracts\ADOTestBase.ps1
. $PSScriptRoot\Core\Abstracts\SVTTestBase.ps1
. $PSScriptRoot\TestCases\SVT\KeyVault\KeyVaultTest.ps1
. $PSScriptRoot\TestCases\SVT\VirtualMachine\VirtualMachineResource.ps1
. $PSScriptRoot\TestCases\SVT\VirtualNetwork\VirtualNetworkTest.ps1
. $PSScriptRoot\TestCases\SVT\AppService\AppServiceTest.ps1
. $PSScriptRoot\TestCases\SVT\Search\SearchTest.ps1
. $PSScriptRoot\TestCases\SVT\Batch\BatchTest.ps1
. $PSScriptRoot\TestCases\SVT\ADLA\ADLATest.ps1
. $PSScriptRoot\TestCases\SVT\ADLS\ADLSTest.ps1
. $PSScriptRoot\TestCases\SVT\LogicApps\LogicAppsTest.ps1
. $PSScriptRoot\TestCases\SVT\VirtualMachine\VirtualMachineTest.ps1
. $PSScriptRoot\TestCases\SVT\SQLDB\SQLDBTest.ps1
. $PSScriptRoot\TestCases\SVT\DataFactory\DataFactoryTest.ps1
. $PSScriptRoot\TestCases\SVT\Storage\StorageTest.ps1
. $PSScriptRoot\TestCases\SVT\AnalysisServices\AnalysisServicesTest.ps1
. $PSScriptRoot\TestCases\SVT\NotificationHub\NotificationHubTest.ps1
. $PSScriptRoot\TestCases\SVT\LoadBalancer\LoadBalancerTest.ps1
. $PSScriptRoot\TestCases\SVT\ServiceBus\ServiceBusTest.ps1
. $PSScriptRoot\TestCases\SVT\EventHub\EventHubTest.ps1
. $PSScriptRoot\TestCases\SVT\CDN\CDNTest.ps1
. $PSScriptRoot\TestCases\SVT\Common\ParallelScanData.ps1
. $PSScriptRoot\TestCases\SVT\Common\CommonTest.ps1
. $PSScriptRoot\TestCases\SVT\CosmosDb\CosmosDbTest.ps1
. $PSScriptRoot\TestCases\SVT\TrafficManager\TrafficManagerTest.ps1
. $PSScriptRoot\TestCases\SVT\Functions\FunctionsTest.ps1
. $PSScriptRoot\TestCases\SVT\RedisCache\RedisCacheTest.ps1
. $PSScriptRoot\TestCases\SVT\Automation\AutomationTest.ps1
. $PSScriptRoot\TestCases\SVT\SVTCommon\SVTCommonTest.ps1
. $PSScriptRoot\TestCases\SVTCore\SVTCore.ps1
. $PSScriptRoot\TestCases\ADOScanner\ScanCommands\ADOScanning.ps1
. $PSScriptRoot\TestCases\ADOScanner\BugLogging\ADOBugLogging.ps1
. $PSScriptRoot\TestCases\ADOScanner\PartialCommit\ADOPartialCommit.ps1
. $PSScriptRoot\TestCases\ADOScanner\ControlCorrectness\ADOControlCorrectness.ps1
. $PSScriptRoot\TestCases\ARMChecker\ARMChecker.ps1
. $PSScriptRoot\TestCases\SubscriptionSecurity\SSProvisioning\SSProvisioningTest.ps1
. $PSScriptRoot\TestCases\ContinuousAssurance\ContinuousAssurance.ps1
. $PSScriptRoot\TestCases\SubscriptionSecurity\SSHealth\SSHealthTest.ps1
. $PSScriptRoot\TestCases\Setup\Installation\InstallationTest.ps1
. $PSScriptRoot\TestCases\AlertMonitoring\OMS\OMSTest.ps1
. $PSScriptRoot\TestCases\SecurityIntellisense\SecIntel\SecIntelTest.ps1
. $PSScriptRoot\TestCases\CICDPipeline\CICD\CICDTest.ps1
. $PSScriptRoot\TestCases\AzSKInfo\AzSKInfo.ps1
. $PSScriptRoot\Controllers\TestRunner.ps1
. $PSScriptRoot\Controllers\ADOTestRunner.ps1
. $PSScriptRoot\Controllers\TestController.ps1
. $PSScriptRoot\Controllers\ADOTestController.ps1


function GetTestCaseFiles {
    $testCasesRepo = @()
    $path = "$PSScriptRoot\TestCases"
    $files = Get-ChildItem -Path $path -Include "TestCases_*.json" -Recurse
    foreach ($file in $files) {
        $filepath = $file.FullName
        $testCases = ConvertFrom-Json (Get-Content $filepath -raw)
        $testCasesRepo += $testCases.TestCases.TestCase
    }
    $testCasesRepo | ConvertTo-Json -depth 100 | set-content "$PSScriptRoot\TestCasesMaster.json" -Force
}



GetTestCaseFiles




