$s2 = 'abb5301a-22a4-41f9-9e5f-99badff261f8'
$s4 = '254ad434-e2e6-45c0-a32b-34bf24cb7479'
$SubscriptionId = $s2  #(Get-AzContext).Subscription.Id
$AzSKModule = "AzSKStaging" #By default, this loads the module from %Documents\WindowsPowerShell\Modules%

$MandatoryTestSettings = "" | Select-Object SecurityPhoneNo, SecurityPOCEmail, LAWSSharedKey, LAWSId, LAResourceGroup

$MandatoryTestSettings.SecurityPhoneNo = "1-425-882-8080"
$MandatoryTestSettings.SecurityPOCEmail = "abc@def.com" 
$MandatoryTestSettings.LAWSSharedKey = "<xyzpqr>"
$MandatoryTestSettings.LAWSId = "<xyzpqr>"
$MandatoryTestSettings.LAResourceGroup = "<xyzpqr>"


$testPath  = $($PSScriptRoot)

# TODO: Remove hard-coded path
# $testPath = "C:\Users\mprabhu\source\repos\SR-RM-ETR-Cloud-DevOps-AzSK_Internal\Azure\DevOpsToolKit\Projects\AzSK\AzSK.Test"


Import-Module -FullyQualifiedName "$testPath\AzSK.Test.psd1"

[Constants]::RunJobsInParallelScan = ""
[Constants]::WhitelistedControlIds = @()

# Test-AzSK -SubscriptionId $SubscriptionId -AzSKModule $AzSKModule -Feature "<FeatureName>" -ModuleName "<ModuleName>" -TestCaseID "<TestCaseId>" -MandatoryTestSettings $MandatoryTestSettings
$tcLabel = "Test_GRS_Tgt_RGs_for_Sub"

#$tcLabel = "Test_GRS_Tmp"  #For use when adding/doing PoC for a new test case
$myTCId = $tcLabel -replace '_','-'

#$myTCId = 'Test-GRS-Tgt-ControlIds-for-Sub'

#$myTCId = 'Test-GRS-Tag-ExcludeTags-for-Sub ,Test-GRS-Tgt-RGs-for-Sub , Test-GRS-Tag-FilterTags-for-Sub'

$myExclTCId = 'Test-GRS-Tag-ExcludeTags-for-Sub ,Test-GRS-Tgt-RGs-for-Sub , Test-GRS-Tag-FilterTags-for-Sub'


#$myTCId = 'Test-GRS-Tag-FilterTags-for-Sub'

#$myTCId = 'Test-GRS-Tgt-ControlIds-Single-Rsrc'
#$myTCId = 'Test_StateDrift_ProdVsNonProd'
# Sample Command


#Test-AzSK -SubscriptionId $SubscriptionId -AzSKModule $AzSKModule -Feature 'ContinuousAssurance' -ModuleName 'ContinuousAssurance' -TestCaseID "Test-Demo" -MandatoryTestSettings $MandatoryTestSettings

#Test-AzSK -SubscriptionId $SubscriptionId -AzSKModule $AzSKModule -Feature 'SVTCore' -ModuleName 'GRS' -TestCaseID "Test-GRS-Tmp" -MandatoryTestSettings $MandatoryTestSettings -DevTestMode $True

### myTCID
#Test-AzSK -SubscriptionId $SubscriptionId -AzSKModule $AzSKModule -Feature 'SVT' -ModuleName 'Common' -TestCaseID $myTCId -MandatoryTestSettings $MandatoryTestSettings -DevTestMode $True

#Test-AzSK -SubscriptionId $SubscriptionId -AzSKModule $AzSKModule -Feature 'SVTCore' -ModuleName 'GRS' -TestCaseID $myTCId -MandatoryTestSettings $MandatoryTestSettings -DevTestMode $True

### All SVTCore
# $TestCases = "Test-GRS-Swt-Ubc-Single-RG,Test-GRS-Tgt-ControlIds-for-Sub"
# -TestCaseIDs $TestCases
# $testCase = "Test-GRS-Tgt-ControlIds-for-Sub,Test-GRS-Tgt-ControlIds-Single-Rsrc"
# $testCase = "Test-GRS-Tag-TagName-TagVal-for-Sub"
Test-AzSK -SubscriptionId $SubscriptionId -AzSKModule $AzSKModule -Feature 'ARMChecker' -ModuleName 'ARMChecker' -DevTestMode $True -MandatoryTestSettings $MandatoryTestSettings -TestCaseID 'Test_ARMChecker_Scan_Baseline_Controls'


# Test-AzSK -SubscriptionId $SubscriptionId -AzSKModule $AzSKModule -Feature SVT -ModuleName Common -MandatoryTestSettings $MandatoryTestSettings -ParallelScan


