# Set flag to bypass multiple AzSK modules check in same session for debug model
#Manual change in ADOScanner code has to be made for handling this flag, until the code is pushed and deployed
$env:AzSKSkipMutliModuleCheck = $true 


# Import test pass modules
$testPath = (Get-Location).path
Import-Module -FullyQualifiedName "$testPath\AzSK.Test.psd1"

################ Todo ###############
#1) Document
<#
*******************************TODO Before Running test harness *******************************
Verify the ADO config in TestSettings.json and check if you have access to the mentioned resources
#>

# Replace the below mandatory arguments
$org = "SafetiTestVSO" 
$pat = "NA" 

<# 
To run test harness feature wise, follow the below steps : 
1) Run the below script to fetch all the supported features of ADO  test harness
    $testCasesFile = $testPath+"\ADOTestCasesMaster.json"
    $testCasesInfo = Get-Content -Raw -Path $testCasesFile | ConvertFrom-Json
    $testFeatures =  @($testCasesInfo | Select-Object Feature -Unique)
2) Then run the Test-ADO command specifying the feature
#>
#Eg :
# To run feature testcases
Test-ADO -Org $org -Pat $pat -AzSKModule AzSK.ADO -Feature "Scanning"    -ParallelScan
#Test-ADO -Org $org -Pat $pat -AzSKModule AzSKStaging.ADO -Feature "ControlCorrectness"  -DevTestMode $True

# To run individual testcases , Refer TestCaseID's from ADOTestCasesMaster.json
#Test-ADO -Org $org -Pat $pat -AzSKModule AzSK.ADO -TestCaseIDs "AzureDevOps_Svc_Verify_Control_Correctness_Success,AzureDevOps_Svc_Verify_Control_Correctness_Fail"  -DevTestMode $True
