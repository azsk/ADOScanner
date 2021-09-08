Param(

	[Parameter(Mandatory = $True)]
    [string] $SubscriptionID,
	[Parameter(Mandatory = $True)]
    [string] $Path 
	)
$CurrentValue = [Environment]::GetEnvironmentVariable("PSModulePath")
[Environment]::SetEnvironmentVariable("PSModulePath", $CurrentValue + ";"  + $Path)


Import-Module AzSDK
Import-Module AzSDK.Test
$outputfilepath = "d:\a\1\_sdt\logs\TestSuite\"
mkdir $outputfilepath

$outputlogs=Test-AzSDK -SubscriptionId $SubscriptionID -TestScenarioID "TS_BVTs"

[string]$csvfilepath=$outputlogs[2]

Copy-Item $csvfilepath $outputfilepath

$failedtestcases=@()
$testcasesdetail=Get-Content $csvfilepath | ConvertFrom-Csv
$testcasesdetail|ForEach-Object {
if($_.TestStatus -eq 'Failed')
    {
    $failedtestcases+=$_.TestCaseID
    }
}
if($failedtestcases -ne $null)
    {
    Write-Error "test suite failed"
    }
else{
    Write-Host "test cases passed"
    }