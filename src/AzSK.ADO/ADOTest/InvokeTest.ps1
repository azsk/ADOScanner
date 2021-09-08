   Param(

	[Parameter(Mandatory = $True)]
    [string] $SubscriptionID,
	[Parameter(Mandatory = $False)]
    [string] $Path ,
    [Parameter(Mandatory = $False)]
    [string] $Settings=$null
	)

Function Run_CICD_TestSuite
{
	$CurrentValue = [Environment]::GetEnvironmentVariable("PSModulePath")
	[Environment]::SetEnvironmentVariable("PSModulePath", $CurrentValue + ";" + (Get-Item -Path $PSScriptRoot).Parent.FullName)
	# TODO: $testSettings should be replaced by testContext.
	# $testSettings=  $Settings|ConvertFrom-Json 
    # $testSettings
	Import-Module AzSK
	Import-Module AzSK.Test

	$SubscriptionId = $SubscriptionID 
	#Path for output CSV in bild VM.
	$outputfilepath = "d:\a\1\_sdt\logs\TestSuite\"
	mkdir $outputfilepath
	#Run appropriate command below for the scenario you want. You can refer all the scenarios in DefaultTestScenarios.json
	#$outputlogs=Test-AzSK -SubscriptionId $SubscriptionId -TestScenarioID "TS_AllP1s_ExceptSVTs" -Settings $testSettings
	$outputlogs=Test-AzSK -SubscriptionId $SubscriptionId -TestScenarioID "TS_AllP1s" #-Settings $testSettings
	#$outputlogs=Test-AzSK -SubscriptionId $SubscriptionId -Feature "ContinuousCompliance" -ModuleName "ContinuousAssurance" -Settings $testSettings 
	[string]$Logfilepath=$outputlogs[1].path
	[string]$csvfilepath=$outputlogs[2]
	Copy-Item $Logfilepath $outputfilepath
	Copy-Item $csvfilepath $outputfilepath

	$failedtestcases=@()
	$testcasesdetail=Get-Content $csvfilepath | ConvertFrom-Csv
	$testcasesdetail|ForEach-Object {

		if($_.TestStatus -eq 'Failed')
		 {
		$failedtestcases+=$_.TestCaseID
		}
	}
	if($null -ne $failedtestcases)
    {
	   Write-Error "Some or all the test cases failed. Please check detailed logs."
    }
	else{
    Write-Host "Test cases passed."
    }
}


function Run_Local_TestSuite {
    $CurrentValue = [Environment]::GetEnvironmentVariable("PSModulePath")
	[Environment]::SetEnvironmentVariable("PSModulePath", $CurrentValue + ";" + (Get-Item -Path $PSScriptRoot).Parent.FullName)

	#Assign appropriate value below before you run this script.
	$SubscriptionId = $SubscriptionID 
	Import-Module AzSK -requiredversion 2.0.0.0

	#Run appropriate command below for the scenario you want. You can refer all the scenarios in DefaultTestScenarios.json
	#Test-AzSK -SubscriptionId $SubscriptionId -TestScenarioID "TS_AllP1s_ExceptSVTs"
	Test-AzSK -SubscriptionId $SubscriptionId -TestScenarioID "TS_AllP1s"
	#Test-AzSK -SubscriptionId $SubscriptionId -Feature "ContinuousAssurance" -ModuleName "ContinuousAssurance"


	#Run the following command in the Powershell Interactive Window whenever you make any code/json changes. 
	#You can open the Powershell Interactive Window by 'Ctrl+Shift+\'
	Stop-Process -Name PowerShellToolsProcessHost
}


#If the value of $Settings variable is not null then run testsuite in CICD, else run testsuite in local.
if(!([System.String]::IsNullOrEmpty($Settings)))
{
	Run_CICD_TestSuite
}
else{
	Run_Local_TestSuite
}

