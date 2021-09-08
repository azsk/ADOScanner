Set-StrictMode -Version Latest 

function Test-AzSK{
    Param(
		[Parameter(Mandatory = $True)]
        [string]
        $SubscriptionId,

		[ValidateSet('AzSKStaging','AzSKPreview','AzSK')]
		[Parameter(Mandatory = $True)]
		[string]
		$AzSKModule,

		[Parameter(Mandatory = $False)]
        [string]
        $Feature = [string]::Empty,

        [Parameter(Mandatory = $False)]
        [string]
        $ModuleName = [string]::Empty,

		[Parameter(Mandatory = $False)]
		[Alias("TestCaseID")]
        [string]
		$TestCaseIDs = [string]::Empty,
		
		[Parameter(Mandatory = $False)]
		[Alias("ExcludeTestCaseID")]
        [string]
        $ExcludeTestCaseIDs = [string]::Empty,

        [Parameter(Mandatory = $False)]
        [string]
        $Priority = [string]::Empty,

		[Parameter(Mandatory = $true)]
        [PSObject]
        $MandatoryTestSettings = $null,

		[Parameter(Mandatory = $False)]
        [PSObject]
        $UserDefinedTestSettings = $null,

		[Parameter(Mandatory = $False)]
		[string]
		$AzSKModulePath = [string]::Empty,

		[Parameter(Mandatory = $False)]
		[switch]
		$ParallelScan,

		[ValidateSet('CSE','OSS','Contoso')]
		[Parameter(Mandatory = $False)]
		[string]
		$OrgPolicy,

        [Parameter(Mandatory = $False)]
        [string]
        $TestScenariosFileName = "DefaultTestScenarios.json",

		[Parameter(Mandatory = $False)]
        [string]
		$TestScenarioID = [string]::Empty,
		
		[Parameter(Mandatory = $False)]
		[bool]
		$DevTestMode = $False
	)
	try
	{
			#Stage 1: Prerequisite
			$testsettings = [TestHelper]::PostCommandStartedAction($SubscriptionId, $AzSKModule,$AzSKModulePath,$MandatoryTestSettings,$UserDefinedTestSettings,$OrgPolicy);
			[TestHelper]::SetDevTestMode($DevTestMode)
			[TestContext] $testContext = [TestContext]::new($SubscriptionId,$PSCmdlet.MyInvocation)
			
			#Stage 2: Identify applicable test cases
			[CommonHelper]::Log("`r`nChecking applicable test cases and verify testsettings file...", [MessageType]::Information)
			[TestCase[]] $testcases = [TestHelper]::GetTestCases($TestScenariosFileName,$TestScenarioID, $Feature, $ModuleName, $TestCaseIDs, $ExcludeTestCaseIDs, $Priority, $ParallelScan)
			
			#Stage 3: Run applicable test case
			[TestCaseResult[]] $tcResults = @()
			if(($testcases | Measure-Object).Count -eq 0)
			{
				[CommonHelper]::Log("`r`nNo applicable test cases found.", [MessageType]::Information)
				return [CommonHelper]::AzSKTestLogFolderPath
			}
			else
			{
			
				$autoTCCount = @($testcases | ? { $_.AutomationStatus -ne 'Manual' -and  $_.Enabled -ne $false}).Count
				$currTCNum = 0
				if($null -ne $testcases -and $testcases.Count -gt 0){
					foreach ($testcase in $testcases){
						[TestCaseResult] $tcResult = $null
						if($testcase.Enabled)
						{
							$currTCNum++
							if($testcase.AutomationStatus -ne "Manual")
							{
								try 
								{
									[CommonHelper]::Log([Constants]::DoubleDashLine + "`r`nStarting test [$currTCNum/$autoTCCount]: [TestCaseID: $($testcase.TestCaseID)] [Description: $($testcase.Description)]`r`n"+[Constants]::SingleDashLine, [MessageType]::Information)
									$testrunner = [TestRunner]::new($SubscriptionId,$testcase,$testsettings,$testContext,$AzSKModule)					
									$tcResult = $testrunner.RunTestCase()
									[CommonHelper]::Log([Constants]::SingleDashLine + "`r`nCompleted test [$currTCNum/$autoTCCount]: [TestCaseID: $($testcase.TestCaseID)]`r`n"+[Constants]::DoubleDashLine, [MessageType]::Information)	
								}
								catch 
								{
									$tcResult = [TestCaseResult]::new($testCase,[TestStatus]::Error,$_)
								}
							}
							else
							{
								$tcResult = [TestCaseResult]::new($testCase,[TestStatus]::Manual,[string]::Empty)
							}
							[TestHelper]::ExportTestCaseResultToHost($tcResult,$AzSKModule)
							$tcResults += $tcResult
						}
					}		
					[CommonHelper]::Log("Summary", [MessageType]::Header)
					[TestHelper]::ExportTestCaseResultSummaryToHost($testcases,$tcResults)
				}
				else{
					[CommonHelper]::Log("Could not find any test case matching your criteria. Please check the input parameters", [MessageType]::Error)
				}
				
				[CommonHelper]::Log("Test Harness Completed", [MessageType]::Header)
				$ResultPath = [TestHelper]::PostCommandCompletedAction($tcResults, $AzSKModule);
			}
		}
	catch
	{
		[CommonHelper]::Log("Test-AzSK: $($_)", [MessageType]::Error)
		$_
		return [CommonHelper]::AzSKTestLogFolderPath
	}
	
	return $ResultPath	
}

