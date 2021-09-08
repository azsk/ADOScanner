Set-StrictMode -Version Latest 
class ADOBugLogging:ADOTestBase
{	
    [PSCustomObject[]] $testsettings = @();
	static [TestCaseResult] CreateResult([TestCase] $testCase, [bool] $bPassed, [string] $passedMsg, [string] $failedMsg, [string] $cmdStr)
	{
		[TestCaseResult] $tcResult = $null

		if ($bPassed)  
		{
			$tcResult =[TestCaseResult]::new($testCase,[TestStatus]::Passed,"$passedMsg")
		}
		else
		{
			$tcResult =[TestCaseResult]::new($testCase,[TestStatus]::Failed,"Command used: [$cmdStr]`r`n$failedMsg")
		}
		return $tcResult
	}

	ADOBugLogging([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext)
	{
        $this.testsettings = $testsettings
	}

	[void] Execute()
	{
		switch ($this.testcase.TestMethod)
		{
			"Verify_Bug_Logging_For_Controls_Failed"
			{
				$this.Verify_Bug_Logging_For_Controls_Failed()
				break
			}
			"Verify_Bug_Duplicate_Logging_For_Controls_Failed" 
			{
				$this.Verify_Duplicate_Bug_Logging_For_Controls_Failed()
				break
			}
			Default 
			{					
			}
		}
	}


#13Y
[TestCaseResult] Verify_Bug_Logging_For_Controls_Failed()
{
    $Org = $this.testContext.ADOTestResources.Org

	$projName = $this.testsettings.ADOSettings.BugLogging.Verify_Bug_Logging_For_Controls_Failed.Project

    $cmdStr = "gads -OrganizationName $Org -ProjectNames `"$projName`" -ResourceTypeName Project  -AutoBugLog All"  

    $description =  $this.testCase.Description
    $tcName =  $this.testCase.TestMethod

    $results = $null
    if ($true)
    {
        [TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)

        $retObj = [TestHelper]::GetAzSKCommandResults($tcName)
        $outPath = $retObj.ReturnVal
        $scanError = $retObj.Error

        $results = [AzSKScanResults]::new($outPath, $this.testContext.ADOTestResources.ResourceInfo)
    }

    #### Validate		
    $bPass1 = $results.WereAllFailureControlsLogged()

    $bPassed = $bPass1
      $failedMsg = ""
     if (-not $bPassed) 
    {
         $failedMsg = $results.GetErrMsg() 		
    }
      $passedMsg = "All the scan results with status Failed/Verfiy are logged."
    
    $this.testcaseResult = [ADOScanning]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $cmdStr)
    return $this.testcaseResult
}

[TestCaseResult] Verify_Duplicate_Bug_Logging_For_Controls_Failed()
{
    $Org = $this.testContext.ADOTestResources.Org

	$projName = $this.testsettings.ADOSettings.BugLogging.Verify_Bug_Duplicate_Logging_For_Controls_Failed.Project

	$controlId = $this.testsettings.ADOSettings.BugLogging.Verify_Bug_Duplicate_Logging_For_Controls_Failed.ControlID

	$currentWorkItem = $this.testsettings.ADOSettings.BugLogging.Verify_Bug_Duplicate_Logging_For_Controls_Failed.ExistedWorkItem

    $cmdStr = "gads -OrganizationName $Org -ProjectNames `"$projName`" -ResourceTypeName Project  -AutoBugLog All"  

    $description =  $this.testCase.Description
    $tcName =  $this.testCase.TestMethod

    $results = $null
    if ($true)
    {
        #run the command twice and verify if any new bugs are created for second time
        [TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)
        [TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)
        $retObj = [TestHelper]::GetAzSKCommandResults($tcName)
        $outPath = $retObj.ReturnVal
        $scanError = $retObj.Error

        $results = [AzSKScanResults]::new($outPath, $this.testContext.ADOTestResources.ResourceInfo)
    }

    #### Validate		
    $bPass1 = $results.WereDuplicateBugsLogged($currentWorkItem);

    $bPassed = $bPass1
      $failedMsg = ""
     if (-not $bPassed) 
    {
         $failedMsg = $results.GetErrMsg() 		
    }
      $passedMsg = "No duplicate bugs were logged on rescan."
    
    $this.testcaseResult = [ADOScanning]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $cmdStr)
    return $this.testcaseResult
}


	[void] Cleanup()
	{
	}
}
