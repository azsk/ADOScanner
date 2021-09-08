Set-StrictMode -Version Latest 
class ADOScanning:ADOTestBase
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

	ADOScanning([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext)
	{
		$this.testsettings = $testsettings
	}

	[void] Execute()
	{
		switch ($this.testcase.TestMethod)
		{
			"Test_Control_Errors_For_Org"
			{
				$this.Test_Control_Errors_For_Org()
				break
			}
			"Test_Control_Errors_For_Proj"
			{
				$this.Test_Control_Errors_For_Specific_Type()
				break
			}
			"Test_Control_Errors_For_User"
			{
				$this.Test_Control_Errors_For_User()
				break
			}
			"Test_Control_Errors_For_Build"
			{
				$this.Test_Control_Errors_For_Specific_Type()
				break
			}
			"Test_Control_Errors_For_AgentPool"
			{
				$this.Test_Control_Errors_For_Specific_Type()
				break
            }
			"Test_Control_Errors_For_ServiceConnection"
			{
				$this.Test_Control_Errors_For_Specific_Type()
				break
            }
			"Test_Control_Errors_For_Release"
			{
				$this.Test_Control_Errors_For_Specific_Type()
				break
			}
			"Test_ControlId_Scan_Check" 
			{
				$this.Test_ControlId_Scan_Check()
				break				
			}
			"Test_Baseline_controls_Scan_Check" 
			{
				$this.Test_Baseline_controls_Scan_Check()
				break				
            }
			"Test_Severity_Scan_Check" 
			{
				$this.Test_Severity_Scan_Check()
				break				
            }
			Default 
			{					
			}
		}
    }
    
    # create scan command for respective testcase and send relavant metadata for each testcase
	[PSCustomObject] FetchTestMetadata()
	{
        $Org = $this.testContext.ADOTestResources.Org
        $projectList = $this.testsettings.ADOSettings.Scanning.ProjectNames
        $projNames =  [system.String]::Join(",", $projectList)
        $testMetadata = "" | Select-Object command, resources, passedMsg
		switch ($this.testcase.TestMethod)
		{
            "Test_Control_Errors_For_Org" 
			{
                $command = "gads -OrganizationName $Org -ResourceTypeName Organization" 
                $testMetadata.command = $command
                $testMetadata.resources = $Org
                $testMetadata.passedMsg = "All Controls related to Organizations were scanned."
				break
			}
			"Test_Control_Errors_For_Proj"
			{
                $command = "gads -OrganizationName $Org -ProjectNames `"$projNames`" -ResourceTypeName Project" 
                $testMetadata.command = $command
                $testMetadata.resources = $projectList
                $testMetadata.passedMsg = "All Projects  from the specified project list were scanned."
				break
			}
			"Test_Control_Errors_For_User"
			{
                $Org = $this.testContext.ADOTestResources.Org
                $command = "gads -OrganizationName $Org  -ResourceTypeName User "  
                $testMetadata.command = $command
                $testMetadata.resources = ""   
                $testMetadata.passedMsg = "Only the user controls  were scanned." 
				break
			}
			"Test_Control_Errors_For_Build"
			{
                $buildList = $this.testsettings.ADOSettings.Scanning.BuildNames
                $buildNames =  [system.String]::Join(",", $buildList)
                $command = "gads -OrganizationName $Org -ProjectNames `"$projNames`" -BuildNames `"$buildNames`"  -ResourceTypeName Build" 
                $testMetadata.command = $command
                $testMetadata.resources = $buildList   
                $testMetadata.passedMsg = "All Builds  from the specified build list were scanned."             
                break
			}
			"Test_Control_Errors_For_AgentPool"
			{
                $agentPoolList = $this.testsettings.ADOSettings.Scanning.AgentPoolNames
                $agentPoolNames =  [system.String]::Join(",", $agentPoolList)
                $command = "gads -OrganizationName $Org -ProjectNames `"$projNames`" -AgentPoolNames `"$agentPoolNames`"  -ResourceTypeName AgentPool"  
                $testMetadata.command = $command
                $testMetadata.resources = $agentPoolList  
                $testMetadata.passedMsg = "All AgentPools  from the specified agentpool list were scanned."                
                break
            }
            "Test_Control_Errors_For_Release"
			{
                $releaseList = $this.testsettings.ADOSettings.Scanning.ReleaseNames
                $releaseNames =  [system.String]::Join(",", $releaseList)
                $command = "gads -OrganizationName $Org -ProjectNames `"$projNames`" -ReleaseNames `"$releaseNames`"  -ResourceTypeName Release"  
                $testMetadata.command = $command
                $testMetadata.resources = $releaseList    
                $testMetadata.passedMsg = "All Releases  from the specified release list were scanned."              
                break
            }
            "Test_Control_Errors_For_ServiceConnection" 
            {
                $scList = $this.testsettings.ADOSettings.Scanning.ServiceConnections
                $scNames =  [system.String]::Join(",", $scList)
                $command = "gads -OrganizationName $Org -ProjectNames `"$projNames`" -ServiceConnectionNames `"$scNames`"  -ResourceTypeName ServiceConnection"  
                $testMetadata.command = $command
                $testMetadata.resources = $scList    
                $testMetadata.passedMsg = "All ServiceConnections  from the specified serviceconnection list were scanned."             
                break                
            }
			"Test_ControlId_Scan_Check" 
			{
                $controlId = $this.testsettings.ADOSettings.Scanning.ControlID
                $command = "gads -OrganizationName $Org -ControlIds `"$controlId`" "  
                $testMetadata.command = $command
                $testMetadata.resources = $controlId    
                $testMetadata.passedMsg = "Only the specified ControlID is being scanned."  
				break				
			}
			"Test_Baseline_controls_Scan_Check" 
			{
                $command = "gads -OrganizationName $Org -UseBaselineControls " 
                $testMetadata.command = $command
                $testMetadata.resources = ""    
                $testMetadata.passedMsg = "Only the baseline controls were scanned."  
				break				
            }
			"Test_Severity_Scan_Check" 
			{
                $command = "gads -OrganizationName $Org  -ProjectNames `"$projNames`" -ResourceTypeName Project -Severity High" 
                $testMetadata.command = $command
                $testMetadata.resources = ""    
                $testMetadata.passedMsg = "Only the High Severity controls were scanned."  
				break				
			}
			Default 
			{					
			}
        }
        return $testMetadata
	}

    ############# Run the gads command for specified org, check if any errors and validate the result #########
    [TestCaseResult] Test_Control_Errors_For_Org()
    {
        $testMetadata = $this.FetchTestMetadata()

        $description =  $this.testCase.Description
        $tcName =  $this.testCase.TestMethod

        $results = $null
        if ($true)
        {
            [TestHelper]::RunAzSKCommand($testMetadata.command, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)

            $retObj = [TestHelper]::GetAzSKCommandResults($tcName)
            $outPath = $retObj.ReturnVal
            $scanError = $retObj.Error

            $results = [AzSKScanResults]::new($outPath, $this.testContext.ADOTestResources.ResourceInfo)
        }

        #### Validate		
        $bPass1 = $results.WereOrganizationControlsScanned($testMetadata.resources)

        $bPassed = $bPass1
        $failedMsg = ""
        if (-not $bPassed) 
        {
            $failedMsg = $results.GetErrMsg() 		
        }
        $passedMsg = $testMetadata.passedMsg
        
        $this.testcaseResult = [ADOScanning]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $testMetadata.command)
        return $this.testcaseResult
    }


    <# Run the gads command for specified release/build/agentpool/serviceconntection/release
     check if any errors and validate the result #>
    [TestCaseResult] Test_Control_Errors_For_Specific_Type()
    {
        $testMetadata = $this.FetchTestMetadata()

        $description =  $this.testCase.Description
        $tcName =  $this.testCase.TestMethod

        $results = $null
        if ($true)
        {
            [TestHelper]::RunAzSKCommand($testMetadata.command, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)

            $retObj = [TestHelper]::GetAzSKCommandResults($tcName)
            $outPath = $retObj.ReturnVal
            $scanError = $retObj.Error

            $results = [AzSKScanResults]::new($outPath, $this.testContext.ADOTestResources.ResourceInfo)
        }

        #### Validate		
        $bPass1 = $results.WereAllExpectedResourcesScanned($testMetadata.resources)

        $bPassed = $bPass1
        $failedMsg = ""
        if (-not $bPassed) 
        {
            $failedMsg = $results.GetErrMsg() 		
        }
        $passedMsg = $testMetadata.passedMsg
        
        $this.testcaseResult = [ADOScanning]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $testMetadata.command)
        return $this.testcaseResult
    }

    # Perform scan for specified severity and validate the results
    [TestCaseResult] Test_Severity_Scan_Check()
    {
        $testMetadata = $this.FetchTestMetadata()
        $description =  $this.testCase.Description
        $tcName =  $this.testCase.TestMethod

        $results = $null
        if ($true)
        {
            [TestHelper]::RunAzSKCommand($testMetadata.command, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)

            $retObj = [TestHelper]::GetAzSKCommandResults($tcName)
            $outPath = $retObj.ReturnVal
            $scanError = $retObj.Error

            $results = [AzSKScanResults]::new($outPath, $this.testContext.ADOTestResources.ResourceInfo)
        }

        #### Validate		
        $bPass1 = $results.WereOnlyHighSeverityControlsScanned()

        $bPassed = $bPass1
        $failedMsg = ""
        if (-not $bPassed) 
        {
            $failedMsg = $results.GetErrMsg() 		
        }
        $passedMsg = $testMetadata.passedMsg
        
        $this.testcaseResult = [ADOScanning]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $testMetadata.command)
        return $this.testcaseResult
    }

    # Perform scan for usertype controls and validate the result
    [TestCaseResult] Test_Control_Errors_For_User()
    {
        $testMetadata = $this.FetchTestMetadata()
        $description =  $this.testCase.Description
        $tcName =  $this.testCase.TestMethod

        $results = $null
        if ($true)
        {
            [TestHelper]::RunAzSKCommand($testMetadata.command, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)

            $retObj = [TestHelper]::GetAzSKCommandResults($tcName)
            $outPath = $retObj.ReturnVal
            $scanError = $retObj.Error

            $results = [AzSKScanResults]::new($outPath, $this.testContext.ADOTestResources.ResourceInfo)
        }

        #### Validate		
        $bPass1 = $results.WereUserControlsScanned()

        $bPassed = $bPass1
        $failedMsg = ""
        if (-not $bPassed) 
        {
            $failedMsg = $results.GetErrMsg() 		
        }
        $passedMsg = $testMetadata.passedMsg
        
        $this.testcaseResult = [ADOScanning]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $testMetadata.command)
        return $this.testcaseResult
    }


    # Perform the scan for particular controlId and validate the result
    [TestCaseResult] Test_ControlId_Scan_Check()
    {
        $testMetadata = $this.FetchTestMetadata() 

        $description =  $this.testCase.Description
        $tcName =  $this.testCase.TestMethod

        $results = $null
        if ($true)
        {
            [TestHelper]::RunAzSKCommand($testMetadata.command, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)

            $retObj = [TestHelper]::GetAzSKCommandResults($tcName)
            $outPath = $retObj.ReturnVal
            $scanError = $retObj.Error

            $results = [AzSKScanResults]::new($outPath, $this.testContext.ADOTestResources.ResourceInfo)
        }

        #### Validate		
        $bPass1 = $results.WereExpectedControlsScanned($testMetadata.resources)

        $bPassed = $bPass1
        $failedMsg = ""
        if (-not $bPassed) 
        {
            $failedMsg = $results.GetErrMsg() 		
        }
        $passedMsg = $testMetadata.passedMsg
        
        $this.testcaseResult = [ADOScanning]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $testMetadata.command)
        return $this.testcaseResult
    }

    # Perform the scan for baseline controls and validate the result
    [TestCaseResult] Test_Baseline_controls_Scan_Check()
    {
        $testMetadata = $this.FetchTestMetadata() 

        $description =  $this.testCase.Description
        $tcName =  $this.testCase.TestMethod

        $results = $null
        if ($true)
        {
            [TestHelper]::RunAzSKCommand($testMetadata.command, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)

            $retObj = [TestHelper]::GetAzSKCommandResults($tcName)
            $outPath = $retObj.ReturnVal
            $scanError = $retObj.Error

            $results = [AzSKScanResults]::new($outPath, $this.testContext.ADOTestResources.ResourceInfo)
        }

        #### Validate		
        $bPass1 = $results.WereOnlyBaseLineControlsScanned()

        $bPassed = $bPass1
        $failedMsg = ""
        if (-not $bPassed) 
        {
            $failedMsg = $results.GetErrMsg() 		
        }
        $passedMsg = $testMetadata.passedMsg
        
        $this.testcaseResult = [ADOScanning]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $testMetadata.command)
        return $this.testcaseResult
    }
	[void] Cleanup()
	{
	}
}
