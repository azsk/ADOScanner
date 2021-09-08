Set-StrictMode -Version Latest 
class ADOControlCorrectness:ADOTestBase
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

	ADOControlCorrectness([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext)
	{
        $this.testsettings = $testsettings
	}

	[void] Execute()
	{
		switch ($this.testcase.TestMethod)
		{
            "Verify_Control_Correctness_Org_Success"
			{
				$this.AzureDevOps_Verify_Control_Correctness("Passed")
				break
			}
			"Verify_Control_Correctness_Proj_Fail"
			{
				$this.AzureDevOps_Verify_Control_Correctness("Failed")
				break
			}
			"Verify_Control_Correctness_Proj_Success"
			{
				$this.AzureDevOps_Verify_Control_Correctness("Passed")
				break
			}
			"Verify_Control_Correctness_Release_Fail"
			{
				$this.AzureDevOps_Verify_Control_Correctness("Failed")
				break
			}
			"Verify_Control_Correctness_Release_Success"
			{
				$this.AzureDevOps_Verify_Control_Correctness("Passed")
				break
			}
			"Verify_Control_Correctness_Build_Fail"
			{
				$this.AzureDevOps_Verify_Control_Correctness("Failed")
				break
			}
			"Verify_Control_Correctness_Build_Success"
			{
				$this.AzureDevOps_Verify_Control_Correctness("Passed")
				break
			}
			"Verify_Control_Correctness_AgentPool_Fail"
			{
				$this.AzureDevOps_Verify_Control_Correctness("Failed")
				break
			}
			"Verify_Control_Correctness_AgentPool_Success"
			{
				$this.AzureDevOps_Verify_Control_Correctness("Passed")
				break
			}
			"Verify_Control_Correctness_SVC_Fail"  
			{
				$this.AzureDevOps_Verify_Control_Correctness("Failed")
				break
			}
			"Verify_Control_Correctness_SVC_Success" 
			{
				$this.AzureDevOps_Verify_Control_Correctness("Passed")
				break
			}
			"Verify_Control_Correctness_VarGroup_Fail"  
			{
				$this.AzureDevOps_Verify_Control_Correctness("Failed")
				break
			}
			"Verify_Control_Correctness_VarGroup_Success" 
			{
				$this.AzureDevOps_Verify_Control_Correctness("Passed")
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
        $testMetadata = "" | Select-Object command, excludedControls , passedMsg
        $OrgName = $this.testContext.ADOTestResources.Org
		switch ($this.testcase.TestMethod)
		{
            "Verify_Control_Correctness_Org_Success" 
			{
				$OrgName = $this.testsettings.ADOSettings.ControlCorrectness.Organization.OrgName
				$controlIds = $this.testsettings.ADOSettings.ControlCorrectness.Organization.IncludedControls
				$controlString = $controlIds -join "," 
                $command = "gads -OrganizationName $OrgName  -ResourceTypeName Organization  -ControlIds `"$controlString`" "   
                $testMetadata.command = $command
                $testMetadata.excludedControls = $this.testsettings.ADOSettings.ControlCorrectness.Organization.excludedControls
                $testMetadata.passedMsg = "All Controls related to given Org were returning  status as Passed"
				break
            }
			"Verify_Control_Correctness_Proj_Fail"
			{
				$projName = $this.testsettings.ADOSettings.ControlCorrectness.Project.FailedProjectName
				$controlIds = $this.testsettings.ADOSettings.ControlCorrectness.Project.IncludedControls
				$controlString = $controlIds -join "," 
                $command = "gads -OrganizationName $OrgName -ProjectNames `"$projName`"  -ControlIds `"$controlString`" " 
                $testMetadata.command = $command
                $testMetadata.excludedControls = $this.testsettings.ADOSettings.ControlCorrectness.Project.excludedControls
                $testMetadata.passedMsg = "All Controls related to given Project were returning status as Failed"
				break
			}
			"Verify_Control_Correctness_Proj_Success"
			{
				$projName = $this.testsettings.ADOSettings.ControlCorrectness.Project.PassedProjectName
				$controlIds = $this.testsettings.ADOSettings.ControlCorrectness.Project.IncludedControls
				$controlString = $controlIds -join "," 
                $command = "gads -OrganizationName $OrgName -ProjectNames `"$projName`"  -ResourceTypeName Project -ControlIds `"$controlString`" " 
                $testMetadata.command = $command
                $testMetadata.excludedControls = $this.testsettings.ADOSettings.ControlCorrectness.Project.excludedControls
                $testMetadata.passedMsg = "All Controls related to given Project were returning  status as Passed."
				break
			}
			"Verify_Control_Correctness_Release_Fail"
			{
                $projName = $this.testsettings.ADOSettings.ControlCorrectness.Release.FailedProjectName
				$releaseName = $this.testsettings.ADOSettings.ControlCorrectness.Release.FailedRelease
				$controlIds = $this.testsettings.ADOSettings.ControlCorrectness.Release.IncludedControls
				$controlString = $controlIds -join "," 
                $command = "gads -OrganizationName $OrgName -ProjectNames `"$projName`" -ReleaseNames  `"$releaseName`"   -ResourceTypeName Release  -ControlIds `"$controlString`" " 
                $testMetadata.command = $command
                $testMetadata.excludedControls = $this.testsettings.ADOSettings.ControlCorrectness.Release.excludedControls
                $testMetadata.passedMsg = "All Controls related to given Release were returning  status as Failed."
				break
			}
			"Verify_Control_Correctness_Release_Success"
			{
                $projName = $this.testsettings.ADOSettings.ControlCorrectness.Release.PassedProjectName
				$releaseName = $this.testsettings.ADOSettings.ControlCorrectness.Release.PassedRelease  
				$controlIds = $this.testsettings.ADOSettings.ControlCorrectness.Release.IncludedControls
				$controlString = $controlIds -join ","              
                $command = "gads -OrganizationName $OrgName -ProjectNames `"$projName`" -ReleaseNames  `"$releaseName`"   -ResourceTypeName Release  -ControlIds `"$controlString`" " 
                $testMetadata.command = $command
                $testMetadata.excludedControls = $this.testsettings.ADOSettings.ControlCorrectness.Release.excludedControls
                $testMetadata.passedMsg = "All Controls related to given Project were returning  status as Passed."
				break
			}
			"Verify_Control_Correctness_Build_Fail"
			{
                $projName = $this.testsettings.ADOSettings.ControlCorrectness.Build.FailedProjectName
				$buildName = $this.testsettings.ADOSettings.ControlCorrectness.Build.FailedBuild     
				$controlIds = $this.testsettings.ADOSettings.ControlCorrectness.Build.IncludedControls
				$controlString = $controlIds -join ","             
                $command = "gads -OrganizationName $OrgName -ProjectNames `"$projName`"  -BuildNames  `"$buildName`"   -ResourceTypeName Build  -ControlIds `"$controlString`" " 
                $testMetadata.command = $command
                $testMetadata.excludedControls = $this.testsettings.ADOSettings.ControlCorrectness.Build.excludedControls
                $testMetadata.passedMsg = "All Controls related to given Build were returning  status as Failed."
				break
			}
			"Verify_Control_Correctness_Build_Success"
			{
                $projName = $this.testsettings.ADOSettings.ControlCorrectness.Build.PassedProjectName
				$buildName = $this.testsettings.ADOSettings.ControlCorrectness.Build.PassedBuild    
				$controlIds = $this.testsettings.ADOSettings.ControlCorrectness.Build.IncludedControls
				$controlString = $controlIds -join ","            
                $command = "gads -OrganizationName $OrgName -ProjectNames `"$projName`"  -BuildNames  `"$buildName`"   -ResourceTypeName Build  -ControlIds `"$controlString`" " 
                $testMetadata.command = $command
                $testMetadata.excludedControls = $this.testsettings.ADOSettings.ControlCorrectness.Build.excludedControls
                $testMetadata.passedMsg = "All Controls related to given Build were returning  status as Passed."
				break
			}
			"Verify_Control_Correctness_AgentPool_Fail"
			{
                $projName = $this.testsettings.ADOSettings.ControlCorrectness.AgentPool.FailedProjectName
				$agentPool = $this.testsettings.ADOSettings.ControlCorrectness.AgentPool.FailedAgentPool    
				$controlIds = $this.testsettings.ADOSettings.ControlCorrectness.AgentPool.IncludedControls
				$controlString = $controlIds -join ","              
                $command = "gads -OrganizationName $OrgName -ProjectNames `"$projName`" -AgentPoolNames  `"$agentPool`"  -ResourceTypeName AgentPool  -ControlIds `"$controlString`" " 
                $testMetadata.command = $command
                $testMetadata.excludedControls = $this.testsettings.ADOSettings.ControlCorrectness.AgentPool.excludedControls
                $testMetadata.passedMsg = "All Controls related to given AgentPool were returning  status as Failed."
				break
			}
			"Verify_Control_Correctness_AgentPool_Success"
			{
                $projName = $this.testsettings.ADOSettings.ControlCorrectness.AgentPool.PassedProjectName
				$agentPool = $this.testsettings.ADOSettings.ControlCorrectness.AgentPool.PassedAgentPool 
				$controlIds = $this.testsettings.ADOSettings.ControlCorrectness.AgentPool.IncludedControls
				$controlString = $controlIds -join ","              
                $command = "gads -OrganizationName $OrgName -ProjectNames `"$projName`"  -AgentPoolNames  `"$agentPool`"   -ResourceTypeName AgentPool -ControlIds `"$controlString`" " 
                $testMetadata.command = $command
                $testMetadata.excludedControls = $this.testsettings.ADOSettings.ControlCorrectness.AgentPool.excludedControls
                $testMetadata.passedMsg = "All Controls related to given AgentPool were returning  status as Passed."
				break
			}
			"Verify_Control_Correctness_SVC_Fail"
			{
                $projName = $this.testsettings.ADOSettings.ControlCorrectness.ServiceConnection.FailedProjectName
				$svc = $this.testsettings.ADOSettings.ControlCorrectness.ServiceConnection.FailedSvc   
				$controlIds = $this.testsettings.ADOSettings.ControlCorrectness.ServiceConnection.IncludedControls
				$controlString = $controlIds -join ","            
                $command = "gads -OrganizationName $OrgName -ProjectNames `"$projName`"  -ServiceConnectionNames  `"$svc`"   -ResourceTypeName ServiceConnection -ControlIds `"$controlString`" " 
                $testMetadata.command = $command
                $testMetadata.excludedControls = $this.testsettings.ADOSettings.ControlCorrectness.ServiceConnection.excludedControls
                $testMetadata.passedMsg = "All Controls related to given ServiceConnection were returning  status as Failed."
				break
			}
			"Verify_Control_Correctness_SVC_Success"
			{
                $projName = $this.testsettings.ADOSettings.ControlCorrectness.ServiceConnection.PassedProjectName
				$svc = $this.testsettings.ADOSettings.ControlCorrectness.ServiceConnection.PassedSvc   
				$controlIds = $this.testsettings.ADOSettings.ControlCorrectness.ServiceConnection.IncludedControls
				$controlString = $controlIds -join ","           
                $command = "gads -OrganizationName $OrgName -ProjectNames `"$projName`"  -ServiceConnectionNames  `"$svc`"   -ResourceTypeName ServiceConnection  -ControlIds `"$controlString`" " 
                $testMetadata.command = $command
                $testMetadata.excludedControls = $this.testsettings.ADOSettings.ControlCorrectness.ServiceConnection.excludedControls
                $testMetadata.passedMsg = "All Controls related to given ServiceConnection were returning  status as Passed."
				break
			}
			"Verify_Control_Correctness_VarGroup_Fail"
			{
                $projName = $this.testsettings.ADOSettings.ControlCorrectness.VariableGroup.FailedProjectName
				$vargroups = $this.testsettings.ADOSettings.ControlCorrectness.VariableGroup.FailedVarGroup 
				$controlIds = $this.testsettings.ADOSettings.ControlCorrectness.VariableGroup.IncludedControls
				$controlString = $controlIds -join ","             
                $command = "gads -OrganizationName $OrgName -ProjectNames `"$projName`"  -VariableGroupNames  `"$vargroups`"   -ResourceTypeName VariableGroup  -ControlIds `"$controlString`" " 
                $testMetadata.command = $command
                $testMetadata.excludedControls = $this.testsettings.ADOSettings.ControlCorrectness.VariableGroup.excludedControls
                $testMetadata.passedMsg = "All Controls related to given VariableGroup were returning  status as Failed."
				break
			}
			"Verify_Control_Correctness_VarGroup_Success"
			{
                $projName = $this.testsettings.ADOSettings.ControlCorrectness.VariableGroup.PassedProjectName
				$vargroups = $this.testsettings.ADOSettings.ControlCorrectness.VariableGroup.PassedVarGroup  
				$controlIds = $this.testsettings.ADOSettings.ControlCorrectness.VariableGroup.IncludedControls
				$controlString = $controlIds -join ","            
                $command = "gads -OrganizationName $OrgName -ProjectNames `"$projName`"  -VariableGroupNames  `"$vargroups`"   -ResourceTypeName VariableGroup  -ControlIds `"$controlString`" " 
                $testMetadata.command = $command
                $testMetadata.excludedControls = $this.testsettings.ADOSettings.ControlCorrectness.VariableGroup.excludedControls
                $testMetadata.passedMsg = "All Controls related to given VariableGroup were returning  status as Passed."
				break
			}
			Default 
			{					
			}
        }
        return $testMetadata
	}

    #Function to fetch the respective command for control correctness and verify the expected status
    [TestCaseResult] AzureDevOps_Verify_Control_Correctness([string]$status)
    {
        # fetch the command metadata which includes command string, passed message and controlIds to exclude for status check
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

        #### Validate the scan report against the expected status		
        $bPass1 = $results.WereScanResultsGiveExpectedStatus($status, $testMetadata.excludedControls)

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
