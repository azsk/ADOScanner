Set-StrictMode -Version Latest 
class ADOPartialCommit:ADOTestBase
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

	ADOPartialCommit([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext)
	{
		$this.testsettings = $testsettings
	}

	[void] Execute()
	{
		switch ($this.testcase.TestMethod)
		{
			"Verify_PartialCommit_Project"
			{
				$this.Verify_PartialCommits_Project()
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
            "Verify_PartialCommits_Project" 
			{
                $command = "gads -OrganizationName $Org -ResourceTypeName Project -UsePartialCommits" 
                $testMetadata.command = $command
                $testMetadata.resources = ""
                $testMetadata.passedMsg = "All Controls related to Organizations were scanned."
				break
			}
			Default 
			{					
			}
        }
        return $testMetadata
	}

    ############# Run the gads command for specified org, check if any errors and validate the result #########
    [TestCaseResult] Verify_PartialCommits_Project()
    {
         $Command = " Get-AzSKAzureDevOpsSecurityStatus -OrganizationName "+$this.testsettings.org+" -ResourceTypeName Project -UsePartialCommits "

        $description =  $this.testCase.Description
		$tcName =  $this.testCase.TestMethod
		$resourceTrackerFile = $Env:LOCALAPPDATA+"\Microsoft\"+$this.testsettings.AzSKModule+"\TempState\PartialScanData\"+$this.testsettings.org+"\ResourceScanTracker.json"
		
        $ScriptBlock = { 
			param
			(
				[String] $Command,
				[String] $AzSKModule
			)
			Import-Module -Name $AzSKModule -Scope Global
			$output = Invoke-Expression ($Command.Split() -join ' ');
			$i = 0
			$ArchivedPSOutputError = $Error | Select-Object -Unique | ForEach-Object { $i++; "$($i): $($_.CategoryInfo.Activity)`n`r $($_.ScriptStackTrace) `n`r";  }
			Out-File -FilePath ($output + "ArchivedPSOutputError.LOG") -InputObject $ArchivedPSOutputError
			return $output
		}

		$Command = " Get-AzSKAzureDevOpsSecurityStatus -OrganizationName "+$this.testsettings.org+" -ResourceTypeName Project -UsePartialCommits "
		$AzSKModule = $this.testsettings.AzSKModule
		$InitialtimerInSeconds =  60
		$LatertimerInSeconds = 45

		<#
		Step-1 :
		Remove the resource tracker file if already exists
		#>
		if (Test-Path $resourceTrackerFile) 
		{
		  Remove-Item $resourceTrackerFile
		}
		<#
		Step-2 :
		Run the scan command, wait for 2 times the time configured in timer
		Stop the Job and check for pending resources
		#> 
		$Job = Start-Job -Name "ParticalCommit" -ScriptBlock $ScriptBlock -ArgumentList $Command, $AzSKModule
		Wait-Job -Id $Job.Id  -Timeout $InitialtimerInSeconds
		Stop-Job -Id $Job.Id
		$resourceTrackerContent = Get-Content -Raw -Path $resourceTrackerFile | ConvertFrom-Json
		$remainingResourcesInitial = @($resourceTrackerContent.ResourceMapTable | Where-Object {$_.State -eq "INIT"}).Count

		<#
		Step-3 :
		Run the scan command, wait for the time configured in timer
		Stop the Job and check for pending resources
		#> 
		$Job = Start-Job -Name "ParticalCommit" -ScriptBlock $ScriptBlock -ArgumentList $Command, $AzSKModule
		Wait-Job -Id $Job.Id  -Timeout $LatertimerInSeconds
		Stop-Job -Id $Job.Id
		$resourceTrackerContent = Get-Content -Raw -Path $resourceTrackerFile | ConvertFrom-Json
		$remainingResourcesLater = @($resourceTrackerContent.ResourceMapTable | Where-Object {$_.State -eq "INIT"}).Count

		<# 
		Step -4 Validation
		verify if current pending resources are  lesser than the Intial Pending resources for scan
		#>
		$bPass1 = $false
		if ($remainingResourcesLater -lt $remainingResourcesInitial) {
			$bPass1 = $true
		}

        $bPassed = $bPass1
        $failedMsg = ""
        if (-not $bPassed) 
        {
            $failedMsg = " PartialCommits is not scanning the resources where it left from previous scan"		
        }
        $passedMsg =  " PartialCommits is actually scanning the resources where it left from previous scan"
        
        $this.testcaseResult = [ADOScanning]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $command)
        return $this.testcaseResult
    }

	[void] Cleanup()
	{
	}
}
