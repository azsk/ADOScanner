Set-StrictMode -Version Latest
class CommonTest:AzSKTestBase
{
    CommonTest([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
    }

	[Void]Initialize(){
		[CommonHelper]::ScanJobs = @()
		[ParallelScan]::Jobs = @()
	}

	[void] Execute()
	{
		switch ($this.testcase.TestMethod)
		{
			"RunAzSKCommandsAsJobOnLocal"{
				$this.RunAzSKCommandsAsJobOnLocal()
				break
			}
			"CompareResultProdVsNonProd"{
				$this.CompareResultProdVsNonProd()
				break
			}
		}
	}

	[TestCaseResult] RunAzSKCommandsAsJobOnLocal()
	{
		$this.testCaseResult.TestStatus = [TestStatus]::NotStarted;
		$JobsId = $this.RunAzSKCommandsAsJob($this.testContext.HarnessSettings.AzSKModule,$this.testContext.HarnessSettings.AzSKModulePath,$this.TestCase.ScanType, $false)
		$CommandScanResults = [TestHelper]::ValidateAzSKJobsResult($JobsId, $this.testContext.HarnessSettings.AzSKModulePath, $this.TestCase.TestCaseID, [ParallelScan]::Jobs)
		$TestStatus = [TestHelper]::GetAzSKCommandStatus($CommandScanResults)
		$this.testCaseResult = [TestCaseResult]::new($this.testCase,$TestStatus, $("Sanity check scan on AzSK commands '#status#'. Please check ParallelScanResult.csv file for more details." -replace "#status#", $TestStatus))

		return $this.testCaseResult
	}

	[PSObject] RunAzSKCommandsAsJob([string[]] $AzSKModules, [string] $AzSKModulePath, [string] $ScanType, [bool] $SkipWait)
	{
		[PSObject]$JobsId = @()
		try
		{
			$SubscriptionId = $this.testContext.TestResources.SubscriptionId
			$AzSKModules | ForEach-Object {
				[ParallelScan]::LoadParallelScanCommand($_,$AzSKModulePath,$SubscriptionId,$this.testContext);
			}
			$Jobs = [ParallelScan]::Jobs
			if((($AzSKModules|Measure-Object).Count -gt 1) -and ($AzSKModules -contains "AzSK"))
			{
				$Jobs = $Jobs | Where-Object {$_.JobName -match "^G([RS]|AC)S"}
			}
			if(![string]::IsNullOrEmpty([Constants]::SkipJobsInParallelScan))
			{
				$Jobs = $Jobs | Where-Object {$_.JobName -notmatch [Constants]::SkipJobsInParallelScan}
			}
			if(![string]::IsNullOrEmpty([Constants]::RunJobsInParallelScan))
			{
				$Jobs = $Jobs | Where-Object {$_.JobName -match [Constants]::RunJobsInParallelScan} 
			}
			if($Jobs)
			{
				#Run Get Command
				Write-Host "`nRunning Get Commands:`n" -ForegroundColor Cyan;
				$JobsId += [CommonHelper]::RunParallelJobs(($Jobs | Where-Object {$_.JobName -match "^G.*"}) ,$ScanType, $SkipWait)
																										  
				#Run Install Command
				Write-Host "`nRunning Install Commands:`n" -ForegroundColor Cyan;						  
				$JobsId += [CommonHelper]::RunParallelJobs(($Jobs | Where-Object {$_.JobName -match "^I.*"}) ,"Sequential", $SkipWait)

				#Run Remove Command
				Write-Host "`nRunning Remove Commands:`n" -ForegroundColor Cyan;
				$JobsId += [CommonHelper]::RunParallelJobs(($Jobs | Where-Object {$_.JobName -match "^R.*"}) ,"Sequential", $SkipWait)
																										  
				#Run Set Command
				Write-Host "`nRunning Set Commands:`n" -ForegroundColor Cyan;														  
				$JobsId += [CommonHelper]::RunParallelJobs(($Jobs | Where-Object {$_.JobName -match "^S.*"}) ,"Sequential", $SkipWait)
			}
			else
			{
				throw "No jobs found for parallel scan."
			}
			
		}
		catch
		{
			[CommonHelper]::Log("Error while running AzSK commands in parallel. $($_)", [MessageType]::Error)
		}
		return $JobsId;		
	}


	#Compare CSV result of Prod and Non-Prod environment
	[TestCaseResult] CompareResultProdVsNonProd()
	{
		$TestStatus = @([TestStatus]::NotStarted)
		$message = ""
		try
		{
			#Trigger jobs in parallel
			#Basic Test
			[PSObject] $JobsId = $this.RunAzSKCommandsAsJob(@("AzSK", $this.testContext.HarnessSettings.AzSKModule),$this.testContext.HarnessSettings.AzSKModulePath,$this.TestCase.ScanType, $false)
			$CommandScanResults = [TestHelper]::ValidateAzSKJobsResult($JobsId, $this.testContext.HarnessSettings.AzSKModulePath, $this.TestCase.TestCaseID,[ParallelScan]::Jobs)
			
			#Skip CSV comparison if TestSuite is being run for Prod
			if($($this.testContext.HarnessSettings.AzSKModule) -eq "AzSK")
			{
				$this.testCaseResult = [TestCaseResult]::new($this.testCase, [TestStatus]::NotApplicable,'You are comparing Prod Vs Prod. This test case is not applicable.')
				return $this.testCaseResult
			}
			elseif(([ParallelScan]::Jobs | Measure-Object).Count -gt 0 -and ($CommandScanResults | Measure-Object).Count -gt 0)
			{
				$WhiteListedControlIds = $this.GetWhiteListedControlIds()
				$JobsId.Name | ForEach-Object { $_.Split("_")[0] } | Select-Object -Unique | ForEach-Object {
					$JobName = $_
					$Environment = @($($this.testContext.HarnessSettings.AzSKModule))
					if(![string]::IsNullOrEmpty($($this.testContext.HarnessSettings.AzSKModule)) -and ($($this.testContext.HarnessSettings.AzSKModule) -ne "AzSK"))
					{
						$Environment += "AzSK"
					}
					$Environment | ForEach-Object {
						$AzSKModule = $_
						$CommandScanResult = $CommandScanResults | Where-Object { $_.CommandName -eq $($JobName+'_' +$AzSKModule) }
						if(($CommandScanResult | Measure-Object).Count -gt 0 -and ($CommandScanResult.OutputPath| Measure-Object).Count -gt 0 `
								-and (Get-ChildItem -Path $CommandScanResult.OutputPath -Include "SecurityReport-*.csv" -Recurse))
						{
							Set-Variable -Name $("FolderPath"+$AzSKModule) -Value $CommandScanResult.OutputPath
						}						
					}
					$ProdFolderPath = Get-Variable -Name $("FolderPath"+"AzSK") -ValueOnly
					$LocalFolderPath = Get-Variable -Name $("FolderPath"+$($this.testContext.HarnessSettings.AzSKModule)) -ValueOnly
					if(![string]::IsNullOrEmpty($ProdFolderPath) -and ![string]::IsNullOrEmpty($LocalFolderPath) -and (Test-Path -Path $ProdFolderPath) -and (Test-Path -Path $LocalFolderPath))
					{
						$TestResult = [CommonHelper]::CompareCSV($ProdFolderPath,$LocalFolderPath,$WhiteListedControlIds)
						$TestStatus += $TestResult.TestStatus
						if($TestResult.TestStatus -eq [TestStatus]::Failed)
						{
							$message += "`n[JobName : $JobName] CSV output do not match. $($TestResult.Message)";
						}
						elseif($TestResult.TestStatus -eq [TestStatus]::Passed)
						{
							$message += "`n[JobName : $JobName] CSV Match.";
						}
					}
					else
					{
						$TestStatus += [TestStatus]::Failed
						$message += "`n[JobName : $JobName] Output folder of either prod or local scan not found."
					}
				}
				if($WhiteListedControlIds)
				{
					$message += "`n[Whitelisted Controls]`n $($WhiteListedControlIds -join ";`n")"
				}
			}
			else
			{
				$TestStatus += [TestStatus]::Failed
				$message += "`nJobs result not found."
			}
			$TestStatus = [TestHelper]::GetTestCaseStatus($TestStatus)
	    }
	    catch
	    {
	    	[CommonHelper]::Log("Error while comparing local with production. $($_)", [MessageType]::Error)
			$TestStatus = [TestStatus]::ScanInterrupted
	    }
		$this.testCaseResult = [TestCaseResult]::new($this.testCase, $TestStatus, $("#message# `n`rPlease check logs for more details." -replace "#message#", $message))
		return $this.testCaseResult
	}

	[String[]] GetWhiteListedControlIds() {
		$WhitelistedControlIds = $null
		if(!([string]::IsNullOrEmpty([Constants]::WhitelistedControlIds)))
		{
			$WhitelistedControlIds = [Constants]::WhitelistedControlIds;
		}
		if(!([string]::IsNullOrEmpty($this.TestCase.PropertiesFileName))){
			$propsFilePath = [CommonHelper]::GetRootPath() + "\TestCases\"+$this.TestCase.Feature+"\"+$this.TestCase.ModuleName+"\TestData\"+$this.TestCase.PropertiesFileName
			$WhitelistedControlIds += (Get-Content -Path $propsFilePath | ConvertFrom-Json).WhitelistedControlIds
		}
		$WhitelistedControlIds = $WhitelistedControlIds | Select-Object -Unique
		return $WhitelistedControlIds
	}

	[void]Cleanup(){
    }
}