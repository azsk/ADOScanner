Set-StrictMode -Version Latest 
class TestHelper{
	static $DevTestMode = $false
	static $CachedAzSKCmdResults = @{}
	#Gets the collection of the test cases based on the provided inputs
	static [TestCase[]] GetTestCases([string]$tsfileName,[string]$scenarioId,[string]$feature, [string]$moduleName, [string]$tcIds, [string]$exclTcIds, [string]$priority, [bool]$ParallelScan, [bool]$isADOTestCase){
		
		#Reading all test scenarios
		$scenariospath = [CommonHelper]::GetRootPath() + "\" + $tsfileName
		$AllScenarios = Get-Content -Path $scenariospath | ConvertFrom-Json
		
		#Reading all test cases
		if ($isADOTestCase) {
			$testcasespath = [CommonHelper]::GetRootPath()+"\ADOTestCasesMaster.json"
		}
		else {
			$testcasespath = [CommonHelper]::GetRootPath()+"\TestCasesMaster.json"
		}
        $AllTestCases = Get-Content -Path $testcasespath | ConvertFrom-Json

		#Collecting required test scenarios and test cases
		$ReqScenario = $null  #$Scenarios.TestScenarios.TestScenario
		$ReqTestCases= @()

		if(![string]::IsNullOrEmpty($scenarioId)){
            $ReqScenario= $AllScenarios.TestScenarios.TestScenario | Where-Object { $_.TestScenarioID -eq $ScenarioID }
			$ScriptBlock = [scriptblock]::Create($ReqScenario.Query)
            $ReqTestCases += $AllTestCases | Where-Object $ScriptBlock
        }
		else{
			$ReqTestCases = $AllTestCases
		}
		if(!([string]::IsNullOrEmpty($tcIds))){
			$tcIds2 = ($tcIds -split ',').Trim()
            $ReqTestCases = $ReqTestCases | Where-Object {$tcIds2 -contains $_.TestCaseID}
        }
		if(!([string]::IsNullOrEmpty($priority))){
            $ReqTestCases = $ReqTestCases | Where-Object {$_.Priority -eq $priority}
        }

        if(!([string]::IsNullOrEmpty($feature))){
            $ReqTestCases = $ReqTestCases | Where-Object {$_.Feature -eq $feature}
        }
        if(!([string]::IsNullOrEmpty($moduleName))){
            $ReqTestCases = $ReqTestCases | Where-Object {$_.ModuleName -eq $moduleName}
		}
		
		if(!([string]::IsNullOrEmpty($exclTcIds))){
			$exclTcIds2 = ($exclTcIds -split ',').Trim()
            $ReqTestCases = $ReqTestCases | Where-Object {$exclTcIds2 -notcontains $_.TestCaseID}
		}
		
		if($ParallelScan){
            $ReqTestCases | ForEach-Object { 
				if(($_ | Get-Member -Name ScanType | Measure-Object).Count -eq 0) 
				{
					$_ | Add-Member -MemberType NoteProperty -Name ScanType -Value "Parallel"
				}
				else
				{
					$_.ScanType = "Parallel"
				}
			}
        }

		#Removing duplicate test cases from the collection
		$ReqTestCases = $ReqTestCases | Sort-Object -Property "TestCaseID" -Unique

		return $ReqTestCases
	}
	
	static [void] SetDevTestMode([bool] $value)
	{
		[TestHelper]::DevTestMode = $value
	}

	#Writes the test case result to host
	static [void] ExportTestCaseResultToHost([TestCaseResult] $testcaseResult, [string]$AzSKModule) {
                $Report = "" | Select-Object TestCaseID,Feature,ModuleName,AzSKModule,Description,TestStatus,Message
                $Report.TestCaseID= $testcaseResult.TestCase.TestCaseID
                $Report.Feature=$testcaseResult.TestCase.Feature
                $Report.ModuleName=$testcaseResult.TestCase.ModuleName
                $Report.AzSKModule=$AzSKModule
                $Report.Description=$testcaseResult.TestCase.Description
				$Report.TestStatus =$testcaseResult.TestStatus
                $Report.Message=$testcaseResult.Message      

		if ($Report.TestStatus -eq [TestStatus]::Passed)
		{
			$fgColor = 'Green'
		}
		else {
			$fgColor = 'Red'
		}

        Write-Host -ForegroundColor $fgColor ($Report |Format-List | Out-String)    
     }

	#Print test case summary to host
	static [void] ExportTestCaseResultSummaryToHost([TestCase[]]$testcases,[TestCaseResult[]]$testcaseresults){
		
		$Summary = @()
		$testcaseresults | where { $_.TestCase.Enabled -eq $true }| Select-Object * | ForEach-Object {
			$result = "" | Select-Object TestCaseID, TestStatus, Message
			$result.TestCaseID = $_.TestCase.TestCaseID
			$result.TestStatus = $_.TestStatus
			$result.Message = $_.Message

			$Summary +=$result
		}
		$runtests = $testcases | Where-Object {$_.Enabled -eq $true}
		Write-Host "`n`rTest Cases Count : $(($runtests | Measure-Object).Count) `n`r"
		Write-Host ($Summary | Select-Object | Out-String)
	}

	#Writes the test case summary to csv file.
	static [void] ExportTestResultSummaryToCSV([TestCaseResult[]] $testcaseResults, [string]$resultPath, [string]$AzSKModule) {
				$ReportItems = @()
				$testcaseResults | ForEach-Object{
				$testcaseResult = $_
                $ReportItem = "" | Select-Object TestCaseID,Feature,Priority,Type,ModuleName,AzSKModule,Description,TestStatus,Message, ManualSteps,TimeOfExecution
                $ReportItem.TestCaseID= $testcaseResult.TestCase.TestCaseID
                $ReportItem.Feature=$testcaseResult.TestCase.Feature
				$ReportItem.Priority=$testcaseResult.TestCase.Priority
                $ReportItem.Type=$testcaseResult.TestCase.Type
                $ReportItem.ModuleName=$testcaseResult.TestCase.ModuleName
                $ReportItem.AzSKModule = $AzSKModule
                $ReportItem.Description=$testcaseResult.TestCase.Description
                $ReportItem.TestStatus=$testcaseResult.TestStatus
                $ReportItem.Message=$testcaseResult.Message
                $ReportItem.TimeOfExecution=Get-date -Format g
				if(![string]::IsNullOrEmpty($testcaseResult.TestCase.ManualSteps)){
					$ReportItem.ManualSteps =  $testcaseResult.TestCase.ManualSteps   
				}  

				$ReportItems += $ReportItem
			}
			$ReportItems |Export-Csv $resultPath -NoTypeInformation
        }

	#Export test result to ConsolidatedTestResults.csv
	 static [void] ExportConsolidatedTestResultsToCSV() {

		$Path =  [CommonHelper]::AzSKTestLogFolderPath
		$TestCaseResultContent = $null
		$ParallelScanResultContent = $null

		$TestCaseResultCSV = Get-ChildItem -Path ($Path + [constants]::AzSKTestCaseResultFileName)
		$ParallelScanResultCSV = Get-ChildItem -Path ($Path + [constants]::ParallelScanFileName)
		
		if(($TestCaseResultCSV | Measure-Object).Count -gt 0 -and $(Test-Path -Path $TestCaseResultCSV -ErrorAction SilentlyContinue))
		{
			$TestCaseResultContent = Import-Csv -Path $TestCaseResultCSV
		}
		if(($ParallelScanResultCSV | Measure-Object).Count -gt 0 -and $(Test-Path -Path $ParallelScanResultCSV -ErrorAction SilentlyContinue))
		{
			$ParallelScanResultContent = Import-Csv -Path $ParallelScanResultCSV
		}
		$CSVOutput = @()

		#Filter unique test cases
		if(($ParallelScanResultContent | Measure-Object).Count -gt 0)
		{
			$AzSKModules = $ParallelScanResultContent | Select-Object AzSKModule -Unique
			$ParallelScanResultContent = $AzSKModules.AzSKModule | ForEach-Object {
				$AzSKModule = $_
				$ParallelScanResultContent | Where-Object { $_.AzSKModule -eq $AzSKModule} | Sort-Object CommandName -Unique
			}
			if(($ParallelScanResultContent | Measure-Object).Count -gt 0)
			{
				$ParallelScanResultContent |Sort-Object -Property "CommandName" -Unique | ForEach-Object{
							$NewCSV = "" | Select-Object TestCaseID, TestStatus, Message, AzSKModule, Description
							$NewCSV.TestCaseID = 'Test_Basic_Scenarios'+"_"+$_.CommandName
							$NewCSV.TestStatus = $_.TestStatus
							$NewCSV.Message = [CommonHelper]::GetCustomMessageForTestCase($_)
							$NewCSV.AzSKModule = $_.AzSKModule
							$NewCSV.Description = $_.Description
							$CSVOutput += $NewCSV
				}
			}
		}

		if(($TestCaseResultContent | Measure-Object).Count -gt 0)
		{
			foreach ($Row in $TestCaseResultContent)
			{
				if($Row.TestCaseID -ne 'Test_Basic_Scenarios' -and $Row.TestStatus -ne 'Manual')
				{
					$NewCSV = "" | Select-Object TestCaseID, TestStatus, Message, AzSKModule, Description
			
					$NewCSV.TestCaseID = $Row.TestCaseID
					$NewCSV.TestStatus = $Row.TestStatus
					$NewCSV.Message = $Row.Message
					$NewCSV.AzSKModule = $Row.AzSKModule
					$NewCSV.Description = $Row.Description
			
					$CSVOutput += $NewCSV
				}
			}
		}
		$CSVOutput |Export-Csv ($Path + [Constants]::ConsolidatedResultFileName) -Append -NoTypeInformation
     }

	static [String] RunAzSKCommand([String] $Command, [string] $CommandName, [string] $Description, [string] $TestCaseID ,[PSObject] $testContext)
	{
		$OutputPath = ""
		$LogFilePath = ([CommonHelper]::GetOutputFolderPath()) + "\ParallelScan_$($CommandName).LOG"
		[CommonHelper]::Log([Constants]::SingleDashLine + "`r`nStart: [TestCaseID: $($TestCaseID)] [CommandName: $($CommandName)] [AzSKModule: $($testContext.HarnessSettings.AzSKModule)]`r`n"+[Constants]::SingleDashLine, [MessageType]::Information)

		if ([TestHelper]::DevTestMode -eq $True)
		{ 
			#DevTest mode, run cmd inline, cache result using commandName as 'key' (to sort of simulate Receive-Job type behavior)
			$retObj = New-Object PSObject -Property @{Error="";ReturnVal="";Output=""} 
			#TODO: Need to figure out how to capture screen output and cache that as well!
			$Err=""
			$Ret = ""

			Start-Transcript -Path $LogFilePath;
			$r = Invoke-Command -ScriptBlock {iex $Command} -ErrorVariable Err -OutVariable Ret
			Stop-Transcript
			
			$retObj.Error = $Err
			$retObj.ReturnVal = $Ret
			$OutputPath = $Ret #Used for validations further down.
			$retObj.Output = "TBD-TODO" 
			if ([TestHelper]::CachedAzSKCmdResults.Keys -contains $CommandName) 
			{
				Write-Warning "DevTestMode: Overwriting results from previous execution for [$CommandName]:[$Command]..."
			}
			[TestHelper]::CachedAzSKCmdResults[$CommandName] = $retObj
		}
		else
		{ 
			#Non DevTest mode. Run cmd as a job
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
			if($testContext.HarnessSettings.AzSKModule -eq "AzSKStaging" -and ![string]::IsNullOrEmpty($testContext.HarnessSettings.AzSKModulePath))
			{
				$AzSKModule = $testContext.HarnessSettings.AzSKModulePath
			}
			else
			{
				$AzSKModule = $testContext.HarnessSettings.AzSKModule
			}
			if(Get-Job -Name $CommandName)
			{
				$Job = Get-Job -Name $CommandName
			}
			else
			{
				[CommonHelper]::Log("`n`r[+] Starting Job. Please wait until [$($CommandName)] job completes.", [MessageType]::Information)
				$Job = Start-Job -Name $CommandName -ScriptBlock $ScriptBlock -ArgumentList $Command, $AzSKModule
			}
			Wait-Job -Id $Job.Id

			Start-Transcript -Path $LogFilePath;
			Receive-Job -Id $Job.id -Keep -OutVariable OutputPath -ErrorVariable ScanError | Out-Null
			Stop-Transcript
		}

		[CommonHelper]::Log([Constants]::SingleDashLine + "`r`nEnd: [TestCaseID: $($TestCaseID)] [CommandName: $($CommandName)]`r`n"+[Constants]::SingleDashLine, [MessageType]::Information)
		#TODO: Shouldn't ValidateAzSKCommandOutput leverage 'ScanError' as well?
		$CommandScanResult = [TestHelper]::ValidateAzSKCommandOutput($OutputPath, $CommandName, $Description, $TestCaseID, $testContext)

		return $CommandScanResult.TestStatus
	}

	#This function returns the output result and error variable from a command invocation.
	#In normal mode, it is just a wrapper around 'Receive-Job' using commandName as the job-id.
	#In dev-test mode, it uses a static hashtable to simulate 'Receive-Job'.
	static [PSCustomObject] GetAzSKCommandResults([string] $CommandName)
	{
		$retObj = $null
		if ([TestHelper]::DevTestMode -eq $true)
		{
			if ([TestHelper]::CachedAzSKCmdResults -ne $null)
			{
				if ([TestHelper]::CachedAzSKCmdResults.Keys -contains $CommandName)
				{
					$retObj = [TestHelper]::CachedAzSKCmdResults[$commandName]
				}
				else
                {
                    Write-Warning "Could not find cached results for [$commandName]"
                }
			}
		}
		else 
		{
			#This would typically be the 2nd Receive-Job as the RunAzSKCommand will already have done it once!
			$retVal = ""
			$errVal = ""
			$r = Receive-Job -Name $CommandName -Keep -OutVariable retVal -ErrorVariable errVal | Out-Null
			$retObj = [PSCustomObject] @{ReturnVal = $null; Error = $null; Output = $null}
			
			$retObj.ReturnVal = $retVal

			$retObj.Error = $errVal
			$retObj.Output = $r
		}
		return $retObj
	}
	# This function analyse AzSK command results (Multiple Jobs)
	static [PSObject] ValidateAzSKJobsResult([PSObject] $JobsId,[string] $AzSKModulePath, [string] $TestCaseID, [PSObject[]] $Jobs)
	{
		$CommandScanResults = @()
		if(($JobsId.Id | Measure-Object).Count -gt 0)
		{
			$JobsId | ForEach-Object {
				$LogFilePath = ([CommonHelper]::GetOutputFolderPath()) + "\ParallelScan_$($_.Name).LOG"
				$AzSKModule = ($_.Name).Split("_")[-1]
				[CommonHelper]::Log([Constants]::SingleDashLine + "`r`n Start: [CommandName: $($_.Name)] [AzSKModule: $($AzSKModule)]`r`n"+[Constants]::SingleDashLine, [MessageType]::Information)
				Start-Transcript -Path $LogFilePath;
				Receive-Job -Id $_.id -Keep -OutVariable OutputPath -ErrorVariable ScanError | Out-Null
				Stop-Transcript
			    $OutputPath = ([string] $OutputPath).trim();
				[CommonHelper]::Log([Constants]::SingleDashLine + "`r`n End: [CommandName: $($_.Name)]`r`n"+[Constants]::SingleDashLine, [MessageType]::Information)
				$CommandScanResult = "" | Select-Object TestCaseID,TestStatus,CommandName,Description,AzSKModule,OutputPath,FolderStructureDiff, PolicyError,ScanError,CSVError,LogError,LogWarning
				$CommandScanResult.TestCaseID = $TestCaseID
				$CommandScanResult.CommandName = $_.Name
				$CommandScanResult.Description = ($Jobs | Where { $CommandScanResult.CommandName  -eq "$($_.JobName)_$($_.AzSKModule)" }).Description | Select-Object -Unique
				if($OutputPath -eq 'None')
				{
					$CommandScanResult.AzSKModule = $AzSKModule
					$result = [CommonHelper]::RunMandateCheck_CommandsWithOutOutputFolder($_.Name, $LogFilePath)
					$CommandScanResult.OutputPath = 'This command does not generate output folder.'
					$CommandScanResult.ScanError = $result.ScanError
					$CommandScanResult.LogError = $result.LogError
					$CommandScanResult.LogWarning = $result.LogWarning
					$CommandScanResult.TestStatus = [TestHelper]::GetAzSKCommandStatus($CommandScanResult)
				}
				else
				{
					$result = [CommonHelper]::RunMandateCheck($AzSKModule,$AzSKModulePath,$OutputPath)
					$CommandScanResult.AzSKModule = $result.AzSKModule
					$CommandScanResult.OutputPath = $OutputPath -join "`n"
					#Powershell $error will be skipped temporarily, and logged in a separate file. To add store scan error in csv, use >>> ($ScanError | Where-Object { $_.CategoryInfo.Activity -ne 'Get-Member' } ) -join "`n"
					$CommandScanResult.ScanError = ''
					$CommandScanResult.PolicyError = $result.PolicyError -join "`n"
					$CommandScanResult.FolderStructureDiff = $result.FolderDiff
					$CommandScanResult.CSVError = $result.CSVError
					$CommandScanResult.LogError = $result.LogError
					$CommandScanResult.LogWarning = $result.LogWarning
					$CommandScanResult.TestStatus = [TestHelper]::GetAzSKCommandStatus($CommandScanResult)
				}
				$CommandScanResults += $CommandScanResult

				#Capturing powershell $error in a separate file
				$ArchivedErrorPath = ([CommonHelper]::GetOutputFolderPath()) + "\ArchivedErrorList.LOG"
				("`r`n Start: [CommandName: $($_.Name)] [AzSKModule: $($AzSKModule)]`r`n"+[Constants]::SingleDashLine) + ($ScanError) | Out-File $ArchivedErrorPath -Append
			}
		}
		[TestHelper]::ExportAzSKCommandResult($CommandScanResults)
		return $CommandScanResults
	}

	# This function analyse AzSK command results (Single Jobs)
	static [PSObject] ValidateAzSKCommandOutput([string] $OutputPath, [string] $CommandName, [string] $Description ,[string] $TestCaseID, [TestContext] $testContext)
	{
		$AzSKModule = $testContext.HarnessSettings.AzSKModule
		$AzSKModulePath = $testContext.HarnessSettings.AzSKModulePath
		$result = [CommonHelper]::RunMandateCheck($AzSKModule,$AzSKModulePath,$OutputPath)
		
		$CommandScanResult = "" | Select-Object TestCaseID,TestStatus,CommandName,Description,AzSKModule,OutputPath,FolderStructureDiff, PolicyError,ScanError,CSVError,LogError,LogWarning
		$CommandScanResult.TestCaseID = $TestCaseID
		$CommandScanResult.Description = $Description
		$CommandScanResult.CommandName = $CommandName
		$CommandScanResult.AzSKModule = [CommonHelper]::GetModuleVersionFromOutputFile($OutputPath)
		$CommandScanResult.OutputPath = $OutputPath
		$CommandScanResult.ScanError = ''
		$CommandScanResult.PolicyError = $result.PolicyError -join "`n"
		$CommandScanResult.FolderStructureDiff = $result.FolderDiff
		$CommandScanResult.CSVError = $result.CSVError
		$CommandScanResult.LogError = $result.LogError
		$CommandScanResult.LogWarning = $result.LogWarning
		$CommandScanResult.TestStatus = [TestHelper]::GetAzSKCommandStatus($CommandScanResult)
		
		[TestHelper]::ExportAzSKCommandResult($CommandScanResult)
		return $CommandScanResult
	}

	static [void] ExportAzSKCommandResult([PSObject] $CommandScanResults)
	{
		$CommandScanResults | Export-CSV $([CommonHelper]::GetOutputFolderPath()+[constants]::ParallelScanFileName) -Append -NoTypeInformation
	}

	static [TestStatus] GetAzSKCommandStatus([PSObject[]] $CommandScanResults)
	{	
		$Result = [TestStatus]::NotStarted
		if(($CommandScanResults | Measure-Object).Count -gt 0){
			$CommandScanResults | ForEach-Object {
				if([string]::IsNullOrEmpty($_.OutputPath) -or `
					![string]::IsNullOrEmpty($_.ScanError) -or `
					![string]::IsNullOrEmpty($_.CSVError) -or `
					![string]::IsNullOrEmpty($_.LogError) -or `
					![string]::IsNullOrEmpty($_.FolderStructureDiff))
				{
					$Result = [TestStatus]::Failed
					return $Result
				}
			} #$CommandScanResult.PolicyError.Split(";")[0].TrimStart("@{Status=") -eq "Passed"
		}
		else
		{
			$Result = [TestStatus]::Failed
			return $Result
		}
		
		if($Result -ne [TestStatus]::Failed)
		{
			$Result = [TestStatus]::Passed
		}
		return $Result
	}

	# returns test status for a test case.
	static [TestStatus] GetTestCaseStatus([TestStatus[]] $TestStatus)
	{
		if($TestStatus -contains [TestStatus]::Error -or $TestStatus -contains [TestStatus]::Failed)
		{
			return [TestStatus]::Failed
		}
		return [TestStatus]::Passed
	}

	static [ParamSet[]] GetParamSets(){
		$paramSets = @()
		try{
			[string] $path = [CommonHelper]::GetRootPath() +"\ParamSets.json"
			 $paramSets = Get-Content -Path $path | ConvertFrom-Json
		}
		catch{
			# Continue with default params when ParamSets.json file is not available
		}
		return $paramSets
		
	}

	static [TestSettings] PostCommandStartedAction([string] $SubscriptionId,[string] $AzSKModule, [string]$AzSKModulePath, [PSObject] $MandatoryTestSettings, [PSObject] $UserDefinedTestSettings, [string] $OrgPolicy)
	{	
		[CommonHelper]::new();
		Start-Transcript -Path $(([CommonHelper]::AzSKTestLogFolderPath) + "\AzSKTestLog.txt") -Append -Force;
		[CommonHelper]::Log("Initiating Test Harness", [MessageType]::Header)
		[CommonHelper]::SetAzureContext($SubscriptionId)
		[CommonHelper]::LoadAzSKModule($AzSKModule,$AzSKModulePath);
		#[ConfigurationHelper]::SetAzSKSettingsJsonParameter($AzSKModule, $MandatoryTestSettings, $OrgPolicy);
		<#

		if($null -ne $UserDefinedTestSettings){
			[TestSettings] $testsettings = [TestSettings]::new($SubscriptionId, $AzSKModule, $AzSKModulePath, $UserDefinedTestSettings)
		}
		else{
			[TestSettings] $testsettings = [TestSettings]::new($SubscriptionId, $AzSKModule, $AzSKModulePath)
			$testsettings.SetManadatoryTestSettings($MandatoryTestSettings)
		}
		
		#>
		# TODO: This is a temporary place holder
		$testsettings = [TestSettings]::new();
		return $testsettings;
	}

	static [TestSettings] ADOPostCommandStartedAction([string] $Org, [string] $AzSKModule, [string]$AzSKModulePath)
	{	
		[CommonHelper]::new();
		Start-Transcript -Path $(([CommonHelper]::AzSKTestLogFolderPath) + "\ADOTestLog.txt") -Append -Force;
		[CommonHelper]::Log("Initiating Test Harness", [MessageType]::Header)
		[CommonHelper]::LoadAzSKModule($AzSKModule,$AzSKModulePath);
		$testsettings = [TestSettings]::new($Org, $AzSKModule, $AzSKModulePath);
		return $testsettings;
	}

	static [string] PostCommandCompletedAction([TestCaseResult[]] $tcResults, [string] $AzSKModule)
	{
		[ConfigurationHelper]::ResetAzSKSettingsJsonParameter($AzSKModule);
		$OutputFolderPath = [CommonHelper]::AzSKTestLogFolderPath
		$CSVPath = $OutputFolderPath + [Constants]::AzSKTestCaseResultFileName
		[TestHelper]::ExportTestResultSummaryToCSV($tcResults, $CSVPath, $AzSKModule)
		[TestHelper]::ExportConsolidatedTestResultsToCSV()
		[CommonHelper]::Log("AzSK Test output and logs can be found at: " +$OutputFolderPath, [MessageType]::Completed)
		Stop-Transcript
		if(-not [string]::IsNullOrEmpty($OutputFolderPath))
		{
			try
			{
				Invoke-Item -Path $OutputFolderPath;
			}
			catch
			{
				#ignore if any exception occurs
			}
		}
		return $OutputFolderPath
	}
}