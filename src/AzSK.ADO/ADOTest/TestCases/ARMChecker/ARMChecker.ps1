Set-StrictMode -Version Latest 
class ARMChecker:AzSKTestBase
{
	[string] $AppResourceGroupName
	[PSObject[]] $ARMCheckerControls = @();  #ARM Checker controls only.

	ARMChecker([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext)
	{
		$this.LoadARMCheckerControls();
		$this.AppResourceGroupName = "AzSKTestRG" #This is the standard name used for testing resource in subscription.
	}
	[void] Execute()
	{
		switch ($this.testcase.TestMethod.Trim())
		{
			"ErrorOnFileSkip"
			{
				$this.ErrorOnFileSkip()
				break
			}
			"SkipControlsFromFile"
			{
				$this.SkipControlsFromFile()
				break
			}
			"ValidateCompliantTemplates"
			{
				$this.ValidateCompliantTemplates()
				break
			}
			"ScanMultiResourceTemplates"
			{
				$this.ScanMultiResourceTemplates()
				break
			}
			"ValidateRecurseSwitch"
			{
				$this.ValidateRecurseSwitch()
				break
			}
			"ValidateFalseRecurseSwitch"
			{
				$this.ValidateFalseRecurseSwitch()
				break
			}
			"ValidateExcludeFiles"
			{
				$this.ValidateExcludeFiles()
				break
			}
			"ValidateDefaultParameter"{
				$this.ValidateDefaultParameter()
				break
			}
			"ValidateExternalParameterFile"{
				$this.ValidateExternalParameterFile()
				break
			}

			"ValidateBaselineControls"{
				$this.ValidateBaselineControls()
				break
			}

			"ValidatePreviewBaselineControls"{
				$this.ValidatePreviewBaselineControls()
				break
			}

			"ValidateBothUBCandUPBCControls"{
				$this.ValidateBothUBCandUPBCControls()
				break
			}

			Default 
			{					
			}
		}
	}

	#Region Helper methods 

	[void] LoadARMCheckerControls(){
		$resourceControlSets = [AzSKControlInfo]::ARMCheckerControlInfo.resourceControlSets
		$resourceControlSets | ForEach-Object {
			$featureName = $_.featureName
				$_.controls | ForEach-Object {
					$controlObj  = "" | Select-Object "FeatureName", "ControlId", "Severity", "JsonPath","IsEnabled"
					$controlObj.FeatureName = $featureName
					$controlObj.ControlId = $_.controlId
					$controlObj.Severity = $_.Severity
					$controlObj.JsonPath = $_.JsonPath
					$controlObj.IsEnabled = $_.IsEnabled
					$this.ARMCheckerControls += $controlObj
				}
			}
	}

	[PSObject] GetUBCControls(){
		# Get All UBC SVT controls from Control Info class
		$ubcControls = [AzSKControlInfo]::AzSKControlInfoUBC
		# Select controls supported in ARM Checker
		$objects = @{
			ReferenceObject = $ubcControls
			DifferenceObject = $this.ARMCheckerControls
		}
		$ubcControlsInARMChecker = Compare-Object @objects -IncludeEqual -ExcludeDifferent -Property "ControlId" | ForEach-Object {"$($_.ControlID)"}
		$ubcControlsInARMChecker = $this.ARMCheckerControls | Where-Object { $ubcControlsInARMChecker -contains $_.ControlId }
		return $ubcControlsInARMChecker
	}

	[PSObject] GetUPBCControls(){
		# Get All UPBC SVT controls from Control Info class
		$upbcControls = [AzSKControlInfo]::AzSKControlInfoUPBC
		# Select controls supported in ARM Checker
		$objects = @{
			ReferenceObject = $upbcControls
			DifferenceObject = $this.ARMCheckerControls
		}
		$upbcControlsInARMChecker = Compare-Object @objects -IncludeEqual -ExcludeDifferent -Property "ControlId" | ForEach-Object {"$($_.ControlID)"}
		$upbcControlsInARMChecker = $this.ARMCheckerControls | Where-Object { $upbcControlsInARMChecker -contains $_.ControlId }
		return $upbcControlsInARMChecker
	}

    [PSObject] GetRandomControls($FetchControlsForSingleService, $ControlsCount){
		if($FetchControlsForSingleService -eq $true){
			$randomFeature = $this.ARMCheckerControls | Group-Object |  ForEach-Object {"$($_.FeatureName)"} | Get-Random -Count 1
			$applicableControls = $this.ARMCheckerControls | Where-Object { $_.FeatureName -eq $randomFeature} 
			if(($applicableControls | Measure-Object).Count -le $ControlsCount ){
				Write-Warning("Total control count in selected feature $($randomFeature) is less than total expected controls: $($ControlsCount)")
			}
			$randomControls = $applicableControls | Get-Random -Count $ControlsCount
		}else{
			$randomControls = $this.ARMCheckerControls | Get-Random -Count $ControlsCount
		}
		return $randomControls
	}

	[PSObject] GetRandomControlsBySeverity($FetchControlsForSingleService, $ControlsCount, $SeverityArray){
		
		# If required control count is 0 , set it to maximum controls count in ARM Checker 
		# This will return all control with matched severity 
		if($ControlsCount -eq 0){
			$ControlsCount = ($this.ARMCheckerControls | Measure-Object).Count
		}
		if($FetchControlsForSingleService -eq $true){
			$randomFeature = $this.ARMCheckerControls | Group-Object |  ForEach-Object {"$($_.FeatureName)"} | Get-Random -Count 1
			$applicableControls = $this.ARMCheckerControls | Where-Object { ($_.FeatureName -eq $randomFeature) -and ($SeverityArray -contains $_.Severity) } 
			# In case of single service just return all controls with matched severity
			$randomControls = $applicableControls
		}else{
			$applicableControls = $this.ARMCheckerControls | Where-Object {  $SeverityArray -contains $_.Severity } 
			$randomControls = $applicableControls | Get-Random -Count $ControlsCount
		}
		return $randomControls
	}

	[PSObject] GetFileNamesForRequiredControls($Controls){

	  # Here Assumption is that all ARM Template files in compliant folder must follow following pattern for file name
	  # FeatureName*.json
	  $ARMTemplateFilePath =  [CommonHelper]::GetRootPath() + "\TestCases\"+$this.testcase.Feature+"\"+"\TestData\CompliantTemplates"
	  $ARMTemplateFiles = Get-ChildItem -Path $ARMTemplateFilePath
	  $requiredFiles = @()
	  $applicableFeatures = $Controls | Group-Object | ForEach-Object {"$($_.FeatureName)"}  
	  $applicableFeatures | ForEach-Object {
		$featureName = $_
		$requiredFiles +=  $ARMTemplateFiles | Where-Object { $_.Name -like "$($featureName)*" }
	  }
	  # requiredFiles[*].FullName will give the complete path of the file
      return $requiredFiles
	}

	[PSObject] GetControlsForRequiredFilesOrFeatures($fileOrFeatureNames){
		# Here Assumption is that all ARM Template files in compliant folder must follow following pattern for file name
		# FeatureName*.json
		# This function can also support to get controls for required services as well
		$applicableControls  = @()
		$fileOrFeatureNames | ForEach-Object{
			$fileOrFeatureName = $_
			$applicableControls += $this.ARMCheckerControls | Where-Object { $fileOrFeatureName -like "$($_.FeatureName)*"}
		}
		return $applicableControls
	}

	[bool] CheckExpectedControlScanned($scannedControls, $expectedControls, $checkOnlyExpectedControlsScanned ){
		$status = $false
		if($checkOnlyExpectedControlsScanned -eq $true){
			$ubcControlsInARMChecker = Compare-Object $scannedControls $expectedControls -Property "ControlId,FeatureName" 
			if(($ubcControlsInARMChecker | Measure-Object).Count -eq 0){
				$status = $true
			}
		}else{
			throw "Not Implemented Exception"
		}
	
		return $status
	}

	[bool] CheckControlsExcludedFromScan($scannedControls, $excludedControls){
		$status = $false
		$actualExcludedControls = Compare-Object $scannedControls $excludedControls -Property "ControlId,FeatureName,JsonPath" 
		if(($actualExcludedControls | Measure-Object).Count -eq ($excludedControls | Measure-Object).Count){
			$status = $true
		}
		return $status
	}

	[PSObject] ReadSecurityReport($ouputFolderPath){
		$scannedControls  = @()
		$csvFileName=  Get-ChildItem -Path $ouputFolderPath -Include "ARMCheckerResults_*.csv" -Recurse
		if(![string]::IsNullOrEmpty($csvFileName))
		{
			$sourceFile = import-csv -Path $csvFileName
			if(($sourceFile|Measure-Object).Count -gt 0)
			{
		        # Get all scanned controls 
				$scannedControls = $sourceFile | Select-Object ControlId,FeatureName
			}
			else
			{
				$scannedControls = @()
				Write-Warning  "SecurityReport CSV file does not any control scan record."
			}

		}else{
			$scannedControls = @()
			Write-Warning "SecurityReport CSV file not found at expected path: $($ouputFolderPath)"
		}
		return $scannedControls
	}

	[string] CopyRequiredFilesToTempLocation($fileOrFeatureNames){
		# Here Assumption is that all ARM Template files in compliant folder must follow following pattern for file name
		# FeatureName*.json
	    # This fucntion will copy all reuired files to temporary folder and will return path of the folder
        throw "Not Implemented Exception"
		$outFilePath = ""
		return $outFilePath
	}

	[TestCaseResult] ValidateBaselineHelper($extendedCommand, $expectedBaselineControls, $msgUpdate)
	{
		# Start with failed status
		$testStatus = [TestStatus]::Failed
		$message = ""

        # This path must contain ARM Temaplates for services for which preview baseline controls are defined else test case will fail
		$ARMTemplateFilePath =  [CommonHelper]::GetRootPath() + "\TestCases\"+$this.testcase.Feature+"\"+"\TestData\CompliantTemplates" 
		$cmdStr = "Get-AzSKARMTemplateSecurityStatus -ARMTemplatePath $($ARMTemplateFilePath) " + $extendedCommand
		$description =  $this.testCase.Description
		$tcName =  $this.testCase.TestMethod

		[TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)
	    $retObj = [TestHelper]::GetAzSKCommandResults($tcName)
		
		$outPath = $retObj.ReturnVal
		$scanError = $retObj.Error
		# Get all scanned controls 
		$scannedControls = $this.ReadSecurityReport($outPath[0])
		# Check only UBC controls should be scanned and all expected UBC controls should be scanned
		$allExpectedControlsScanned = $this.CheckExpectedControlScanned($scannedControls, $expectedBaselineControls, $true)
		if($allExpectedControlsScanned -eq $true){
			$testStatus = [TestStatus]::Passed
			$message = "All expected $($msgUpdate) controls were scanned by the ARM Checker."
		}else{
			$testStatus = [TestStatus]::Failed
			$message = "All expected $($msgUpdate) controls were not scanned by the ARM Checker."
		}
		$this.testcaseResult =[TestCaseResult]::new($this.testCase,$testStatus,$message)
        return $this.testcaseResult
	}

    #End Region Helper methods

	[TestCaseResult] ErrorOnFileSkip()
	{
		# Start with failed status
		$testStatus = [TestStatus]::Failed

		#Assuming path in DSC
        $ARMTemplateFilePath = [CommonHelper]::GetRootPath() + "\TestCases\"+$this.testcase.Feature+"\"+"\TestData"
		

		$cmdStr = "Get-AzSKARMTemplateSecurityStatus -ARMTemplatePath $($ARMTemplateFilePath)"
		$description =  $this.testCase.Description
		$tcName =  $this.testCase.TestMethod

		[TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)
	    $retObj = [TestHelper]::GetAzSKCommandResults($tcName)
		
		$outPath = $retObj.ReturnVal
		$scanError = $retObj.Error
		# Commenting this method as it is checking for hard coded 'SecurityReport*'
		# constrcutor call is just updating, csv file path that can be handled in individual scenario
		#$results = [AzSKScanResults]::new($outPath, $this.testContext.TestResources.ResourceInfo)

		$PSContent = Get-Content -Path ($outPath[0]+ "/" + "PowerShellOutput.LOG")
        $skippedFileContent = ($PSContent | Where { $_ -match "One or more files were skipped during the scan." })
        
        if($skippedFileContent -ne $null -and (Test-Path $($outPath[0] + "/" + "SkippedFiles.LOG") -Type Leaf))
        {
            $testStatus = [TestStatus]::Passed
            $message = "One or more files were skipped during the scan."
		}else{
			# Initial status is already 'Failed'
            $message = "No file(s) were skipped during scan."
		}
		$this.testcaseResult =[TestCaseResult]::new($this.testCase,$testStatus,$message)
        return $this.testcaseResult
	}

	[TestCaseResult] SkipControlsFromFile()
	{
		# Start with failed status
		$testStatus = [TestStatus]::Failed
        $ARMTemplateFilePath = [CommonHelper]::GetRootPath() + "\TestCases\"+$this.testcase.Feature+"\"+"\TestData"
		$cmdStr = "Get-AzSKARMTemplateSecurityStatus -ARMTemplatePath $($ARMTemplateFilePath)"
		$description =  $this.testCase.Description
		$tcName =  $this.testCase.TestMethod

		[TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)
	    $retObj = [TestHelper]::GetAzSKCommandResults($tcName)
		$outPath = $retObj.ReturnVal
		$scanError = $retObj.Error

		$failedControlCount = 0
		$sourceFileName=  Get-ChildItem -Path $outPath[0] -Include "ARMCheckerResults_*.csv" -Recurse	
		if(![string]::IsNullOrEmpty($sourceFileName))
		{
			$sourceFile = import-csv -Path $sourceFileName
			if(($sourceFile|Measure-Object).Count -gt 0)
			{
				$failedControls = $sourceFile | Where-Object {$_.status -eq "Failed" -or $_.status -eq "Verify"}
				if($null -ne $failedControls){
					$failedControlCount = ($failedControls | Measure-Object).Count
				}
			}
			else
			{
				$testStatus = [TestStatus]::Failed
				$message = "SecurityReport CSV file not found. ($_)"
			}
		}else{
			$testStatus = [TestStatus]::Failed
			$message = "SecurityReport CSV file not found. ($_)"
		}
	   
		if($failedControlCount -gt 0){
			$SkipControlFromFile = $sourceFileName
			$cmdStr = "Get-AzSKARMTemplateSecurityStatus -ARMTemplatePath $($ARMTemplateFilePath) -SkipControlsFromFile $($SkipControlFromFile)"
			[TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)
			$retObj = [TestHelper]::GetAzSKCommandResults($tcName)
			$outPath = $retObj.ReturnVal
			$scanError = $retObj.Error
	
			$skippedControlCount = 0
			$sourceFileName=  Get-ChildItem -Path $outPath[0] -Include "ARMCheckerResults_*.csv" -Recurse	
			if(![string]::IsNullOrEmpty($sourceFileName))
			{
				$sourceFile = import-csv -Path $sourceFileName
				if(($sourceFile|Measure-Object).Count -gt 0)
				{
					$skippedControls = $sourceFile | Where-Object {$_.status -eq "Skipped" }
					if($null -ne $skippedControls){
						$skippedControlCount = ($skippedControls | Measure-Object).Count
					}
				}
				else
				{
					$testStatus = [TestStatus]::Failed
					$message = "SecurityReport CSV file not found. ($_)"
				}
			}
			else{
				$testStatus = [TestStatus]::Failed
				$message = "SecurityReport CSV file not found. ($_)"
			}

			if($skippedControlCount -eq $failedControlCount)
			{
				$testStatus = [TestStatus]::Passed
				$message = "All expected falied controls were skipped."
			}else{
				$testStatus = [TestStatus]::Failed
				$message = "Skipped controls count in second run doesn't match with failed controls count in first run."
			}
		}else{
			$testStatus = [TestStatus]::Failed
			$message = "CSV file does not contains any failing control."
		}
		
		$this.testcaseResult =[TestCaseResult]::new($this.testCase,$testStatus,$message)
        return $this.testcaseResult
	}

	[TestCaseResult] ValidateCompliantTemplates()
	{
		# Start with failed status
		$testStatus = [TestStatus]::Failed
		$message = ""

		# Scanning folder which has all compliant templates
        $ARMTemplateFilePath = [CommonHelper]::GetRootPath() + "\TestCases\"+$this.testcase.Feature+"\"+"\TestData\CompliantTemplates"
		$cmdStr = "Get-AzSKARMTemplateSecurityStatus -ARMTemplatePath $($ARMTemplateFilePath)"
		$description =  $this.testCase.Description
		$tcName =  $this.testCase.TestMethod

		[TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)
	    $retObj = [TestHelper]::GetAzSKCommandResults($tcName)
		
		$outPath = $retObj.ReturnVal
		$scanError = $retObj.Error

		$csvFileName=  Get-ChildItem -Path $outPath[0] -Include "ARMCheckerResults_*.csv" -Recurse	
		$failedControlCount = -1
		if(![string]::IsNullOrEmpty($csvFileName))
		{
			$sourceFile = import-csv -Path $csvFileName
			if(($sourceFile|Measure-Object).Count -gt 0)
			{
				$failedControls = $sourceFile | Where-Object {$_.status -eq "Failed"}
				if($null -ne $failedControls -and ($failedControls | Measure-Object).Count -gt 0){
					$testStatus = [TestStatus]::Failed
					$message = "There are one or more failing controls in CSV file."
				}else{
					$failedControlCount = 0
				}
			}
			else
			{
				$testStatus = [TestStatus]::Failed
				$message = "SecurityReport CSV file does not any control scan record."
			}
		}else{
			$testStatus = [TestStatus]::Failed
			$message = "SecurityReport CSV file not found. ($_)"
		}
        if($failedControlCount -eq 0){
			$testStatus = [TestStatus]::Passed
			$message = "All controls are in 'Passed/Verify' state."
		}
		$this.testcaseResult =[TestCaseResult]::new($this.testCase,$testStatus,$message)
        return $this.testcaseResult
	}

	[TestCaseResult] ScanMultiResourceTemplates()
	{
		# Start with failed status
		$testStatus = [TestStatus]::Failed
		$message = ""

		# Scanning template(s) which has multiple AzSK supported template(s)
		# Todo: Try using a template with too many resources
        $ARMTemplateFilePath = [CommonHelper]::GetRootPath() + "\TestCases\"+$this.testcase.Feature+"\"+"\TestData\MultiResourceTemplates"
		$cmdStr = "Get-AzSKARMTemplateSecurityStatus -ARMTemplatePath $($ARMTemplateFilePath)"
		$description =  $this.testCase.Description
		$tcName =  $this.testCase.TestMethod

		[TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)
	    $retObj = [TestHelper]::GetAzSKCommandResults($tcName)
		
		$outPath = $retObj.ReturnVal
		$scanError = $retObj.Error

		$csvFileName=  Get-ChildItem -Path $outPath[0] -Include "ARMCheckerResults_*.csv" -Recurse	
		$failedControlCount = -1
		if(![string]::IsNullOrEmpty($csvFileName))
		{
			$sourceFile = import-csv -Path $csvFileName
			if(($sourceFile|Measure-Object).Count -gt 0)
			{
				$scannedUniqueResourceTypes = $sourceFile | Select-Object "FeatureName" -Unique
				if($null -ne $scannedUniqueResourceTypes -and ($scannedUniqueResourceTypes | Measure-Object).Count -gt 1){
					$testStatus = [TestStatus]::Passed
					$message = "Following different resource type were present in scanned ARM Templates:." + [system.String]::Join(" , ",$scannedUniqueResourceTypes)
				}else{
					$testStatus = [TestStatus]::Failed
					$message = "ARM Template does not contains multiple ARM Checker supported resources."
				}
			}
			else
			{
				$testStatus = [TestStatus]::Failed
				$message = "SecurityReport CSV file does not any control scan record."
			}
		}else{
			$testStatus = [TestStatus]::Failed
			$message = "SecurityReport CSV file not found. ($_)"
		}
		$this.testcaseResult =[TestCaseResult]::new($this.testCase,$testStatus,$message)
        return $this.testcaseResult
	}

	[TestCaseResult] ValidateRecurseSwitch()
	{
		# Start with failed status
		$testStatus = [TestStatus]::Failed
		$message = ""
        # Scanning all ARM Templates 
        $ARMTemplateFilePath = [CommonHelper]::GetRootPath() + "\TestCases\"+$this.testcase.Feature+"\"+"\TestData"
		$cmdStr = "Get-AzSKARMTemplateSecurityStatus -ARMTemplatePath $($ARMTemplateFilePath) -Recurse"
		$description =  $this.testCase.Description
		$tcName =  $this.testCase.TestMethod

		[TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)
	    $retObj = [TestHelper]::GetAzSKCommandResults($tcName)
		
		$outPath = $retObj.ReturnVal
		$scanError = $retObj.Error
        
		$csvFileName=  Get-ChildItem -Path $outPath[0] -Include "ARMCheckerResults_*.csv" -Recurse	
		$skippedARMTemplatePaths = @()
		# Get Expected ARM Templates for given path with recurse switch
		$baseDirectory = [System.IO.Path]::GetDirectoryName($ARMTemplateFilePath);
		$expectedARMTemplatePaths = Get-ChildItem -Path $ARMTemplateFilePath -Recurse -Filter '*.json' | ForEach-Object { $_.FullName.Replace($baseDirectory, ".") }
	
		if(![string]::IsNullOrEmpty($csvFileName))
		{
			$sourceFile = import-csv -Path $csvFileName
			if(($sourceFile|Measure-Object).Count -gt 0)
			{
				$scannedARMTemplatePaths = $sourceFile | ForEach-Object{  $_.FilePath } | Select -Unique
				if( Test-Path $($outPath[0] + "/" + "SkippedFiles.LOG") -Type Leaf )
				{
					$skippedARMTemplatePaths += Get-Content -Path ($outPath[0]+ "/" + "SkippedFiles.LOG")
				}
				if($null -ne $scannedARMTemplatePaths -and ($scannedARMTemplatePaths | Measure-Object).Count -gt 0){
					$scannedARMTemplatePaths += $skippedARMTemplatePaths
					$difference = Compare-Object $expectedARMTemplatePaths $scannedARMTemplatePaths
					# Pass control, If there no difference b/w expected ARM Templates and scanned ARM Temaplates path 
					if($null -eq $difference){
                        $testStatus = [TestStatus]::Passed
				        $message = "All expected Templates were scanned by ARM Checker."
                    }else{
						$testStatus = [TestStatus]::Failed
						$message = "All expected Templates were not scanned by ARM Checker."
					}
					
				}else{
					$testStatus = [TestStatus]::Failed
					$message = "No ARM Template(s) Scanned."
				}
			}
			else
			{
				$testStatus = [TestStatus]::Failed
				$message = "SecurityReport CSV file does not any control scan record."
			}
		}else{
			$testStatus = [TestStatus]::Failed
			$message = "SecurityReport CSV file not found. ($_)"
		}
		$this.testcaseResult =[TestCaseResult]::new($this.testCase,$testStatus,$message)
        return $this.testcaseResult
	}

    [TestCaseResult] ValidateFalseRecurseSwitch()
	{
		# Start with failed status
		$testStatus = [TestStatus]::Failed
		$message = ""
        # Scanning all ARM Templates 
        $ARMTemplateFilePath = [CommonHelper]::GetRootPath() + "\TestCases\"+$this.testcase.Feature+"\"+"\TestData"
		$cmdStr = "Get-AzSKARMTemplateSecurityStatus -ARMTemplatePath $($ARMTemplateFilePath) "
		$description =  $this.testCase.Description
		$tcName =  $this.testCase.TestMethod

		[TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)
	    $retObj = [TestHelper]::GetAzSKCommandResults($tcName)
		
		$outPath = $retObj.ReturnVal
		$scanError = $retObj.Error
        
		$csvFileName=  Get-ChildItem -Path $outPath[0] -Include "ARMCheckerResults_*.csv" -Recurse	
		$skippedARMTemplatePaths = @()
		# Get Expected ARM Templates for given path with recurse switch
		$baseDirectory = [System.IO.Path]::GetDirectoryName($ARMTemplateFilePath);
		$expectedARMTemplatePaths = Get-ChildItem -Path $ARMTemplateFilePath -Filter '*.json' | ForEach-Object { $_.FullName.Replace($baseDirectory, ".") }
	
		if(![string]::IsNullOrEmpty($csvFileName))
		{
			$sourceFile = import-csv -Path $csvFileName
			if(($sourceFile|Measure-Object).Count -gt 0)
			{
				$scannedARMTemplatePaths = $sourceFile | ForEach-Object{  $_.FilePath } | Select -Unique
				if( Test-Path $($outPath[0] + "/" + "SkippedFiles.LOG") -Type Leaf )
				{
					$skippedARMTemplatePaths += Get-Content -Path ($outPath[0]+ "/" + "SkippedFiles.LOG")
				}
				if($null -ne $scannedARMTemplatePaths -and ($scannedARMTemplatePaths | Measure-Object).Count -gt 0){
					$scannedARMTemplatePaths += $skippedARMTemplatePaths
					$difference = Compare-Object $expectedARMTemplatePaths $scannedARMTemplatePaths
					# Pass control, If there no difference b/w expected ARM Templates and scanned ARM Temaplates path 
					if($null -eq $difference){
                        $testStatus = [TestStatus]::Passed
				        $message = "All expected Templates were scanned by ARM Checker."
                    }else{
						$testStatus = [TestStatus]::Failed
						$message = "All expected Templates were not scanned by ARM Checker."
					}
					
				}else{
					$testStatus = [TestStatus]::Failed
					$message = "No ARM Template(s) Scanned."
				}
			}
			else
			{
				$testStatus = [TestStatus]::Failed
				$message = "SecurityReport CSV file does not any control scan record."
			}
		}else{
			$testStatus = [TestStatus]::Failed
			$message = "SecurityReport CSV file not found. ($_)"
		}
		$this.testcaseResult =[TestCaseResult]::new($this.testCase,$testStatus,$message)
        return $this.testcaseResult
	}

	[TestCaseResult] ValidateExcludeFiles()
	{
		# Start with failed status
		$testStatus = [TestStatus]::Failed
		$message = ""
        # Scanning all ARM Templates 
        $ARMTemplateFilePath = [CommonHelper]::GetRootPath() + "\TestCases\"+$this.testcase.Feature+"\"+"\TestData"
		# Get Expected ARM Templates for given path with recurse switch
		$baseDirectory = [System.IO.Path]::GetDirectoryName($ARMTemplateFilePath);
		# Get all ARM Templates and exclude some files randomly
		$shuffledARMTemplateFileNames = Get-ChildItem -Path $ARMTemplateFilePath -Recurse -Filter '*.json' | ForEach-Object { $_.Name } | Select -Unique | Sort-Object {Get-Random}
		$filesToExclude =  $shuffledARMTemplateFileNames | Select -First 3
		$ExcludeFiles = [system.String]::Join(",",$filesToExclude)

		$cmdStr = "Get-AzSKARMTemplateSecurityStatus -ARMTemplatePath $($ARMTemplateFilePath) -Recurse -ExcludeFiles '$($ExcludeFiles)'"
		$description =  $this.testCase.Description
		$tcName =  $this.testCase.TestMethod

		[TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)
	    $retObj = [TestHelper]::GetAzSKCommandResults($tcName)
		
		$outPath = $retObj.ReturnVal
		$scanError = $retObj.Error
        
		$csvFileName=  Get-ChildItem -Path $outPath[0] -Include "ARMCheckerResults_*.csv" -Recurse	
		$skippedARMTemplatePaths = @()
        $expectedARMTemplatePaths = Get-ChildItem -Path $ARMTemplateFilePath -Recurse -Filter '*.json' | Where-Object {$_.Name -notin $filesToExclude}| ForEach-Object { $_.FullName.Replace($baseDirectory, ".") }
	
		if(![string]::IsNullOrEmpty($csvFileName))
		{
			$sourceFile = import-csv -Path $csvFileName
			if(($sourceFile|Measure-Object).Count -gt 0)
			{
				$scannedARMTemplateFileNames = $sourceFile | ForEach-Object{  $_.FilePath } | Select -Unique
				if( Test-Path $($outPath[0] + "/" + "SkippedFiles.LOG") -Type Leaf )
				{
					$skippedARMTemplatePaths += Get-Content -Path ($outPath[0]+ "/" + "SkippedFiles.LOG")
				}
				if($null -ne $scannedARMTemplateFileNames -and ($scannedARMTemplateFileNames | Measure-Object).Count -gt 0){
					$scannedARMTemplateFileNames += $skippedARMTemplatePaths
					$difference = Compare-Object $expectedARMTemplatePaths $scannedARMTemplateFileNames
					# Pass control, If there no difference b/w expected ARM Templates and scanned ARM Temaplates path 
					if($null -eq $difference){
                        $testStatus = [TestStatus]::Passed
				        $message = "All required Templates were excluded by ARM Checker."
                    }else{
						$testStatus = [TestStatus]::Failed
						$message = "One or more required Template(s) was not excluded by ARM Checker."
					}
					
				}else{
					$testStatus = [TestStatus]::Failed
					$message = "No ARM Template(s) Scanned."
				}
			}
			else
			{
				$testStatus = [TestStatus]::Failed
				$message = "SecurityReport CSV file does not any control scan record."
			}
		}else{
			$testStatus = [TestStatus]::Failed
			$message = "SecurityReport CSV file not found. ($_)"
		}
		$this.testcaseResult =[TestCaseResult]::new($this.testCase,$testStatus,$message)
        return $this.testcaseResult
	}

	[TestCaseResult] ValidateDefaultParameter()
	{
		# Start with failed status
		$testStatus = [TestStatus]::Failed
		$message = ""

		# Scanning folder which has all templates for which required properties are defined by parameter
		# and parameter value is defined in default parameter list within ARM template
        $ARMTemplateFilePath = [CommonHelper]::GetRootPath() + "\TestCases\"+$this.testcase.Feature+"\"+"\TestData\DefaultParamTemplates"
		$cmdStr = "Get-AzSKARMTemplateSecurityStatus -ARMTemplatePath $($ARMTemplateFilePath)"
		$description =  $this.testCase.Description
		$tcName =  $this.testCase.TestMethod

		[TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)
	    $retObj = [TestHelper]::GetAzSKCommandResults($tcName)
		
		$outPath = $retObj.ReturnVal
		$scanError = $retObj.Error

		$csvFileName=  Get-ChildItem -Path $outPath[0] -Include "ARMCheckerResults_*.csv" -Recurse	
		if(![string]::IsNullOrEmpty($csvFileName))
		{
			$sourceFile = import-csv -Path $csvFileName
			if(($sourceFile|Measure-Object).Count -gt 0)
			{
		        # Get all control for which expected property is defined as 'Parameterized value'
				$parameterizedControls = $sourceFile | Where-Object {$_.CurrentValue -like "*parameters*" }
				# Get all control for which expected property is defined as 'Parameterized value' and status is failed
				$failedControls = $parameterizedControls | Where-Object { $_.status -eq "Failed" }
				# If no paramterized control found, fail test case 
				if($null -eq $parameterizedControls -or ($parameterizedControls | Measure-Object).Count -eq 0){
					$testStatus = [TestStatus]::Failed
					$message = "No control found in scan logs for which expected property is defined as 'parameterized value'."
				}
				elseif($null -ne $failedControls -and ($failedControls | Measure-Object).Count -gt 0){
					$testStatus = [TestStatus]::Failed
					$message = "There are one or more failing controls in CSV file which means default parameter value is not respected."
				}else{
					$testStatus = [TestStatus]::Passed
					$message = "All controls are in 'Passed/Verify' state which means default parameter value is respected by ARM Checker."
				}
			}
			else
			{
				$testStatus = [TestStatus]::Failed
				$message = "SecurityReport CSV file does not any control scan record."
			}
		}else{
			$testStatus = [TestStatus]::Failed
			$message = "SecurityReport CSV file not found. ($_)"
		}
		$this.testcaseResult =[TestCaseResult]::new($this.testCase,$testStatus,$message)
        return $this.testcaseResult
	}

	[TestCaseResult] ValidateExternalParameterFile()
	{
		# Start with failed status
		$testStatus = [TestStatus]::Failed
		$message = ""

        #TODO: get random arm template file and paramter file instead of hard coding
		$ARMTemplateFilePath = [CommonHelper]::GetRootPath() + "\TestCases\"+$this.testcase.Feature+"\"+"\TestData\ExternalParameterFile\AppService.json" 
		$ParameterFilePath = [CommonHelper]::GetRootPath() + "\TestCases\"+$this.testcase.Feature+"\"+"\TestData\ExternalParameterFile\parameters.AppService.json" 
		$cmdStr = "Get-AzSKARMTemplateSecurityStatus -ARMTemplatePath $($ARMTemplateFilePath) -ParameterFilePath $($ParameterFilePath)"
		$description =  $this.testCase.Description
		$tcName =  $this.testCase.TestMethod

		[TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)
	    $retObj = [TestHelper]::GetAzSKCommandResults($tcName)
		
		$outPath = $retObj.ReturnVal
		$scanError = $retObj.Error

		$csvFileName=  Get-ChildItem -Path $outPath[0] -Include "ARMCheckerResults_*.csv" -Recurse	
		if(![string]::IsNullOrEmpty($csvFileName))
		{
			$sourceFile = import-csv -Path $csvFileName
			if(($sourceFile|Measure-Object).Count -gt 0)
			{
		        # Get all control for which expected property is defined as 'Parameterized value'
				$parameterizedControls = $sourceFile | Where-Object {$_.CurrentValue -like "*parameters*" }
				# Get all control for which expected property is defined as 'Parameterized value' and status is failed
				$failedControls = $parameterizedControls | Where-Object { $_.status -eq "Failed" }
				# If no paramterized control found, fail test case 
				if($null -eq $parameterizedControls -or ($parameterizedControls | Measure-Object).Count -eq 0){
					$testStatus = [TestStatus]::Failed
					$message = "No control found in scan logs for which expected property is defined as 'parameterized value'."
				}
				elseif($null -ne $failedControls -and ($failedControls | Measure-Object).Count -gt 0){
					$testStatus = [TestStatus]::Failed
					$message = "There are one or more failing controls in CSV file which means parameter value from external parameter file is not respected."
				}else{
					$testStatus = [TestStatus]::Passed
					$message = "All controls are in 'Passed/Verify' state which means parameter value from external file is respected by ARM Checker."
				}
			}
			else
			{
				$testStatus = [TestStatus]::Failed
				$message = "SecurityReport CSV file does not any control scan record."
			}
		}else{
			$testStatus = [TestStatus]::Failed
			$message = "SecurityReport CSV file not found. ($_)"
		}
		$this.testcaseResult =[TestCaseResult]::new($this.testCase,$testStatus,$message)
        return $this.testcaseResult
	}
 
	[TestCaseResult] ValidateBaselineControls()
	{
		# Extended command
		$extendedCommand = "-UBC"
		# Upadte message
		$msgUpdate = "Baseline Controls"
		# Get all expected UBC controls 	
        $expectedUBCControls = $this.GetUBCControls()
	    # Call common baseline helper method and return 
        return $this.ValidateBaselineHelper($extendedCommand, $expectedUBCControls,$msgUpdate)
	}

	[TestCaseResult] ValidatePreviewBaselineControls()
	{
			# Extended command
			$extendedCommand = "-UPBC"
			# Upadte message
			$msgUpdate = "Preview Baseline Controls"
			# Get all expected UBC controls 	
			$expectedUPBCControls = $this.GetUPBCControls()
			# Call common baseline helper method and return 
			return $this.ValidateBaselineHelper($extendedCommand, $expectedUPBCControls,$msgUpdate)
	}

	[TestCaseResult] ValidateBothUBCandUPBCControls()
	{
		# Extended command
		$extendedCommand = "-UBC -UPBC"
		# Upadte message
		$msgUpdate = "Preview Baseline and Baseline Controls"
		# Get all expected UBC controls 	
		$expectedAllBaselineControls = $this.GetUPBCControls() +  $this.GetUBCControls()
		# Call common baseline helper method and return 
		return $this.ValidateBaselineHelper($extendedCommand, $expectedAllBaselineControls, $msgUpdate)
	}

	[void] Cleanup()
	{
		#TODO: Clean up all files in temp location if any
	}


}