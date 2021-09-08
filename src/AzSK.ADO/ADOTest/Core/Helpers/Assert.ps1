Class Assert{

static [TestCaseResult] AreFilesEqual([String] $expectedFile, [String] $actualFile, [TestCase] $testCase){
		#Validate actual file status
		if(!(Test-path $actualFile))
		{
			return [TestCaseResult]::new($testCase,[TestStatus]::Failed,"Overall Security Status report not generated : [$actualFile]")
		}

		$isTestCasepPass = $True
		$actualFileJSONData = Import-Csv $actualFile
		if(($testCase.ControlResultSet | Measure-Object ).Count -gt 0)
			{
				$testCase.ControlResultSet| ForEach-Object {
					$currentControlId = $_.ControlID
    				$testExcutionStatus = ($actualFileJSONData | Where-Object {$_.ControlId -eq $currentControlId }).Status
					if($testExcutionStatus -ne $_.ControlStatus)
					{
						$isTestCasepPass = $False
					}
				}
				if($isTestCasepPass)
					{
						return [TestCaseResult]::new($testCase,[TestStatus]::Passed, "Test case passed")
					}
					else {
						return [TestCaseResult]::new($testCase,[TestStatus]::Failed,"Expected and actual results don't match!")
					}

            }
			else
			{
				        #Validate Expected Output file
						if(!(Test-path $expectedFile))
						{
						   return [TestCaseResult]::new($testCase,[TestStatus]::Failed,"Baseline Output file not present : [$expectedFile]")
						} 
 
						#Validate if result is expected result
						if([CommonHelper]::CompareCSV($expectedFile,$actualFile))
						{
						   return [TestCaseResult]::new($testCase,[TestStatus]::Passed, "Test case passed")
						}
						else {
							return [TestCaseResult]::new($testCase,[TestStatus]::Failed,"Expected and actual results don't match!")
						}
			}	
	}

}




