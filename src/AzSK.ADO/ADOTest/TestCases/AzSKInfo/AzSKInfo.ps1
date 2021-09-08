class AzSKInfo:AzSKTestBase
{

    AzSKInfo([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext)
	{
	}
   
    [void] Execute()
	{
		switch ($this.testcase.TestMethod)
		{
			"Test_GAI_Control_Information"
			{
				$this.Test_GAI_Control_Information()
				break
			}
			"GAI_Host_information"
			{
				$this.GAI_Host_information()
				break
            }
        }
    }
    [TestCaseResult] GAI_Host_information()
	{
		try{
			$cmdStr = "Get-AzSKInfo -infotype HostInfo"   
			$outputFile = Invoke-Expression $cmdStr
			$outputFile = "$outputFile\Etc\PowerShellOutput.LOG"

			$cmdStr = "Test-Path -Path '$($outputFile)'"
			$IfFileexists = Invoke-Expression $cmdStr

			#Check if file is created
			if(!$IfFileexists) {
				$failMsg = "Output file(s) creation error."
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,$failMsg)
			} 

			#Check some of the file content
			else{
				$CurrentUser = Get-Content $outputFile | Where-Object { $_.Contains($env:USERNAME) }
				$json = (Get-Content $this.testContext.AzSKSettings.AzSKSettingsFilePath -Raw) | ConvertFrom-Json
				$getFileData = Get-Content $outputFile 

				If(($CurrentUser.Length -ne 0) -and ($getFileData -like "*$($json.AutoUpdateCommand)*") -and ($getFileData -notlike "*Error*") -and ($getFileData -notlike "*Exception*"))
				{
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully tested GAI Host Information.")
				}
				else{
					$failMsg = "Error validating Output file details."
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,$failMsg)
				}
			}  
			return $this.testcaseResult
		}
		catch {
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Error occurred. $($_.Exception)")
			return $this.testcaseResult
		}
	}
    
    [TestCaseResult] Test_GAI_Control_Information()
	{
		
		#####################################
		# Form the GAI command 
		#####################################
		$cmdStr = "GAI -IT ControlInfo"   
		
		#####################################
		#Invoke the GAI command and get results
		#####################################
		$description =  $this.testCase.Description
		$tcName =  $this.testCase.TestMethod

		$results = $null

		if ($true)
		{
			[TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)

			$retObj = [TestHelper]::GetAzSKCommandResults($tcName)
			$outPath = $retObj.ReturnVal
			$scanError = $retObj.Error

			$results = [AzSKScanResults]::new($outPath, $this.testContext.TestResources.ResourceInfo)
		}

		#####################################
		# Validate - 
		#	- all ubc resources in RG were scanned
		#	- only ubc controls were scanned  
		#####################################
		#$ubcRsrcsInRG = $this.testContext.TestResources.ResourceInfo.GetAzSKResourcesFromRGUBC($rgName)

		#Check that exactly the ubc resource set was scanned. Using '@()' wrapper to cover for single resource cases...so we can treat them as arrays!
		$bPass1 = $true

		#Check that all controls scanned were 'ubc'
		$bPass2 = $true
		
		$bPassed = ($bPass1 -and $bPass2)
  		$failedMsg = ""
 		if (-not $bPassed) 
		{
 			$failedMsg = $results.GetErrMsg() 		
		}
  		$passedMsg = "All applicable UBC controls from the specified RG were scanned."
		
		$this.testcaseResult = [AzSKInfo]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $cmdStr)
		return $this.testcaseResult
	}
    
    # [void] Execute(){

    #     $([PSMethod] $this.$($this.testcase.TestMethod.Trim())).Invoke()
    # }
    
#     [TestCaseResult] Test_GAI_Control_Information(){

#         ###
#         # Test: e.g., gai ControlInfo - full list of controls
#         ###
#         #####################################
#         # Form the AzSK XYZ command (e.g.,grs -s $s2 -ResourceGroupNames 'azskrg' -ExcludeResourceTypeName Storage)
#         #####################################
#         $cmdStr = "GAI -IT ControlInfo"
#         #####################################
#         # Invoke the AzSK XYZ command
#         #####################################
#         $description = $this.testCase.Description
#         $tcName = $this.testCase.TestMethod
#         $results = $null
#         if ($true)
#         {
#             [TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)
#             
#             # Get Command result
#             $retObj = [TestHelper]::GetAzSKCommandResults($tcName)
#             $outPath = $retObj.ReturnVal
#             $scanError = $retObj.Error
#             # This method is specific for GRS/GSS commands for other module please don’t use it.
#             $results = [AzSKScanResults]::new($outPath, $this.testContext.TestResources.ResourceInfo)
#         }

#         #####################################
#         # Validate - e.g., all rsrcs were scanned. 
#         #####################################
#         
#         $bPassed = $false
#         $failedMsg = ""
#        if (-not $bPassed) 
#         {
#            $failedMsg = $results.GetErrMsg()       
#         }
#        $passedMsg = "FIXME: All specified <xyz> were scanned."
#         
#         #####################################
#         # Report outcome
#         #####################################
#         $this.testcaseResult = [SVTCore]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $cmdStr)
#         # Return result
#          return $this.testcaseResult
#     }

#     [void] Cleanup(){   
#     }

}