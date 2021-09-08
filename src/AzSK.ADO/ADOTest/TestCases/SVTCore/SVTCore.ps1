Set-StrictMode -Version Latest 
class SVTCore:AzSKTestBase
{	

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

	SVTCore([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext)
	{
	}

	[void] Execute()
	{
		switch ($this.testcase.TestMethod)
		{
			"Test_GRS_Tgt_RsrcNames_for_Sub"
			{
				$this.Test_GRS_Tgt_RsrcNames_for_Sub()
				break
			}
			"Test_GRS_Exc_RsrcTypeName_for_RGs"
			{
				$this.Test_GRS_Exc_RsrcTypeName_for_RGs()
				break
			}
			"Test_GRS_Swt_Ubc_Single_RG"
			{
				$this.Test_GRS_Swt_Ubc_Single_RG()
				break
			}

			"Test_Tag_FilterTags_for_Sub"
			{
				$this.Test_Tag_FilterTags_for_Sub()
				break
			}
			"Test_GRS_Tag_ExcludeTags_for_Sub"
			{
				$this.Test_GRS_Tag_ExcludeTags_for_Sub()
				break
			}
			"Test_GRS_Tgt_ControlIds_for_Sub"
			{
				$this.Test_GRS_Tgt_ControlIds_for_Sub()
				break
			}
			
			"Test_GRS_Tgt_ControlIds_Single_Rsrc"
			{
				$this.Test_GRS_Tgt_ControlIds_Single_Rsrc()
				break
			}
			"Test_GRS_Tgt_RsrcType_for_Sub"
			{
				$this.Test_GRS_Tgt_RsrcType_for_Sub()
				break
			}
			"Test_GRS_Tgt_RsrcType_for_RGs"
			{
				$this.Test_GRS_Tgt_RsrcType_for_RGs()
				break
			}
			
			"Test_GRS_Exc_RGs_for_Sub"
			{
				$this.Test_GRS_Exc_RGs_for_Sub()
				break
			}
			"Test_GRS_Tgt_RGs_for_Sub"
			{
				$this.Test_GRS_Tgt_RGs_for_Sub()
				break
			}
			"Test_GRS_Tag_TagName_TagVal_for_Sub"
			{
				$this.Test_GRS_Tag_TagName_TagVal_for_Sub()
				break
			}

			"Test_GRS_Tmp" #Using this label as a placeholder to work on new test cases...to defer creation of actual JSON for later (after TC is validated).
			{
				$this.Test_GRS_Tmp()
				break
			}			
			# GSS test cases
			"Test_GSS_Swt_Ubc"
			{
				$this.Test_GSS_Swt_Ubc()
				break
			}

			"Test_GSS_Tag_FilterTags_for_Sub"
			{
				$this.Test_GSS_Tag_FilterTags_for_Sub()
				break
			}
			"Test_Swt_Severity_Valid"
			{
				$this.Test_Swt_Severity_Valid()
				break
			}
			"Test_Swt_Severity_Invalid"
			{
				$this.Test_Swt_Severity_Invalid()
				break
			}
			"Test_Swt_Severity_ValidInvalid"
			{
				$this.Test_Swt_Severity_ValidInvalid();
				break
			}
			Default 
			{					
			}
		}
	}


#-----------------------------------------------------------------------------------------------------------------
#-----------------------------------------------------------------------------------------------------------------

#13Y
	[TestCaseResult] Test_GRS_Tgt_RsrcNames_for_Sub()
	{
		$subId = $this.testContext.TestResources.SubscriptionId

		#Generate a random sample of AzSK rsrcs
		$sampleSize = 3
		$azskRsrcs = $this.testContext.TestResources.ResourceInfo.GetRandomAzSKResources($sampleSize)

		$rsrcNames = $($azskRsrcs.Name -join ", ") 

		#Write-Warning "!!!!!!!!!! Remove -ubc !!!!!!!!!"
		$cmdStr = "grs -SubscriptionId $subId -ResourceNames `"$rsrcNames`" " #-ubc"   

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

		#### Validate		
		$bPass1 = $results.WereAllResourcesScanned($azskRsrcs)

		$bPassed = $bPass1
  		$failedMsg = ""
 		if (-not $bPassed) 
		{
 			$failedMsg = $results.GetErrMsg() 		
}
  		$passedMsg = "All resources from the specified resourceNames list were scanned."
		
		$this.testcaseResult = [SVTCore]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $cmdStr)
		return $this.testcaseResult
	}

#12
	[TestCaseResult] Test_GRS_Exc_RsrcTypeName_for_RGs()
	{
		$subId = $this.testContext.TestResources.SubscriptionId

		#Min-threshold for rsrcTypes diversity to look for in RGs
		$minAzSKRsrcTypes = 3
		$rgNames = $this.testContext.TestResources.ResourceInfo.GetRGsWithMultipleAzSKResources($minAzSKRsrcTypes)

		#Pick one at random
		$rgToUse = $rgNames | Get-Random

		#$rgToUse = "azsk-sf-rg"
		#Write-Warning "BUGBUG: Hardcoding RGtoUse: [$rgToUse]"

		$numRsrc = 1
		$randomRsrc = ($this.testContext.TestResources.ResourceInfo.GetRandomAzSKResourcesFromRG($rgToUse, $numRsrc))[0]
		
		#Use the resource type of this for our exclusion
		$rsrcTypeToExclude = $randomRsrc.ResourceType
		#Covert Azure resourceType to AzSKRTN
		$azskRTNToExclude = ($this.testContext.TestResources.ResourceInfo.GetAzSKResourceTypeNamesForAzureResourceTypes(@($rsrcTypeToExclude)))[0]

		<#	
		#Get unique (AzSK supported) resource Types from that RG
		$rsrcTypeList = ($h[$rgToUse] | Select-Object -Unique ResourceType).ResourceType

		Oh no, -ExcludeResourceTypeName supports only 1 type at a time! So all below was in vain :(
			$rsrcTypeCount = $rsrcTypeList.Count
			$rsrcExclCount = $rsrcTypeCount/2  #Always -gt 1 since we chose RGs with -ge 3 rsrcs

			#These are resource types we will exclude
			$rsrcExclList = $rsrcTypeList | Get-Random -Count $rsrcExclCount

			#These are resource types we expect will be scanned.
			$rsrcScanList =  ($rsrcTypeList | ?{$rsrcExclList -notcontains $_}  )
		#>
		
		#####################################
		# Form the GRS command 
		#####################################

		#Write-Warning("!!!!!!!!!!! Using -ubc. Remove it. !!!!!!!!!!!")
		$cmdStr = "grs -SubscriptionId $subId -ResourceGroupNames $rgToUse -ExcludeResourceTypeName $azskRTNToExclude" #-ubc"   

		#####################################
		#Invoke the GRS command and get results
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
		# Validate - scan contains all other types except the one we excluded! 
		#####################################
		# Check that the exclRTN was *not* scanned!
		$bPass1 = -not ($results.WereAllAzSKRTNsScanned( @($azskRTNToExclude) )) 

		#Fail also if all other resource types were not scanned:
		#Get all RTNs for the scanned RG
		$azSKRTNsInRG = $this.testContext.TestResources.ResourceInfo.GetAzSKRTNsForRG($rgToUse)
		#Remove the RTN we wanted to exclude
		$azSKRTNsToCheck = @($azSKRTNsInRG |?{$_ -ne $azskRTNToExclude})
		#Confirm that remaining were in scan
		$bPass2 = $results.WereAllAzSKRTNsScanned($azSKRTNsToCheck)

		$bPassed = ($bPass1 -and $bPass2)
  		$failedMsg = ""
 		if (-not $bPassed) 
		{
 			$failedMsg = $results.GetErrMsg() 		
		}
  		$passedMsg = "All resources except the specified ResourceTypeName were scanned from the specified RGs."
				
		$this.testcaseResult = [SVTCore]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $cmdStr)
		return $this.testcaseResult
	}

#11Y
	[TestCaseResult] Test_GRS_Swt_Ubc_Single_RG()
	{
		$subId = $this.testContext.TestResources.SubscriptionId

		###
		# ubc-switch at RG scope
		###

		#####################################
		# Find an RG with a UBC resource
		$rsrcUBC = ($this.testContext.TestResources.ResourceInfo.GetRandomAzSKResourcesUBC(1))[0]
		$rgName = $rsrcUbc.ResourceGroupName

		#####################################
		# Form the GRS command 
		#####################################
		$cmdStr = "grs -SubscriptionId $subId -ubc -ResourceGroupNames $rgName"   
		
		#####################################
		#Invoke the GRS command and get results
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
		$ubcRsrcsInRG = $this.testContext.TestResources.ResourceInfo.GetAzSKResourcesFromRGUBC($rgName)

		#Check that exactly the ubc resource set was scanned. Using '@()' wrapper to cover for single resource cases...so we can treat them as arrays!
		$bPass1 = $results.WereAllResourcesScanned($ubcRsrcsInRG)

		#Check that all controls scanned were 'ubc'
		$bPass2 = $results.WereAllControlsScannedUBC()
		
		$bPassed = ($bPass1 -and $bPass2)
  		$failedMsg = ""
 		if (-not $bPassed) 
		{
 			$failedMsg = $results.GetErrMsg() 		
		}
  		$passedMsg = "All applicable UBC controls from the specified RG were scanned."
		
		$this.testcaseResult = [SVTCore]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $cmdStr)
		return $this.testcaseResult
	}

#0Y
	[TestCaseResult] Test_Tag_FilterTags_for_Sub()
	{
		$subId = $this.testContext.TestResources.SubscriptionId

		$fTagsScan = $this.testContext.TestResources.ResourceInfo.GetRandomFilterTags()
		$fTagsScanStr = $fTagsScan -join ', '
		$cmdStr = "" #grs -s $subId -FilterTags  `"$fTagsScanStr`" " # -rgns AzSKRG"
		switch($this.testCase.ModuleName)
		{
			"GRS"
			{
				$cmdstr = "grs -s $subId -FilterTags  `"$fTagsScanStr`" " # -rgns AzSKRG"
				break;
			}
			"GSS"
			{
				$cmdstr = "gss -s $subId -FilterTags  `"$fTagsScanStr`" "
				break;
			}
			"GACS"
			{
				$cmdstr = "gacs -s $subId -FilterTags  `"$fTagsScanStr`" "
				break;
			}
			Default 
			{					
			}
	}
		#Write-Warning "BUGBUG - hardcoding filterTags!"
		#$fTagsScanStr = 'OwnerAccess'
		#Write-Warning "!!!!!!!!!!! Remove -rgns !!!!!!!!!!!!!!!"
		

		
		#####################################
		#Invoke the GRS command and get results
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

		#### Validate

		#All AzSK controls which have tags from the filter set
		$fTagsControls = $this.testContext.TestResources.ResourceInfo.FilterControlsWithTags($fTagsScan)
		$fTagsControlsSub = $this.testContext.TestResources.ResourceInfo.FilterApplicableControlsForSub($fTagsControls)
		$bPass1 = $results.WereAllControlsScanned($fTagsControlsSub)

		#TBD: -Ex versions have the orphan logic app workaround.
		$fTagsApplicableResources = $this.testContext.TestResources.ResourceInfo.GetApplicableResourcesForControlsEx($fTagsControls)
		
		$bPass2 = $results.WereAllResourcesScannedEx($fTagsApplicableResources)
	
		$bPassed = ($bPass1 -and $bPass2)
  		$failedMsg = ""
 		if (-not $bPassed) 
		{
 			$failedMsg = $results.GetErrMsg() 		
		}
  		$passedMsg = "All controls chosen via FilterTags option were scanned."
		
		$this.testcaseResult = [SVTCore]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $cmdStr)
		return $this.testcaseResult
	}

#1XY
	[TestCaseResult] Test_GRS_Tag_ExcludeTags_for_Sub()
	{
		$subId = $this.testContext.TestResources.SubscriptionId

		$xTagsScan = $this.testContext.TestResources.ResourceInfo.GetRandomExcludeTags()
		$xTagsScanStr = $xTagsScan -join ', '


		#Write-Warning "!!!!!!!!!!! Remove -rgns !!!!!!!!!!!!"
		$cmdStr = "grs -s $subId -ExcludeTags `"$xTagsScanStr`" " #-rgns AzSKRG"

		#####################################
		#Invoke the GRS command and get results
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

		#### Validate

		#All AzSK controls which *do not* have tags from the exclude set
		$xTagsControls = $this.testContext.TestResources.ResourceInfo.ExcludeControlsWithTags($xTagsScan)
		$xTagsControlsSub = $this.testContext.TestResources.ResourceInfo.FilterApplicableControlsForSub($xTagsControls)
		$bPass1 = $results.WereAllControlsScanned($xTagsControlsSub)

		#TBD: -Ex versions have the orphan logic app workaround.
		$xTagsApplicableResources = $this.testContext.TestResources.ResourceInfo.GetApplicableResourcesForControlsEx($xTagsControls)
		
		$bPass2 = $results.WereAllResourcesScannedEx($xTagsApplicableResources)
	
		$bPassed = ($bPass1 -and $bPass2)
  		$failedMsg = ""
 		if (-not $bPassed) 
		{
 			$failedMsg = $results.GetErrMsg() 		
		}
  		$passedMsg = "All controls specified via ExcludeTags option were scanned."
		
		$this.testcaseResult = [SVTCore]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $cmdStr)
		return $this.testcaseResult
	}

#2Y
	[TestCaseResult] Test_GRS_Tgt_ControlIds_for_Sub()
	{
		$subId = $this.testContext.TestResources.SubscriptionId

		# UniqueRsrcInSub -> Applicable-Controls -> select-1..5
		$nCtrlIds = (1..5 | Get-Random)

		$controlsToScan = $this.testContext.TestResources.ResourceInfo.GetRandomControlsForSub($nCtrlIds)

		$ctrlIdsToScan = $controlsToScan.ControlId

		# Make CtrlIdsString
		$ctrlIdsToScanStr = $ctrlIdsToScan -join ', '
		$ctrlIdsToScanStr

		$cmdStr = "grs -s $subId -ControlIds `"$ctrlIdsToScanStr`" "

		#####################################
		#Invoke the GRS command and get results
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

		#### Validate
		# Chk: All ctrlIds in scan and none else!
		$bPass1 = $results.WereAllControlsScanned($controlsToScan, $true) #Exclusive

		# Chk: All appl. rsrc were scanned
		<# TBDX: Commenting out as this seems redundant given the controls scanned check above! If all expected 
		controls were scanned then all expected features will be there in results!

		$expectedFeatures = $controlsToScan.FeatureName
		$tcsrFeatures = ($tcsr | Select-Object FeatureName -Unique).FeatureName

		$bFail = ($expectedFeatures | ?{$tcsrFeatures -contains $_}).Count -ne $expectedFeatures.Count
		#>

		#Chk: No other controls were scanned!
		$bPass2 = $true

		$bPassed = ($bPass1 -and $bPass2)
  		$failedMsg = ""
 		if (-not $bPassed) 
		{
 			$failedMsg = $results.GetErrMsg() 		
		}
  		$passedMsg = "All specified controlIds were scanned for the sub."
		
		$this.testcaseResult = [SVTCore]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $cmdStr) 
		return $this.testcaseResult
	}

#3Y
	[TestCaseResult] Test_GRS_Tgt_ControlIds_Single_Rsrc()
	{
		$subId = $this.testContext.TestResources.SubscriptionId

		# AzSKRsrcInSub -> Random RsrcName
		$rsrc = ($this.testContext.TestResources.ResourceInfo.GetRandomAzSKResources(1))[0]

		$rsrcType = $rsrc.ResourceType
		$rsrcRTN = $this.testContext.TestResources.ResourceInfo.GetAzSKResourceTypeNamesForAzureResourceTypes($rsrcType)

		$controlsToScan = $this.testContext.TestResources.ResourceInfo.GetRandomControlsForAzSKRTNs($rsrcRTN)

		# Make CtrlIdsString
		$ctrlIdsToScanStr = $controlsToScan.ControlId -join ', '


		$rgName = $rsrc.ResourceGroupName
		$rsrcName = $rsrc.Name

		#Write-Warning "!!!!!! Using -ubc. Remove it. !!!!!!!!"
		$cmdStr = "grs -s $subId -rgns $rgName -rns $rsrcName -ControlIds `"$ctrlIdsToScanStr`" " # -ubc"

		#####################################
		#Invoke the GRS command and get results
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
			#$outPath = "C:\Users\mprabhu\AppData\Local\Microsoft\AzSKStagingLogs\Sub_MSFT-Security Reference Architecture-04\20190629_083025_GRS"
			$results = [AzSKScanResults]::new($outPath, $this.testContext.TestResources.ResourceInfo)
		}

		#### Validate
		# Chk: All controls were scanned
		$bPass1 = $results.WereAllControlsScanned($controlsToScan, $true) #exclusive

		# Chk: No other rsrcName in scan
		$bPass2 = $results.WereAllAzSKRTNsScanned($rsrcRTN, $true)
		
		$bPassed = $bPass1 -and $bPass2

		$failedMsg = ""
		if (-not $bPassed)
		{
			$failedMsg = $results.GetErrMsg()
		}

		$passedMsg = "All controls from just the required resource type names were scanned."
		
		$this.testcaseResult = [SVTCore]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $cmdStr)
		return $this.testcaseResult
	}

#4Y
	[TestCaseResult] Test_GRS_Tgt_RsrcType_for_Sub()
	{
		$subId = $this.testContext.TestResources.SubscriptionId

		# AzSKRsrcInSub -> One Random RTN
		$rsrc = ($this.testContext.TestResources.ResourceInfo.GetRandomAzSKResources(1))[0]

		$rsrcType = $rsrc.ResourceType

		$rsrcRTN = $this.testContext.TestResources.ResourceInfo.GetAzSKResourceTypeNamesForAzureResourceTypes($rsrcType)

		$cmdStr = "grs -s $subId -ResourceTypeName $rsrcRTN"

		#####################################
		#Invoke the GRS command and get results
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

		#### Validate
		# Chk: Only expected RTN in scan and none other
		$bPass1 = $results.WereAllAzSKRTNsScanned($rsrcRTN, $true)

		# Chk: All rsrc for that RTN are in scan

		$allRTNRsrcInSub = $this.testContext.TestResources.ResourceInfo.GetResourcesForAzSKRTNs($rsrcRTN)

		$bPass2 = $results.WereAllResourcesScanned($allRTNRsrcInSub)

		$bPassed = ($bPass1 -and $bPass2)
  		$failedMsg = ""
 		if (-not $bPassed) 
		{
 			$failedMsg = $results.GetErrMsg() 		
		}
  		$passedMsg = "All resources with the specified ResourceTypeName were scanned."
		
		$this.testcaseResult = [SVTCore]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $cmdStr)
		return $this.testcaseResult
	}

#5Y
	[TestCaseResult] Test_GRS_Tgt_RsrcType_for_RGs()
	{
		$subId = $this.testContext.TestResources.SubscriptionId

		# Get some AzSK RTN which exists in multiple RGs
		$azskRTN = @($this.testContext.TestResources.ResourceInfo.GetRandomAzSKRTN($true))

		$rgNamesToScan = $this.testContext.TestResources.ResourceInfo.GetRGNamesForAzSKRTNs($azSKRTN)
		#---------------
		$rgNamesToScanStr = $rgNamesToScan -join ', '

		#GRS for that RTN across target RGs
		$cmdStr = "grs -s $subId -rgns `"$rgNamesToScanStr`" -ResourceTypeName $azskRTN"

		#####################################
		#Invoke the GRS command and get results
		#####################################
		$description =  $this.testCase.Description
		$tcName =  $this.testCase.TestMethod

		[TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)

		$retObj = [TestHelper]::GetAzSKCommandResults($tcName)
		$outPath = $retObj.ReturnVal
		$scanError = $retObj.Error
		$tcScanResults = Import-Csv "$outPath\SecurityReport*.csv" 

		$results = [AzSKScanResults]::new($outPath, $this.testContext.TestResources.ResourceInfo)
	

		# Chk: All RGNames in scan and none other.
		$bPass1 = $results.WereAllRGNamesScanned($rgNamesToScan)

		# Chk: Only expected RTN in scan and none other.
		$bPass2 = $results.WereAllAzSKRTNsScanned($azskRTN, $true)

		# Chk: Unique rsrc in scan match count of resources of that RTN across the RGNames
		$bPass3 = $results.WereAllResourcesForAzSKRTNsScanned($azskRTN, $rgNamesToScan)

		Write-Host -ForegroundColor Yellow "@@@@@@@@@@@ 5-GRS-Tgt-RsrcTypeName-RGs [$bPass1, $bPass2] @@@@@@@@@@@@@@"

		$bPassed = ($bPass1 -and $bPass2 -and $bPass3)
  		$failedMsg = ""
 		if (-not $bPassed) 
		{
 			$failedMsg = $results.GetErrMsg() 		
		}
  		$passedMsg = "All resources with the specified ResourceTypeName in the specified RGs were scanned."
		
		$this.testcaseResult = [SVTCore]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $cmdStr)
		return $this.testcaseResult
	}

# 6Y
	[TestCaseResult] Test_GRS_Exc_RGs_for_Sub()
	{
		$subId = $this.testContext.TestResources.SubscriptionId

		# Get a split of RGs into 2 groups per $fraction
		
		#TODO: may be make the fraction itself random (btwn 0 and 1)
		$rgNamesSplit = $this.testContext.TestResources.ResourceInfo.SelectRandomRGNamesForSub(0.20) #0.33

		$inclRGNames = @($rgNamesSplit.SelectedRGNames)
		$exclRGNames = @($rgNamesSplit.NotSelectedRGNames)


		# Make RGNamesExclString
		$excludeRGsString = $exclRGNames -join ', '

		#GRS for that RTN across target RGs
		$cmdStr = "grs -s $subId -ExcludeResourceGroupNames `"$excludeRGsString`" "

		#####################################
		#Invoke the GRS command and get results
		#####################################
		$description =  $this.testCase.Description
		$tcName =  $this.testCase.TestMethod

		[TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)

		$retObj = [TestHelper]::GetAzSKCommandResults($tcName)
		$outPath = $retObj.ReturnVal
		$scanError = $retObj.Error

		$results = [AzSKScanResults]::new($outPath, $this.testContext.TestResources.ResourceInfo)
	

		# Chk: All target RGNames were in scan *and* none else.	
		$bPass1 = $results.WereAllRGNamesScanned($inclRGNames, $true) #bExclusive

		# Chk: All expected resources were scanned... (#sanity)
		$bPass2 = $results.WereAllResourcesInRGNamesScanned($inclRGNames)  

		$bPassed = ($bPass1 -and $bPass2)
  		$failedMsg = ""
 		if (-not $bPassed) 
		{
 			$failedMsg = $results.GetErrMsg() 		
		}
  		$passedMsg = "Resources from specified exclude-RGs were excluded as expected."
		
		$this.testcaseResult = [SVTCore]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $cmdStr)
		return $this.testcaseResult
	}

# 7Y
	[TestCaseResult] Test_GRS_Tgt_RGs_for_Sub()
	{
		$subId = $this.testContext.TestResources.SubscriptionId

		# AzSKRsrcInSub -> Unique-RGs
		$inclCount = ((1..5) | Get-Random)
		#$inclCount = 1
		#Write-Warning "---- BUGBUG: hardcoding inclCount ----"
		$rgNamesSplit = $this.testContext.TestResources.ResourceInfo.SelectRandomRGNamesForSub(0.0, $inclCount) #use the count instead of fraction option

		#BUGBUG: Using @() as even though we return an array, it gets converted to a single string if only one element :-(
		$inclRGNames = @($rgNamesSplit.SelectedRGNames) 
		$exclRGNames = @($rgNamesSplit.NotSelectedRGNames)

		#$inclRGNames = 'RiniTestRG'
		#Write-Warning "---- BUGBUG: hardcoding RGName ----"
		# Make inclRGNamesStr  
		$inclRGNamesStr = $inclRGNames -join ', '

		#GRS for that RTN across target RGs
		$cmdStr = "grs -s $subId -rgns `"$inclRGNamesStr`" "

		#####################################
		#Invoke the GRS command and get results
		#####################################
		$description =  $this.testCase.Description
		$tcName =  $this.testCase.TestMethod

		[TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)

		$retObj = [TestHelper]::GetAzSKCommandResults($tcName)
		$outPath = $retObj.ReturnVal
		$scanError = $retObj.Error

		<# 
		$outPath = "C:\Users\mprabhu\AppData\Local\Microsoft\AzSKStagingLogs\Sub_MSFT-SECURITY REFERENCE ARCHITECTURE-02\20190712_114353_GRS"
		$scanError = $null
		#>

		$results = [AzSKScanResults]::new($outPath, $this.testContext.TestResources.ResourceInfo)

		# Chk: All target RGNames were in scan *and* none else.
		$bPass1 = $results.WereAllRGNamesScanned($inclRGNames, $true) #exclusive

		# Chk: All expected resources were scanned... (#sanity)
		$bPass2 = $results.WereAllResourcesInRGNamesScanned($inclRGNames) 


		$bPassed = ($bPass1 -and $bPass2)
  		$failedMsg = ""
 		if (-not $bPassed) 
		{
 			$failedMsg = $results.GetErrMsg() 		
		}
  		$passedMsg = "All resources from specified RGs in sub were scanned."
		
		$this.testcaseResult = [SVTCore]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $cmdStr)
		return $this.testcaseResult
	}


	# 8Y
	[TestCaseResult] Test_GRS_Tag_TagName_TagVal_for_Sub()
	{
		$subId = $this.testContext.TestResources.SubscriptionId

		# Get a random tag from some AzSK rsrc in sub
		$tag = $this.testContext.TestResources.ResourceInfo.GetRandomTagAndValuesForSub() 

		$tagName = $tag.TagName
		$tagVals = $tag.TagValues
		#GRS for that tag-name, tag-vals
		$cmdStr = "grs -s $subId -TagName $tagName -TagValues `"$tagVals`" "

		#####################################
		#Invoke the GRS command and get results
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

		#### Validate
		# Chk: All target RGNames were in scan *and* none else.
		$azskRsrcsWithTagAndValue = $this.testContext.TestResources.ResourceInfo.GetAzSKResourcesWithTagAndValuesForSub($tag.TagName, $tag.TagValues)

		$bPass1 = $results.WereAllResourcesScanned($azskRsrcsWithTagAndValue)

		$bPassed = ($bPass1)
  		$failedMsg = ""
 		if (-not $bPassed) 
		{
 			$failedMsg = $results.GetErrMsg() 		
		}
  		$passedMsg = "All resources with specified Azure tagName, tagValue were scanned."
		
		$this.testcaseResult = [SVTCore]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $cmdStr)
		return $this.testcaseResult
	}

	<# Template
	[TestCaseResult] Test_GRS_XXXXXX()
	{
		$subId = $this.testContext.TestResources.SubscriptionId

		###
		# Test: e.g., ubc at RG scope
		###

		#####################################
		# Determine resources/RGs/RTypes/ControlIds/etc
		#####################################

		#####################################
		# Form the GRS command (e.g.,grs -s $s2 -ResourceGroupNames 'azskrg' -ExcludeResourceTypeName Storage)
		#####################################

		$cmdStr = "grs -s $subId "

		#####################################
		#Invoke the GRS command and get results
		#####################################
		$description = $this.testCase.Description
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
		# Validate - e.g., all rsrcs were scanned. 
		#####################################
		
		$bPassed = $false
  		$failedMsg = ""
 		if (-not $bPassed) 
		{
 			$failedMsg = $results.GetErrMsg() 		
		}
  		$passedMsg = "FIXME: All specified <xyz> were scanned."
		
		#####################################
		# Report outcome
		#####################################
		$this.testcaseResult = [SVTCore]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $cmdStr)
		return $this.testcaseResult
	}
	#>

	#The next 3 tests were written before rsrc/azsk/results-helpers were created. 
	#Leaving these around mostly for reference...can remove after a couple of sprints.
	#-3D
	[TestCaseResult] Test_GRS_Tgt_RsrcNames_Random_DoNotUse()
	{
		$subId = $this.testContext.TestResources.SubscriptionId
		$rList = $this.testContext.TestResources.ResourceInfo.AllAzSKSupportedResourcesInSub		
		#Generate a random sample (of size $sampleSize) from RList
		$sampleSize = 3
		$rngIdx = 0..($rList.Count - 1) | Get-Random -Count $sampleSize
		#@@@@@@ GetRandomAzSKResources($sampleSize)
		$rListSample = $rList[$rngIdx] 

		$rNamesSample = $($rListSample.Name -join ", ") 

		#Write-Warning "Using -ubc to save time, remove it!"
		$cmdStr = "grs -SubscriptionId $subId -ResourceNames `"$rNamesSample`""    # -ubc "
		$description =  $this.testCase.Description
		$tcName =  $this.testCase.TestMethod

		[TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)

		$outPath = ""
		$scanError = ""
		#Receive-Job -Name $tcName -Keep -OutVariable OutputPath -ErrorVariable ScanError | Out-Null
		$retObj = [TestHelper]::GetAzSKCommandResults($tcName)
		$outPath = $retObj.ReturnVal
		$scanError = $retObj.Error

		#TODO: Validate that OutputCSV has expected rsrcNames in the control scan rows!
		$tcScanResults = Import-Csv "$outPath\SecurityReport*.csv" 

		[PSCustomObject] $scannedResourceList = $tcScanResults | Select-Object ResourceName, ResourceGroupName | Group-Object ResourceName| ForEach-Object {$_ | Select-Object -ExpandProperty Group | Select-Object -First 1} 
		
		$scannedResourceNames = ($scannedResourceList |  % {$_.ResourceName} )
		#TODO: scannedResourcesList will always have 'AzSKCfg' as first resource, to be ignored

		$numFound = 0
		$rListSample | % { $r = $_; if ($scannedResourceNames -contains $r.Name){$numFound++} }
		#@@@@@@ WerAllControlsScanned($rListSample)
		if ($numFound -eq $rListSample.count)  
		{
			$this.testcaseResult =[TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"GRS: Expected types were scanned!")
		}
		else
		{
			$this.testcaseResult =[TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"GRS: All expected types were *not* scanned! Command: [$cmdStr]")
		}
		return $this.testcaseResult
	}

#-2D
	[TestCaseResult] Test_GRS_Excl_RsrcTypes_in_RG_DoNotUse()
	{
		$subId = $this.testContext.TestResources.SubscriptionId
		$rList = $this.testContext.TestResources.ResourceInfo.AllAzSKSupportedResourcesInSub		
		$h = ($rList | Group-Object ResourceGroupName -AsHashTable)      
		# @@@@@@ Move to helper func... GetRGsContainingAtLeastNAzSKResources($n)
		#Get names of RGs with more than 3 AzSK supported RsrcTypes
		$minRsrcType = 3
		$rgNames = foreach ($x in $h.Keys) { if( ($h[$x] | Group-Object ResourceType).Count -ge $minRsrcType) { $x}} 

		#Pick one at random
		$rgToUse = $rgNames | Get-Random

		#Get unique (AzSK supported) resource Types from that RG
		$rsrcTypeList = ($h[$rgToUse] | Select-Object -Unique ResourceType).ResourceType

		<#	Oh no, -ExcludeResourceTypeName supports only 1 type at a time! So all below was in vain :(
			$rsrcTypeCount = $rsrcTypeList.Count
			$rsrcExclCount = $rsrcTypeCount/2  #Always -gt 1 since we chose RGs with -ge 3 rsrcs

			#These are resource types we will exclude
			$rsrcExclList = $rsrcTypeList | Get-Random -Count $rsrcExclCount

			#These are resource types we expect will be scanned.
			$rsrcScanList =  ($rsrcTypeList | ?{$rsrcExclList -notcontains $_}  )
		#>
		#Get one rsrcType
		$rsrcTypeToExclude = $rsrcTypeList | Get-Random

		#Map it back to AzSK RsrcTypeName (select-object -First 1 is reqd due to ErVNet and VNet both mapping to VirtualNetwork)
		$rsrcTypeNameToExclude = (($this.testContext.TestResources.ResourceInfo.AzSkSupportedResourceTypeMapping | where-object { $_.ResourceType -eq $rsrcTypeToExclude } | Select-Object -First 1)).ResourceTypeName

		#####################################
		# Form the GRS command (e.g.,grs -s $s2 -ResourceGroupNames 'azskrg' -ExcludeResourceTypeName Storage)
		#####################################

		#Write-Warning "Using -ubc to save time. Remove it!"
		$cmdStr = "grs -SubscriptionId $subId -ResourceGroupNames $rgToUse -ExcludeResourceTypeName $rsrcTypeNameToExclude"    # -ubc "

		#####################################
		#Invoke the command and get results
		#####################################
		$description =  $this.testCase.Description
		$tcName =  $this.testCase.TestMethod

		[TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)

		$outPath = ""
		$scanError = ""

		$retObj = [TestHelper]::GetAzSKCommandResults($tcName)
		$outPath = $retObj.ReturnVal
		$scanError = $retObj.Error

		#####################################
		# Validate - scan contains all other types except the one we excluded! 
		#####################################
		$tcScanResults = Import-Csv "$outPath\SecurityReport*.csv" 

		[PSCustomObject] $scannedResourceList = ($tcScanResults |  Select-Object FeatureName -Unique)
		<#
			ResourceName       FeatureName
			------------       -----------
			AzSKCfg            AzSKCfg    
			azsk20190208084531 Storage 
		#>
		#TODO: scannedResourcesList will always have 'AzSKCfg' as first resource, to be ignored

		#Fail if feature did not get excluded.
		$bFailed = ($scannedResourceList.FeatureName -contains $rsrcTypeNameToExclude) 

		#Fail also if all other resource types were not scanned

		$bFailed = $scannedResourceList.Count -ne $rsrcTypeList.Count #we account for one more due to AzSKCfg

		#####################################
		# Report outcome
		#####################################
		if (-not $bFailed)  
		{
			$this.testcaseResult =[TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"GRS: Expected rsrcTypeName was ignored in scan!")
		}
		else
		{
			$this.testcaseResult =[TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"GRS: Expected rsrcTypeName was not ignored/other types not scanned! Command: [$cmdStr]")
		}
		return $this.testcaseResult
	}

#-1D
	[TestCaseResult] Test_GRS_Swt_Ubc_Single_RG_DoNotUse()
	{
		$subId = $this.testContext.TestResources.SubscriptionId
		$rList = $this.testContext.TestResources.ResourceInfo.AllAzSKSupportedResourcesInSub		

		###
		# ubc-switch at RG scope
		###

		#####################################
		# Determine resources/RGs/RTypes/ControlIds/etc
		#####################################
		# Find an RG with a UBC resource
		$bFoundUbc = $false
		$rsrcUbc = $null
		while ($bFoundUbc -ne $true)
		{
			$rsrc = ($this.testContext.TestResources.ResourceInfo.AllAzSKSupportedResourcesInSub | Get-Random)
			$azskRTN = ($this.testContext.TestResources.ResourceInfo.GetAzSKResourceTypeNamesForAzureResourceTypes(@("$($rsrc.ResourceType)")))

			#Write-Host "$($rsrc.ResourceType):$azSKRTN"
			if ($this.testContext.TestResources.ResourceInfo.AzSKResourceTypeNamesUBC -contains $azskRTN)
			{
				$bFoundUbc = $true
				$rsrcUbc = $rsrc
			}
		}

		$rgName = $rsrcUbc.ResourceGroupName

		#####################################
		# Form the GRS command 
		#####################################
		$cmdStr = "grs -SubscriptionId $subId -ubc -ResourceGroupNames $rgName"   

		#####################################
		#Invoke the GRS command and get results
		#####################################
		$description =  $this.testCase.Description
		$tcName =  $this.testCase.TestMethod

		[TestHelper]::RunAzSKCommand($cmdStr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)

		$outPath = ""
		$scanError = ""

		$retObj = [TestHelper]::GetAzSKCommandResults($tcName)
		$outPath = $retObj.ReturnVal
		$scanError = $retObj.Error
		$tcScanResults = Import-Csv "$outPath\SecurityReport*.csv" 

		#####################################
		# Validate - 
		#	- all ubc resources in RG were scanned
		#	- only ubc controls were scanned  
		#####################################

		#AzSK supported rsrc in scanned RG
		$azSKRsrcInRG = ($this.testContext.TestResources.ResourceInfo.AllAzSKSupportedResourcesInSub | Where-Object {$_.ResourceGroupName -eq $rgName})

		#Figure out AzSK-UBC rsrc in that set (we have to exclude virtualNetworks if the RG-name is not ErNetwork)
		$azskRsrcInRGUBCx = $azSKRsrcInRG | ? {$this.testContext.TestResources.ResourceInfo.AzSKAzureResourceTypesUBC -contains $_.ResourceType}

		#Keep all other resources except vNets. Keep vNets only if RGName starts with ErNetwork
		$azSKRsrcInRGUBC = @($azskRsrcInRGUBCx | ? {($_.ResourceType -ne "Microsoft.Network/virtualNetworks" -or $_.ResourceGroupName -match "^ErNetwork*")})

		$scannedResourceList = @($tcScanResults | Select-Object ResourceName, FeatureName -Unique)
		
		#Check that exactly the ubc resource set was scanned. Using '@()' wrapper to cover for single resource cases...so we can treat them as arrays!
		$bFailed = $scannedResourceList.Count -ne $azskRsrcInRGUBC.Count + 1  # '+1' to consider AzSKCfg
		$bFailed = (@($azSKRsrcInRGUBC | Where-Object {$scannedResourceList.ResourceName -contains $_.Name})).Count -ne $azSKRsrcInRGUBC.Count

		#Check that all controls scanned were 'ubc'
		$bFailed = (@($tcScanResults | Where-Object{$_.IsBaselineControl -eq 'No'})).Count -ne 0

		#####################################
		# Report outcome
		#####################################
		if (-not $bFailed)  
		{
			$this.testcaseResult =[TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"GRS: Scan random RG with '-ubc' switch.")
		}
		else
		{
			$this.testcaseResult =[TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"GRS: Scan random RG with '-ubc' switch. Command used: [$cmdStr]")
		}
		return $this.testcaseResult
	}

	
# GSS test cases
# Duplication the same test case as for GRS that can be later combined and made more generic

[TestCaseResult] Test_GSS_Swt_Ubc()
{
	$subId = $this.testContext.TestResources.SubscriptionId
	$controlsToScan = [AzSKControlInfo]::AzSKControlInfoUBC | Where-Object{$_.FeatureName -eq 'SubscriptionCore'}
	###
	# ubc-switch 
	###

	#####################################
	# Form the GSS command 
	#####################################
	$cmdStr = "gss -SubscriptionId $subId -ubc "   
	
	#####################################
	#Invoke the GRS command and get results
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
	
	#Check that all controls scanned were 'ubc'
	$bPass1 = $results.WereAllControlsScannedUBC()
	$bPass2 = $results.WereAllControlsScanned($controlsToScan, $true)
	$bPassed = ($bPass1 -and $bPass2)
	  $failedMsg = ""
	 if (-not $bPassed) 
	{
		 $failedMsg = $results.GetErrMsg(); 		
	}
	  $passedMsg = "All applicable UBC controls from the specified RG were scanned."
	
	$this.testcaseResult = [SVTCore]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $cmdStr)
	return $this.testcaseResult
}


	

[TestCaseResult] Test_Swt_Severity_Valid()
{
	$subId = $this.testContext.TestResources.SubscriptionId

	#1) Get random Severity values from control Settings/harness settings
	$validSevs = $this.testContext.TestResources.ResourceInfo.GetValidControlSeverities();
	$rndmSev = @($validSevs | Get-Random -Count 2)
	$sevstr = $rndmSev -join ', '
	$cmdstr=""
	$rsrcRTNC = @();
	switch($this.testCase.ModuleName)
	{
		"GRS"
		{
			$rsrc = ($this.testContext.TestResources.ResourceInfo.GetRandomAzSKResources(1))[0]
			$rsrcType = $rsrc.ResourceType
			$rsrcRTN = $this.testContext.TestResources.ResourceInfo.GetAzSKResourceTypeNamesForAzureResourceTypes($rsrcType)
			$rsrcRTNC += @($rsrcRTN);
			# limiting by resource type so as to get the valid sevs for a feature and reduce scan time
			$cmdstr = "grs -s $subid -rtn $rsrcRTN -Severity `"$sevstr`"  "
			break;
		}
		"GSS"
		{
			$rsrcRTNC = @('SubscriptionCore')
			$cmdstr = "gss -s $subid -Severity `"$sevstr`"  "
			break;
		}
		"GACS"
		{
			$rsrc = ($this.testContext.TestResources.ResourceInfo.GetRandomAzSKResources(1))[0]
			$rsrcType = $rsrc.ResourceType
			$rsrcRTN = $this.testContext.TestResources.ResourceInfo.GetAzSKResourceTypeNamesForAzureResourceTypes($rsrcType)
			$rsrcRTNC += @($rsrcRTN)+@('SubscriptionCore')
			# limiting by resource type so as to get the valid sevs for a feature and reduce scan time
			$cmdstr = "gacs -s $subid -rtn $rsrcRTN -Severity `"$sevstr`"  "
			break;
		}
		Default 
		{					
		}

	}
	

	$TestResult = $this.TestSeveritySwitch($cmdstr, $rndmSev, $rsrcRTNC)
	return $TestResult
}

[TestCaseResult] Test_Swt_Severity_ValidInvalid()
{
	$subId = $this.testContext.TestResources.SubscriptionId

	#1) Get random Severity values from control Settings/harness settings
	$validSevs = $this.testContext.TestResources.ResourceInfo.GetValidControlSeverities();

	# Add some junk values to be passed in parameters
	$invalidSevValues = @('junk','High','Medum')
	$rndmSev = @($validSevs | Get-Random -Count 2)
	$rndmSev+=$invalidSevValues
	$sevstr = $rndmSev -join ', '
	$cmdstr=""
	$rsrcRTNC = @();
	switch($this.testCase.ModuleName)
	{
		"GRS"
		{
			$rsrc = ($this.testContext.TestResources.ResourceInfo.GetRandomAzSKResources(1))[0]
			$rsrcType = $rsrc.ResourceType
			$rsrcRTN = $this.testContext.TestResources.ResourceInfo.GetAzSKResourceTypeNamesForAzureResourceTypes($rsrcType)
			$rsrcRTNC += @($rsrcRTN);
			# limiting by resource type so as to get the valid sevs for a feature and reduce scan time
			$cmdstr = "grs -s $subid -rtn $rsrcRTN -Severity `"$sevstr`"  "
			break;
		}
		"GSS"
		{
			$rsrcRTNC = @('SubscriptionCore')
			$cmdstr = "gss -s $subid -Severity `"$sevstr`"  "
			break;
		}
		"GACS"
		{
			$rsrc = ($this.testContext.TestResources.ResourceInfo.GetRandomAzSKResources(1))[0]
			$rsrcType = $rsrc.ResourceType
			$rsrcRTN = $this.testContext.TestResources.ResourceInfo.GetAzSKResourceTypeNamesForAzureResourceTypes($rsrcType)
			$rsrcRTNC += @($rsrcRTN)+@('SubscriptionCore')
			# limiting by resource type so as to get the valid sevs for a feature and reduce scan time
			$cmdstr = "gacs -s $subid -rtn $rsrcRTN -Severity `"$sevstr`"  "
			break;
		}
		Default 
		{					
		}

	}
	
	
	$TestResult = $this.TestSeveritySwitch($cmdstr, $rndmSev, $rsrcRTNC)
	return $TestResult
}

[TestCaseResult] Test_Swt_Severity_Invalid()
{
	$subId = $this.testContext.TestResources.SubscriptionId	
	$validSevs = $this.testContext.TestResources.ResourceInfo.GetValidControlSeverities();
	# Add some junk values to be passed in parameters
	$invalidSevValues = @('junk','High','Medum')
	$sevstr = $invalidSevValues -join ', '
	$cmdstr =""
	$rsrcRTNC = @();
	switch($this.testCase.ModuleName)
	{
		"GRS"
		{
			$rsrc = ($this.testContext.TestResources.ResourceInfo.GetRandomAzSKResources(1))[0]
			$rsrcType = $rsrc.ResourceType
			$rsrcRTN = $this.testContext.TestResources.ResourceInfo.GetAzSKResourceTypeNamesForAzureResourceTypes($rsrcType)
			$rsrcRTNC += @($rsrcRTN);
			# limiting by resource type so as to get the valid sevs for a feature and reduce scan time
			$cmdstr = "grs -s $subid -rtn $rsrcRTN -Severity `"$sevstr`"  "
			break;
		}
		"GSS"
		{
			$rsrcRTNC = @('SubscriptionCore')
			$cmdstr = "gss -s $subid -Severity `"$sevstr`"  "
			break;
		}
		"GACS"
		{
			$rsrc = ($this.testContext.TestResources.ResourceInfo.GetRandomAzSKResources(1))[0]
			$rsrcType = $rsrc.ResourceType
			$rsrcRTN = $this.testContext.TestResources.ResourceInfo.GetAzSKResourceTypeNamesForAzureResourceTypes($rsrcType)
			$rsrcRTNC += @($rsrcRTN)+@('SubscriptionCore')
			# limiting by resource type so as to get the valid sevs for a feature and reduce scan time
			$cmdstr = "gacs -s $subid -rtn $rsrcRTN -Severity `"$sevstr`"  "
			break;
		}
		Default 
		{					
		}

	}
	
	
	$TestResult = $this.TestSeveritySwitch($cmdstr, $validSevs, $rsrcRTNC)
	return $TestResult
}

[TestCaseResult] TestSeveritySwitch($commandstr, $sevValuesPassed, $Feature)
{
	
	$description =  $this.testCase.Description
	$tcName =  $this.testCase.TestMethod
	$expectedSev = @();
	# Get valid severity values for the feature given that some features may not have controls with all severity
	$SevsValidForFeature = ($this.testContext.TestResources.ResourceInfo.AzSKControlInfoAll | Where-Object{$_.FeatureName -in $Feature -and $_.ControlSeverity -in $sevValuesPassed})
	$SevsValidForFeature = $SevsValidForFeature.ControlSeverity | Sort-Object | Get-Unique
	$expectedSev += $SevsValidForFeature | Where-Object {$_ -in $sevValuesPassed}
	
	
	#2) Run GSS with severity
	[TestHelper]::RunAzSKCommand($commandstr, $tcName, $description, $this.testcase.TestCaseID, $this.testContext)
	$retObj = [TestHelper]::GetAzSKCommandResults($tcName)
	$outPath = $retObj.ReturnVal
	$scanError = $retObj.Error
	$results = [AzSKScanResults]::new($outPath, $this.testContext.TestResources.ResourceInfo)
	$failedMsg=""
	#3) Check result severity has only the passed values
	$bPassed = $results.WereOnlyRequiredSeverityScanned($sevValuesPassed, $expectedSev);
	if (-not $bPassed) 
	{
		 $failedMsg = $results.GetErrMsg() 		
	}
	  $passedMsg = "All controls chosen '-Severity' option were scanned."
	
	$this.testcaseResult = [SVTCore]::CreateResult($this.TestCase, $bPassed, $passedMsg, $failedMsg, $commandstr)
	
	return $this.testcaseResult
	
}


	#####################################


#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	[void] Cleanup()
	{
	}
}
