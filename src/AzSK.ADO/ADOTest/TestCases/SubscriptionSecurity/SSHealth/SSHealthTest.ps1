Set-StrictMode -Version Latest 
class SSHealthTest:AzSKTestBase{
	[string]$BaselineOutputPath = [string]::Empty
	SSHealthTest([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
		if(![string]::IsNullOrEmpty($testcase.BaselineOutput))
		{
			$this.BaselineOutputPath =[CommonHelper]::GetPath([PathList]::TestData,$testcase)+$testcase.BaselineOutput
		}
 }

	[void] Execute(){

	switch ($this.testcase.TestMethod){
				"TestGetAzSKSubscriptionSecurityStatus"{
					$this.TestGetAzSKSubscriptionSecurityStatus()
					break
				}
				"TestGetAzSKSubscriptionSecurityStatusWithControlIds"{
					$this.TestGetAzSKSubscriptionSecurityStatusWithControlIds()
					break
				}
				"TestGetAzSKSubscriptionSecurityStatusWithFilterTags"{
					$this.TestGetAzSKSubscriptionSecurityStatusWithFilterTags()
					break
				}
				"TestGetAzSKSubscriptionSecurityStatusWithExcludeTags"{
					$this.TestGetAzSKSubscriptionSecurityStatusWithExcludeTags()
				}
				"TestSetAzSKSubscriptionSecurity"{
					$this.TestSetAzSKSubscriptionSecurity()
				}
				"TestRemoveAzSKSubscriptionSecurity"{
					$this.TestRemoveAzSKSubscriptionSecurity()
				}
}
	}

	[TestCaseResult] TestGetAzSKSubscriptionSecurityStatus(){
		try{
			$outputpath = Get-AzSKSubscriptionSecurityStatus -SubscriptionId $this.testContext.TestResources.SubscriptionId -DoNotOpenOutputFolder
			if([CommonHelper]::IsSecurityReportGenerated($outputpath))
			{
				if(([CommonHelper]::VerifyCSVForError($outputpath,"Status")).Status -eq [TestStatus]::Passed)
				{
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully ran the subscription health scan.")
				}
				else{
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"One or more controls went into error.")
				}
			}
			else{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Security report is not generated.")
			}
		}
		catch{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Error,"Error while running the subscription health scan.")
		}

		return $this.testcaseResult
	}

	[TestCaseResult] TestGetAzSKSubscriptionSecurityStatusWithControlIds(){
		try{
			$outputpath = Get-AzSKSubscriptionSecurityStatus -SubscriptionId $this.testContext.TestResources.SubscriptionId -ControlIds "Azure_Subscription_AuthZ_Limit_Admin_Owner_Count, Azure_Subscription_AuthZ_Add_Required_Central_Accounts" -DoNotOpenOutputFolder
			if([CommonHelper]::IsSecurityReportGenerated($outputpath))
			{
				if(([CommonHelper]::VerifyCSVForError($outputpath,"Status")).Status -eq [TestStatus]::Passed)
				{
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully ran the subscription health scan.")
				}
				else{
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"One or more controls went into error.")
				}
			}
			else{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Security report is not generated.")
			}
		}
		catch{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Error,"Error while running the subscription health scan.")
		}

		return $this.testcaseResult
	}

	[TestCaseResult] TestGetAzSKSubscriptionSecurityStatusWithFilterTags(){
		try{
			$outputpath = Get-AzSKSubscriptionSecurityStatus -SubscriptionId $this.testContext.TestResources.SubscriptionId -FilterTags "AuthZ" -DoNotOpenOutputFolder
			if([CommonHelper]::IsSecurityReportGenerated($outputpath))
			{
				if(([CommonHelper]::VerifyCSVForError($outputpath,"Status")).Status -eq [TestStatus]::Passed){
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully ran the subscription health scan.")
				}
				else{
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"One or more controls went into error.")
				}
			}
			else{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Security report is not generated.")
			}
		}
		catch{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Error,"Error while running the subscription health scan.")
		}

		return $this.testcaseResult
	}

	[TestCaseResult] TestGetAzSKSubscriptionSecurityStatusWithExcludeTags(){
		try{
			$outputpath = Get-AzSKSubscriptionSecurityStatus -SubscriptionId $this.testContext.TestResources.SubscriptionId -FilterTags "AuthZ" -ExcludeTags "Best Practice" -DoNotOpenOutputFolder
			if([CommonHelper]::IsSecurityReportGenerated($outputpath))
			{
				if(([CommonHelper]::VerifyCSVForError($outputpath,"Status")).Status -eq [TestStatus]::Passed){
					$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully ran the subscription health scan.")
				}
				else{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"One or more controls went into error.")
				}
			}
			else{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Security report is not generated.")
			}
		}
		catch{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Error,"Error while running the subscription health scan.")
		}

		return $this.testcaseResult
	}
	[TestCaseResult] TestSetAzSKSubscriptionSecurity(){
		try{
				Set-AzSKSubscriptionSecurity -SubscriptionId $this.testContext.TestResources.SubscriptionId -SecurityContactEmails $this.settings.SecurityPOCEmail -SecurityPhoneNumber $this.settings.SecurityPhoneNo -DoNotOpenOutputFolder
				$outputPath = Get-AzSKSubscriptionSecurityStatus -SubscriptionId $this.testContext.TestResources.SubscriptionId -DoNotOpenOutputFolder
				$securityReportCsv = [string]::Empty
				if(![string]::IsNullOrEmpty($outputPath)){
					$securityReportCsv = Get-ChildItem -Path $outputPath -Include "SecurityReport-*.csv" -Recurse       
				}	
				if(![string]::IsNullOrEmpty($securityReportCsv)){
					$this.testCaseResult = [Assert]::AreFilesEqual($this.BaselineOutputPath,$securityReportCsv,$this.testcase) 
				}
			
			#$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully set the subscription security.")

				#$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Security report is not generated.")

		}
		catch{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Error,"Error while setting the subscription security.")
		}

		return $this.testcaseResult
	}

	[TestCaseResult] TestRemoveAzSKSubscriptionSecurity(){
		try{
			$outputpath = Remove-AzSKSubscriptionSecurity -SubscriptionId $this.testContext.TestResources.SubscriptionId -Tags 'Mandatory' -DoNotOpenOutputFolder
		    if([CommonHelper]::IsSecurityReportGenerated($outputpath))
			{
			 $this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Passed,"Successfully removed the subscription security.")
			}
			else{
				$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Failed,"Failed to run the subscription health scan.")
			}
		}
		catch{
			$this.testcaseResult = [TestCaseResult]::new($this.testCase,[TestStatus]::Error,"Error while removing the subscription security.")
		}

		return $this.testcaseResult
	}

}

