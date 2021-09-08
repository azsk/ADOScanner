class SVTTestBase: AzSKTestBase {

    [string] $BaselineOutputPath 
    [SVTControlTestResource] $Resource = $null
    SVTTestBase([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext): Base([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext) {
        
        $this.BaselineOutputPath =[CommonHelper]::GetPath([PathList]::TestData,$testcase)+$testcase.BaselineOutput
    }
    
    #Initialize the appropriate resource
    [Void]Initialize(){     
		switch ($this.testcase.ModuleName.ToUpper()){
			<#
			"ADLA"{
				$this.Resource   =  [ADLAResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			"ADLS"{
				$this.Resource   =  [ADLSResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			"Automation"{
				$this.Resource   =  [AutomationResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			"LogicApps"{
				$this.Resource   =  [LogicAppsResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			"APPSERVICE"{
				$this.Resource   =  [AppServiceResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			"SEARCH"{
				$this.Resource   =  [SearchResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			"BATCH"{
				$this.Resource   =  [BatchResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			"ANALYSISSERVICES"{
				$this.Resource   =  [AnalysisServicesResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			"DATAFACTORY"{
				$this.Resource   =  [DataFactoryResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			"STORAGE"{
				$this.Resource   =  [StorageResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			"SQLDB"{
				$this.Resource   =  [SQLDBResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
            "KEYVAULT"{
				$this.Resource   =  [KeyVaultResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			"VIRTUALNETWORK"{
				$this.Resource   =  [VirtualNetworkResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			"NOTIFICATIONHUB"{
				$this.Resource = [NotificationHubResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			"LOADBALANCER"{
				$this.Resource = [LoadBalancerResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			"SERVICEBUS"{
				$this.Resource = [ServiceBusResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			"CDN"{
				$this.Resource = [CDNResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			"REDISCACHE"{
				$this.Resource = [RedisCacheResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			"TRAFFICMANAGER"{
				$this.Resource = [TrafficManagerResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			"FUNCTIONS"{
				$this.Resource = [FunctionsResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			"EVENTHUB"{
				$this.Resource = [EventHubResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
			#>
			"COMMON"{
				$this.Resource = $null
				break
			}
			Default{
				$this.Resource = [SVTControlTestResource]::new($this.testcase, $this.settings, $this.TestContext)
				break
			}
		}

		# TODO: Change subid object reference
		$this.Resource.SubscriptionId = $this.testContext.TestResources.SubscriptionId
		$this.Resource.SetBaseResourceProps()
		$this.Resource.SetDerivedResourceProps()
		$this.Resource.InitializeResourceGroup()
		$this.Resource.InitializeResource()
		$this.Resource.PresetResource()
    }

	#Execute the test case
    [TestCaseResult]Execute(){
		[string]$outputpath = [string]::Empty  
		[string]$OverallControlStatuscsv = [string]::Empty
		try{
		if($this.Resource.ProvisioningState -eq "Succeeded"){
        $Global:EnableAuditing = $false   
        $outputpath = Get-AzSKAzureServicesSecurityStatus -SubscriptionId $this.Resource.SubscriptionId -ResourceGroupNames $this.Resource.ResourceGroupName -ResourceName $this.Resource.ResourceName -ResourceType $this.Resource.ResourceType -ExcludeTags "AzSKCfgControl" -DoNotOpenOutputFolder
		if(![string]::IsNullOrEmpty($outputpath)){
			$OverallControlStatuscsv = Get-ChildItem -Path $outputpath -Include "SecurityReport-*.csv" -Recurse       
		}
		}
			}
		catch{
			$this.testCaseResult.Message = "An Error occurred while running the test case!"
			[CommonHelper]::Log($_, [MessageType]::Error)
		}
		try{
			if(![string]::IsNullOrEmpty($OverallControlStatuscsv)){
			[CommonHelper]::Log("Refer the output at: " + $OverallControlStatuscsv , [MessageType]::Information) 
			$this.testCaseResult = [Assert]::AreFilesEqual($this.BaselineOutputPath,$OverallControlStatuscsv,$this.testcase) 
			}
			else{
			$this.testCaseResult.Message = "Security report csv file was not created, please refer AzSKTestLogs for more details!"
			}
		}
		catch{
			$this.testCaseResult.Message = "An Error occurred while comparing the security report csv files!"
			[CommonHelper]::Log($_, [MessageType]::Error)
		}
		
        return $this.testCaseResult
    }

	#Cleanup the resource
    [void]Cleanup(){
		try{
		# If resource is not marked for retention, then delete it , useful in case of resources which have significant retention costs.
		if(!$this.Resource.RetainResource){
			$status = Remove-AzResource -ResourceName $this.Resource.ResourceName -ResourceType $this.Resource.ResourceType -ResourceGroupName $this.Resource.ResourceGroupName -Force
			[CommonHelper]::Log("Deleted resource: " + $this.Resource.ResourceName, [MessageType]::Information)
			}
		#Else Run the reset functions 
		else{
			$this.Resource.ResetResource()
		}
		}
		catch{
			[CommonHelper]::Log("Failed to cleanup resource: " + $this.Resource.ResourceName, [MessageType]::Error)
			[CommonHelper]::Log($_, [MessageType]::Error)
		}
    }



}