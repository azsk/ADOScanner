Set-StrictMode -Version Latest 
class AnalysisServicesResource:SVTControlTestResource{
	AnalysisServicesResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
     
    }

	#Setting the properties as required by this resource type.
	[void]SetDerivedResourceProps(){
		$this.SetAdmin()
		#Pick the resource name from Params file if its not null
		if(![string]::IsNullOrEmpty($this.Params)){
				$this.ResourceName = $this.GetResourceNameFromARMJson($this.Params, "ResName", "value")
			}
		else{
			$this.ResourceName = "azsktestanalysisservice" #Else set the default resource name
		}
		$this.ResourceType = "Microsoft.AnalysisServices/servers" 
	}

	#Set Two Analysis Service Admin
	[void] AddTwoAnalysisServiceAdmin(){
		try{
			if($this.ProvisioningState -eq "Succeeded"){
				if(($this.settings.EmailAccounts | Measure-Object).Count -gt 1){
					[string] $emailAccounts = ($this.settings.EmailAccounts | Select-Object -ExpandProperty Name) -join ","
					set-Azanalysisservicesserver -Name $this.ResourceName -ResourceGroupName $this.ResourceGroupName -Administrator $emailAccounts
				}
				else{
					[CommonHelper]::Log("2 Email accounts are not configured, not able to set correct properties for the test case!", [MessageType]::Warning)
				}
		    }
		}
		catch{
				[CommonHelper]::Log("Error while setting the two Analysis Services Admin for: " + $this.ResourceName, [MessageType]::Error)
		}
	}

   #Set Three Analysis Service Admin
	[void] AddThreeAnalysisServiceAdmin()
	{
		try{
			if($this.ProvisioningState -eq "Succeeded"){
				if(($this.settings.EmailAccounts | Measure-Object).Count -gt 2){
					[string] $emailAccounts = ($this.settings.EmailAccounts | Select-Object -ExcludeProperty *) -join ","
					set-Azanalysisservicesserver -Name $this.ResourceName -ResourceGroupName $this.ResourceGroupName -Administrator $emailAccounts
				}
				else{
					[CommonHelper]::Log("3 Email accounts are not configured, not able to set correct properties for the test case!", [MessageType]::Warning)
				}
             }		
		}
		catch{
			[CommonHelper]::Log("Error while setting the three Analysis Services Admin for:" + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Reset Analysis Service with default analysis service admin
	[void] AddDefaultAnalysisServiceAdmin()
	{
	   try{
			if($this.ProvisioningState -eq "Succeeded"){
			if(($this.settings.EmailAccounts | Measure-Object).Count -gt 0){
				if(($this.settings.EmailAccounts | Measure-Object).Count -gt 1){
					set-Azanalysisservicesserver -Name $this.ResourceName -ResourceGroupName $this.ResourceGroupName -Administrator $this.settings.EmailAccounts[0]
				}
				else{
					set-Azanalysisservicesserver -Name $this.ResourceName -ResourceGroupName $this.ResourceGroupName -Administrator $this.settings.EmailAccounts
				}
			}
			else{
				[CommonHelper]::Log("No email account is configured, please check the Test Settings file!", [MessageType]::Error)
				$this.ProvisioningState = "Failed"
				}
              
	          }		
		}
		catch{
			[CommonHelper]::Log("Error while setting the default Analysis Services Admin for:" + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Pause Analysis Services
	[void] PauseAnalysisServices()
	{
        try{
			if($this.ProvisioningState -eq "Succeeded"){
			   #Getting Azure Resource details
			   $resourceDetails =   Get-AzAnalysisServicesServer -Name $this.ResourceName -ResourceGroupName $this.ResourceGroupName -ErrorAction Stop
			   if($resourceDetails.State -eq "Succeeded")
				{
				   #Pause Analysis Service
				   Suspend-AzAnalysisServicesServer -ResourceGroupName  $this.ResourceGroupName  -Name $this.ResourceName	
				}
             }		
		}
		catch{
			[CommonHelper]::Log("Error while pausing Analysis Services" + $this.ResourceName, [MessageType]::Error)
		} 
	}

	#Start Analysis Services
	[void] StartAnalysisServices()
	{
	   try{
			if($this.ProvisioningState -eq "Succeeded"){
			   #Getting Azure Resource details
			   $resourceDetails =   Get-AzAnalysisServicesServer -Name $this.ResourceName -ResourceGroupName $this.ResourceGroupName -ErrorAction Stop
			   if($resourceDetails.State -eq "Paused")
				{
				   #Start Analysis Service
				   Resume-AzAnalysisServicesServer -ResourceGroupName  $this.ResourceGroupName  -Name $this.ResourceName	
				}
             }		
		}
		catch{
			[CommonHelper]::Log("Error while re-starting Analysis Services :" + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Setting the admin field value in parameters file
	[void] SetAdmin(){
		try{
			$paramFile = [CommonHelper]::GetRootPath() + "\TestCases\"+$this.TestCase.Feature+"\"+$this.TestCase.ModuleName+"\TestData\"+$this.TestCase.ParamFileName
			if(!([string]::IsNullOrEmpty($paramFile))){
				if(($this.settings.EmailAccounts | Measure-Object).Count -gt 0){
					if(($this.settings.EmailAccounts | Measure-Object).Count -gt 1){
						[CommonHelper]::SetValueIntoJson($paramFile, "analysisservicesadmin", "value", $this.settings.EmailAccounts[0])
					}
					else{
						[CommonHelper]::SetValueIntoJson($paramFile, "analysisservicesadmin", "value", $this.settings.EmailAccounts)
					}
				}
				else{
					[CommonHelper]::Log("Failed to set analysis services admin in parameters file, please verify the test settings!", [MessageType]::Error)
				}
					
			}
		}
		catch{
			[CommonHelper]::Log("Failed to set analysis service admin in parameters file!", [MessageType]::Error)
		}
	}
}
