Set-StrictMode -Version Latest 
Class SVTControlTestResource{
    [string] $SubscriptionId = [string]::Empty
      [string] $ResourceGroupName = "AzSKTestRG" #Override in the SetResource function if required
	[string] $Location = "eastus2" #Override in the SetResource function if required
	[string] $ResourceType = [string]::Empty
    [string] $ResourceName = [string]::Empty
    [string] $ProvisioningState = [string]::Empty
	[string] $Template = [string]::Empty
	[string] $Params = [string]::Empty
	[TestSettings] $Settings
	[TestContext] $testContext
	[string[]]$PresetMethods = @()
	[string[]]$ResetMethods = @()
	[bool] $RetainResource = $true  #Set this to false if resource needs to be deleted after test case execution in the SetResource function
	[PSObject] $CustomProps = $null
	[TestCase] $TestCase = $null

	SVTControlTestResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext){
		$this.TestCase = $testcase
		$this.Settings = $testsettings
		$this.testContext = $testContext
		$this.SubscriptionId = $testContext.TestResources.SubscriptionId
	}

	#Set the basic resource properties that are independent of resource type
	[void] SetBaseResourceProps(){
		
		if(!([string]::IsNullOrEmpty($this.TestCase.TemplateFileName))){
			$this.Template = [CommonHelper]::GetRootPath() + "\TestCases\"+$this.TestCase.Feature+"\"+$this.TestCase.ModuleName+"\TestData\"+$this.TestCase.TemplateFileName
		}
		if(!([string]::IsNullOrEmpty($this.TestCase.ParamFileName))){
			$this.Params = [CommonHelper]::GetRootPath() + "\TestCases\"+$this.TestCase.Feature+"\"+$this.TestCase.ModuleName+"\TestData\"+$this.TestCase.ParamFileName
		}
		if(!([string]::IsNullOrEmpty($this.TestCase.PropertiesFileName))){
			$propsFilePath = [CommonHelper]::GetRootPath() + "\TestCases\"+$this.TestCase.Feature+"\"+$this.TestCase.ModuleName+"\TestData\"+$this.TestCase.PropertiesFileName
			$this.CustomProps = Get-Content -Path $propsFilePath | ConvertFrom-Json
		}
		if(![string]::IsNullOrEmpty($this.TestCase.PresetMethods)){
			if($this.TestCase.PresetMethods.Contains(";")){
				$this.PresetMethods = $this.TestCase.PresetMethods.Split(";").Trim()
			}
			else{
				$this.PresetMethods = $this.TestCase.PresetMethods
			}
		}
		if(![string]::IsNullOrEmpty($this.TestCase.ResetMethods)){
			if($this.TestCase.ResetMethods.Contains(";")){
				$this.ResetMethods = $this.TestCase.ResetMethods.Split(";").Trim()
			}
			else{
				$this.ResetMethods = $this.TestCase.ResetMethods
			}
	    }
	}

	#Override this method in the derived class to set some specific properties based on the resource type
	[void] SetDerivedResourceProps(){

	}

	#Do the Preset resource activity (if any) before running the test case
	[void] PresetResource(){
		try{
		if($null -ne $this.PresetMethods){
			foreach($presetmethod in $this.PresetMethods){
				if(![string]::IsNullOrEmpty($presetmethod)){
				$this.$presetmethod()
					}
			}
		}
		}
		catch{
			[CommonHelper]::Log("Error while presetting the resource " + $this.ResourceName, [MessageType]::Error)
			[CommonHelper]::Log("Check if the corresponding preset method exists!" + $this.ResourceName, [MessageType]::Information)
		}
	}

	#Do the Reset resource activity (if any) after running the test case
	[void] ResetResource(){
		try{
		if($null -ne $this.ResetMethods){
			foreach($resetmethod in $this.ResetMethods){
				if(![string]::IsNullOrEmpty($resetmethod)){
				$this.$resetmethod()
					}
			}
		}
		}
		catch{
			[CommonHelper]::Log("Error while resetting the resource " + $this.ResourceName, [MessageType]::Error)
			[CommonHelper]::Log("Check if the corresponding reset method exists!" + $this.ResourceName, [MessageType]::Information)
		}
	}

	#Checks and deploys the resource if it does not exist.
	[void] InitializeResource( ){
		if($this.IfResourceExists()){
			if($this.TestCase.NeedsDefaultResource){
			   if($this.RemoveResource()){
					$this.ARMDeployResource()
				}
				else{
					[CommonHelper]::Log("Could not remove the resource, will use the existing one", [MessageType]::Warning)
				}
			}
		}
		else{
			$this.ARMDeployResource()	
		}
    }

	#Sets the name of the deployment
    [string] SetDeploymentName(){
        $deploymentName = "AzSKTestDeployment_" + (Get-Date -format "yyyyMMdd_HHmmss") 
        return $deploymentName
    }
	
	#Checks if the resource exists
    [bool] IfResourceExists(){
        
        try{
            $resource = Get-AzResource -ResourceGroupName $this.ResourceGroupName  -ResourceName $this.ResourceName -ResourceType $this.ResourceType
			if($null -ne $resource){
			[CommonHelper]::Log("Verified that the resource " + $this.ResourceName + " exists!", [MessageType]::Information)
			$this.ProvisioningState = "Succeeded"
            return $true
			}
			else{
			return $false
			}
        }
        catch{
			[CommonHelper]::Log("Could not find the resource " + $this.ResourceName, [MessageType]::Information)
            return $false
        }
        
    }

	#Checks if the linked resource exists
    [bool] IfLinkedResourceExists([String]$linkedResourceName,[String]$linkedResourceType){
        
        try{
            Get-AzResource -ResourceGroupName $this.ResourceGroupName  -ResourceName $linkedResourceName -ResourceType $linkedResourceType
			[CommonHelper]::Log("Verified that the linked resource " + $linkedResourceName + " exists!", [MessageType]::Information)
		    return $true
		}
        catch{
			[CommonHelper]::Log("Could not find the linked resource " + $linkedResourceName, [MessageType]::Information)
            return $false
        }
	}
	# Create Linked Resource 
	 [void] CreateLinkedResource([String]$linkedResourceName){
        
        try{
			 $linkedresource=New-AzStorageAccount -Location $this.Location -Name $linkedResourceName -ResourceGroupName $this.ResourceGroupName -SkuName Standard_LRS
            if($null -ne $linkedresource){
				[CommonHelper]::Log("Linked resource " + $linkedResourceName + " deployed", [MessageType]::Information)
			}
			else{
				[CommonHelper]::Log("Could not deploy the linked resource " + $LinkedResourceName, [MessageType]::Information)
			}
        }
        catch{
			[CommonHelper]::Log("Error in deploying linked resource " + $LinkedResourceName, [MessageType]::Information)
        }
	}

	#Remove the resource
	[bool] RemoveResource(){
		[bool]$result = $true
		try{
			Remove-AzResource -ResourceName $this.ResourceName -ResourceType $this.ResourceType -ResourceGroupName $this.ResourceGroupName -Force
			[CommonHelper]::Log("Removed resource " + $this.ResourceName, [MessageType]::Information)
		}
		catch{
			[CommonHelper]::Log("Error while removing the resource " + $this.ResourceName, [MessageType]::Warning)
			$result = $false
		}
		return $result
	}

	#Checks if the resource group exists
	[bool] IfResourceGroupExists(){
		try{
       $resGroup = Get-AzResourceGroup -Name $this.ResourceGroupName
	   if($null -ne $resGroup){
		[CommonHelper]::Log("Verified that the resource group " + $this.ResourceGroupName + " exists!", [MessageType]::Information)
           return $true
		}
		else
		{
		   return $false
		}
		}
		catch{
			[CommonHelper]::Log("Could not find the resource group " + $this.ResourceGroupName, [MessageType]::Information)
			return $false
		}
    }
	
	#Creates a new resource group
	[void] InitializeResourceGroup(){
		try{
			#Check if the corresponding resource group exists, if not then create it
			if(!$this.IfResourceGroupExists()){
				[CommonHelper]::Log("Creating resource group: " + $this.ResourceGroupName, [MessageType]::Information)
				New-AzResourceGroup -Name $this.ResourceGroupName -Location $this.Location -Force
			}
		}
		catch{
			[CommonHelper]::Log("Error creating resource group " + $this.ResourceGroupName, [MessageType]::Error)
			[CommonHelper]::Log($_, [MessageType]::Error)
			throw
		}
	}

	#Deploys the resource using ARM
	[void] ARMDeployResource(){
		$deploymentName = $this.SetDeploymentName()
		$deploymentDetails = $null
		try{
			#If the resource is deployable by ARM template
			if(![string]::IsNullOrEmpty($this.Template)){
				if(![string]::IsNullOrEmpty($this.Params)){
					$deploymentDetails =  New-AzResourceGroupDeployment -ResourceGroupName $this.ResourceGroupName -TemplateFile $this.Template -TemplateParameterFile $this.Params -Name $deploymentName
				}
				else{
					$deploymentDetails =  New-AzResourceGroupDeployment -ResourceGroupName $this.ResourceGroupName -TemplateFile $this.Template -Name $deploymentName
				}
			}
			$this.ProvisioningState = $deploymentDetails.ProvisioningState
			if($deploymentDetails.ProvisioningState -eq "Succeeded"){
				[CommonHelper]::Log( "Resource "+$this.ResourceName + " is successfully deployed using the ARM template.", [MessageType]::Information)
			}
			else{
				[CommonHelper]::Log( "Deployment for resource "+$this.ResourceName + " failed!", [MessageType]::Error)
			}
        }
		catch{
			$this.ProvisioningState = "Failed"
			[CommonHelper]::Log("Error deploying resource: " + $this.ResourceName + " using the ARM template.", [MessageType]::Error)
			[CommonHelper]::Log($_, [MessageType]::Error)
		}

	}

	#Get the resource name from ARM template or ARM Params jsons
	[string] GetResourceNameFromARMJson([string]$path,[string]$keyNode, [string]$valueNode){
		$resName = [string]::Empty
		try{
		if(![string]::IsNullOrEmpty($path)){
			if(![string]::IsNullOrEmpty($keyNode)){
				if(![string]::IsNullOrEmpty($valueNode)){
				   $resName=[CommonHelper]::GetValueFromJson($path, $keyNode,$valueNode)
				}
			}
		}
		}
		catch{
			[CommonHelper]::Log("Error while fetching the resource name from template/params jsons!", [MessageType]::Error)
		}
		return $resName
	}
	[bool] IfCommonStorageExists(){
		 try{
				$commonstorage=Get-AzResource -ResourceGroupName $this.ResourceGroupName  -ResourceName $this.Settings.CommonStorageAcctName 
				if($null -ne $commonstorage){
						[CommonHelper]::Log("Verified that the Common Storage account " + $this.Settings.CommonStorageAcctName  + " exists!", [MessageType]::Information)
						return $true
				}
				else
				{
					[CommonHelper]::Log("Could not find the Common Storage account " + $this.Settings.CommonStorageAcctName , [MessageType]::Information)
					return $false
				}

			}
		 catch{
				[CommonHelper]::Log("Error finding the Common Storage account " + $this.Settings.CommonStorageAcctName , [MessageType]::Information)
				return $false
			}
	}
	
	[void] CreateCommonStorage(){
        try{
			 $storageaccount=New-AzStorageAccount -Location $this.Location -Name $this.Settings.CommonStorageAcctName -ResourceGroupName $this.ResourceGroupName -SkuName Standard_LRS
             if($null -ne  $storageaccount){
				[CommonHelper]::Log("Common Storage account " + $this.Settings.CommonStorageAcctName + " deployed", [MessageType]::Information)
			}
			 else{
				[CommonHelper]::Log("Could not deploy the Common Storage account " + $this.Settings.CommonStorageAcctName, [MessageType]::Information)
			}
        }
        catch{
			[CommonHelper]::Log("Error in deploying Common Storage account " + $this.Settings.CommonStorageAcctName, [MessageType]::Information)
        }
	}

}