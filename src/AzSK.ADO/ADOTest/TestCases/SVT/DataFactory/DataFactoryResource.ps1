Set-StrictMode -Version Latest 
class DataFactoryResource:SVTControlTestResource{
	DataFactoryResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
     
    }

#Setting the properties as required by this resource type.
	[void]SetDerivedResourceProps(){
		$this.ResourceName = "azsktestdatafactory" #Else set the default resource name
		$this.ResourceType = "Microsoft.DataFactory/datafactories" 
	}

	#Checks and deploys the data factory if it does not exist.
	[void] InitializeResource( ){
		if(!$this.IfResourceExists()){
			$this.DeployDataFactory()	
		}
    }

	#Deploy the data factory
	[void]DeployDataFactory(){
		try{
			New-AzDataFactory -ResourceGroupName $this.ResourceGroupName -Name $this.ResourceName -Location "eastus" -Force
			$this.ProvisioningState = "Succeeded"
			[CommonHelper]::Log("Resource "+$this.ResourceName + " is successfully deployed", [MessageType]::Information)
		}
		catch{
			[CommonHelper]::Log("Error while deploying the Data Factory: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Set data factory linked service 
	[void]SetLinkedService()
	{
		try
		{
			$linkServices = Get-AzDataFactoryLinkedService -ResourceGroupName $this.ResourceGroupName -DataFactoryName $this.ResourceName
			if(($linkServices|Measure-Object).count -eq 0)
			{
				$Path = [CommonHelper]::GetRootPath()
				$Path+="\TestCases\SVT\DataFactory\TestData\DataFactoryStorageLinkedService.json"
				New-AzDataFactoryLinkedService -ResourceGroupName $this.ResourceGroupName -DataFactoryName $this.ResourceName -Name "LinkedServiceCuratedWikiData" -File $Path -Force | Format-List
				[CommonHelper]::Log("Successfully set the data factory linked service to: "+$this.ResourceName, [MessageType]::Information)
			}
		}
		catch
		{
			[CommonHelper]::Log("Error while setting data factory linked service for: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Remove data factory linked service 
	[void]RemoveLinkedService()
	{
		try
		{
			# Remove all pipeline if exist
			$pipelines = Get-AzDataFactoryPipeline -ResourceGroupName $this.ResourceGroupName -DataFactoryName $this.ResourceName
			if(($pipelines|Measure-Object).count -gt 0)
			{
				foreach ($pipeline in $pipelines)
				{            
					Remove-AzDataFactoryPipeline -DataFactoryName $this.ResourceName -ResourceGroupName $this.ResourceGroupName -Name $pipeline.PipelineName -Confirm:$false -Force
				}
			}
			
			# Remove all dataset if exist
			$datasets = Get-AzDataFactoryDataset -ResourceGroupName $this.ResourceGroupName -DataFactoryName $this.ResourceName
			if(($datasets|Measure-Object).count -gt 0)
			{
				foreach ($dataset in $datasets)
				{            
					AzureRM\Remove-AzDataFactoryDataset -DataFactoryName $this.ResourceName -ResourceGroupName $this.ResourceGroupName -Name $dataset.DatasetName -Confirm:$false -Force
				}
			}  

			# Remove all LinkedService if exist
			$linkServices = Get-AzDataFactoryLinkedService -ResourceGroupName $this.ResourceGroupName -DataFactoryName $this.ResourceName
			if(($linkServices|Measure-Object).count -gt 0)
			{
				foreach ($linkService in $linkServices)
				{            
					Remove-AzDataFactoryLinkedService -DataFactoryName $this.ResourceName -ResourceGroupName $this.ResourceGroupName -Name $linkService.LinkedServiceName -Confirm:$false -Force
				}
			}  
			
			[CommonHelper]::Log("Successfully remove the data factory linked service to: "+$this.ResourceName, [MessageType]::Information)
		}
		catch
		{
			[CommonHelper]::Log("Linked Service does not exist or error while remove data factory linked service for: " + $this.ResourceName, [MessageType]::Error)
		}
	}
}