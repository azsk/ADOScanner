Set-StrictMode -Version Latest 
class ADLATest:SVTTestBase{
    ADLATest([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
     
    }
    #Cleanup the resource
    [void]Cleanup(){
		try{
			Start-Sleep -Seconds 5				
			Remove-AzDataLakeAnalyticsAccount -Name $this.Resource.ResourceName -ResourceGroupName $this.Resource.ResourceGroupName -Force
			[CommonHelper]::Log("Deleted ADLA: " + $this.Resource.ResourceName, [MessageType]::Information)
		}
		catch{
			[CommonHelper]::Log("Failed to cleanup resource: " + $this.Resource.ResourceName, [MessageType]::Error)
			[CommonHelper]::Log($_, [MessageType]::Error)
		}
		try
		{
			Start-Sleep -Seconds 15
			Remove-AzDataLakeStoreAccount -Name $this.Resource.defaultDataLakeStoreName -ResourceGroupName $this.Resource.ResourceGroupName -Force
			[CommonHelper]::Log("Deleted ADLS: " + $this.Resource.defaultDataLakeStoreName, [MessageType]::Information)
		}
		catch{
			[CommonHelper]::Log("Failed to cleanup resource: " + $this.Resource.defaultDataLakeStoreName, [MessageType]::Error)
			[CommonHelper]::Log($_, [MessageType]::Error)
		}
    }
}