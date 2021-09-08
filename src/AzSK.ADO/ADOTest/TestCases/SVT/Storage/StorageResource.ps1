Set-StrictMode -Version Latest 
class StorageResource:SVTControlTestResource{
	
	StorageResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
     
    }

	#Setting the properties as required by this resource type.
	[void]SetDerivedResourceProps(){
		#Pick the resource name from Params file if its not null
		if(![string]::IsNullOrEmpty($this.Params)){
				$this.ResourceName = $this.GetResourceNameFromARMJson($this.Params, "ResName", "value")
			}
		else{
			$this.ResourceName = "azskteststg" + $(get-date -f MMddyyHHmm)  #Else set the default resource name
		}
		$this.ResourceType = "Microsoft.Storage/storageAccounts" 
	}

	#Set storage diagnostics on
	[void]SetStorageDiagnisticsOn(){
		try{
			if($this.ProvisioningState -eq "Succeeded"){
					$recDtls = (Get-AzStorageAccount -Name $this.ResourceName -ResourceGroupName $this.ResourceGroupName -ErrorAction Stop).Context
					$currentContext = $recDtls.Context

					Set-AzureStorageServiceLoggingProperty -ServiceType Blob -LoggingOperations All -Context $currentContext -RetentionDays 365 -PassThru
					Set-AzureStorageServiceLoggingProperty -ServiceType Queue -LoggingOperations All -Context $currentContext -RetentionDays 365 -PassThru
					Set-AzureStorageServiceLoggingProperty -ServiceType Table -LoggingOperations All -Context $currentContext -RetentionDays 365 -PassThru    
               
					Set-AzureStorageServiceMetricsProperty -MetricsType Hour -ServiceType Blob -Context $currentContext -MetricsLevel ServiceAndApi -RetentionDays 365 -PassThru
					Set-AzureStorageServiceMetricsProperty -MetricsType Hour -ServiceType Queue -Context $currentContext -MetricsLevel ServiceAndApi -RetentionDays 365 -PassThru
					Set-AzureStorageServiceMetricsProperty -MetricsType Hour -ServiceType Table -Context $currentContext -MetricsLevel ServiceAndApi -RetentionDays 365 -PassThru
					Set-AzureStorageServiceMetricsProperty -MetricsType Hour -ServiceType File -Context $currentContext -MetricsLevel ServiceAndApi -RetentionDays 365 -PassThru
			 }
		}
		catch{
				[CommonHelper]::Log("Error while setting Diagnostics On for: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Add storage alerts
	[void]AddAzSKTestStorageAlerts(){
		try{
			if($this.ProvisioningState -eq "Succeeded"){
				$rmRecDtls = Get-AzResource -ResourceName $this.ResourceName -ResourceGroupName $this.ResourceGroupName -ErrorAction Stop
				$rmRecDtls.Location
				$rmRecDtls.ResourceId

				$email = New-AzAlertRuleEmail  -SendToServiceOwners -WarningAction SilentlyContinue
				$targetRecId = $rmRecDtls.ResourceId+"/services/"+"blob"

				$alertName = "azsktestalert" + (get-date -Format "dd-mm-yyyy-hh-mm-ss").ToString()
				Add-AzMetricAlertRule -Location $rmRecDtls.Location -MetricName AnonymousSuccess -Name $alertName -Operator GreaterThan `
												-ResourceGroup $this.ResourceGroupName `
												-TargetResourceId $targetRecId `
												-Threshold 0 -TimeAggregationOperator Total -WindowSize 01:00:00  -Actions $email

				$targetRecId = $rmRecDtls.ResourceId+"/services/"+"queue"
				$alertName = "azsktestalert" + (get-date -Format "dd-mm-yyyy-hh-mm-ss").ToString()
				Add-AzMetricAlertRule -Location $rmRecDtls.Location -MetricName AnonymousSuccess -Name $alertName -Operator GreaterThan `
												-ResourceGroup $this.ResourceGroupName `
												-TargetResourceId $targetRecId `
												-Threshold 0 -TimeAggregationOperator Total -WindowSize 01:00:00  -Actions $email

				$targetRecId = $rmRecDtls.ResourceId+"/services/"+"table"
				$alertName = "azsktestalert" + (get-date -Format "dd-mm-yyyy-hh-mm-ss").ToString()
				Add-AzMetricAlertRule -Location $rmRecDtls.Location -MetricName AnonymousSuccess -Name $alertName -Operator GreaterThan `
												-ResourceGroup $this.ResourceGroupName  `
												-TargetResourceId $targetRecId `
												-Threshold 0 -TimeAggregationOperator Total -WindowSize 01:00:00  -Actions $email

				$targetRecId = $rmRecDtls.ResourceId+"/services/"+"file"
				$alertName = "azsktestalert" + (get-date -Format "dd-mm-yyyy-hh-mm-ss").ToString()
				Add-AzMetricAlertRule -Location $rmRecDtls.Location -MetricName AnonymousSuccess -Name $alertName -Operator GreaterThan `
												-ResourceGroup $this.ResourceGroupName `
												-TargetResourceId $targetRecId `
												-Threshold 0 -TimeAggregationOperator Total -WindowSize 01:00:00  -Actions $email
			 }
		}
		catch{
				[CommonHelper]::Log("Error while setting Alerts for: " + $this.ResourceName, [MessageType]::Error)
		}
			
	}

	#Add container with public access
	[void]AddContainerWithPublicAcess(){	
		try{
			if($this.ProvisioningState -eq "Succeeded"){
				$currentContext = (Get-AzStorageAccount -Name  $this.ResourceName -ResourceGroupName $this.ResourceGroupName).Context
				$permissions = "Blob"
				$contanierName = "azsktestcontainer" + (get-date -Format "dd-mm-yyyy-hh-mm-ss").ToString()
				New-AzureStorageContainer -Name $contanierName -Permission $permissions -Context $currentContext  
			}
		}
		catch{
				[CommonHelper]::Log("Error while adding storage container with public access for : " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Remove storage alerts
	[void]RemoveAzSKTestStorageAlerts(){
		try{
			 $allAzureRmAlertRulesDtls = Get-AzAlertRule -ResourceGroup $this.ResourceGroupName -ErrorAction Stop -WarningAction SilentlyContinue
			 $azureRmAlertRulesName = $allAzureRmAlertRulesDtls | Where-Object {($_.Id -like $this.Settings.StorageAlertId + "*") -and ($_.Condition.DataSource.MetricName -eq "AnonymousSuccess")}  
			 if(($azureRmAlertRulesName | Measure-Object).Count -gt 0){
				 $azureRmAlertRulesName.Name | ForEach-Object {
  					Remove-AzAlertRule -ResourceGroup $this.ResourceGroupName -Name $_ -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
				 }	
			}
		}
		catch{
				[CommonHelper]::Log("Error while re-setting alerts : " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Remove storage container
	[void]RemoveAzSKTestStorageContainer(){
		try{
				$recDtls = (Get-AzStorageAccount -Name $this.ResourceName -ResourceGroupName $this.ResourceGroupName -ErrorAction Stop).Context
				$currentContext = $recDtls.Context

				$storageContainerDtls = Get-AzureStorageContainer -Context $currentContext -ErrorAction Stop
					if( ($storageContainerDtls | Measure-Object).Count -gt 0){
     
					$storageContainerDtls.Name | ForEach-Object{
						Remove-AzureStorageContainer -Name $_  -Context $currentContext   -Force -ErrorAction SilentlyContinue
						}
					}
			}
		catch{
				[CommonHelper]::Log("Error while removing storage container for: " + $this.ResourceName, [MessageType]::Error)
		}
	
	}

	#Set file encryption at rest
	[void]SetFileEncryptionAtRest(){
		try{
			if($this.ProvisioningState -eq "Succeeded"){
			Set-AzStorageAccount -Name $this.ResourceName -ResourceGroupName $this.ResourceGroupName -StorageEncryption -EnableEncryptionService 'File'
			
			}
		}
		catch{
			[CommonHelper]::Log("Error while setting file encryption at rest for: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Enable HTTPS traffic only
	[void]SetEnableHttpsTrafficOnly(){
		try{
			if($this.ProvisioningState -eq "Succeeded"){
			  Set-AzStorageAccount -Name $this.ResourceName -ResourceGroupName $this.ResourceGroupName -EnableHttpsTrafficOnly $true
			}
		}
		catch{
		  [CommonHelper]::Log("Error while setting EnableHttpsTrafficOnly for: " + $this.ResourceName, [MessageType]::Error)
		}
	}

}

