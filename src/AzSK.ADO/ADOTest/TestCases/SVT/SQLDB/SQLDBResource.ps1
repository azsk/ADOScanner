Set-StrictMode -Version Latest 
class SQLDBResource:SVTControlTestResource{
	
	SQLDBResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
     
    }
	#Setting the properties as required by this resource type.
	[void]SetDerivedResourceProps(){
		$this.SetKeyVaultUrl()

		#Pick the resource name from Params file if its not null
		if(![string]::IsNullOrEmpty($this.Params)){
				$this.ResourceName = $this.GetResourceNameFromARMJson($this.Params, "ResName", "value")
			}
		else{
			$this.ResourceName = "azsktestsqldb" #Else set the default resource name
		}
		$this.ResourceType = "Microsoft.Sql/servers" 
	}

	#Enable Sql Server Auditing
	[void]EnableSqlServerAuditing(){
		try{
			$TableIdentifier = "SQLServer" + $(Get-Date -format "yyyyMMDDHHmmss")
            Set-AzSqlServerAuditing `
                -ResourceGroupName $this.ResourceGroupName `
                -ServerName $this.ResourceName `
                -StorageAccountName $this.settings.CommonStorageAcctName `
                -State Enabled `
                -RetentionInDays 365 `
                -TableIdentifier $TableIdentifier `
                -ErrorAction Stop
		}
		catch{
				[CommonHelper]::Log("Error while Enabling Sql Server Auditing : " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Disable Sql Server Auditing
	[void]DisableSqlServerAuditing(){
		try{
			$TableIdentifier = "SQLServer" + $(Get-Date -format "yyyyMMDDHHmmss")
            Set-AzSqlServerAuditing `
                -ResourceGroupName $this.ResourceGroupName `
                -ServerName $this.ResourceName `
                -StorageAccountName $this.settings.CommonStorageAcctName `
                -State Disabled `
                -RetentionInDays 10 `
                -TableIdentifier $TableIdentifier `
                -ErrorAction Stop
		}
		catch{
				[CommonHelper]::Log("Error while disabling Sql Server Auditing : " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Enable Sql Server Threat Detection Policy
	[void]EnableSqlServerThreatDetectionPolicy(){
		try{ 
            Set-AzSqlServerThreatDetectionPolicy -ResourceGroupName $this.ResourceGroupName `
													  -ServerName $this.ResourceName `
			                                          -StorageAccountName $this.settings.CommonStorageAcctName `
                                                      -EmailAdmins $true `
			                                          -ExcludedDetectionType None `
                                                      -ErrorAction Stop
		}
		catch{
				[CommonHelper]::Log("Error while Enabling Sql Server Threat Detection Policy : " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Disable Sql Server Threat Detection Policy
	[void]DisableSqlServerThreatDetectionPolicy(){
		try{ 
            Set-AzSqlServerThreatDetectionPolicy -ResourceGroupName $this.ResourceGroupName `
													  -ServerName $this.ResourceName `
			                                          -StorageAccountName $this.settings.CommonStorageAcctName `
                                                      -EmailAdmins $false `
			                                          -ExcludedDetectionType Sql_Injection `
                                                      -ErrorAction Stop
		}
		catch{
				[CommonHelper]::Log("Error while disabling Sql Server Threat Detection Policy : " + $this.ResourceName, [MessageType]::Error)
		}
	}


	#set Sql Server Active Directory Administrator
	[void]SetSqlServerActiveDirectoryAdmin(){
		try{ 
            Set-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $this.ResourceGroupName `
														     -ServerName $this.ResourceName `
														     -ErrorAction Stop
			}
		catch{
				[CommonHelper]::Log("Error while setting Sql Server Active Directory Administrator : " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Remove Sql Server Active Directory Administrator
	[void]RemoveSqlServerActiveDirectoryAdmin(){
		try{ 
            Remove-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName $this.ResourceGroupName `
														     -ServerName $this.ResourceName `
														     -Force `
														     -ErrorAction Stop
			}
		catch{
				[CommonHelper]::Log("Error while removing Sql Server Active Directory Administrator : " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#set Sql Server Firewall IP Address Ranges
	[void]SetSqlServerFirewallIPAddressRanges(){
		try{ 
			#Set Allow access to Azure services
            New-AzSqlServerFirewallRule -FirewallRuleName "AllowAllWindowsAzureIps" -ResourceGroupName $this.ResourceGroupName   -ServerName $this.ResourceName `
                                             -StartIpAddress "0.0.0.0" -EndIpAddress "0.0.0.0"
			
			New-AzSqlServerFirewallRule -FirewallRuleName "AzSKTestFirewallRule" -ResourceGroupName $this.ResourceGroupName   -ServerName $this.ResourceName `
                                             -StartIpAddress "0.0.0.10" -EndIpAddress "0.0.0.20"
		
		}
		catch{
				[CommonHelper]::Log("Error while setting Sql Server Firewall IP Address Ranges : " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Remove Sql Server Firewall IP Address Ranges
	[void]RemoveSqlServerFirewallIPAddressRanges(){
		try{ 
            Remove-AzSqlServerFirewallRule -FirewallRuleName "AllowAllWindowsAzureIps" -ResourceGroupName $this.ResourceGroupName   -ServerName $this.ResourceName -Force			
			Remove-AzSqlServerFirewallRule -FirewallRuleName "AzSKTestFirewallRule" -ResourceGroupName $this.ResourceGroupName   -ServerName $this.ResourceName -Force		
		}
		catch{
				[CommonHelper]::Log("Error while removing Sql Server Firewall IP Address Ranges : " + $this.ResourceName, [MessageType]::Error)
		}
	}


	#set Sql Server Any to Any Firewall Rule
	[void]SetSqlServerAnyToAnyFirewallRule(){
		try{ 	
			New-AzSqlServerFirewallRule -FirewallRuleName "AzSKTestAnyToAnyRule" -ResourceGroupName $this.ResourceGroupName   -ServerName $this.ResourceName `
                                             -StartIpAddress "0.0.0.0" -EndIpAddress "255.255.255.255"
		
		}
		catch{
				[CommonHelper]::Log("Error while setting Sql Server Any to Any Firewall Rule: " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#set Sql Server Any to Any Firewall Rule
	[void]RemoveSqlServerAnyToAnyFirewallRule(){
		try{ 	
			Remove-AzSqlServerFirewallRule -FirewallRuleName "AzSKTestAnyToAnyRule" -ResourceGroupName $this.ResourceGroupName   -ServerName $this.ResourceName 		
		}
		catch{
				[CommonHelper]::Log("Error while setting Sql Server Any to Any Firewall Rule: " + $this.ResourceName, [MessageType]::Error)
		}
	}


	#Add Single DB to SQL Server
	[void]AddDataBase()
	{
       try{ 	
				New-AzSqlDatabase  -ResourceGroupName $this.ResourceGroupName `
										-ServerName $this.ResourceName `
										-DatabaseName "AzSKTestDB01" `
										-RequestedServiceObjectiveName "Basic" 
		
		}
		catch{
				[CommonHelper]::Log("Error while adding database " + $this.ResourceName, [MessageType]::Error)
		}
	}

	#Add Single DB to SQL Server
	[void]EnableSqlDatabaseTransparentDataEncryption()
	{
       try{ 	
				Set-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName $this.ResourceGroupName `
										-ServerName $this.ResourceName `
										-DatabaseName "AzSKTestDB01" `
                                        -State Enabled
		}
		catch{
				[CommonHelper]::Log("Error while setting Sql Database Transparent Data Encryption " + $this.ResourceName, [MessageType]::Error)
		}
	}

	[void]RemoveDatabase()
	{
		try{ 	
						Remove-AzSqlDatabase -ResourceGroupName $this.ResourceGroupName   `
												-ServerName $this.ResourceName `
												-DatabaseName "AzSKTestDB01" `
												-Force
				}
				catch{
						[CommonHelper]::Log("Error while deleting database " + $this.ResourceName, [MessageType]::Error)
				}
	}

	#Setting the Key Vault Url in SQL DB ARM template parameter
	[void] SetKeyVaultUrl(){
		try{
			$paramFile = [CommonHelper]::GetRootPath() + "\TestCases\"+$this.TestCase.Feature+"\"+$this.TestCase.ModuleName+"\TestData\"+$this.TestCase.ParamFileName
			if(!([string]::IsNullOrEmpty($paramFile))){
					$jsonFile =  Get-Content -Path $paramFile | ConvertFrom-Json
					$jsonFile.parameters.administratorLoginPassword.keyVault.id = $this.settings.CommonKeyVaultUrl
					$jsonFile |ConvertTo-Json | Set-Content $paramFile
			}
		}
		catch{
			[CommonHelper]::Log("Failed to set Key vault url in parameters file!", [MessageType]::Error)
		}
	}

}



