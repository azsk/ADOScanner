Set-StrictMode -Version Latest 
class KeyVaultResource:SVTControlTestResource{
	KeyVaultResource([TestCase] $testcase, [TestSettings] $testsettings, [TestContext] $testContext):Base($testcase, $testsettings, $testContext){
     
    }

	#Setting the properties as required by this resource type.
	[void]SetDerivedResourceProps(){
		$this.SetParametersInTemplateFile()
		#Pick the resource name from Params file if its not null
		if(![string]::IsNullOrEmpty($this.Params)){
				$this.ResourceName = $this.GetResourceNameFromARMJson($this.Params, "ResourceName", "value")
			}
		else{
			$this.ResourceName = "azsktestkeyvault" #Else set the default resource name
		}
		$this.ResourceType = "Microsoft.KeyVault/vaults" 
	}

	[void]RemoveKeyVault()
	{
		try{
			 Remove-AzResource -ResourceName  $this.ResourceName -ResourceGroupName $this.ResourceGroupName -ResourceType $this.ResourceType -Force
		}
		catch{
				[CommonHelper]::Log("Error while Removing KeyVault " + $this.ResourceName, [MessageType]::Error)
		}
	}

	[void]SetKVDiagnosticsOn()
		{
		try{
			
		$linkedResourceName = "azskstorageforkeyvault" 
		$linkedResourceType = "Microsoft.Storage/storageAccounts" 
		$linkedResourceExists=$this.IfLinkedResourceExists($linkedResourceName,$linkedResourceType)
		if(!$linkedResourceExists){
				$this.CreateLinkedResource($linkedResourceName)
		}

			  $resourceId =  (Get-AzResource -ResourceName  $this.ResourceName -ResourceGroupName $this.ResourceGroupName).ResourceId
			  $diagnosticStorageAccountId = (Get-AzResource -ResourceName $linkedResourceName -ResourceGroupName $this.ResourceGroupName).ResourceId

			 Set-AzDiagnosticSetting   -ResourceId $resourceId `
											-Enable $true `
											-StorageAccountId $diagnosticStorageAccountId `
											-RetentionInDays 365 `
											-RetentionEnabled $true `
											-ErrorAction Stop 
			}
		catch{
				[CommonHelper]::Log("Error while setting Diagnostics setting On" + $this.ResourceName, [MessageType]::Error)
		}
	}

	[void]SetKVDiagnosticsOff()
		{
		try{
			
		$linkedResourceName = "azskstorageforkeyvault" 
		$linkedResourceType = "Microsoft.Storage/storageAccounts" 
		$linkedResourceExists=$this.IfLinkedResourceExists($linkedResourceName,$linkedResourceType)
		if(!$linkedResourceExists){
				$this.CreateLinkedResource($linkedResourceName)
		} 
			 $resourceId =  (Get-AzResource -ResourceName  $this.ResourceName -ResourceGroupName $this.ResourceGroupName).ResourceId
			  $diagnosticStorageAccountId = (Get-AzResource -ResourceName $linkedResourceName -ResourceGroupName $this.ResourceGroupName).ResourceId

			 Set-AzDiagnosticSetting   -ResourceId $resourceId `
											-Enable $False `
											-StorageAccountId $diagnosticStorageAccountId `
											-RetentionInDays 10 `
											-RetentionEnabled $False `
											-ErrorAction Stop 
			}
		catch{
				[CommonHelper]::Log("Error while setting Diagnostics setting On" + $this.ResourceName, [MessageType]::Error)
		}
	}



	[void]SetAllAdvanceAcessPolicies()
		{
		try{
			 Set-AzKeyVaultAccessPolicy -VaultName $this.ResourceName -ResourceGroupName $this.ResourceGroupName  -EnabledForDeployment -EnabledForTemplateDeployment -EnabledForDiskEncryption
		}
		catch{
				[CommonHelper]::Log("Error while setting Advance Access Policies"+ $this.ResourceName, [MessageType]::Error)
		}
	}

	[void]ResetAllAdvanceAcessPolicies()
		{
		try{
			 Remove-AzKeyVaultAccessPolicy -VaultName $this.ResourceName -ResourceGroupName $this.ResourceGroupName  -EnabledForDeployment -EnabledForTemplateDeployment -EnabledForDiskEncryption 
		}
		catch{
				[CommonHelper]::Log("Error while re-setting Advance Access Policies"+ $this.ResourceName, [MessageType]::Error)
		}
	}

	[void]GetReadAcessOnKey(){
		try{
					$adUserDtls = (Get-AzADUser -UserPrincipalName (Get-AzContext).Account.Id)
					$ObjId = $adUserDtls.Id.Guid 
            
					Set-AzKeyVaultAccessPolicy -VaultName $this.ResourceName -ResourceGroupName $this.ResourceGroupName   -PermissionsToKeys all -PermissionsToSecrets all -ObjectId $ObjId
			}
			catch{
					[CommonHelper]::Log("Error while setting Access Policies:"+ $this.ResourceName, [MessageType]::Error)
			}
	}

	[void]SetAllAcessPolicies()
		{
		try{
			$adUserDtls = (Get-AzADUser -UserPrincipalName (Get-AzContext).Account.Id)
            $ObjId = $adUserDtls.Id.Guid 
            
			Set-AzKeyVaultAccessPolicy -VaultName $this.ResourceName -ResourceGroupName $this.ResourceGroupName  -PermissionsToKeys all -PermissionsToSecrets all  -PermissionsToCertificates all `
                                -ObjectId $ObjId
		}
		catch{
				[CommonHelper]::Log("Error while setting Access Policies:"+ $this.ResourceName, [MessageType]::Error)
		}
	}

	[void]ResetAllAcessPolicies()
		{
		try{
			 $adUserDtls = (Get-AzADUser -UserPrincipalName (Get-AzContext).Account.Id)
            $ObjId = $adUserDtls.Id.Guid 
            
			Set-AzKeyVaultAccessPolicy -VaultName $this.ResourceName -ResourceGroupName $this.ResourceGroupName   -PermissionsToKeys list -PermissionsToSecrets list  -PermissionsToCertificates get `
                                -ObjectId $ObjId
		}
		catch{
				[CommonHelper]::Log("Error while re-setting Access Policies"+ $this.ResourceName, [MessageType]::Error)
		}
	}
	[void]AddNonHSMKeyWithExpiryDate()
		{
		try{ 
            Add-AzureKeyVaultKey -VaultName  $this.ResourceName -Name "AzSKTestKey01" -Expires (get-date).AddDays(90) -Destination Software 
		}
		catch{
				[CommonHelper]::Log("Error while adding Non-HSM key with expiry date:"+ $this.ResourceName, [MessageType]::Error)
		}
	}
	
	[void] SetParametersInTemplateFile(){
		try{
			$Subscription=Get-AzSubscription -SubscriptionId $this.testContext.TestResources.SubscriptionId | Select-Object -Property TenantId
			$adUserDtls = (Get-AzADUser -UserPrincipalName (Get-AzContext).Account.Id)
            $ObjId = $adUserDtls.Id.Guid 
			
			$paramFile = [CommonHelper]::GetRootPath() + "\TestCases\"+$this.TestCase.Feature+"\"+$this.TestCase.ModuleName+"\TestData\"+$this.TestCase.ParamFileName
			
			if(!([string]::IsNullOrEmpty($paramFile)))
			{
		
			[CommonHelper]::SetValueIntoJson($paramFile, "objectId", "value", $ObjId)
			[CommonHelper]::SetValueIntoJson($paramFile, "tenantId", "value",  $Subscription.TenantId)
			}
		}
		catch{
			[CommonHelper]::Log("Failed to set parameters in template file!", [MessageType]::Error)
		}
	}
}
