Set-StrictMode -Version Latest 
class TestSettings {

	# TODO: Move these settings to ModuleContext
	[string] $CommonStorageAcctName = [string]::Empty
	[string] $CommonStorageAcctId = [string]::Empty
	[string] $StorageAlertName = [string]::Empty
	[string] $StorageAlertId = [string]::Empty
	[string] $CommonKeyVaultUrl = [string]::Empty
	[string] $SecurityPOCEmail = [string]::Empty
	[string] $SecurityPhoneNo = [string]::Empty
	[string[]] $EmailAccounts = @()
	[string] $AlertName = [string]::Empty
	[string] $CAAutomationAccountName = [string]::Empty
	[string] $CAStorageContainerName = [string]::Empty
	[string] $CAConnectionName = [string]::Empty
	[string] $Org = [string]::Empty
	[string] $AzSKModule = [string]::Empty
	[string] $AzSKModulePath = [string]::Empty
	[PSObject] $ADOSettings = @{}
	
	<#
	[string] $SubscriptionId = [string]::Empty
	[string] $RGForTestHarness = [string]::Empty
	[string] $LAWSId = [string]::Empty
	[string] $LAWSSharedKey = [string]::Empty
	[string] $LAResourceGroup = [string]::Empty
	[string] $LAViewName = [string]::Empty
	[string] $AzSKResourceGroupName = [string]::Empty
	[string] $OrgPolicyURL = [string]::Empty
	[string] $AzSKAppFolderPath = [string]::Empty
	[string] $AzSKModule = [string]::Empty
	[string] $AzSKModulePath = [string]::Empty
	#>
	
	TestSettings([string] $Org, [string] $AzSKModule, [string] $AzSKModulePath)
	{
		$this.Org = $Org
		$this.AzSKModule = $AzSKModule
		$this.AzSKModulePath = $AzSKModulePath
		[string] $path = [CommonHelper]::GetRootPath() +"\TestSettings.json"
		$testSettings = Get-Content -Path $path | ConvertFrom-Json
		$this.ADOSettings = $testSettings.ADOSettings
	}

	TestSettings()
	{}
	<#
	#Gets the default test settings from local 'TestSettings.json' file.
	TestSettings([string] $subId, [string] $AzSKModule, [string] $AzSKModulePath)#:Base([string] $subId)
	{
		[string] $path = [CommonHelper]::GetRootPath() +"\TestSettings.json"
		$this.SubscriptionId = $subId
		$this.AzSKModule = $AzSKModule
		$this.AzSKModulePath = $AzSKModulePath
		try{
			$testSettings = Get-Content -Path $path | ConvertFrom-Json
			if($null -ne $testSettings){
				$this.ResourceGroupName = $testSettings.ResourceGroupName
				$this.CommonStorageAcctName = $testSettings.CommonStorageAcctName
				$this.CommonStorageAcctId = "/subscriptions/" +$this.SubscriptionId + "/resourceGroups/" + $this.ResourceGroupName + "/providers/Microsoft.Storage/storageAccounts/" + $this.CommonStorageAcctName
				$this.StorageAlertName = $testSettings.StorageAlertName
				$this.StorageAlertId = "/subscriptions/" +$this.SubscriptionId + "/resourceGroups/" + $this.ResourceGroupName + "/providers/microsoft.insights/alertrules/" + $this.StorageAlertName
				if($testSettings.EmailAccounts.Contains(",")){
				 $this.EmailAccounts = $testSettings.EmailAccounts.Split(",").Trim()
				}
				else{
					$this.EmailAccounts = $testSettings.EmailAccounts
				}
				$this.CommonKeyVaultUrl = "/subscriptions/" +$this.SubscriptionId + "/resourceGroups/" + $this.ResourceGroupName + "/providers/Microsoft.KeyVault/vaults/" + $testSettings.CommonKeyVaultName
				$this.SecurityPOCEmail = $testSettings.SecurityPOCEmail
				$this.AlertName = $testSettings.AlertName
				$this.LAWSId = $testSettings.LAWSId
				$this.LAWSSharedKey = $testSettings.LAWSSharedKey
				$this.LAResourceGroup = $testSettings.LAResourceGroup
				$this.LAViewName = $testSettings.LAViewName
				$this.SecurityPhoneNo = $testSettings.SecurityPhoneNo
				$this.CAAutomationAccountName = $testSettings.CAAutomationAccountName
				$this.CAStorageContainerName = $testSettings.CAStorageContainerName
				$this.AzSKResourceGroupName = $testSettings.AzSKResourceGroupName
				$this.CAConnectionName = $testSettings.CAConnectionName
				$this.OrgPolicyURL = $testSettings.OrgPolicyURL
				$this.AzSKAppFolderPath = $testSettings.AzSKAppFolderPath				
			}
		}
		catch{
			[CommonHelper]::Log("Error while fetching the Test Settings", [MessageType]::Error)
			[CommonHelper]::Log($_, [MessageType]::Error)
		}
	}

	#Gets user defined 'TestSettings.json' file.
	TestSettings([string]$subId, [string] $AzSKModule, [string]$AzSKModulePath, [PSObject] $settings)#:Base([string] $subId)
	{
		#[string] $path = [CommonHelper]::GetRootPath() +"\TestSettings.json"
		$this.SubscriptionId = $subId
		$this.AzSKModule = $AzSKModule
		$this.AzSKModulePath = $AzSKModulePath
		try{
			#$testSettings = Get-Content -Path $path | ConvertFrom-Json
			$testSettings=$settings
			if($null -ne $testSettings){
				$this.ResourceGroupName = $testSettings.ResourceGroupName
				$this.CommonStorageAcctName = $testSettings.CommonStorageAcctName
				$this.CommonStorageAcctId = "/subscriptions/" +$this.SubscriptionId + "/resourceGroups/" + $this.ResourceGroupName + "/providers/Microsoft.Storage/storageAccounts/" + $this.CommonStorageAcctName
				$this.StorageAlertName = $testSettings.StorageAlertName
				$this.StorageAlertId = "/subscriptions/" +$this.SubscriptionId + "/resourceGroups/" + $this.ResourceGroupName + "/providers/microsoft.insights/alertrules/" + $this.StorageAlertName
				if($testSettings.EmailAccounts.Contains(",")){
				 $this.EmailAccounts = $testSettings.EmailAccounts.Split(",").Trim()
				}
				else{
					$this.EmailAccounts = $testSettings.EmailAccounts
				}
				$this.CommonKeyVaultUrl = "/subscriptions/" +$this.SubscriptionId + "/resourceGroups/" + $this.ResourceGroupName + "/providers/Microsoft.KeyVault/vaults/" + $testSettings.CommonKeyVaultName
				$this.SecurityPOCEmail = $testSettings.SecurityPOCEmail
				$this.AlertName = $testSettings.AlertName
				$this.LAWSId = $testSettings.LAWSId
				$this.LAWSSharedKey = $testSettings.LAWSSharedKey
				$this.LAResourceGroup = $testSettings.LAResourceGroup
				$this.LAViewName = $testSettings.LAViewName
				$this.SecurityPhoneNo = $testSettings.SecurityPhoneNo
				$this.CAAutomationAccountName = $testSettings.CAAutomationAccountName
				$this.CAStorageContainerName = $testSettings.CAStorageContainerName
				$this.AzSKResourceGroupName = $testSettings.AzSKResourceGroupName
				$this.CAConnectionName = $testSettings.CAConnectionName
				$this.OrgPolicyURL = $testSettings.OrgPolicyURL
				$this.AzSKAppFolderPath = $testSettings.AzSKAppFolderPath
			}
		}
		catch{
			[CommonHelper]::Log("Error while fetching the Test Settings", [MessageType]::Error)
			[CommonHelper]::Log($_, [MessageType]::Error)
		}
	}

	[void] SetManadatoryTestSettings([PSObject] $MandatoryTestSettings)
	{
		 $this.LAWSId =   $MandatoryTestSettings.LAWSId
		 $this.LAWSSharedKey =     $MandatoryTestSettings.LAWSSharedKey
		 $this.LAResourceGroup = $MandatoryTestSettings.LAResourceGroup
		 $this.SecurityPhoneNo =  $MandatoryTestSettings.SecurityPhoneNo
		 $this.SecurityPOCEmail = $MandatoryTestSettings.SecurityPOCEmail
	}
	#>
}
