Set-StrictMode -Version Latest 
class ConfigurationHelper
{
		#Set AzSKSettings.json parameters to enable AzSK testing in non-interactive mode
		static [void] SetAzSKSettingsJsonParameter([string] $AzSKModule, [PSObject] $MandatoryTestSettings, [string] $OrgPolicy)
		{
			$Environment = @($AzSKModule)
			if(![string]::IsNullOrEmpty($AzSKModule) -and ($AzSKModule -ne "AzSK"))
			{
				$Environment += "AzSK"
			}
			$Environment | ForEach-Object {
				Write-Host "Updating $($_) AzSKSettings.Json File.."
				$AzSKSettingsPath = ($Env:LOCALAPPDATA+"\Microsoft\"+$($_)+"\AzSKSettings.json")
				Copy-Item -Path $AzSKSettingsPath -Destination $($AzSKSettingsPath+".txt")
				$AzSKSetting = Get-Content -Path $AzSKSettingsPath | ConvertFrom-Json
				if(($AzSKSetting | Measure-Object).Count -gt 0)
				{
					if($_ -ne "AzSK")
					{
						if(![string]::IsNullOrEmpty($MandatoryTestSettings.LAWSId) -and ![string]::IsNullOrEmpty($MandatoryTestSettings.LAWSSharedKey))
						{
							$AzSKSetting.LAWSId = $MandatoryTestSettings.LAWSId
							$AzSKSetting.LAWSSharedKey = $MandatoryTestSettings.LAWSSharedKey
						}
						# TODO: Remove this comment after test drive
						$AzSKSetting.LASource = "CA"
					}
					else
					{
						if(![string]::IsNullOrEmpty($MandatoryTestSettings.LAWSId) -and ![string]::IsNullOrEmpty($MandatoryTestSettings.LAWSSharedKey))
						{
							$AzSKSetting.LAWSId = $MandatoryTestSettings.LAWSId
							$AzSKSetting.LAWSSharedKey = $MandatoryTestSettings.LAWSSharedKey
						}
						# TODO: Remove this comment after test drive
						$AzSKSetting.LASource = "CA"
					}
					
					$AzSKSetting.PrivacyNoticeAccepted = $true
					$AzSKSetting.UsageTelemetryLevel = "Anonymous"
					#Switch to OSS policy
					if($OrgPolicy -eq 'OSS')
					{
					   $AzSKSetting.OnlinePolicyStoreUrl = switch($_)
														   {
															 'AzSKStaging' { [Constants]::OnlineStoreURL.'org-neutral_AzSKStaging'; }
															 'AzSKPreview' { [Constants]::OnlineStoreURL.'org-neutral_AzSKPreview';}
															 'AzSK'    { [Constants]::OnlineStoreURL.'org-neutral_AzSK';}
														   }
					   $AzSKSetting.EnableAADAuthForOnlinePolicyStore = $false
					}
					elseif ($OrgPolicy -eq 'CSE')
					{
						$AzSKSetting.OnlinePolicyStoreUrl = switch($_)
														   {
															 'AzSKStaging' { [Constants]::OnlineStoreURL.'cse_AzSKStaging'; }
															 'AzSKPreview' { [Constants]::OnlineStoreURL.'cse_AzSKPreview';}
															 'AzSK'    { [Constants]::OnlineStoreURL.'cse_AzSK';}
														   }
					   $AzSKSetting.EnableAADAuthForOnlinePolicyStore = $true
					}
				}
				else
				{
					Write-Host "[Warning] $($_) AzSKSettings.Json file not found. If using build pipeline, please check if IWR command ran without error " -ForegroundColor Cyan
				}
				$AzSKSetting | ConvertTo-Json | Set-Content -Path $AzSKSettingsPath
				Get-Content -Path $AzSKSettingsPath | Out-Host
			}
		}
	    #Reset AzSKSettings.json to original file
		static [void] ResetAzSKSettingsJsonParameter([string] $AzSKModule)
		{
			$Environment = @($AzSKModule)
			if(![string]::IsNullOrEmpty($AzSKModule) -and ($AzSKModule -ne "AzSK"))
			{
				$Environment += "AzSK"
			}
			$Environment | ForEach-Object {
				$AzSKSettingsPath = ($Env:LOCALAPPDATA+"\Microsoft\"+$_+"\AzSKSettings.json")
				if((Test-Path -Path $AzSKSettingsPath) -and (Test-Path -Path $($AzSKSettingsPath+".txt")))
				{
					Write-Host "Rolling back changes done by test suite in $($_) AzSKSettings.Json file."
					Copy-Item -Path $($AzSKSettingsPath+".txt") -Destination $AzSKSettingsPath
					Remove-Item -Path $($AzSKSettingsPath+".txt")
				}
			}
		}
}
