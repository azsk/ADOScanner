Set-StrictMode -Version Latest 
Class LogAnalyticsHelper{
	static [string] $DefaultLAType = "AzSK"
	hidden static [int] $IsLAWSSettingValid = 0  #-1:Fail (Log Analytics workspace Empty, Log Analytics workspace Return Error) | 1:CA | 0:Local
	hidden static [int] $IsAltLAWSSettingValid = 0
	# Create the function to create and post the request
	static PostLAWSData([string] $workspaceId, [string] $sharedKey, $body, $logType, $laType)
	{
		try
		{
			if(($laType | Measure-Object).Count -gt 0 -and [LogAnalyticsHelper]::$("is"+$laType+"SettingValid") -ne -1)
			{
				if([string]::IsNullOrWhiteSpace($logType))
				{
					$logType = [LogAnalyticsHelper]::DefaultLAType
				}
				[string] $method = "POST"
				[string] $contentType = "application/json"
				[string] $resource = "/api/logs"
				$rfc1123date = [System.DateTime]::UtcNow.ToString("r")
				[int] $contentLength = $body.Length
				[string] $signature = [LogAnalyticsHelper]::GetLAWSSignature($workspaceId , $sharedKey , $rfc1123date ,$contentLength ,$method ,$contentType ,$resource)
				$LADataCollectorAPI = [WebRequestHelper]::GetLADataCollectorAPI()	
				[string] $uri = "https://" + $workspaceId + $LADataCollectorAPI + $resource + "?api-version=2016-04-01"
				[DateTime] $TimeStampField = [System.DateTime]::UtcNow
				$headers = @{
					"Authorization" = $signature;
					"Log-Type" = $logType;
					"x-ms-date" = $rfc1123date;
					"time-generated-field" = $TimeStampField;
				}
				$response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
			}
		}
		catch
		{
			$warningMsg=""
			if($laType -eq 'LAWS')
			{
				switch([LogAnalyticsHelper]::$("is"+$laType+"SettingValid"))
				{
					0 { $warningMsg += "The Log Analytics workspace ID or key is invalid in the local settings file. Use Set-AzSKADOMonitoringSettings to update either/both with corrected values.";}
					1 { $warningMsg += "The Log Analytics workspace ID or key is invalid in the ContinuousAssurance configuration. Use Update-AzSKADOContinuousAssurance to update either/both with corrected values."; }
				}
				
				[EventBase]::PublishGenericCustomMessage(" `r`nWARNING: $($warningMsg)", [MessageType]::Warning);
				
				#Flag to disable Log Analytics scan 
				[LogAnalyticsHelper]::$("is"+$laType+"SettingValid") = -1
			}
			elseif($laType -eq 'AltLAWS')
			{
				switch([LogAnalyticsHelper]::$("is"+$laType+"SettingValid"))
				{
					0 { $warningMsg += "The alternate Log Analytics workspace ID or key is invalid in the local settings file. Use Set-AzSKADOMonitoringSettings to update either/both with corrected values.";}
					1 { $warningMsg += "The alternate Log Analytics workspace ID or key is invalid in the ContinuousAssurance configuration. Use Update-AzSKADOContinuousAssurance to update either/both with corrected values."; }
				}
				
				[EventBase]::PublishGenericCustomMessage(" `r`nWARNING: $($warningMsg)", [MessageType]::Warning);
				
				#Flag to disable Log Analytics scan 
				[LogAnalyticsHelper]::$("is"+$laType+"SettingValid") = -1
			}
		}
	}

	static [string] GetLAWSSignature ($workspaceId, $sharedKey, $Date, $ContentLength, $Method, $ContentType, $Resource)
	{
			[string] $xHeaders = "x-ms-date:" + $Date
			[string] $stringToHash = $Method + "`n" + $ContentLength + "`n" + $ContentType + "`n" + $xHeaders + "`n" + $Resource
        
			[byte[]]$bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
			
			[byte[]]$keyBytes = [Convert]::FromBase64String($sharedKey)

			[System.Security.Cryptography.HMACSHA256] $sha256 = New-Object System.Security.Cryptography.HMACSHA256
			$sha256.Key = $keyBytes
			[byte[]]$calculatedHash = $sha256.ComputeHash($bytesToHash)
			$encodedHash = [Convert]::ToBase64String($calculatedHash)
			$authorization = 'SharedKey {0}:{1}' -f $workspaceId,$encodedHash
			return $authorization   
	}

	static [PSObject[]] GetLAWSBodyObjects([SVTEventContext] $eventContext,[AzSKContextDetails] $AzSKContext)
	{
		[PSObject[]] $output = @();

		[array] $eventContext.ControlResults | ForEach-Object{
			Set-Variable -Name ControlResult -Value $_ -Scope Local
			$out = [LAWSModel]::new() 
			if($eventContext.IsResource())
			{
				$out.ResourceType=$eventContext.ResourceContext.ResourceType
				$out.ResourceGroup=$eventContext.ResourceContext.ResourceGroupName			
				$out.ResourceName=$eventContext.ResourceContext.ResourceName
				$out.ResourceId = $eventContext.ResourceContext.ResourceId
				$out.ChildResourceName=$ControlResult.ChildResourceName
				$out.PartialScanIdentifier=$eventContext.PartialScanIdentifier
			}

			$out.Env = $this.GetModuleName();
			$out.Reference=$eventContext.Metadata.Reference
			$out.ControlStatus=$ControlResult.VerificationResult.ToString()
			$out.ActualVerificationResult=$ControlResult.ActualVerificationResult.ToString()
			$out.ControlId=$eventContext.ControlItem.ControlID
			$out.OrganizationName=$eventContext.OrganizationContext.OrganizationName
			$out.OrganizationId=$eventContext.OrganizationContext.OrganizationId
			$out.FeatureName=$eventContext.FeatureName
			$out.Recommendation=$eventContext.ControlItem.Recommendation
			$out.ControlSeverity=$eventContext.ControlItem.ControlSeverity.ToString()
			$out.Source=$AzSKContext.Source
			$out.Tags=$eventContext.ControlItem.Tags
			$out.RunIdentifier = $AzSKContext.RunIdentifier
			$out.HasRequiredAccess = $ControlResult.CurrentSessionContext.Permissions.HasRequiredAccess 
			$out.ScannerVersion = $AzSKContext.Version
			$out.IsBaselineControl = $eventContext.ControlItem.IsBaselineControl
			#addPreviewBaselineControl Flag
			$out.IsPreviewBaselineControl = $eventContext.ControlItem.IsPreviewBaselineControl
			$out.HasAttestationWritePermissions = $ControlResult.CurrentSessionContext.Permissions.HasAttestationWritePermissions
			$out.HasAttestationReadPermissions = $ControlResult.CurrentSessionContext.Permissions.HasAttestationReadPermissions				
			$out.IsLatestPSModule = $ControlResult.CurrentSessionContext.IsLatestPSModule
			$out.PolicyOrgName = $AzSKContext.PolicyOrgName
			$out.IsControlInGrace = $ControlResult.IsControlInGrace
			$out.ScannedBy=[ContextHelper]::GetCurrentSessionUser()
			$out.IsResourceActive = $ControlResult.IsResourceActive
			$out.InactiveFromDays = $ControlResult.InactiveFromDays
			#mapping the attestation properties
			if($null -ne $ControlResult -and $null -ne $ControlResult.StateManagement -and $null -ne $ControlResult.StateManagement.AttestedStateData)
			{
				$attestedData = $ControlResult.StateManagement.AttestedStateData;
				$out.AttestationStatus = $ControlResult.AttestationStatus.ToString();
				$out.AttestedBy = $attestedData.AttestedBy;
				$out.Justification = $attestedData.Justification;
				$out.AttestedDate = $attestedData.AttestedDate
				$out.ExpiryDate = $attestedData.ExpiryDate
			}
			if ($ControlResult.AdditionalInfo)
			{
                $out.AdditionalInfo = $ControlResult.AdditionalInfo;
            }
			if ($ControlResult.Exception)
			{
                $out.Exception += $ControlResult.Exception;
            }
			$output += $out
		}
		return $output	
	}

	static [void] PostApplicableControlSet([SVTEventContext[]] $contexts,[AzSKContextDetails] $AzSKContext) {
        if (($contexts | Measure-Object).Count -lt 1) { return; }
        $set = [LogAnalyticsHelper]::ConvertToSimpleSet($contexts,$AzSKContext);
        [LogAnalyticsHelper]::WriteControlResult($set,"AzSK_Inventory")		
    }

	static [void] WriteControlResult([PSObject[]] $lawsDataObject, [string] $laEventType)
	{
		try
		{
			$settings = [ConfigurationManager]::GetAzSKSettings()
			if([string]::IsNullOrWhiteSpace($laEventType))
			{
				$laEventType = $settings.LAType
			}

			if((-not [string]::IsNullOrWhiteSpace($settings.LAWSId)) -or (-not [string]::IsNullOrWhiteSpace($settings.AltLAWSId)))
			{
				$lawsDataObject | ForEach-Object{
					Set-Variable -Name tempBody -Value $_ -Scope Local
					$body = $tempBody | ConvertTo-Json
					$lawsBodyByteArray = ([System.Text.Encoding]::UTF8.GetBytes($body))
					#publish to primary workspace
					if(-not [string]::IsNullOrWhiteSpace($settings.LAWSId) -and [LogAnalyticsHelper]::IsLAWSSettingValid -ne -1)
					{
						[LogAnalyticsHelper]::PostLAWSData($settings.LAWSId, $settings.LAWSSharedKey, $lawsBodyByteArray, $laEventType, 'LAWS')
					}
					#publish to secondary workspace
					if(-not [string]::IsNullOrWhiteSpace($settings.AltLAWSId) -and [LogAnalyticsHelper]::IsAltLAWSSettingValid -ne -1)
					{
						[LogAnalyticsHelper]::PostLAWSData($settings.AltLAWSId, $settings.AltLAWSSharedKey, $lawsBodyByteArray, $laEventType, 'AltLAWS')
					}				
				}            
			}
		}
		catch
		{			
			throw ([SuppressedException]::new("Error sending events to Log Analytics. The following exception occurred: `r`n$($_.Exception.Message) `r`nFor more on AzSK Log Analytics workspace setup, refer: https://aka.ms/devopskit/ca"));
		}
	}

	static [PSObject[]] ConvertToSimpleSet($contexts,[AzSKContextDetails] $AzSKContext)
	{
        $ControlSet = [System.Collections.ArrayList]::new()
        foreach ($item in $contexts) {
			$set = [LAWSResourceInvModel]::new()
			$set.RunIdentifier = $AzSKContext.RunIdentifier
			$set.OrganizationId = $item.OrganizationContext.OrganizationId
			$set.OrganizationName = $item.OrganizationContext.OrganizationName
			$set.Source = $AzSKContext.Source
			$set.ScannerVersion = $AzSKContext.Version
			$set.FeatureName = $item.FeatureName
			if([Helpers]::CheckMember($item,"ResourceContext"))
			{
				$set.ResourceGroupName = $item.ResourceContext.ResourceGroupName
				$set.ResourceName = $item.ResourceContext.ResourceName
				$set.ResourceId = $item.ResourceContext.ResourceId
            }
			$set.ControlIntId = $item.ControlItem.Id
            $set.ControlId = $item.ControlItem.ControlID
            $set.ControlSeverity = $item.ControlItem.ControlSeverity
			$set.Tags = $item.ControlItem.Tags
			$set.IsBaselineControl = $item.ControlItem.IsBaselineControl
			#add PreviewBaselineFlag
			$set.IsPreviewBaselineControl = $item.ControlItem.IsPreviewBaselineControl
			 $ControlSet.Add($set) 
        }
        return $ControlSet;
	}
	
	static [void] SetLAWSDetails()
	{
		#Check if Settings already contain details of Log Analytics workspace
		$settings = [ConfigurationManager]::GetAzSKSettings()
		#Can we add one flag in 'AzSKSettings' or 'ControlSettings.json' to control this 
		#Step 1: if Log Analytics workspace details are not present on machine
		if([string]::IsNullOrWhiteSpace($settings.LAWSId) -or [string]::IsNullOrWhiteSpace($settings.AltLAWSId))
		{
			$rgName = [ConfigurationManager]::GetAzSKConfigData().AzSKRGName
			#Step 2: Validate if CA is enabled on subscription
			$automationAccDetails = $null
			#$automationAccDetails= Get-AzAutomationAccount -ResourceGroupName $rgName -ErrorAction SilentlyContinue 
			if($automationAccDetails)
			{
				if([string]::IsNullOrWhiteSpace($settings.LAWSId))
				{
					#Step 3: Get workspace id from automation account variables
					#Try getting the values from the LAWS variables, if they don't exist, read value from OMS variables
					$laWSId = Get-AzAutomationVariable -ResourceGroupName $automationAccDetails.ResourceGroupName -AutomationAccountName $automationAccDetails.AutomationAccountName -Name "LAWSId" -ErrorAction SilentlyContinue
					if(($laWSId | Measure-Object).Count -eq 0)
					{
						$laWSId = Get-AzAutomationVariable -ResourceGroupName $automationAccDetails.ResourceGroupName -AutomationAccountName $automationAccDetails.AutomationAccountName -Name "OMSWorkspaceId" -ErrorAction SilentlyContinue
					}
					
					#Step 4: set workspace id and shared key in setting file
					if($laWSId)
					{
						$laWSSharedKey = Get-AzAutomationVariable -ResourceGroupName $automationAccDetails.ResourceGroupName -AutomationAccountName $automationAccDetails.AutomationAccountName -Name "LAWSSharedKey" -ErrorAction SilentlyContinue	
						if(($laWSSharedKey | Measure-Object).Count -eq 0)
						{
							$laWSSharedKey = Get-AzAutomationVariable -ResourceGroupName $automationAccDetails.ResourceGroupName -AutomationAccountName $automationAccDetails.AutomationAccountName -Name "OMSSharedKey"
						}

						if([Helpers]::CheckMember($laWSSharedKey,"Value") -and (-not [string]::IsNullOrWhiteSpace($laWSSharedKey.Value)))
						{
							#Step 6: Assign it to AzSKSettings Object
							$settings.LAWSId = $laWSId.Value
							$settings.LAWSSharedKey = $laWSSharedKey.Value
							[LogAnalyticsHelper]::IsLAWSSettingValid = 1
						}					

					}
				}

				if([string]::IsNullOrWhiteSpace($settings.LAWSId) -or [string]::IsNullOrWhiteSpace($settings.LAWSSharedKey))
				{
					[LogAnalyticsHelper]::IsLAWSSettingValid = -1
				}


				if([string]::IsNullOrWhiteSpace($settings.AltLAWSId))
				{
					#Step 3: Get alternate workspace id from automation account variables
					#Try getting the values from the LAWS variables, if they don't exist, read value from OMS variables
					$altLAWSId = Get-AzAutomationVariable -ResourceGroupName $automationAccDetails.ResourceGroupName -AutomationAccountName $automationAccDetails.AutomationAccountName -Name "AltLAWSId" -ErrorAction SilentlyContinue
					if(($altLAWSId | Measure-Object).Count -eq 0)
					{
						$altLAWSId = Get-AzAutomationVariable -ResourceGroupName $automationAccDetails.ResourceGroupName -AutomationAccountName $automationAccDetails.AutomationAccountName -Name "AltOMSWorkspaceId" -ErrorAction SilentlyContinue
					}

					#Step 4: set alternate workspace id and shared key in setting file
					if($altLAWSId)
					{
						$altLAWSSharedKey = Get-AzAutomationVariable -ResourceGroupName $automationAccDetails.ResourceGroupName -AutomationAccountName $automationAccDetails.AutomationAccountName -Name "AltLAWSSharedKey" -ErrorAction SilentlyContinue
						if(($altLAWSSharedKey | Measure-Object).Count -eq 0)
						{
							$altLAWSSharedKey = Get-AzAutomationVariable -ResourceGroupName $automationAccDetails.ResourceGroupName -AutomationAccountName $automationAccDetails.AutomationAccountName -Name "AltOMSSharedKey"
						}
						if([Helpers]::CheckMember($altLAWSSharedKey,"Value") -and (-not [string]::IsNullOrWhiteSpace($altLAWSSharedKey.Value)))
						{
							#Step 6: Assign it to AzSKSettings Object
							$settings.AltLAWSId = $altLAWSId.Value
							$settings.AltLAWSSharedKey = $altLAWSSharedKey.Value
							[LogAnalyticsHelper]::IsAltLAWSSettingValid = 1
						}
					}
				}
				
				if([string]::IsNullOrWhiteSpace($settings.AltLAWSId) -or [string]::IsNullOrWhiteSpace($settings.AltLAWSSharedKey))
				{
					[LogAnalyticsHelper]::IsAltLAWSSettingValid = -1
				}				
			}
		}		
	}

	static PostResourceInventory([AzSKContextDetails] $AzSKContext)
	{
		if($AzSKContext.Source.Equals("CA", [System.StringComparison]::OrdinalIgnoreCase)){
			$resourceSet = [System.Collections.ArrayList]::new()
			[ResourceInventory]::FetchResources();
			foreach($resource in [ResourceInventory]::FilteredResources){
				$set = [LAWSResourceModel]::new()
				$set.RunIdentifier = $AzSKContext.RunIdentifier
				$set.OrganizationId = $resource.OrganizationId
				#$set.OrganizationName = $item.OrganizationContext.OrganizationName
				$set.Source = $AzSKContext.Source
				$set.ScannerVersion = $AzSKContext.Version
				$set.ResourceType = $resource.ResourceType				
				$set.ResourceGroupName = $resource.ResourceGroupName
				$set.ResourceName = $resource.Name
				$set.ResourceId = $resource.ResourceId

			$resourceSet.Add($set) 
		}
			[LogAnalyticsHelper]::WriteControlResult($resourceSet,"AzSK_Inventory")
			$laMetadata = [ConfigurationManager]::LoadServerConfigFile("LogAnalyticsSettings.json")
			[LogAnalyticsHelper]::WriteControlResult($laMetadata,"AzSK_MetaData")
		}			
	}

	hidden static [PSObject] QueryStatusfromWorkspace([string] $workspaceId,[string] $query)
	{
		$result=$null;
		try
		{
			$body = @{query=$query};
			$url="https://api.loganalytics.io/v1/workspaces/" +$workspaceId+"/query"
			$response=[WebRequestHelper]::InvokePostWebRequest($url ,  $body);

			# Formating the response obtained from querying workspace.
			if(($response | Measure-Object).Count -gt 0)
			{
				$data = $response;				
				#Out of four tables obtained, the first table contains result of query
				if(($data | Measure-Object).Count -gt 0)
				{
					$table= $data.Tables[0];
					$Columns=$table.Columns;
					$objectView = @{};		
					$j = 0;
					if($null -ne $table)
					{
						foreach ($valuetable in $table) {
							foreach ($row in $table.Rows) {
								#If timestamp/first column value is null means row is empty
								if($row[0])
								{
									$i = 0;
									$count=$valuetable.Columns.Count;
									$properties = @{}            
									foreach($col in $Columns)
									{
										if($i -lt  $count)
										{
											$properties[$col.Name] = $row[$i];
										}
										$i++;
									}
									$objectView[$j] = (New-Object PSObject -Property $properties)
									$j++;
								}
								
							}
						}
						$result=$objectView;
					}
				}
			}
		}
		catch
		{
			[EventBase]::PublishGenericCustomMessage($_)
		}
		return $result;		
	}

}



Class LAWSModel {
	[string] $RunIdentifier
	[string] $ResourceType 
	[string] $ResourceGroup 
	[string] $Reference
	[string] $ResourceName 
	[string] $ChildResourceName 
	[string] $ResourceId
	[string] $ControlStatus 
	[string] $ActualVerificationResult 
	[string] $ControlId 
	[string] $OrganizationName 
	[string] $OrganizationId 
	[string] $FeatureName 
	[string] $Source 
	[string] $Recommendation 
	[string] $ControlSeverity 
	[string] $TimeTakenInMs 
	[string] $AttestationStatus 
	[string] $AttestedBy 
	[string] $Justification 
	[string] $AttestedDate
	[bool] $HasRequiredAccess
	[bool] $HasAttestationWritePermissions
	[bool] $HasAttestationReadPermissions
	[bool] $IsLatestPSModule
	[bool] $IsControlInGrace
	[string[]] $Tags
	[string] $ScannerVersion
	[bool] $IsBaselineControl
	#add PreviewBaselineFlag
	[bool] $IsPreviewBaselineControl
	[string] $ExpiryDate
	[string] $PartialScanIdentifier
	[string] $PolicyOrgName
	[string] $ScannedBy
	[string] $Env
	[string] $ComponentId
	[String[]] $AdditionalInfo
	[bool] $IsResourceActive
	[int] $InactiveFromDays
	[String[]] $Exception
}

Class LAWSResourceInvModel{
	[string] $RunIdentifier
	[string] $OrganizationId
	[string] $OrganizationName
	[string] $Source
	[string] $ScannerVersion
	[string] $FeatureName
	[string] $ResourceGroupName
	[string] $ResourceName
	[string] $ResourceId
	[string] $ControlId
	[string] $ControlIntId
	[string] $ControlSeverity
	[string[]] $Tags
	[bool] $IsBaselineControl
	#add PreviewBaselineFlag
	[bool] $IsPreviewBaselineControl
}

Class LAWSResourceModel{
	[string] $RunIdentifier
	[string] $OrganizationId
	[string] $Source
	[string] $ScannerVersion
	[string] $ResourceType
	[string] $ResourceGroupName
	[string] $ResourceName
	[string] $ResourceId
}

Class AzSKContextDetails {
	[string] $RunIdentifier
	[string] $Version
	[string] $Source
	[string] $PolicyOrgName
	}

Class CommandModel{
	[string] $EventName
	[string] $RunIdentifier
	[string] $PartialScanIdentifier
	[string] $ModuleVersion
	[string] $MethodName
	[string] $ModuleName
	[string] $Parameters
	[string] $OrganizationId
	[string] $OrganizationName
}
class CredHygieneAlert{
    [int] $ExpiryDueInDays
	[bool] $IsExpired
	[string] $CredentialName 
	[string] $CredentialGroup
    [string] $LastUpdatedBy
	[string] $OrganizationId
	[string] $OrganizationName
}