Set-StrictMode -Version Latest

class RemoteReportHelper
{
	hidden static [string[]] $IgnoreScanParamList = "DoNotOpenOutputFolder";
	hidden static [string[]] $AllowedServiceScanParamList = "organizationName", "ResourceGroupNames";
	hidden static [string[]] $AllowedOrganizationScanParamList = "organizationName";
	hidden static [int] $MaxServiceParamCount = [RemoteReportHelper]::IgnoreScanParamList.Count + [RemoteReportHelper]::AllowedServiceScanParamList.Count;
	hidden static [int] $MaxOrganizationParamCount = [RemoteReportHelper]::IgnoreScanParamList.Count + [RemoteReportHelper]::AllowedOrganizationScanParamList.Count;
	hidden static [System.Security.Cryptography.SHA256Managed] $sha256AlgForMasking = [System.Security.Cryptography.SHA256Managed]::new();
	hidden static [AIOrgTelemetryStatus] $AIOrgTelemetryState = [AIOrgTelemetryStatus]::Undefined;
	hidden static [string] $TelemetryKey = "";

	static [FeatureGroup] GetFeatureGroup([SVTEventContext[]] $SVTEventContexts)
	{
		if(($SVTEventContexts | Measure-Object).Count -eq 0 -or $null -eq $SVTEventContexts[0].FeatureName) {
			return [FeatureGroup]::Unknown
		}
		$feature = $SVTEventContexts[0].FeatureName.ToLower()
		if($feature.Contains("organization")){
			return [FeatureGroup]::Organization
		} else{
			return [FeatureGroup]::Service
		}
	}

	static [ServiceScanKind] GetServiceScanKind([string] $command, [hashtable] $parameters)
	{
		$parameterNames = [array] $parameters.Keys
		if($parameterNames.Count -gt [RemoteReportHelper]::MaxServiceParamCount)
		{
			return [ServiceScanKind]::Partial;
		}
		$validParamCounter = 0;
		foreach($parameterName in $parameterNames)
		{
			if ([RemoteReportHelper]::AllowedServiceScanParamList.Contains($parameterName))
			{
				$validParamCounter += 1
			}
			elseif ([RemoteReportHelper]::IgnoreScanParamList.Contains($parameterName))
			{
				# Ignoring
			}
			else
			{
				return [ServiceScanKind]::Partial;
			}
		}

		if ($validParamCounter -eq 1)
		{
			return [ServiceScanKind]::Organization;
		}
		elseif ($validParamCounter -eq 2)
		{
			return [ServiceScanKind]::ResourceGroup;
		}
		else
		{
			return [ServiceScanKind]::Partial;
		}
	}

	static [OrganizationScanKind] GetOrganizationScanKind([string] $command, [hashtable] $parameters)
	{
		$parameterNames = [array] $parameters.Keys
		if($parameterNames.Count -gt [RemoteReportHelper]::MaxOrganizationParamCount)
		{
			return [OrganizationScanKind]::Partial;
		}
		$validParamCounter = 0;
		foreach($parameterName in $parameterNames)
		{
			if ([RemoteReportHelper]::AllowedOrganizationScanParamList.Contains($parameterName))
			{
				$validParamCounter += 1
			}
			elseif ([RemoteReportHelper]::IgnoreScanParamList.Contains($parameterName))
			{
				# Ignoring
			}
			else
			{
				return [OrganizationScanKind]::Partial;
			}
		}

		if ($validParamCounter -eq 1)
		{
			return [OrganizationScanKind]::Complete;
		}
		else
		{
			return [OrganizationScanKind]::Partial;
		}
	}

	static [OrganizationControlResult] BuildOrganizationControlResult([ControlResult] $controlResult, [ControlItem] $control)
	{
		$result = [OrganizationControlResult]::new()
		$result.ControlId = $control.ControlId
		$result.ControlIntId = $control.Id
		$result.ControlSeverity = $control.ControlSeverity
		$result.ActualVerificationResult = $controlResult.ActualVerificationResult
		$result.AttestationStatus = $controlResult.AttestationStatus
		$result.VerificationResult = $controlResult.VerificationResult
		$result.HasRequiredAccess = $controlResult.CurrentSessionContext.Permissions.HasRequiredAccess
		$result.IsBaselineControl = $control.IsBaselineControl
		#add PreviewBaselineFlag
		$result.IsPreviewBaselineControl = $control.IsPreviewBaselineControl
		$result.MaximumAllowedGraceDays = $controlResult.MaximumAllowedGraceDays
		if($control.Tags.Contains("OwnerAccess")  -or $control.Tags.Contains("GraphRead"))
		{
			$result.HasOwnerAccessTag = $true
		}

		$result.UserComments = $controlResult.UserComments

		if($null -ne $controlResult.StateManagement -and $null -ne $controlResult.StateManagement.AttestedStateData) {
			$result.AttestedBy = $controlResult.StateManagement.AttestedStateData.AttestedBy
			$result.Justification = $controlResult.StateManagement.AttestedStateData.Justification
			$result.AttestedState = [JsonHelper]::ConvertToJsonCustomCompressed($controlResult.StateManagement.AttestedStateData.DataObject)
			$result.AttestedDate = $controlResult.StateManagement.AttestedStateData.AttestedDate
			$result.AttestationExpiryDate = $controlResult.StateManagement.AttestedStateData.ExpiryDate

		}
		if($null -ne $controlResult.StateManagement -and $null -ne $controlResult.StateManagement.CurrentStateData) {
			$result.CurrentState = [JsonHelper]::ConvertToJsonCustomCompressed($controlResult.StateManagement.CurrentStateData.DataObject)
		}
		return $result;
	}

	static [ServiceControlResult] BuildServiceControlResult([ControlResult] $controlResult, [bool] $isNestedResource, [ControlItem] $control)
	{
		$result = [ServiceControlResult]::new()
		$result.IsNestedResource = $isNestedResource
		if ($isNestedResource)
		{
			$result.NestedResourceName = $controlResult.ChildResourceName
		}
		else
		{
			$result.NestedResourceName = $null
		}
		$result.ControlId = $control.ControlID
		$result.ControlIntId = $control.Id
		$result.ControlSeverity = $control.ControlSeverity
		$result.ActualVerificationResult = $controlResult.ActualVerificationResult
		$result.AttestationStatus = $controlResult.AttestationStatus
		$result.VerificationResult = $controlResult.VerificationResult
		$result.HasRequiredAccess = $controlResult.CurrentSessionContext.Permissions.HasRequiredAccess
		$result.IsBaselineControl = $control.IsBaselineControl
		#add PreviewBaselineFlag
		$result.IsPreviewBaselineControl = $control.IsPreviewBaselineControl
		$result.UserComments = $controlResult.UserComments
		$result.MaximumAllowedGraceDays = $controlResult.MaximumAllowedGraceDays
		if($control.Tags.Contains("OwnerAccess")  -or $control.Tags.Contains("GraphRead"))
		{
			$result.HasOwnerAccessTag = $true
		}

		if($null -ne $controlResult.StateManagement -and $null -ne $controlResult.StateManagement.AttestedStateData) {
			$result.AttestedBy = $controlResult.StateManagement.AttestedStateData.AttestedBy
			$result.Justification = $controlResult.StateManagement.AttestedStateData.Justification
			$result.AttestedState = [JsonHelper]::ConvertToJsonCustomCompressed($controlResult.StateManagement.AttestedStateData.DataObject)
			$result.AttestedDate = $controlResult.StateManagement.AttestedStateData.AttestedDate
			$result.AttestationExpiryDate = $controlResult.StateManagement.AttestedStateData.ExpiryDate
		}
		if($null -ne $controlResult.StateManagement -and $null -ne $controlResult.StateManagement.CurrentStateData) {
			$result.CurrentState = [JsonHelper]::ConvertToJsonCustomCompressed($controlResult.StateManagement.CurrentStateData.DataObject)
		}
		return $result;
	}

	static [ScanSource] GetScanSource()
	{		
		$settings = [ConfigurationManager]::GetAzSKSettings();
		[string] $laSource = $settings.LASource;
		if([string]::IsNullOrWhiteSpace($laSource)){
			return [ScanSource]::SpotCheck
		}
		if($laSource.Equals("CICD", [System.StringComparison]::OrdinalIgnoreCase)){
			return [ScanSource]::VSO
		}
		if($laSource.Equals("CA", [System.StringComparison]::OrdinalIgnoreCase)){
			return [ScanSource]::Runbook
		}
		return [ScanSource]::SpotCheck
	}

	static [string] GetAIOrgTelemetryKey()
	{
		if(-not [string]::IsNullOrEmpty([RemoteReportHelper]::TelemetryKey))
		{
			return [RemoteReportHelper]::TelemetryKey
		}
		$settings = [ConfigurationManager]::GetAzSKConfigData();
		[RemoteReportHelper]::TelemetryKey = $settings.ControlTelemetryKey
		[guid]$key = [guid]::Empty
		# Trying to parse [RemoteReportHelper]::TelemetryKey into  $key and then checking that it is not empty
		if([guid]::TryParse([RemoteReportHelper]::TelemetryKey, [ref] $key) -and ![guid]::Empty.Equals($key))
		{
			return [RemoteReportHelper]::TelemetryKey;
		}
		[RemoteReportHelper]::TelemetryKey = [ConfigurationManager]::GetAzSKSettings().LocalControlTelemetryKey
		return [RemoteReportHelper]::TelemetryKey;
	}

	static [bool] IsAIOrgTelemetryEnabled()
	{
		$scanSource = [AzSKSettings]::GetInstance().GetScanSource();
		# Disabled the AI telemetry for SDL scan.
		if ($scanSource -eq 'SDL') {
			[RemoteReportHelper]::AIOrgTelemetryState = [AIOrgTelemetryStatus]::Disabled
			return $false
		}
		if([RemoteReportHelper]::AIOrgTelemetryState -eq [AIOrgTelemetryStatus]::Enabled)
		{
			return $true
		}
		elseif([RemoteReportHelper]::AIOrgTelemetryState -eq [AIOrgTelemetryStatus]::Disabled)
		{
			return $false
		}
		#If AIOrgTelemetryState is Undefined then evaluate
		$settings = [ConfigurationManager]::GetAzSKConfigData();
		$orgTelemetryKey = $settings.ControlTelemetryKey
		[guid]$key = [guid]::Empty
		# Trying to parse [RemoteReportHelper]::TelemetryKey into  $key and then checking that it is not empty
		if([guid]::TryParse($orgTelemetryKey, [ref] $key) -and ![guid]::Empty.Equals($key))
		{
			if($settings.EnableControlTelemetry)
			{
				[RemoteReportHelper]::AIOrgTelemetryState = [AIOrgTelemetryStatus]::Enabled
				return $true
			}
			else 
			{
				[RemoteReportHelper]::AIOrgTelemetryState = [AIOrgTelemetryStatus]::Disabled
				return $false
			}
		}
		if([ConfigurationManager]::GetAzSKSettings().LocalEnableControlTelemetry)
		{
			[RemoteReportHelper]::AIOrgTelemetryState = [AIOrgTelemetryStatus]::Enabled
			return $true
		}
		else 
		{
			[RemoteReportHelper]::AIOrgTelemetryState = [AIOrgTelemetryStatus]::Disabled
			return $false
		}
	}
	
	static [string] Mask([psobject] $toMask)
	{
		$maskBytes = [System.Text.Encoding]::UTF8.GetBytes($toMask.ToString().ToLower())
		$maskBytes = ([RemoteReportHelper]::sha256AlgForMasking).ComputeHash($maskBytes)
		$take = 16
		$sb = [System.Text.StringBuilder]::new($take)
		for($i = 0; $i -lt ($take/2); $i++){
			$x = $sb.Append($maskBytes[$i].ToString("x2"))
		}
		return $sb.ToString();
	}
}
