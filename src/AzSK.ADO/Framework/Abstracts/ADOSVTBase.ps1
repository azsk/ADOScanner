class ADOSVTBase: SVTBase {

	hidden [ControlStateExtension] $ControlStateExt;
	hidden [AzSKSettings] $AzSKSettings;	
	# below variable will be used by SVT's and overriden for each individual resource.
	hidden [bool] $isResourceActive = $true;
	# below variable will contains the inactivity period for resources in days.
	hidden [int] $InactiveFromDays = -1;
	# below variable will contain resources approval & checks settings data.
	static [System.Collections.Generic.List[ResourceApprovalCheck]] $ResourceApprovalChecks = @();
	ADOSVTBase() {

	}

	ADOSVTBase([string] $organizationName):
	Base($organizationName) {
		$this.CreateInstance();
	}
	ADOSVTBase([string] $organizationName, [SVTResource] $svtResource):
	Base($organizationName) {
		$this.CreateInstance($svtResource);
	}
	#Create instance for organization scan
	hidden [void] CreateInstance() {
		[Helpers]::AbstractClass($this, [SVTBase]);
		Write-Host -ForegroundColor Yellow "No mapping!? Do we use this .ctor?"
		#$this.LoadSvtConfig([SVTMapping]::OrganizationMapping.JsonFileName);
		$this.ResourceId = $this.OrganizationContext.Scope;
	}

	#Add PreviewBaselineControls
	hidden [bool] CheckBaselineControl($controlId) {
		if (($null -ne $this.ControlSettings) -and [Helpers]::CheckMember($this.ControlSettings, "BaselineControls.ResourceTypeControlIdMappingList")) {
			$baselineControl = $this.ControlSettings.BaselineControls.ResourceTypeControlIdMappingList | Where-Object { $_.ControlIds -contains $controlId }
			if (($baselineControl | Measure-Object).Count -gt 0 ) {
				return $true
			}
		}
		return $false
	}
	hidden [bool] CheckPreviewBaselineControl($controlId) {
		if (($null -ne $this.ControlSettings) -and [Helpers]::CheckMember($this.ControlSettings, "PreviewBaselineControls.ResourceTypeControlIdMappingList")) {
			$PreviewBaselineControls = $this.ControlSettings.PreviewBaselineControls.ResourceTypeControlIdMappingList | Where-Object { $_.ControlIds -contains $controlId }
			if (($PreviewBaselineControls | Measure-Object).Count -gt 0 ) {
				return $true
			}
		}
		return $false
	}

	hidden [void] UpdateControlStates([SVTEventContext[]] $ControlResults) {
		if ($null -ne $this.ControlStateExt -and $this.ControlStateExt.HasControlStateWriteAccessPermissions() -and ($ControlResults | Measure-Object).Count -gt 0 -and ($this.ResourceState | Measure-Object).Count -gt 0) {
			$effectiveResourceStates = @();
			if (($this.DirtyResourceStates | Measure-Object).Count -gt 0) {
				$this.ResourceState | ForEach-Object {
					$controlState = $_;
					if (($this.DirtyResourceStates | Where-Object { $_.InternalId -eq $controlState.InternalId -and $_.ChildResourceName -eq $controlState.ChildResourceName } | Measure-Object).Count -eq 0) {
						$effectiveResourceStates += $controlState;
					}
				}
			}
			else {
				#If no dirty states found then no action needed.
				return;
			}

			#get the uniqueid from the first control result. Here we can take first as it would come here for each resource.
			$id = $ControlResults[0].GetUniqueId();
			$resourceType = $ControlResults[0].FeatureName
			$resourceName = $ControlResults[0].ResourceContext.ResourceName

			$this.ControlStateExt.SetControlState($id, $effectiveResourceStates, $true, $resourceType, $resourceName, $ControlResults[0].ResourceContext.ResourceGroupName)
		}
	}

	#isRescan parameter is added to check if method is called from rescan. state data is fetching for rescan
	hidden [ControlState[]] GetResourceState([bool] $isRescan = $false) {
		if ($null -eq $this.ResourceState) {
			$this.ResourceState = @();
			if ($this.ControlStateExt -and $this.ControlStateExt.HasControlStateReadAccessPermissions()) {
				$resourceType = "";
				if ($this.ResourceContext) {
					$resourceType = $this.ResourceContext.ResourceTypeName
				}
				#Fetch control state for organization only if project is configured for org spesific control attestation (Check for Organization only, for other resource go inside without project check).

				if($resourceType -ne "Organization" -or $this.ControlStateExt.GetProject())
				{
					$resourceStates = $this.ControlStateExt.GetControlState($this.ResourceId, $resourceType, $this.ResourceContext.ResourceName, $this.ResourceContext.ResourceGroupName, $isRescan)
					if ($null -ne $resourceStates) {
						$this.ResourceState += $resourceStates

					}
				}
			}
		}

		return $this.ResourceState;
	}

	hidden [void] PostProcessData([SVTEventContext] $eventContext) {
		$tempHasRequiredAccess = $true;
		$controlState = @();
		$controlStateValue = @();
		try {
			$resourceStates = $this.GetResourceState($false)
			if (!$this.AzSKSettings)
			{
				$this.AzSKSettings = [ConfigurationManager]::GetAzSKSettings();
			}
			$enableOrgControlAttestation = $this.AzSKSettings.EnableOrgControlAttestation

			if (($resourceStates | Measure-Object).Count -ne 0) {
				$controlStateValue += $resourceStates | Where-Object { $_.InternalId -eq $eventContext.ControlItem.Id };
				$controlStateValue | ForEach-Object {
					$currentControlStateValue = $_;
					if ($null -ne $currentControlStateValue) {
						if ($this.IsStateActive($eventContext, $currentControlStateValue)) {
							$controlState += $currentControlStateValue;
						}
						else {
							#add to the dirty state list so that it can be removed later
							$this.DirtyResourceStates += $currentControlStateValue;
						}
					}
				}
			}
			# If Project name is not configured in ext storage & policy project parameter is not used or attestation repo is not present in policy project,
			# then 'IsOrgAttestationProjectFound' will be false so that HasRequiredAccess for org controls can be set as false
			elseif (($eventContext.FeatureName -eq "Organization" -and [ControlStateExtension]::IsOrgAttestationProjectFound -eq $false) -and ($enableOrgControlAttestation -eq $true)){
				$tempHasRequiredAccess = $false;
			}
			elseif ($null -eq $resourceStates) {
				$tempHasRequiredAccess = $false;
			}
		}
		catch {
			$this.EvaluationError($_);
		}

		$eventContext.ControlResults |
		ForEach-Object {
			try {
				$currentItem = $_;
				# Copy the current result to Actual Result field
				$currentItem.ActualVerificationResult = $currentItem.VerificationResult;

				# override the default value with current status
				$currentItem.IsResourceActive = $this.IsResourceActive;
				$currentItem.InactiveFromDays = $this.InactiveFromDays;
				#Logic to append the control result with the permissions metadata
				[SessionContext] $sc = $currentItem.CurrentSessionContext;
				$sc.Permissions.HasAttestationWritePermissions = $this.ControlStateExt.HasControlStateWriteAccessPermissions();
				$sc.Permissions.HasAttestationReadPermissions = $this.ControlStateExt.HasControlStateReadAccessPermissions();
				# marking the required access as false if there was any error reading the attestation data
				$sc.Permissions.HasRequiredAccess = $sc.Permissions.HasRequiredAccess -and $tempHasRequiredAccess;

				# Disable the fix control feature
				if (-not $this.GenerateFixScript) {
					$currentItem.EnableFixControl = $false;
				}

				if ($currentItem.StateManagement.CurrentStateData -and $currentItem.StateManagement.CurrentStateData.DataObject -and $eventContext.ControlItem.DataObjectProperties) {
					$currentItem.StateManagement.CurrentStateData.DataObject = [Helpers]::SelectMembers($currentItem.StateManagement.CurrentStateData.DataObject, $eventContext.ControlItem.DataObjectProperties);
				}

				if ($controlState.Count -ne 0) {
					# Process the state if its available
					$childResourceState = $controlState | Where-Object { $_.ChildResourceName -eq $currentItem.ChildResourceName } | Select-Object -First 1;
					if ($childResourceState) {
						$validatePreviousAttestation = $true
						# if EnforceApprovedException is true and controls is not attested with exception id, based on configuration, invalidate the previous attestation
						if ([Helpers]::CheckMember($this.ControlSettings, "EnforceApprovedException") -and $this.ControlSettings.EnforceApprovedException -eq $true -and (-not [Helpers]::CheckMember($childResourceState.state, "ApprovedExceptionID") -or [string]::IsNullOrWhiteSpace($childResourceState.state.ApprovedExceptionID))) {
							$attestationExpiryDays = ""
							# check if InvalidatePreviousAttestations is set to true to invalidate previous attestation
							if ([Helpers]::CheckMember($this.ControlSettings, "ApprovedExceptionSettings") -and $this.ControlSettings.ApprovedExceptionSettings.InvalidatePreviousAttestations -eq $true) {
								$approvedExceptionsControlList = $this.ControlSettings.ApprovedExceptionSettings.ControlsList
								# verify if the control attested is in the list of approved exception enabled controls
								if ($approvedExceptionsControlList -contains $controlState.ControlId) {
									$validatePreviousAttestation = $false
									Write-Host "Per your org policy, this control now requires an associated approved exception id. Previous attestation has been invalidated." -ForegroundColor Yellow
									#add to the dirty state list so that it can be removed later
									$this.DirtyResourceStates += $childResourceState
								}
							}
						}
						# Skip passed ones from State Management
                        # Skip the validation if invalidatePreviousAttestations is enabled to true in control settings
						if ($currentItem.ActualVerificationResult -ne [VerificationResult]::Passed) {
							#compare the states
							if (($childResourceState.ActualVerificationResult -eq $currentItem.ActualVerificationResult) -and $childResourceState.State) {

								$currentItem.StateManagement.AttestedStateData = $childResourceState.State;

								# Compare dataobject property of State
								if ($null -ne $childResourceState.State.DataObject) {
									if ($currentItem.StateManagement.CurrentStateData -and $null -ne $currentItem.StateManagement.CurrentStateData.DataObject) {
										$currentStateDataObject = [JsonHelper]::ConvertToJsonCustom($currentItem.StateManagement.CurrentStateData.DataObject) | ConvertFrom-Json

										try {
											# Objects match, change result based on attestation status
											if ($eventContext.ControlItem.AttestComparisionType -and $eventContext.ControlItem.AttestComparisionType -eq [ComparisionType]::NumLesserOrEqual) {
												$dataObjMatched = $false
												if ([Helpers]::CompareObject($childResourceState.State.DataObject, $currentStateDataObject, $true, $eventContext.ControlItem.AttestComparisionType)) {
													$dataObjMatched = $true
												}
												if (-not $dataObjMatched)
												{
													#In Linux env base24 encoding is different from that in Windows. Therefore doing a comparison of decoded data object as fallback
													$decodedAttestedDataObj = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($childResourceState.State.DataObject))  | ConvertFrom-Json
													$decodedCurrentDataObj = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($currentStateDataObject))  | ConvertFrom-Json
													if ([Helpers]::CompareObject($decodedAttestedDataObj, $decodedCurrentDataObj, $true))
													{
														$dataObjMatched = $true
													}

													# Don't fail attestation if current state data object is a subset of attested state data object
													if (($decodedCurrentDataObj | Measure-Object).Count -lt ($decodedAttestedDataObj | Measure-Object).Count) {
														if ([Helpers]::CompareObject($decodedAttestedDataObj, $decodedCurrentDataObj, $false, $eventContext.ControlItem.AttestComparisionType))
														{
															$dataObjMatched = $true
														}
													}
												}
												if ($dataObjMatched)
												{
													$this.ModifyControlResult($currentItem, $childResourceState);
												}

											}
											else {
												$dataObjMatched = $false
												if ([Helpers]::CompareObject($childResourceState.State.DataObject, $currentStateDataObject, $true)) {
													#$this.ModifyControlResult($currentItem, $childResourceState);
													$dataObjMatched = $true
												}
												if (-not $dataObjMatched)
												{
													#In Linux env base24 encoding is different from that in Windows. Therefore doing a comparison of decoded data object as fallback
													$decodedAttestedDataObj = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($childResourceState.State.DataObject))  | ConvertFrom-Json
													$decodedCurrentDataObj = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($currentStateDataObject))  | ConvertFrom-Json
													if ([Helpers]::CompareObject($decodedAttestedDataObj, $decodedCurrentDataObj, $true) -and [Helpers]::CompareObject($decodedCurrentDataObj, $decodedAttestedDataObj, $true))
													{
														$dataObjMatched = $true
													}
													
													# Don't fail attestation if current state data object is a subset of attested state data object
													if (($decodedCurrentDataObj | Measure-Object).Count -lt ($decodedAttestedDataObj | Measure-Object).Count) {
														if ([Helpers]::CompareObject($decodedCurrentDataObj, $decodedAttestedDataObj, $false))
														{
															$dataObjMatched = $true
														}
													}
													elseif ($decodedCurrentDataObj.GetType() -eq [Int] -and $decodedAttestedDataObj.GetType() -eq [Int]) {
														if ($decodedCurrentDataObj -lt $decodedAttestedDataObj) {
															$dataObjMatched = $true
														}
													}
												}
												if ($dataObjMatched)
												{
													$this.ModifyControlResult($currentItem, $childResourceState);
												}
											}
										}
										catch {
											$this.EvaluationError($_);
										}
									}
								}
								else {
									if ($currentItem.StateManagement.CurrentStateData) {
										if ($null -eq $currentItem.StateManagement.CurrentStateData.DataObject) {
											# No object is persisted, change result based on attestation status
											$this.ModifyControlResult($currentItem, $childResourceState);
										}
									}
									else {
										# No object is persisted, change result based on attestation status
										$this.ModifyControlResult($currentItem, $childResourceState);
									}
								}
							}
                        }
						else {
							#add to the dirty state list so that it can be removed later
							$this.DirtyResourceStates += $childResourceState
						}
					}
				}
			}
			catch {
				$this.EvaluationError($_);
			}
		};
	}

	# State Machine implementation of modifying verification result
	hidden [void] ModifyControlResult([ControlResult] $controlResult, [ControlState] $controlState) {
		# No action required if Attestation status is None OR verification result is Passed
		if ($controlState.AttestationStatus -ne [AttestationStatus]::None -or $controlResult.VerificationResult -ne [VerificationResult]::Passed) {
			$controlResult.AttestationStatus = $controlState.AttestationStatus;
			$controlResult.VerificationResult = [Helpers]::EvaluateVerificationResult($controlResult.VerificationResult, $controlState.AttestationStatus);
		}
	}

	#Function to validate attestation data expiry validation
	hidden [bool] IsStateActive([SVTEventContext] $eventcontext, [ControlState] $controlState) {
		try {
			$expiryIndays = $this.CalculateExpirationInDays([SVTEventContext] $eventcontext, [ControlState] $controlState);
			#Validate if expiry period is passed
			#Added a condition so as to expire attested controls that were in 'Error' state.
			if (($expiryIndays -ne -1 -and $controlState.State.AttestedDate.AddDays($expiryIndays) -lt [DateTime]::UtcNow) -or ($controlState.ActualVerificationResult -eq [VerificationResult]::Error)) {
				return $false
			}
			else {
				$controlState.State.ExpiryDate = ($controlState.State.AttestedDate.AddDays($expiryIndays)).ToString("MM/dd/yyyy");
				return $true
			}
		}
		catch {
			#if any exception occurs while getting/validating expiry period, return true.
			$this.EvaluationError($_);
			return $true
		}
	}

	hidden [int] CalculateExpirationInDays([SVTEventContext] $eventcontext, [ControlState] $controlState) {
		try {
			#For exempt controls, either the no. of days for expiry were provided at the time of attestation or a default of 6 motnhs was already considered,
			#therefore skipping this flow and calculating days directly using the expiry date already saved.
			$isApprovedExceptionEnforced = $false
			$approvedExceptionControlsList = @();
			if ([Helpers]::CheckMember($this.ControlSettings, "EnforceApprovedException") -and ($this.ControlSettings.EnforceApprovedException -eq $true)) {
				if ([Helpers]::CheckMember($this.ControlSettings, "ApprovedExceptionSettings") -and (($this.ControlSettings.ApprovedExceptionSettings.ControlsList | Measure-Object).Count -gt 0)) {
					$isApprovedExceptionEnforced = $true
					$approvedExceptionControlsList = $this.ControlSettings.ApprovedExceptionSettings.ControlsList
				}
			}
			
			if ($controlState.AttestationStatus -ne [AttestationStatus]::ApprovedException) {
				#Get controls expiry period. Default value is zero
				$controlAttestationExpiry = $eventcontext.controlItem.AttestationExpiryPeriodInDays
				$controlSeverity = $eventcontext.controlItem.ControlSeverity
				$controlSeverityExpiryPeriod = 0
				$defaultAttestationExpiryInDays = [Constants]::DefaultControlExpiryInDays;
				$expiryInDays = -1;

				if (($eventcontext.ControlResults | Measure-Object).Count -gt 0) {
					$isControlInGrace = $eventcontext.ControlResults.IsControlInGrace;
				}
				else {
					$isControlInGrace = $true;
				}
				if ([Helpers]::CheckMember($this.ControlSettings, "AttestationExpiryPeriodInDays") `
						-and [Helpers]::CheckMember($this.ControlSettings.AttestationExpiryPeriodInDays, "Default") `
						-and $this.ControlSettings.AttestationExpiryPeriodInDays.Default -gt 0) {
					$defaultAttestationExpiryInDays = $this.ControlSettings.AttestationExpiryPeriodInDays.Default
				}
				#Expiry in the case of WillFixLater or StateConfirmed/Recurring Attestation state will be based on Control Severity.
				# Checking if the resource id is present in extended expiry list of control settings
				if ($controlState.AttestationStatus -eq [AttestationStatus]::NotAnIssue -or $controlState.AttestationStatus -eq [AttestationStatus]::NotApplicable) {
					$expiryInDays = $defaultAttestationExpiryInDays;
				}
				else {
					# Expire WillFixLater if GracePeriod has expired
					if (-not($isControlInGrace) -and $controlState.AttestationStatus -eq [AttestationStatus]::WillFixLater) {
						$expiryInDays = 0;
					}
					else {
						if ($controlAttestationExpiry -ne 0) {
							$expiryInDays = $controlAttestationExpiry
						}
						elseif ([Helpers]::CheckMember($this.ControlSettings, "AttestationExpiryPeriodInDays")) {
							$controlsev = $this.ControlSettings.ControlSeverity.PSobject.Properties | Where-Object Value -eq $controlSeverity | Select-Object -First 1
							$controlSeverity = $controlsev.name
							#Check if control severity has expiry period
							if ([Helpers]::CheckMember($this.ControlSettings.AttestationExpiryPeriodInDays.ControlSeverity, $controlSeverity) ) {
								$expiryInDays = $this.ControlSettings.AttestationExpiryPeriodInDays.ControlSeverity.$controlSeverity
							}
							#If control item and severity does not contain expiry period, assign default value
							else {
								$expiryInDays = $defaultAttestationExpiryInDays
							}
						}
						#Return -1 when expiry is not defined
						else {
							$expiryInDays = -1
						}
					}
				}
			}
			else {
				#Calculating the expiry in days for exempt controls
				if ([String]::IsNullOrEmpty($controlState.State.ExpiryDate))
				{
					$expiryPeriod = $this.ControlSettings.DefaultAttestationPeriodForExemptControl
					$expiryDate = ($controlState.State.AttestedDate).AddDays($expiryPeriod)
				}
				else
				{
					$expiryDate = [DateTime]$controlState.State.ExpiryDate
				}
				# #Adding 1 explicitly to the days since the differnce below excludes the expiryDate and that also needs to be taken into account.
				# $expiryInDays = ($expiryDate - $controlState.State.AttestedDate).Days + 1
				# #Calculating the expiry in days for exempt controls

				# $expiryDate = [DateTime]$controlState.State.ExpiryDate
				# #Adding 1 explicitly to the days since the differnce below excludes the expiryDate and that also needs to be taken into account.
				$expiryInDays = ($expiryDate - $controlState.State.AttestedDate).Days + 1
			}

			if (($controlState.AttestationStatus -eq [AttestationStatus]::ApprovedException) -or ( $isApprovedExceptionEnforced -and $approvedExceptionControlsList -contains $controlState.ControlId)) {
				$expiryInDays = $this.ControlSettings.DefaultAttestationPeriodForExemptControl
			}
			elseif([Helpers]::CheckMember($this.ControlSettings, "ExtendedAttestationExpiryResources") -and [Helpers]::CheckMember($this.ControlSettings, "ExtendedAttestationExpiryDuration")){
				# Checking if the resource id is present in extended expiry list of control settings
				if(($this.ControlSettings.ExtendedAttestationExpiryResources | Get-Member "ResourceType") -and ($this.ControlSettings.ExtendedAttestationExpiryResources | Get-Member "ResourceIds")) {
					$extendedResources = $this.ControlSettings.ExtendedAttestationExpiryResources | Where { $_.ResourceType -match $eventcontext.FeatureName }
					# type null check
					if(($extendedResources | Measure-Object).Count -gt 0 -and [Helpers]::CheckMember($extendedResources, "ResourceIds") -and $controlState.ResourceId -in $extendedResources.ResourceIds){
						$expiryInDays = $this.ControlSettings.ExtendedAttestationExpiryDuration;
					}
				}
			}
		}
		catch {
			#if any exception occurs while getting/validating expiry period, return -1.
			$this.EvaluationError($_);
			$expiryInDays = -1
		}
		return $expiryInDays
	}

	[SVTEventContext[]] FetchStateOfAllControls() {
		[SVTEventContext[]] $resourceSecurityResult = @();
		if (-not $this.ValidateMaintenanceState()) {
			if ($this.GetApplicableControls().Count -eq 0) {
				$this.PublishCustomMessage("No security controls match the input criteria specified", [MessageType]::Warning);
			}
			else {
				$this.EvaluationStarted();
				$resourceSecurityResult += $this.GetControlsStateResult();
				if (($resourceSecurityResult | Measure-Object).Count -gt 0) {
					$this.EvaluationCompleted($resourceSecurityResult);
				}
			}
		}
		return $resourceSecurityResult;
	}

	hidden [SVTEventContext[]] GetControlsStateResult() {
		[SVTEventContext[]] $automatedControlsResult = @();
		$this.DirtyResourceStates = @();
		try {
			$this.GetApplicableControls() |
			ForEach-Object {
				$eventContext = $this.FetchControlState($_);
				#filter controls if there is no state found
				if ($eventContext) {
					$eventContext.ControlResults = $eventContext.ControlResults | Where-Object { $_.AttestationStatus -ne [AttestationStatus]::None }
					if ($eventContext.ControlResults) {
						$automatedControlsResult += $eventContext;
					}
				}
			};
		}
		catch {
			$this.EvaluationError($_);
		}

		return $automatedControlsResult;
	}
 #isRescan parameter is added to check if method is called from rescan.
	hidden [SVTEventContext] FetchControlState([ControlItem] $controlItem, $isRescan = $false) {
		[SVTEventContext] $singleControlResult = $this.CreateSVTEventContextObject();
		$singleControlResult.ControlItem = $controlItem;

		$controlState = @();
		$controlStateValue = @();
		try {
			$resourceStates = $this.GetResourceState($isRescan);
			if (($resourceStates | Measure-Object).Count -ne 0) {
				$controlStateValue += $resourceStates | Where-Object { $_.InternalId -eq $singleControlResult.ControlItem.Id };
				$controlStateValue | ForEach-Object {
					$currentControlStateValue = $_;
					if ($null -ne $currentControlStateValue) {
						#assign expiry date
						$expiryIndays = $this.CalculateExpirationInDays($singleControlResult, $currentControlStateValue);
						if ($expiryIndays -ne -1) {
							$currentControlStateValue.State.ExpiryDate = ($currentControlStateValue.State.AttestedDate.AddDays($expiryIndays)).ToString("MM/dd/yyyy");
						}
						$controlState += $currentControlStateValue;
					}
				}
			}
		}
		catch {
			$this.EvaluationError($_);
		}
		if (($controlState | Measure-Object).Count -gt 0) {
		#Added check to resolve duplicate log issue in rescan
			if (!$isRescan) {
			   $this.ControlStarted($singleControlResult);
			}
			if ($controlItem.Enabled -eq $false) {
				$this.ControlDisabled($singleControlResult);
			}
			else {
				$controlResult = $this.CreateControlResult($controlItem.FixControl);
				$singleControlResult.ControlResults += $controlResult;
				$singleControlResult.ControlResults |
				ForEach-Object {
					try {
						$currentItem = $_;

						if ($controlState.Count -ne 0) {
							# Process the state if it's available
							$childResourceState = $controlState | Where-Object { $_.ChildResourceName -eq $currentItem.ChildResourceName } | Select-Object -First 1;
							if ($childResourceState) {
								$currentItem.StateManagement.AttestedStateData = $childResourceState.State;
								$currentItem.AttestationStatus = $childResourceState.AttestationStatus;
								$currentItem.ActualVerificationResult = $childResourceState.ActualVerificationResult;
								$currentItem.VerificationResult = [VerificationResult]::NotScanned
							}
						}
					}
					catch {
						$this.EvaluationError($_);
					}
				};

			}
			#Added check to resolve duplicate log issue in rescan
			if (!$isRescan) {
			   $this.ControlCompleted($singleControlResult);
			}
		}

		return $singleControlResult;
	}

	hidden [void] GetManualSecurityStatusExt($arg) {
		$this.PostProcessData($arg);
	}

	hidden [void] RunControlExt($singleControlResult) {
		$this.PostProcessData($singleControlResult);
	}

	hidden [void] EvaluateAllControlsExt($resourceSecurityResult) {
		$this.PostEvaluationCompleted($resourceSecurityResult);
	}

	hidden [void] PostEvaluationCompleted([SVTEventContext[]] $ControlResults) {
		$this.UpdateControlStates($ControlResults);

		$BugLogParameterValue =$this.InvocationContext.BoundParameters["AutoBugLog"]
		#perform bug logging after control scans for the current resource
		if ($BugLogParameterValue)
		{
			# using checkmember without null check, if field is present in control settings but no value has been set then allow bug logging for inactive resources.
			if([Helpers]::CheckMember($this.ControlSettings.BugLogging, "LogBugsForInactiveResources", $false))
			{
				# if bug logging is enabled for inactive resources, then only bug will be logged for inactive resources.
				if ($this.ControlSettings.BugLogging.LogBugsForInactiveResources -eq $false)
				{
					$logBugsForInactiveResources = $this.isResourceActive;
				}
				# if bug logging is not enabled or its value has not been set in control setting, then treat bug logging is active for all resources.
				else
				{
					$logBugsForInactiveResources = $true;
				}
			}
			# if required field is not present in the controlSettings,json then follow the older approach
			else
			{
				$logBugsForInactiveResources = $true;
			}
			#added check azuretable check here, if ((azuretable is used for storing bug info and scan mode is CA) OR azuretable bug info is disabed) then only allow bug logging
			$scanSource = [AzSKSettings]::GetInstance().GetScanSource();
			$isAzureTableEnabled = [Helpers]::CheckMember($this.ControlSettings.BugLogging, "UseAzureStorageAccount");
			if (!$isAzureTableEnabled -or ($isAzureTableEnabled -and ($scanSource -eq "CA")) )
			{
				if ($logBugsForInactiveResources) {
					if (($ControlResults.ControlResults.VerificationResult -contains "Failed") -or ($ControlResults.ControlResults.VerificationResult -contains "Verify")) {
						$this.BugLoggingPostEvaluation($ControlResults, $BugLogParameterValue)
					}
				}
				else {
					$this.PublishCustomMessage("The current resource is inactive. Bug logging is disabled for inactive resources.", [MessageType]::Warning);
				}
			}

		}
	}

	#function to call AutoBugLog class for performing bug logging
	hidden [void] BugLoggingPostEvaluation([SVTEventContext []] $ControlResults,[string] $BugLogParameterValue)
	{
		$AutoBugLog = [AutoBugLog]::AutoBugInstance
		if (!$AutoBugLog) {
			#Settting initial value true so will evaluate in all different cmds.(Powershell keeping static variables in memory in next command also.)
			[BugLogPathManager]::checkValidPathFlag = $true;
			$AutoBugLog = [AutoBugLog]::GetInstance($this.OrganizationContext.OrganizationName, $this.InvocationContext, $this.ControlStateExt, $BugLogParameterValue);
		}
		$AutoBugLog.LogBugInADO($ControlResults)
	}

	#function to Get Approval & Check details of resource
	hidden [psobject]GetResourceApprovalCheck()
    {        
			$resourceType = $this.ResourceContext.ResourceTypeName;
			if($resourceType -eq 'AgentPool'){
				$name=$this.ResourceContext.ResourceName;
				$resourceId = $this.AgentPoolId;
			}
			else{
				$name = $this.ResourceContext.ResourceDetails.Name; 
				$resourceId = $this.ResourceContext.ResourceDetails.Id;	
			}		
			if($resourceType -eq 'ServiceConnection'){
				$resourceType = 'endpoint'
			}
			if($resourceType -eq 'AgentPool'){
				$resourceType = 'queue'
			}			
			$approvalChecks = [ADOSVTBase]::ResourceApprovalChecks | Where-Object {($_.ResourceId -eq $($resourceId)) -and ($_.ResourceType -eq $($resourceType))}  
            
            if(!$approvalChecks){    
                $url = "https://dev.azure.com/{0}/{1}/_apis/pipelines/checks/queryconfigurations?`$expand=settings&api-version=6.1-preview.1" -f $this.OrganizationContext.OrganizationName, $this.ResourceContext.ResourceGroupName;
                #using ps invoke web request instead of helper method, as post body (json array) not supported in helper method
                $rmContext = [ContextHelper]::GetCurrentContext();
                $user = "";
                $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $user,$rmContext.AccessToken))) 
                $body = "[{'name':  '$($name)','id':  '$($resourceId)','type':  '$($resourceType)'}]" 
                if($resourceType -eq 'Repository'){
                    $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
                    $body = "[{'name':  '$($name)','id':  '$($projectId +"."+$resourceId)','type':  'repository'}]"
                }                                       
                $response = @(Invoke-RestMethod -Uri $url -Method Post -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo)} -Body $body)
                $yamlTemplateControl = @()
                if([Helpers]::CheckMember($response, "count") -and $response[0].count -gt 0){                                                         
                    try{
                        $yamlTemplateControl = @($response.value | Where-Object {$_.PSObject.Properties.Name -contains "settings"})
                    } catch{
                        $yamlTemplateControl = @()
                    }
                }
                $svtResourceApprovalCheck = [ResourceApprovalCheck]::new();
                $svtResourceApprovalCheck.ResourceType = $resourceType;
                $svtResourceApprovalCheck.ResourceId = $resourceId;
                $svtResourceApprovalCheck.ApprovalCheckObj = $yamlTemplateControl;
                [ADOSVTBase]::ResourceApprovalChecks.add($svtResourceApprovalCheck);  
            }     
            
            $approvalChecks = [ADOSVTBase]::ResourceApprovalChecks | Where-Object {($_.ResourceId -eq $($resourceId)) -and ($_.ResourceType -eq $($resourceType))} 
            return $approvalChecks;
    }


}
#Class used to create Resource Approval Check list inside resolver
class ResourceApprovalCheck
{
	[string] $ResourceId = "";	    
    [string] $ResourceType = "";    
    [PSObject] $ApprovalCheckObj;        
}