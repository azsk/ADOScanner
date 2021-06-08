﻿<#
.Description
# SVTBase class for all service classes. 
# Provides functionality to create context object for resources, load controls for resource,
#>
Set-StrictMode -Version Latest
class SVTBase: AzSKRoot
{
	#Region: Properties
	hidden [string] $ResourceId = ""
    [ResourceContext] $ResourceContext = $null;
    hidden [SVTConfig] $SVTConfig
	hidden [PSObject] $ControlSettings
	
	hidden [ControlStateExtension] $ControlStateExt;
	
	hidden [ControlState[]] $ResourceState;
	hidden [ControlState[]] $DirtyResourceStates;

    hidden [ControlItem[]] $ApplicableControls = $null;
	hidden [ControlItem[]] $FeatureApplicableControls = $null;
	[string[]] $ChildResourceNames = $null;
	[System.Net.SecurityProtocolType] $currentSecurityProtocol;
	#User input parameters for controls
	[string[]] $FilterTags = @();
	[string[]] $ExcludeTags = @();
	[string[]] $ControlIds = @();
	[string[]] $Severity = @();
	[string[]] $ExcludeControlIds = @();
	[hashtable] $ResourceTags = @{}
	[bool] $GenerateFixScript = $false;

	[bool] $IncludeUserComments = $false;
	[string] $PartialScanIdentifier = [string]::Empty
	[ComplianceStateTableEntity[]] $ComplianceStateData = @();
	[PSObject[]] $ChildSvtObjects = @();
	[System.Diagnostics.Stopwatch] $StopWatch
	[Datetime] $ScanStart
	[Datetime] $ScanEnd
	[bool] $IsAIEnabled = $false;
	#EndRegion

	SVTBase([string] $organizationName):
        Base($organizationName)
    {		

	}
	SVTBase([string] $organizationName, [SVTResource] $svtResource):
	Base($organizationName, [SVTResource] $svtResource)
	{		
		$this.CreateInstance($svtResource);
	}


	#Create instance for resource scan
	hidden [void] CreateInstance([SVTResource] $svtResource)
	{
		[Helpers]::AbstractClass($this, [SVTBase]);

		#Region: validation for resource object 
		if(-not $svtResource)
		{
			throw [System.ArgumentException] ("The argument 'svtResource' is null");
		}

		if([string]::IsNullOrEmpty($svtResource.ResourceName))
		{
			throw [System.ArgumentException] ("The argument 'ResourceName' is null or empty");
		}
		#EndRegion

        if (-not $svtResource.ResourceTypeMapping)
		{
            throw [System.ArgumentException] ("No ResourceTypeMapping found");
        }

        if ([string]::IsNullOrEmpty($svtResource.ResourceTypeMapping.JsonFileName))
		{
            throw [System.ArgumentException] ("JSON file name is null or empty");
        }

		$this.ResourceId = $svtResource.ResourceId;

        $this.LoadSvtConfig($svtResource.ResourceTypeMapping.JsonFileName);

        $this.ResourceContext = [ResourceContext]@{
            ResourceGroupName = $svtResource.ResourceGroupName;
            ResourceName = $svtResource.ResourceName;
            ResourceType = $svtResource.ResourceTypeMapping.ResourceType;
			ResourceTypeName = $svtResource.ResourceTypeMapping.ResourceTypeName;
			ResourceId = $svtResource.ResourceId
			ResourceDetails = $svtResource.ResourceDetails
		};
		
		#<TODO Framework: Fetch resource group details from resolver itself>
		$this.ResourceContext.ResourceGroupTags = $this.ResourceTags;

		if ([RemoteReportHelper]::IsAIOrgTelemetryEnabled()) { 
			$this.IsAIEnabled =$true
		}
	}

   	hidden [void] LoadSvtConfig([string] $controlsJsonFileName)
    {
        $this.ControlSettings = $this.LoadServerConfigFile("ControlSettings.json");

        if (-not $this.SVTConfig) {

			#Check if SVTConfig is present in cache. If so, use that.
			$cachedPolicyContent = [ConfigurationHelper]::PolicyCacheContent | Where-Object { $_.Name -eq $controlsJsonFileName }
			if ($cachedPolicyContent)
			{
				$this.SVTConfig = $cachedPolicyContent.Content
				if ($this.SVTConfig)
				{
					return
				}
			}
            $this.SVTConfig =  [ConfigurationManager]::GetSVTConfig($controlsJsonFileName);
			
            $this.SVTConfig.Controls | Foreach-Object {

				#Expand description and recommendation string if any dynamic values defined field using control settings
                $_.Description = $global:ExecutionContext.InvokeCommand.ExpandString($_.Description)
                $_.Recommendation = $global:ExecutionContext.InvokeCommand.ExpandString($_.Recommendation)
				
				$ControlSeverity = $_.ControlSeverity
				
				#Check if ControlSeverity is customized/overridden using controlsettings configurations
                if([Helpers]::CheckMember($this.ControlSettings,"ControlSeverity.$ControlSeverity"))
                {
                    $_.ControlSeverity = $this.ControlSettings.ControlSeverity.$ControlSeverity
                }

				if(-not [string]::IsNullOrEmpty($_.MethodName))
				{
					$_.MethodName = $_.MethodName.Trim();
				}

				#Check if 
				if($this.CheckBaselineControl($_.ControlID))
				{
					$_.IsBaselineControl = $true
				}
				#AddPreviewBaselineFlag
				if($this.CheckPreviewBaselineControl($_.ControlID))
				{
					$_.IsPreviewBaselineControl = $true
				}
			}
			#Save the final, fully resolved SVTConfig JSON in cache
			#Because we may have the network/local-module content already in cached from a call to [ConfigurationHelper]::LoadServerConfigFile, we need to check first.
			#If there is an entry, we just overwrite the Content portion. If there is on entry, we create a new one.
			[bool] $ConfigFoundInCache = $false
			[ConfigurationHelper]::PolicyCacheContent | Foreach-Object {
				if ($_.Name -eq $controlsJsonFileName)
				{
					$_.Content = $this.SVTConfig   #Overwrite the cached entry.
					$ConfigFoundInCache = $true
				} 
			}
			if (-not $ConfigFoundInCache)
			{
				$policy = [Policy]@{
					Name    = $controlsJsonFileName
					Content = $this.SVTConfig
				}
				[ConfigurationHelper]::PolicyCacheContent += $policy #Create a new entry.
			}
        }
    }
	#stub to be used when Baseline configuration exists 
	hidden [bool] CheckBaselineControl($controlId)
	{
		return $false
	}
	#stub to be used when PreviewBaseline configuration exists 
	hidden [bool] CheckPreviewBaselineControl($controlId)
	{
		return $false
	}


	#Check if service is under mentainance and display maintenance warning message
    [bool] ValidateMaintenanceState()
    {
        if ($this.SVTConfig.IsMaintenanceMode) {
            $this.PublishCustomMessage(([ConfigurationManager]::GetAzSKConfigData().MaintenanceMessage -f $this.SVTConfig.FeatureName), [MessageType]::Warning);
        }
        return $this.SVTConfig.IsMaintenanceMode;
    }

    hidden [ControlResult] CreateControlResult([string] $childResourceName, [VerificationResult] $verificationResult)
    {
        [ControlResult] $control = [ControlResult]@{
            VerificationResult = $verificationResult;
        };

        if(-not [string]::IsNullOrEmpty($childResourceName))
        {
            $control.ChildResourceName = $childResourceName;
        }

		[SessionContext] $sc = [SessionContext]::new();
		$sc.IsLatestPSModule = $this.RunningLatestPSModule;
		$control.CurrentSessionContext = $sc;

        return $control;
    }

    [ControlResult] CreateControlResult()
    {
        return $this.CreateControlResult("", [VerificationResult]::Manual);
    }

	hidden [ControlResult] CreateControlResult([FixControl] $fixControl)
    {
        $control = $this.CreateControlResult();
		if($this.GenerateFixScript -and $fixControl -and $fixControl.Parameters -and ($fixControl.Parameters | Get-Member -MemberType Properties | Measure-Object).Count -ne 0)
		{
			$control.FixControlParameters = $fixControl.Parameters | Select-Object -Property *;
		}
		return $control;
    }

	[ControlResult] CreateControlResult([string] $childResourceName)
    {
        return $this.CreateControlResult($childResourceName, [VerificationResult]::Manual);
    }

	[ControlResult] CreateChildControlResult([string] $childResourceName, [ControlResult] $controlResult)
    {
        $control = $this.CreateControlResult($childResourceName, [VerificationResult]::Manual);
		if($controlResult.FixControlParameters -and ($controlResult.FixControlParameters | Get-Member -MemberType Properties | Measure-Object).Count -ne 0)
		{
			$control.FixControlParameters = $controlResult.FixControlParameters | Select-Object -Property *;
		}
		return $control;
    }

	hidden [SVTEventContext] CreateSVTEventContextObject()
	{
		return [SVTEventContext]@{
			FeatureName = $this.ResourceContext.ResourceTypeName #$this.ResourceContext.ResourceTypeName bcz feature and rtn is same and feature name is coming from control.json file, in case of generic it will have generic name
			Metadata = [Metadata]@{
				Reference = $this.SVTConfig.Reference;
			};

            OrganizationContext = $this.OrganizationContext;
            ResourceContext = $this.ResourceContext;
			PartialScanIdentifier = $this.PartialScanIdentifier
			
        };
	}

    hidden [SVTEventContext] CreateErrorEventContext([System.Management.Automation.ErrorRecord] $exception)
    {
        [SVTEventContext] $arg = $this.CreateSVTEventContextObject();
        $arg.ExceptionMessage = $exception;

        return $arg;
    }

    hidden [void] ControlStarted([SVTEventContext] $arg)
    {
        $this.PublishEvent([SVTEvent]::ControlStarted, $arg);
    }

    hidden [void] ControlDisabled([SVTEventContext] $arg)
    {
        $this.PublishEvent([SVTEvent]::ControlDisabled, $arg);
    }

    hidden [void] ControlCompleted([SVTEventContext] $arg)
    {
        $this.PublishEvent([SVTEvent]::ControlCompleted, $arg);
    }

    hidden [void] ControlError([ControlItem] $controlItem, [System.Management.Automation.ErrorRecord] $exception)
    {
        $arg = $this.CreateErrorEventContext($exception);
        $arg.ControlItem = $controlItem;
        $this.PublishEvent([SVTEvent]::ControlError, $arg);
    }

    hidden [void] EvaluationCompleted([SVTEventContext[]] $arguments)
    {
        $this.PublishEvent([SVTEvent]::EvaluationCompleted, $arguments);
    }

    hidden [void] EvaluationStarted()
    {
        $this.PublishEvent([SVTEvent]::EvaluationStarted, $this.CreateSVTEventContextObject());
	}
	
    hidden [void] EvaluationError([System.Management.Automation.ErrorRecord] $exception)
    {
        $this.PublishEvent([SVTEvent]::EvaluationError, $this.CreateErrorEventContext($exception));
    }

    [SVTEventContext[]] EvaluateAllControls()
    {
        [SVTEventContext[]] $resourceSecurityResult = @();
        if (-not $this.ValidateMaintenanceState()) {
			if($this.GetApplicableControls().Count -eq 0)
			{
				if($this.ResourceContext)
				{
					$this.PublishCustomMessage("No controls have been found to evaluate for Resource [$($this.ResourceContext.ResourceName)]", [MessageType]::Warning);
					$this.PublishCustomMessage("$([Constants]::SingleDashLine)");
				}
				else
				{
					$this.PublishCustomMessage("No controls have been found to evaluate for organization", [MessageType]::Warning);
				}
			}
			else
			{
				$this.PostTelemetry();
				$this.EvaluationStarted();	
				$resourceSecurityResult += $this.GetAutomatedSecurityStatus();
				$resourceSecurityResult += $this.GetManualSecurityStatus();			
				
				$this.InvokeExtensionMethod($resourceSecurityResult)
                #Call the ADOSVTBase PostEvaluationCompleted method which read the attestation data and modify conntrol result.
				$this.PostEvaluationCompleted($resourceSecurityResult);
				$this.EvaluationCompleted($resourceSecurityResult);
			}
        }
        return $resourceSecurityResult;
	}

	[SVTEventContext[]] RescanAndPostAttestationData()
    {
		[SVTEventContext[]] $resourceScanResult = @();
		[SVTEventContext[]] $stateResult = @();
		[ControlItem[]] $controlsToBeEvaluated = @();

		$this.PostTelemetry();
		#Publish event to display host message to indicate start of resource scan 
		$this.EvaluationStarted();	
		#Fetch attested controls list from Blob
		$stateResult = $this.GetControlsStateResult($true)
		If (($stateResult | Measure-Object).Count -gt 0 )
		{
			#Get controls list which were attested in last 24 hours
			$attestedControlsinBlob = $stateResult | Where-Object {$_.ControlResults.StateManagement.AttestedStateData.AttestedDate -gt ((Get-Date).AddDays(-1))}
			if (($attestedControlsinBlob | Measure-Object).Count -gt 0 )
			{
				$attestedControlsinBlob | ForEach-Object {
					$controlsToBeEvaluated += $_.ControlItem
				};
				$this.ApplicableControls = @($controlsToBeEvaluated);
				$resourceScanResult += $this.GetAutomatedSecurityStatus();
				$resourceScanResult += $this.GetManualSecurityStatus();

				$this.PostEvaluationCompleted($resourceScanResult);
				$this.EvaluationCompleted($resourceScanResult);
			}
			else {
				Write-Host "No attested control found.`n$([Constants]::SingleDashLine)" 
			}
		}
		else {
			Write-Host "No attested control found.`n$([Constants]::SingleDashLine)" 
		}
         return $resourceScanResult;
	}

	[void] PostTelemetry()
	{
	    # Setting the protocol for databricks
		if([Helpers]::CheckMember($this.ResourceContext, "ResourceType") -and $this.ResourceContext.ResourceType -eq "Microsoft.Databricks/workspaces")
		{
			$this.currentSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
			[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
		}
		$this.PostFeatureControlTelemetry()
	}

	[void] PostFeatureControlTelemetry()
	{
		#todo add check for latest module version
		if($this.RunningLatestPSModule -and ($this.FeatureApplicableControls | Measure-Object).Count -gt 0)
		{
			[CustomData] $customData = [CustomData]::new();
			$customData.Name = "FeatureControlTelemetry";
			$ResourceObject = "" | Select ResourceContext, Controls, ChildResourceNames;
			$ResourceObject.ResourceContext = $this.ResourceContext;
			$ResourceObject.Controls = $this.FeatureApplicableControls;
			$ResourceObject.ChildResourceNames = $this.ChildResourceNames;
			$customData.Value = $ResourceObject;
			$this.PublishCustomData($customData);		
		}
	}

	[SVTEventContext[]] FetchStateOfAllControls()
    {
        [SVTEventContext[]] $resourceSecurityResult = @();
        if (-not $this.ValidateMaintenanceState()) {
			if($this.GetApplicableControls().Count -eq 0)
			{
				$this.PublishCustomMessage("No security controls match the input criteria specified", [MessageType]::Warning);
			}
			else
			{
				$this.EvaluationStarted();
				$resourceSecurityResult += $this.GetControlsStateResult();
				if(($resourceSecurityResult | Measure-Object).Count -gt 0)
				{
					$this.EvaluationCompleted($resourceSecurityResult);
				}
			}
        }
        return $resourceSecurityResult;
	}


	[ControlItem[]] ApplyServiceFilters([ControlItem[]] $controls)
	{
		return $controls;
	}

	hidden [ControlItem[]] GetApplicableControls()
	{
		#Lazy load the list of the applicable controls
		#If applicablecontrol is already there in singleton object case, then need to filter again for different resourcetype
		#Second condition (in case of singleton) ApplicableControls will not empty for second resource scan in and check if resource type is different 
		if($null -eq $this.ApplicableControls -or ($this.ApplicableControls -and !($this.ApplicableControls[0].Id.StartsWith($this.ResourceContext.ResourceTypeName)) ) )
		{
			$this.ApplicableControls = @();
			$this.FeatureApplicableControls = @();
			$filterControlsById = @();
			$filteredControls = @();

			#Apply service filters based on default set of controls
			$this.FeatureApplicableControls += $this.ApplyServiceFilters($this.SVTConfig.Controls);

			if($this.ControlIds.Count -ne 0)
			{
                $filterControlsById += $this.FeatureApplicableControls | Where-Object { $this.ControlIds -Contains $_.ControlId };
			}
			else
			{
				$filterControlsById += $this.FeatureApplicableControls
			}

			if($this.ExcludeControlIds.Count -ne 0)
			{
				$filterControlsById = $filterControlsById | Where-Object { $this.ExcludeControlIds -notcontains $_.ControlId };
			}

			#Filter controls based on filterstags and excludetags
			$filterTagsCount = ($this.FilterTags | Measure-Object).Count
            $excludeTagsCount = ($this.ExcludeTags | Measure-Object).Count

			#filters controls based on Severity
			if($this.Severity.Count -ne 0 -and ($filterControlsById | Measure-Object).Count -gt 0)
			{
				$filterControlsById = $filterControlsById | Where-Object {$_.ControlSeverity -in $this.Severity };				
			}

			
            $unfilteredControlsCount = ($filterControlsById | Measure-Object).Count

			if($unfilteredControlsCount -gt 0) #If we have any controls at this point...
            {
                #If FilterTags are specified, limit the candidate set to matching controls
                if ($filterTagsCount -gt 0)
                {
                    #Look at each candidate control's tags and see if there's a match in FilterTags
                    $filterControlsById | ForEach-Object {
                        Set-Variable -Name control -Value $_ -Scope Local
                        Set-Variable -Name filterMatch -Value $false -Scope Local
                        
						$filterMatch = $false
												
						$control.Tags | ForEach-Object {
													Set-Variable -Name cTag -Value $_ -Scope Local

													if( ($this.FilterTags | Where-Object { $_ -like $cTag} | Measure-Object).Count -ne 0)
													{
														$filterMatch = $true
													}
												}

                        #Add if this control has a tag that matches FilterTags 
                        if ($filterMatch) 
                        {
                            $filteredControls += $control
                        }   
                    }                     
                }
                else #No FilterTags specified, so all controls qualify
                {
                    $filteredControls = $filterControlsById
                }

                #Note: Candidate controls list is now in $filteredControls...we will use that to calculate $filteredControlsFinal
                $filteredControlsFinal = @()
                if ($excludeTagsCount -eq 0)
                {
                    #If exclude tags are not specified, then not much to do.
                    $filteredControlsFinal = $filteredControls
                }
                else 
                {
                    #ExludeTags _are_ specified, we need to check if candidate set has to be reduced...
                    
                    #Look at each candidate control's tags and see if there's a match in ExcludeTags
                    $filteredControls | ForEach-Object {
                        Set-Variable -Name control -Value $_ -Scope Local
                        Set-Variable -Name excludeMatch -Value $false -Scope Local
                        $excludeMatch = $false

                        $control.Tags | ForEach-Object {
                              Set-Variable -Name cTag -Value $_ -Scope Local

                              if(($this.ExcludeTags | Where-Object { $_ -like $cTag} | Measure-Object).Count -ne 0)
                              {
                                    $excludeMatch = $true
                              }
                        }
                        
                        #Add to final list if this control *does-not* have a tag that matches ExcludeTags
                        if (-not $excludeMatch) 
                        {
                            $filteredControlsFinal += $control
                        }   
					}
					$filteredControls = $filteredControlsFinal                
                } 
            }

			$this.ApplicableControls = $filteredControls;
			#this filtering has been done as the first step it self;
			#$this.ApplicableControls += $this.ApplyServiceFilters($filteredControls);
			
		}
		#filter control for generic common control 
		if ($this.SVTConfig.FeatureName -eq "CommonConfigForControlScan") {
			$controlstoscan = @();
			$controlstoscan += $this.ApplicableControls | Where {$_.Id.StartsWith($this.ResourceContext.ResourceTypeName)};
			$this.ApplicableControls = $controlstoscan;
		}
		return $this.ApplicableControls;
	}

    hidden [SVTEventContext[]] GetManualSecurityStatus()
    {
        [SVTEventContext[]] $manualControlsResult = @();
        try
        {
            $this.GetApplicableControls() | Where-Object { $_.Automated -eq "No" -and $_.Enabled -eq $true } |
            ForEach-Object {
                $controlItem = $_;
				[SVTEventContext] $arg = $this.CreateSVTEventContextObject();

				$arg.ControlItem = $controlItem;
				[ControlResult] $control = [ControlResult]@{
					VerificationResult = [VerificationResult]::Manual;
				};

				[SessionContext] $sc = [SessionContext]::new();
				$sc.IsLatestPSModule = $this.RunningLatestPSModule;
				$control.CurrentSessionContext = $sc;

				$arg.ControlResults += $control
				
				$this.PostProcessData($arg);

                $manualControlsResult += $arg;
            }
        }
        catch
        {
            $this.EvaluationError($_);
        }

        return $manualControlsResult;
    }

    hidden [SVTEventContext[]] GetAutomatedSecurityStatus()
    {
		[SVTEventContext[]] $automatedControlsResult = @();

		if ($this.IsAIEnabled)
		{
			$this.StopWatch = [System.Diagnostics.Stopwatch]::StartNew();
		}
		
		$this.DirtyResourceStates = @();
        try
        {
			$this.GetApplicableControls() | Where-Object { $_.Automated -ne "No" -and (-not [string]::IsNullOrEmpty($_.MethodName)) } |
            ForEach-Object {
				$evaluateControl = $true; 
				# if control is disabled and warning message is also disabled in org policy than do not evaluate the control.
				if ($this.ControlSettings -and [Helpers]::CheckMember($this.ControlSettings, "DisableWarningMessage") -and $this.ControlSettings.DisableWarningMessage -eq $true -and $_.Enabled -eq $false) {
						$evaluateControl = $false;
				}
				if ($evaluateControl)
				{
					$eventContext = $this.RunControl($_);
					if($null -ne $eventContext -and $eventcontext.ControlResults.Length -gt 0)
					{
						$automatedControlsResult += $eventContext;
					}
				}
            };
        }
        catch
        {
            $this.EvaluationError($_);
        }

        return $automatedControlsResult;
	}

	hidden [SVTEventContext[]] GetControlsStateResult($isRescan = $false)
    {
        [SVTEventContext[]] $automatedControlsResult = @();
		$this.DirtyResourceStates = @();
        try
        {
            $this.GetApplicableControls() |
            ForEach-Object {
                $eventContext = $this.FetchControlState($_, $isRescan);
				#filter controls if there is no state found
				if($eventContext)
				{
					$eventContext.ControlResults = $eventContext.ControlResults | Where-Object{$_.AttestationStatus -ne [AttestationStatus]::None}
					if($eventContext.ControlResults)
					{
						$automatedControlsResult += $eventContext;
					}
				}
            };
        }
        catch
        {
            $this.EvaluationError($_);
        }

        return $automatedControlsResult;
	}
	
    hidden [SVTEventContext] RunControl([ControlItem] $controlItem)
    {
		[SVTEventContext] $singleControlResult = $this.CreateSVTEventContextObject();
        $singleControlResult.ControlItem = $controlItem;

        $this.ControlStarted($singleControlResult);
		if($controlItem.Enabled -eq $false)
        {
            $this.ControlDisabled($singleControlResult);
        }
        else
        {
			$azskScanResult = $this.CreateControlResult($controlItem.FixControl);
            try
            {
                $methodName = $controlItem.MethodName;
				#$this.CurrentControlItem = $controlItem;

				#Getting scan time for each control. This is being done to monitor perf issues in ADOScanner internally
				if ($this.IsAIEnabled)
				{
					$this.ScanStart = [DateTime]::UtcNow
					$this.StopWatch.Restart()
					$scanResult = $this.$methodName($azskScanResult);
					$this.StopWatch.Stop()
					$this.ScanEnd = [DateTime]::UtcNow

					$scanResult.TimeTakenInMs = $this.StopWatch.ElapsedMilliseconds
					$scanResult.ScanStartDateTime = $this.ScanStart
					$scanResult.ScanEndDateTime = $this.ScanEnd

					$singleControlResult.ControlResults += $scanResult	
				}	
				else
				{
					$singleControlResult.ControlResults += $this.$methodName($azskScanResult);
				}		
            }
            catch
            {
				$azskScanResult.VerificationResult = [VerificationResult]::Error				
				$azskScanResult.AddError($_);
				$singleControlResult.ControlResults += $azskScanResult
                $this.ControlError($controlItem, $_);
			}

			$this.PostProcessData($singleControlResult);

			$this.InvokeExtensionMethod($singleControlResult);

			# Check for the control which requires elevated permission to modify 'Recommendation' so that user can know it is actually automated if they have the right permission
			if($singleControlResult.ControlItem.Automated -eq "Yes")
			{
				$singleControlResult.ControlResults |
					ForEach-Object {
					$currentItem = $_;
					if($_.VerificationResult -eq [VerificationResult]::Manual -and $singleControlResult.ControlItem.Tags.Contains([Constants]::OwnerAccessTagName))
					{
						$singleControlResult.ControlItem.Recommendation = [Constants]::RequireOwnerPermMessage + $singleControlResult.ControlItem.Recommendation
					}
				}
			}
        }

		$this.ControlCompleted($singleControlResult);

        return $singleControlResult;
	}
	
	
	# Policy compliance methods begin
	hidden [ControlResult] ComputeFinalScanResult([ControlResult] $azskScanResult, [ControlResult] $policyScanResult)
	{
		if($policyScanResult.VerificationResult -ne [VerificationResult]::Failed -and $azskScanResult.VerificationResult -ne [VerificationResult]::Passed)
		{
			return $azskScanResult
		}
		else
		{
			return $policyScanResult;
		}
	}
	
	hidden AddResourceMetadata([PSObject] $metadataObj)
	{
		[hashtable] $resourceMetadata = New-Object -TypeName Hashtable;
			$metadataObj.psobject.properties |
				ForEach-Object {
					$resourceMetadata.Add($_.name, $_.value)
				}

		if([Helpers]::CheckMember($this.ControlSettings, 'AllowedResourceTypesForMetadataCapture') )
		{
			if( $this.ResourceContext.ResourceTypeName -in $this.ControlSettings.AllowedResourceTypesForMetadataCapture)
			{
				$this.ResourceContext.ResourceMetadata = $resourceMetadata
			}
			else
			{
				$this.ResourceContext.ResourceMetadata = $null
			}
		}
		else 
		{
			$this.ResourceContext.ResourceMetadata = $resourceMetadata
		}

	}

	hidden [SVTResource] CreateSVTResource([string] $ConnectionResourceId,[string] $ResourceGroupName, [string] $ConnectionResourceName, [string] $ResourceType, [string] $Location, [string] $MappingName)
	{
		$svtResource = [SVTResource]::new();
		$svtResource.ResourceId = $ConnectionResourceId; 
		$svtResource.ResourceGroupName = $ResourceGroupName;
		$svtResource.ResourceName = $ConnectionResourceName
		$svtResource.ResourceType = $ResourceType; # 
		$svtResource.Location = $Location;
		$svtResource.ResourceTypeMapping = ([SVTMapping]::AzSKADOResourceMapping |
						Where-Object { $_.ResourceTypeName -eq $MappingName } |
						Select-Object -First 1);

		return $svtResource;
	}
  
	#stub to be used when ComplianceState 
	hidden [void] GetDataFromSubscriptionReport($singleControlResult)
   	{ 
		
	}

	[int] hidden CalculateGraceInDays([SVTEventContext] $context)
	{
		
		$controlResult=$context.ControlResults;
		$computedGraceDays=15;
		$ControlBasedGraceExpiryInDays=0;
		$currentControlItem=$context.controlItem;
		$controlSeverity=$currentControlItem.ControlSeverity;
		if([Helpers]::CheckMember($this.ControlSettings,"NewControlGracePeriodInDays"))
		{
            if([Helpers]::CheckMember($this.ControlSettings,"ControlSeverity"))
            {
                $controlsev = $this.ControlSettings.ControlSeverity.PSobject.Properties | Where-Object Value -eq $controlSeverity | Select-Object -First 1
                $controlSeverity = $controlsev.name
                $computedGraceDays=$this.ControlSettings.NewControlGracePeriodInDays.ControlSeverity.$ControlSeverity;
            }
            else
            {
                $computedGraceDays=$this.ControlSettings.NewControlGracePeriodInDays.ControlSeverity.$ControlSeverity;
            }
		}
		if($null -ne $currentControlItem.GraceExpiryDate)
		{
			if($currentControlItem.GraceExpiryDate -gt [DateTime]::UtcNow )
			{
				$ControlBasedGraceExpiryInDays=$currentControlItem.GraceExpiryDate.Subtract($controlResult.FirstScannedOn).Days
				if($ControlBasedGraceExpiryInDays -gt $computedGraceDays)
				{
					$computedGraceDays = $ControlBasedGraceExpiryInDays
				}
			}			
		}

	  return $computedGraceDays;
	}	
}
