﻿Set-StrictMode -Version Latest
class ServicesSecurityStatus: ADOSVTCommandBase
{
	[SVTResourceResolver] $Resolver = $null;
	[bool] $IsPartialCommitScanActive = $false;
	[System.Diagnostics.Stopwatch] $StopWatch
	[Datetime] $ScanStart
	[Datetime] $ScanEnd
	[bool] $IsAIEnabled = $false;
	[bool] $IsBugLoggingEnabled = $false;
	$ActualResourcesPerRsrcType = @(); # Resources count based on resource type . This count is evaluated before comparison with resource tracker file.

	ServicesSecurityStatus([string] $organizationName, [InvocationInfo] $invocationContext, [SVTResourceResolver] $resolver):
        Base($organizationName, $invocationContext)
    {
		if(-not $resolver)
		{
			throw [System.ArgumentException] ("The argument 'resolver' is null");
		}

		$this.Resolver = $resolver;
		$this.Resolver.LoadResourcesForScan();
		#If resource scan count is more than allowed foe scan (>1000) then stopping scan and returning.
		if (!$this.Resolver.SVTResources) {
			return;
		}
		$this.ActualResourcesPerRsrcType = $this.Resolver.SVTResources | Group-Object -Property ResourceType |select-object Name, Count           

		$this.UsePartialCommits = $invocationContext.BoundParameters["UsePartialCommits"];

		#BaseLineControlFilter with control ids
		$this.UseBaselineControls = $invocationContext.BoundParameters["UseBaselineControls"];
		$this.UsePreviewBaselineControls = $invocationContext.BoundParameters["UsePreviewBaselineControls"];
		if ([RemoteReportHelper]::IsAIOrgTelemetryEnabled()) { 
			$this.IsAIEnabled = $true; 
		}
		if($invocationContext.BoundParameters["AutoBugLog"]){
			$this.IsBugLoggingEnabled = $true; 
		}
		if($invocationContext.BoundParameters["UseGraphAccess"]){
			[IdentityHelpers]::useGraphAccess = $true; 
		}
		[PartialScanManager]::ClearInstance();
		$this.BaselineFilterCheck();
		$this.UsePartialCommitsCheck();
	}

	hidden [SVTEventContext[]] RunForAllResources([string] $methodNameToCall, [bool] $runNonAutomated, [PSObject] $resourcesList)
	{
		$ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
		$scanSource = [AzSKSettings]::GetInstance().GetScanSource();

		if ($Env:AzSKADOUPCSimulate -eq $true)
		{
			$ControlSettings.PartialScan.LocalScanUpdateFrequency = $Env:AzSKADOLocalScanUpdateFrequency
			$ControlSettings.PartialScan.DurableScanUpdateFrequency = $Env:AzSKADODurableScanUpdateFrequency
		}

		if ([string]::IsNullOrWhiteSpace($methodNameToCall))
		{
			throw [System.ArgumentException] ("The argument 'methodNameToCall' is null. Pass the reference of method to call. e.g.: [YourClass]::new().YourMethod");
		}
		
		$this.Severity = $this.ConvertToStringArray($this.Severity) # to handle when no severity is passed in command
		if($this.Severity)
		{
			$this.Severity = [ControlHelper]::CheckValidSeverities($this.Severity);
			
		}
		[SVTEventContext[]] $result = @();
		
		if(($resourcesList | Measure-Object).Count -eq 0)
		{
			$this.PublishCustomMessage("No security controls/resources match the input criteria specified. `nPlease rerun the command using a different set of criteria.");
			return $result;
		}
		$this.PublishCustomMessage("Number of resources: $($this.resolver.SVTResourcesFoundCount)");
		$automatedResources = @();
		
		$automatedResources += ($resourcesList | Where-Object { $_.ResourceTypeMapping });
		
		# Resources skipped from scan using excludeResourceName parameter
		$ExcludedResources=$this.resolver.ExcludedResources ;
		if(($this.resolver.ExcludeResourceNames| Measure-Object).Count -gt 0)
		{
			$this.PublishCustomMessage("One or more resources/resource groups will be excluded from the scan based on exclude flags.")	
			if(-not [string]::IsNullOrEmpty($this.resolver.ExcludeResourceGroupWarningMessage))
			{
				$this.PublishCustomMessage("$($this.resolver.ExcludeResourceGroupWarningMessage)",[MessageType]::Warning)
				
			}
			if(-not [string]::IsNullOrEmpty($this.resolver.ExcludeResourceWarningMessage))
			{
				$this.PublishCustomMessage("$($this.resolver.ExcludeResourceWarningMessage)",[MessageType]::Warning)
			}
			$this.PublishCustomMessage("Summary of exclusions: ");

			$this.PublishCustomMessage("	Resources excluded: $(($ExcludedResources | Measure-Object).Count)(includes RGs,resourcetypenames and explicit exclusions).", [MessageType]::Info);	
			$this.PublishCustomMessage("For a detailed list of excluded resources, see 'ExcludedResources-$($this.RunIdentifier).txt' in the output log folder.")
			$this.ReportExcludedResources($this.resolver);
		}
		if($runNonAutomated)
		{
			$this.ReportNonAutomatedResources();
		}

		#Begin-perf-optimize for ControlIds parameter  
		#If controlIds are specified  filter only to applicable resources
		#Filter resources based control tags like OwnerAccess, GraphAccess,RBAC, Authz, SOX etc 
		$this.MapTagsToControlIds();
		#Filter automated resources based on control ids 
        $automatedResources = $this.MapControlsToResourceTypes($automatedResources)
		#End-perf-optimize
					
		$this.PublishCustomMessage("`nNumber of resources for which security controls will be evaluated: $($automatedResources.Count)",[MessageType]::Info);
		
        if ($this.IsAIEnabled)
        {
            $this.StopWatch = New-Object System.Diagnostics.Stopwatch
            #Send Telemetry for actual resource count. This is being done to monitor perf issues in ADOScanner internally
            if ($this.UsePartialCommits)
            {
                $resourceTypeCountHT = @{}
                foreach ($resType in $this.ActualResourcesPerRsrcType) 
                {
                    $resourceTypeCountHT["$($resType.Name)"] = "$($resType.Count)"
                }
				
				[AIOrgTelemetryHelper]::TrackCommandExecution("Actual Resources Count",
					@{"RunIdentifier" = $this.RunIdentifier}, $resourceTypeCountHT, $this.InvocationContext);
            }
            #Send Telemetry for target resource count (after partial commits has been checked). This is being done to monitor perf issues in ADOScanner internally
            $resourceTypeCount =$automatedResources | Group-Object -Property ResourceType |select-object Name, Count
            $resourceTypeCountHT = @{}
            foreach ($resType in $resourceTypeCount) 
            {
                $resourceTypeCountHT["$($resType.Name)"] = "$($resType.Count)"
            }
            $memoryUsage = [System.Diagnostics.Process]::GetCurrentProcess().PrivateMemorySize64 / [Math]::Pow(10,6)
            $resourceTypeCountHT += @{MemoryUsageInMB = $memoryUsage}
			
            [AIOrgTelemetryHelper]::TrackCommandExecution("Target Resources Count",
                @{"RunIdentifier" = $this.RunIdentifier}, $resourceTypeCountHT, $this.InvocationContext);
        }

		$totalResources = $automatedResources.Count;
		[int] $currentCount = 0;
		$childResources = @();
		$automatedResources | ForEach-Object {
			$exceptionMessage = "Exception for resource: [ResourceType: $($_.ResourceTypeMapping.ResourceTypeName)] [ResourceGroupName: $($_.ResourceGroupName)] [ResourceName: $($_.ResourceName)]"
            try
            {
				if ($this.IsAIEnabled)
				{
					$this.ScanStart = [DateTime]::UtcNow
					$this.StopWatch.Restart()
				}

				$currentCount += 1;
				if($totalResources -gt 1)
				{
					$this.PublishCustomMessage(" `r`nChecking resource [$currentCount/$totalResources] ");
				}
				
				$svtClassName = $_.ResourceTypeMapping.ClassName;

				$svtObject = $null;

                #Update resource scan retry count in scan snapshot in storage if user partial commit switch is on
				if($this.UsePartialCommits)
				{
					$this.UpdateRetryCountForPartialScan();
				}

				try
				{
					$extensionSVTClassName = $svtClassName + "Ext";
					$extensionSVTClassFilePath = $null

					#Check if the extended class of this type is already loaded?
					if(-not ($extensionSVTClassName -as [type]))
					{
						#Check if we know from a previous attempt that this 'type' has not been extended.
						if ([ConfigurationHelper]::NotExtendedTypes.containsKey($svtClassName))
						{
							$extensionSVTClassFilePath = $null
						}
						else 
						{
							$extensionSVTClassFilePath = [ConfigurationManager]::LoadExtensionFile($svtClassName); 
							if ([string]::IsNullOrEmpty($extensionSVTClassFilePath))
							{
								[ConfigurationHelper]::NotExtendedTypes["$svtClassName"] = $true
							}
						}

						#If $extensionSVTClassFilePath is null => use the built-in type from our module.
						if([string]::IsNullOrWhiteSpace($extensionSVTClassFilePath))
						{
							$svtObject = New-Object -TypeName $svtClassName -ArgumentList $this.OrganizationContext.OrganizationName, $_
						}
						else #Use extended type.
						{
							# file has to be loaded here due to scope contraint
							Write-Warning "########## Loading extended type [$extensionSVTClassName] into memory ##########"
							. $extensionSVTClassFilePath
							$svtObject = New-Object -TypeName $extensionSVTClassName -ArgumentList $this.OrganizationContext.OrganizationName, $_
						}
					}
					else 
					{
                       # Extended type is already loaded. Create an instance of that type.
					   $svtObject = New-Object -TypeName $extensionSVTClassName -ArgumentList $this.OrganizationContext.OrganizationName, $_						
					}

				}
				catch
				{
					$this.PublishCustomMessage($exceptionMessage);
					# Unwrapping the first layer of exception which is added by New-Object function
					$this.CommandError($_.Exception.InnerException.ErrorRecord);
				}

				[SVTEventContext[]] $currentResourceResults = @();
				if($svtObject)
				{
					$svtObject.RunningLatestPSModule = $this.RunningLatestPSModule;
					$this.SetSVTBaseProperties($svtObject);
					$childResources += $svtObject.ChildSvtObjects;
					$currentResourceResults += $svtObject.$methodNameToCall();
					$result += $currentResourceResults;
				}
				
				if([Organization]::InstalledextensionInfo)
				{
					# Default value if property 'ExtensionsLastUpdatedInYears' not exist in ControlSettings
					$years = 2
					
					# Fetching property 'ExtensionsLastUpdatedInYears' from ControlSettings to print in csv column.
					if([Helpers]::CheckMember($svtObject.ControlSettings, "Organization.ExtensionsLastUpdatedInYears"))
                    {
                        $years = $svtObject.ControlSettings.Organization.ExtensionsLastUpdatedInYears
					}
					$folderpath=([WriteFolderPath]::GetInstance().FolderPath) + "\$($_.ResourceName)"+"_ExtensionInfo.csv";
					$MaxScore = [Organization]::InstalledextensionInfo[0].MaxScore
					[Organization]::InstalledextensionInfo | Select-Object extensionName,publisherId,KnownPublisher,publisherName,version,@{Name = "Too Old (>$($years)year(s))"; Expression = { $_.TooOld } },@{Name = "LastPublished (MM-dd-yyyy)"; Expression = { $_.lastPublished} },@{Name = "Sensitive Permissions"; Expression = { $_.SensitivePermissions} },@{Name = "NonProd (ExtensionName)"; Expression = { $_.NonProdByName}},@{Name = "NonProd (Galleryflags) "; Expression = { $_.Preview }},TopPublisher,PrivateVisibility,NoOfInstalls,MarketPlaceAverageRating,@{Name = "Score (Out of $($MaxScore))"; Expression = { $_.Score } } | Export-Csv -Path $folderpath -NoTypeInformation #The NoTypeInformation parameter removes the #TYPE information header from the CSV output 
					[Organization]::InstalledExtensionInfo = @()   # Clearing the static variable value so that extensioninfo.csv file gets generated only once and when computed during the installed extension control
				}

				$memoryUsage = 0
				if(($result | Measure-Object).Count -gt 0 -and $this.UsePartialCommits)
				{
					$updateSucceeded = $false
					
					if ([system.String]::IsNullOrEmpty($scanSource) -or $scanSource -eq "SDL")
					{
						if($currentCount % $ControlSettings.PartialScan.LocalScanUpdateFrequency -eq 0 -or $currentCount -eq $totalResources)
						{
							# Update local resource tracker file
							$this.UpdatePartialCommitFile($false, $result)
							$updateSucceeded = $true
						}	
					}	
					else{			
						if($currentCount % $ControlSettings.PartialScan.DurableScanUpdateFrequency -eq 0 -or $currentCount -eq $totalResources)
						{
							# Update durable resource tracker file
							$this.UpdatePartialCommitFile($true, $result)
							$updateSucceeded = $true
						}	
					}	
					if ($updateSucceeded)		
					{
						[SVTEventContext[]] $result = @();
						[System.GC]::Collect();
                        $memoryUsage = [System.Diagnostics.Process]::GetCurrentProcess().PrivateMemorySize64 / [Math]::Pow(10,6)
					}	
				}
				
				#Send Telemetry for scan time taken for a resource. This is being done to monitor perf issues in ADOScanner internally
				if ($this.IsAIEnabled)
				{
					$this.StopWatch.Stop()
					$this.ScanEnd = [DateTime]::UtcNow
					
					$properties =  @{ 
						TimeTakenInMs = $this.StopWatch.ElapsedMilliseconds;
						ResourceCount = "$currentCount/$totalResources"; 
						ResourceName = $svtObject.ResourceContext.ResourceName;
						ResourceType = $svtObject.ResourceContext.ResourceType ;
						ScanStartDateTime = $this.ScanStart;
						ScanEndDateTime = $this.ScanEnd;
						RunIdentifier = $this.RunIdentifier;
					}
					if ($memoryUsage -gt 0)
					{
						$properties += @{MemoryUsageInMB = $memoryUsage;}
					}

					[AIOrgTelemetryHelper]::PublishEvent( "Resource Scan Completed",$properties, @{})
				}

			}
            catch
            {
				$this.PublishCustomMessage($exceptionMessage);
				$this.CommandError($_);
            }
		}
		if(($childResources | Measure-Object).Count -gt 0)
		{
			try
			{
				[SVTEventContext[]] $childResourceResults = @();
				$temp=  $childResources |Sort-Object -Property @{Expression={$_.ResourceId}} -Unique
				$temp| ForEach-Object {
					$_.RunningLatestPSModule = $this.RunningLatestPSModule
					$this.SetSVTBaseProperties($_)
					$childResourceResults += $_.$methodNameToCall();
					
				}
				$result += $childResourceResults;
			}
			catch
			{
				$this.PublishCustomMessage($_);
				
			}
		}
		
		
		return $result;
	}

	hidden [SVTEventContext[]] RunAllControls()
	{
		return $this.RunForAllResources("EvaluateAllControls",$true,$this.Resolver.SVTResources)
	}

	hidden [void] ReportNonAutomatedResources()
	{
		$nonAutomatedResources = @();
		$nonAutomatedResources += ($this.Resolver.SVTResources | Where-Object { $null -eq $_.ResourceTypeMapping });

		if(($nonAutomatedResources|Measure-Object).Count -gt 0)
		{
			$this.PublishCustomMessage("Number of resources for which security controls will NOT be evaluated: $($nonAutomatedResources.Count)", [MessageType]::Warning);

			$nonAutomatedResTypes = [array] ($nonAutomatedResources | Select-Object -Property ResourceType -Unique);
			$this.PublishCustomMessage([MessageData]::new("Security controls are yet to be automated for the following service types: ", $nonAutomatedResTypes));

			$this.PublishAzSKRootEvent([AzSKRootEvent]::UnsupportedResources, $nonAutomatedResources);
		}
	}
    #Rescan controls post attestation
	hidden [SVTEventContext[]] ScanAttestedControls()
	{
		[ControlStateExtension] $ControlStateExt = [ControlStateExtension]::new($this.OrganizationContext, $this.InvocationContext);
		$ControlStateExt.UniqueRunId = $this.ControlStateExt.UniqueRunId;
		$ControlStateExt.Initialize($false);
		#$ControlStateExt.ComputeControlStateIndexer();
		[PSObject] $ControlStateIndexer = $null;
		foreach ($items in $this.Resolver.SVTResources) {
			$resourceType = $null;
			$projectName = $null;
			if ($items.ResourceType -ne "ADO.Organization") {
				
				if ($items.ResourceType -eq "ADO.Project") {
					$projectName = $items.ResourceName
					$resourceType = "Project";
				}
				else {
					$projectName = $items.ResourceGroupName
					$resourceType = $items.ResourceType
				}
			}
			else {
				$resourceType = "Organization";
			}
		  $ControlStateIndexer += $ControlStateExt.RescanComputeControlStateIndexer($projectName, $resourceType);
		}
		$ControlStateIndexer = $ControlStateIndexer | Select-Object * -Unique
		$resourcesAttestedinCurrentScan = @()
		if(($null -ne $ControlStateIndexer) -and ([Helpers]::CheckMember($ControlStateIndexer, "ResourceId")))
		{
			$resourcesAttestedinCurrentScan = $this.Resolver.SVTResources | Where-Object {$ControlStateIndexer.ResourceId -contains $_.ResourceId}
		}
		return $this.RunForAllResources("RescanAndPostAttestationData",$false,$resourcesAttestedinCurrentScan)
	}

	#BaseLine Control Filter Function
	[void] BaselineFilterCheck()
	{
		
		#Check if use baseline or preview baseline flag is passed as parameter
		if($this.UseBaselineControls -or $this.UsePreviewBaselineControls)
		{
			$ResourcesWithBaselineFilter =@()
			#Load ControlSetting file
			$ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");

			$baselineControlsDetails = $ControlSettings.BaselineControls
			#if baselineControls switch is available and baseline controls available in settings
			if ($null -ne $baselineControlsDetails -and ($baselineControlsDetails.ResourceTypeControlIdMappingList | Measure-Object).Count -gt 0 -and  $this.UseBaselineControls)
			{
				#Get resource type and control ids mapping from controlsetting object
				#$this.PublishCustomMessage("Running cmdlet with baseline resource types and controls.", [MessageType]::Warning);
				$baselineResourceTypes = $baselineControlsDetails.ResourceTypeControlIdMappingList | Select-Object ResourceType | Foreach-Object {$_.ResourceType}
				#Filter SVT resources based on baseline resource types
				$ResourcesWithBaselineFilter += $this.Resolver.SVTResources | Where-Object {$null -ne $_.ResourceTypeMapping -and   $_.ResourceTypeMapping.ResourceTypeName -in $baselineResourceTypes }
				
				#Get the list of control ids
				$controlIds = $baselineControlsDetails.ResourceTypeControlIdMappingList | Select-Object ControlIds | ForEach-Object {  $_.ControlIds }
				$BaselineControlIds = [system.String]::Join(",",$controlIds);
				if(-not [system.String]::IsNullOrEmpty($BaselineControlIds))
				{
					#Assign preview control list to ControlIds filter parameter. This controls gets filtered during scan.
					$this.ControlIds = $controlIds;

				}		
			}
			#If baseline switch is passed and there is no baseline control list present then throw exception 
			elseif (($baselineControlsDetails.ResourceTypeControlIdMappingList | Measure-Object).Count -eq 0 -and $this.UseBaselineControls) 
			{
				throw ([SuppressedException]::new(("There are no baseline controls defined for your org. No controls will be scanned."), [SuppressedExceptionType]::Generic))
			}

			#Preview Baseline Controls

			$previewBaselineControlsDetails = $null
			#if use preview baseline switch is passed and preview baseline list property present 
			if($this.UsePreviewBaselineControls -and [Helpers]::CheckMember($ControlSettings,"PreviewBaselineControls"))
			{
				$previewBaselineControlsDetails = $ControlSettings.PreviewBaselineControls
				#if preview baseline list is defined in settings
				if ($null -ne $previewBaselineControlsDetails -and ($previewBaselineControlsDetails.ResourceTypeControlIdMappingList | Measure-Object).Count -gt 0 )
				{
					
					$previewBaselineResourceTypes = $previewBaselineControlsDetails.ResourceTypeControlIdMappingList | Select-Object ResourceType | Foreach-Object {$_.ResourceType}
					#Filter SVT resources based on preview baseline baseline resource types
					$BaselineResourceList = @()
					if(($ResourcesWithBaselineFilter | Measure-Object).Count -gt 0)
					{
						$BaselineResourceList += $ResourcesWithBaselineFilter | Foreach-Object { $_.ResourceId}
					}
					$ResourcesWithBaselineFilter += $this.Resolver.SVTResources | Where-Object {$null -ne $_.ResourceTypeMapping -and  $_.ResourceTypeMapping.ResourceTypeName -in $previewBaselineResourceTypes -and $_.ResourceId -notin $BaselineResourceList }
					
					#Get the list of preview control ids
					$controlIds = $previewBaselineControlsDetails.ResourceTypeControlIdMappingList | Select-Object ControlIds | ForEach-Object {  $_.ControlIds }
					$previewBaselineControlIds = [system.String]::Join(",",$controlIds);
					if(-not [system.String]::IsNullOrEmpty($previewBaselineControlIds))
					{
						# Assign preview control list to ControlIds filter parameter. This controls gets filtered during scan.
						$this.ControlIds += $controlIds;
					}			
				}
				#If preview baseline switch is passed and there is no baseline control list present then throw exception 
				elseif (($previewBaselineControlsDetails.ResourceTypeControlIdMappingList | Measure-Object).Count -eq 0 -and $this.UsePreviewBaselineControls) 
				{
					if(($baselineControlsDetails.ResourceTypeControlIdMappingList | Measure-Object).Count -eq 0 -and $this.UseBaselineControls)
					{
						throw ([SuppressedException]::new(("There are no  baseline and preview-baseline controls defined for this policy. No controls will be scanned."), [SuppressedExceptionType]::Generic))
					}
					if(-not ($this.UseBaselineControls))
					{
						throw ([SuppressedException]::new(("There are no preview-baseline controls defined for your org. No controls will be scanned."), [SuppressedExceptionType]::Generic))
					} 		
				}
			}

			#Assign baseline filtered resources to SVTResources list (resource list to be scanned)
			if(($ResourcesWithBaselineFilter | Measure-Object).Count -gt 0)
			{
				$this.Resolver.SVTResources = $ResourcesWithBaselineFilter
			}
		}
	}

	[void] UpdateRetryCountForPartialScan()
	{
		[PartialScanManager] $partialScanMngr = [PartialScanManager]::GetInstance();
		#If Scan source is in supported sources or UsePartialCommits switch is available
		if ($this.UsePartialCommits)
		{
			$partialScanMngr.UpdateResourceScanRetryCount($_.ResourceId);
		}
	}


	[void] UpdatePartialCommitFile($isDurableStorageUpdate , $result)
	{
		[PartialScanManager] $partialScanMngr = [PartialScanManager]::GetInstance();
		#If Scan source is in supported sources or UsePartialCommits switch is available
		if ($isDurableStorageUpdate)
		{
			$partialScanMngr.WriteToDurableStorage();
		}
		else {
			$partialScanMngr.WriteToResourceTrackerFile();
		}
		# write to csv after every partial commit
		$partialScanMngr.WriteToCSV($result, [FileOutputBase]::CSVFilePath);

		# append summary counts
		$partialScanMngr.CollateSummaryData($result);

		# append summary counts for bug logging & append control results with bug logging data
		if($this.IsBugLoggingEnabled  -and [BugLogPathManager]::GetIsPathValid()){
			$partialScanMngr.CollateBugSummaryData($result);
		}
		
	}

	[void] UsePartialCommitsCheck()
    {
            #If Scan source is in supported sources or UsePartialCommits switch is available
            if ($this.UsePartialCommits)
            {
                #Load ControlSetting Resource Types and Filter resources
                if($this.CentralStorageAccount){
                    [PartialScanManager] $partialScanMngr = [PartialScanManager]::GetInstance($this.CentralStorageAccount, $this.OrganizationContext.OrganizationName);   
                }
                else{
                    [PartialScanManager] $partialScanMngr = [PartialScanManager]::GetInstance();
                }
                #$this.PublishCustomMessage("Running cmdlet under transactional mode. This will scan resources and store intermittent scan progress to Storage. It resume scan in next run if something breaks inbetween.", [MessageType]::Warning);
                #Validate if active resources list already available in store
                #If list not available in store. Get resources filtered by baseline resource types and store it storage
				$nonScannedResourcesList = @();
				if(($partialScanMngr.IsPartialScanInProgress($this.OrganizationContext.OrganizationName) -eq [ActiveStatus]::Yes)  )
                {
					$this.IsPartialCommitScanActive = $true;
                    $allResourcesList = $partialScanMngr.GetAllListedResources()
                    # Get list of non-scanned active resources
                    $nonScannedResourcesList = $partialScanMngr.GetNonScannedResources();
                    $this.PublishCustomMessage("Resuming scan from last commit. $(($nonScannedResourcesList | Measure-Object).Count) out of $(($allResourcesList | Measure-Object).Count) resources will be scanned.", [MessageType]::Warning);
                    $nonScannedResourceIdList = $nonScannedResourcesList | Select-Object Id | ForEach-Object { $_.Id}
                    #Filter SVT resources based on master resources list available and scan completed
                    #Commenting telemtry here to include PartialScanIdentifier
					#[AIOrgTelemetryHelper]::PublishEvent( "Partial Commit Details", @{"TotalSVTResources"= $($this.Resolver.SVTResources | Where-Object { $_.ResourceTypeMapping } | Measure-Object).Count;"UnscannedResource"=$(($nonScannedResourcesList | Measure-Object).Count); "ResourceToBeScanned" = ($this.Resolver.SVTResources | Where-Object {$_.ResourceId -in $nonScannedResourceIdList } | Measure-Object).Count;},$null)
                    $this.Resolver.SVTResources = $this.Resolver.SVTResources | Where-Object {$_.ResourceId -in $nonScannedResourceIdList }             
                }
                else{
                    $this.IsPartialCommitScanActive = $false;
					$resourceIdList =  $this.Resolver.SVTResources| Where-Object {$null -ne $_.ResourceTypeMapping} | Select ResourceId | ForEach-Object {  $_.ResourceId }
                	$partialScanMngr.CreateResourceMasterList($resourceIdList);
                    #This should fetch full list of resources to be scanned 
                    $nonScannedResourcesList = $partialScanMngr.GetNonScannedResources();
                }
				#Set unique partial scan identifier (used for correlating events in AI when partial scan resumes.)
				#ADOTODO: Move '12' to Constants.ps1 later.
                $this.PartialScanIdentifier = [Helpers]::ComputeHashShort($partialScanMngr.ResourceScanTrackerObj.Id,12)
                
                #Telemetry with addition for Subscription Id, PartialScanIdentifier and correction in count of resources
                #Need optimization for calcuations done for total resources.
                try{
                    $CompletedResources  = 0;
                    $IncompleteScans = 0;
                    $InErrorResources = 0;
                    $ScanResourcesList = $partialScanMngr.GetAllListedResources() 
                    
                    $ScanResourcesList | Group-Object -Property State | Select-Object Name,Count | ForEach-Object{
                        if($_.Name -eq "COMP")
                        {
                            $CompletedResources = $_.Count
                        }
                        elseif ($_.Name -eq "INIT") {
                            $IncompleteScans = $_.Count
                        }
                        elseif ($_.Name -eq "ERR") {
                            $InErrorResources = $_.Count
                        }
                          
                    }   
                    [AIOrgTelemetryHelper]::PublishEvent( "Partial Commit Details",@{"TotalSVTResources"= $($ScanResourcesList |Measure-Object).Count;"ScanCompletedResourcesCount"=$CompletedResources; "NonScannedResourcesCount" = $IncompleteScans;"ErrorStateResourcesCount"= $InErrorResources;"OrganizationName"=$this.OrganizationContext.OrganizationName;"PartialScanIdentifier"=$this.PartialScanIdentifier;}, $null)
                }
                catch{
                    #Continue exexution if telemetry is not sent 
                }            
        }
}


	#Get list of controlIds based control tags like OwnerAccess, GraphAccess,RBAC, Authz, SOX etc.
	[void] MapTagsToControlIds()
	{
		#Check if filtertags or exclude filter tags parameter is passed from user then get mapped control ids
		if(-not [string]::IsNullOrEmpty($this.FilterTags) ) #-or -not [string]::IsNullOrEmpty($this.ExcludeTags)
		{
			$resourcetypes = @() 
			$controlList = @()
			#Get list of all supported resource Types
			$resourcetypes += ([SVTMapping]::AzSKADOResourceMapping | Sort-Object ResourceTypeName | Select-Object JsonFileName )

			$resourcetypes | ForEach-Object{
				#Fetch control json for all resource type and collect all control jsons
				$controlJson = [ConfigurationManager]::GetSVTConfig($_.JsonFileName); 
				if ([Helpers]::CheckMember($controlJson, "Controls")) 
				{
					$controlList += $controlJson.Controls | Where-Object {$_.Enabled}
				}
			}

			#If FilterTags are specified, limit the candidate set to matching controls
			if (-not [string]::IsNullOrEmpty($this.FilterTags))
			{
				$filterTagList = $this.ConvertToStringArray($this.FilterTags)
				$controlIdsWithFilterTagList = @()
				#Look at each candidate control's tags and see if there's a match in FilterTags
				$filterTagList | ForEach-Object {
					$tagName = $_ 
					$controlIdsWithFilterTagList += $controlList | Where-Object{ $tagName -in $_.Tags  } | ForEach-Object{ $_.ControlId}
				}
				#Assign filtered control Id with tag name 
				$this.ControlIds = $controlIdsWithFilterTagList
			}

			#********** Commentiing Exclude tags logic as this will not require perf optimization as excludeTags mostly will result in most of the resources
			# #If FilterTags are specified, limit the candidate set to matching controls
			# #Note: currently either includeTag or excludeTag will work at a time. Combined flag result will be overridden by excludeTags 
			# if (-not [string]::IsNullOrEmpty($this.ExcludeTags))
			# {
			# 	$excludeFilterTagList = $this.ConvertToStringArray($this.ExcludeTags)
			# 	$controlIdsWithFilterTagList = @()
			# 	#Look at each candidate control's tags and see if there's a match in FilterTags
			# 	$excludeFilterTagList | ForEach-Object {
			# 		$tagName = $_ 
			# 		$controlIdsWithFilterTagList += $controlList | Where-Object{ $tagName -notin $_.Tags  } | ForEach-Object{ $_.ControlId}
			# 	}
			# 	#Assign filtered control Id with tag name 
			# 	$this.ControlIds = $controlIdsWithFilterTagList
			# }
		}		
	}

	[PSObject] MapControlsToResourceTypes([PSObject] $automatedResources)
	{
		$allTargetControlIds = @($this.ControlIds)
		$allTargetControlIds += $this.ConvertToStringArray($this.ControlIdString)
		#Do this only for the actual controlIds case (not the Severity-Spec "Severity:High" case)
        if ($allTargetControlIds.Count -gt 0 )
        {
            #Infer resource type names from control ids 
            $allTargetResourceTypeNames = @($allTargetControlIds | ForEach-Object { ($_ -split '_')[1]})
            $allTargetResourceTypeNamesUnique = @($allTargetResourceTypeNames | Sort-Object -Unique)
            #Match resources based on resource types. Here we have made exception for AzSKCfg to scan it every time and virtual network as its type name (VirtualNetwork) is different than controls type name (VNet) 
            $automatedResources = @($automatedResources | Where-Object {$allTargetResourceTypeNamesUnique -contains $_.ResourceTypeMapping.ResourceTypeName -or $_.ResourceType -match 'AzSKCfg' -or ($_.ResourceTypeMapping.ResourceTypeName -match 'VirtualNetwork' -and $allTargetResourceTypeNamesUnique -contains "VNet")})
		}
		return $automatedResources
	}
	
	[void] ReportExcludedResources($SVTResolver)
	{
		$excludedObj=New-Object -TypeName PSObject;

		$excludedObj | Add-Member -NotePropertyName ExcludedResources -NotePropertyValue $SVTResolver.ExcludedResources
		$excludedObj | Add-Member -NotePropertyName ExcludedResourceType -NotePropertyValue $SVTResolver.ExcludeResourceTypeName 
		$excludedObj | Add-Member -NotePropertyName ExcludeResourceNames -NotePropertyValue $SVTResolver.ExcludeResourceNames 
		$this.PublishAzSKRootEvent([AzSKRootEvent]::WriteExcludedResources,$excludedObj);
	}
	
}