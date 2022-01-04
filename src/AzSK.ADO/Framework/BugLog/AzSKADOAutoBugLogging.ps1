using namespace System.Management.Automation
Set-StrictMode -Version Latest 

class AzSKADOAutoBugLogging : CommandBase
{    
    [string] $OrgName
    [string] $BugLogProjectName
    $ScanResult = @();
    $ScanResultToCloseBug = @();
    hidden [InvocationInfo] $InvocationContext;
    hidden [bool] $IsLAFile = $false;
    $ResourceControlJson = @();
    $BugTemplate = $null;
    $STMappingFilePath = $null;
    $BugDescription = $null;


	AzSKADOAutoBugLogging([string] $organizationName, $BugLogProject, $AutoBugLog, $ResourceTypeName, $ControlIds, $scanResultData, $BugTemplate, [InvocationInfo] $invocationContext, $isLAFile, $stMappingFilePath, $BugDescription): 
        Base($organizationName, $invocationContext) 
    { 
        $this.OrgName = $organizationName;
        $this.BugLogProjectName = $BugLogProject;
        $this.IsLAFile = $isLAFile;
        $this.BugTemplate = $BugTemplate;
        $this.STMappingFilePath = $stMappingFilePath;
        $this.BugDescription = $BugDescription;

        #Can remove later if not needed.
        $resourcetypes = @()
		if($ResourceTypeName -ne [ResourceTypeName]::All)
		{
			$resourcetypes += ([SVTMapping]::AzSKADOResourceMapping |
					Where-Object { $_.ResourceTypeName -eq $ResourceTypeName } | Select-Object JsonFileName, ResourceTypeName)
		}
		else
		{
			$resourcetypes += ([SVTMapping]::AzSKADOResourceMapping | Sort-Object ResourceTypeName | Select-Object JsonFileName, ResourceTypeName)
		}
        $resourcetypes = $resourcetypes | Sort-Object -Property JsonFileName -Unique
        foreach ($item in $resourcetypes) {
            $this.ResourceControlJson += [ConfigurationManager]::LoadServerConfigFile("$($item.JsonFileName)").Controls;
        }

        $this.GetAndFilterScanResultData($AutoBugLog, $ResourceTypeName, $ControlIds, $scanResultData, $isLAFile, $false);

	}

    AzSKADOAutoBugLogging([string] $organizationName, $BugLogProject, $ResourceTypeName, $ControlIds, $scanResultData, [InvocationInfo] $invocationContext, $isLAFile): 
        Base($organizationName, $invocationContext) 
    { 
        $this.OrgName = $organizationName;
        $this.BugLogProjectName = $BugLogProject;
        $this.IsLAFile = $isLAFile;

        #Can remove later if not needed.
        $resourcetypes = @()
		if($ResourceTypeName -ne [ResourceTypeName]::All)
		{
			$resourcetypes += ([SVTMapping]::AzSKADOResourceMapping |
					Where-Object { $_.ResourceTypeName -eq $ResourceTypeName } | Select-Object JsonFileName, ResourceTypeName)
		}
		else
		{
			$resourcetypes += ([SVTMapping]::AzSKADOResourceMapping | Sort-Object ResourceTypeName | Select-Object JsonFileName, ResourceTypeName)
		}
        $resourcetypes = $resourcetypes | Sort-Object -Property JsonFileName -Unique
        foreach ($item in $resourcetypes) {
            $this.ResourceControlJson += [ConfigurationManager]::LoadServerConfigFile("$($item.JsonFileName)").Controls;
        }

        $this.GetAndFilterScanResultData($null, $ResourceTypeName, $ControlIds, $scanResultData, $isLAFile, $true);

	}
	
	[SVTEventContext[]] StartBugLogging()
	{
        return $this.InitiateBugLogging($false);
    }

    [SVTEventContext[]] ClosingLoggedBugs()
	{
        return $this.InitiateBugLogging($true);
    }
    
    hidden [SVTEventContext[]] InitiateBugLogging($isCloseBug) {  
        [ResourceContext] $ResourceContext = $null;
        [SVTEventContext[]] $ResourceContextControlResult = $null;

        $resourcesToLogBugs = $this.ScanResult | Group-Object -Property ResourceId;
        if ($isCloseBug) {
            $this.PublishCustomMessage("`nNumber of resources for which bug clossing will be evaluated: $($resourcesToLogBugs.count)",[MessageType]::Info);
        }
        else {
            $this.PublishCustomMessage("`nNumber of resources for which bug logging will be evaluated: $($resourcesToLogBugs.count)",[MessageType]::Info);
        }

		foreach ($controlResult in $resourcesToLogBugs) {
            if ($this.IsLAFile) {
                $ResourceContext = [ResourceContext]@{
                    ResourceGroupName = $controlResult.Group[0].ResourceGroup;
                    ResourceName = $controlResult.Group[0].ResourceName_s;
                    ResourceType = "ADO."+$controlResult.Group[0].FeatureName_s;
                    ResourceTypeName = $controlResult.Group[0].FeatureName_s;
                    ResourceId = $controlResult.Group[0].ResourceId
                    ResourceDetails = @{ResourceLink = $controlResult.Group[0].ResourceLink_s}
                };    
            }
            else {
                $ResourceContext = [ResourceContext]@{
                    ResourceGroupName = $controlResult.Group[0].ResourceGroupName;
                    ResourceName = $controlResult.Group[0].ResourceName;
                    ResourceType = "ADO."+$controlResult.Group[0].FeatureName;
                    ResourceTypeName = $controlResult.Group[0].FeatureName;
                    ResourceId = $controlResult.Group[0].ResourceId
                    ResourceDetails = @{ResourceLink = $controlResult.Group[0].ResourceLink}
                };
            }
            
            $ResourceContextControlResult += $this.CreateResultContextObject($ResourceContext, $controlResult.Group);
        }
		return $this.BugLoggingEvaluation($ResourceContextControlResult, $isCloseBug);

    }

    #function to call AutoBugLog class for performing bug logging
	hidden [SVTEventContext []] BugLoggingEvaluation([SVTEventContext []] $ControlResults, $isCloseBug)
	{
        $AutoBugLog = $null;
        if (!$isCloseBug) {
		    $AutoBugLog = [AutoBugLog]::AutoBugInstance
		    if (!$AutoBugLog) {
		    	[BugLogPathManager]::checkValidPathFlag = $true;
                $BugLogParameterValue = $this.InvocationContext.BoundParameters["AutoBugLog"];
		    	$AutoBugLog = [AutoBugLog]::GetInstance($this.OrgName, $this.InvocationContext, $null, $BugLogParameterValue);
		    }
            $resourcename = "";
            foreach ($controlResult in $ControlResults) {
                if ($resourcename -ne $controlResult.ResourceContext.ResourceName ) {
                    $this.PublishCustomMessage([Constants]::DoubleDashLine, [MessageType]::Info);
                    $this.PublishCustomMessage("Running bug logging: [FeatureName: $($controlResult.FeatureName)] [ParentGroupName: $($controlResult.ResourceContext.ResourceGroupName)] [ResourceName: $($controlResult.ResourceContext.ResourceName)]", [MessageType]::Info);                
                }
                $resourcename = $controlResult.ResourceContext.ResourceName 

		        $AutoBugLog.LogBugInADOCSV($controlResult, $this.BugLogProjectName, $this.BugTemplate, $this.STMappingFilePath, $this.BugDescription) 
            }
        }
        else {
            $this.PublishCustomMessage([Constants]::DoubleDashLine, [MessageType]::Info);
            $this.PublishCustomMessage("Closing bugs in bulk mode...", [MessageType]::Info);
            #$AutoClose = [AutoCloseBugManager]::new($this.OrganizationContext.OrganizationName);
            #$AutoClose.AutoCloseBugCSV($ControlResults)
        }

        $this.PublishCustomMessage([Constants]::DoubleDashLine, [MessageType]::Info);
        $this.PublishCustomMessage("Bug logging has been completed.", [MessageType]::Info);
        $this.PublishCustomMessage([Constants]::DoubleDashLine, [MessageType]::Info);
        return $ControlResults;
	}

    hidden [bool] GetAndFilterScanResultData($AutoBugLog, $ResourceTypeName, $ControlIds, $scanResultData, $isLAFile, $AutoCloseBug)
    {
        try {
            $this.PublishCustomMessage("`nFiltering scan result data.....",[MessageType]::Info);
            if (!$isLAFile) {
                if ($ResourceTypeName) {
                    $scanResultData = $scanResultData | Where { $_.FeatureName -eq $ResourceTypeName }
                }
                if ($AutoBugLog -eq "BaseLineControls" -and $scanResultData) {
                    $scanResultData = $scanResultData | Where { $_.IsBaselineControl -eq "Yes" }
                }
                if ($ControlIds -and $scanResultData) {
                    $cids = $this.ConvertToStringArray($ControlIds);
                    $scanResultData = $scanResultData | Where { $_.ControlId -In $cids }
                }
                if ($scanResultData -and $AutoBugLog -ne $null) {
                    $scanResultData = $scanResultData | Where {$_.Status -eq "Failed" -or $_.Status -eq "Varify"} 
                }
                if ($AutoCloseBug) {
                    $scanResultData = $scanResultData | Where {$_.Status -eq "Passed"} 
                }

                $this.ScanResult += $scanResultData;   
            }
            else {
                if ($ResourceTypeName) {
                    $scanResultData = $scanResultData | Where { $_.FeatureName_s -eq $ResourceTypeName }
                }
                if ($AutoBugLog -eq "BaseLineControls" -and $scanResultData) {
                    $scanResultData = $scanResultData | Where { $_.IsBaselineControl_b -eq "TRUE" }
                    Write-Host 'Can not read IsBaselineControl_b data from csv.' -ForegroundColor Yellow
                }
                if ($ControlIds -and $scanResultData) {
                    $cids = $this.ConvertToStringArray($ControlIds);
                    $scanResultData = $scanResultData | Where { $_.ControlId_s -In $cids }
                }
                if ($scanResultData -and $AutoBugLog -ne $null) {
                    $scanResultData = $scanResultData | Where {$_.ControlStatus_s -eq "Failed" -or $_.ControlStatus_s -eq "Varify"}
                    
                }
                if ($AutoCloseBug) {
                    $scanResultData = $scanResultData | Where {$_.ControlStatus_s -eq "Passed"}
                    
                }
                $this.ScanResult += $scanResultData;
            }
            return $true;   
        }
        catch {
            return $false;
        }
    }

    

    hidden [SVTEventContext[]] CreateResultContextObject($ResourceContext, $controlResult)
	{
        [SVTEventContext[]] $ResourceContextControlResult = @();
        [ControlResult[]] $controlResults = @();
        [ControlItem[]] $controlResults = @();

        foreach ($item in $controlResult) {
            $CtrlItm = [ControlItem]::new();
            if ($this.IsLAFile) 
            {
                $currentControlJson = $this.ResourceControlJson | Where {$_.ControlId -eq $item.ControlID_s}
                $CtrlItm.ID = $currentControlJson.ID
                $CtrlItm.ControlID = $item.ControlID_s
                $CtrlItm.ControlSeverity = $item.ControlSeverity_s
                #$CtrlItm.IsBaselineControl = $item.IsBaselineControl
                $CtrlItm.Description = $currentControlJson.Description 
                $CtrlItm.Recommendation = $currentControlJson.Recommendation
                $CtrlItm.Rationale = $currentControlJson.Rationale
                $CtrlResult = [ControlResult]::new();
                $CtrlResult.VerificationResult = $item.ControlStatus_s
                #$CtrlResult.ActualVerificationResult = $item.ActualVerificationResult_s
                $CtrlResult.AdditionalInfoInCSV = $item.AdditionalInfo_s
            }
            else {
                $currentControlJson = $this.ResourceControlJson | Where {$_.ControlId -eq $item.ControlID}

                $CtrlItm.ID = $currentControlJson.ID
                $CtrlItm.ControlID = $item.ControlID
                $CtrlItm.ControlSeverity = $item.ControlSeverity
                $CtrlItm.IsBaselineControl = $item.IsBaselineControl
                $CtrlItm.Description = $item.Description
                $CtrlItm.Recommendation = $item.Recommendation
                $CtrlItm.Rationale = $item.Rationale
                $CtrlResult = [ControlResult]::new();
                $CtrlResult.VerificationResult = $item.Status
                #$CtrlResult.ActualVerificationResult = $item.ActualStatus
                $CtrlResult.AdditionalInfoInCSV = $item.AdditionalInfo
            }
            $svtControlResult = [SVTEventContext]@{
                FeatureName = $ResourceContext[0].ResourceTypeName 
                Metadata = [Metadata]@{
                    Reference = "";
                };
            
                OrganizationContext = $this.OrganizationContext;
                ResourceContext = $ResourceContext;
                ControlResults = $CtrlResult;
                ControlItem = $CtrlItm;
            };
            $ResourceContextControlResult += $svtControlResult;
        }
        return $ResourceContextControlResult;
	}
  
}
