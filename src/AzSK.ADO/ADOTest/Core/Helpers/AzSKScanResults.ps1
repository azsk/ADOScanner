class AzSKScanResults 
{
    
    [string] $AzSKReportFolder = $null;
    [PSCustomObject[]] $AzSKScanResults = @();
    [PSCustomObject] $AzSKResourceInfo = $null;
    [string] $ErrMsg = "`r`n***Issues***";

    #$f = (Get-ChildItem -Path $outPath -Include 'PowerShellOutput.LOG' -Recurse)

    <#
        ControlID             : Azure_VirtualMachine_SI_Enable_Antimalware
        Status                : Passed
        FeatureName           : VirtualMachine
        ResourceGroupName     : aimlrg
        ResourceName          : aimlvm3
        ControlSeverity       : High
        IsBaselineControl     : No
        IsControlInGrace      : No
        SupportsAutoFix       : No
        Description           : Antimalware must be ...
        ActualStatus          : Passed
        AttestedSubStatus     : 
        AttestationExpiryDate : 
        AttestedBy            : 
        AttesterJustification : 
        Recommendation        : To install antimalware...
        ResourceId            : /subscriptions/254ad434-e2e6-45c0-a32b-34bf24cb7479/res...
        DetailedLogFile       : /aimlrg/VirtualMachine.LOG
    #>

    AzSKScanResults([string] $reportFolder, [PSCustomObject] $resourceInfo)
    {
        $this.AzSKReportFolder = $reportFolder
        $this.InitAzSKScanResults($reportFolder)
        $this.AzSKResourceInfo = $resourceInfo
    }

    [void] InitAzSKScanResults($reportFolder)
    {
        if (-not (Test-Path -Path "$reportFolder\SecurityReport*.csv") )
        {
            throw "Error. No CSV file found in output folder!"
        }

        $this.AzSKScanResults = @(Import-Csv "$reportFolder\SecurityReport*.csv" |?{$_.ControlId -notmatch "^Azure_AzSKCfg_"})
        if ($this.AzSKScanResults.Count -eq 0)
        {
            throw "No controls scan events found in CSV!"
        }
        $this.AzSKReportFolder = $reportFolder
    }

    [string] GetErrMsg()
    {
        return $this.ErrMsg
    }

    # InitAzSKbResults -reportFolder "<reportFolderPathHere>"

    [bool] WereAllControlsScanned($controlsToCheck)
    {
        return $this.WereAllControlsScanned($controlsToCheck, $false)      
    }

    [bool] WereAllControlsScanned($controlsToCheck, [switch] $Exclusive)
    {
        if (@($controlsToCheck).Count -eq 0)
        {
            Write-Warning("Empty object passed to results check function! Returning `$false")
            return $false
        }
        #Unique controls in results
        $ctrlsInScan = @($this.AzSKScanResults | Select-Object ControlId -Unique)

        $bOk1 = @($controlsToCheck | ?{$ctrlsInScan.ControlId -contains $_.ControlId}).Count -eq $controlsToCheck.Count 
        
        if (-not $bOk1)
        {
            $notInScan = ( @($controlsToCheck | ?{$ctrlsInScan.ControlId -notcontains $_.ControlId}) ).ControlId -join ', '
            
            $msg = "Did not find the following expected controls in scan:`r`n[$notInScan]"
            Write-Warning "$msg"
            $this.ErrMsg += "`r`n$msg"
        }

        #TBD: This next line be reverse? Each control in results is in the controls-to-check list
        #As opposed to each control in the check-list is in the scan-results!
        #$bOk = ($ctrlsInScan | ?{$controlsToCheck.ControlId -notcontains $_.ControlId}).Count -eq 0

        $bOk2 = $true 
        if ($Exclusive)
        {
            #Chk: No other ctrlIds in scan
            $otherCtrlIdsInScan = @($ctrlsInScan.ControlId | ?{$controlsToCheck.ControlId -notcontains $_})

            $bOK2 = ($otherCtrlIdsInScan.Count -eq 0)
            if (-not $bOK2)
            {        
                $otherCtrlIdsStr = $otherCtrlIdsInScan -join ', '
                $msg = "Found extra control ids in scan:`r`n[$otherCtrlIdsStr]"
                Write-Warning "$msg"
                $this.ErrMsg += "`r`n$msg"
            }
        }
        return $bOk1 -and $bOk2
    }


    [bool] WereAllResourcesScanned($resourcesToCheck)
    {
        return $this.WereAllResourcesScanned($resourcesToCheck, 0)
    }

    [bool] WereAllResourcesScanned($resourcesToCheck, $nHack = 0)
    {
        if (@($resourcesToCheck).Count -eq 0)
        {
            Write-Warning("Empty object passed to results check function! Returning `$false.")
            return $false
        }
        #Unique resources in scan
        $resourcesInScan = @($this.AzSKScanResults  | Select-Object ResourceGroupName, ResourceName -Unique)


        switch ($nHack)
        {
            0 { Write-Warning "No hack used!" }
            1 {
                Write-Warning "APIConn hack used!"
                #BUGBUG: Temp: remove substring till "/" for APIConn from the resource names in scan results.
                for ($i = 0; $i -lt $resourcesInScan.Count; $i++) 
                {
                    if ($resourcesInScan[$i].ResourceName -match "/")
                    {
                        Write-Host "Truncating: $($resourcesInScan[$i].ResourceName)"; 
                        $x = $resourcesInScan[$i].ResourceName; 
                        $resourcesInScan[$i].ResourceName = $x.Substring($x.IndexOf("/")+1)
                    }
                }
            }
        }

        $foundInScanCount = @($resourcesToCheck | ?{$resourcesInScan.ResourceName -contains $_.Name}).Count
        $excessInScanCount = @($resourcesInScan.ResourceName | ?{$resourcesToCheck.Name -notcontains $_}).Count

        $bOk = ($resourcesInScan.Count -eq $resourcesToCheck.Count)`
                    -and @($resourcesInScan | ?{$resourcesToCheck.ResourceGroupName -contains $_.ResourceGroupName}).Count -eq $resourcesInScan.Count`
                    -and @($resourcesInScan | ?{$resourcesToCheck.Name -contains $_.ResourceName}).Count -eq $resourcesInScan.Count


        if (-not $bOk)
        {
            $missingRsrcs = @($resourcesToCheck | ? {$resourcesInScan.ResourceName -notcontains $_.Name})
            if ($missingRsrcs.Count -gt 0)
            {
                $missingRsrcNames = $missingRsrcs.Name -join ', '
                $msg = "The following resources were missing:`r`n$missingRsrcNames."
                Write-Warning "$msg"
                $this.ErrMsg += "`r`n$msg"  
            }

            $otherRsrcs = @($resourcesInScan | ? {$resourcesToCheck.Name -notcontains $_.ResourceName})
            
            if ($otherRsrcs.Count -gt 0)
            {
                $otherRsrcNames = $otherRsrcs.ResourceName -join ', '
                $msg = "The following other resources were present:`r`n$otherRsrcNames."
                Write-Warning "$msg"
                $this.ErrMsg += "`r`n$msg"  
            }   
        }

        return $bOk
    }

    [bool] WereAllResourcesScannedEx($resourcesToCheck)
    {
        return $this.WereAllResourcesScanned($resourcesToCheck,1) #nHack
    }

    [bool] WereAllControlsScannedUBC()
    {
        $nonUbcResults = @( $this.AzSKScanResults | Where-Object{$_.IsBaselineControl -eq 'No'} ) 
        $bOk1 = $nonUbcResults.Count -eq 0

        if (-not $bOk1)
        {
            $nonUbcControlIds = @(($nonUbcResults | Sort-Object ControlId -Unique).ControlId)
            $nonUbcControlIdsStr = $nonUbcControlIds -join ', '

            $msg =  "Found the following non-UBC controls in scan:`r`n$nonUbcControlIdsStr"
            Write-Warning "$msg"
            $this.ErrMsg += "`r`n$msg"
        }

        return $bOk1
    }


    [bool] WereAllAzSKRTNsScanned($rtnsToCheck)
    {
        return $this.WereAllAzSKRTNsScanned($rtnsToCheck, $false)
    }

    [bool] WereAllAzSKRTNsScanned($rtnsToCheck, [switch] $Exclusive)
    {
        if (@($rtnsToCheck).Count -eq 0)
        {
            Write-Warning("Empty object passed to results check function! Returning `$false.")
            return $false
        }

        $rtnsInScan = @($this.AzSKScanResults.FeatureName | Select-Object -Unique)

        $bOk1 = @($rtnsToCheck | ?{$rtnsInScan -contains $_}).Count -eq $rtnsToCheck.Count 
        
        if (-not $bOk1)
        {
            $notInScan = @($rtnsToCheck | ?{$rtnsInScan -notcontains $_}) -join ', '
            
            $msg =  "Did not find the following expected AzSK RTNs in scan:`r`n$notInScan"
            Write-Warning "$msg"
            $this.ErrMsg += "`r`n$msg"
        }

        $bOk2 = $true 
        if ($Exclusive)
        {
            # Chk: No other RTNs are in scan
            $otherRTNs = @($rtnsInScan | ?{$rtnsToCheck -notcontains $_})

            $bOK2 = ($otherRTNs.Count -eq 0)
            if (-not $bOK2)
            {        
                $msg = "Found extra AzSK RTNs in scan:`r`n$otherRTNs"
                Write-Warning "$msg"
                $this.ErrMsg += "`r`n$msg"
            }
        }
        return $bOk1 -and $bOk2
    }

    [bool] WereAllRGNamesScanned($rgNamesToCheck)
    {
        return $this.WereAllRGNamesScanned($rgNamesToCheck,$false)    
    }

    [bool] WereAllRGNamesScanned($rgNamesToCheck, [switch] $Exclusive)
    {
        if (@($rgNamesToCheck).Count -eq 0)
        {
            Write-Warning("Empty object passed to results check function! Returning `$false.")
            return $false
        }
        
        # Get the RG names in the scan results
        $rgNamesInScan  = @(($this.AzSKScanResults | Sort-Object ResourceGroupName -Unique ).ResourceGroupName)

        # Verify that: 
        #  (1) counts of RGs match between result and expected
        #  (2) all expected RGs are in scanned RGs list
        $bOk1 = $rgNamesInScan.count -eq $rgNamesToCheck.Count`
                -and @($rgNamesToCheck | ?{$rgNamesInScan -contains $_}).Count -eq $rgNamesToCheck.Count
        
        if (-not $bOk1)
        {
            $notInScan = @($rgNamesToCheck | ?{$rgNamesInScan -notcontains $_}) -join ', '
            
            $msg =  "Did not find the following expected RGs in scan:`r`n$notInScan"
            Write-Warning "$msg"
            $this.ErrMsg += "`r`n$msg"
        }

        $bOk2 = $true
        if ($Exclusive)
        {
            #  (3) all RGs in scanned RG list are in expected RGs
            $otherRGs = @($rgNamesInScan | ?{$rgNamesToCheck -notcontains $_}) 
            $bOk2 = $otherRGs.Count -eq 0
            if (-not $bOk2)
            {
                $otherRGNames = $otherRGs -join ', '
                $msg = "Found extra RGs in scan:`r`n$otherRGNames"
                Write-Warning "$msg"
                $this.ErrMsg += "`r`n$msg"
            }
        }

        return $bOk1 -and $bOk2
    }

    [bool] WereAllResourcesInRGNamesScanned($rgNamesToCheck) 
    {
        return $this.WereAllResourcesInRGNamesScanned($rgNamesToCheck,$false) 
    }
    

    [bool] WereAllResourcesInRGNamesScanned($rgNamesToCheck,[switch]$CheckCountsOnly) 
    {
        if (@($rgNamesToCheck).Count -eq 0)
        {
            Write-Warning("Empty object passed to results check function! Returning `$false.")
            return $false
        }
        $expectedRsrcsInScan = @($this.AzSKResourceInfo.AllAzSKSupportedResourcesInSub | ?{$rgNamesToCheck -contains $_.ResourceGroupName} | Sort-Object ResourceGroupName, Name -Unique)

        $actualRsrcsInScan = @($this.AzSKScanResults | Sort-Object ResourceGroupName, ResourceName -Unique)

        $bOk1 = $expectedRsrcsInScan.Count -eq $actualRsrcsInScan.Count

        if (-not $bOk1)
        {            
            $msg =  "Expected $($expectedRsrcsInScan.Count) resources but found $($actualRsrcsInScan.Count)."
            Write-Warning "$msg"
            $this.ErrMsg += "`r`n$msg"
        }


        $bOk2 = $true

        if (-not $CheckCountsOnly)
        {
            $expectedRsrcRGTuples = @( $expectedRsrcsInScan | %{"$($_.ResourceGroupName):$($_.Name)"} )
            $actualRsrcRGTuples = @( $actualRsrcsInScan | %{"$($_.ResourceGroupName):$($_.ResourceName)"} )
            
            $bOk2 = @($expectedRsrcRGTuples | ? {$actualRsrcRGTuples -contains $_}).Count -eq $expectedRsrcRGTuples.Count

            if (-not $bOk2)
            {
                $missingRsrcRGTuples = @($expectedRsrcRGTuples | ? {$actualRsrcRGTuples -notcontains $_})
                $missingRsrcRGTupleNames = $missingRsrcRGTuples -join ', '

                $msg = "Did not find the following RG:Rsrc tuples in scan:`r`n$missingRsrcRGTupleNames"
                Write-Warning "$msg"
                $this.ErrMsg += "`r`n$msg"                
            }
        }
        return $bOk1 -and $bOk2        
    }

    [bool] WereAllResourcesForAzSKRTNsScanned([string[]] $rtnsToCheck)
    {
        return $this.WereAllResourcesForAzSKRTNsScanned([string[]]$rtnsToCheck, @())
    }

    [bool] WereAllResourcesForAzSKRTNsScanned([string[]] $rtnsToCheck, [PSCustomObject[]] $resourceGroupNames=@())
    {
        if (@($rtnsToCheck).Count -eq 0)
        {
            Write-Warning("Empty object passed to results check function! Returning `$false.")
            return $false
        }
        
        #Keep one control result row per unique resource
        $allRsrcsInScan = @( $this.AzSKScanResults | Sort-Object ResourceGroupName, ResourceName -Unique )
        
        #Filter results for RTNs we are looking for
        $rtnRsrcsInScan = @( $allRsrcsInScan | ?{$rtnsToCheck -contains $_.FeatureName} )

        #Get Azure rsrc types for RTNs we are looking for
        #BUGBUG: Currently AzSKResourceInfo is a base class so this works. May need to rework after making the TestContext changes.
        $rsrcTypesToCheck = $this.AzSKResourceInfo.GetAzureResourceTypesForAzSKResourceTypeNames($rtnsToCheck)
        
        #BUGBUG: same as above.
        #Get set of resources we'd expect to get scanned (corresponding to the rsrcTypes)
        $expectedRsrcsInScan = @($this.AzSKResourceInfo.AllAzSKSupportedResourcesInSub | ?{$rsrcTypesToCheck -contains $_.ResourceType})

        #If RGnames are specified, we filter down expected rsrcs set to those RGs only
        if ($resourceGroupNames.Count -gt 0)
        {
            $expectedRsrcsInScan = @( $expectedRsrcsInScan|?{$resourceGroupNames -contains $_.ResourceGroupName} )
        }

        #The two counts must match
        $bOk = $rtnRsrcsInScan.Count -eq $expectedRsrcsInScan.Count

        if (-not $bOk)
        {
            $expectedRTNs = $this.AzSKResourceInfo.GetAzureResourceTypesForAzSKResourceTypeNames($expectedRsrcsInScan)

            $missingRTNs = @($expectedRTNs | ? {$rtnRsrcsInScan -notcontains $_})

            if ($missingRTNs.Count -gt 0)
            {
                $missingRTNNames = $missingRTNs -join ', '
                
                $msg = "Did not find the following expected ResourceTypeNames in scan:`r`n$missingRTNNames."
                Write-Warning "$msg"
                $this.ErrMsg += "`r`n$msg"  
            }

            $otherRTNs = @($rtnRsrcsInScan | ? {$expectedRTNs -notcontains $_})

            if ($otherRTNs.Count -gt 0)
            {
                $otherRTNNames = $otherRTNs -join ', '
                $msg = "Found the following excess ResourceTypeNames in scan:`r`n$otherRTNNames."
                Write-Warning "$msg"
                $this.ErrMsg += "`r`n$msg"  
            }
        }
        return $bOk
    }

    [bool] WereOnlyRequiredSeverityScanned([string[]] $passedSeverity, [string[]] $validSevs)
    {
        $bok = $true;
        $unexpectedSev = @();
        $SevNotScanned = @();
        $scannedSevs = $this.AzSKScanResults.ControlSeverity | Sort-Object|Get-Unique
        $unexpectedSev += $scannedSevs| Where-Object{$_ -notin $validSevs}
        $SevNotScanned += $validSevs | Where-Object{$_ -notin $scannedSevs }
        if($unexpectedSev.Count -gt 0)
        {
            $bok= $false;
            $this.ErrMsg += "Controls with following unexpected severity found in scan: $($unexpectedSev -join ', ')"
            return $bok;

        }
        if($SevNotScanned.Count -gt 0)
        {
            $bok= $false;
            $this.ErrMsg += "No controls with following expected sev found: $($SevNotScanned -join ', ')"
            return $bok;

        }

        return $bok;
    }

    ########################## ADOScanner TestCases #################################

    ######################### Scanning testcases functions ##########################
    [bool] WereAllExpectedResourcesScanned($resourcesToCheck)
    {
        if (@($resourcesToCheck).Count -eq 0)
        {
            Write-Warning("Empty object passed to results check function! Returning `$false.")
            return $false
        }
        #Unique resources in scan
        $resourcesInScan = @($this.AzSKScanResults  | Select-Object ResourceName -Unique)
        $testCaseStatus = $false
        $diff = @($resourcesInScan | ? {$resourcesToCheck -notcontains $_.ResourceName})
        if ($diff.Count -eq 0) {
            $testCaseStatus = $true
        }
        
        if (-not $testCaseStatus)
        {
            $missingResources = @($resourcesToCheck | ? {$resourcesInScan.ResourceName -notcontains $_})
            if ($missingResources.Count -gt 0)
            {
                $missingResources = $missingResources.Name -join ', '
                $msg = "The following resources were missing:`r`n$missingResources."
                Write-Warning "$msg"
                $this.ErrMsg += "`r`n$msg"  
            }
    
            $otherResources = @($resourcesInScan | ? {$resourcesToCheck -notcontains $_.ResourceName})
            
            if ($otherResources.Count -gt 0)
            {
                $otherResourceNames = $otherResources -join ', '
                $msg = "The following other resources were present:`r`n$otherResourceNames."
                Write-Warning "$msg"
                $this.ErrMsg += "`r`n$msg"  
            }   
        }
    
        return $testCaseStatus
    }

    [bool] WereOrganizationControlsScanned($org)
    {
        #Unique resources in scan
        $featuresInScan = @($this.AzSKScanResults  | Select-Object FeatureName -Unique)
        $orgsInScan = @($this.AzSKScanResults  | Select-Object ResourceName -Unique)
        $testCaseStatus = $false
        if ($featuresInScan.Count -eq 1 -and $featuresInScan[0].FeatureName -eq "Organization" -and  $orgsInScan.Count -eq 1 -and $orgsInScan[0].ResourceName -eq $org) {
            $testCaseStatus = $true
        }
        return $testCaseStatus
    }



    [bool] WereUserControlsScanned()
    {
        #Unique resources in scan
        $featuresInScan = @($this.AzSKScanResults  | Select-Object FeatureName -Unique)
        $testCaseStatus = $false
        if ($featuresInScan.Count -eq 1 -and $featuresInScan[0].FeatureName -eq 'User') {
            $testCaseStatus = $true
        }
        return $testCaseStatus
    }

    [bool] WereExpectedControlsScanned($controlId)
    {
        #Unique resources in scan
        $controlsInScan = @($this.AzSKScanResults  | Select-Object ControlID -Unique)
        $testCaseStatus = $false
        if ($controlsInScan.Count -eq 1 -and $controlsInScan[0].ControlID -eq $controlId) {
                $testCaseStatus = $true
        }
        return $testCaseStatus
    }

    [bool] WereOnlyBaseLineControlsScanned()
    {
        #Unique resources in scan
        $featuresInScan = @($this.AzSKScanResults  | Select-Object IsBaselineControl -Unique)
        $testCaseStatus = $false
        if ($featuresInScan.Count -eq 1 -and $featuresInScan[0].IsBaselineControl -eq 'Yes') {
            $testCaseStatus = $true
        }
        return $testCaseStatus
    }

    [bool] WereOnlyHighSeverityControlsScanned()
    {
        #Unique resources in scan
        $serverityInScan = @($this.AzSKScanResults  | Select-Object ControlSeverity -Unique)
        $testCaseStatus = $false
        if ($serverityInScan.Count -eq 1 -and $serverityInScan[0].ControlSeverity -eq 'High') {
            $testCaseStatus = $true
        }
        return $testCaseStatus
    }

    ################################ ControlCorrectness Functions ##############################
    [bool] WereScanResultsGiveExpectedStatus($status, $excludedControls)
    {
        #Unique resources in scan
        $filteredScanResult = $this.AzSKScanResults | Where-Object -FilterScript {$excludedControls -notcontains $_.ControlID}
        $statusInScan = @($filteredScanResult  | Select-Object Status -Unique)
        $testCaseStatus = $false
        
        if ($statusInScan.Count -eq 1 -and $statusInScan[0].Status -eq $status) {
            $testCaseStatus = $true
        }
        else {
            $this.ErrMsg += "Control correctness validation is not returning expected status."  
        }
    
        return $testCaseStatus
    }

    ################################ Buglogging Functions ########################################
    [bool] WereAllFailureControlsLogged()
    {
        #Unique resources in scan
        ### Todo : check the cases where bug logging is not supported ###
        $activeBugs =  @()
        $newBugs = @()
        $missedBugs = @()
        $controlIdsToBeLogged= @($this.AzSKScanResults  | Where-Object -FilterScript {($_.Status -eq "Failed" -or $_.Status -eq "Verify")} | Select-Object ControlID -Unique)
        $buSummaryFile =  $this.AzSKReportFolder + "\BugSummary.json"
        $bugSummary = (Get-Content -Path  $buSummaryFile) | ConvertFrom-Json
        if ("ActiveBugs" -in $bugSummary.PSobject.Properties.Name)
        {
            $activeBugs = $bugSummary.ActiveBugs
        }
        if  ("NewBugs" -in $bugSummary.PSobject.Properties.Name)
        {
            $newBugs = $bugSummary.NewBugs
        }
    
        $allLoggedBugs = $activeBugs + $newBugs
        $loggedBugsControlIds = @($allLoggedBugs  | Select-Object Control -Unique)
        $missedBugs = @($loggedBugsControlIds.Control | where {$controlIdsToBeLogged.ControlID -notcontains $_})
    
        $testCaseStatus = $false
        
        if ($missedBugs.Count -eq 0) {
            $testCaseStatus = $true
        }
        else {
            $this.ErrMsg += "Bug logging for few failure controls failed."  
        }
    
        return $testCaseStatus
    }

    [bool] WereDuplicateBugsLogged($currentWorkItem)
    {
        $activeBugs =  @()
        $newBugs = @()
        $missedBugs = @()
        $buSummaryFile =  $this.AzSKReportFolder + "\BugSummary.json"
        $bugSummary = (Get-Content -Path  $buSummaryFile) | ConvertFrom-Json
        $testCaseStatus = $false
        if  (-not ("NewBugs" -in $bugSummary.PSobject.Properties.Name))
        {
            if ("ActiveBugs" -in $bugSummary.PSobject.Properties.Name){
                if ($bugSummary.ActiveBugs[0].Url -eq $currentWorkItem) {
                    $testCaseStatus = $true
                }
            }
        }
               
        if (-not $testCaseStatus ) {
            $this.ErrMsg += "Duplicate WorkItems has been created for same bug."  
        }
    
        return $testCaseStatus
    }

    [bool] WereNewBugsLogged()
    {
        $activeBugs =  @()
        $newBugs = @()
        $missedBugs = @()
        $buSummaryFile =  $this.AzSKReportFolder + "\BugSummary.json"
        $bugSummary = (Get-Content -Path  $buSummaryFile) | ConvertFrom-Json
        $testCaseStatus = $false
        if  (-not ("NewBugs" -in $bugSummary.PSobject.Properties.Name))
        {
            $testCaseStatus = $true
        }
               
        if (-not $testCaseStatus ) {
            $this.ErrMsg += "Duplicate WorkItems has been created for existing WorkItem."  
        }
    
        return $testCaseStatus
    }

    [PSObject] GetWorkItem( $workItemApiEndpoint, $pat) {
        $token =[System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($pat)"))
        $header = @{authorization = "Basic $token"}
        $workItemResponse = Invoke-WebRequest -Uri $workItemApiEndpoint -Method Get -ContentType "application/json-patch+json" -Headers $header
        $workItemInfo = $workItemResponse.Content | ConvertFrom-Json
        return $workItemInfo
    }

    [bool] WereBugsLoggedInValidPath($org, $pat, $project, $expectedPath)
    {
        $activeBugs =  @()
        $newBugs = @()
        $missedBugs = @()
        $buSummaryFile =  $this.AzSKReportFolder + "\BugSummary.json"
        $bugSummary = (Get-Content -Path  $buSummaryFile) | ConvertFrom-Json
        $testCaseStatus = $false
        if   ("NewBugs" -in $bugSummary.PSobject.Properties.Name)
        {
            $randomBugEndpoint = $bugSummary.NewBugs[0].Url
            $workItemId = ($randomBugEndpoint -split "_workitems/edit/")[1];
            $workItemApiEndpoint =  "https://dev.azure.com/$org/$project/_apis/wit/workitems/"+$workItemId+"?api-version=6.0-preview.3"
            $workItemInfo = $this.GetWorkItem($workItemApiEndpoint , $pat);
            if ($workItemInfo.fields.'System.AreaPath' -eq $expectedPath) {
                $testCaseStatus = $true
            }
        }
               
        if (-not $testCaseStatus ) {
            $this.ErrMsg += "Bugs are not logged into expected path"  
        }
    
        return 0
    }

}