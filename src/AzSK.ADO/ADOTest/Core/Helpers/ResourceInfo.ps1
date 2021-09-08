Set-StrictMode -Version Latest 
class ResourceInfo:AzSKControlInfo
{
    [PSObject[]] $AllResourcesInSub = @();
    [PSObject[]] $AllResourceGroupsInSub = @();

    [PSObject[]] $AllAzSKSupportedResourcesInSub = @();
    [PSObject[]] $UniqueResourcesInSub = @();

    [PSObject[]] $AzSKSupportedUniqueResourcesInSub = @();
    [PSObject[]] $AzSKSupportedResourceTypesInSub = @();

    ResourceInfo([String] $subscriptionId):base($false)
	{	
        $this.InitResourceInfo()
    }

    [void] InitResourceInfo()
    {
        $this.AllResourcesInSub = @(Get-AzResource)
        if ($this.AllResourcesInSub.Count -eq 0)
        {
            throw "Could not find resources! No network/access?"
        }
        <# Array of resource entries:
                "ResourceId":  "/subscriptions/254ad434-e2e6-45c0-a32b-34bf24cb7479/resourceGroups/aimlrg/providers/Microsoft.DevTestLab/schedules/shutdown-computevm-aimlvm3",
                "Id":  "/subscriptions/254ad434-e2e6-45c0-a32b-34bf24cb7479/resourceGroups/aimlrg/providers/Microsoft.DevTestLab/schedules/shutdown-computevm-aimlvm3",
                "Identity":  null,
                "Kind":  null,
                "Location":  "southeastasia",
                "ManagedBy":  null,
                "Name":  "shutdown-computevm-aimlvm3",
                "ParentResource":  null,
                "Plan":  null,
                "Properties":  null,
                "ResourceGroupName":  "aimlrg",
                "ResourceType":  "Microsoft.DevTestLab/schedules",
                "Sku":  null,
                "Tags":  null,
                "Type":  "Microsoft.DevTestLab/schedules"
        #>

        $this.AllResourceGroupsInSub = @(Get-AzResourceGroup)
        
        <#Array of resource group entries:
            ResourceGroupName : testlaw
            Location          : southeastasia
            ProvisioningState : Succeeded
            Tags              : 
                                Name         Value                               
                                ===========  ====================================
                                ComponentID  f0660da0-77d8-403d-9dec-c3cf5f4c9c73
                                Env          Pre-Production                      
                                Environment  PRE-PRODUCTION                      
                                    
            ResourceId        : /subscriptions/abb5301a-22a4-41f9-9e5f-99badff261f8/resourceGroups/testlaw
        #>

        #TBDX
        $this.AllAzSKSupportedResourcesInSub = @($this.AllResourcesInSub |Where-Object { $this.AzSKSupportedResourceTypes -contains $_.ResourceType });
        if ($this.AllAzSKSupportedResourcesInSub.Count -eq 0)
        {
            throw "No AzSK resources in sub! Network/access issue?"
        }
        $this.UniqueResourcesInSub = $this.AllResourcesInSub | Select-Object ResourceType, Kind, ResourceGroupName, Name | Group-Object ResourceType, Kind| ForEach-Object {$_ | Select-Object -ExpandProperty Group | Select-Object -First 1} | Sort-Object ResourceType;
        $this.AzSKSupportedUniqueResourcesInSub = $this.AllAzSKSupportedResourcesInSub | Select-Object ResourceType, Kind, ResourceGroupName, Name | Group-Object ResourceType, Kind| ForEach-Object {$_ | Select-Object -ExpandProperty Group | Select-Object -First 1} | Sort-Object ResourceType;
        $this.AzSkSupportedResourceTypesInSub = $this.AzSKSupportedUniqueResourcesInSub.ResourceType
    }

    [PSCustomObject[]] GetRandomAzSKResources($count)
    {
        return @($this.AllAzSKSupportedResourcesInSub | Get-Random -Count $count)
    }

    [PSCustomObject[]] GetRandomAzSKResourcesUBC($count)
    {
        $allUBCRsrcs = @($this.AllAzSKSupportedResourcesInSub | ?{ $this.AzSKAzureResourceTypesUBC -contains $_.ResourceType})

        return @($allUBCRsrcs | Get-Random -Count $count)
    }
    
    [PSCustomObject[]] GetRandomAzSKResourcesFromRG($rgName, $count)
    {
        #All AzSK supported rsrc in RG
		$azSKRsrcsInRG = @( $this.AllAzSKSupportedResourcesInSub | Where-Object {$_.ResourceGroupName -eq $rgName} )

        #Return random subset of requested size
        return @($azSKRsrcsInRG | Get-Random -Count $count)
    }

    [PSCustomObject[]] GetAzSKRTNsForRG($rgName)
    {
        #All AzSK supported rsrc in RG
		$azSKRsrcsInRG = @( $this.AllAzSKSupportedResourcesInSub | Where-Object {$_.ResourceGroupName -eq $rgName} )

        #AzSK supported types in RG
        $rsrcTypesInRG = @( ($azSKRsrcsInRG | Sort-Object ResourceType -Unique).ResourceType )

        #Map Azure types to AzSKRTNs to return
        $azSKRTNsInRG = $this.GetAzSKResourceTypeNamesForAzureResourceTypes($rsrcTypesInRG)

        if ($rgName -match "^ERNetwork*")
        {
            $azSKRTNsInRG = @( $AzSKRTNsInRG | ? {$_ -ne "VirtualNetwork"})
        }
        else 
        {
            $azSKRTNsInRG = @( $AzSKRTNsInRG | ? {$_ -ne "ERvNet"})
        }
        return $azSKRTNsInRG
    }
    
    [PSCustomObject[]] GetRGsWithMultipleAzSKResources($minRsrcTypes)
    {
        #Find RGs with at least 'minRsrcTypes' different AzSK supported rsrc types
        $rList = $this.AllAzSKSupportedResourcesInSub		
		$h = ($rList | Group-Object ResourceGroupName -AsHashTable)      
        
        #Get names of RGs with more than 'minRsrcTypes' AzSK supported RsrcTypes
		$rgNames = foreach ($x in $h.Keys) { if( @($h[$x] | Group-Object ResourceType).Count -ge $minRsrcTypes) { $x}}
        return @($rgNames)
    }
    
    [PSCustomObject[]] GetAzSKResourcesFromRGUBC($rgName)
    {
		#AzSK supported rsrc in scanned RG
		$azSKRsrcsInRG = @( $this.AllAzSKSupportedResourcesInSub | Where-Object {$_.ResourceGroupName -eq $rgName} )

		#Figure out AzSK-UBC rsrc in that set (we have to exclude virtualNetworks if the RG-name is not ErNetwork)
		$azskRsrcsInRGUBCx = @( $azSKRsrcsInRG | ? {$this.AzSKAzureResourceTypesUBC -contains $_.ResourceType} )

		#Keep all other resources except vNets. Keep vNets only if RGName starts with ErNetwork
		$azSKRsrcsInRGUBC = @( $azskRsrcsInRGUBCx | ? {($_.ResourceType -ne "Microsoft.Network/virtualNetworks" -or $_.ResourceGroupName -match "^ErNetwork*")} )
        
        return $azSKRsrcsInRGUBC
    }
    
    [string[]] GetRandomAzSKRTN()
    {
        return GetRandomAzSKRTN($false)
    }
    
    [string[]] GetRandomAzSKRTN([switch]$InMultipleRG)
    {
        $azskRTN = ""
    
        if ($InMultipleRG)
        {
            # ResourceTypes and how many RGs they exist in
            $azskRsrcTypesByRG = $this.AllAzSKSupportedResourcesInSub | Sort-Object ResourceType, ResourceGroupName -unique | Group-Object ResourceType 
    
            # ResourceTypes which are in >1 RGs, grouped  
            $azSKRsrcTypesMultiRG = $azSKRsrcTypesByRG | ?{$_.Count -gt 1}
    
            #Get group belonging to one random rsrcType
            $rsrcTypeToScanGrp = ($azSKRsrcTypesMultiRG | Get-Random -Count 1)
    
            $rsrcTypeToScan = $rsrcTypeToScanGrp.Name
        }
        else
        {
            #Just get some supported RTN
            $rsrcTypeToScan = ($this.AllAzSKSupportedResourcesInSub | Get-Random -Count 1).ResourceType
        }
        $azskRTN = $this.GetAzSKResourceTypeNamesForAzureResourceTypes($rsrcTypeToScan)
    
        #BUGBUG: vNet maps back to 2 AzSKRTNs! Randomly returning one for now.
        if ($rsrcTypeToScan -eq 'Microsoft.Network/virtualNetworks')
        {
            $azskRTN = $azskRTN | Get-Random -Count 1
        }
    
        return $azskRTN 
    }
    
    [string[]] GetRGNamesForAzSKRTNs($rtns)
    {
        $rsrcTypes = $this.GetAzureResourceTypesForAzSKResourceTypeNames($rtns)
    
        #This gets the representative set of resources covering all AzSK-supported RGs.
        #$rsrcs = @( $AllAzSKSupportedResourcesInSub | Sort-Object ResourceGroupName -unique)
    
        #Get RGs where RTN is present. ISSUE: Sort-Object is reqd due to case issue (icto-xxx RGs)
        $rgNamesRTNs = ($this.AllAzSKSupportedResourcesInSub |?{$rsrcTypes -contains $_.ResourceType} | Sort-Object ResourceGroupName -Unique).ResourceGroupName
    
        return $rgNamesRTNs
    }

    [PSCustomObject[]] FilterApplicableControlsForSub($ctrls)
    {
        #TODO: this should be a class member...init once.
        $allAzSKRTNResourcesInSub = $this.GetAzSKResourceTypeNamesForAzureResourceTypes(@($this.AllAzSKSupportedResourcesInSub | Select-Object ResourceType -Unique).ResourceType)

        $ctrlsForSub = @($ctrls | ?{$allAzSKRTNResourcesInSub -contains $_.FeatureName})
        return $ctrlsForSub
    }
    
    [PSCustomObject[]] GetApplicableResourcesForControls($ctrls)
    {
        #Rsrc types with FilterTags applicable
        $azskRTNs = $this.GetAzSKRTNsForControls($ctrls)
    
        return $this.GetResourcesForAzSKRTNs($azskRTNs)
    }
    
    [PSCustomObject[]] GetApplicableResourcesForControlsEx($ctrls)
    {
        #RTNs for the ctrls
        $azskRTNs = $this.GetAzSKRTNsForControls($ctrls)
    
        return $this.GetResourcesForAzSKRTNs($azskRTNs,1) #nHack
    }
    
    [PSCustomObject[]] GetResourcesForAzSKRTNs($rtns)
    {
        return $this.GetResourcesForAzSKRTNs($rtns, 0)
    }    
    
    [PSCustomObject[]] GetResourcesForAzSKRTNs($rtns, $nHack=0)
    {
        #Azure types for these...
        $rsrcTypes = $this.GetAzureResourceTypesForAzSKResourceTypeNames($rtns)
    
        
        $rsrcs = @($this.AllAzSKSupportedResourcesInSub | ?{$rsrcTypes -contains $_.ResourceType}) 
    
        switch ($nHack)
        {
            0 { Write-Warning "No hacks used!"}
    
            
            1 { 
                Write-Warning "Using APIConn hack."
                #TODO: Can we skip if $rtns has no LogicApps to begin with?
                #Orphan LA connections may not get scanned. Create the list.
                $lax = @(Get-AzLogicApp)  
                if ($lax.Count -gt 0)
                {
                    $inUseAPIConnNames = @($lax | %{ if( @($_.Parameters.Values[0]).Count -gt 0) {$_.Parameters.Values[0].Value.Path}} | Select-Object -Unique)
                    $allAPIConnNames = (($this.AllAzSKSupportedResourcesInSub | ? {$_.ResourceType -match 'connection'} | Select-Object Name -Unique)).Name
                    $notInUseAPIConnNames = $allAPIConnNames | ?{$inUseAPIConnNames -notcontains $_} 
                    
                    #Remove orphaned APIConnections and return rest
                    $rsrcs = @($rsrcs | ?{$notInUseAPIConnNames -notcontains $_.Name}) 
                }
            }
        }
    
        return $rsrcs
    }
    
    [PSCustomObject[]] SelectRandomRGNamesForSub($Fraction)
    {
        return $this.SelectRandomRGNamesForSub($Fraction, 0)
    }

    #TODO: what about select... -count only option?
    [PSCustomObject[]] SelectRandomRGNamesForSub($Fraction=0.0, $count=0)
    {
        if ($Fraction -ne 0 -and $count -ne 0)
        {
            Write-Error "Cannot use both '-Count' and '-Fraction' in the same call."
            Write-Warning "Will use $Fraction and ignore $count"
        }
        if ($Fraction -lt 0.0 -or $Fraction -gt 1.0)
        {
            Write-Error "The fraction specified [$Fraction] should be between 0.0 and 1.0!"
        }
    
        #Get unique AzSK-supp-RGs in sub
        $uniqueAzSKRGsInSub = @($this.AllAzSKSupportedResourcesInSub | Sort-object ResourceGroupName -Unique)
    
        $nSelect = 0
        if ($Fraction -ne 0.0)
        {
            $nSelect = [int]($uniqueAzSKRGsInSub.Count*$Fraction)
        }
        else
        {
            $nSelect = $count
        }

        #Constrain $nSelect to 1..N-1
        if ($nSelect -eq 0)
        {
            $nSelect = 1
        }
        elseif ($nSelect -eq $uniqueAzSKRGsInSub.Count)
        {
            $nSelect = $uniqueAzSKRGsInSub.Count-1
        }

        $retObj = [PSCustomObject] @{SelectedRGNames = @(); NotSelectedRGNames = @()}
    
        $retObj.SelectedRGNames = @( ($uniqueAzSKRGsInSub | Get-Random -Count $nSelect).ResourceGroupName)
        $retObj.NotSelectedRGNames = @( ($uniqueAzSKRGsInSub | ?{$retObj.SelectedRGNames -notcontains $_.ResourceGroupName}).ResourceGroupName)
        
        return $retObj
    }
    
    [PSCustomObject] GetRandomTagAndValuesForSub()
    {
        # Get rsrc with tags 
        $azSKRsrcWithTags  = $this.AllAzSKSupportedResourcesInSub | ?{$_.Tags -ne $null -and $_.Tags.Count -gt 0}
    
        # Get subset that has non-empty tag values
        $azSKRsrcWithNonEmptyTagValues = ($azSKRsrcWithTags | ?{$_.Tags.Values -notcontains "empty"})
        
        # Get one of those resources
        $rsrc = $azSKRsrcWithNonEmptyTagValues | Get-Random -Count 1
    
        # Get a random index to iterate till
        $tagIdx = ( (0..($rsrc.Tags.Count-1)) | Get-Random -count 1)
    
        $y=0
        $z = ""
        $rsrc.Tags.Keys | %{$_;if ($y++ -eq $tagIdx){$z=$_}}
    
        $retObj = [PSCustomObject] @{TagName = ""; TagValues = @()}
        $retObj.TagName = $z
        $retObj.TagValues = @($rsrc.Tags[$z])
        
        return $retObj
    }

    [PSCustomObject[]] GetAzSKResourcesWithTagAndValuesForSub($tagName, $tagValues)
    {
        $rsrcsWithTagAndValue = @(Get-AzResource -Tag @{$tagName="$tagValues"})

        $azSKrsrcsWithTagAndValue = @( $rsrcsWithTagAndValue | ?{$this.AllAzSKSupportedResourcesInSub.ResourceId -contains $_.ResourceId } )
    
        return $azSKrsrcsWithTagAndValue
    }

    ###############################################################################################################  
    [PSCustomObject[]] GetApplicableControlsForSub()
    {
        $azskRTNsInSub = $this.GetAzSKResourceTypeNamesForAzureResourceTypes($this.AzSKSupportedResourceTypesInSub)
    
        #? ($this.AzSKControlInfo | ?($azskRTNsInSub -contains $_.FeatureName))
        $azSKControlInfoSub = @($this.AzSKControlInfo | ? {$azskRTNsInSub -contains $_.FeatureName})
        return $azSKControlInfoSub
    }
    
    [PSCustomObject[]] GetRandomControlsForSub($count)
    {
        $nCtrls = (1..$count | Get-Random)
    
        $azSKControlsSub = $this.GetApplicableControlsForSub()
    
        if ($nCtrls -gt $azSKControlsSub.Count)
        {
            Write-Warning "Not enough applicable controls in sub!"
        }
    
        $controls = @($azSKControlsSub | Get-Random -Count $nCtrls)
    
        return $controls
    }
}