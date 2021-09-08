Set-StrictMode -Version Latest 
class AzSKControlInfo
{
    [string] $ControlDetailsFile = $null;
    [string] $ARMCheckerControlsFile = $null;

    [PSObject[]] $AzSKControlInfoAll = @(); #Includes GSS controls
    [PSObject[]] $AzSKControlInfo = @();  #GRS controls only.
    static [PSObject[]] $ARMCheckerControlInfo = @();  #ARM Checker controls only.
    static [PSObject[]] $AzSKControlInfoUBC = @();
    static [PSObject[]] $AzSKControlInfoUPBC = @();

    [PSObject[]] $AzSkSupportedResourceTypeMapping =  @();
    [PSObject[]] $AzSkSupportedResourceTypes =  @();

    [PSObject[]] $AzSKResourceTypeNamesAll =  @();
    [PSObject[]] $AzSKResourceTypeNamesUBC = @();

    [PSObject[]] $AzSKAzureResourceTypesAll = @();
    [PSObject[]] $AzSKAzureResourceTypesUBC = @();

    $AzSKImptFilterTags = @('OwnerAccess', 'GraphRead', 'SOX');
    $AzSKImptExcludeTags = @('OwnerAccess', 'GraphRead', 'Databricks', 'RBAC') ;   

    AzSKControlInfo([bool] $getFromModule=$false)
	{	
        if ($getFromModule -eq $false)
        {
            #We use the cached one 
            $this.ControlDetailsFile = "$([CommonHelper]::GetRootPath())\Core\TestData\Control_Details_azsk_4.9.0.csv"
            Write-Warning("Loading hard-coded AzSKControlInfo from: `r`n$($this.ControlDetailsFile)")
            $this.ARMCheckerControlsFile = "$([CommonHelper]::GetRootPath())\Core\TestData\ARMControls.json"
            Write-Warning("Loading hard-coded ARMCheckerControlsFile from: `r`n$($this.ARMCheckerControlsFile)")
        }
        else 
        {
            throw "Yet to implement getFromModule for AzSKControlInfo."
        }
        <# Array of control details, each row contains:
                FeatureName       : RedisCache
                ControlID         : Azure_RedisCache_AuthZ_Configure_IP_Range
                Description       : Configure Redis Cache firewall settings for additional protection
                ControlSeverity   : Moderate
                IsBaselineControl : No
                Rationale         : Using the firewall feature ensures that access to the data or the 
                                                service is restricted to a specific set/group of clients. NOTE: 
                                                While this control does provide an extra layer of access control 
                                                protection, it may not always be feasible to implement in all 
                                                scenarios.
                Recommendation    : Enable firewall and add rules specifying permitted IPs/ranges. Do 
                                                not add IP range 0.0.0.0-255.255.255.255 as that allows access to 
                                                all possible IPs. Refer: https://docs.microsoft.com/en-us/azure/redis
                                                -cache/cache-configure#firewall, (REST API) 
                                                https://docs.microsoft.com/en-in/rest/api/redis/redisfirewallrule.  
                                                Note: In case the IP range is indeterminate (for instance, if the 
                                                client is a PaaS endpoint), you may need to attest this control.
                Automated         : Yes
                SupportsAutoFix   : No
                Tags              : SDL, Best Practice, Automated, AuthZ, RedisCache
        #>
        $this.InitAzSKControlInfo()
    }   

    [void] InitAzSKControlInfo()
    {   
        $this.AzSKControlInfoAll = Import-CSV $this.ControlDetailsFile
        $this.AzSKControlInfo = $this.AzSKControlInfoAll | ? {$_.FeatureName -ne 'AzSKCfg'}
        [AzSKControlInfo]::ARMCheckerControlInfo = Get-Content $this.ARMCheckerControlsFile | Out-String | ConvertFrom-Json

        [AzSKControlInfo]::AzSKControlInfoUBC = ($this.AzSKControlInfo | ?{$_.IsBaselineControl -eq 'Yes'})
        [AzSKControlInfo]::AzSKControlInfoUPBC = ($this.AzSKControlInfo | ?{$_.IsPreviewBaselineControl -eq 'Yes'})


        $this.AzSkSupportedResourceTypeMapping = Get-AzSKSupportedResourceTypes
        <# Table of mappings, each row containing:
            "ResourceTypeName":  "APIConnection",
            "ResourceType":  "Microsoft.Web/connections"
        #>

        $this.AzSKSupportedResourceTypes = ($this.AzSKSupportedResourceTypeMapping  | ForEach-Object {$_.ResourceType} )

        $this.AzSKResourceTypeNamesAll = ($this.AzSKControlInfo | Select-Object FeatureName -Unique)
        $this.AzSKResourceTypeNamesUBC = ( [AzSKControlInfo]::AzSKControlInfoUBC | Select-Object FeatureName -Unique).FeatureName

        $this.AzSKAzureResourceTypesAll = $this.GetAzureResourceTypesForAzSKResourceTypeNames($this.AzSKSupportedResourceTypeMapping.ResourceTypeName)
        $this.AzSKAzureResourceTypesUBC = $this.GetAzureResourceTypesForAzSKResourceTypeNames($this.AzSKResourceTypeNamesUBC)
    }

    [string[]]  GetAzSKResourceTypeNamesForAzureResourceTypes($azureResourceTypes)
    {
        $azskRTNs =  new-object collections.generic.list[object]
        foreach ($azType in $azureResourceTypes)
        {
            #Write-Host $azType
            $azSKTypeName = @(($this.AzSkSupportedResourceTypeMapping | where-object {$_.ResourceType -eq $azType}).ResourceTypeName)

            if ($azSKTypeName.Count -ne 1)
            {
                Write-Warning "Found two mappings for [$azType]: [$azSKTypeName]" #This happens for vNet --> ERvNet, VirtualNetwork
                foreach ($t in $azSKTypeName)
                {
                    $azSKRTNs.Add($t)
                }
            }
            else
            {
                $azskRTNs.Add($azSKTypeName)
            }

        }
        return $azSKRTNs
    }

    [string[]] GetAzureResourceTypesForAzSKResourceTypeNames($azskResourceTypeNames)
    {
        $azRTs =  new-object collections.generic.list[object]
        #Write-Host $azskResourceTypeNames
        foreach ($azSKTN in $azskResourceTypeNames)
        {
            #Write-Host "Looking for: $azSKTN"
            $azTypeEntry = @($this.AzSkSupportedResourceTypeMapping | where-object {$_.ResourceTypeName -eq $azSKTN})
            if ($azTypeEntry.Count -ne 0)
            {
                $azRTs.Add($azTypeEntry.ResourceType)
            }

        }
        return $azRTs
    }

    [void] RefreshAzSKControlInfo([String] $subscriptionId)
    {
        $cmdOutput = Get-AzSKInfo -InfoType ControlInfo -SubscriptionId $subscriptionId -DoNotOpenOutputFolder
        if(![String]::IsNullOrEmpty($cmdOutput) -and $(Test-Path -Path "$($cmdOutput)\Control Details.csv" ))
        {
            $this.ControlDetailsFile = "$($cmdOutput)\Control Details.csv"
            $this.InitAzSKControlInfo()
        }
        else
        {
            Write-Error "Control details file update failed. Please update the file manually."
        }
    }

    [PSCustomObject[]] FilterControlsWithTags($listOfTags)
    {
        $matchTags = $null
        if (@($listOfTags).Count -ne 0)
        {
            $matchTags = $listOfTags -join '|'
        }
        Write-Host "Filtering for tags: [$matchTags]"
        return @($this.AzSKControlInfo | ? {$_.Tags -match $matchTags})
    }

    [PSCustomObject[]] ExcludeControlsWithTags($listOfTags)
    {
        $matchTags = $null
        if (@($listOfTags).Count -ne 0)
        {
            $matchTags = $listOfTags -join '|'
        }
        Write-Host "Excluding tags: [$matchTags]"
        return @($this.AzSKControlInfo | ? {$_.Tags -notmatch $matchTags})
    }

    [PSCustomObject[]] GetRandomFilterTags()
    {		
        #Random subset
        $numTags = 1..$this.AzSKImptFilterTags.Count | Get-Random
        $rngIdx = 0..($this.AzSKImptFilterTags.Count - 1) | Get-Random -Count $numTags
            
        $fTagsScan = $this.AzSKImptFilterTags[$rngIdx]
        return @($fTagsScan)
    }

    [PSCustomObject[]] GetRandomExcludeTags()
    {	
        #Random subset
        $numTags = 1..$this.AzSKImptExcludeTags.Count | Get-Random
        $rngIdx = 0..($this.AzSKImptExcludeTags.Count - 1) | Get-Random -Count $numTags
        $xTagsScan = $this.AzSKImptExcludeTags[$rngIdx]
        return @($xTagsScan)
    }


    [PSCustomObject[]] GetAzSKRTNsForControls($ctrls)
    {
        return  @(($ctrls | Select-Object FeatureName -Unique).FeatureName)
    }


    [PSCustomObject[]] GetControlsForAzSKRTNs($rtns)
    {
        return  @( $this.AzSKControlInfo | ?{$rtns -eq $_.FeatureName} )
    }

    [PSCustomObject[]] GetRandomControlsForAzSKRTNs($rtns)
    {   
        return $this.GetRandomControlsForAzSKRTNs($rtns, 0)
    }
    
    [PSCustomObject[]] GetRandomControlsForAzSKRTNs($rtns, $count=0)
    {
        $controlsForRTNs = $this.GetControlsForAzSKRTNs($rtns)

        $nControls = 0

        if ($count -gt 0)
        {
            $nControls = $count
        }
        else
        {
            #Select a random count (n)
            $nControls = (1..$controlsForRTNs.Count) | Get-Random
        }

        # Select 1..n from controlIds of that RsrcType

        return @( $controlsForRTNs | Get-Random -count $nControls )
    }
    [PSCustomObject[]] GetValidControlSeverities()
    {
        #TODO: Get the values from Server
        $validValues = @('Important','Critical','Moderate','Low');
        return $validValues;
    }
}