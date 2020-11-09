class MetaInfoProvider {
    hidden static [MetaInfoProvider] $_instance = [MetaInfoProvider]::new()
    static [MetaInfoProvider] $Instance = [MetaInfoProvider]::GetInstance()

	hidden [bool] $bUseADOInfoAPI 
	hidden [string] $FuncAPI = '/api/getadoinfo'; 
	hidden [string] $code;
    hidden [string] $baseURL;
    hidden [PSObject] $ControlSettings; 
    
    hidden [PSObject] $buildSTDetails;
    hidden [PSObject] $releaseSTDetails;
    hidden [PSObject] $svcConnSTDetails;
    hidden [PSObject] $agtPoolSTDetails;
    hidden [PSObject] $varGroupSTDetails;
    hidden [PSObject] $serviceTreeDetails;

    hidden MetaInfoProvider() {
    }

    hidden static [MetaInfoProvider] GetInstance() {
        return [MetaInfoProvider]::_instance
    }

    [bool] CheckIsADOInfoAPIEnabled()
	{
        if ($null -eq $this.ControlSettings)
        {
            $this.ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
        }
        $adoInfoAPI = $this.ControlSettings.ADOInfoAPI;
        if ($null -ne $adoInfoAPI -and $Env:AzSKADODoNotUseADOInfoAPI -ne $true)
        {
            #TODO
            #$adoInfoAPI.Enabled = $false;
            if ($adoInfoAPI.Enabled)
            {
                $this.bUseADOInfoAPI = $true;
                $this.code = $adoInfoAPI.Code;
                $this.baseURL = $adoInfoAPI.Endpoint;
            }
		}
		return $this.bUseADOInfoAPI;
	}

	[PSObject] CallADOInfoAPI($queryString )
	{
        $adoInfoInvokeURL = $this.baseURL + $this.FuncAPI + $queryString
        $Header = @{
            "x-functions-key" = $this.code;
        }
        $rsrcList = $null
        
        try 
        {
            $rsrcList = Invoke-RestMethod -Method 'GET' -Uri $adoInfoInvokeURL -Headers $Header
        }
        catch
        {
            Write-Host "Error calling ADO Info API. `r`nPlease contact your project's ADO security team." -ForegroundColor Red 
        }
        return $rsrcList;
	}

	[void] FetchMappingFiles($ResourceTypeName)
	{
		if ($ResourceTypeName -in ([ResourceTypeName]::Build, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User))
		{
		   if (!$this.buildSTDetails) {
                $this.buildSTDetails = [ConfigurationManager]::LoadServerConfigFile("BuildSTData.json");
               }	
		}

		if ($ResourceTypeName -in ([ResourceTypeName]::Release, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User))
		{
			if (!$this.releaseSTDetails) {
				$this.releaseSTDetails = [ConfigurationManager]::LoadServerConfigFile("ReleaseSTData.json");
			}
		}

		if ($ResourceTypeName -in ([ResourceTypeName]::ServiceConnection, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User))
		{
			if (!$this.svcConnSTDetails) {
				$this.svcConnSTDetails = [ConfigurationManager]::LoadServerConfigFile("ServiceConnectionSTData.json");
			}
		}
		if ($ResourceTypeName -in ([ResourceTypeName]::AgentPool, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User))
		{
			if (!$this.agtPoolSTDetails) {
				$this.agtPoolSTDetails = [ConfigurationManager]::LoadServerConfigFile("AgentPoolSTData.json");
			}
		}

		if ($ResourceTypeName -in ([ResourceTypeName]::VariableGroup, [ResourceTypeName]::All))
		{
			if (!$this.varGroupSTDetails) {
				$this.varGroupSTDetails = [ConfigurationManager]::LoadServerConfigFile("VariableGroupSTData.json");
			}
        }
        if ($ResourceTypeName -eq "ServiceTree")
		{
			if (!$this.serviceTreeDetails) {
				$this.serviceTreeDetails = [ConfigurationManager]::LoadServerConfigFile("ServiceTreeData.json");
			}
		}
    }
    
    [PSObject] FetchServiceAssociatedResources($svcId, $projectName, $ResourceTypeName)
    {
        $rsrcList = $null;
        if ($this.bUseADOInfoAPI -eq $true -or $this.CheckIsADOInfoAPIEnabled())
        {
            #TODO: Look at cleaning up these multiple "-in" checks across the API_call-v-Policy_Repo cases...
            #TODO-PERF: For now we are erring on the side of avoiding multiple network calls...revisit based on observed pattern of -svcid <xyz> usage
            $qs = "?svcId={0}" -f $svcId
            $rsrcList = $this.CallADOInfoAPI($qs);
        }
        else 
        {
            $this.FetchMappingFiles($ResourceTypeName);

            $buildList = @{};
            $releaseList = @{};
            $svcConnList = @{};
            $varGroupList = @{};
            $agentPoolList = @{};

            if ($this.buildSTDetails) {
                $buildList = $this.buildSTDetails.Data | Where-Object { ($_.serviceId -eq $svcId) -and ($_.projectName -eq $projectName) }
            }
            if ($this.releaseSTDetails) {
                $releaseList = $this.releaseSTDetails.Data | Where-Object { ($_.serviceId -eq $svcId) -and ($_.projectName -eq $projectName) }
            }
            if ($this.svcConnSTDetails) {
                $svcConnList = $this.svcConnSTDetails.Data | Where-Object { ($_.serviceId -eq $svcId) -and ($_.projectName -eq $projectName) }
            }
            if ($this.agtPoolSTDetails) {
                $agentPoolList = $this.agtPoolSTDetails.Data | Where-Object { ($_.serviceId -eq $svcId) -and ($_.projectName -eq $projectName) }
            }
            if ($this.varGroupSTDetails) {
                $varGroupList = $this.varGroupSTDetails.Data | Where-Object { ($_.serviceId -eq $svcId) -and ($_.projectName -eq $projectName) }
            } 
            
            $rsrcList = @{
                Builds = $buildList
                Releases = $releaseList
                SvcConns = $svcConnList
                VarGroups = $varGroupList
                AgentPools = $agentPoolList
            }

        }
        return $rsrcList; 
    }
    
    [PSObject] FetchResourceMappingWithServiceData($rscId, $projectName, $resourceTypeName)
    {
        $serviceTree = $null;
        try 
        {
            #check if adoinfoapi is enabled in org-policy file 
            if ($this.bUseADOInfoAPI -eq $true -or $this.CheckIsADOInfoAPIEnabled())
            {
                $qs = "?ResourceType=$resourceTypeName";
                #call adoinfoapi only if STDetails files is not already loaded.
                if ( ($resourceTypeName -eq "Build" -and !$this.buildSTDetails) -or ($resourceTypeName -eq "Release" -and !$this.releaseSTDetails) -or ($resourceTypeName -eq "ServiceConnection" -and !$this.svcConnSTDetails) -or ($resourceTypeName -eq "AgentPool" -and !$this.agtPoolSTDetails)  -or ($resourceTypeName -eq "VariableGroupp" -and !$this.varGroupSTDetails) ) {
                    $rsrcList = $this.CallADOInfoAPI($qs);
                    $apiReturnedResourceTypeName = $resourceTypeName+"s";
                    if ($rsrcList -and ( [Helpers]::CheckMember($rsrcList, "$apiReturnedResourceTypeName") -and $rsrcList."$apiReturnedResourceTypeName") ) {
                        $this.BindADOInfoAPIResponseToSTMappingFiles($rsrcList, $resourceTypeName);
                    }
                    else {
                        $this.FetchMappingFiles($resourceTypeName);
                    }
                }
                
                $serviceTree = $this.GetServiceDataForResource($rscId, $resourceTypeName);
            }
            else 
            {
                $this.FetchMappingFiles($resourceTypeName);
                $serviceTree = $this.GetServiceDataForResource($rscId, $resourceTypeName);
            }
        }
        catch
        {
            Write-Host "Could not fetch service mapping files. `r`nPlease contact your project's ADO security team." -ForegroundColor Red 
        }
        return $serviceTree; 
    }

    hidden [void] BindADOInfoAPIResponseToSTMappingFiles($resourceList, $resourceTypeName)
    {
        if ($resourceTypeName -eq "Build") {
            $this.buildSTDetails = $resourceList.Builds;
        }
        elseif ($resourceTypeName -eq "Release") {
            $this.releaseSTDetails = $resourceList.Releases;
        }
        elseif ($resourceTypeName -eq "ServiceConnection") {
            $this.svcConnSTDetails = $resourceList.ServiceConnections;
        }
        elseif ($resourceTypeName -eq "AgentPool") {
            $this.agtPoolSTDetails = $resourceList.AgentPools;
        }
        elseif ($resourceTypeName -eq "VariableGroup") {
            $this.varGroupSTDetails = $resourceList.VariableGroups;
        }
    }

    hidden [PSObject] GetServiceDataForResource($rscId, $resourceTypeName)
    {
        $serviceTree = $null;
        if(($resourceTypeName -eq "Build") -and $this.buildSTDetails -and [Helpers]::CheckMember($this.buildSTDetails, "Data"))
        {
            $buildSTData = $this.buildSTDetails.Data | Where-Object { $_.buildDefinitionID -eq $rscId -and $_.projectName -eq $projectName }; 
            
            if ($buildSTData) 
            {
                $serviceTree = $this.GetDataFromServiceTree($buildSTData.serviceID);
            }
        }
        elseif(($resourceTypeName -eq "Release") -and $this.releaseSTDetails -and [Helpers]::CheckMember($this.releaseSTDetails, "Data"))
        {
            $releaseSTData = $this.releaseSTDetails.Data | Where-Object { $_.releaseDefinitionID -eq $rscId -and $_.projectName -eq $projectName}; 
            if ($releaseSTData) 
            {
                $serviceTree = $this.GetDataFromServiceTree($releaseSTData.serviceID);
            }
        }
        elseif(($resourceTypeName -eq "ServiceConnection") -and $this.svcConnSTDetails -and [Helpers]::CheckMember($this.svcConnSTDetails, "Data"))
        {
            $svcConnSTData = $this.svcConnSTDetails.Data | Where-Object { $_.serviceConnectionID -eq $rscId -and $_.projectName -eq $projectName}; 
            if ($svcConnSTData) 
            {
                $serviceTree = $this.GetDataFromServiceTree($svcConnSTData.serviceID);
            }
        }
        elseif(($resourceTypeName -eq "AgentPool") -and $this.agtPoolSTDetails -and [Helpers]::CheckMember($this.agtPoolSTDetails, "Data"))
        {
            $agtPoolSTData = $this.agtPoolSTDetails.Data | Where-Object { $_.agentPoolID -eq $rscId -and $_.projectName -eq $projectName}; 
            if ($agtPoolSTData) 
            {
                $serviceTree = $this.GetDataFromServiceTree($agtPoolSTData.serviceID);
            }
        }
        elseif(($resourceTypeName -eq "VariableGroup") -and $this.varGroupSTDetails -and [Helpers]::CheckMember($this.varGroupSTDetails, "Data"))
        {
            $varGroupSTData = $this.varGroupSTDetails.Data | Where-Object { $_.variableGroupID -eq $rscId -and $_.projectName -eq $projectName}; 
            if ($varGroupSTData) 
            {
                $serviceTree = $this.GetDataFromServiceTree($varGroupSTData.serviceID);
            }
        }

        return $serviceTree;
    }

    hidden [PSObject] GetDataFromServiceTree($serviceId) 
    {
        $serviceTree = $null;        
        if (!$this.serviceTreeDetails) 
        {
            $qs = "?ResourceType=ServiceTree";
            if ($this.bUseADOInfoAPI -eq $true) {
                $rsrcList = $this.CallADOInfoAPI($qs);
                if ($rsrcList -and [Helpers]::CheckMember($rsrcList, "serviceTreeDetails") -and $rsrcList.serviceTreeDetails) {
                    $this.BindADOInfoAPIResponseToSTMappingFiles($rsrcList, "ServiceTree");
                }
                else {
                    $this.FetchMappingFiles("ServiceTree");
                }
            }
            else {
                $this.FetchMappingFiles("ServiceTree");
            }  
        }
        if ($this.serviceTreeDetails -and [Helpers]::CheckMember($this.serviceTreeDetails, "Data")) {
            $serviceTree = $this.serviceTreeDetails.Data | Where-Object { $_.serviceID -eq $serviceId };
        }
        return $serviceTree;
    }
}

