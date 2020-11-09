class MetaInfoProvider {
    hidden static [MetaInfoProvider] $metaInfoInstance = [MetaInfoProvider]::new()
    static [MetaInfoProvider] $Instance = [MetaInfoProvider]::metaInfoInstance # [MetaInfoProvider]::GetInstance()

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
    
    #Variable to check whether ST file is present in policy, if ST file is not present then set them to false so for next resource don't call policy server to fetch this file
    hidden [bool] $checkBuildSTFileOnServer = $true;	
    hidden [bool] $checkReleaseSTFileOnServer = $true;
    hidden [bool] $checkServiceConnectionSTFileOnServer = $true;
    hidden [bool] $checkAgentPoolSTFileOnServer = $true;	
    hidden [bool] $checkVariableGroupSTFileOnServer = $true;	
    hidden [bool] $checkServiceTreeFileOnServer = $true;

    hidden MetaInfoProvider() {
        #Getting call only once and set bUseADOInfoAPI
        $this.IsADOInfoAPIEnabled();
    }

    #Return MetaInfoProvider instance
    hidden static [MetaInfoProvider] GetInstance() {
        return [MetaInfoProvider]::metaInfoInstance
    }

    #checking adoinfo api is enabled or not in org policy file
    [bool] IsADOInfoAPIEnabled()
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

    #Calling adoinfo api and returning response
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
    
    #Fetching sesrvice id associated resources and internally calling adoinfo api if enabled else getting data from local org policy files
    [PSObject] FetchServiceAssociatedResources($svcId, $projectName, $resourceTypeName)
    {
        $rsrcList = $null;
        if ($this.bUseADOInfoAPI -eq $true)
        {
            #TODO: Look at cleaning up these multiple "-in" checks across the API_call-v-Policy_Repo cases...
            #TODO-PERF: For now we are erring on the side of avoiding multiple network calls...revisit based on observed pattern of -svcid <xyz> usage
            $qs = "?svcId={0}" -f $svcId
            $rsrcList = $this.CallADOInfoAPI($qs);
        }
        else 
        {
            $this.FetchMappingFiles($resourceTypeName);

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
    
    #Fetching service tree info details based on resource id and internally calling adoinfo api and loading resource file if enabled, else loading resource file from local org policy files
    [PSObject] FetchResourceMappingWithServiceData($rscId, $projectName, $resourceTypeName)
    {
        $serviceTreeInfo = $null;
        try 
        {
            #check if adoinfoapi is enabled in org-policy file 
            if ($this.bUseADOInfoAPI -eq $true)
            {
                $qs = "?ResourceType=$resourceTypeName";
                #call adoinfoapi only if STDetails files is not already loaded.
                if ( ($resourceTypeName -eq "Build" -and !$this.buildSTDetails) -or ($resourceTypeName -eq "Release" -and !$this.releaseSTDetails) -or ($resourceTypeName -eq "ServiceConnection" -and !$this.svcConnSTDetails) -or ($resourceTypeName -eq "AgentPool" -and !$this.agtPoolSTDetails)  -or ($resourceTypeName -eq "VariableGroupp" -and !$this.varGroupSTDetails) ) {
                    $rsrcList = $this.CallADOInfoAPI($qs);
                    $apiReturnedResourceTypeName = $resourceTypeName+"s";
                    if ($rsrcList -and ( [Helpers]::CheckMember($rsrcList, "$apiReturnedResourceTypeName") -and $rsrcList."$apiReturnedResourceTypeName") ) {
                        $this.BindADOInfoAPIResponseToSTMappingFiles($rsrcList, $resourceTypeName);
                    }
                    #If not get files from adoinfoapi, take then from local org policy files. 
                    #else {
                    #    $this.FetchMappingFiles($resourceTypeName);
                    #}
                }
            }
            else 
            {
                $this.FetchMappingFiles($resourceTypeName);
            }

            $serviceTreeInfo = $this.GetServiceDataForResource($rscId, $resourceTypeName);
        }
        catch
        {
            Write-Host "Could not fetch service mapping files. `r`nPlease contact your project's ADO security team." -ForegroundColor Red 
        }
        return $serviceTreeInfo; 
    }

    #Binding adoinfo api response to class local variable
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
        elseif ($resourceTypeName -eq "ServiceTree") {
            $this.serviceTreeDetails = $resourceList.ServiceTree;
        }
    }

    #Loading local org policy ST files based on supplied resource type, 
    #1.Fetch ST files from policy only if ...STDetails variable is null (if not already fetch)
    #2.Do not fetch ST files again from policy, if already fetched and file is not present in policy server.
    [void] FetchMappingFiles($ResourceTypeName)
	{
		if ($ResourceTypeName -in ([ResourceTypeName]::Build, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User))
		{
		   if (!$this.buildSTDetails -and $this.checkBuildSTFileOnServer) {
                $this.buildSTDetails = [ConfigurationManager]::LoadServerConfigFile("BuildSTData.json");
                
                $this.checkBuildSTFileOnServer = $false;
            }	
		}

		if ($ResourceTypeName -in ([ResourceTypeName]::Release, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User))
		{
			if (!$this.releaseSTDetails -and $this.checkReleaseSTFileOnServer) {
                $this.releaseSTDetails = [ConfigurationManager]::LoadServerConfigFile("ReleaseSTData.json");

                $this.checkReleaseSTFileOnServer = $false;
			}
		}

		if ($ResourceTypeName -in ([ResourceTypeName]::ServiceConnection, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User))
		{
			if (!$this.svcConnSTDetails -and $this.checkServiceConnectionSTFileOnServer) {
                $this.svcConnSTDetails = [ConfigurationManager]::LoadServerConfigFile("ServiceConnectionSTData.json");
                
                $this.checkServiceConnectionSTFileOnServer = $false;
			}
		}
		if ($ResourceTypeName -in ([ResourceTypeName]::AgentPool, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User))
		{
			if (!$this.agtPoolSTDetails -and $this.checkAgentPoolSTFileOnServer) {
                $this.agtPoolSTDetails = [ConfigurationManager]::LoadServerConfigFile("AgentPoolSTData.json");
                
                $this.checkAgentPoolSTFileOnServer = $false;
			}
		}

		if ($ResourceTypeName -in ([ResourceTypeName]::VariableGroup, [ResourceTypeName]::All))
		{
			if (!$this.varGroupSTDetails -and $this.checkVariableGroupSTFileOnServer) {
                $this.varGroupSTDetails = [ConfigurationManager]::LoadServerConfigFile("VariableGroupSTData.json");
                $this.checkVariableGroupSTFileOnServer = $false;
                
            }
        
        }
        
        if ($ResourceTypeName -eq "ServiceTree")
		{
			if (!$this.serviceTreeDetails -and $this.checkServiceTreeFileOnServer) {
                $this.serviceTreeDetails = [ConfigurationManager]::LoadServerConfigFile("ServiceTreeData.json");
                $this.checkServiceTreeFileOnServer = $false;
            }
		}
    }

    #Fetching service tree data based on resource id from ST data loaded in class variables
    hidden [PSObject] GetServiceDataForResource($rscId, $resourceTypeName)
    {
        $serviceTreeInfo = $null;
        if(($resourceTypeName -eq "Build") -and $this.buildSTDetails -and [Helpers]::CheckMember($this.buildSTDetails, "Data"))
        {
            $buildSTData = $this.buildSTDetails.Data | Where-Object { $_.buildDefinitionID -eq $rscId -and $_.projectName -eq $projectName }; 
            
            if ($buildSTData) 
            {
                $serviceTreeInfo = $this.GetDataFromServiceTree($buildSTData.serviceID);
            }
        }
        elseif(($resourceTypeName -eq "Release") -and $this.releaseSTDetails -and [Helpers]::CheckMember($this.releaseSTDetails, "Data"))
        {
            $releaseSTData = $this.releaseSTDetails.Data | Where-Object { $_.releaseDefinitionID -eq $rscId -and $_.projectName -eq $projectName}; 
            if ($releaseSTData) 
            {
                $serviceTreeInfo = $this.GetDataFromServiceTree($releaseSTData.serviceID);
            }
        }
        elseif(($resourceTypeName -eq "ServiceConnection") -and $this.svcConnSTDetails -and [Helpers]::CheckMember($this.svcConnSTDetails, "Data"))
        {
            $svcConnSTData = $this.svcConnSTDetails.Data | Where-Object { $_.serviceConnectionID -eq $rscId -and $_.projectName -eq $projectName}; 
            if ($svcConnSTData) 
            {
                $serviceTreeInfo = $this.GetDataFromServiceTree($svcConnSTData.serviceID);
            }
        }
        elseif(($resourceTypeName -eq "AgentPool") -and $this.agtPoolSTDetails -and [Helpers]::CheckMember($this.agtPoolSTDetails, "Data"))
        {
            $agtPoolSTData = $this.agtPoolSTDetails.Data | Where-Object { $_.agentPoolID -eq $rscId -and $_.projectName -eq $projectName}; 
            if ($agtPoolSTData) 
            {
                $serviceTreeInfo = $this.GetDataFromServiceTree($agtPoolSTData.serviceID);
            }
        }
        elseif(($resourceTypeName -eq "VariableGroup") -and $this.varGroupSTDetails -and [Helpers]::CheckMember($this.varGroupSTDetails, "Data"))
        {
            $varGroupSTData = $this.varGroupSTDetails.Data | Where-Object { $_.variableGroupID -eq $rscId -and $_.projectName -eq $projectName}; 
            if ($varGroupSTData) 
            {
                $serviceTreeInfo = $this.GetDataFromServiceTree($varGroupSTData.serviceID);
            }
        }

        return $serviceTreeInfo;
    }

    #Fetching Service tree info data based on service id from service tree mapping file
    hidden [PSObject] GetDataFromServiceTree($serviceId) 
    {
        $serviceTreeInfo = $null;        
        if (!$this.serviceTreeDetails) 
        {
            $qs = "?ResourceType=ServiceTree";
            if ($this.bUseADOInfoAPI -eq $true) {
                $rsrcList = $this.CallADOInfoAPI($qs);
                if ($rsrcList -and [Helpers]::CheckMember($rsrcList, "serviceTreeDetails") -and $rsrcList.serviceTreeDetails) {
                    $this.BindADOInfoAPIResponseToSTMappingFiles($rsrcList, "ServiceTree");
                }
                #If not get file from adoinso api, get it from local org policy file.
                #else {
                #    $this.FetchMappingFiles("ServiceTree");
                #}
            }
            else {
                $this.FetchMappingFiles("ServiceTree");
            }  
        }
        if ($this.serviceTreeDetails -and [Helpers]::CheckMember($this.serviceTreeDetails, "Data")) {
            $serviceTreeInfo = $this.serviceTreeDetails.Data | Where-Object { $_.serviceID -eq $serviceId };
        }
        return $serviceTreeInfo;
    }
}

