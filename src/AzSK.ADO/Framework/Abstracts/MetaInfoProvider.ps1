class MetaInfoProvider {
    hidden static [MetaInfoProvider] $metaInfoInstance = [MetaInfoProvider]::new()
    static [MetaInfoProvider] $Instance = [MetaInfoProvider]::GetInstance()

	hidden [bool] $bUseADOInfoAPI 
	hidden [string] $FuncAPI = '/api/getadoinfo'; 
	hidden [string] $code;
    hidden [string] $baseURL;
    hidden [PSObject] $ControlSettings; 
    
    hidden $buildSTDetails = @{};
    hidden $releaseSTDetails = @{};
    hidden $svcConnSTDetails = @{};
    hidden $agtPoolSTDetails = @{};
    hidden $varGroupSTDetails = @{};
    hidden $serviceTreeDetails = @{};
    
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
            $qs = "?svcId=$svcId&ProjectName=$projectName";
            $rsrcList = $this.CallADOInfoAPI($qs);
        }
        else 
        {
            $this.FetchMappingFiles($resourceTypeName, $projectName);

            $buildList = @();
            $releaseList = @();
            $svcConnList = @();
            $varGroupList = @();
            $agentPoolList = @();

            if ($this.buildSTDetails.ContainsKey($projectName)) {
                $buildList += $this.buildSTDetails."$projectName".Data | Where-Object { ($_.serviceId -eq $svcId) -and ($_.projectName -eq $projectName) }
            }
            if ($this.releaseSTDetails.ContainsKey($projectName)) {
                $releaseList += $this.releaseSTDetails."$projectName".Data | Where-Object { ($_.serviceId -eq $svcId) -and ($_.projectName -eq $projectName) }
            }
            if ($this.svcConnSTDetails.ContainsKey($projectName)) {
                $svcConnList += $this.svcConnSTDetails."$projectName".Data | Where-Object { ($_.serviceId -eq $svcId) -and ($_.projectName -eq $projectName) }
            }
            if ($this.agtPoolSTDetails.ContainsKey($projectName)) {
                $agentPoolList += $this.agtPoolSTDetails."$projectName".Data | Where-Object { ($_.serviceId -eq $svcId) -and ($_.projectName -eq $projectName) }
            }
            if ($this.varGroupSTDetails.ContainsKey($projectName)) {
                $varGroupList += $this.varGroupSTDetails."$projectName".Data | Where-Object { ($_.serviceId -eq $svcId) -and ($_.projectName -eq $projectName) }
            } 
            
            $rsrcList = @{
                Builds = $buildList
                Releases = $releaseList
                ServiceConnections = $svcConnList
                AgentPools = $agentPoolList
                VariableGroups = $varGroupList
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
                $qs = "?ResourceType={0}&ProjectName={1}" -f $resourceTypeName, $projectName
                #call adoinfoapi only if STDetails files is not already loaded.
                $isSTDetailsFilesLoaded = (($resourceTypeName -eq "Build" -and !$this.buildSTDetails.ContainsKey($projectName)) -or ($resourceTypeName -eq "Release" -and !$this.releaseSTDetails.ContainsKey($projectName)) -or ($resourceTypeName -eq "ServiceConnection" -and !$this.svcConnSTDetails.ContainsKey($projectName)) -or ($resourceTypeName -eq "AgentPool" -and !$this.agtPoolSTDetails.ContainsKey($projectName))  -or ($resourceTypeName -eq "VariableGroupp" -and !$this.varGroupSTDetails.ContainsKey($projectName)) );
                if ($isSTDetailsFilesLoaded) {
                    $rsrcList = $this.CallADOInfoAPI($qs);
                    if ($rsrcList -and ( [Helpers]::CheckMember($rsrcList, "Data") -and $rsrcList.Data) ) {
                        $this.BindADOInfoAPIResponseToSTMappingFiles($rsrcList, $resourceTypeName, $projectName);
                    }
                    #If not get files from adoinfoapi, take then from local org policy files. 
                    #else {
                    #    $this.FetchMappingFiles($resourceTypeName);
                    #}
                }
            }
            else 
            {
                $this.FetchMappingFiles($resourceTypeName, $projectName);
            }

            $serviceTreeInfo = $this.GetServiceDataForResource($rscId, $resourceTypeName, $projectName);
        }
        catch
        {
            Write-Host "Could not fetch service mapping files. `r`nPlease contact your project's ADO security team." -ForegroundColor Red 
        }
        return $serviceTreeInfo; 
    }

    #Binding adoinfo api response to class local variable
    hidden [void] BindADOInfoAPIResponseToSTMappingFiles($resourceList, $resourceTypeName, $projectName)
    {
        if ($resourceTypeName -eq "Build") {
            #$this.buildSTDetails = $resourceList;
            $this.buildSTDetails.add($projectName, $resourceList);
        }
        elseif ($resourceTypeName -eq "Release") {
            #$this.releaseSTDetails = $resourceList;
            $this.releaseSTDetails.add($projectName, $resourceList);
        }
        elseif ($resourceTypeName -eq "ServiceConnection") {
            #$this.svcConnSTDetails = $resourceList;
            $this.svcConnSTDetails.add($projectName, $resourceList);
        }
        elseif ($resourceTypeName -eq "AgentPool") {
            #$this.agtPoolSTDetails = $resourceList;
            $this.agtPoolSTDetails.add($projectName, $resourceList);
        }
        elseif ($resourceTypeName -eq "VariableGroup") {
            #$this.varGroupSTDetails = $resourceList;
            $this.varGroupSTDetails.add($projectName, $resourceList);
        }
        elseif ($resourceTypeName -eq "ServiceTree") {
            #$this.serviceTreeDetails = $resourceList;
            $this.serviceTreeDetails.add($projectName, $resourceList);
        }
    }

    #Loading local org policy ST files based on supplied resource type, 
    #1.Fetch ST files from policy only if ...STDetails variable is null (if not already fetch)
    #2.Do not fetch ST files again from policy, if already fetched and file is not present in policy server.
    [void] FetchMappingFiles($ResourceTypeName, $projectName)
	{
		if ($ResourceTypeName -in ([ResourceTypeName]::Build, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User))
		{
		   if (!$this.buildSTDetails.ContainsKey("$projectName")) {
                $this.buildSTDetails.add($projectName, [ConfigurationManager]::LoadServerConfigFile("$projectName\BuildSTData.json"));
                
                #$this.checkBuildSTFileOnServer = $false;
            }	
		}

		if ($ResourceTypeName -in ([ResourceTypeName]::Release, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User))
		{
			if (!$this.releaseSTDetails.ContainsKey("$projectName")) {
                $this.releaseSTDetails.add($projectName, [ConfigurationManager]::LoadServerConfigFile("$projectName\ReleaseSTData.json"));

			}
		}

		if ($ResourceTypeName -in ([ResourceTypeName]::ServiceConnection, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User))
		{
			if (!$this.svcConnSTDetails.ContainsKey("$projectName")) {
                $this.svcConnSTDetails.add($projectName, [ConfigurationManager]::LoadServerConfigFile("$projectName\ServiceConnectionSTData.json"));
                
			}
		}
		if ($ResourceTypeName -in ([ResourceTypeName]::AgentPool, [ResourceTypeName]::All, [ResourceTypeName]::Build_Release_SvcConn_AgentPool_User))
		{
			if (!$this.agtPoolSTDetails.ContainsKey("$projectName")) {
                $this.agtPoolSTDetails.add($projectName, [ConfigurationManager]::LoadServerConfigFile("$projectName\AgentPoolSTData.json"));
                
			}
		}

		if ($ResourceTypeName -in ([ResourceTypeName]::VariableGroup, [ResourceTypeName]::All))
		{
			if (!$this.varGroupSTDetails.ContainsKey("$projectName")) {
                $this.varGroupSTDetails.add($projectName, [ConfigurationManager]::LoadServerConfigFile("$projectName\VariableGroupSTData.json"));
                
            }
        
        }
        
        if ($ResourceTypeName -eq "ServiceTree")
		{
			if (!$this.serviceTreeDetails.ContainsKey("$projectName")) {
                $this.serviceTreeDetails.add($projectName, [ConfigurationManager]::LoadServerConfigFile("$projectName\ServiceTreeData.json"));
                
            }
		}
    }

    #Fetching service tree data based on resource id from ST data loaded in class variables
    hidden [PSObject] GetServiceDataForResource($rscId, $resourceTypeName, $projectName)
    {
        $serviceTreeInfo = $null;
        if(($resourceTypeName -eq "Build") -and $this.buildSTDetails -and $this.buildSTDetails.ContainsKey("$projectName") -and [Helpers]::CheckMember($this.buildSTDetails."$projectName", "Data"))
        {
            $buildSTData = $this.buildSTDetails."$projectName".Data | Where-Object { $_.buildDefinitionID -eq $rscId -and $_.projectName -eq $projectName }; 
            
            if ($buildSTData) 
            {
                $serviceTreeInfo = $this.GetDataFromServiceTree($buildSTData.serviceID, $projectName);
            }
        }
        elseif(($resourceTypeName -eq "Release") -and $this.releaseSTDetails -and $this.releaseSTDetails.ContainsKey("$projectName") -and [Helpers]::CheckMember($this.releaseSTDetails."$projectName", "Data"))
        {
            $releaseSTData = $this.releaseSTDetails."$projectName".Data | Where-Object { $_.releaseDefinitionID -eq $rscId -and $_.projectName -eq $projectName}; 
            if ($releaseSTData) 
            {
                $serviceTreeInfo = $this.GetDataFromServiceTree($releaseSTData.serviceID, $projectName);
            }
        }
        elseif(($resourceTypeName -eq "ServiceConnection") -and $this.svcConnSTDetails -and $this.svcConnSTDetails.ContainsKey("$projectName") -and [Helpers]::CheckMember($this.svcConnSTDetails."$projectName", "Data"))
        {
            $svcConnSTData = $this.svcConnSTDetails."$projectName".Data | Where-Object { $_.serviceConnectionID -eq $rscId -and $_.projectName -eq $projectName}; 
            if ($svcConnSTData) 
            {
                $serviceTreeInfo = $this.GetDataFromServiceTree($svcConnSTData.serviceID, $projectName);
            }
        }
        elseif(($resourceTypeName -eq "AgentPool") -and $this.agtPoolSTDetails -and $this.agtPoolSTDetails.ContainsKey("$projectName") -and [Helpers]::CheckMember($this.agtPoolSTDetails."$projectName", "Data"))
        {
            $agtPoolSTData = $this.agtPoolSTDetails."$projectName".Data | Where-Object { $_.agentPoolID -eq $rscId -and $_.projectName -eq $projectName}; 
            if ($agtPoolSTData) 
            {
                $serviceTreeInfo = $this.GetDataFromServiceTree($agtPoolSTData.serviceID, $projectName);
            }
        }
        elseif(($resourceTypeName -eq "VariableGroup") -and $this.varGroupSTDetails -and $this.varGroupSTDetails.ContainsKey("$projectName") -and [Helpers]::CheckMember($this.varGroupSTDetails."$projectName", "Data"))
        {
            $varGroupSTData = $this.varGroupSTDetails."$projectName".Data | Where-Object { $_.variableGroupID -eq $rscId -and $_.projectName -eq $projectName}; 
            if ($varGroupSTData) 
            {
                $serviceTreeInfo = $this.GetDataFromServiceTree($varGroupSTData.serviceID, $projectName);
            }
        }

        return $serviceTreeInfo;
    }

    #Fetching Service tree info data based on service id from service tree mapping file
    hidden [PSObject] GetDataFromServiceTree($serviceId, $projectName) 
    {
        $serviceTreeInfo = $null;        
        if (!$this.serviceTreeDetails.ContainsKey("$projectName")) 
        {
            if ($this.bUseADOInfoAPI -eq $true) {
                $qs = "?ResourceType=ServiceTree&ProjectName=$projectName"; 
                $rsrcList = $this.CallADOInfoAPI($qs);
                if ($rsrcList -and [Helpers]::CheckMember($rsrcList, "Data") -and $rsrcList.Data) {
                    $this.BindADOInfoAPIResponseToSTMappingFiles($rsrcList, "ServiceTree", $projectName);
                }
                #If not get file from adoinso api, get it from local org policy file.
                #else {
                #    $this.FetchMappingFiles("ServiceTree");
                #}
            }
            else {
                $this.FetchMappingFiles("ServiceTree", $projectName);
            }  
        }
        if ($this.serviceTreeDetails -and $this.serviceTreeDetails.ContainsKey("$projectName") -and [Helpers]::CheckMember($this.serviceTreeDetails."$projectName", "Data")) {
            $serviceTreeInfo = $this.serviceTreeDetails."$projectName".Data | Where-Object { $_.serviceID -eq $serviceId };
        }
        return $serviceTreeInfo;
    }
}

