Set-StrictMode -Version Latest
class AutoBugLog {
    hidden static [AutoBugLog] $AutoBugInstance;
    hidden [ControlStateExtension] $ControlStateExt;
    hidden [string] $OrganizationName;
    hidden [InvocationInfo] $InvocationContext;
    hidden [PSObject] $ControlSettings; 
    hidden [bool] $IsBugLogCustomFlow = $false;
    hidden [bool] $ShowBugsInS360 = $false;

    hidden [string] $BugLogParameterValue;
    hidden [string] $BugDescriptionField;
    hidden [string] $ServiceIdPassedInCMD;

    hidden [bool] $UseAzureStorageAccount = $false;
    hidden [BugLogHelper] $BugLogHelperObj;
    hidden [string] $ScanSource;
    hidden [bool] $LogBugsForUnmappedResource = $true;
    
    AutoBugLog([string] $orgName, [InvocationInfo] $invocationContext, [ControlStateExtension] $controlStateExt, $bugLogParameterValue) {
        $this.OrganizationName = $orgName;
        $this.InvocationContext = $invocationContext;	
        $this.ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
        $this.ControlStateExt = $controlStateExt    
        $this.BugLogParameterValue = $bugLogParameterValue  
        
        #flag to check if pluggable bug logging interface (service tree)
        if ([Helpers]::CheckMember($this.ControlSettings.BugLogging, "BugAssigneeAndPathCustomFlow", $null)) {
            $this.IsBugLogCustomFlow = $this.ControlSettings.BugLogging.BugAssigneeAndPathCustomFlow;
            $this.ServiceIdPassedInCMD = $InvocationContext.BoundParameters["ServiceId"];
        }
        $this.ScanSource = [AzSKSettings]::GetInstance().GetScanSource();
        
        #If UseAzureStorageAccount is true then initialize the BugLogHelperObj singleton class object.
        if ([Helpers]::CheckMember($this.ControlSettings.BugLogging, "UseAzureStorageAccount")) {
            $this.UseAzureStorageAccount = $this.ControlSettings.BugLogging.UseAzureStorageAccount;
            if ($this.UseAzureStorageAccount) {
                $this.BugLogHelperObj = [BugLogHelper]::BugLogHelperInstance
		        if (!$this.BugLogHelperObj) {
		        	$this.BugLogHelperObj = [BugLogHelper]::GetInstance($this.OrganizationName);
		        }
            }
        }

        # Replace the field reference name for bug description if it is customized
        if ($this.InvocationContext.BoundParameters['BugDescriptionField']) {
            $this.BugDescriptionField = "/fields/" + $this.InvocationContext.BoundParameters['BugDescriptionField']
        }
        elseif ([Helpers]::CheckMember($this.controlsettings.BugLogging, 'BugDescriptionField') -and -not ([string]::IsNullOrEmpty($this.ControlSettings.BugLogging.BugDescriptionField))) {
            $this.BugDescriptionField = "/fields/" + $this.ControlSettings.BugLogging.BugDescriptionField
        }

        #Check whether LogBugsForUnmappedResource variable exist in policy fiile.
        $LogBugsForUnmappedResourceVarExistInPolicy = $this.ControlSettings.BugLogging.PSobject.Properties | where-object {$_.Name -eq "LogBugsForUnmappedResource"} 
        #If LogBugForUnmappedResource exist in the policy file then get it's value.
        if ($LogBugsForUnmappedResourceVarExistInPolicy) {
            $this.LogBugsForUnmappedResource = $LogBugsForUnmappedResourceVarExistInPolicy.Value;
        }
    }
    
    #Return AutoBugLog instance
    hidden static [AutoBugLog] GetInstance([string] $orgName, [InvocationInfo] $invocationContext, [ControlStateExtension] $ControlStateExt, [string] $bugLogParameterValue) {
        [AutoBugLog]::AutoBugInstance = [AutoBugLog]::new($orgName, $invocationContext, $ControlStateExt, $bugLogParameterValue)
        return [AutoBugLog]::AutoBugInstance
    }

    static [string] ComputeHashX([string] $dataToHash) {
        return [Helpers]::ComputeHashShort($dataToHash, [Constants]::AutoBugLogTagLen)
    }

    #main function where bug logging takes place 
    hidden [void] LogBugInADO([SVTEventContext[]] $ControlResults) {
        #check if user has permissions to log bug for the current resource
        if ($this.CheckPermsForBugLog($ControlResults[0])) {
            #retrieve the project name for the current resource
            $ProjectName = $this.GetProjectForBugLog($ControlResults[0])

            #check if the area and iteration path are valid 
            if ([BugLogPathManager]::CheckIfPathIsValid($this.OrganizationName, $ProjectName, $this.InvocationContext, $this.ControlSettings.BugLogging.BugLogAreaPath, $this.ControlSettings.BugLogging.BugLogIterationPath, $this.IsBugLogCustomFlow)) {
                #Obtain the assignee for the current resource, will be same for all the control failures for this particular resource
                $metaProviderObj = [BugMetaInfoProvider]::new();   
                $AssignedTo = $metaProviderObj.GetAssignee($ControlResults[0], $this.ControlSettings.BugLogging, $this.IsBugLogCustomFlow, $this.ServiceIdPassedInCMD);
                $serviceId = $metaProviderObj.ServiceId
                #Log bug only if LogBugForUnmappedResource is enabled (default value is true) or resource is mapped to serviceid
                #Restrict bug logging, if resource is not mapped to serviceid and LogBugForUnmappedResource is not enabled.
                if($this.LogBugsForUnmappedResource -or $serviceId)
                {
                    #Set ShowBugsInS360 if customebuglog is enabled and sericeid not null and ShowBugsInS360 enabled in policy
                    if ($this.IsBugLogCustomFlow -and (-not [string]::IsNullOrEmpty($serviceId)) -and ([Helpers]::CheckMember($this.ControlSettings.BugLogging, "ShowBugsInS360") -and $this.ControlSettings.BugLogging.ShowBugsInS360) ) {
                        $this.ShowBugsInS360 = $true;
                    }
                    else {
                        $this.ShowBugsInS360 = $false;
                    }
    
                    #this falg is added to restrict 'Determining bug logging' message should print only once 
                    $printLogBugMsg = $true;
                    #Loop through all the control results for the current resource
                    $ControlResults | ForEach-Object {
                        $control = $_;                                     
                        #filter controls on basis of whether they are baseline or not depending on the value given in autobuglog flag
                        $LogControlFlag = $false
                        if ($this.BugLogParameterValue -eq [BugLogForControls]::All) {
                                $LogControlFlag = $true
                        }
                        elseif ($this.BugLogParameterValue -eq [BugLogForControls]::BaselineControls) {
                                $LogControlFlag = $this.CheckBaselineControl($control.ControlItem.ControlID)				
                        }
                        elseif ($this.BugLogParameterValue -eq [BugLogForControls]::PreviewBaselineControls) {
                                $LogControlFlag = $this.CheckPreviewBaselineControl($control.ControlItem.ControlID)
                        }
                        elseif ($this.BugLogParameterValue -eq [BugLogForControls]::Custom) {
                            $LogControlFlag = $this.CheckControlInCustomControlList($control.ControlItem.ControlID)
                        }
		    
                        if ($LogControlFlag -and ($control.ControlResults[0].VerificationResult -eq "Failed" -or $control.ControlResults[0].VerificationResult -eq "Verify") ) 
                        {
                            #compute hash of control Id and resource Id 
                            $hash = $this.GetHashedTag($control.ControlItem.Id, $control.ResourceContext.ResourceId)
                            #check if a bug with the computed hash exists
                            #Removed ProjectName param and direcly added [BugLogPathManager]::BugLoggingProject, previously holding in variable and passing in method
                            $workItem = $this.GetWorkItemByHash($hash, [BugLogPathManager]::BugLoggingProject)
                            if ($workItem[0].results.count -gt 0) {
                                #a work item with the hash exists, find if it's state and reactivate if resolved bug
                                $this.ManageActiveAndResolvedBugs($ProjectName, $control, $workItem, $AssignedTo, $serviceId)
                            }
                            else {
                                if ($printLogBugMsg) {
                                    Write-Host "Determining bugs to log..." -ForegroundColor Cyan
                                }
                                $printLogBugMsg = $false;

                                #filling the bug template
                                $Title = "[ADOScanner] Control failure - {0} for resource {1} {2}"
                                $Description = "Control failure - {3} for resource {4} {5} </br></br> <b>Control Description: </b> {0} </br></br> <b> Control Result: </b> {6} </br> </br> <b> Rationale:</b> {1} </br></br> <b> Recommendation:</b> {2}"
                            
                                $Title = $Title -f $control.ControlItem.ControlID, $control.ResourceContext.ResourceTypeName, $control.ResourceContext.ResourceName
                                if ($control.ResourceContext.ResourceTypeName -ne "Organization" -and $control.ResourceContext.ResourceTypeName -ne "Project") {
                                    $Title += " in project " + $control.ResourceContext.ResourceGroupName;
                                }
                                $Description = $Description -f $control.ControlItem.Description, $control.ControlItem.Rationale, $control.ControlItem.Recommendation, $control.ControlItem.ControlID, $control.ResourceContext.ResourceTypeName, $control.ResourceContext.ResourceName, $control.ControlResults[0].VerificationResult
                                $Description += "</br></br> <b> Resource Link: </b> <a href='$($control.ResourceContext.ResourceDetails.ResourceLink)' target='_blank'>$($control.ResourceContext.ResourceName)</a>"
                                $RunStepsForControl = " </br></br> <b>Control Scan Command:</b> Run:  {0}"
                                $Description += ($RunStepsForControl -f $this.GetControlReproStep($control));

                                $ADOScannerDocLink = "https://microsoftit.visualstudio.com/OneITVSO/_wiki/wikis/OneITVSO.wiki/15868/ADO-Security-Scanner-for-CSEO?anchor=installing-and-scanning-locally";                       
                                if ($this.IsBugLogCustomFlow) {
                                    $Description += "</br></br>For more info, please visit <a href='$ADOScannerDocLink' target='_blank'>here</a>. </br>"
                                }
				            
                                #check and append any detailed log and state data for the control failure
                                $log = $this.GetDetailedLogForControl($control);
                                if ($log) {
                                    $Description += "<hr></br><b>Some other details for your reference</b> </br><hr> {7} "
                                    $Description = $Description.Replace("{7}", $log)
                                }               
                                $Description = $Description.Replace("`"", "'")
                                $Severity = $this.GetSeverity($control.ControlItem.ControlSeverity)		
                    
                                #function to attempt bug logging
                                $this.AddWorkItem($Title, $Description, $AssignedTo, $Severity, $ProjectName, $control, $hash, $serviceId);

                            }
                        }    
                    }
                }
                else {
                    Write-Host "Bug logging is disabled for resources that are not mapped to any service." -ForegroundColor Yellow
                }    
            }
        }

    }

    #function to get the security command for repro of this bug 
    hidden [string] GetControlReproStep([SVTEventContext []] $ControlResult) {
        $StepsForRepro = ""
        if ($ControlResult.FeatureName -eq "Organization") {
            $StepsForRepro = "Get-AzSKADOSecurityStatus -OrganizationName '{0}' -ControlIds '{1}'"
            $StepsForRepro = $StepsForRepro -f $ControlResult.ResourceContext.ResourceName, $ControlResult.ControlItem.ControlID;
        }
        elseif ($ControlResult.ResourceContext.ResourceTypeName -eq "Project") {
            $StepsForRepro = "Get-AzSKADOSecurityStatus -OrganizationName '{0}' -ProjectNames '{1}' -ControlIds '{2}'"
            $StepsForRepro = $StepsForRepro -f $ControlResult.ResourceContext.ResourceGroupName, $ControlResult.ResourceContext.ResourceName, $ControlResult.ControlItem.ControlID;
        }
        else {
            $StepsForRepro = "Get-AzSKADOSecurityStatus -OrganizationName '{0}' -ProjectNames '{1}' -{2}Names '{3}' -ControlIds '{4}'"
            $StepsForRepro = $StepsForRepro -f $this.OrganizationName, $ControlResult.ResourceContext.ResourceGroupName, $ControlResult.FeatureName, $ControlResult.ResourceContext.ResourceName, $ControlResult.ControlItem.ControlID;
        }
        return $StepsForRepro
    }
    
    #function to retrieve project name according to the resource
    hidden [string] GetProjectForBugLog([SVTEventContext[]] $ControlResult) {
        $ProjectName = ""
        #if resource is the organization, call control state extension to retreive attestation host project
        if ($ControlResult.FeatureName -eq "Organization") {
            $ProjectName = $this.ControlStateExt.GetProject()
        }
        #for all the other resource types, retrieve the project name from the control itself
        elseif ($ControlResult.ResourceContext.ResourceTypeName -eq "Project") {
            $ProjectName = $ControlResult.ResourceContext.ResourceName
        }
        else {
            $ProjectName = $ControlResult.ResourceContext.ResourceGroupName
        }
        return $ProjectName
    }
    
    #function to check if the bug can be logged for the current resource type
    hidden [bool] CheckPermsForBugLog([SVTEventContext[]] $ControlResult) 
    {
        if($ControlResult.FeatureName -eq 'Build' -or $ControlResult.FeatureName -eq 'Release' -or $ControlResult.FeatureName -eq 'ServiceConnection' -or $ControlResult.FeatureName -eq 'AgentPool' -or $ControlResult.FeatureName -eq 'VariableGroup') {
             return $true;
        }
        elseif($ControlResult.FeatureName -eq 'Organization') {
                #check if any host project can be retrieved, if not use getHostProject to return the correct behaviour output
                if (!($this.GetHostProject($ControlResult))) {
                    return $false
                }				
            }
        elseif($ControlResult.FeatureName -eq 'Project') {
                #check if user is member of PA/PCA
                if (!$this.ControlStateExt.GetControlStatePermission($ControlResult.FeatureName, $ControlResult.ResourceContext.ResourceName)) {
                    Write-Host "`nAuto bug logging denied due to insufficient permissions. Make sure you are a project administrator. " -ForegroundColor Red
                    return $false
                }
            }
        elseif($ControlResult.FeatureName -eq 'User') {
                #TODO: User controls dont have a project associated with them, can be rectified in future versions
                Write-Host "`nAuto bug logging for user control failures is currently not supported." -ForegroundColor Yellow
                return $false
            }
        return $true
    }
    
    #function to retrive the attestation host project for organization level control failures
    hidden [string] GetHostProject([SVTEventContext[]] $ControlResult) {
        $Project = $null
        
        #check if attestationhost project has been specified along with the command
        if ($this.InvocationContext.BoundParameters["AttestationHostProjectName"]) {
            #check if the user has permission to log bug at org level
            if ($this.ControlStateExt.GetControlStatePermission("Organization", "")) { 
                #user is PCA member, set the host project and return the project name
                $this.ControlStateExt.SetProjectInExtForOrg()	
                $Project = $this.ControlStateExt.GetProject()
                return $Project
            }
            #user is not a member of PCA, invalidate the bug log
            else {
                Write-Host "Error: Could not configure host project to log bugs for organization-specific control failures.`nThis may be because you may not have correct privilege (requires 'Project Collection Administrator')." -ForegroundColor Red
                return $null
            }
        }
        
        else {
            #check if the user is a member of PCA after validating that the host project name was not provided 
            if (!$this.ControlStateExt.GetControlStatePermission("Organization", "") ) {
                Write-Host "Error: Auto bug logging denied.`nThis may be because you are attempting to log bugs for areas you do not have RBAC permission to." -ForegroundColor Red
                return $null
					  
            }
            else {
                $Project = $this.ControlStateExt.GetProject()
                #user is a PCA member but the project has not been set for org control failures
                if (!$Project) { 
                    Write-Host "`nNo project defined to log bugs for organization-specific controls." -ForegroundColor Red
                    Write-Host "Use the '-AttestationHostProjectName' parameter with this command to configure the project that will host bug logging details for organization level controls.`nRun 'Get-Help -Name Get-AzSKADOSecurityStatus -Full' for more info." -ForegroundColor Yellow
                    return $null
                }
            }
        }
        return $Project

    }

    #function to check any detailed log and state data for the control failure
    hidden [string] GetDetailedLogForControl([SVTEventContext[]] $ControlResult) {
        $log = ""
        #retrieve the message data for control result
        $Messages = $ControlResult.ControlResults[0].Messages

        $Messages | ForEach-Object {
            if ($_.Message) {
                $log += "<b>$($_.Message)</b> </br></br>"
            }
            #check for state data
            if ($_.DataObject) {
                $log += "<hr>"

                #beautify state data for bug template
                $stateData = [Helpers]::ConvertObjectToString($_, $false)
                $stateData = $stateData.Replace("`"", "'")
                $stateData = $stateData.Replace("@{", "@{</br>")
                $stateData = $stateData.Replace("@(", "@(</br>")
                $stateData = $stateData.Replace(";", ";</br>")
                $stateData = $stateData.Replace("},", "</br>},</br>")
                $stateData = $stateData.Replace(");", "</br>});</br>")
					
                $log += "$($stateData) </br></br>"	
            }
        }
        
        #sanitizing input for JSON
        $log = $log.Replace("\", "\\")	

        return $log
    }
    
    #function to retrieve the person to whom the bug will be assigned
    hidden [string] GetAssignee([SVTEventContext[]] $ControlResult) {
        $metaProviderObj = [BugMetaInfoProvider]::new();        
        return $metaProviderObj.GetAssignee($ControlResult, $this.ControlSettings.BugLogging);   
    }

    #function to map severity of the control item
    hidden [string] GetSeverity([string] $ControlSeverity) {
        $Severity = ""
        switch -regex ($ControlSeverity) {
            'Critical' {
                $Severity = "1 - Critical"
            }
            'High' {
                $Severity = "2 - High"
            }
            'Important' {
                $Severity = "2 - High"
            }
            'Medium' {
                $Severity = "3 - Medium"
            }
            'Moderate' {
                $Severity = "3 - Medium"
            }
            'Low' {
                $Severity = "4 - Low"
            }

        }

        return $Severity
    }

    hidden [string] GetSecuritySeverity([string] $ControlSeverity) {
        $Severity = ""
        switch -regex ($ControlSeverity) {
            'Critical' {
                $Severity = "1 - Critical"
            }
            'High' {
                $Severity = "2 - Important"
            }
            'Important' {
                $Severity = "2 - Important"
            }
            'Moderate' {
                $Severity = "3 - Moderate"
            }
            'Medium' {
                $Severity = "3 - Moderate"
            }
            'Low' {
                $Severity = "4 - Low"
            }

        }

        return $Severity
    }
    
    #function to find active bugs and reactivate resolved bugs
    hidden [void] ManageActiveAndResolvedBugs([string]$ProjectName, [SVTEventContext[]] $control, [object] $workItem, [string] $AssignedTo, [string] $serviceId) {
        
        #If using azure storage then calling documented api as we have ado id, so response will be different, so added if else condition
        $state = "";
        $id = "";
        #serviceid return in the bug api response to match with current scanned resource service id.
        $serviceIdInLoggedBug = ""; 
        if ($this.UseAzureStorageAccount -and $this.ScanSource -eq "CA") 
        {
            $state = $workItem[0].results.fields."System.State"
            $id = $workItem[0].results.id
            #Check ShowBugsInS360 and Security.ServiceHierarchyId property exist in object.
            if ($this.ShowBugsInS360 -and ($workItem[0].results.fields.PSobject.Properties.name -match "Security.ServiceHierarchyId")) 
            {
                $serviceIdInLoggedBug = $workItem[0].results.fields."Security.ServiceHierarchyId"
            }
        }
        else {
            $state = ($workItem[0].results.values[0].fields | where { $_.name -eq "State" }).value
            $id = ($workItem[0].results.values[0].fields | where { $_.name -eq "ID" }).value
            #Check ShowBugsInS360 and Security.ServiceHierarchyId property exist in object.
            if ($this.ShowBugsInS360 -and ($workItem[0].results.values[0].fields.PSobject.Properties.name -match "Security.ServiceHierarchyId")) 
            {
                $serviceIdInLoggedBug = ($workItem[0].results.values[0].fields | where { $_.name -eq "Security.ServiceHierarchyId" }).value
            }
        }
        
        #bug url that redirects user to bug logged in ADO, this is not available via the API response and thus has to be created via the ID of bug
        $bugUrl = "https://{0}.visualstudio.com/{1}/_workitems/edit/{2}" -f $this.OrganizationName, $ProjectName , $id

        #TODO : whether the bug is active or resolved, we have to ensure the state of the bug remains active after this function  
        #if a PCA assigns this to a non PCA, the control can never be fixed for org/project controls. to tackle this, reassign it to the original owner PCA
        #do this for both active and resolved bugs, as we need it to be assigned to the actual person who can fix this control
        #for other control results, we need not changed the assignee
        <#    $url = "https://dev.azure.com/{0}/{1}/_apis/wit/workitems/{2}?api-version=5.1" -f $($this.OrganizationName), $ProjectName, $id
            $BugTemplate = [ConfigurationManager]::LoadServerConfigFile("TemplateForResolvedBug.json")
            $BugTemplate = $BugTemplate | ConvertTo-Json -Depth 10 
            $BugTemplate=$BugTemplate.Replace("{0}",$AssignedTo)           
            $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($url)                
            try {
                #TODO: shift all this as a patch request in webrequesthelper class and manage accented characters as well
                $responseObj = Invoke-RestMethod -Uri $url -Method Patch  -ContentType "application/json-patch+json ; charset=utf-8" -Headers $header -Body $BugTemplate
            }
            catch {
                #if the user to whom the bug has been assigneed is not a member of org any more
                if ($_.ErrorDetails.Message -like '*System.AssignedTo*') {
                    $body = $BugTemplate | ConvertFrom-Json
                    #let it remain assigned
                    $body[2].value = "";
                    $body = $body | ConvertTo-Json
                    try {
                        $responseObj = Invoke-RestMethod -Uri $url -Method Patch -ContentType "application/json-patch+json ; charset=utf-8" -Headers $header -Body $body
                        $bugUrl = "https://{0}.visualstudio.com/_workitems/edit/{1}" -f $($this.OrganizationName), $responseObj.id
                    }
                    catch {
                        Write-Host "Could not reactivate the bug" -ForegroundColor Red
                    }
                }
                else {
                    Write-Host "Could not reactivate the bug" -ForegroundColor Red
                }
            }
        #if the bug state was intially resolved, add in the state data to be referenced later
        if ($state.value -eq "Resolved") {
            $control.ControlResults.AddMessage("Resolved Bug", $bugUrl)
        }
        #if the bug state was initially active
        else {
            $control.ControlResults.AddMessage("Active Bug", $bugUrl)
        }#>


        #change the assignee for resolved bugs only
        $url = "https://dev.azure.com/{0}/{1}/_apis/wit/workitems/{2}?api-version=5.1" -f $this.OrganizationName, $ProjectName, $id
        if ($state -eq "Resolved") {
            $BugTemplate = $null;
            #Check if serviceid is not null and current resource scanned serviceid and bug respons serviceid is not equal, then update the service data.
            if ($this.ShowBugsInS360 -and $serviceId -and ($serviceIdInLoggedBug -ne $serviceId)) 
            {
                $BugTemplate = $this.UpdateSTBugTemplate($serviceId, $control.ControlItem.ControlSeverity, $true, $AssignedTo)        
            }
            else 
            {
                $BugTemplate = [ConfigurationManager]::LoadServerConfigFile("TemplateForResolvedBug.json")
                $BugTemplate = $BugTemplate | ConvertTo-Json -Depth 10 
                $BugTemplate = $BugTemplate.Replace("{0}", $AssignedTo)           
            }
            $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($url)                
            try {
                #TODO: shift all this as a patch request in webrequesthelper class and manage accented characters as well
                $responseObj = Invoke-RestMethod -Uri $url -Method Patch  -ContentType "application/json-patch+json ; charset=utf-8" -Headers $header -Body $BugTemplate
                $control.ControlResults.AddMessage("Resolved Bug", $bugUrl)
            }
            catch {
                $areaPath = [BugLogPathManager]::AreaPath
                #if the user to whom the bug has been assigneed is not a member of org any more
                if ($_.ErrorDetails.Message -like '*System.AssignedTo*') {
                    $body = $BugTemplate | ConvertFrom-Json
                    #let it remain assigned
                    $body[2].value = "";
                    $body = $body | ConvertTo-Json
                    try {
                        $responseObj = Invoke-RestMethod -Uri $url -Method Patch -ContentType "application/json-patch+json ; charset=utf-8" -Headers $header -Body $body
                        $control.ControlResults.AddMessage("Resolved Bug", $bugUrl)
                    }
                    catch {
                        Write-Host "Could not reactivate the bug" -ForegroundColor Red
                    }
                }
                elseif ($_.ErrorDetails.Message -like '*Invalid Area*') {
                    Write-Host "Could not reactivate the bug. Please verify the area path [$areaPath]. Area path should belong under the same project area." -ForegroundColor Red
                }
                elseif ($_.ErrorDetails.Message -like '*Invalid tree name given for work item*' -and $_.ErrorDetails.Message -like '*System.AreaPath*') {
                    Write-Host "Could not reactivate the bug. Please verify the area path [$areaPath]. Area path should belong under the same project area." -ForegroundColor Red
                }
                elseif ($_.ErrorDetails.Message -like '*The current user does not have permissions to save work items under the specified area path*') {
                    Write-Host "Could not reactivate the bug. You do not have permissions to save work items under the area path [$areaPath]." -ForegroundColor Red
                }
                else {
                    Write-Host "Could not reactivate the bug." -ForegroundColor Red
                }
            }
        }
        else {
            $control.ControlResults.AddMessage("Active Bug", $bugUrl);
            #Update the serviceid details, if serviceid not null and not matched with bug response serviceid.
            if ($this.ShowBugsInS360 -and $serviceId -and ($serviceIdInLoggedBug -ne $serviceId)) 
            {
                $BugTemplate = $null;
                $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($url)                
                try 
                {
                    $BugTemplate = $this.UpdateSTBugTemplate($serviceId, $control.ControlItem.ControlSeverity, $false, $AssignedTo); 
                    $responseObj = Invoke-RestMethod -Uri $url -Method Patch  -ContentType "application/json-patch+json ; charset=utf-8" -Headers $header -Body $BugTemplate
                }
                catch 
                {
                    $areaPath = [BugLogPathManager]::AreaPath
                    if ($_.ErrorDetails.Message -like '*Invalid Area*') {
                        Write-Host "Could not update service tree details in the bug. Please verify the area path [$areaPath]. Area path should belong under the same project area." -ForegroundColor Red
                    }
                    elseif ($_.ErrorDetails.Message -like '*Invalid tree name given for work item*' -and $_.ErrorDetails.Message -like '*System.AreaPath*') {
                        Write-Host "Could not update service tree details in the bug. Please verify the area path [$areaPath]. Area path should belong under the same project area." -ForegroundColor Red
                    }
                    elseif ($_.ErrorDetails.Message -like '*The current user does not have permissions to save work items under the specified area path*') {
                        Write-Host "Could not update service tree details in the bug. You do not have permissions to save work items under the area path [$areaPath]." -ForegroundColor Red
                    }
                    else {
                        Write-Host "Could not update service tree details in the bug."
                    }
                }
            }
        }
    }

    #status has value if it is called from resolved to activate bug, else the value is empty, if status not needed to change
    hidden [object] UpdateSTBugTemplate($serviceId, $controlSeverity, $reactivateBug, $assignedTo)
    {
        $BugTemplate = [ConfigurationManager]::LoadServerConfigFile("TemplateForUpdateBugS360.json");
        #Activate resolved bug, else update serviceid details only.
        if ($reactivateBug) {
            $BugTemplate = $BugTemplate | ConvertTo-Json -Depth 10 
            $BugTemplate = $BugTemplate.Replace("{0}", "Active")           
        }
        else {
            $BugTemplate = $BugTemplate | Where {$_.path -ne "/fields/System.State" }
            $BugTemplate = $BugTemplate | ConvertTo-Json -Depth 10
        }
        $BugTemplate = $BugTemplate.Replace("{1}", $AssignedTo)           

        #$secSeverity used to get calculated value of security severity (if supplied in command parameter then get it from command, else get from control severity)
        $secSeverity = "";
        if ($this.InvocationContext.BoundParameters["SecuritySeverity"]) {
            $secSeverity = $this.InvocationContext.BoundParameters["SecuritySeverity"];
        }
        else {
            $secSeverity = $controlSeverity;
        }
        $SecuritySeverity = $this.GetSecuritySeverity($secSeverity)		
        $BugTemplate = $BugTemplate.Replace("{2}", $this.controlsettings.BugLogging.HowFound)
        #ComplianceArea
        $BugTemplate = $BugTemplate.Replace("{3}", $this.controlsettings.BugLogging.ComplianceArea)
        #ServiceHierarchyId
        $BugTemplate = $BugTemplate.Replace("{4}", $serviceId)
        #ServiceHierarchyIdType
        $BugTemplate = $BugTemplate.Replace("{5}", $this.controlsettings.BugLogging.ServiceTreeIdType)
        #Severity
        $BugTemplate = $BugTemplate.Replace("{6}", $SecuritySeverity)

        $BugTemplate = $BugTemplate.Replace("{7}", [BugLogPathManager]::AreaPath)
        return $BugTemplate;
    }

    #function to search for existing bugs based on the hash
    hidden [object] GetWorkItemByHash([string] $hash, [string] $ProjectName) 
    {
        if ($this.UseAzureStorageAccount -and $this.ScanSource -eq "CA") 
        {
            return $this.BugLogHelperObj.GetWorkItemByHashAzureTable($hash, $ProjectName, $this.ControlSettings.BugLogging.ResolvedBugLogBehaviour);
        }
        else 
        {
            $url = "https://{0}.almsearch.visualstudio.com/{1}/_apis/search/workItemQueryResults?api-version=5.1-preview" -f $this.OrganizationName, $ProjectName

            #TODO: validate set to allow only two values : ReactiveOldBug and CreateNewBug
            #check for ResolvedBugBehaviour in control settings
            #takeResults is used to fetch number of workitems to be return. At caller side of this method we are checking if return greter then 0, then manage work item else add new.
            if ($this.ControlSettings.BugLogging.ResolvedBugLogBehaviour -ne "ReactiveOldBug") {
                #new bug is to be logged for every resolved bug, hence search for only new/active bug
                $body = '{"searchText":"{0}","skipResults":0,"takeResults":2,"sortOptions":[],"summarizedHitCountsNeeded":true,"searchFilters":{"Projects":["{1}"],"Work Item Types":["Bug"],"States":["Active","New"]},"filters":[],"includeSuggestions":false}' | ConvertFrom-Json
            }
            else {
                #resolved bug needs to be reactivated, hence search for new/active/resolved bugs
                $body = '{"searchText":"{0}","skipResults":0,"takeResults":2,"sortOptions":[],"summarizedHitCountsNeeded":true,"searchFilters":{"Projects":["{1}"],"Work Item Types":["Bug"],"States":["Active","New","Resolved"]},"filters":[],"includeSuggestions":false}' | ConvertFrom-Json
            }
    
            #tag to be searched
            $body.searchText = "Tags: " + $hash
            $body.searchFilters.Projects = $ProjectName
    
            $response = [WebRequestHelper]::InvokePostWebRequest($url, $body)
        
            return  $response
        }
    }

    #function to compute hash and return the tag
    hidden [string] GetHashedTag([string] $ControlId, [string] $ResourceId) {
        $hashedTag = $null
        $stringToHash = "$ResourceId#$ControlId";
        #return the bug tag
        if ($this.UseAzureStorageAccount -and $this.ScanSource -eq "CA") 
        {
            return [AutoBugLog]::ComputeHashX($stringToHash);
        }
        else 
        {
            return "ADOScanID: " + [AutoBugLog]::ComputeHashX($stringToHash)
        }
    }

    #Logging new bugs
    hidden [void] AddWorkItem([string] $Title, [string] $Description, [string] $AssignedTo, [string]$Severity, [string]$ProjectName, [SVTEventContext[]] $control, [string] $hash, [string] $serviceId) 
    {	
        $apiurl = 'https://dev.azure.com/{0}/{1}/_apis/wit/workitems/$bug?api-version=5.1' -f $this.OrganizationName, $ProjectName;

        $BugTemplate = $null;
        $SecuritySeverity = "";

        if ($this.ShowBugsInS360) {
            $BugTemplate = [ConfigurationManager]::LoadServerConfigFile("TemplateForNewBugS360.json")
            #Check if security severity passed in the command parameter, if passed take command parameter else take control severity.
            $secSeverity = "";
            if ($this.InvocationContext.BoundParameters["SecuritySeverity"]) {
                $secSeverity = $this.InvocationContext.BoundParameters["SecuritySeverity"];
            }
            else {
                $secSeverity = $control.ControlItem.ControlSeverity;
            }
            $SecuritySeverity = $this.GetSecuritySeverity($secSeverity)		
        }
        else {
            $BugTemplate = [ConfigurationManager]::LoadServerConfigFile("TemplateForNewBug.json");
        }

        # Replace the field reference name for bug description if it is customized
        if ($this.BugDescriptionField) {
            $BugTemplate[1].path = $this.BugDescriptionField;
        }

        $BugTemplate = $BugTemplate | ConvertTo-Json -Depth 10 
        #$BugTemplate = $BugTemplate -f $Title, $Description, $Severity, $AreaPath, $IterationPath, $hash, $AssignedTo
        $BugTemplate = $BugTemplate.Replace("{0}", $Title)
        $BugTemplate = $BugTemplate.Replace("{1}", $Description)
        $BugTemplate = $BugTemplate.Replace("{2}", $Severity)
        $BugTemplate = $BugTemplate.Replace("{3}", [BugLogPathManager]::AreaPath)
        $BugTemplate = $BugTemplate.Replace("{4}", [BugLogPathManager]::IterationPath)
        if ($this.UseAzureStorageAccount -and $this.ScanSource -eq "CA") {
            $BugTemplate = $BugTemplate.Replace("{5}", "ADOScanner")
        }
        else {
            $BugTemplate = $BugTemplate.Replace("{5}", $hash)
        }
        $BugTemplate = $BugTemplate.Replace("{6}", $AssignedTo)

        if ($this.ShowBugsInS360) {
            $BugTemplate = $BugTemplate.Replace("{7}", $this.controlsettings.BugLogging.HowFound)
            #ComplianceArea
            $BugTemplate = $BugTemplate.Replace("{8}", $this.controlsettings.BugLogging.ComplianceArea)
            #ServiceHierarchyId
            $BugTemplate = $BugTemplate.Replace("{9}", $serviceId)
            #ServiceHierarchyIdType
            $BugTemplate = $BugTemplate.Replace("{10}", $this.controlsettings.BugLogging.ServiceTreeIdType)
            #Severity
            $BugTemplate = $BugTemplate.Replace("{11}", $SecuritySeverity)
        }

        $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($apiurl)
        try {
            $responseObj = Invoke-RestMethod -Uri $apiurl -Method Post -ContentType "application/json-patch+json ; charset=utf-8" -Headers $header -Body $BugTemplate
            $bugUrl = "https://{0}.visualstudio.com/_workitems/edit/{1}" -f $this.OrganizationName, $responseObj.id
            $control.ControlResults.AddMessage("New Bug", $bugUrl);
            if ($this.UseAzureStorageAccount -and $this.ScanSource -eq "CA") {
                $this.BugLogHelperObj.InsertBugInfoInTable($hash, $ProjectName, $responseObj.id); 
            }
        }
        catch {
            #handle assignee users who are not part of org any more
            if ($_.ErrorDetails.Message -like '*System.AssignedTo*') {
                $BugTemplate = $BugTemplate | ConvertFrom-Json
                $BugTemplate[6].value = "";
                $BugTemplate = $BugTemplate | ConvertTo-Json
                try {
                    $responseObj = Invoke-RestMethod -Uri $apiurl -Method Post -ContentType "application/json-patch+json ; charset=utf-8" -Headers $header -Body $BugTemplate
                    $bugUrl = "https://{0}.visualstudio.com/_workitems/edit/{1}" -f $this.OrganizationName, $responseObj.id
                    $control.ControlResults.AddMessage("New Bug", $bugUrl)
                    if ($this.UseAzureStorageAccount -and $this.ScanSource -eq "CA") {
                        $this.BugLogHelperObj.InsertBugInfoInTable($hash, $ProjectName, $responseObj.id); 
                    }
                }
                catch {
                    Write-Host "Could not log the bug" -ForegroundColor Red
                }
            }
            #handle the case wherein due to global search area/ iteration paths from different projects passed the checkvalidpath function
            elseif ($_.ErrorDetails.Message -like '*Invalid Area/Iteration id*') {
                Write-Host "Please verify the area and iteration path. They should belong under the same project area." -ForegroundColor Red
            }
            elseif ($_.ErrorDetails.Message -like '*Invalid tree name given for work item*' -and $_.ErrorDetails.Message -like '*System.AreaPath*') {
                Write-Host "Please verify the area and iteration path are valid." -ForegroundColor Red
            }
            elseif ($_.ErrorDetails.Message -like '*The current user does not have permissions to save work items under the specified area path*') {
                $areaPath = [BugLogPathManager]::AreaPath
                Write-Host "Could not log the bug. You do not have permissions to save work items under the area path [$($areaPath)]." -ForegroundColor Red
            }
            else {
                Write-Host "Could not log the bug" -ForegroundColor Red
            }
        }
    }

    #the next two functions to check baseline and preview baseline, are duplicate controls that are present in ADOSVTBase as well.
    #they have been added again, due to behaviour of framework, where the file that needs to called in a certain file has to be mentioned
    #above the other file as it is dumped in the memory before the second file. This behaviour will effectively create a deadlock
    #in this case, as we have to create autobuglog object in adosvtbase, making it be declared first in framework and hence the following controls
    #cant be accessed here from adosvtbase.

    #function to check if the current control is a baseline control or not
    hidden [bool] CheckBaselineControl($controlId) {
        $baselineControl = $this.ControlSettings.BaselineControls.ResourceTypeControlIdMappingList | Where-Object { $_.ControlIds -contains $controlId }
        if (($baselineControl | Measure-Object).Count -gt 0 ) {
            return $true
        }
        return $false
    }
    
    #function to check if the current control is a preview baseline control or not

    hidden [bool] CheckPreviewBaselineControl($controlId) {
        if (($null -ne $this.ControlSettings) -and [Helpers]::CheckMember($this.ControlSettings, "PreviewBaselineControls.ResourceTypeControlIdMappingList")) {
            $PreviewBaselineControls = $this.ControlSettings.PreviewBaselineControls.ResourceTypeControlIdMappingList | Where-Object { $_.ControlIds -contains $controlId }
            if (($PreviewBaselineControls | Measure-Object).Count -gt 0 ) {
                return $true
            }
        }
        return $false
    }

    hidden [bool] CheckControlInCustomControlList($controlId) {
        if ([Helpers]::CheckMember($this.ControlSettings.BugLogging, "CustomControlList")) {
            $customControlList = $this.ControlSettings.BugLogging | Where-Object { $_.CustomControlList -contains $controlId }
            if (($customControlList | Measure-Object).Count -gt 0 ) {
                return $true
            }
        }
        
        return $false
    }
    
}

