Set-StrictMode -Version Latest
class AutoCloseBugManager {
    hidden [string] $OrganizationName;
    hidden [PSObject] $ControlSettings;
    hidden [string] $ScanSource;
    hidden [bool] $UseAzureStorageAccount = $false;
    hidden [BugLogCheckerHelper] $BugLogCheckerObj;

    AutoCloseBugManager([string] $orgName) {
        $this.OrganizationName = $orgName;
        $this.ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
        $This.ScanSource = [AzSKSettings]::GetInstance().GetScanSource();
        #TODO:
        #$this.ScanSource = "CA"
        if ([Helpers]::CheckMember($this.ControlSettings.BugLogging, "UseAzureStorageAccount", $null)) {
            $this.UseAzureStorageAccount = $this.ControlSettings.BugLogging.UseAzureStorageAccount;
            if ($this.UseAzureStorageAccount) {
                $this.BugLogCheckerObj = [BugLogCheckerHelper]::BugLogCheckerInstance
		        if (!$this.BugLogCheckerObj) {
		        	#Settting initial value true so will evaluate in all different cmds.(Powershell keeping static variables in memory in next command also.)
		        	$this.BugLogCheckerObj = [BugLogCheckerHelper]::GetInstance($this.OrganizationName);
		        }
            }
        }
    }


    #function to auto close resolved bugs
    hidden [void] AutoCloseBug([SVTEventContext []] $ControlResults) {

        #tags that need to be searched
        $TagSearchKeyword = ""
        #flag to check number of current keywords in the tag
        $QueryKeyWordCount = 0;
        #maximum no of keywords that need to be checked per batch
        $MaxKeyWordsToQuery=0;    
        #all passing control results go here
        $PassedControlResults = @();
        $autoCloseOrgBugFlag=$true
        $autoCloseProjBugFlag=$true;

        

        try {
            $MaxKeyWordsToQuery = $this.ControlSettings.BugLogging.MaxKeyWordsToQueryForBugClose;
            $autoCloseOrgBugFlag=$this.ControlSettings.BugLogging.AutoCloseOrgBug
            $autoCloseProjBugFlag=$this.ControlSettings.BugLogging.AutoCloseProjectBug
        }
        catch {
            $MaxKeyWordsToQuery=30
            $autoCloseOrgBugFlag=$true
            $autoCloseProjBugFlag=$true;
        }

        #collect all passed control results
        $ControlResults | ForEach-Object {
            if ($_.ControlResults[0].VerificationResult -eq "Passed") {
                #to check if org level bugs should be auto closed based on control settings
                if($_.FeatureName -eq "Organization"){
                    if($autoCloseOrgBugFlag -eq $true){
                        $PassedControlResults += $_
                    }
                }
                #to check if proj level bugs should be auto closed based on control settings
                elseif($_.FeatureName -eq "Project"){
                    if($autoCloseProjBugFlag -eq $true){
                        $PassedControlResults += $_
                    }
                }
                else {
                    $PassedControlResults += $_
                }
            }
        }

        #number of passed controls
        $PassedControlResultsLength = ($PassedControlResults | Measure-Object).Count
        #the following loop will call api for bug closing in batches of size as defined in control settings,
        #first check if passed controls length is less than the batch size, if yes then we have to combine all tags in one go
        #and call the api
        #if length is more divide the control results in chunks of batch size, after a particular batch is made call the api
        #reinitialize the variables for the next batch

        $PassedControlResults | ForEach-Object {
            			
            $control = $_;

            #if control results are less than the maximum no of tags per batch
            if ($PassedControlResultsLength -lt $MaxKeyWordsToQuery) {
                #check for number of tags in current query
                $QueryKeyWordCount++;

                if ($this.UseAzureStorageAccount -and $this.ScanSource -eq "CA")
                {
                    #complete the query
                    $TagSearchKeyword += "(ADOScannerHashId eq '" + $this.GetHashedTag($control.ControlItem.Id, $control.ResourceContext.ResourceId) + "') or "
                    #if the query count equals the passing control results, search for bugs for this batch
                    if ($QueryKeyWordCount -eq $PassedControlResultsLength) {
                        #to remove OR from the last tag keyword. Ex: Tags: Tag1 OR Tags: Tag2 OR. Remove the last OR from this keyword
                        $TagSearchKeyword = $TagSearchKeyword.Substring(0, $TagSearchKeyword.length - 3)
                        $response = $this.BugLogCheckerObj.GetTableEntityAndCloseBug($TagSearchKeyword)
                    }
                }
                else {
                    #complete the query
                    $TagSearchKeyword += "Tags: " + $this.GetHashedTag($control.ControlItem.Id, $control.ResourceContext.ResourceId) + " OR "
                    #if the query count equals the passing control results, search for bugs for this batch
                    if ($QueryKeyWordCount -eq $PassedControlResultsLength) {
                        #to remove OR from the last tag keyword. Ex: Tags: Tag1 OR Tags: Tag2 OR. Remove the last OR from this keyword
                        $TagSearchKeyword = $TagSearchKeyword.Substring(0, $TagSearchKeyword.length - 3)
                        $response = $this.GetWorkItemByHash($TagSearchKeyword,$MaxKeyWordsToQuery)
                        #if bug was present
                        if ($response[0].results.count -gt 0) {
                            $response.results.values | ForEach-Object {
                                #close the bug
                                $id = ($_.fields | where { $_.name -eq "ID" }).value
                                $Project = $_.project
                                $this.CloseBug($id, $Project)
                            }
                        }
                    }
                }
            }
                #if the number of control results was more than batch size
                else {
                    $QueryKeyWordCount++;
                    if ($this.UseAzureStorageAccount -and $this.ScanSource -eq "CA")
                    {
                        $TagSearchKeyword += "(ADOScannerHashId eq '" + $this.GetHashedTag($control.ControlItem.Id, $control.ResourceContext.ResourceId) + "') or "

                        #if number of tags reaches batch limit
                        if ($QueryKeyWordCount -eq $MaxKeyWordsToQuery) {
                            #query for all these tags and their bugs
                            $TagSearchKeyword = $TagSearchKeyword.Substring(0, $TagSearchKeyword.length - 3)
                            $response = $this.BugLogCheckerObj.GetTableEntityAndCloseBug($TagSearchKeyword);
                            #Reinitialize for the next batch
                            $QueryKeyWordCount = 0;
                            $TagSearchKeyword = "";
                            $PassedControlResultsLength -= $MaxKeyWordsToQuery
                        }
                    }
                    else
                    {
                        $TagSearchKeyword += "Tags: " + $this.GetHashedTag($control.ControlItem.Id, $control.ResourceContext.ResourceId) + " OR "
                        #if number of tags reaches batch limit
                        if ($QueryKeyWordCount -eq $MaxKeyWordsToQuery) {
                        #query for all these tags and their bugs
                        $TagSearchKeyword = $TagSearchKeyword.Substring(0, $TagSearchKeyword.length - 3)
                        $response = $this.GetWorkItemByHash($TagSearchKeyword,$MaxKeyWordsToQuery)
                        if ($response[0].results.count -gt 0) {
                            $response.results.values | ForEach-Object {
                                $id = ($_.fields | where { $_.name -eq "ID" }).value
                                $Project = $_.project
                                $this.CloseBug($id, $Project)
                            }
                        }
                        #Reinitialize for the next batch
                        $QueryKeyWordCount = 0;
                        $TagSearchKeyword = "";
                        $PassedControlResultsLength -= $MaxKeyWordsToQuery
                        }
                    }
                }
                
            }

        
        
    
    }

    #function to close an active bug
    hidden [void] CloseBug([string] $id, [string] $Project) {
        $url = "https://dev.azure.com/{0}/{1}/_apis/wit/workitems/{2}?api-version=5.1" -f $this.OrganizationName, $Project, $id
        
        #load the closed bug template
        $BugTemplate = [ConfigurationManager]::LoadServerConfigFile("TemplateForClosedBug.Json")
        $BugTemplate = $BugTemplate | ConvertTo-Json -Depth 10

           
           
        $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($url)
                
        try {
            $responseObj = Invoke-RestMethod -Uri $url -Method Patch  -ContentType "application/json-patch+json ; charset=utf-8" -Headers $header -Body $BugTemplate

        }
        catch {
            Write-Host "Could not close the bug" -Red
        }
    }

    #function to retrieve all new/active/resolved bugs 
    hidden [object] GetWorkItemByHash([string] $hash,[int] $MaxKeyWordsToQuery) 
    {
        $url = "https://{0}.almsearch.visualstudio.com/_apis/search/workItemQueryResults?api-version=5.1-preview" -f $this.OrganizationName
        #take results have been doubled, as their might be chances for a bug to be logged more than once, if the tag id is copied.
        #in this case we want all the instances of this bug to be closed
        $body = "{'searchText':'{0}','skipResults':0,'takeResults':$(($MaxKeyWordsToQuery)*2),'sortOptions':[],'summarizedHitCountsNeeded':true,'searchFilters':{'Projects':[],'Work Item Types':['Bug'],'States':['Active','New','Resolved']},'filters':[],'includeSuggestions':false}" | ConvertFrom-Json
        $body.searchText = $hash
        $response = [WebRequestHelper]:: InvokePostWebRequest($url, $body)
        return  $response
    }

    #function to create hash for bug tag
    hidden [string] GetHashedTag([string] $ControlId, [string] $ResourceId) {
        $hashedTag = $null
        $stringToHash = "$ResourceId#$ControlId";
        #return the bug tag
        if ($this.UseAzureStorageAccount -and $this.ScanSource -eq "CA") 
        {
            return [AutoBugLog]::ComputeHashX($stringToHash);
        }
        else {
            return "ADOScanID: " + [AutoBugLog]::ComputeHashX($stringToHash)
        }
    }



}