Set-StrictMode -Version Latest
class AutoCloseBugManager {
    hidden [string] $OrganizationName;
    hidden [PSObject] $ControlSettings;
    hidden [string] $ScanSource;
    hidden [bool] $UseAzureStorageAccount = $false;
    hidden [BugLogHelper] $BugLogHelperObj;
    static [SVTEventContext []] $ClosedBugs=$null;

    AutoCloseBugManager([string] $orgName) {
        $this.OrganizationName = $orgName;
        $this.ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
        $this.ScanSource = [AzSKSettings]::GetInstance().GetScanSource();
        
        if ([Helpers]::CheckMember($this.ControlSettings.BugLogging, "UseAzureStorageAccount", $null)) {
            $this.UseAzureStorageAccount = $this.ControlSettings.BugLogging.UseAzureStorageAccount;
            if ($this.UseAzureStorageAccount) {
                $this.BugLogHelperObj = [BugLogHelper]::BugLogHelperInstance
		        if (!$this.BugLogHelperObj) {
		        	$this.BugLogHelperObj = [BugLogHelper]::GetInstance($this.OrganizationName);
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
        [AutoCloseBugManager]::ClosedBugs=$null

        

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
        #This Hash map is used to map an ADOScan hashtag value to a control. 
        $hashToControlIDMap=@{}
        #the following loop will call api for bug closing in batches of size as defined in control settings,
        #first check if passed controls length is less than the batch size, if yes then we have to combine all tags in one go
        #and call the api
        #if length is more divide the control results in chunks of batch size, after a particular batch is made call the api
        #reinitialize the variables for the next batch

        $PassedControlResults | ForEach-Object {
            			
            $control = $_;

            #if control results are less than the maximum no of tags per batch
            #ToDo add common method for both if and else condition
            if ($PassedControlResultsLength -lt $MaxKeyWordsToQuery) {
                #check for number of tags in current query
                $QueryKeyWordCount++;

                if ($this.UseAzureStorageAccount -and $this.ScanSource -eq "CA")
                {
                    $tagHash=$this.GetHashedTag($control.ControlItem.Id, $control.ResourceContext.ResourceId)
                    $hashToControlIDMap.add($tagHash,$control);
                    #complete the query
                    $TagSearchKeyword += "(ADOScannerHashId eq '" + $tagHash + "') or "
                    #if the query count equals the passing control results, search for bugs for this batch
                    if ($QueryKeyWordCount -eq $PassedControlResultsLength) {
                        #to remove OR from the last tag keyword. Ex: Tags: Tag1 OR Tags: Tag2 OR. Remove the last OR from this keyword
                        $TagSearchKeyword = $TagSearchKeyword.Substring(0, $TagSearchKeyword.length - 3)
                        $closedBugsResponse = $this.BugLogHelperObj.GetTableEntityAndCloseBug($TagSearchKeyword)
                        if ($closedBugsResponse){
                            $this.closedBugInfoCollect($closedBugsResponse, $hashToControlIDMap)
                        }
                    }
                }
                else {
                    $tagHash=$this.GetHashedTag($control.ControlItem.Id, $control.ResourceContext.ResourceId)
                    $hashToControlIDMap.add($tagHash,$control);
                    $TagSearchKeyword += "Tags: " + $tagHash + " OR "
                    #if the query count equals the passing control results, search for bugs for this batch
                    if ($QueryKeyWordCount -eq $PassedControlResultsLength) {
                        #to remove OR from the last tag keyword. Ex: Tags: Tag1 OR Tags: Tag2 OR. Remove the last OR from this keyword
                        $TagSearchKeyword = $TagSearchKeyword.Substring(0, $TagSearchKeyword.length - 3)
                        $response = $this.GetWorkItemByHash($TagSearchKeyword,$MaxKeyWordsToQuery)
                        #if bug was present
                        if ($response[0].results.count -gt 0) {
                            $ids = @();
                            $ids += $response.results.fields."system.id";
                            $closedBugsResponse = $this.CloseBugsInBulk($ids);
                            #$response.results | ForEach-Object {
                            #    #close the bug
                            #    $id = $_.fields."system.id"
                            #    $Project = $_.project.name
                            #    $this.CloseBug($id, $Project)
                            #}
                            
                            if ($closedBugsResponse){
                                $this.closedBugInfoCollect($closedBugsResponse, $hashToControlIDMap)
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
                        $tagHash=$this.GetHashedTag($control.ControlItem.Id, $control.ResourceContext.ResourceId)
                        $hashToControlIDMap.add($tagHash,$control);
                        $TagSearchKeyword += "(ADOScannerHashId eq '" + $tagHash + "') or "

                        #if number of tags reaches batch limit
                        if ($QueryKeyWordCount -eq $MaxKeyWordsToQuery) {
                            #query for all these tags and their bugs
                            $TagSearchKeyword = $TagSearchKeyword.Substring(0, $TagSearchKeyword.length - 3)
                            $closedBugsResponse = $this.BugLogHelperObj.GetTableEntityAndCloseBug($TagSearchKeyword);

                            if ($closedBugsResponse){
                                $this.closedBugInfoCollect($closedBugsResponse, $hashToControlIDMap)
                            }
                            #Reinitialize for the next batch
                            $QueryKeyWordCount = 0;
                            $TagSearchKeyword = "";
                            $PassedControlResultsLength -= $MaxKeyWordsToQuery
                            $hashToControlIDMap.Clear();
                        }
                    }
                    else
                    {
                        $tagHash=$this.GetHashedTag($control.ControlItem.Id, $control.ResourceContext.ResourceId) 
                        $hashToControlIDMap.add($tagHash,$control);
                        $TagSearchKeyword += "Tags: " + $tagHash + " OR "
                        #if number of tags reaches batch limit
                        if ($QueryKeyWordCount -eq $MaxKeyWordsToQuery) {
                        #query for all these tags and their bugs
                        $TagSearchKeyword = $TagSearchKeyword.Substring(0, $TagSearchKeyword.length - 3)
                        $response = $this.GetWorkItemByHash($TagSearchKeyword,$MaxKeyWordsToQuery)
                        if ($response[0].results.count -gt 0) {
                            $ids = @();
                            $ids += $response.results.fields."system.id";
                            $closedBugsResponse = $this.CloseBugsInBulk($ids);
                            #$response.results | ForEach-Object {
                            #    $id = $_.fields."system.id"
                            #    $Project = $_.project.name
                            #    $this.CloseBug($id, $Project)
                            #}
                            if ($closedBugsResponse){
                                $this.closedBugInfoCollect($closedBugsResponse, $hashToControlIDMap)
                            }
                        }
                        #Reinitialize for the next batch
                        $QueryKeyWordCount = 0;
                        $TagSearchKeyword = "";
                        $PassedControlResultsLength -= $MaxKeyWordsToQuery
                        $hashToControlIDMap.Clear();
                        }
                    }
                }
                
            }
        $hashToControlIDMap.Clear();
        $hashToControlIDMap=$null
        Remove-Variable hashToControlIDMap;    
    }

    #function to close an active bug
    hidden [void] CloseBug([string] $id, [string] $Project) {
        $url = "https://dev.azure.com/{0}/{1}/_apis/wit/workitems/{2}?api-version=6.0" -f $this.OrganizationName, $Project, $id
        
        #load the closed bug template
        $BugTemplate = [ConfigurationManager]::LoadServerConfigFile("TemplateForClosedBug.Json")
        $BugTemplate = $BugTemplate | ConvertTo-Json -Depth 10

           
           
        $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($url)
                
        try {
            $responseObj = Invoke-RestMethod -Uri $url -Method Patch  -ContentType "application/json-patch+json ; charset=utf-8" -Headers $header -Body $BugTemplate

        }
        catch {
            Write-Host "Could not close the bug" -ForegroundColor Red
        }
    }

    #function to close an active bugs in bulk
    hidden [object] CloseBugsInBulk([string[]] $ids) 
    {
        try {
            $closeBugTemplate = @();
            foreach ($id in $ids) {
                $closeBugTemplate += [PSCustomObject] @{ method = 'PATCH'; uri = "/_apis/wit/workitems/$($id)?api-version=4.1"; headers = @{"Content-Type" = 'application/json-patch+json'};
                body = @(@{op = "add"; "path"= "/fields/System.State"; "value"= "Closed"}; @{op = "add"; "path"= "/fields/Microsoft.VSTS.Common.ResolvedReason"; "value"= ""})
                }
            }
            if ($closeBugTemplate.count -gt 0) {
                $body = $null;
                if ($closeBugTemplate.count -eq 1) {
                    $body = "[$($closeBugTemplate | ConvertTo-Json -depth 10)]"
                }
                else {
                    $body = $closeBugTemplate | ConvertTo-Json -depth 10  
                }
                $uri = 'https://{0}.visualstudio.com/_apis/wit/$batch?api-version=4.1' -f $this.OrganizationName
                $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($uri)
                $adoResult = Invoke-RestMethod -Uri $uri -Method Patch -ContentType "application/json" -Headers $header -Body $body
                if ($adoResult -and $adoResult.count -gt 0) {
                    return $adoResult.value;
                }
            }
            return $false;
        }
        catch {
            Write-Host $_
            Write-Host "Could not close the bug." -ForegroundColor Red
            return $false
        }
    }

    hidden [void] closedBugInfoCollect([object] $closedBugsResponse, [hashtable] $hashToControlIDMap){
        # Hash map checks for duplicate work items
        $hashClosedBugs=@{}
        $closedBugsResponse| ForEach-Object{
            #Store closed bug details
            $bug=$_.body |ConvertFrom-Json
            $controlHashValue=$null
            #Fetch hash From storage account CA response
            if($this.UseAzureStorageAccount -and $this.ScanSource -eq "CA"){
                $controlHashValue=$bug.ADOScannerHashID
            }
            #Fetch hash for regular scan
            else{
                $controlHashValue=$bug.fields.'System.Tags'
            }
            
            if ($hashToControlIDMap.ContainsKey($controlHashValue) -and $bug.fields.'System.State' -eq 'Closed')
            {
                $id=$bug.id
                $project=$bug.fields.'System.TeamProject'
                $urlClose= "https://dev.azure.com/{0}/{1}/_workitems/edit/{2}" -f $this.OrganizationName, $project , $id;
                $hashToControlIDMap[$controlHashValue].ControlResults.AddMessage("Closed Bug",$urlClose);
                # duplicate work items do not populate static variable $ClosedBugs multiple times
                if(!$hashClosedBugs.ContainsKey($controlHashValue)){
                    [AutoCloseBugManager]::ClosedBugs+=$hashToControlIDMap[$controlHashValue]
                    $hashClosedBugs.add($controlHashValue,$true)
                }
            }
        }
        $hashClosedBugs.Clear()
    } 

    #function to retrieve all new/active/resolved bugs 
    hidden [object] GetWorkItemByHash([string] $hash,[int] $MaxKeyWordsToQuery) 
    {
        $url = "https://almsearch.dev.azure.com/{0}/_apis/search/workitemsearchresults?api-version=6.0-preview.1" -f $this.OrganizationName
        #take results have been doubled, as their might be chances for a bug to be logged more than once, if the tag id is copied.
        #in this case we want all the instances of this bug to be closed
        $body = '{"searchText": "{0}","$skip": 0,"$top": 60,"filters": {"System.TeamProject": [],"System.WorkItemType": ["Bug"],"System.State": ["New","Active","Resolved"]}}'| ConvertFrom-Json
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
