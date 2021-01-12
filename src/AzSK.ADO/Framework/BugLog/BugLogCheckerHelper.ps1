Set-StrictMode -Version Latest
class BugLogCheckerHelper {

    hidden static [BugLogCheckerHelper] $BugLogCheckerInstance;

    hidden [bool] $UseAzureStorageAccount;
    hidden [string] $OrganizationName;
    hidden [string] $StorageAccount;

    hidden [object] $StorageAccountCtx;
    hidden [string] $StorageRG;
    hidden [bool] $hasAccessOnStorage = $true;
    hidden [bool] $errorMsgDisplayed = $false

    BugLogCheckerHelper([string] $orgName) {
        $this.OrganizationName = $orgName;
        #$this.UseAzureStorageAccount = $useAzureStorageAccount;
        #TODO:
        $this.StorageAccount = $env:StorageName;
        $this.StorageRG = $env:StorageRG;
        #TODO:
        #$this.StorageAccount = "adoscannersa201021102003";
        #$this.StorageRG = "ADOScannerRG";

        #get storage
        $keys = Get-AzStorageAccountKey -ResourceGroupName $this.StorageRG -Name $this.StorageAccount
        $StorageContext = New-AzStorageContext -StorageAccountName $this.StorageAccount -StorageAccountKey $keys[0].Value -Protocol Https

        #$storageAcc = Get-AzStorageAccount -ResourceGroupName $this.StorageRG -Name $this.StorageAccount
        $this.StorageAccountctx = $StorageContext.Context;
    }
    
    #Return BugLogCheckerHelper instance
    hidden static [BugLogCheckerHelper] GetInstance([string] $orgName) {
        [BugLogCheckerHelper]::BugLogCheckerInstance = [BugLogCheckerHelper]::new($orgName)
        return [BugLogCheckerHelper]::BugLogCheckerInstance
    }

    #function to search for existing bugs based on the hash
    hidden [object] GetWorkItemByHashAzureTable([string] $hash, [string] $projectName, [string] $reactiveOldBug) 
    {
        #get table filter by name
        $tableName = $this.GetTableName($projectName);
        $bugObj = @(@{});
        $bugObj[0].results = @();

        try {
            #get storage table.
            $cloudTable = (Get-AzStorageTable -Name $tableName -Context $this.StorageAccountCtx).CloudTable;
            if ($cloudTable) {
                #Get clouddata to do some operation on the table
    
                $azTableBugInfo = @();
                #$azTableBugInfo += Get-AzTableRow -table $cloudTable -columnName "ADOScannerHashId" -value $hash -operator Equal 
                $azTableBugInfo += Get-AzTableRow -table $cloudTable -CustomFilter "(ADOScannerHashId eq '$hash' and IsDeleted eq 'N')";

                if ($azTableBugInfo -and $azTableBugInfo.count -gt 0) {
                    $adoBugId = $azTableBugInfo[0].ADOBugId;
    
                    $uri = "https://dev.azure.com/$($this.OrganizationName)/$projectName/_apis/wit/workitems/{0}?api-version=6.0" -f $adoBugId;
                    $response = [WebRequestHelper]::InvokeGetWebRequest($uri);
                    if($response -and ($response.count -gt 0) -and ($response.fields."System.State" -ne "Closed"))
                    {
                        #check for reactive old bug. 
                        #if status not resolve, send response.
                        #if status resolved and ReactiveOldBug find true, then send response. (when response goes empty we add new bug)
                        if (($response.fields."System.State" -ne "Resolved") -or ($response.fields."System.State" -eq "Resolved" -and $reactiveOldBug -eq "ReactiveOldBug") )
                        {
                            $bugObj[0].results += $response; 
                        }  
                    }
                    else {
                        #if bug status is closed in the ado and isdeleted in 'N' in azuretable then update azure table set isdeleted ='Y'
                        $azTableBugInfo[0].IsDeleted = "Y";
                        $azTableBugInfo[0] | Update-AzTableRow -Table $cloudTable;
                    }

                    return $bugObj;
                }
            }
        }
        catch {
            Write-Host "Not able to access storage account."
        }
        
        return $bugObj;
    }

    hidden [bool] InsertBugInfoInTable([string] $hash, [string] $projectName, [string] $ADOBugId) 
    {
        try 
        {
           $tableName = $this.GetTableName($projectName);

           #Get table filterd by name.
           $storageTables = Get-AzStorageTable -Context $this.StorageAccountCtx | Select Name;

           #create table if table not found.
           if ( !$storageTables -or ($storageTables.Count -eq 0) -or !($storageTables.Name -eq $tableName) ) {
               New-AzStorageTable -Name $tableName -Context $this.StorageAccountCtx;   
           }
           #Get cloudTable to do some operations on the table.
           $cloudTable = (Get-AzStorageTable -Name $tableName -Context $this.StorageAccountCtx).CloudTable;

           #Add data in table.
           $partitionKey = $hash;
           $rowKey = $hash + "_" + $ADOBugId;
           Add-AzTableRow -Table $cloudTable -PartitionKey $partitionKey -RowKey ($rowKey) -property @{"ADOBugId" = $ADOBugId; "ADOScannerHashId" = $hash; "IsDeleted" = "N"; "ProjectName" = $projectName};
           return $true;           
        }
        catch {
            return $false;
        } 
    }

    hidden [bool] GetTableEntityAndCloseBug([string] $hash) 
    {    
        #get table filter by name
        $tableName = $this.GetTableName("");

        try {
            #get storage table.
            $cloudTable = (Get-AzStorageTable -Name $tableName -Context $this.StorageAccountCtx).CloudTable;
            if ($cloudTable) {
                #Get clouddata to do some operation on the table
    
                #$azTableBugInfo += Get-AzTableRow -table $cloudTable -columnName "ADOScannerHashId" -value $hash -operator Equal 
                $azTableBugInfo = @();
                $azTableBugInfo += Get-AzTableRow -table $cloudTable -CustomFilter "(($hash) and (IsDeleted eq 'N'))";

                if ($azTableBugInfo -and $azTableBugInfo.count -gt 0) {
                    foreach ($row in $azTableBugInfo) {
                        if($this.CloseBug($row[0].ADOBugId, $row[0].projectName) )
                        {
                            $row.IsDeleted = "Y";
                            $row | Update-AzTableRow -Table $cloudTable;
                        }
                    } 
                }
            }
        }
        catch {
            if (!$this.errorMsgDisplayed) {
               Write-Host "Not able to access storage account. Could not close the bug." -Red  
            }
            return $false;
        }
        
        return $true;
    } 

    hidden [string] GetTableName([string] $resourceNameToMakeTableName)
    {
        #return ($resourceNameToMakeTableName + "ADOBugInfo") -replace "[^a-zA-Z0-9]"
        return ($this.OrganizationName + "ADOBugInfo") -replace "[^a-zA-Z0-9]"
    }

    #function to close an active bug
    hidden [bool] CloseBug([string] $id, [string] $Project) {
        $url = "https://dev.azure.com/{0}/{1}/_apis/wit/workitems/{2}?api-version=5.1" -f $this.OrganizationName, $Project, $id
        #load the closed bug template
        $BugTemplate = [ConfigurationManager]::LoadServerConfigFile("TemplateForClosedBug.Json")
        $BugTemplate = $BugTemplate | ConvertTo-Json -Depth 10
        $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($url)               
        try {
            $responseObj = Invoke-RestMethod -Uri $url -Method Patch  -ContentType "application/json-patch+json ; charset=utf-8" -Headers $header -Body $BugTemplate
            return $true;
        }
        catch {
            Write-Host "Could not close the bug" -Red
            return $false
        }
    }


}