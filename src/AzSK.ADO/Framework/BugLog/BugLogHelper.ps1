Set-StrictMode -Version Latest
class BugLogHelper {

    hidden static [BugLogHelper] $BugLogHelperInstance;

    hidden [bool] $UseAzureStorageAccount;
    hidden [string] $OrganizationName;
    hidden [string] $StorageAccount;

    hidden [object] $StorageAccountCtx;
    hidden [string] $StorageRG;
    hidden [bool] $hasAccessOnStorage = $false;
    hidden [bool] $errorMsgDisplayed = $false

    BugLogHelper([string] $orgName) {
        $this.OrganizationName = $orgName;
        
        $this.StorageAccount = $env:StorageName;
        $this.StorageRG = $env:StorageRG;
        
        #get storage details
        if ($this.StorageRG -and $this.StorageAccount) {
            $keys = Get-AzStorageAccountKey -ResourceGroupName $this.StorageRG -Name $this.StorageAccount
            $StorageContext = New-AzStorageContext -StorageAccountName $this.StorageAccount -StorageAccountKey $keys[0].Value -Protocol Https
    
            $this.StorageAccountCtx = $StorageContext.Context;
            $this.hasAccessOnStorage = $true;
        }
        
    }
    
    #Return BugLogHelper instance
    hidden static [BugLogHelper] GetInstance([string] $orgName) {
        [BugLogHelper]::BugLogHelperInstance = [BugLogHelper]::new($orgName)
        return [BugLogHelper]::BugLogHelperInstance
    }

    #function to search for existing bugs based on hash id
    hidden [object] GetWorkItemByHashAzureTable([string] $hash, [string] $projectName, [string] $reactiveOldBug) 
    {
        #get table filter by name
        $tableName = $this.GetTableName();
        $bugObj = @(@{});
        $bugObj[0].results = @();

        try {
            #get storage table.
            $cloudTable = (Get-AzStorageTable -Name $tableName -Context $this.StorageAccountCtx).CloudTable;
            if ($cloudTable) {
                #Get clouddata to do perform read/write operations on the table
    
                $azTableBugInfo = @();
                $azTableBugInfo += Get-AzTableRow -table $cloudTable -CustomFilter "(ADOScannerHashId eq '$hash' and IsDeleted eq 'N')";

                if ($azTableBugInfo -and $azTableBugInfo.count -gt 0) {
                    $adoBugId = $azTableBugInfo[0].ADOBugId;
    
                    $uri = "https://dev.azure.com/$($this.OrganizationName)/$projectName/_apis/wit/workitems/{0}?api-version=6.0" -f $adoBugId;
                    $response = [WebRequestHelper]::InvokeGetWebRequest($uri);
                    if($response -and ($response.count -gt 0) -and ($response.fields."System.State" -ne "Closed"))
                    {
                        #check if org policy wants to reactivate resolved bugs. 
                        #if status is not 'Resolve', send response.
                        #if status is 'Resolved' and ReactiveOldBug flag is true, then send response. (when response goes empty we add new bug)
                        if (($response.fields."System.State" -ne "Resolved") -or ($response.fields."System.State" -eq "Resolved" -and $reactiveOldBug -eq "ReactiveOldBug") )
                        {
                            $bugObj[0].results += $response; 
                        }  
                    }
                    else {
                        #if bug state is closed on the ADO side and isDeleted is 'N' in azuretable then update azure table -> set isdeleted ='Y'
                        $azTableBugInfo[0].IsDeleted = "Y";
                        $azTableBugInfo[0] | Update-AzTableRow -Table $cloudTable;
                    }

                    return $bugObj;
                }
            }
        }
        catch {
            Write-Host "Could not access storage account." -ForegroundColor Red
        }
        
        return $bugObj;
    }

    hidden [bool] InsertBugInfoInTable([string] $hash, [string] $projectName, [string] $ADOBugId) 
    {
        try 
        {
           $tableName = $this.GetTableName();

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
        $tableName = $this.GetTableName();

        try {
            #get storage table.
            $cloudTable = (Get-AzStorageTable -Name $tableName -Context $this.StorageAccountCtx).CloudTable;
            if ($cloudTable) {
                #Get clouddata to do perform read/write operations on the table
    
                 
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
               Write-Host "Could not update entry of closed bug in storage table." -ForegroundColor Red  
            }
            return $false;
        }
        
        return $true;
    } 

    hidden [string] GetTableName()
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
            Write-Host "Could not close the bug." -ForegroundColor Red
            return $false
        }
    }


}