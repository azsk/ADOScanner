Set-StrictMode -Version Latest
class BugLogHelper {

    hidden static [BugLogHelper] $BugLogHelperInstance;

    hidden [bool] $UseAzureStorageAccount;
    hidden [string] $OrganizationName;
    hidden [string] $StorageAccount;

    hidden [object] $StorageAccountCtx;
    hidden [string] $StorageRG;
    hidden [bool] $errorMsgDisplayed = $false
    hidden [string] $SharedKey
    hidden [object] $hmacsha

    BugLogHelper([string] $orgName) {
        $this.OrganizationName = $orgName;
        
        $this.StorageAccount = $env:StorageName;
        $this.StorageRG = $env:StorageRG;
        #get storage details
        if ($this.StorageRG -and $this.StorageAccount) {
            $keys = Get-AzStorageAccountKey -ResourceGroupName $this.StorageRG -Name $this.StorageAccount
            $StorageContext = New-AzStorageContext -StorageAccountName $this.StorageAccount -StorageAccountKey $keys[0].Value -Protocol Https
            $this.SharedKey = $keys[0].Value;
            $this.StorageAccountCtx = $StorageContext.Context;

            $this.hmacsha = New-Object System.Security.Cryptography.HMACSHA256
            $this.hmacsha.key = [Convert]::FromBase64String($this.SharedKey)
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
            #get storage table data.
            $azTableBugInfo = @();
            $azTableBugInfo += $this.GetTableEntity($tableName, $hash); 
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
                   #$isDeleted = $this.DeleteTableEntity($tableName, $hash, $adoBugId);
                   #if ($isDeleted -eq $true) {
                   #    $this.AddDataInTable($tableName, $hash, $adoBugId, $projectName, "Y");
                   #}
                    $isUpdated = $this.UpdateTableEntity($tableName, $hash, $adoBugId, $projectName);
                }
                return $bugObj;
            }
        }
        catch {
            Write-Host $_
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
           $storageTables = @();
           $storageTables += Get-AzStorageTable -Context $this.StorageAccountCtx | Select Name;

           #create table if table not found.
           if ( !$storageTables -or ($storageTables.count -eq 0) -or !($storageTables.Name -eq $tableName) ) {
               New-AzStorageTable $tableName -Context $this.StorageAccountCtx;
           }

           $isDataAddedInTable = $this.AddDataInTable($tableName, $hash, $ADOBugId, $projectName, "N")
           return $isDataAddedInTable;           
        }
        catch {
            return $false;
        } 
        return $false
    }

    hidden [object] GetTableEntity($tableName, $hash) {
        try 
        {
            $query = 'ADOScannerHashId eq ''{0}'' and IsDeleted eq ''N''' -f $hash;
            $resource = '$filter='+[System.Web.HttpUtility]::UrlEncode($query);
            $table_url = "https://{0}.table.core.windows.net/{1}?{2}" -f $this.StorageAccount, $tableName, $resource
            $headers = $this.GetHeader($tableName)
            $item = Invoke-RestMethod -Method Get -Uri $table_url -Headers $headers -ContentType "application/json"
            return $item.value;
        }
        catch
        {
            #Write-Host $_
            Write-Host "Could not fetch the entry for partition key [$hash] in the table storage or the table was not found.";
            return $null
        }
    }

    hidden [bool] AddDataInTable($tableName, $hash, $ADOBugId, $projectName, $isDeleted)
    {
        $partitionKey = $hash;
        $rowKey = $hash + "_" + $ADOBugId;
           
        try 
        {
            #Add data in table.
            
            $entity = @{"PartitionKey" = $partitionKey; "RowKey" = $rowKey; "ADOBugId" = $ADOBugId; "ADOScannerHashId" = $hash; "IsDeleted" = $isDeleted; "ProjectName" = $projectName};
            $table_url = "https://{0}.table.core.windows.net/{1}" -f $this.StorageAccount, $tableName
            $headers = $this.GetHeader($tableName);
            $body = $entity | ConvertTo-Json
            $item = Invoke-RestMethod -Method POST -Uri $table_url -Headers $headers -Body $body -ContentType "application/json"
            return $true;
        }
        catch
        {
            Write-Host $_
            Write-Host "Could not push an entry in the table for row key [$rowKey]";
            return $false;
        }
    }

    hidden [bool] UpdateTableEntity($tableName, $hash, $ADOBugId, $projectName)
    {
        $PartitionKey = $hash;
        $Rowkey = $hash + "_" + $ADOBugId;
        
        try {
            #Update data in table.
           
            $entity = @{"ADOBugId" = $ADOBugId; "ADOScannerHashId" = $hash; "IsDeleted" = "Y"; "ProjectName" = $projectName};
            $body = $entity | ConvertTo-Json

            $version = "2017-04-17"
            $resource = "$tableName(PartitionKey='$PartitionKey',RowKey='$Rowkey')"
            $table_url = "https://$($this.StorageAccount).table.core.windows.net/$resource"
            $GMTTime = (Get-Date).ToUniversalTime().toString('R')
            $stringToSign = "$GMTTime`n/$($this.StorageAccount)/$resource"

            $signature = $this.hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($stringToSign))
            $signature = [Convert]::ToBase64String($signature)
            $body = $entity | ConvertTo-Json
            $headers = @{
                'x-ms-date'      = $GMTTime
                Authorization    = "SharedKeyLite " + $this.StorageAccount + ":" + $signature
                "x-ms-version"   = $version
                Accept           = "application/json;odata=minimalmetadata"
                'If-Match'       = "*"
            }
            Invoke-RestMethod -Method PUT -Uri $table_url -Headers $headers -Body $body -ContentType "application/json;odata=minimalmetadata"

            return $true;
        }
        catch
        {
            Write-Host $_
            Write-Host "Could not update entry in the table for row key [$RowKey]";
            return $false;
        }
    }

    hidden [bool] DeleteTableEntity($tableName, $hash, $ADOBugId) {
        $PartitionKey = $hash;
        $Rowkey = $hash + "_" + $ADOBugId;
        
        try {
            $version = "2017-04-17"
            $resource = "$tableName(PartitionKey='$PartitionKey',RowKey='$Rowkey')"
            $table_url = "https://$($this.StorageAccount).table.core.windows.net/$resource"
            $GMTTime = (Get-Date).ToUniversalTime().toString('R')
            $stringToSign = "$GMTTime`n/$($this.StorageAccount)/$resource"
            $signature = $this.hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($stringToSign))
            $signature = [Convert]::ToBase64String($signature)
            $headers = @{
                'x-ms-date'    = $GMTTime
                Authorization  = "SharedKeyLite " + $($this.StorageAccount) + ":" + $signature
                "x-ms-version" = $version
                Accept         = "application/json;odata=minimalmetadata"
                'If-Match'     = "*"
            }
            $item = Invoke-RestMethod -Method DELETE -Uri $table_url -Headers $headers -ContentType application/http
            return $true
        }
        catch {
            Write-Host $_
            Write-Host "Could not delete the entry for row key [$Rowkey] in the table storage.";
            return $false;
        }
        
    }

    hidden [object] GetHeader($tableName)
    {
        $version = "2017-07-29"
        $GMTTime = (Get-Date).ToUniversalTime().toString('R')
        $stringToSign = "$GMTTime`n/$($this.StorageAccount)/$tableName"
        
        $signature = $this.hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($stringToSign))
        $signature = [Convert]::ToBase64String($signature)
        $headers = @{
            'x-ms-date'    = $GMTTime
            Authorization  = "SharedKeyLite " + $this.StorageAccount + ":" + $signature
            "x-ms-version" = $version
            Accept         = "application/json;odata=minimalmetadata"
        }
        return $headers
    }

    hidden [object[]] GetTableEntityAndCloseBug([string] $hash) 
    {    
        #get table filter by name
        $tableName = $this.GetTableName();
        
        try {

            #Get clouddata to do perform read/write operations on the table
            $azTableBugInfo = @();

            $query = '({0}) and IsDeleted eq ''N''' -f $hash;
            $resource = '$filter='+[System.Web.HttpUtility]::UrlEncode($query);
            $table_url = "https://{0}.table.core.windows.net/{1}?{2}" -f $this.StorageAccount, $tableName, $resource
            $headers = $this.GetHeader($tableName)
            $item = Invoke-RestMethod -Method Get -Uri $table_url -Headers $headers -ContentType "application/json"
            
            $azTableBugInfo = $item.value
            if ($azTableBugInfo -and $azTableBugInfo.count -gt 0) {
                $adoBugIds = @();
                $adoBugIds += $azTableBugInfo.ADOBugId;
                $adoClosedBugResponse = $this.CloseBugsInBulk($adoBugIds);

                if($adoClosedBugResponse)
                {
                    foreach ($row in $adoClosedBugResponse) {
                        if($row.code -eq 200 )
                        {
                            $id = ($row.body | ConvertFrom-Json).id
                            $tableData = $azTableBugInfo | Where {$_.ADOBugId -eq $id} | Select PartitionKey, projectName, ADOScannerHashId
                            #$isDeleted = $this.DeleteTableEntity($tableName, $tableData.partitionKey , $id);
                            #if ($isDeleted -eq $true) {
                            #    $this.AddDataInTable($tableName, $tableData.partitionKey, $id, $tableData.projectName, "Y");
                            #}
                            $isUpdated = $this.UpdateTableEntity($tableName, $tableData.partitionKey, $id, $tableData.projectName);
                            #Adds ADOScannerHashId to response object
                            $row.body=$row.body.TrimEnd("}")
                            $row.body+=",`"ADOScannerHashId`":`"{0}`"" -f $tableData.ADOScannerHashId
                            $row.body+="}"
                        }
                    }
                return $adoClosedBugResponse
                } 
            }
        }
        catch {
            if (!$this.errorMsgDisplayed) {
               Write-Host "Could not update entry of closed bug in storage table." -ForegroundColor Red  
            }
            return $null;
        }
        
        return $null;
    } 

    hidden [string] GetTableName()
    {
        #return ($resourceNameToMakeTableName + "ADOBugInfo") -replace "[^a-zA-Z0-9]"
        return ($this.OrganizationName + "ADOBugInfo") -replace "[^a-zA-Z0-9]"
    }

    #function to close an active bug
    hidden [bool] CloseBug([string] $id, [string] $Project) {
        $url = "https://dev.azure.com/{0}/{1}/_apis/wit/workitems/{2}?api-version=6.0" -f $this.OrganizationName, $Project, $id
        #load the closed bug template
        $BugTemplate = [ConfigurationManager]::LoadServerConfigFile("TemplateForClosedBug.Json")
        $BugTemplate = $BugTemplate | ConvertTo-Json -Depth 10
        $header = [WebRequestHelper]::GetAuthHeaderFromUriPatch($url)               
        try {
            $responseObj = Invoke-RestMethod -Uri $url -Method Patch  -ContentType "application/json-patch+json ; charset=utf-8" -Headers $header -Body $BugTemplate
            return $true;
        }
        catch {
            Write-Host $_
            Write-Host "Could not close the bug." -ForegroundColor Red
            return $false
        }
        return $true;

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


}
