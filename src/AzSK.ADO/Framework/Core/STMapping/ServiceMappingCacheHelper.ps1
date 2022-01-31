Set-StrictMode -Version Latest
class ServiceMappingCacheHelper {

    hidden static [ServiceMappingCacheHelper] $ServiceMappingCacheHelperInstance;
    hidden [bool] $UseAzureStorageAccount;
    hidden [string] $OrganizationName;
    # Resource Caching Storage settings to cache mappings
    hidden [string] $CacheStorageName;# Storage account name for Caching 
    hidden [string] $CacheStorageRG;# Storage resource group name for Caching 
    hidden [string] $CacheTable;#Storage table to cache resource mapping
    hidden [object] $CacheStorageAccountCtx;
    hidden [string] $SharedKey
    hidden [object] $hmacsha 

    ServiceMappingCacheHelper([string] $orgName) {
        $this.OrganizationName = $orgName;
        # Resources Caching Storage settings
        $this.CacheStorageName = $env:CacheStorageName;
        $this.CacheStorageRG = $env:CacheStorageRG;
        $this.CacheTable = $env:CacheTable;         
        #get storage details       
        if ($this.CacheStorageRG -and $this.CacheStorageName) {
            $keys = Get-AzStorageAccountKey -ResourceGroupName $this.CacheStorageRG -Name $this.CacheStorageName
            if ($null -ne $keys)
            {             
               #storage context to cache resource mappings
               $CacheStorageContext = New-AzStorageContext -StorageAccountName $this.CacheStorageName -StorageAccountKey $keys[0].Value -Protocol Https                                
               $this.CacheStorageAccountCtx = $CacheStorageContext.Context; 
               $this.SharedKey = $keys[0].Value;
               $this.hmacsha = New-Object System.Security.Cryptography.HMACSHA256
               $this.hmacsha.key = [Convert]::FromBase64String($this.SharedKey) 
            }
                         
        }
        
    }
    
    #Return ServiceMappingCacheHelper instance
    hidden static [ServiceMappingCacheHelper] GetInstance([string] $orgName) {
        [ServiceMappingCacheHelper]::ServiceMappingCacheHelperInstance = [ServiceMappingCacheHelper]::new($orgName)
        return [ServiceMappingCacheHelper]::ServiceMappingCacheHelperInstance
    }

    #function to search for existing mapping based on hash id
    hidden [object] GetWorkItemByHashAzureTable([string] $resourceType, [string] $pipelineType, [string] $pipelineId,[string] $resourceId, [string] $projectID) 
    {    
        #get storage table data.
        $azTableMappingInfo = @();   
        try {            
            $azTableMappingInfo += $this.GetTableEntity($projectID,$pipelineId,$pipelineType, $resourceId,$resourceType); 
            if ($azTableMappingInfo -and $azTableMappingInfo.count -gt 0) {                            
                return $azTableMappingInfo;
            }
        }
        catch {
            Write-Host $_
            Write-Host "Could not access storage account." -ForegroundColor Red
        }  
        
        return $azTableMappingInfo;
    }

    hidden [bool] InsertMappingInfoInTable( [string]  $orgName, [string]  $projectID, [string]  $pipelineID, [string]  $serviceTreeID,[string]  $pipelineLastModified,[string]  $resourceID,[string]  $resourceType,[string]  $resourceName,[string]  $pipelineType,[string]  $mappingExpiration, [bool] $isIncrementalScan) 
    {
        try 
        {                   
           #Get table filterd by name.
           $storageTables = @();
           $storageTables += Get-AzStorageTable -Context $this.CacheStorageAccountCtx | Select Name;

           #create table if table not found.
           if ( !$storageTables -or ($storageTables.count -eq 0) -or !($storageTables.Name -eq $this.CacheTable) ) {
               New-AzStorageTable $this.CacheTable -Context $this.CacheStorageAccountCtx;
           }

           $isDataAddedInTable = $this.AddDataInTable($orgName,$projectID,$pipelineID,$serviceTreeID,$pipelineLastModified,$resourceID,$resourceType,$resourceName,$pipelineType, $mappingExpiration, $isIncrementalScan)
           return $isDataAddedInTable;           
        }
        catch {
            return $false;
        } 
        return $false
    }

    hidden [string] GenerateSearchQuery($projectID,$pipelineId,$pipelineType, $resourceId,$resourceType,$hash)
    {
        $query = 'PartitionKey eq ''{0}''' -f $hash;
        if($resourceType -eq "All")
        {
           return 'OrgName eq ''{0}'' and ProjectID eq ''{1}''' -f $this.OrganizationName, $projectID; 
        }
        if($resourceType -eq "VariableGroup" -or $resourceType -eq "SecureFile" -and ![string]::IsNullOrEmpty($resourceId)) 
        {
            return 'RowKey eq ''{0}''' -f $hash;
        }
        if($resourceType -eq "VariableGroup" -or $resourceType -eq "SecureFile" -and [string]::IsNullOrEmpty($resourceId)) 
        {
            return 'OrgName eq ''{0}'' and ProjectID eq ''{1}'' and ResourceType eq ''{2}'' and ServiceTreeID ne ''UNMAPPED''' -f $this.OrganizationName, $projectID, $resourceType;
        }
        return $query;
    }

    hidden [object] GetTableEntity($projectID,$pipelineId,$pipelineType, $resourceId,$resourceType) {
        try 
        {
            $hash = $this.GetHashedTag($projectID, $pipelineID, $pipelineType,$resourceID,$resourceType)            
            $query =$this.GenerateSearchQuery($projectID,$pipelineId,$pipelineType, $resourceId,$resourceType,$hash)                         
            $resource = '$filter='+[System.Web.HttpUtility]::UrlEncode($query);
            $table_url = "https://{0}.table.core.windows.net/{1}?{2}" -f $this.CacheStorageName, $this.CacheTable, $resource
            $headers = $this.GetHeader($this.CacheTable)
            $item = Invoke-RestMethod -Method Get -Uri $table_url -Headers $headers -ContentType "application/json"
            return $item.value;
        }
        catch
        {
            #Write-Host $_
            Write-Host "Could not fetch the entry for partition key from table storage or the table was not found.";
            return $null
        }
    }

    hidden [bool] AddDataInTable([string]  $orgName, [string]  $projectID, [string]  $pipelineID, [string]  $serviceTreeID,[string]  $pipelineLastModified,[string]  $resourceID,[string]  $resourceType,[string]  $resourceName,[string]  $pipelineType,[string]  $mappingExpiration,[bool] $isIncrementalScan) 
    {    
        $partitionKey = $null;
        $rowKey = $null;
        if($isIncrementalScan){
            $partitionKey = $this.GetHashedTag($projectID, "", "","","");
            $rowKey = $this.GetHashedTag($projectID, "", "",$resourceID,$resourceType)
        }   
        else{
            $partitionKey = $this.GetHashedTag($projectID, $pipelineID, $pipelineType,"","");
            $rowKey = $this.GetHashedTag($projectID, $pipelineID, $pipelineType,$resourceID,$resourceType)
        }        
        
           
        try 
        {
            #Add data in table.            
            $entity = @{"PartitionKey" = $partitionKey; "RowKey" = $rowKey; "OrgName" = $orgName; "ProjectID" = $projectID; "PipelineID" = $pipelineID;"ServiceTreeID" = $serviceTreeID;"PipelineLastModified" = $pipelineLastModified;"ResourceID" = $resourceID;"ResourceType" = $resourceType;"ResourceName" = $resourceName;"PipelineType" = $pipelineType;  "MappingExpiration" = $MappingExpiration};
            $table_url = "https://{0}.table.core.windows.net/{1}" -f $this.CacheStorageName, $this.CacheTable
            $headers = $this.GetHeader($this.CacheTable);
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

    hidden [bool] UpdateTableEntity([string]  $orgName, [string]  $projectID, [string]  $pipelineID, [string]  $serviceTreeID,[string]  $pipelineLastModified,[string]  $resourceID,[string]  $resourceType,[string]  $resourceName,[string]  $pipelineType,[string]  $mappingExpiration,[bool] $isIncrementalScan) 
    {
        $partitionKey = $null;
        $rowKey = $null;
        if($isIncrementalScan){
            $partitionKey = $this.GetHashedTag($projectID, "", "","","");
            $rowKey = $this.GetHashedTag($projectID, "", "",$resourceID,$resourceType)
        }   
        else{
            $partitionKey = $this.GetHashedTag($projectID, $pipelineID, $pipelineType,"","");
            $rowKey = $this.GetHashedTag($projectID, $pipelineID, $pipelineType,$resourceID,$resourceType)
        }        
        
        
        try {
            #Update data in table.
            $tableName = $this.CacheTable;
            $entity = @{"OrgName" = $orgName; "ProjectID" = $projectID; "PipelineID" = $pipelineID;"ServiceTreeID" = $serviceTreeID;"PipelineLastModified" = $pipelineLastModified;"ResourceID" = $resourceID;"ResourceType" = $resourceType;"ResourceName" = $resourceName;"PipelineType" = $pipelineType;  "MappingExpiration" = $MappingExpiration};
            $body = $entity | ConvertTo-Json
            $version = "2017-04-17"
            $resource = "$tableName(PartitionKey='$PartitionKey',RowKey='$Rowkey')"
            $table_url = "https://$($this.CacheStorageName).table.core.windows.net/$resource"
            $GMTTime = (Get-Date).ToUniversalTime().toString('R')
            $stringToSign = "$GMTTime`n/$($this.CacheStorageName)/$resource"

            $signature = $this.hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($stringToSign))
            $signature = [Convert]::ToBase64String($signature)
            $body = $entity | ConvertTo-Json
            $headers = @{
                'x-ms-date'      = $GMTTime
                Authorization    = "SharedKeyLite " + $this.CacheStorageName + ":" + $signature
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

    hidden [bool] DeleteDataInTable($projectID, $resourceID,$resourceType){
        $partitionKey = $this.GetHashedTag($projectID, "", "","","");
        $rowKey = $this.GetHashedTag($projectID, "", "",$resourceID,$resourceType);
        try{
            $tableName = $this.CacheTable;
            $version = "2017-04-17"
            $resource = "$tableName(PartitionKey='$PartitionKey',RowKey='$Rowkey')"
            $table_url = "https://$($this.CacheStorageName).table.core.windows.net/$resource"
            $GMTTime = (Get-Date).ToUniversalTime().toString('R')
            $stringToSign = "$GMTTime`n/$($this.CacheStorageName)/$resource"

            $signature = $this.hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($stringToSign))
            $signature = [Convert]::ToBase64String($signature)
            $headers = @{
                'x-ms-date'      = $GMTTime
                Authorization    = "SharedKeyLite " + $this.CacheStorageName + ":" + $signature
                "x-ms-version"   = $version
                'If-Match'       = "*"
                Accept         = "application/json;odata=minimalmetadata"
            }
            Invoke-RestMethod -Method Delete -Uri $table_url -Headers $headers -ContentType "application/http"
        }
        catch{
            return $false;
        }
        return $true;
    }

    hidden [object] GetHeader($tableName)
    {
        $version = "2017-07-29"
        $GMTTime = (Get-Date).ToUniversalTime().toString('R')
        $stringToSign = "$GMTTime`n/$($this.CacheStorageName)/$tableName"
        
        $signature = $this.hmacsha.ComputeHash([Text.Encoding]::UTF8.GetBytes($stringToSign))
        $signature = [Convert]::ToBase64String($signature)
        $headers = @{
            'x-ms-date'    = $GMTTime
            Authorization  = "SharedKeyLite " + $this.CacheStorageName + ":" + $signature
            "x-ms-version" = $version
            Accept         = "application/json;odata=minimalmetadata"
        }
        return $headers
    }
    
    #function to compute hash and return the tag
    hidden [string] GetHashedTag([string] $projectID, [string] $pipelineID, [string] $pipelineType,[string] $resourceID,[string] $resourceType) { 
        $stringToHash = "$projectID#$pipelineID#$pipelineType";  
        if(![string]::IsNullOrEmpty($resourceType))
        {    
            $stringToHash = "$projectID#$pipelineID##$pipelineType$resourceID#$resourceType";
        }   
        return $this.ComputeHashX($stringToHash);     
    }

    hidden [string] ComputeHashX([string] $dataToHash) {
        return [Helpers]::ComputeHashShort($dataToHash, [Constants]::AutoBugLogTagLen)
    }
}
