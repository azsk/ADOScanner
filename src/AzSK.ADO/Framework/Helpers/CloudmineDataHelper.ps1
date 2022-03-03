Set-StrictMode -Version Latest
class CloudmineDataHelper
{
    hidden static [CloudmineDataHelper] $CloudmineDataHelperInstance;
    hidden [bool] $UseAzureStorageAccount;
    hidden [string] $OrganizationName;
    hidden [string] $StorageAccount;
    hidden [object] $StorageAccountCtx;
    hidden [string] $StorageRG;
    hidden [bool] $errorMsgDisplayed = $false
    hidden [string] $SharedKey
    hidden [object] $hmacsha
    hidden [string] $Table = "variablegroups"

    CloudmineDataHelper([string] $orgName) {
        $this.OrganizationName = $orgName;
        # Resources Caching Storage settings
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

    hidden static [CloudmineDataHelper] GetInstance([string] $orgName) {
        [CloudmineDataHelper]::CloudmineDataHelperInstance = [CloudmineDataHelper]::new($orgName)
        return [CloudmineDataHelper]::CloudmineDataHelperInstance
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

    hidden [object] GetCloudMineData($projectID){
        $azTableMappingInfo = @();   
        try {            
            $azTableMappingInfo += $this.GetDataFromTable($projectID); 
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

    hidden [object] GetDataFromTable($projectID){
        try 
        {
            #$hash = $this.GetHashedTag($projectID)            
            $query = 'OrgName eq ''{0}'' and ProjectID eq ''{1}'''  -f $this.OrganizationName, $projectID                       
            $resource = '$filter='+[System.Web.HttpUtility]::UrlEncode($query);
            $table_url = "https://{0}.table.core.windows.net/{1}?{2}" -f $this.StorageAccount, $this.Table, $resource
            $headers = $this.GetHeader($this.Table)
            $item = [WebRequestHelper]::InvokeWebRequest([Microsoft.PowerShell.Commands.WebRequestMethod]::Get,$table_url,$headers,"application/json; charset=UTF-8"); 
            return $item;
        }
        catch
        {
            #Write-Host $_
            Write-Host "Could not fetch the entry for partition key from table storage or the table was not found.";
            return $null
        }
    }
}