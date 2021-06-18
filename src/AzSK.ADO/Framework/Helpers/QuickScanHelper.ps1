Set-StrictMode -Version Latest
class QuickScanHelper{

    hidden [string] $OrganizationName;
    hidden [string] $StorageAccount;
    hidden [object] $StorageAccountCtx;
    hidden [string] $StorageRG;
    hidden [bool] $errorMsgDisplayed = $false
    hidden [string] $SharedKey
    hidden [object] $hmacsha

    QuickScanHelper([string] orgName){
        $this.OrganizationName = $orgName;
        
        # $this.StorageAccount = $env:StorageName;
        # $this.StorageRG = $env:StorageRG;
        $this.StorageAccount="ritikbavdekarstorage"
        $this.StorageRG="Ritik_Storage_Test"
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
    [System.Object[]] GetNewList([System.Object[]] $buildDefnsObj){
        $tableName=$this.GetTableName($buildDefnsObj[0].type)
        $newBuildDefnsObj=$null
        [System.Object[]] buildDefnsObjNew=$null
        $cloudCacheTableReference=(Get-AzStorageTable –Name $tableName –Context $this.StorageAccountCtx).CloudTable
        $rows=$this.queryCacheEntries($cloudCacheTableReference)
        $buildDefnsObj | ForEach-Object{
            $build=$_
            if(row[build] -eq build.revisionId)
            {

            }
            else {
                $this.UpdateCacheTable(tableName,id,rev);
                $newBuildDefnsObj+=$build
            }
        }
        

        # $rows=$this.GetTableEntity($tableName)
        # foreach($bldDef in $buildDefnsObj){


        # }  
        return $newBuildDefnsObj
     }

     [string] GetTableName([string] resourceType){
         return "{0}_Cache" -f resourceType
     }

     [System.Object[]] queryCacheEntries($cloudCacheTableReference){
         $rows=Get-AzTableRow -table $cloudCacheTableReference -partitionKey $this.OrganizationName -customFilter "ProjectId -eq "
     }

}