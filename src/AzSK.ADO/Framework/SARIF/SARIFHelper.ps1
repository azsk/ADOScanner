Set-StrictMode -Version Latest
class SARIFHelper{
    hidden [string] $folderPath
    SARIFHelper([string] $folderPath){
        $this.folderPath=$folderPath
    }

    hidden [void] AddDollar()
    {
        $logLocation=$folderPath+"\logs.sarif"
        
    }

    


}