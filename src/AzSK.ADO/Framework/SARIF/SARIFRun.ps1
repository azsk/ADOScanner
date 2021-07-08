Set-StrictMode -Version Latest
class SARIFRun{
    hidden [SARIFTool] $tool
    hidden [SARIFResult[]] $results
    SARIFRun([SVTEventContext[]]$ControlResults){
        $this.tool=[SARIFTool]::new($ControlResults)
        $this.results=$null
        $this.populateSARIFResult($ControlResults)
    }
    hidden [void]populateSARIFResult([SVTEventContext[]]$ControlResults)
    {
        #parse through control results and populate
        $ControlResults | ForEach-Object{
            $control=$_
            $this.results+=[SARIFResult]::new($_)
        }        
    }
}



