Set-StrictMode -Version Latest
class SARIFRun{
    hidden [SARIFTool] $tool
    hidden [SARIFResult[]] $result
    SARIFRun([SVTEventContext[]]$ControlResults,[SVTEventContext[]]$ClosedBugs){
        $this.tool=[SARIFTool]::new($ControlResults)
        $this.result=$null
        $this.populateSARIFResult($ControlResults,$ClosedBugs)
    }
    hidden [void]populateSARIFResult([SVTEventContext[]]$ControlResults,[SVTEventContext[]]$ClosedBugs)
    {
        #parse through control results and populate
        $this.result+=[SARIFResult]::new()

    }
}



