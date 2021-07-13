Set-StrictMode -Version Latest
class SARIFTool{
    hidden[SARIFDriver] $driver
    SARIFTool([SVTEventContext[]] $ControlResults){
        $this.driver=[SARIFDriver]::new($ControlResults)
    }   
}