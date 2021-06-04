Set-StrictMode -Version Latest
class SARIFLogsGenerator {
    hidden [SVTEventContext []] $ClosedBugs;
    hidden [SVTEventContext []] $controls;
    hidden [string] $FolderPath;
    hidden [SARIFLog] $sarifLogInstance;
    SARIFLogsGenerator([SVTEventContext[]] $ControlResults,[string] $FolderPath)
    {
        $this.controls=$ControlResults
        $this.FolderPath=$FolderPath
		$this.ClosedBugs=$null
        $this.sarifLogInstance=$null
        $this.GenerateSARIFLogs($ControlResults,$FolderPath,$this.ClosedBugs)
    }
    hidden [void] GenerateSARIFLogs([SVTEventContext []] $Controls, [string] $FolderPath,[SVTEventContext []] $ClosedBugs)
    {
        $this.sarifLogInstance=[SARIFLog]::new()
        $this.sarifLogInstance.PublishLogs($FolderPath,$Controls,$ClosedBugs);
    }


}
