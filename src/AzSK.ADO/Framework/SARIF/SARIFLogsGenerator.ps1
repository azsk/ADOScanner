Set-StrictMode -Version Latest
class SARIFLogsGenerator {
    hidden [SVTEventContext []] $ClosedBugs;
    hidden [SARIFLog] $sarifLogInstance;
    SARIFLogsGenerator([SVTEventContext[]] $ControlResults,[string] $FolderPath,[string] $RunIdentifier)
    {
        $filteredControlResults= $ControlResults | Where-Object{$_.ControlResults.VerificationResult -eq "Failed" -or $_.ControlResults.VerificationResult -eq "Verify"}
		$this.ClosedBugs=$null
        $this.sarifLogInstance=$null
        $this.GenerateSARIFLogs($filteredControlResults,$FolderPath,$this.ClosedBugs,$RunIdentifier)
    }
    hidden [void] GenerateSARIFLogs([SVTEventContext []] $Controls, [string] $FolderPath,[SVTEventContext []] $ClosedBugs,[string] $RunIdentifier)
    {
        $this.sarifLogInstance=[SARIFLog]::new()
        $this.sarifLogInstance.PublishLogs($FolderPath,$Controls,$ClosedBugs,$RunIdentifier);
    }


}
