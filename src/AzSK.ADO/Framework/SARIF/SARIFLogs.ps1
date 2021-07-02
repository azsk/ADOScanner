Set-StrictMode -Version Latest
class SARIFLog{
    [string] $version
    [string] $schema
    [SARIFRun[]] $runs
    SARIFLog(){
        $this.version="2.1.0"
        $this.schema="https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        $this.runs=$null;
    }
    hidden [void] PublishLogs([string] $FolderPath,[SVTEventContext[]] $ControlResults,[string] $RunIdentifier){
        $this.runs+=[SARIFRun]::new($ControlResults)
        #Publishing SARIF File
        $fileName="\ScanLog-{0}.sarif" -f $RunIdentifier 
        $filePath=$FolderPath+$fileName
        #hardCoded Approach
        # ($this |ConvertTo-Json -Depth 10).Insert(34,"$") | Out-File $filePath
        #Replace string approach
        # ($this |ConvertTo-Json -Depth 10).Replace("schema","`$schema") | Out-File $filePath
        #RegEx Approach
        $sarif=$this |ConvertTo-Json -Depth 10
        $s=[regex]'schema';
        ($s.Replace($sarif,"`$schema",1)) | Out-File $filePath;
        $sarif=$null
        Remove-Variable sarif
    }

}