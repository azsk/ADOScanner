Set-StrictMode -Version Latest
class SARIFDriver{
    hidden [string] $name
    hidden [string] $version
    hidden [string] $SemanticVersion
    hidden [SARIFRuleDescriptor[]] $rules
    SARIFDriver([SVTEventContext[]] $ControlResults){
        $this.name="SVT.ps1"
        ##Fix
        $this.version="1.2"
        $this.SemanticVersion="1.7"
        $this.rules=$null
        $this.populateRules($ControlResults)

    }   
    hidden [void] populateRules([SVTEventContext[]] $ControlResults){
        #Parsing through rules
        $this.rules+=[SARIFRuleDescriptor]::new();
    }
}