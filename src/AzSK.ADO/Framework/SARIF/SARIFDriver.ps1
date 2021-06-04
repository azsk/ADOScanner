Set-StrictMode -Version Latest
class SARIFDriver{
    hidden [string] $name
    hidden [string] $version
    hidden [string] $SemanticVersion
    hidden [SARIFRuleDescriptor[]] $rules
    SARIFDriver([SVTEventContext[]] $ControlResults){
        $this.name=$PSCmdlet.MyInvocation.PSCommandPath
        ##Fix
        $this.version="1.2"
        $this.SemanticVersion="1.7"
        $this.rules=$null
        $this.populateRules($ControlResults)

    }   
    hidden [void] populateRules([SVTEventContext[]] $ControlResults){
        #Parsing through rules
        $ControlResults | ForEach-Object{
            $control=$_
            if($control.ControlResults[0].VerificationResult -eq "Failed" -or $control.ControlResults[0].VerificationResult -eq "Verify"){
                if(!$this.ContainsRules($control)){
                    $this.rules+=[SARIFRuleDescriptor]::new($control);
                }
            }
        }

    }
    hidden [bool] ContainsRules([SVTEventContext] $control)
    {
        $this.rules | ForEach-Object{
            if($control.ControlResults.ControlID -eq $_.id){
                return $true
            }
        }
        return $false

    }
}