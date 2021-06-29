Set-StrictMode -Version Latest
class SARIFDriver{
    hidden [string] $name
    hidden [string] $version
    hidden [string] $semanticVersion
    hidden [string] $informationUri="https://github.com/azsk/ADOScanner-docs"
    $properties=[PSCustomObject]@{
        Source=""
    }

     [SARIFRuleDescriptor[]] $rules
    SARIFDriver([SVTEventContext[]] $ControlResults){
        $this.name="ADO Scanner"
        ##ADO Version and Source populate
        $ver=$PSCmdlet.MyInvocation.MyCommand.Version 
        $this.semanticVersion="{0}.{1}" -f $ver.Major, $ver.Minor
        $this.version="{0}.{1}.{2}" -f $ver.Major, $ver.Minor, $ver.Build
        $this.properties.Source=$PSCmdlet.MyInvocation.MyCommand.Source
        $this.rules=$null
        $this.populateRules($ControlResults)

    }   
    hidden [void] populateRules([SVTEventContext[]] $ControlResults){
        #Parsing through rules
        $severityMap=@{}
        $ControlSettings = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
        if([Helpers]::CheckMember($ControlSettings,"ControlSeverity")){
            $severityMap=$ControlSettings."ControlSeverity"
        }
        $RulesHashMap=@{}
        $ControlResults | ForEach-Object{
            $control=$_
                if(!$RulesHashMap.ContainsKey($control.ControlItem.Id)){
                    $this.rules+=[SARIFRuleDescriptor]::new($control,$severityMap);
                    $RulesHashMap.Add($control.ControlItem.Id,$true)
                    }
        }
        $RulesHashMap.Clear()
    }
}