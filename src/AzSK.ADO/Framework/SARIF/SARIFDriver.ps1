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
        #ToDo remove both if else condition, if it works correctly on CA
        $tempVersion=$PSCmdlet.MyInvocation.MyCommand.Version
        if($tempVersion){ 
            $this.semanticVersion="{0}.{1}" -f $tempVersion.Major, $tempVersion.Minor
            $this.version="{0}.{1}.{2}" -f $tempVersion.Major, $tempVersion.Minor, $tempVersion.Build
        }
        else{
            $this.semanticVersion="1.1"
            $this.version="1.1.1"
        }
        $source=$PSCmdlet.MyInvocation.MyCommand.Source
        if($source){
            $this.properties.Source=$PSCmdlet.MyInvocation.MyCommand.Source
        }
        else{
            $this.properties.Source="Stage"
        }
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

        #Information required for helpuri. Please comment it out after documentation is updated.
        $CommonSVTResources=@{}
        if([Helpers]::CheckMember($ControlSettings,"ResourceTypesForCommonSVT")){
            $CommonSVTResources=$ControlSettings."ResourceTypesForCommonSVT"
        }
        $RulesHashMap=@{}
        $ControlResults | ForEach-Object{
            $control=$_
                if(!$RulesHashMap.ContainsKey($control.ControlItem.Id)){
                    $this.rules+=[SARIFRuleDescriptor]::new($control,$severityMap,$CommonSVTResources);
                    $RulesHashMap.Add($control.ControlItem.Id,$true)
                    }
        }
        $RulesHashMap.Clear()
    }
}