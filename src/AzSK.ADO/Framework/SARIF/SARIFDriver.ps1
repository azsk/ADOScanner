Set-StrictMode -Version Latest
class SARIFDriver{
    hidden [string] $name
    hidden [string] $version
    hidden [string] $semanticVersion
    $properties=[PSCustomObject]@{
        Source=""
    }

     [SARIFRuleDescriptor[]] $rules
    SARIFDriver([SVTEventContext[]] $ControlResults){
        #ToDo add driver name not hardcoded
        $this.name="SVT.ps1"
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

#     hidden [bool] ContainsRules([SVTEventContext] $control)
#     {
#         if($null -eq $this.rules)
#         {
#             return $false
#         }
#         $this.rules | ForEach-Object{
#             if($control.ControlItem.Id -eq $_.id){
#                 return $true
#             }
#         }
#         return $false

#     }
}