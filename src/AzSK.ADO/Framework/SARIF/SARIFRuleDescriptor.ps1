Set-StrictMode -Version Latest
class SARIFRuleDescriptor{
    [string] $id
    [string] $name
    $shortDescription=[PSCustomObject]@{
        text = ""
    }

    $fullDescription=[PSCustomObject]@{
        text = ""
    }


    $defaultConfiguration=[PSCustomObject]@{
        level = ""
    }
    # $help=[PSCustomObject]@{
    #     text = ""
    # }

    $properties=[PSCustomObject]@{
        FeatureName = ""
        isBaseline =$false
    } 
    [string] $helpUri
    $messageStrings=[PSCustomObject]@{
         Recommendation= [PSCustomObject]@{
             text = $null
         }
        #  Description=[PSCustomObject]@{
        #      text =$null
        #  }
    }


    SARIFRuleDescriptor([SVTEventContext] $control,$severityMap,$CommonSVTResources)
    {
        $this.id="AdoS@"+ $control.ControlItem.Id
        $this.name=$control.ControlItem.ControlID
        $this.shortDescription.text=$control.ControlItem.Description
        $this.fullDescription.text=$control.ControlItem.Rationale
        $this.messageStrings.Recommendation.text=$control.ControlItem.Recommendation
        # $this.messageStrings.Description.text=$control.ControlItem.Description
        $this.defaultConfiguration.level=$this.MapConfigToSARIF($control.ControlItem.ControlSeverity,$severityMap)
        $this.properties.FeatureName=$control.FeatureName
        $this.properties.isBaseline=$control.ControlItem.isBaselineControl
        #Common SVT Resources are mapped to Common SVT header of github docs.
        if($CommonSVTResources -Contains $this.properties.FeatureName){
            $this.helpUri="https://github.com/azsk/ADOScanner-docs/tree/master/References/Control%20Coverage#{0}" -f "CommonSVTControls"
        }
        else{
            $this.helpUri="https://github.com/azsk/ADOScanner-docs/tree/master/References/Control%20Coverage#{0}" -f $control.FeatureName 
        }
        # $this.help.text=$control.ControlItem.Recommendation
        

    }

    hidden [string] MapConfigToSARIF([string] $value,$severityMap){

        if($severityMap){
            if([Helpers]::CheckMember($severityMap,"Critical") -and $value -eq $severityMap.Critical){
                return "error"
            }
            elseif([Helpers]::CheckMember($severityMap,"High") -and $value -eq $severityMap.High){
                return "error"
            }
            elseif([Helpers]::CheckMember($severityMap,"Medium") -and $value -eq $severityMap.Medium){
                return "warning"
            }
            elseif([Helpers]::CheckMember($severityMap,"Low") -and $value -eq $severityMap.Low){
                return "info"
            }

        }
        if($value -eq "High" -or $value -eq "Critical"){
            return "error"
        }
        elseif($value -eq "Medium"){
            return "warning"
        }
        else{
            return "info"
        }
    }

}