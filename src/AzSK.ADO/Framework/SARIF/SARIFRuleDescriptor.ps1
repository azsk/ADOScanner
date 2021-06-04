Set-StrictMode -Version Latest
class SARIFRuleDescriptor{
    [string] $id
    [string] $name
    [PSCustomObject]@{
        "text" = ""
    }] $shortDescription

    [PSCustomObject]@{
        "text" = ""
    }] $fullDescription

    [string] $defaultConfiguration

    [PSCustomObject]@{
        "FeatureName" = ""
        "isBaseline" =$false
    }] $properties


    SARIFRuleDescriptor([SVTEventContext] $control)
    {
        $this.id=$control.ControlItem.Id
        $this.name=$control.ControlItem.ControlID
        $this.shortDescription."text"=$control.ControlItem.Description
        $this.fullDescription."text"=$control.ControlItem.Rationale
        $this.defaultConfiguration=$this.MapConfigToSARIF($control.ControlItem.ControlSeverity)
        $this.propeties."FeatureName"=$control.FeatureName
        $this.properties."isBaseline"=$control.ControlItem.isBaselineControl

    }

    hidden [string] MapConfigToSARIF([string] $value){
        #ToDo fix for other configs
        if($value -eq "High"){
            return "Error"
        }

        elseif($value -eq "Medium"){
            return "Warning"
        }

        else{
            return "Info"
        }

    }
}