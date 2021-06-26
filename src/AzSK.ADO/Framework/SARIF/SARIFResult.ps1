Set-StrictMode -Version Latest
class SARIFResult{
    [string] $ruleId
    $message=[PSCustomObject]@{
        id = ""
        # rationale=""
        # recommendation=""
    }
    $properties=[PSCustomObject]@{
        ResourceId = ""
        ResourceName=""
        OrgId=""
        OrgName=""
        VerificationResult=""
    }

    # [string] $baselineState="unchanged"
    [SARIFLocation[]] $locations
    SARIFResult( [SVTEventContext] $control)
    {
        $this.ruleId="AdoS@" + $control.ControlItem.Id
        $this.message.id="Recommendation"
        # $this.message.rationale=$control.ControlItem.Rationale
        # $this.message.recommendation=$control.ControlItem.Recommendation
        # $this.determineBaselineState($control)
        
        $this.properties.ResourceId=$control.ResourceContext.ResourceId
        $this.properties.ResourceName=$control.ResourceContext.ResourceName
        $this.properties.OrgId=$control.OrganizationContext.OrganizationId
        $this.properties.OrgName=$control.OrganizationContext.OrganizationName
        $this.properties.VerificationResult= $control.ControlResults[0].VerificationResult
        $this.locations+=[SARIFLocation]::new($control)


    }

    hidden [void] determineBaselineState([SVTEventContext] $control){
        if($PSCmdlet.MyInvocation.BoundParameters.ContainsKey("AutoBugLog")){
            $control.ControlResults[0].Messages |ForEach-Object{
                if($_.Message -eq "Active Bug"){
                    $this.baselineState="unchanged"
                }
            }
        }
    }



}
