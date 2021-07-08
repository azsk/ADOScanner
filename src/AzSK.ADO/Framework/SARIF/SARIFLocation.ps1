Set-StrictMode -Version Latest
class SARIFLocation{

    $physicalLocation=[PSCustomObject]@{
        artifactLocation = [PSCustomObject]@{
            uri = ""
        }
    }

    SARIFLocation($control){
        $this.physicalLocation.artifactLocation.uri=$control.ResourceContext.ResourceDetails.ResourceLink
    }


}