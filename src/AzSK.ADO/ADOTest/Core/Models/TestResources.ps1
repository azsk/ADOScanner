Set-StrictMode -Version Latest 
class TestResources
{
    #TESTRESOURCES
    # Resources for testing (PIM, attestation)
    [string] $SubscriptionId = [string]::Empty
    [string] $RGForTestResources = "AzSKRG" # Name of the resource group to be used for testing eg., AZSKTestRG
    [ResourceInfo] $ResourceInfo
    # TODO: ResourceInfo ( Should ControlInfo be independent?)
    # Intialize "ResourceInfo"

    TestResources([String] $subscriptionId,[PSObject] $invocationContext)
    {
        $this.SubscriptionId = $subscriptionId
        if ($invocationContext.BoundParameters["RGForTestResources"]) {
            $this.RGForTestResources = $invocationContext.BoundParameters["RGForTestResources"]
        }
        $this.ResourceInfo = [ResourceInfo]::new($subscriptionId) # Currently we are directly inheriting AzSKControlInfo in ResourceInfo
    }
}