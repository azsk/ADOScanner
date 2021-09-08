Set-StrictMode -Version Latest
class TestContext
{
    [AzSKSettings] $AzSKSettings;
    [HarnessSettings] $HarnessSettings;
    [TestResources] $TestResources;
    [ADOTestResources] $ADOTestResources;
        
    TestContext([string] $subscriptionId, [PSObject] $invocationContext)
    {
        $this.HarnessSettings = [HarnessSettings]::new($invocationContext);
        $this.AzSKSettings = [AzSKSettings]::new($invocationContext);
        $this.TestResources = [TestResources]::new($subscriptionId,$invocationContext);
    }

    TestContext([string] $org, [string] $Pat,  [PSObject] $invocationContext)
    {
        $this.HarnessSettings = [HarnessSettings]::new($invocationContext);
        $this.AzSKSettings = [AzSKSettings]::new($invocationContext);
        $this.ADOTestResources = [ADOTestResources]::new($org,$Pat);
    }

    [TestContext] GetTestContextInstance()
    {   
        return $this;
    }
}