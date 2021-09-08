Set-StrictMode -Version Latest 
class HarnessSettings
{
     #TESTSETTINGS/HARNESSSETTINGS
    # Test harness setting
    [string] $AzSKModule = [string]::Empty # TODO: AzSKModuleType
    [string] $AzSKModulePath = [string]::Empty
    

    HarnessSettings([PSObject] $invocationContext)
    {
        $this.AzSKModule = $invocationContext.BoundParameters["AzSKModule"];
        if($invocationContext.BoundParameters["AzSKModulePath"]) {
            $this.AzSKModulePath = $invocationContext.BoundParameters["AzSKModulePath"];
        }
    }
}