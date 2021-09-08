Set-StrictMode -Version Latest 
class ADOTestResources
{
    #TESTRESOURCES
    [string] $Org = [string]::Empty
    [string]  $Pat = [string]::Empty 
    [ADOResourceInfo] $ResourceInfo

    ADOTestResources([String] $Org, [String] $Pat)
    {
        $this.Pat = $Pat
        $this.Org = $Org
        $this.ResourceInfo = [ADOResourceInfo]::new($Org, $Pat) 
    }
}