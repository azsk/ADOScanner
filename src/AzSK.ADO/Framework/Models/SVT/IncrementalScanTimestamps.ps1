Set-StrictMode -Version Latest
class IncrementalScanTimestamps
{
    [string] $orgName = 0
	[datetime] $Build = 0
    [datetime] $Release = 0
    [datetime] $AgentPools = 0
    [datetime] $VariableGroups = 0
    [datetime] $SecureFiles = 0

    IncrementalScanTimestamps([string] $OrganizationName)
    {
        $this.orgName = $OrganizationName
    }
}