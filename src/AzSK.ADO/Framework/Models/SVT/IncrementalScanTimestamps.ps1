Set-StrictMode -Version Latest
class IncrementalScanTimestamps
{
	[datetime] $Build = 0
    [datetime] $Release = 0
    [datetime] $AgentPools = 0
    [datetime] $VariableGroups = 0
    [datetime] $SecureFiles = 0
}