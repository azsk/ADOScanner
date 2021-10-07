Set-StrictMode -Version Latest
class IncrementalScanTimestamps
{
	[PSObject] $Build
    [PSObject] $Release
}

class IncrementalTimeStampsResources
{
    [datetime] $LastScanTime = 0
    #to save timestamp for last partial scan
    [datetime] $LastPartialTime = 0
    #to save timestamp for last full scan for the resource
    [datetime] $LastFullScanTime = 0
    [bool] $IsFullScanInProgress
}