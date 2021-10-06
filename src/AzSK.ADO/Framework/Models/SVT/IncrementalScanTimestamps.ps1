Set-StrictMode -Version Latest
class IncrementalScanTimestamps
{
	[datetime] $Build = 0
    [datetime] $Release = 0
    [datetime] $BuildPreviousTime = 0
    [datetime] $ReleasePreviousTime = 0
    [datetime] $LastFullScanBuild = 0
    [datetime] $LastFullScanRelease = 0
}