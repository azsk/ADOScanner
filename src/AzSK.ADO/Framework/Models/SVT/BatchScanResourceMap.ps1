Set-StrictMode -Version Latest 
class BatchScanResourceMap
{
    [int] $Skip
    [int] $Top
    [string] $BuildCurrentContinuationToken
    [string] $BuildNextContinuationToken
    [BatchScanState] $BatchScanState
    [DateTime] $LastModifiedTime
    [string] $ReleaseCurrentContinuationToken
    [string] $ReleaseNextContinuationToken
    [int] $ResourceCount
    [string] $SkipMarker
    
       
}

enum BatchScanState{
	INIT
	COMP
}