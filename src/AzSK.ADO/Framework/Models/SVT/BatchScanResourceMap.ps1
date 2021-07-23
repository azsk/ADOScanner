Set-StrictMode -Version Latest 
class BatchScanResourceMap
{
    [int] $Skip
    [int] $Top
    [string] $CurrentContinuationToken
    [string] $NextContinuationToken
    [BatchScanState] $BatchScanState
    [DateTime] $LastModifiedTime
       
}

enum BatchScanState{
	INIT
	COMP
}