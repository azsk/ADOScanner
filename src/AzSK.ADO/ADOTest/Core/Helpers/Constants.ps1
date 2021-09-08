Set-StrictMode -Version Latest 
class Constants
{
    #All constant used across all modules Defined Here.
    static [string] $DoubleDashLine    = "================================================================================"
    static [string] $HashLine          = "################################################################################"
	static [string] $GTLine          =   ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
    static [string] $SingleDashLine    = "--------------------------------------------------------------------------------"
    static [string] $UnderScoreLineLine= "________________________________________________________________________________"
	static [string] $ExpectedDirectoryStucture = "\Core\Models\Default_Output_Directory_Stucture.json"
	static [string] $ExpectedPowerShellOutput = "\Core\Models\AzSK_Command_Expected_PS_Output.json"
	static [PSCustomObject[]] $ParallelScan = @()
	static [int] $MaxThreads = 20
	static [int] $SleepTimer = 120
	static [string] $AzSKTestCaseResultFileName = "\AzSKTestCaseResult.csv"
	static [string] $ConsolidatedResultFileName = "\ConsolidatedTestCaseResult.csv"
	static [string] $ParallelScanFileName = "\ParallelScanResultDetailed.csv"

	static [System.Collections.Hashtable] $OnlineStoreURL = @{
		"org-neutral_AzSKStaging" = "https://azsdkossepstaging.azureedge.net/`$Version/`$FileName"
		"org-neutral_AzSKPreview" = "https://azsdkosseppreview.azureedge.net/`$Version/`$FileName"
		"org-neutral_AzSK" = "https://azsdkossep.azureedge.net/`$Version/`$FileName"
		"cse_AzSKStaging" = "https://getazsdkcontrolsmsstaging.azurewebsites.net/api/files?version=`$Version&fileName=`$FileName"
		"cse_AzSKPreview" = "https://getazsdkcontrolsmspreview.azurewebsites.net/api/files?version=`$Version&fileName=`$FileName"
		"cse_AzSK" = "https://getazsdkcontrolsms.azurewebsites.net/api/files?version=`$Version&fileName=`$FileName"
	}
	static [String] $SkipJobsInParallelScan = 'IOM|GAI_AttestationInfo|GES' # Use following pattern to skip command 'GAI|GRS'; The IOM command block needs to be updated in ParallelScanData.ps1 before use.
	static [String] $RunJobsInParallelScan = '' # Use following pattern to select command 'GAI|GRS'
	static [String[]] $WhitelistedControlIds = @()

}