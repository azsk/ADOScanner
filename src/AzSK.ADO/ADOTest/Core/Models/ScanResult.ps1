Set-StrictMode -Version Latest
class ScanResult {    
	[String] $Name = [string]::Empty
	[System.Collections.ArrayList] $ScanError = @()
	[System.Collections.ArrayList] $OutputFolder = @()
	[string[]] $FolderDiff = @()
	[string] $CSVError = [string]::Empty
	[PSObject] $LogError

	ScanResult([String] $Name, [System.Collections.ArrayList] $ScanError, [System.Collections.ArrayList] $OutputFolder, [string[]] $FolderDiff, [Boolean] $CSVError,[String] $LogError){
		$this.Name = $Name
		$this.PSScanError = $ScanError
		$this.OutputFolder = $OutputFolder
		$this.FolderDiff = $FolderDiff
		$this.CSVError = $CSVError
		$this.LogError = $LogError
	}
}