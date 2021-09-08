class TestCaseResult {    
    [TestCase] $TestCase
	[TestStatus] $TestStatus
    [String] $Message = [string]::Empty

	TestCaseResult([TestCase] $tc, [TestStatus] $TestStatus, [string]$message){
		$this.TestCase = $tc
		$this.TestStatus = $TestStatus
		$this.Message = $message
	}
	TestCaseResult([TestCase] $tc){
		$this.TestCase = $tc
		$this.TestStatus = [TestStatus]::NotStarted
		$this.Message = [string]::Empty
	}
}