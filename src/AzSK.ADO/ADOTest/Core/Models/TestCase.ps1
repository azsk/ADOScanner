Set-StrictMode -Version Latest 
class TestCase{
    [string]$TestCaseID = [string]::Empty
	[bool]$Enabled = $false #Make it False to disable certain test case
	[bool]$AzureLoginRequired = $true #Set to 'false' if the test case does not require active Azure session, default is 'true'
    [string]$Priority = [string]::Empty
    [string]$Feature = [string]::Empty #SVT, Subscription Security etc.
    [string]$ModuleName = [string]::Empty  #KeyVault, App Service etc
    [string]$ParamFileName = [string]::Empty #Name of the ARM parameters file
    [string]$TemplateFileName = [string]::Empty #Name of the ARM template file
    [string]$BaselineOutput = [string]::Empty #Name of the output csv file against which the test case output is to be verified.
	[string]$PresetMethods = [string]::Empty #Names (semicolon separated) of the methods needed to preset the resource i.e. before running the test case.
	[string]$ResetMethods = [string]::Empty #Names (semicolon separated) of the methods needed to reset the resource i.e. after running the test case.
	[string]$PropertiesFileName = [string]::Empty #Properties json file name if one is required by any preset methods
    [string]$Description = [string]::Empty #Description of the test case
	[PSObject]$ControlResultSet = $null #Specific set of TCPs that are to be verified (if any)
	[bool]$NeedsDefaultResource = $false  #Set to 'true' if the test case needs a fresh resource.
	[string]$Type = "FVT" #You can set it to BVT in TestCases.json, Default is FVT i.e. Functional Verification Test
	[string]$TestMethod = [string]::Empty
	[string]$AutomationStatus = "Automated" # Default is automated, set to 'Manual' or 'PartiallyAutomated'
	[string]$ManualSteps = "NA"
	[string]$ParamSetId = "AllValidParams" #Default set to AllValidParams, will be overridden in TestCase.json
	[string]$ScanType = "" #Default 'Sequential', Other option "Parallel"
}