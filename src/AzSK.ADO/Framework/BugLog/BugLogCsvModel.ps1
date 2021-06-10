Set-StrictMode -Version Latest

class BugLogCsvItem
{
    #Fields from JSON
    [string] $BugStatus=""
    [string] $FeatureName = ""
    [string] $ResourceName = ""
    [string] $ControlID = ""
    [string] $Severity = ""
    [string] $URL = ""
}