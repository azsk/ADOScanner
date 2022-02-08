Import-Module "C:\Users\juhitiwari\Desktop\CurrentSprint\2202\PGBug\ADOScanner\src\AzSK.ADO\AzSKStaging.ADO.psd1"

$reportFolder="C:\Users\juhitiwari\Desktop\CurrentSprint\2202\PGBug\BugLog"
$securityReport = "$($reportFolder)\SecurityReportAzTS.csv"
$bugTemplate = "$($reportFolder)\BugTemplate.Json"
$mappings = "$($reportFolder)\STMappingFiles"

Start-AzSKADOBugLogging -OrganizationName safetitestvso -BugLogProjectName StandaloneBugLogProject `
-ScanResultFilePath $securityReport -BugTemplateFilePath $bugTemplate -STMappingFilePath $mappings `
-AutoBugLog All -AreaPath "StandaloneBugLogProject" -IterationPath "StandaloneBugLogProject" 
