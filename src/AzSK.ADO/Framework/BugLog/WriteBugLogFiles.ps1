Set-StrictMode -Version Latest

class WriteBugLogCsv
{
    hidden [SVTEventContext[]] $ControlResults
    hidden [string] $FolderPath
    hidden [SVTEventContext[]] $bugsClosed
    WriteBugLogCsv([SVTEventContext[]] $ControlResults,[string] $FolderPath,[SVTEventContext[]] $bugsClosed){
        $this.ControlResults=$ControlResults
        $this.FolderPath=$FolderPath
        $this.bugsClosed=$bugsClosed
        $this.WriteBugSummaryToCsv($ControlResults,$FolderPath,$bugsClosed)
    }
    hidden [void] WriteBugSummaryToCsv($ControlResults,[string] $FolderPath,$bugsClosed ){
        [BugLogCsvItem[]] $BugsList = @();
        $ControlResults | ForEach-Object{
            $result=$_;
            if($result.ControlResults[0].VerificationResult -eq "Failed" -or $result.ControlResults[0].VerificationResult -eq "Verify"){
                $result.ControlResults[0].Messages | ForEach-Object{
                    if($_.Message -eq "Active Bug" -or $_.Message -eq "Resolved Bug" -or $_.Message -eq "New Bug"){	
                        $Bug=[BugLogCsvItem] @{
                            BugType=$_.Message
                            FeatureName=$result.FeatureName
                            ResourceName=$result.ResourceContext.ResourceName
                            ControlId=$result.ControlItem.ControlID
                            Severity=$result.ControlItem.ControlSeverity
                            URL=$_.DataObject
                        };
                        $BugsList+=$Bug;					
                    }
                }

            }

        
        }
        if($bugsClosed)
        {
        $bugsClosed | ForEach-Object{
        $bug=$_;
        $bug.ControlResults[0].Messages | ForEach-Object{
        if($_.Message -eq "Closed Bug"){
            $Bug=[BugLogCsvItem] @{
                BugType=$_.Message
                FeatureName=$bug.FeatureName
                ResourceName=$bug.ResourceContext.ResourceName
                ControlId=$bug.ControlItem.ControlID
                Severity=$bug.ControlItem.ControlSeverity
                URL=$_.DataObject
            };
            $BugsList+=$Bug;
        }
        }
    }
    }
        $bugLogFilePath= $FolderPath + "\BugLogDetails.csv";
        $BugsList | Export-Csv -Path $bugLogFilePath;
        return ;

    }
}