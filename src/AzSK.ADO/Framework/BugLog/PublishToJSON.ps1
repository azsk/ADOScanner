Set-StrictMode -Version Latest
class PublishToJSON {
    hidden [SVTEventContext[]] $ControlResults
    hidden [string] $FolderPath
    PublishToJSON([SVTEventContext[]] $ControlResults,[string] $FolderPath){
        $this.ControlResults=$ControlResults
        $this.FolderPath=$FolderPath
        $this.PublishBugSummaryToJSON($ControlResults,$FolderPath)
    }

    hidden [void] PublishBugSummaryToJSON($ControlResults,[string] $FolderPath){
        #create three empty jsons for active, resolved and new bugs
        $ActiveBugs=@{ActiveBugs=@()}
		$ResolvedBugs=@{ResolvedBugs=@()}
        $NewBugs=@{NewBugs=@()}
		[PSCustomObject[]] $bugsList = @();

        #for each control result, check for failed/verify control results and look for the message associated with bug that differentiates it as one of the three kinds of bug
		$ControlResults | ForEach-Object{
				$result=$_;
				if($result.ControlResults[0].VerificationResult -eq "Failed" -or $result.ControlResults[0].VerificationResult -eq "Verify"){
					$result.ControlResults[0].Messages | ForEach-Object{
						if($_.Message -eq "Active Bug"){							
							$bugInfo= [PSCustomObject]@{
								'Feature Name'=$result.FeatureName
								'Bug Status'=$_.Message
								'Resource Name'=$result.ResourceContext.ResourceName
								'Control'=$result.ControlItem.ControlID
								'Severity'=$result.ControlItem.ControlSeverity
								'Url'=$_.DataObject
							}
							$ActiveBugs.ActiveBugs+=$bugInfo
							$bugsList+=$bugInfo
							
						}
						if($_.Message -eq "Resolved Bug"){
							$bugInfo= [PSCustomObject]@{
								'Feature Name'=$result.FeatureName
								'Bug Status'=$_.Message
								'Resource Name'=$result.ResourceContext.ResourceName
								'Control'=$result.ControlItem.ControlID
								'Severity'=$result.ControlItem.ControlSeverity
								'Url'=$_.DataObject
							}
							$ResolvedBugs.ResolvedBugs+=$bugInfo
							$bugsList+=$bugInfo	
							
						}
						if($_.Message -eq "New Bug"){
							$bugInfo = [PSCustomObject]@{
								'Feature Name'=$result.FeatureName
								'Bug Status'=$_.Message
								'Resource Name'=$result.ResourceContext.ResourceName
								'Control'=$result.ControlItem.ControlID
								'Severity'=$result.ControlItem.ControlSeverity
								'Url'=$_.DataObject
							}
							$NewBugs.NewBugs+=$bugInfo
							$bugsList+=$bugInfo
							
						}
					}
				}
			
		}

		
		#the file where the json is stored
		$FilePath=$FolderPath+"\BugSummary.json"
        $combinedJson=$null;

		$CSVFilePath=$FolderPath+"\BugSummary.csv"
        
        #merge all three jsons in one consolidated json
		if($NewBugs.NewBugs){
			$combinedJson=$NewBugs
		}
		if($ResolvedBugs.ResolvedBugs){
			$combinedJson+=$ResolvedBugs
		}
		if($ActiveBugs.ActiveBugs){
			$combinedJson+=$ActiveBugs
        }
        
        #output the json and csv to file
		if($combinedJson){
		Add-Content $FilePath -Value ($combinedJson | ConvertTo-Json)
		$bugsList | Export-Csv -Path $CSVFilePath -NoTypeInformation;
		}
		
    }
}