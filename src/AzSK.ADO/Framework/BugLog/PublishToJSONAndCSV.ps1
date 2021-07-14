Set-StrictMode -Version Latest
class PublishToJSONAndCSV {
    hidden [SVTEventContext[]] $ControlResults
    hidden [string] $FolderPath
	hidden[SVTEventContext[]] $bugsClosed
    PublishToJSONAndCSV([SVTEventContext[]] $ControlResults,[string] $FolderPath,[SVTEventContext[]] $bugsClosed){
        $this.ControlResults=$ControlResults
        $this.FolderPath=$FolderPath
		$this.bugsClosed=$bugsClosed
        $this.PublishBugSummaryToJSONAndCSV($ControlResults,$FolderPath,$bugsClosed)
    }

    hidden [void] PublishBugSummaryToJSONAndCSV([SVTEventContext[]] $ControlResults,[string] $FolderPath,[SVTEventContext[]] $bugsClosed){
        #create three empty jsons for active, resolved and new bugs
        $ActiveBugs=@{ActiveBugs=@()}
		$ResolvedBugs=@{ResolvedBugs=@()}
        $NewBugs=@{NewBugs=@()}
		#create empty json for closed bugs
		$ClosedBugs=@{ClosedBugs=@()}
		#Variable to dump info to CSV
		[PSCustomObject[]] $bugsList = @();

        #for each control result, check for failed/verify control results and look for the message associated with bug that differentiates it as one of the three kinds of bug
		if($ControlResults)
		{
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
		}
		#For each closed bug search for "Closed Bug" message and add to publishing files.
		if($bugsClosed){
		
			$bugsClosed | ForEach-Object{
				$result=$_
				$result.ControlResults[0].Messages | ForEach-Object{
					if($_.Message -eq "Closed Bug"){
						$bugInfo= [PSCustomObject]@{
							'Feature Name'=$result.FeatureName
							'Bug Status'=$_.Message
							'Resource Name'=$result.ResourceContext.ResourceName
							'Control'=$result.ControlItem.ControlID
							'Severity'=$result.ControlItem.ControlSeverity
							'Url'=$_.DataObject
                		}
						$ClosedBugs.ClosedBugs+=$bugInfo
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
		if($ClosedBugs.ClosedBugs){
			$combinedJson+=$ClosedBugs
        }
        
        #output the json and csv to file
		if($combinedJson){
		Add-Content $FilePath -Value ($combinedJson | ConvertTo-Json)
		$bugsList | Export-Csv -Path $CSVFilePath -NoTypeInformation;
		}
		
    }
}