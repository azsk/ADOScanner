Set-StrictMode -Version Latest
class PublishToJSON {
    hidden [SVTEventContext[]] $ControlResults
    hidden [string] $FolderPath
	hidden[SVTEventContext[]] $bugsClosed
    PublishToJSON([SVTEventContext[]] $ControlResults,[string] $FolderPath,[SVTEventContext[]]$bugsClosed){
        $this.ControlResults=$ControlResults
        $this.FolderPath=$FolderPath
		$this.bugsClosed=$bugsClosed
        $this.PublishBugSummaryToJSON($ControlResults,$FolderPath,$bugsClosed)
		
    }

    hidden [void] PublishBugSummaryToJSON($ControlResults,[string] $FolderPath,$bugsClosed){
        #create three empty jsons for active, resolved and new bugs
        $ActiveBugs=@{ActiveBugs=@()}
		$ResolvedBugs=@{ResolvedBugs=@()}
        $NewBugs=@{NewBugs=@()}
		#Extra json for closed bugs
		$ClosedBugs=@{ClosedBugs=@()}

        #for each control result, check for failed/verify control results and look for the message associated with bug that differentiates it as one of the three kinds of bug
		$ControlResults | ForEach-Object{
				$result=$_;
				if($result.ControlResults[0].VerificationResult -eq "Failed" -or $result.ControlResults[0].VerificationResult -eq "Verify"){
					$result.ControlResults[0].Messages | ForEach-Object{
						if($_.Message -eq "Active Bug"){							
							$ActiveBugs.ActiveBugs+= [PSCustomObject]@{
								'Feature Name'=$result.FeatureName
								'Resource Name'=$result.ResourceContext.ResourceName
								'Control'=$result.ControlItem.ControlID
								'Severity'=$result.ControlItem.ControlSeverity
								'Url'=$_.DataObject
							}						
							
						}
						if($_.Message -eq "Resolved Bug"){
							$ResolvedBugs.ResolvedBugs+= [PSCustomObject]@{
								'Feature Name'=$result.FeatureName
								'Resource Name'=$result.ResourceContext.ResourceName
								'Control'=$result.ControlItem.ControlID
								'Severity'=$result.ControlItem.ControlSeverity
								'Url'=$_.DataObject
							}						
							
						}
						if($_.Message -eq "New Bug"){
							$NewBugs.NewBugs+= [PSCustomObject]@{
								'Feature Name'=$result.FeatureName
								'Resource Name'=$result.ResourceContext.ResourceName
								'Control'=$result.ControlItem.ControlID
								'Severity'=$result.ControlItem.ControlSeverity
								'Url'=$_.DataObject
							}
						
							
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
				$ClosedBugs.ClosedBugs+= [PSCustomObject]@{
					'Feature Name'=$bug.FeatureName
					'Resource Name'=$bug.ResourceContext.ResourceName
					'Control'=$bug.ControlItem.ControlID
					'Severity'=$bug.ControlItem.ControlSeverity
					'Url'=$_.DataObject
                }
			}
            }
		}
		}
		
		#the file where the json is stores
		$FilePath=$FolderPath+"\BugSummary.json"
        $combinedJson=$null;
        
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

        
        #output the json to file
		if($combinedJson){
		Add-Content $FilePath -Value ($combinedJson | ConvertTo-Json)
		}

    }
}