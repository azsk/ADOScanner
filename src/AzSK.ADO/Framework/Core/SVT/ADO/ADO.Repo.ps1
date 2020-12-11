Set-StrictMode -Version Latest 
class Repo: ADOSVTBase {    
    hidden $RepoId = "";

    Repo([string] $subscriptionId, [SVTResource] $svtResource): Base($subscriptionId,$svtResource) {
        $this.RepoId = $svtResource.ResourceId.split('/')[-1]
    }
    
    hidden [ControlResult] CheckInactiveRepo([ControlResult] $controlResult) {
        $currentDate = Get-Date
        try {
            $projectId = ($this.ResourceContext.ResourceId -split "project/")[-1].Split('/')[0]
            # check if repo has commits in past ActivityThresholdInDays days
            $thresholdDate = $currentDate.AddDays(-$this.ControlSettings.Repo.ActivityThresholdInDays);
            $url = "https://dev.azure.com/$($this.SubscriptionContext.SubscriptionName)/$projectId/_apis/git/repositories/$($this.RepoId)/commits?searchCriteria.fromDate=$($thresholdDate)&&api-version=6.0"
            $res = [WebRequestHelper]::InvokeGetWebRequest($url);
            if([Helpers]::CheckMember($res[0].PSobject.Properties.Name, "count")) {
                $controlResult.AddMessage([VerificationResult]::Failed, "Repository has no commits since last $($this.ControlSettings.Repo.ActivityThresholdInDays) days.");
            }
            else {
                $controlResult.AddMessage([VerificationResult]::Passed, "Repository has commits since last $($this.ControlSettings.Repo.ActivityThresholdInDays) days.");
            }
        }
        catch {
            $controlResult.AddMessage([VerificationResult]::Error, "Could not fetch the list of inactive repositories in the project.");
        }
        return $controlResult
    }

}