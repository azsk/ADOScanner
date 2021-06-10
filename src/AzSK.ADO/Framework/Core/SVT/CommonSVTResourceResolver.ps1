Set-StrictMode -Version Latest

class CommonSVTResourceResolver {
    [string] $ResourceType = "";
    [ResourceTypeName] $ResourceTypeName = [ResourceTypeName]::All;

    [string] $organizationName

    CommonSVTResourceResolver($organizationName) {
        $this.organizationName = $organizationName;
    }

    [SVTResource[]] LoadResourcesForScan($projectName, $repoNames, $secureFileNames, $feedNames, $ResourceTypeName, $MaxObjectsToScan) {
        #Get resources    
        [SVTResource[]] $SVTResources = @();
        if ($repoNames.Count -gt 0 -or $ResourceTypeName -eq [ResourceTypeName]::Repository) {
            #Write-Host "Getting repository configurations..." -ForegroundColor cyan
            if ($ResourceTypeName -eq [ResourceTypeName]::Repository -and $repoNames.Count -eq 0) {
                $repoNames += "*";
            }
            $repoObjList = @();
            $repoObjList += $this.FetchRepositories($projectName, $repoNames);
            if ($repoObjList.count -gt 0 -and [Helpers]::CheckMember($repoObjList[0], "Id")) {
                $maxObjScan = $MaxObjectsToScan
                foreach ($repo in $repoObjList) {
                    $resourceId = "organization/{0}/project/{1}/repository/{2}" -f $this.organizationName, $projectName, $repo.id;
                    $SVTResources += $this.AddSVTResource($repo.name, $projectName, "ADO.Repository", $resourceId, $repo, $repo.webUrl);
                    if (--$maxObjScan -eq 0) { break; }
                }

                $repoObjList = $null;
            }
        }
        
        ##Get SecureFiles
        if ($secureFileNames.Count -gt 0 -or $ResourceTypeName -eq [ResourceTypeName]::SecureFile) {
            if ($ResourceTypeName -eq [ResourceTypeName]::SecureFile -and $secureFileNames.Count -eq 0) {
                $secureFileNames += "*"
            }
            # Here we are fetching all the secure files in the project.
            $secureFileObjList = @();
            $secureFileObjList += $this.FetchSecureFiles($projectName, $secureFileNames);
            if ($secureFileObjList.count -gt 0 -and [Helpers]::CheckMember($secureFileObjList[0], "Id")) {
                $maxObjScan = $MaxObjectsToScan
                foreach ($securefile in $secureFileObjList) {
                    $resourceId = "organization/{0}/project/{1}/securefile/{2}" -f $this.organizationName, $projectName, $securefile.Id;
                    $secureFileLink = "https://dev.azure.com/{0}/{1}/_library?itemType=SecureFiles&view=SecureFileView&secureFileId={2}&path={3}" -f $this.organizationName, $projectName, $securefile.Id, $securefile.Name;
                    $SVTResources += $this.AddSVTResource($securefile.Name, $projectName, "ADO.SecureFile", $resourceId, $securefile, $secureFileLink);
                    if (--$maxObjScan -eq 0) { break; }
                }

                $secureFileObjList = $null;
            }
        }

        #Get feeds
        if ($feedNames.Count -gt 0 -or $ResourceTypeName -eq [ResourceTypeName]::Feed) {
            #Write-Host "Getting feed configurations..." -ForegroundColor cyan
            if ($ResourceTypeName -eq [ResourceTypeName]::Feed -and $feedNames.Count -eq 0) {
                $feedNames += "*"
            }

            $feedObjList = @();
            $feedObjList += $this.FetchFeeds($projectName, $feedNames);
            if ($feedObjList.count -gt 0) {
                $maxObjScan = $MaxObjectsToScan
                foreach ($feed in $feedObjList -and [Helpers]::CheckMember($feedObjList[0], "Id")) {
                    if ([Helpers]::CheckMember($feed, "id")) {
                        $resourceId = "organization/{0}/project/{1}/feed/{2}" -f $this.organizationName, $projectName, $feed.id;
                        $SVTResources += $this.AddSVTResource($feed.name, $projectName, "ADO.Feed", $resourceId, $feed, $feed.Url);
                        if (--$maxObjScan -eq 0) { break; }
                    }
                }

                $feedObjList = $null;
            }
        }

        return $SVTResources;
    }

    hidden [PSObject] FetchRepositories($projectName, $repoNames) {
        try {
            # Here we are fetching all the repositories in the project and then filtering out.
            $repoDefnURL = "";
            $repoDefnURL = "https://dev.azure.com/$($this.organizationName)/$projectName/_apis/git/repositories?api-version=6.1-preview.1"
            $repoDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($repoDefnURL);
            if ($repoNames -ne "*") {
                $repoDefnsObj = $repoDefnsObj | Where-Object { $repoNames -contains $_.name }
            }

            return $repoDefnsObj;
        }
        catch {
            return $null;
        }
    }

    hidden [PSObject] FetchFeeds($projectName, $feedNames) {
        try {
            # Here we are fetching all the feeds in the project.
            $feedDefnURL = 'https://feeds.dev.azure.com/{0}/{1}/_apis/packaging/feeds?api-version=6.0-preview.1' -f $this.organizationName, $projectName
            $feedDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($feedDefnURL);
            if ($feedNames -ne "*") {
                $feedDefnsObj = $feedDefnsObj | Where-Object { $feedNames -contains $_.name }
            }

            return $feedDefnsObj;
        }
        catch {
            return $null;
        }
    }

    hidden [PSObject] FetchSecureFiles($projectName, $secureFileNames)
    {
        $secureFileDefnURL = "https://dev.azure.com/$($this.organizationName)/$projectName/_apis/distributedtask/securefiles?api-version=6.1-preview.1"
        try {
            $secureFileDefnObj = [WebRequestHelper]::InvokeGetWebRequest($secureFileDefnURL);
            if ($secureFileNames -ne "*") {
                $secureFileDefnObj = $secureFileDefnObj | Where-Object { $secureFileNames -contains $_.name }
            }
            return $secureFileDefnObj;
        }
        catch 
        {
            return $null;
        }
    }

    [SVTResource] AddSVTResource([string] $name, [string] $resourceGroupName, [string] $resourceType, [string] $resourceId, [PSObject] $resourceDetailsObj, $resourceLink)
    {
        $svtResource = [SVTResource]::new();
        $svtResource.ResourceName = $name;
        if ($resourceGroupName) {
            $svtResource.ResourceGroupName = $resourceGroupName;
        }
        $svtResource.ResourceType = $resourceType;
        $svtResource.ResourceId = $resourceId;
        $svtResource.ResourceTypeMapping = ([SVTMapping]::AzSKADOResourceMapping | Where-Object { $_.ResourceType -eq $resourceType } | Select-Object -First 1)

        if ($resourceDetailsObj) {
            $svtResource.ResourceDetails = $resourceDetailsObj;
            $svtResource.ResourceDetails | Add-Member -Name 'ResourceLink' -Type NoteProperty -Value $resourceLink;
        }
        else {
            $svtResource.ResourceDetails = New-Object -TypeName psobject -Property @{ ResourceLink = $resourceLink }
        }                         
                                        
        return $svtResource;
    }
}
