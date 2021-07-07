Set-StrictMode -Version Latest

class CommonSVTResourceResolver {
    [string] $ResourceType = "";
    [ResourceTypeName] $ResourceTypeName = [ResourceTypeName]::All;

    [string] $organizationName
    [string] $organizationId
    [string] $projectId

    CommonSVTResourceResolver($organizationName, $organizationId, $projectId) {
        $this.organizationName = $organizationName;
        $this.organizationId = $organizationId;
        $this.projectId = $projectId;
    }

    [SVTResource[]] LoadResourcesForScan($projectName, $repoNames, $secureFileNames, $feedNames, $environmentNames, $ResourceTypeName, $MaxObjectsToScan) {
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
                    $resourceId = "organization/{0}/project/{1}/repository/{2}" -f $this.organizationId, $this.projectId, $repo.id;
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
                    $resourceId = "organization/{0}/project/{1}/securefile/{2}" -f $this.organizationId, $this.projectId, $securefile.Id;
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
            if ($feedObjList.count -gt 0 -and [Helpers]::CheckMember($feedObjList[0], "Id")) {
                $maxObjScan = $MaxObjectsToScan
                foreach ($feed in $feedObjList) {
                    $resourceId = "organization/{0}/project/{1}/feed/{2}" -f $this.organizationId, $this.projectId, $feed.id;
                    $SVTResources += $this.AddSVTResource($feed.name, $projectName, "ADO.Feed", $resourceId, $feed, $feed.Url);
                    if (--$maxObjScan -eq 0) { break; }
                }

                $feedObjList = $null;
            }
        }

        #Get $EnvironmentNames
        if ($environmentNames.Count -gt 0 -or $ResourceTypeName -eq [ResourceTypeName]::Environment) {
            #Write-Host "Getting feed configurations..." -ForegroundColor cyan
            if ($ResourceTypeName -eq [ResourceTypeName]::Environment -and $environmentNames.Count -eq 0) {
                $environmentNames += "*"
            }

            $environmentObjList = @();
            $environmentObjList += $this.FetchEnvironments($projectName, $environmentNames, $MaxObjectsToScan);
            if ($environmentObjList.count -gt 0 -and [Helpers]::CheckMember($environmentObjList[0], "Id")) {
                $maxObjScan = $MaxObjectsToScan
                foreach ($environment in $environmentObjList) {
                    $resourceId = "organization/{0}/project/{1}/environment/{2}" -f $this.organizationId, $this.projectId, $environment.id;
                    $resourceLink = "https://dev.azure.com/{0}/{1}/_environments/{2}?view=resources" -f $this.organizationName, $environment.project.id, $environment.id;
                    $SVTResources += $this.AddSVTResource($environment.name, $projectName, "ADO.Environment", $resourceId, $environment, $resourceLink);
                    if (--$maxObjScan -eq 0) { break; }
                }

                $environmentObjList = $null;
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

    hidden [PSObject] FetchEnvironments($projectName, $environmentNames, $MaxObjectsToScan) {
        try {
            if ($MaxObjectsToScan -eq 0) {
                $topNQueryString = '&$top=10000'
            }
            else {
                $topNQueryString = '&$top={0}' -f $MaxObjectsToScan
            }
            # Here we are fetching all the environments in the project.
            $environmentDefnURL = ("https://dev.azure.com/{0}/{1}/_apis/distributedtask/environments?api-version=6.0-preview.1" + $topNQueryString) -f $this.organizationName, $projectName;
            $environmentDefnsObj = [WebRequestHelper]::InvokeGetWebRequest($environmentDefnURL);

            if ($environmentNames -ne "*") {
                $environmentDefnsObj = $environmentDefnsObj | Where-Object { $environmentNames -contains $_.name }
            }

            return $environmentDefnsObj;
        }
        catch {
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
