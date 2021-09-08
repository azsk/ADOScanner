Set-StrictMode -Version Latest 
class ADOResourceInfo
{
    [PSObject[]] $AllProjectsInOrg = @();
    [string] $Org;
    [string] $Pat;

    ADOResourceInfo([String] $Org, [String] $Pat)
	{	
        $this.InitResourceInfo($Org, $Pat)
    }

    [void] InitResourceInfo($Org, $Pat)
    {
        $this.Org = $Org 
        $this.Pat = $Pat
        $this.AllProjectsInOrg = @()
        <#if ($this.AllProjectsInOrg.Count -eq 0)
        {
            throw "Could not find projects! Invalid org/pat token?"
        }
        #>
    }

    ############## Fetch all the projects in a given org using PAT token ##############
    [PSCustomObject[]] GetProjectsInOrg($Org, $Pat) {
        Write-Host "Initialize authentication context" -ForegroundColor Yellow
        $token =[System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(":$($Pat)"))
    
        $header = @{authorization = "Basic $token"}
        $Uri="https://dev.azure.com/$Org/_apis/projects?api-version=4&top=2"
        $ProjSets=Invoke-WebRequest -Uri $Uri -Method Get -ContentType "application/json" -Headers $header
        $ProjectSet=$projsets.content | ConvertFrom-Json

        $projects=$ProjectSet.value

        return @($projects)

        #### Pagination to be implemented if needed #####
        <# Pagination

        while ($ContinuationToken -ne $null)
        {
        $Uri="https://dev.azure.com/$Org/_apis/projects?continuationToken==$token&api-version=5.1"
        $ProjSets=Invoke-WebRequest -Uri $Uri -Method Get -ContentType "application/json" -Headers $header
        $ProjectSet=$ProjSets.content | ConvertFrom-Json
        $projects += $ProjectSet.value.name
        $global:org_project_names = $projects
        write-host "Total number of projects = $($projects.count)"
       }
       #>
    }

    
    [PSCustomObject[]] GetRandomADOProjects($count) {
        return @($this.AllProjectsInOrg | Get-Random -Count $count)
    }
}