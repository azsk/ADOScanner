using namespace System.Management.Automation
Set-StrictMode -Version Latest

class OrganizationInfo: CommandBase {

    hidden [string] $organizationName;
    hidden [PSObject[]] $projects = @();

    OrganizationInfo([string] $organizationName, [PSObject[]] $projects, [InvocationInfo] $invocationContext):
    Base($organizationName, $invocationContext) {
        $this.organizationName = $organizationName;
        $this.projects += $projects;
    }


    [MessageData[]] GetResourceInventory() {
        # fetching the resource count for the given org and project
        [MessageData[]] $returnMsgs = @();
        try {
            $settings = [ConfigurationManager]::GetAzSKSettings()
            $this.PublishCustomMessage("Inventory details will be fetched within the scope of current identity. `n", [MessageType]::Info)
            $returnMsgs += [MessageData]::new("Inventory details will be fetched based on permissions assigned to current identity. `n")
            $this.PublishCustomMessage("Resource inventory for the organization [$($this.organizationName)]`n")
            $returnMsgs += [MessageData]::new("Fetching resource inventory for the organization: $($this.organizationName)`n")
            $returnMsgs += [MessageData]::new("Resource inventory for the organization: $($this.organizationName)`n")
            $projectsList = $this.projects | Select-Object @{Name="Projects"; Expression = {$_.name}}
            $projectsList = $projectsList | Out-String
            $this.PublishCustomMessage("Fetching resource inventory for below projects: $($projectsList)`n")
            $returnMsgs += [MessageData]::new("Fetching resource inventory for below projects: $($projectsList)`n")
            $outputFolder = ([WriteFolderPath]::GetInstance().FolderPath)
            $inventorySummary = @()
            $outputPath = $outputFolder + "\$($this.organizationName)" + "_Inventory.csv";
            foreach ($project in $this.projects) {
                $projectId = $project.id
                $projectName = $project.name
                [Hashtable] $resourceInventoryData = @{
                    Repositories       =  0;
                    TestPlans          =  0;
                    Build              =  0;
                    Release            =  0;
                    TaskGroups         =  0;
                    AgentPools         =  0;
                    VariableGroups     =  0;
                    ServiceConnections =  0;
                };
                [InventoryHelper]::GetResourceCount($this.organizationName, $projectName, $projectId, $resourceInventoryData);
                # Change the hashtable headers to resource type and resource count
                $tempObj = [PSCustomObject] @{
                    ProjectName = $projectName
                    Build = $resourceInventoryData['Build']
                    Release = $resourceInventoryData['Release']
                    ServiceConnections = $resourceInventoryData['ServiceConnections']
                    AgentPools = $resourceInventoryData['AgentPools']
                    VariableGroups = $resourceInventoryData['VariableGroups']
                    TaskGroups = $resourceInventoryData['TaskGroups']
                    Repositories = $resourceInventoryData['Repositories']
                    TestPlans = $resourceInventoryData['TestPlans'] 
                }
                $tempObj | Add-Member -Name 'ProjectName' -Type NoteProperty -Value $projectName
                $inventorySummary += $tempObj
                $resourceInventoryDataWithNewHeaders = $resourceInventoryData.keys  | Select @{l = 'ResourceType'; e = { $_ } }, @{l = 'Count'; e = { if ($resourceInventoryData.$_ -eq -1 ) { 0 } else { $resourceInventoryData.$_ } } }
                $this.PublishCustomMessage("$([Constants]::DoubleDashLine)`nResource inventory for the project [$($projectName)] `n$([Constants]::DoubleDashLine)`n")
                $returnMsgs += [MessageData]::new("$([Constants]::DoubleDashLine)`nResource inventory for the project [$($projectName)] `n$([Constants]::DoubleDashLine)`n")
                $formattedResourceInventoryData = ($resourceInventoryDataWithNewHeaders | Out-String)
                $this.PublishCustomMessage($formattedResourceInventoryData);
                #publish to primary workspace
                if(-not [string]::IsNullOrWhiteSpace($settings.LAWSId) -and [LogAnalyticsHelper]::IsLAWSSettingValid -ne -1)
                {
                    $laInventoryData = @()
                    $resourceInventoryData["Project"] = $projectName
                    $resourceInventoryData["OrganizationName"] = $this.organizationName
                    $laInventoryData += $resourceInventoryData
                    $body = $laInventoryData | ConvertTo-Json
                    $lawsBodyByteArray = ([System.Text.Encoding]::UTF8.GetBytes($body))
                    [LogAnalyticsHelper]::PostLAWSData($settings.LAWSId, $settings.LAWSSharedKey, $lawsBodyByteArray, 'AzSK_ADO_RESOURCE_INVENTORY', 'LAWS') 
                }
                $returnMsgs += $formattedResourceInventoryData;
            }
            if ($inventorySummary.Count -gt 0) {
                $inventorySummary | Export-Csv -NoTypeInformation -Path $outputPath
            }
        }
        catch {
            $this.PublishCustomMessage("Could not fetch the resource inventory of the organization.", [MessageType]::Error)
            $returnMsgs += [MessageData]::new("Could not fetch the resource inventory of the organization.")
            # [EventBase]::PublishGenericException($_);
        }
        return $returnMsgs
    }
}
