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
            $this.PublishCustomMessage("Inventory details will be fetched within the scope of current identity. `n", [MessageType]::Info)
            $returnMsgs += [MessageData]::new("Inventory details will be fetched based on permissions assigned to current identity. `n")
            $this.PublishCustomMessage("Resource inventory for the organization [$($this.organizationName)]`n")
            $returnMsgs += [MessageData]::new("Fetching resource inventory for the organization: $($this.organizationName)`n")
            $returnMsgs += [MessageData]::new("Resource inventory for the organization: $($this.organizationName)`n")
            $projectsList = $this.projects | Select-Object @{Name="Projects"; Expression = {$_.name}}
            $projectsList = $projectsList | Out-String
            $this.PublishCustomMessage("Fetching resource inventory for below projects : $($projectsList)`n")
            $returnMsgs += [MessageData]::new("Fetching resource inventory for below projects: $($projectsList)`n")
            foreach ($project in $this.projects) {
                $projectId = $project.id
                $projectName = $project.name
                [Hashtable] $resourceInventoryData = @{
                    Repositories       = -1;
                    TestPlans          = -1;
                    Build              = -1;
                    Release            = -1;
                    TaskGroups         = -1;
                    AgentPools         = -1;
                    VariableGroups     = -1;
                    ServiceConnections = -1;
                };
                [InventoryHelper]::GetResourceCount($this.organizationName, $projectName, $projectId, $resourceInventoryData);
                # Change the hashtable headers to resource type and resource count
                $resourceInventoryDataWithNewHeaders = $resourceInventoryData.keys  | Select @{l = 'Resource type'; e = { $_ } }, @{l = 'Count'; e = { $resourceInventoryData.$_ } }
                $this.PublishCustomMessage("$([Constants]::DoubleDashLine)`nResource inventory for the project [$($projectName)] `n$([Constants]::DoubleDashLine)`n")
                $returnMsgs += [MessageData]::new("$([Constants]::DoubleDashLine)`nResource inventory for the project [$($projectName)] `n$([Constants]::DoubleDashLine)`n")
                $formattedResourceInventoryData = ($resourceInventoryDataWithNewHeaders | Out-String)
                $this.PublishCustomMessage($formattedResourceInventoryData);
                $returnMsgs += $formattedResourceInventoryData;
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