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
            $this.PublishCustomMessage("Fetching resource inventory details for the organization [$($this.organizationName)]`n")
            $returnMsgs += [MessageData]::new("Fetching resource inventory details for the organization: $($this.organizationName)`n")
            foreach ($project in $this.projects) {
                $projectId = $project.id
                $projectName = $project.name
                [Hashtable] $resourceInventoryData = @{
                    Repositories       = 0;
                    TestPlans          = 0;
                    Build              = 0;
                    Release            = 0;
                    TaskGroups         = 0;
                    AgentPools         = 0;
                    VariableGroups     = 0;
                    ServiceConnections = 0;
                };
                [InventoryHelper]::GetResourceCount($this.organizationName, $projectName, $projectId, $resourceInventoryData);
                $this.PublishCustomMessage("$([Constants]::DoubleDashLine)`nResource inventory details for the project [$($projectName)] `n$([Constants]::DoubleDashLine)`n")
                $returnMsgs += [MessageData]::new("$([Constants]::DoubleDashLine)`nResource inventory details for the project [$($projectName)] `n$([Constants]::DoubleDashLine)`n")
                $formattedResourceInventoryData = ($resourceInventoryData | Out-String)
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