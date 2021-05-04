using namespace System.Management.Automation
Set-StrictMode -Version Latest

class OrganizationInfo: CommandBase {

    hidden [string] $organizationName;
    hidden [PSObject[]] $projects = @();

    OrganizationInfo([string] $organizationName, [PSObject[]] $projects, [InvocationInfo] $invocationContext):
    Base($organizationName, $invocationContext) {
        $this.organizationName = $organizationName;
        $this.projects = $projects;
    }


    [MessageData[]] GetResourceInventory() {
        # fetching the resource count for the given org and project
        [MessageData[]] $returnMsgs = @();
        try {
            $this.PublishCustomMessage("Fetching the resource inventory details for the organization: $($this.organizationName)`n")
            $returnMsgs += [MessageData]::new("Fetching the resource inventory details for the organization: $($this.organizationName)`n")
            $this.PublishCustomMessage("Total projects in the organization: $($this.projects.count)`n")
            $returnMsgs += [MessageData]::new("Total projects in the organization: $($this.projects.count)`n")
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
                [CommonHelper]::GetResourceCount($this.organizationName, $projectName, $projectId, $resourceInventoryData);
                $this.PublishCustomMessage("$([Constants]::DoubleDashLine)`nResource inventory details for the project: $($projectName) `n$([Constants]::DoubleDashLine)`n")
                $returnMsgs += [MessageData]::new("$([Constants]::DoubleDashLine)`nResource inventory details for the project: $($projectName) `n$([Constants]::DoubleDashLine)`n")
                $formattedResourceInventoryData = ($resourceInventoryData | Out-String)
                $this.PublishCustomMessage($formattedResourceInventoryData);
                $returnMsgs += $formattedResourceInventoryData;
            }
        }
        catch {
            $this.PublishCustomMessage("Could not fetch the resource count in the organization.", [MessageType]::Error)
            $returnMsgs += [MessageData]::new("Could not fetch the resource count in the organization.")
            # [EventBase]::PublishGenericException($_);
        }
        return $returnMsgs
    }
}