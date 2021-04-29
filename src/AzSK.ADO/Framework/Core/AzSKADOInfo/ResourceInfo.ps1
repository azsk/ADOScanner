using namespace System.Management.Automation
Set-StrictMode -Version Latest

class ResourceInfo: CommandBase {

    hidden [string] $organizationName;
    hidden [string] $projectName;
    hidden [string] $projectId;
    hidden [string] $resourceType;

    ResourceInfo([string] $organizationName, [string] $ProjectName, [string] $projectId, [InvocationInfo] $invocationContext):
    Base($organizationName, $invocationContext) {
        $this.organizationName = $organizationName;
        $this.projectName = $ProjectName;
        $this.projectId = $projectId;
    }

    [MessageData[]] GetResourceInventory() {
        # fetching the resource count for the given org and project
        [MessageData[]] $returnMsgs = @();
        try {
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
            [CommonHelper]::GetResourceCount($this.organizationName, $this.ProjectName, $this.projectId, $resourceInventoryData);
            $this.PublishCustomMessage("$([Constants]::DoubleDashLine)`nResource inventory details for the project $($this.ProjectName) `n$([Constants]::DoubleDashLine)`n")
            $returnMsgs += [MessageData]::new("$([Constants]::DoubleDashLine)`nResource inventory details for the project $($this.ProjectName) `n$([Constants]::DoubleDashLine)")
            $formattedResourceInventoryData = ($resourceInventoryData | Out-String)
            $this.PublishCustomMessage($formattedResourceInventoryData);
            $returnMsgs += $formattedResourceInventoryData;
        }
        catch {
            $this.PublishCustomMessage("Could not fetch the resource count in the organization.", [MessageType]::Error)
            # [EventBase]::PublishGenericException($_);
        }
        return $returnMsgs
    }
}