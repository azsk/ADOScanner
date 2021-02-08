Set-StrictMode -Version Latest 

class OrganizationMapping
{    
	[string] $JsonFileName
    [string] $ClassName
    [string] $FixClassName = "";
    [string] $FixFileName = "";
}

class ResourceTypeMapping: OrganizationMapping
{
    [string] $ResourceTypeName
    [string] $ResourceType
}

#Class used to create SVTResources list inside resolver
class SVTResource
{
	[string] $ResourceId = "";
	[string] $ResourceGroupName = "";
    [string] $ResourceName = ""; 
    [string] $Location = "";
    [string] $ResourceType = "";
    hidden [ResourceTypeMapping] $ResourceTypeMapping = $null;
    [PSObject] $ResourceDetails
}
