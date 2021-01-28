
Class Resolver : AzSKRoot {

    # Indicates to fetch all resource groups
	Resolver([string] $organizationId):Base($organizationId)
    {
        
    }
    Resolver([string] $organizationId,  [System.Security.SecureString] $PATToken):Base($organizationId, $PATToken)
    {
        
    }
}