
Class Resolver : AzSKRoot {

    # Indicates to fetch all resource groups
	Resolver([string] $organizationName):Base($organizationName)
    {
        
    }
    Resolver([string] $organizationName,  [System.Security.SecureString] $PATToken):Base($organizationName, $PATToken)
    {
        
    }
}