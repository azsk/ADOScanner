Set-StrictMode -Version Latest 

class AzSKSettings
{
    #AZSKSETTINGS
    #AzSK Settings/Config (available to each module) #Take from AzSKSettings file

    [PSObject] $Endpoints;
    [string] $AzSKSettingsFilePath = "$Env:LOCALAPPDATA\\Microsoft\\#AzSKModule#\\AzSKSettings.json" #AzSKSettings.json path (Location of AzSK Setting?)
	[string] $LAResourceGroup = [string]::Empty
	[string] $LAViewName = "TestHarness_Custom_View"
    
    AzSKSettings([PSObject] $invocationContext)
    {
        $this.AzSKSettingsFilePath = $this.AzSKSettingsFilePath -replace '#AzSKModule#',$invocationContext.BoundParameters["AzSKModule"];
        #[ConfigurationHelper]::SetAzSKSettingsJsonParameter($invocationContext.BoundParameters["AzSKModule"],$invocationContext.BoundParameters["MandatoryTestSettings"],$invocationContext.BoundParameters["OrgPolicy"])
        $this.Endpoints = $this.GetAzSKSettingsEndpoints()
    }

    [PSObject] GetAzSKSettingsEndpoints()
    {        
        if(Test-Path -Path $this.AzSKSettingsFilePath)
        {
            $tempendpoints = (Get-Content -Path $this.AzSKSettingsFilePath) | ConvertFrom-Json
            return $tempendpoints
        }
        else {
            throw "Unable to create AzSKSettings object. Please check $($this.AzSKSettingsFilePath) file exists"
        }

        return $null        
    }
}