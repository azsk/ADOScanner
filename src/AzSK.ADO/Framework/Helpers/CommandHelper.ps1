﻿using namespace System.Management.Automation
Set-StrictMode -Version Latest  
class CommandHelper
{
    static [CommandDetails[]] $Mapping = @(
		# Services Security Status
		[CommandDetails]@{
            Verb = "Get";
            Noun = "AzSKADOSecurityStatus";
            ShortName = "gads";
			IsLatestRequired = $false;
		},
		[CommandDetails]@{
            Verb = "Set";
            Noun = "AzSKADOMonitoringSettings";
            ShortName = "sms";
		},
		[CommandDetails]@{
            Verb = "Get";
            Noun = "AzSKADOInfo";
            ShortName = "gadi";
			IsLatestRequired = $false;
        },
		[CommandDetails]@{
            Verb = "Install";
            Noun = "AzSKADOMonitoringSolution";
            ShortName = "iadm";
			IsLatestRequired = $false;
		},
		[CommandDetails]@{
            Verb = "Clear";
            Noun = "AzSKADOSessionState";
            ShortName = "css";
			IsLatestRequired = $false;
		},
		[CommandDetails]@{
            Verb = "Install";
            Noun = "AzSKADOContinuousAssurance";
            ShortName = "ica";
			IsLatestRequired = $false;
        },
		[CommandDetails]@{
            Verb = "Update";
            Noun = "AzSKADOContinuousAssurance";
            ShortName = "uca";
			IsLatestRequired = $false;
        },
		[CommandDetails]@{
            Verb = "Get";
            Noun = "AzSKADOContinuousAssurance";
            ShortName = "gca";
			IsLatestRequired = $false;
        },
        [CommandDetails]@{
            Verb = "Get";
            Noun = "AzSKADOServiceMapping";
            ShortName = "gsm";
			IsLatestRequired = $false;
        },
		[CommandDetails]@{
            Verb = "Get";
            Noun = "AzSKADOUserPermissions";
            ShortName = "gup";
			IsLatestRequired = $false;
		}
    );

	static BeginCommand([InvocationInfo] $invocationContext)
	{
		# Validate Command Prerequisites like Az multiple version load issue
		[CommandHelper]::CheckCommandPrerequisites($invocationContext);
		[CommandHelper]::SetAzSKModuleName($invocationContext);
        [CommandHelper]::SetCurrentAzSKModuleVersion($invocationContext);
        [CommandHelper]::SetAzSKEnvironmentMode($invocationContext);
	}

	static CheckCommandPrerequisites([InvocationInfo] $invocationContext)
	{
		# Validate required module version dependency
	    try
		{			
			#Loop through all required modules list
			$invocationContext.MyCommand.Module.RequiredModules | ForEach-Object {				
				$requiredModule = $_
				$moduleList = Get-Module $requiredModule.Name 
				#Get list of other than required version is loaded into session
				$otherThanRequiredModule = @();
				$otherThanRequiredModule += $moduleList | Where-Object { $_.Version -ne $requiredModule.Version}
				if($otherThanRequiredModule.Count -gt 0 )
				{	 
					#Display warning   
					$loadedVersions = @();
					$moduleList | ForEach-Object {
						$loadedVersions += $_.Version.ToString()
					};
					Write-Host "WARNING: Found multiple versions of Azure PowerShell ($($requiredModule.Name)) modules loaded in the session. ($($requiredModule.Name) versions found: $([string]::Join(", ", $loadedVersions)))" -ForegroundColor Yellow
                    Write-Host "WARNING: This will lead to issues when running AzSK.ADO cmdlets." -ForegroundColor Yellow
                    Write-Host 'Recommendation: Please start a fresh PowerShell session and run "Import-Module AzSK.ADO" first to avoid getting into this situation.' -ForegroundColor Yellow					
				}
				else
				{
					# Continue execution without any error or warning
					Write-Debug ($requiredModule.Name + " module version dependency validation successful")
				}			
			};		
		}
		catch
		{
			Write-Debug "Not able to validate version dependency $_"
		}
		
	}

	static [void] SetAzSKModuleName([InvocationInfo] $invocationContext)
	{
		if($invocationContext)
		{
			[Constants]::SetAzSKModuleName($invocationContext.MyCommand.Module.Name);
		}
	}
	static [void] SetCurrentAzSKModuleVersion([InvocationInfo] $invocationContext)
	{
		if($invocationContext)
		{
			[Constants]::SetAzSKCurrentModuleVersion($invocationContext.MyCommand.Version);
		}
    }
    
    static [void] SetAzSKEnvironmentMode([InvocationInfo] $invocationContext)
	{
		if($invocationContext)
		{
			[Constants]::SetAzSKCurrentEnvironmentMode($invocationContext.MyCommand.Version);
		}
	}
}
