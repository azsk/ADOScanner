﻿Set-StrictMode -Version Latest 
class WriteFolderPath: FileOutputBase
{
    hidden static [WriteFolderPath] $Instance = $null;
    static [WriteFolderPath] GetInstance()
    {
        if ($null -eq  [WriteFolderPath]::Instance)
        {
            [WriteFolderPath]::Instance = [WriteFolderPath]::new();
        }

        return [WriteFolderPath]::Instance
    }

    [void] RegisterEvents()
    {        
        $this.UnregisterEvents();

        $this.RegisterEvent([AzSKRootEvent]::GenerateRunIdentifier, {
            $currentInstance = [WriteFolderPath]::GetInstance();
            try 
            {
                $currentInstance.SetRunIdentifier([AzSKRootEventArgument] ($Event.SourceArgs | Select-Object -First 1));                         
            }
            catch 
            {
                $currentInstance.PublishException($_);
            }
        });

		$this.RegisterEvent([SVTEvent]::CommandStarted, {
            $currentInstance = [WriteFolderPath]::GetInstance();
            try 
            {
				$currentInstance.CommandStartedAction($Event.SourceArgs.OrganizationContext);
            }
            catch 
            {
                $currentInstance.PublishException($_);
            }
        });

		$this.RegisterEvent([AzSKRootEvent]::CommandStarted, {
            $currentInstance = [WriteFolderPath]::GetInstance();
            try 
            {
				$currentInstance.CommandStartedAction($Event.SourceArgs.OrganizationContext);
            }
            catch 
            {
                $currentInstance.PublishException($_);
            }
        });
    }

	[void] CommandStartedAction([OrganizationContext] $context)
	{
		$this.SetFolderPath($context);
		Copy-Item (Join-Path $PSScriptRoot "README.txt") $this.FolderPath
	}

}
