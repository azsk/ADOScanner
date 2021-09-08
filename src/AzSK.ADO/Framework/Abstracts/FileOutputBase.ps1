Set-StrictMode -Version Latest 
class FileOutputBase: ListenerBase
{
    static [string] $ETCFolderPath = "Etc";
    static [string] $CSVFilePath = $null;
    [string] $FilePath = "";
    [string] $FolderPath = "";
    #[string] $BasePath = "";
    hidden [string[]] $BasePaths = @();
    
    FileOutputBase()
    {   
        [Helpers]::AbstractClass($this, [FileOutputBase]);
    }     

	hidden [void] AddBasePath([string] $path)
    {
		if(-not [string]::IsNullOrWhiteSpace($path))
		{
			$path = $global:ExecutionContext.InvokeCommand.ExpandString($path);
			if(Test-Path -Path $path)
			{
				$this.BasePaths += $path;
			}
		}
	}

	[void] SetRunIdentifier([AzSKRootEventArgument] $arguments)
    {
		([ListenerBase]$this).SetRunIdentifier($arguments);

		$this.AddBasePath([ConfigurationManager]::GetAzSKSettings().OutputFolderPath);
		$this.AddBasePath([ConfigurationManager]::GetAzSKConfigData().OutputFolderPath);
		$this.AddBasePath([Constants]::AzSKLogFolderPath);
	}

	hidden [string] CalculateFolderPath([OrganizationContext] $context, [string] $subFolderPath, [int] $pathIndex)
    {
		$outputPath = "";
		if($context -and (-not [string]::IsNullOrWhiteSpace($context.OrganizationName)))
		{
			$isDefaultPath = $false;
			if($pathIndex -lt $this.BasePaths.Count)
			{
				$basePath = $this.BasePaths.Item($pathIndex);
			}
			else
			{
				$isDefaultPath = $true;
				$basePath = [Constants]::AzSKLogFolderPath;
			}

			$outputPath = Join-Path $basePath ($([Constants]::AzSKModuleName)+"Logs")  ;

			$sanitizedPath = [Helpers]::SanitizeFolderName($context.OrganizationName);
			if ([string]::IsNullOrEmpty($sanitizedPath)) {
				$sanitizedPath = $context.OrganizationName;
			}

			$runPath = $this.RunIdentifier;
			$commandMetadata = $this.GetCommandMetadata();

			#if this is a batch scan, we have to add results to the batch scan folder
			$batchScanSanitizedPath = $null
			if($commandMetaData.PSObject.Properties.Name.Contains("BatchScan")){
				$batchScanSanitizedPath = [Helpers]::SanitizeFolderName($commandMetadata.BatchScan)
			}
			

			if($commandMetadata)
			{
				$runPath += "_" + $commandMetadata.ShortName;
			}

			if ([string]::IsNullOrEmpty($sanitizedPath)) {
				$outputPath = Join-Path $outputPath -ChildPath "Default" |Join-Path -ChildPath $runPath ;           
			}
			else {
				if(![string]::IsNullOrEmpty($batchScansanitizedPath)) {
					$outputPath = Join-Path $outputPath -ChildPath ([Constants]::ParentFolder + $sanitizedPath) | Join-Path -ChildPath "BatchScan" | Join-Path -ChildPath $batchScanSanitizedPath |Join-Path -ChildPath $runPath ;
				}
				else {
					if ($this.invocationContext.BoundParameters["ServiceIds"]) {
						$runPath += "_SVCIdBased";
					}
					if ($this.invocationContext.BoundParameters["UsePartialCommit"]) {
						$runPath += "_UPC";
					}
					if ($this.invocationContext.BoundParameters["UseBaselineControls"]) {
						$runPath += "_UBC";
					}
					if ($this.invocationContext.BoundParameters["ResourceTypeName"]) {
						$runPath += "_" + $this.invocationContext.BoundParameters["ResourceTypeName"];
					}
					if ($this.invocationContext.BoundParameters["FilterTags"]) {
						$runPath += "_FT_"+ $this.invocationContext.BoundParameters["FilterTags"];
					}
					#if ($this.invocationContext.BoundParameters["MaxObj"]) {
					#	$runPath += "_" +"MO"+ $this.invocationContext.BoundParameters["MaxObj"];
					#}FilterTags
					
					$outputPath = Join-Path $outputPath -ChildPath ([Constants]::ParentFolder + $sanitizedPath) |Join-Path -ChildPath $runPath ;
					
				}
				            
			}

			if (-not [string]::IsNullOrEmpty($subFolderPath)) {
				$sanitizedPath = [Helpers]::SanitizeFolderName($subFolderPath);
				if (-not [string]::IsNullOrEmpty($sanitizedPath)) {
					$outputPath = Join-Path $outputPath $sanitizedPath ;          
				}   
			}

			if(-not (Test-Path $outputPath))
			{
				try
				{
					New-Item -Path $outputPath -ItemType Directory -ErrorAction Stop | Out-Null
				}
				catch
				{
					$outputPath = "";
					if(-not $isDefaultPath)
					{
						$outputPath = $this.CalculateFolderPath($context, $subFolderPath, $pathIndex + 1);
					}
				}
			}
		}
		return $outputPath;
	}

	[string] CalculateFolderPath([OrganizationContext] $context, [string] $subFolderPath)
	{
		return $this.CalculateFolderPath($context, $subFolderPath, 0);
	}

	[string] CalculateFolderPath([OrganizationContext] $context)
	{
		return $this.CalculateFolderPath($context, "");
	}

	[void] SetFolderPath([OrganizationContext] $context)
    {
		$this.SetFolderPath($context, "");
	}

    [void] SetFolderPath([OrganizationContext] $context, [string] $subFolderPath)
    {
        $this.FolderPath = $this.CalculateFolderPath($context, $subFolderPath);
    }

	[string] CalculateFilePath([OrganizationContext] $context, [string] $fileName)
	{
		return $this.CalculateFilePath($context, "", $fileName);
	}

	[string] CalculateFilePath([OrganizationContext] $context, [string] $subFolderPath, [string] $fileName)
    {
		$outputPath = "";
		$this.SetFolderPath($context, $subFolderPath); 
        if ([string]::IsNullOrEmpty($this.FolderPath)) {
            return $outputPath;
        }

		$outputPath = $this.FolderPath;
		
        if ([string]::IsNullOrEmpty($fileName)) {
            $outputPath = Join-Path $outputPath ($(Get-Date -format "yyyyMMdd_HHmmss") + ".LOG");
        }
        else {
            $outputPath = Join-Path $outputPath $fileName;            
        }
		return $outputPath;
	}

    [void] SetFilePath([OrganizationContext] $context, [string] $fileName)
    {
        $this.SetFilePath($context, "", $fileName);
    }

    [void] SetFilePath([OrganizationContext] $context, [string] $subFolderPath, [string] $fileName)
    {
		$this.FilePath = $this.CalculateFilePath($context, $subFolderPath, $fileName);
    }
}
