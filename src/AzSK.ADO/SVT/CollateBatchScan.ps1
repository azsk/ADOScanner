Set-StrictMode -Version Latest

function CollateBatchScan
{
    [OutputType([String])]
    Param
    (
        [string]
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias("oz")]
        $OrganizationName,

        [string]
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias("pn")]
        $ProjectName,


        [string]
        [Parameter(Mandatory = $true)]
        [Alias("fn")]
        $FolderName
        )
    Begin
    {
        [CommandHelper]::BeginCommand($PSCmdlet.MyInvocation);
        [ListenerHelper]::RegisterListeners();
    }

    Process
    {
        try
        {

            $basePath = [Constants]::AzSKLogFolderPath;
            $outputPath = Join-Path $basePath ($([Constants]::AzSKModuleName)+"Logs")  ;

			$sanitizedPath = [Helpers]::SanitizeFolderName($OrganizationName);
			if ([string]::IsNullOrEmpty($sanitizedPath)) {
				$sanitizedPath = $context.OrganizationName;
			}
            $batchScanSanitizedPath = [Helpers]::SanitizeFolderName($FolderName)
            if(![string]::IsNullOrEmpty($batchScansanitizedPath)) {
                $outputPath = Join-Path $outputPath -ChildPath ([Constants]::ParentFolder + $sanitizedPath) | Join-Path -ChildPath "BatchScan" | Join-Path -ChildPath $batchScanSanitizedPath ;
            }

            if(-not (Test-Path $outputPath)) {
                Write-Host "Path is incorrect" -ForegroundColor Red
                return;
            }
           
            $folderCount = (Get-ChildItem $outputPath -Directory | Measure-Object).Count;
            $progress=1;
            
            Get-ChildItem $outputPath | foreach {
               $scanFolder = $_.name;
               $csvFolder = Join-Path $outputPath -ChildPath $scanFolder;
               $csvFilePath = $csvFolder+"\*.csv";
               
               Get-ChildItem $csvFilePath | foreach {
                $csv=$_
                $temp = Import-Csv $csv
                
                $temp | foreach  {
                    $oldDetailedLogFile = $_.DetailedLogFile
                    $newDetailedLogFile = Join-Path $scanFolder $oldDetailedLogFile
                    $_.DetailedLogFile = $newDetailedLogFile
                }

                $temp | Export-Csv (Join-Path $outputPath "finalnew.csv") -append -NoTypeInformation 
                Write-Progress -Activity "Collated results from $($progress) folders out of $($folderCount) folders " -PercentComplete ($progress / $folderCount  * 100)
                $progress+=1
                
               }
            }
            Write-Progress -Activity "All results collated" -Status "Ready" -Completed
            Write-Host "Collated results have been exported to $(Join-Path $outputPath "finalnew.csv") "  -ForegroundColor Green
            
           
            
        }
        catch
        {
            [EventBase]::PublishGenericException($_);
        }
    }

    End
    {
    [ListenerHelper]::UnregisterListeners();
    }
}
