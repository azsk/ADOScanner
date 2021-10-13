Set-StrictMode -Version Latest

function Get-AzSKADOSecurityStatusCombinedResults
{
    [OutputType([String])]
    [Alias("Get-AzSKAzureDevOpsSecurityStatusCombinedResults")]
    Param
    (
        [string]
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias("oz")]
        $OrganizationName,

        [string]
        [Parameter(Mandatory = $true)]
        [Alias("fn")]
        $FolderName,

        [string]
        [Parameter(Mandatory = $true)]
        [ValidateSet("UPC","GADSBM")]
        [Alias("md")]
        $Mode
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
            $folderSanitizedPath = [Helpers]::SanitizeFolderName($FolderName)
            $fileName=""
            if(![string]::IsNullOrEmpty($foldersanitizedPath)) {
                if($Mode -eq 'UPC'){
                    $outputPath = Join-Path $outputPath -ChildPath ([Constants]::ParentFolder + $sanitizedPath) | Join-Path -ChildPath $folderSanitizedPath ;
                    $fileName = "SecurityReport_CollatedUPC.csv"
                }
                else{
                    $outputPath = Join-Path $outputPath -ChildPath ([Constants]::ParentFolder + $sanitizedPath) | Join-Path -ChildPath "BatchScan" | Join-Path -ChildPath $folderSanitizedPath ;
                    $fileName = "SecurityReport_CollatedBatchScan.csv"
                }
                
            }

            if(-not (Test-Path $outputPath)) {
                Write-Host "Could not find path $($outputPath). Make sure the folder exists in the correct path." -ForegroundColor Red
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

                $temp | Export-Csv (Join-Path $outputPath $fileName) -append -NoTypeInformation 
                Write-Progress -Activity "Combined results from $($progress) folders out of $($folderCount) folders " -PercentComplete ($progress / $folderCount  * 100)
                $progress+=1
                
               }
            }         


            Write-Progress -Activity "All results collated" -Status "Ready" -Completed
            Write-Host "Results from $($Mode) mode have been combined and exported to $(Join-Path $outputPath $fileName) "  -ForegroundColor Green
            
           
            
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
