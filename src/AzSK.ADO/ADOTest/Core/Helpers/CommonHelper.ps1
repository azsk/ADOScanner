Set-StrictMode -Version Latest 
class CommonHelper {
	static [PSObject] $ScanJobs = @();
	static [string] $AzSKTestLogFolderPath =""

	CommonHelper()
	{
		[CommonHelper]::AzSKTestLogFolderPath = "";
		[CommonHelper]::GetOutputFolderPath()
	}

    static [PSObject] CompareCSV([string] $sourcefolderpath,[string] $destinationfolderpath, [String[]] $WhiteListedControlIds) {
		$Result = "" | Select-Object TestStatus, Message
		$Result.TestStatus = [TestStatus]::NotStarted
		$LogFile = ([CommonHelper]::GetOutputFolderPath() + "\CSVComparisonDifference.LOG")
		if($WhiteListedControlIds)
		{
			[Constants]::DoubleDashLine | Out-File $LogFile -Append
			"List of white listed control ids:" | Out-File $LogFile -Append
			$WhiteListedControlIds | Out-File $LogFile -Append
			[Constants]::DoubleDashLine | Out-File $LogFile -Append
		}
        try {
			$sourcefilepath=  Get-ChildItem -Path $sourcefolderpath -Include "SecurityReport-*.csv" -Recurse
			$destinationfilepath=  Get-ChildItem -Path $destinationfolderpath -Include "SecurityReport-*.csv" -Recurse
			if(![String]::IsNullOrEmpty($sourcefilepath) -and ![String]::IsNullOrEmpty($destinationfilepath))
			{
				$sourcefile = import-csv -Path $sourcefilepath
				$destinationfile = import-csv -Path $destinationfilepath
				if(($sourcefile | Measure-Object).Count -gt 0 -and ($destinationfile | Measure-Object).Count -gt 0 )
				{
					[PSObject[]] $difference = $null
					$difference = Compare-Object $sourcefile $destinationfile -property ControlID,Status 
					$difference = $difference | Sort-Object -Property "ControlID" -Unique
					$difference = $difference | Select-Object ControlID | Where-Object {$_.ControlId -notlike "Azure_AzSKCfg*" -and $WhiteListedControlIds -notcontains $_.ControlId}
					if($null -ne $difference -and $difference.Count -gt 0){
						[Constants]::SingleDashLine | Out-File $LogFile -Append
						"Found difference in CSV comparison:" | Out-File $LogFile -Append
						"File1 : $sourcefilepath" | Out-File $LogFile -Append
						"File2 : $destinationfilepath" | Out-File $LogFile -Append
						"Controls that differ are:" | Out-File $LogFile -Append
						$FailedControls = @()
						foreach($diff in $difference){
							$FailedControlInSource =  ($sourcefile | Where-Object { $_.ControlID -eq $diff.ControlID }) | Out-String
							$FailedControlInDestination = ($destinationfile | Where-Object { $_.ControlID -eq $diff.ControlID }) | Out-String
							
							if(!$FailedControlInSource)
							{
								$FailedControlInSource = "No details found."
							}
							if(!$FailedControlInDestination)
							{
								$FailedControlInDestination = "No details found."
							}
							$FailedControls += $($diff.ControlID)
							"[+] $($diff.ControlID)"| Out-File $LogFile -Append
							"[-] File1:$($FailedControlInSource)"| Out-File $LogFile -Append
							"[-] File2:$($FailedControlInDestination)"| Out-File $LogFile -Append
						}
						Get-Content -Path $LogFile
						$Result.TestStatus = [TestStatus]::Failed
						$FailedControls = $FailedControls | Select-Object -Unique
						$Result.Message = "`n[Failed Controls]`n" + ($FailedControls -join ";`n")
					}
					else{
						$Result.TestStatus = [TestStatus]::Passed 
					}
				}
				else
				{
					$Result.TestStatus = [TestStatus]::Failed
					$Result.Message = "[Failed] SecurityReport.CSV could not be loaded. Please check folder location $sourcefolderpath and $destinationfolderpath"
					$Result.Message | Out-File -FilePath $LogFile -Append
				}
			}
			else{
				$Result.TestStatus = [TestStatus]::Failed 
				$Result.Message = "[Failed] SecurityReport.CSV file not found. Please check folder location $sourcefolderpath and $destinationfolderpath";
				$Result.Message | Out-File -FilePath $LogFile -Append
			}
			
        }
        catch {
             [CommonHelper]::Log("Error comparing csv files.", [MessageType]::Error)
			 [CommonHelper]::Log($_, [MessageType]::Error)
        }
        return $Result
    }

    static [string] GetRootPath() {
        return (get-item $PSScriptRoot).Parent.Parent.FullName
    }

    static [string] GetPath([PathList] $pathList,[TestCase]$testcase ) {
        $Path = [CommonHelper]::GetRootPath()
        try {
        switch ($pathList.ToString()) {
            ([PathList]::TestCases){
                $Path+="\TestCasesMaster.json"
            }
            ([PathList]::TestData) {
                $Path +="\TestCases\"+$testcase.Feature +"\"+$testcase.ModuleName+"\TestData\"
            }
            Default {
            }
        }
                }
        catch {
            [CommonHelper]::Log("Error fetching path for: $pathList", [MessageType]::Error)
        }
                return $Path
    }

    static [string] GetPath([PathList] $pathList) {
        $Path = [CommonHelper]::GetRootPath()
        switch ($pathList.ToString()) {
            ([PathList]::Constants){
                $Path+="\Config\Constants.json"
            }
            ([PathList]::TestCases){
                $Path+="\TestCasesMaster.json"
            }
            Default {
            }
        }
        return $Path
    }

    static [void] Log([string] $Message,[MessageType] $MessageType){
		switch ($MessageType.ToString()) {
		    ([MessageType]::Information)
			{
				Write-Host $Message -foregroundcolor "White"
		    }
		    ([MessageType]::Warning)
			{
				Write-Host "Warning: $($Message)" -foregroundcolor "Yellow"
		    }
		    ([MessageType]::Error)
			{
				Write-Host "Error: $($Message)" -foregroundcolor "Red"
		    }
			([MessageType]::Completed)
			{
				Write-Host "$($Message)" -foregroundcolor "Green"
			}
			([MessageType]::Header){
				Write-Host ([Constants]::DoubleDashLine + "`r`n$($message)`r`n" + [Constants]::DoubleDashLine) -ForegroundColor Cyan;
			}
		    Default
			{
				Write-Host $Message -foregroundcolor "White"
		    }
		 }
    }

	static [string] GetValueFromJson([string]$path, [string]$keyNode, [string]$valueNode){
		$val = [string]::Empty
		$jsonFile =  Get-Content -Path $path | ConvertFrom-Json
		$val = $jsonFile.parameters.$keyNode.$valueNode
		return $val
	}

	static [void] SetValueIntoJson([string]$path, [string]$keyNode, [string]$valueNode, [string]$value){
		$jsonFile =  Get-Content -Path $path | ConvertFrom-Json
		$jsonFile.parameters.$keyNode.$valueNode = $value
		$jsonFile |ConvertTo-Json | Set-Content $path
	}

	static [string] GetOutputFolderPath(){
		if([string]::IsNullOrEmpty([CommonHelper]::AzSKTestLogFolderPath))
		{
			[CommonHelper]::AzSKTestLogFolderPath = $Env:LOCALAPPDATA + "\AzSKTestLogs" + "\" + $(get-date -f MMddyyHHmmss)
			if(-not (Test-Path $([CommonHelper]::AzSKTestLogFolderPath)))
			{
			    try
			    {
			        mkdir -Path $([CommonHelper]::AzSKTestLogFolderPath) -ErrorAction Stop | Out-Null
			    }
			    catch
			    {
				 [CommonHelper]::Log("Error creating output directory!", [MessageType]::Error)
				 [CommonHelper]::Log($_, [MessageType]::Error)
			    }
			}
			return [CommonHelper]::AzSKTestLogFolderPath
		}
		return [CommonHelper]::AzSKTestLogFolderPath
	}

	static [void] SetOSSURL()
	{
		$OSSPolicyURL = "https://azskossep.azureedge.net/`$Version/`$FileName"
		#Set OSS settings   
		Set-AzSKPolicySettings -OnlinePolicyStoreUrl $OSSPolicyURL
	}
	static [void] SetOrgURL()
	{
		$OrgPolicyURL = "https://getazskcontrolsms.azurewebsites.net/api/files?version=`$Version&fileName=`$FileName"
		#Set Org settings   
		Set-AzSKPolicySettings -OnlinePolicyStoreUrl $OrgPolicyURL -EnableAADAuthForOnlinePolicyStore
	}

	static[bool]IsSecurityReportGenerated([string]$OutputPath)
	{
		[bool]$result = $false
		if(![string]::IsNullOrEmpty($OutputPath)){
			try{
				$OverallControlStatuscsv = Get-ChildItem -Path $outputpath -Include "SecurityReport-*.csv" -Recurse   
				$result = $true
			}
			catch{
			
			}    
		}
		return $result
	}

	static [PSObject] VerifyPolicyInUse([string]$AzSKModule,[string] $AzSKModulePath, [string] $OutputPath)
	{
		$Result = "" | Select-Object Status, Message
		#if($AzSKModule -eq "AzSKStaging" -and ![string]::IsNullOrEmpty($AzSKModulePath))
		#{
		#	$AZSKSettingFile = (Split-Path $AzSKModulePath)+"\Framework\Configurations\AzSkSettings.json"
		#}
		#else
		#{
		#	$AZSKSettingFile = ($Env:LOCALAPPDATA+"\Microsoft\"+$AzSKModule+"\AzSKSettings.json")
		#}
		$AZSKSettingFile = ($Env:LOCALAPPDATA+"\Microsoft\"+$AzSKModule+"\AzSKSettings.json")
		$PSContent = Get-Content -Path ($OutputPath + "\Etc\PowerShellOutput.LOG")
		$CurrentScanPolicy = ($PSContent | Where { $_ -match "Running .* cmdlet using .* policy..." })
		if($CurrentScanPolicy -ne $null){
			$CurrentScanPolicy = $CurrentScanPolicy.Split(" ")[-2].Trim("(*)").Trim()
		}
		
		if(($CurrentScanPolicy|Measure-Object).Count -gt 0)
		{
			if(Test-Path -Path $AZSKSettingFile)
			{
				$Content = (Get-Content -Path $AZSKSettingFile) | ConvertFrom-Json
			    $PolicyDetails = ([Constants]::OnlineStoreURL.GetEnumerator() | Where-Object { $_.Value -eq $Content.OnlinePolicyStoreUrl }).Name
			    if(($PolicyDetails|Measure-Object).Count -gt 0 -and $PolicyDetails.Split("_")[1]  -eq $AzSKModule)
			    {
			        if($PolicyDetails.Split("_")[0] -eq $CurrentScanPolicy)
					{
						$Result.Status = [TestStatus]::Passed
						$Result.Message = "Policy Name: " + $CurrentScanPolicy + "URL : " + $($Content.OnlinePolicyStoreUrl)
					}
					else
					{
						$Result.Status = [TestStatus]::Failed
						$Result.Message = "Incorrect policy : Policy Name: " + $CurrentScanPolicy + "URL : " + $($Content.OnlinePolicyStoreUrl)
					}
			    }
			    else
			    {
					$Result.Status = [TestStatus]::Failed
					$Result.Message = "Incorrect Policy URL : $($Content.OnlinePolicyStoreUrl) Please check the AzSKSettings.json file."
			    }
			}
			else
			{
				$Result.Status = [TestStatus]::Failed
				$Result.Message = "$AZSKSettingFile file not found."
			}
		}
		else
		{
			$Result.Status = [TestStatus]::Failed
			$Result.Message = "Policy details not found in \Etc\PowerShellOutput.LOG file"
		}
		return $Result
	}

	static [PSCustomObject] VerifyCSVForError([string] $sourceFilePath, [string] $columnName)
	{
		$Result = "" | Select-Object Status, Message
		try{
			$sourceFileName=  Get-ChildItem -Path $sourceFilePath -Include "SecurityReport-*.csv" -Recurse
			if(![string]::IsNullOrEmpty($sourceFileName))
			{
				$sourceFile = import-csv -Path $sourceFileName
				if(($sourceFile|Measure-Object).Count -gt 0)
				{
					$sourceFile | ForEach-Object {
						foreach ($property in $_.PSObject.Properties ) 
						{
							if($property.Name -eq 'ControlID')
							{
							  $ControlID = $property.Value
							}
							if($property.Name -eq $columnName -and $property.Value -eq "Error"){
										$Result.Status = [TestStatus]::Failed
										$Result.Message += $ControlID + "`n"
							}					
						}
					}
				}
				else
				{
					[CommonHelper]::Log("[Failed] SecurityReport CSV could not be imported. Folder location : $($sourceFilePath) ($_)", [MessageType]::Error)
					$Result.Status = [TestStatus]::Failed
					$Result.Message = "SecurityReport CSV could not be imported. ($_)"
				}
			}
			else
			{
				[CommonHelper]::Log("[Failed] SecurityReport CSV file not found. Folder location : $($sourceFilePath) ($_)", [MessageType]::Error)
				$Result.Status = [TestStatus]::Failed
				$Result.Message = "SecurityReport CSV file not found. ($_)"
			}
		}
		catch{
			[CommonHelper]::Log("Error while verifying CSV for error. Folder location : $($sourceFilePath) ($_)", [MessageType]::Error)
			$Result.Status = [TestStatus]::Failed
			$Result.Message = "Error while verifying CSV for error. ($_)"
		}
		if([string]::IsNullOrEmpty($Result.Status))
		{
			$Result.Status = [TestStatus]::Passed
		}
		return $Result
	}

	#This function verifies that powershell output of a command contains all the expected lines.
	static [PSCustomObject] VerifyAzSKPowerShellOutput([String] $CommandName, [String] $LogFilePath)
	{
		$Result = "" | Select-Object Status, Message
		#Get expected output
		$JSONFilePath = [CommonHelper]::GetRootPath() + [Constants]::ExpectedPowerShellOutput
		$JSONFileContent = Get-Content -Path $JSONFilePath | ConvertFrom-Json
		$ExpectedOutputContent = ($JSONFileContent.ExpectedPowershellOutput.Command | Where-Object { $_.CommandName -eq $CommandName.Split("_")[0] }).ExpectedOutput
		
		#Get log file content
		$ActualOutputContent = Get-Content -Path $LogFilePath
		
		$ExpectedOutputContent | ForEach-Object {
		    $FindPattern = $_
		    $MatchFound = $null
		    $MatchFound = $ActualOutputContent | Where-Object { ($_.ToString() -eq $FindPattern) -or ($_.ToString() -match $FindPattern) }
		    if(($MatchFound | Measure-Object).Count -eq 0)
		    {
		        $Result.Status = [TestStatus]::Failed
		        $Result.Message += "`nPowershell output does not contain :'$($FindPattern)'"
		    }
		}

		if($Result.Status -ne [TestStatus]::Failed)
		{
			$Result.Status = [TestStatus]::Passed
		}

		return $Result
	}

	static [PSCustomObject] CheckErrorInLogFiles([string] $sourceFilePath)
	{
		$result = @()
		$result = "" | Select LogError, LogWarning
		try{
			$sourceFileName=  Get-ChildItem -Path $sourceFilePath -Include "*.LOG" -Recurse
			$result.LogError = $sourceFileName | ForEach-Object { 
				$content = Get-Content -Path $_ | Where-Object {($_ | Select-String -Pattern 'StackTrace','^InvalidArgument:','^NullArgument:','^Generic:','^InvalidOperation:')}
				if($content)
				{
					"[File Name: $($_.FullName.Replace($sourceFilePath,''))] [$($content)]"
				}
			} | Out-String
			$result.LogWarning = $sourceFileName | ForEach-Object { 
				$content = Get-Content -Path $_ | Where-Object {($_ | Select-String -Pattern 'Warning')}
				if($content)
				{
					"[File Name: $($_.FullName.Replace($sourceFilePath,''))] [$($content)]"
				}
			} | Out-String
		}
		catch{
			 [CommonHelper]::Log("Error verifying Logs for error. ($_)", [MessageType]::Error)
		}
		return $result
	}

	static [PSObject] RunParallelJobs([PSCustomObject[]] $Jobs,[String] $ScanType, [bool] $SkipWait){
		try
		{
			[CommonHelper]::ScanJobs = @()
			if(($Jobs|Measure-Object).Count -gt 0)
			{
				$Jobs| ForEach-Object{
						$JobName = $_.JobName
						$AzSKModule = $_.AzSKModule
					    $AzSKModulePath = $_.AzSKModulePath
						$Parameters = $_.Parameters
						While ((Get-Job -state running | Measure-Object).Count -ge [Constants]::MaxThreads -or ((($ScanType -eq "") -or ($ScanType -eq "Sequential")) -and (Get-Job -state running | Measure-Object).Count -ge 1)){
							Write-Host "`n`rPlease wait while the following job(s) complete:" -ForegroundColor Cyan;
							(Get-Job -state Running) | Out-Host
							Start-Sleep -Seconds $([Constants]::SleepTimer)
						}
						$JobExists = Get-Job | Where { $_.Name -eq ($JobName+'_'+$AzSKModule)}
						if(($JobExists|Measure-Object).Count -eq 0)
						{
							$ScriptBlock = [scriptblock]::Create($_.Command)
							if(Get-Job | Where-Object { ($_.Name -match "$($JobName.Split("_")[0]).*") -and ($_.State -eq "Running")})
							{
								Write-Host "`n`rJobs will resume in 60 seconds.`n" -ForegroundColor Cyan
								(Get-Job | Where-Object { ($_.Name -match "$($JobName.Split("_")[0]).*") -and ($_.State -eq "Running")}) | Out-Host
								Start-Sleep -s 60
							}
							elseif(($($JobName.Split("_")[0]) -match "^R.*") -or ($($JobName.Split("_")[0]) -match "^S.*"))
							{
								(Get-Job -state Running) | Out-Host
								Start-Sleep -s 60
							}
							if($AzSKModule -eq "AzSKStaging" -and ![string]::IsNullOrEmpty($AzSKModulePath))
							{
								[CommonHelper]::ScanJobs += Start-Job -Name ($JobName+'_'+$AzSKModule) -ScriptBlock $ScriptBlock -ArgumentList $AzSKModulePath, $Parameters
							}
							else
							{
								[CommonHelper]::ScanJobs += Start-Job -Name ($JobName+'_'+$AzSKModule) -ScriptBlock $ScriptBlock -ArgumentList $AzSKModule, $Parameters
							}
						}
						else
						{
							[CommonHelper]::ScanJobs += $JobExists
						}
				}

				if(-not $SkipWait) {
					[CommonHelper]::WaitForAzSKJobsToComplete();
				}
			}
			else
			{
				Write-Host "`n`rJob(s) not found.`n" -ForegroundColor Cyan
			}	
		}
		catch
		{
			[CommonHelper]::Log("Error while running parallel jobs. ($_)", [MessageType]::Error)
		}
		return [CommonHelper]::ScanJobs;
	}

	static [void] WaitForAzSKJobsToComplete(){
		if(Get-Job -state Running)
		{
			[CommonHelper]::Log("Job(s) triggered. It may take 5-10 min for the following jobs to complete.", [MessageType]::Information)
			[CommonHelper]::ScanJobs | Get-Job
		}
		#print job status
		do{
			[CommonHelper]::ScanJobs | Get-Job | Wait-Job -Timeout 60
			[Constants]::SingleDashLine
			Write-Host "`n`rJob(s) Completed:`n" -ForegroundColor Cyan
			(Get-Job -state Completed) | Out-Host
			Write-Host "`n`rJob(s) Running:`n" -ForegroundColor Cyan
			(Get-Job -state Running) | Out-Host
			[Constants]::SingleDashLine
		}while((Get-Job -state Running | Measure-Object).Count -gt 0);
		#print failed/blocked jobs
		if(Get-Job | Where-Object { ($_.State -ne 'Running') -and ($_.State -ne 'Completed')})
		{
			Write-Host "`n`rJob(s) failed or blocked:`n" -ForegroundColor Red
			Get-Job | Where-Object { ($_.State -ne 'Running') -and ($_.State -ne 'Completed')} | ForEach-Object { 
				Write-Host "`n`r[JobName: $($_.Name)] [JobStatus: $($_.State)]" ;
				Receive-Job -Id $_.Id -Keep
			}
		}
	}

	static [void] LoadAzSKModule([string]$AzSKModule,[string]$AzSKModulePath){
		try
		{
			$flag = 0;
			do
			{
				$flag = $flag + 1;
				if($AzSKModule -eq "AzSKStaging" -and ![string]::IsNullOrEmpty($AzSKModulePath) -and (Get-Module -ListAvailable -FullyQualifiedName $AzSKModulePath| Measure-Object).Count -gt 0)
				{
					Write-Host "`n`rLoading $($AzSKModule) module from $($AzSKModulePath)."
				    Import-Module -Name $AzSKModulePath -Scope Global
				}
				elseif(-not(Get-Module -Name $AzSKModule |  Measure-Object).Count -gt 0){
					Write-Host "`n`rLoading $($AzSKModule) module."
				    Import-Module -Name $AzSKModule -Scope Global
				}
			}while((-not(Get-Module -Name $AzSKModule |  Measure-Object).Count -gt 0) -and ($flag -lt 3));
			#Fail if module not loaded
			if(-not (Get-Module -Name $AzSKModule |  Measure-Object).Count -gt 0)
			{
				Write-Host "Unable to load $($AzSKModule) module. Please load module manually." -ForegroundColor Red;
				exit;
			}
		}
		catch
		{
			[CommonHelper]::Log("AzSK Module Installation Error. `n`rModule Details: $($AzSKModule) : $($AzSKModulePath)`n`r$($_)", [MessageType]::Error)
			throw $_
		}
	}

	static [string[]] VerifyOutputDirectoryStructure([string] $outputpath)
	{
		$Diff = $null
		try
		{
			if($outputpath)
			{
				$ExpectedDirectoryStucture = [CommonHelper]::GetExpectedDirectoryStucture($outputpath)
				$OutputDirectoryStucture = (Get-ChildItem -Path $outputpath -Recurse -File).FullName.Replace($outputpath,"")
				$OutputDirectoryStucture = $OutputDirectoryStucture | ForEach-Object{ $_ -replace "[-|_]\d{8}_\d{6}", "-*" }
				$OutputDirectoryStucture = $OutputDirectoryStucture | ForEach-Object{ $_.trimstart("\")}
				#Write-Host Comparision result are: -BackgroundColor DarkGreen
				$Diff = Compare-Object -ReferenceObject $ExpectedDirectoryStucture -DifferenceObject $OutputDirectoryStucture
				if($Diff)
				{
				  $Diff = [CommonHelper]::FilterRGFolder($Diff)
				}
				if($Diff)
				{
				  $Diff = $Diff.InputObject
				}
			}
			else
			{
				#[CommonHelper]::Log("[Failed] No output directory found.", [MessageType]::Error)
				$Diff= "Output directory not found."
			}
		}
		catch{
			 [CommonHelper]::Log("Error verifying output directory structure. ($_)", [MessageType]::Error)
		}
		return $Diff;
	}

	static [string[]] GetExpectedDirectoryStucture([string] $outputpath){
		$path = @()
		$command = $outputpath.Trim("\").Split('\')[-1].Split('_')[-1]
		#C:\Users\v-siniki\Source\Repos\SR-IM-Cloud-DevOps-AzSDK\AzSK\AzSK.Test\Core\Models\Default_Output_Directory_Stucture.json
		$EDSFilePath = [CommonHelper]::GetRootPath() + [Constants]::ExpectedDirectoryStucture
		$EDSFileContent = Get-Content -Path $EDSFilePath | ConvertFrom-Json
		$EDSMatchFileContent = $EDSFileContent.OutputDirectoryStucture.Command | Where-Object { $_.CommandName -match ($command) }
		switch(($EDSMatchFileContent | Measure-Object).Count)
		{
			0		{ $command = "Default"; break;}
			1		{ break;}
			default {					  
					  $PSLogFile = Get-ChildItem -Path	$outputpath -Include "PowerShellOutput.LOG" -Recurse
					  $SearchPattern = $EDSMatchFileContent.CommandName | % { $_.Split("_")[1] }
					  $SearchPattern = Get-Content -Path $PSLogFile | Out-String -Stream | Select-String $SearchPattern | Select-Object * -First 1
					  if($SearchPattern)
					  {
						$command =$command +"_"+ $SearchPattern.Pattern
					  }
					  else{
						$command = "Default"
					  }
					}
		}
		$FileList = ($EDSFileContent.OutputDirectoryStucture.Command | Where-Object { $_.CommandName -eq $command }).DefaultFilesList
		$FileList = $FileList -replace "#SubscrptionName#", $((Get-AzContext).Subscription.Name)
		return $FileList;
	}

	static [PSObject[]] FilterRGFolder([PSObject[]] $FolderList)
	{
		$ResourceList = [CommonHelper]::GetAzureRMResourceList($false);
		$ResourceList = ($ResourceList.ResourceGroupName | Select -Unique)
		$ExcludeList = ForEach($resource in $ResourceList){
		   $FolderList.InputObject | Where { $_ -match "$resource\.*"}
		}
		$ExcludeList += $FolderList.InputObject | Where { $_ -eq 'Etc\UnsupportedResources-*.csv.LOG' -or $_ -eq "ArchivedPSOutputError.LOG"}
		if(($FolderList.InputObject|Measure-Object).Count -gt 0 -and ($ExcludeList|Measure-Object).Count -gt 0)
		{
			$ExcludeList = $ExcludeList | Select-Object -Unique
			return (Compare-Object $FolderList.InputObject $ExcludeList)
		}
		else
		{
			return $FolderList
		}
	}

	static [PSObject] RunMandateCheck([string] $AzSKModule,[string] $AzSKModulePath, [string] $outputpath){
			$result = "" | Select-Object AzSKModule,PolicyError,FolderDiff,CSVError,LogError,LogWarning
			$result.AzSKModule = $AzSKModule
			$result.CSVError = $null
			$result.LogError = $null
			$result.LogWarning = $null
			$result.PolicyError = $null
			if(![string]::IsNullOrEmpty($outputpath) -and (Test-Path -Path $outputpath) -and ![string]::IsNullOrEmpty($AzSKModule))
			{
				$result.AzSKModule = [CommonHelper]::GetModuleVersionFromOutputFile($OutputPath)
				$result.FolderDiff = [CommonHelper]::VerifyOutputDirectoryStructure($OutputPath) -join "`n"
				$result.PolicyError = [CommonHelper]::VerifyPolicyInUse($AzSKModule,$AzSKModulePath,$OutputPath)
				if(Get-ChildItem -Path $outputpath -Recurse -Filter "SecurityReport-*.csv")
				{
					$CSVError = [CommonHelper]::VerifyCSVForError($OutputPath,'Status')
					if($null -ne $CSVError.Message)
					{
						$result.CSVError = $CSVError.Message
					}
				}
				$logresult = [CommonHelper]::CheckErrorInLogFiles($OutputPath)
				$result.LogError = $logresult.LogError
				$result.LogWarning = $logresult.LogWarning
			}
			else
			{
				$result.FolderDiff = "Failed: directory not found."
			}
			return $result;
		}

	static [PSObject] RunMandateCheck_CommandsWithOutOutputFolder([string] $CommandName, [string] $Logpath){
				$result = "" | Select-Object ScanError, LogError,LogWarning
				$result.LogError = $null
				$result.LogWarning = $null
				$result.ScanError = ([Commonhelper]::VerifyAzSKPowerShellOutput([string] $CommandName, [string] $Logpath)).Message
				$logresult = [CommonHelper]::CheckErrorInLogFiles($Logpath)
				$result.LogError = $logresult.LogError
				$result.LogWarning = $logresult.LogWarning
				return $result;
		}
	
	static [PSObject[]] GetAzureRMResourceList([bool] $filterResource){
			$AzureRmResourceList = Get-AzResource;
			if($filterResource)
			{
				$AzureRmResourceList = $AzureRmResourceList | Select-Object Kind,ResourceGroupName, Name,ResourceType | Group-Object ResourceType, Kind| ForEach-Object {
					$_ | Select-Object -ExpandProperty Group | Select-Object -First 1
				} | Sort-Object ResourceType;
			}
			return $AzureRmResourceList
		}

	#This function reads the AzSK module version used to run the scan from PowerShellOutput.Log file
	static [String] GetModuleVersionFromOutputFile([String] $OutputPath){
		
			$OutputFile = (Get-ChildItem -Path $OutputPath -Include 'PowerShellOutput.LOG' -Recurse).FullName
			$Content = Get-Content -Path $OutputFile
			$ModuleVersion = $Content | Where { $_ -match ".* Version: .*" } | Select-Object -First 1
			
			return $ModuleVersion
		}

	static [String] GetCustomMessageForTestCase([PSObject] $TestCaseDetails){
			$CustomMessage = ""
		    $i=1
		    if([String]::IsNullOrEmpty($TestCaseDetails.OutputPath))
		    {
		        $CustomMessage += "$($i)." + $TestCaseDetails.FolderStructureDiff + "`n`r"
		        $i++
		    }
		    elseif(![string]::IsNullOrEmpty($TestCaseDetails.FolderStructureDiff))
		    {
		        $CustomMessage += "$($i)." + "Found difference in folder structure:`n`r" + $TestCaseDetails.FolderStructureDiff + "`n`r"
		        $i++
		    }
		
		    if(![String]::IsNullOrEmpty($TestCaseDetails.PolicyError) -and $TestCaseDetails.PolicyError -match ".*Failed.*")
		    {
		        $CustomMessage += "$($i)." + "Policy do not match.`n`r$($TestCaseDetails.PolicyError)" + "`n`r"
		        $i++
		    }
		    if(![String]::IsNullOrEmpty($TestCaseDetails.ScanError))
		    {
		        $CustomMessage += "$($i)." + "Error captured in PowerShell output.`n`r$($TestCaseDetails.ScanError)" + "`n`r"
		        $i++
		    }
		    if(![String]::IsNullOrEmpty($TestCaseDetails.CSVError))
		    {
		        $CustomMessage += "$($i)." + "Error captured in CSV for following controls:`n$($TestCaseDetails.CSVError)" + "`n`r"
		        $i++
		    }
		    if(![String]::IsNullOrEmpty($TestCaseDetails.LogError))
		    {
		        $CustomMessage += "$($i)." + "Error captured in Log files.`n`r$($TestCaseDetails.LogError)" + "`n`r"
		        $i++
		    }
		    if(![String]::IsNullOrEmpty($TestCaseDetails.LogWarning))
		    {
		        $CustomMessage += "$($i)." + "Warning captured in Log files.`n`r$($TestCaseDetails.LogWarning)" + "`n`r"
		        $i++
		    }
			return $CustomMessage
		}

		static [void] SetAzureContext([String] $subscriptionId){
			$isContextNull = $false;
			$currentContext = $null;
			try
			{
				$currentContext = Get-AzContext -ErrorAction Stop
			}
			catch
			{
				$isContextNull = $true
			}
			if(($null -eq $currentContext) -or $isContextNull -or ($null -eq $currentContext.Subscription))
			{
				[CommonHelper]::Log("No active Azure login session found. Initiating login flow...",[MessageType]::Warning)
	
				$currentContext = Add-AzAccount
	
				try
				{
					$currentContext = Get-AzContext -ErrorAction Stop
				}
				catch
				{
					throw [System.ArgumentException] ("Subscription Id [" + $subscriptionId + "] is invalid or you may not have permissions.")
				}
			}
	
			if($currentContext.Subscription.Id -ne $subscriptionId)      
			{
				$currentContext = Set-AzContext -SubscriptionId $subscriptionId -ErrorAction Stop
	
				# $currentContext will contain the desired subscription (or $null if id is wrong or no permission)
				if ($null -eq $currentContext)
				{
					throw [System.ArgumentException] ("Invalid Subscription Id: [" + $subscriptionId + "]")
				}
			}
		}
}
