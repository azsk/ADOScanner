Set-StrictMode -Version Latest

function BatchScan
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
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [Alias("bp")]
        $BuildsFolderPath,

        [switch]
        [Parameter()]
        [Alias("ubc")]
        $UseBaselineControls,

        [string]
        [Parameter()]
        [Alias("cids")]
        $ControlIds,

        [string]
		[Parameter(Mandatory = $true)]
		[Alias("ptu")]
		$PATTokenURL,

        [int]
        [Parameter()]
        [Alias("bsz")]
        $BatchSize,

        [string]
        [Parameter(Mandatory = $true)]
        [Alias("mp")]
        $ModulePath,

        [string]
        [Parameter(Mandatory = $true)]
        [Alias("fn")]
        $FolderName,

        [string]
        [Parameter(Mandatory = $true)]
        [Alias("rtn")]
        $ResourceTypeName,

        [string]
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [Alias("rfp")]
        $ReleasesFolderPath



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


            if (-not [String]::IsNullOrEmpty($PATTokenURL))
			{
				
				$Context = @(Get-AzContext -ErrorAction SilentlyContinue )
				if ($Context.count -eq 0)  {
                    $KeyVaultToken=$null;
                    try{
                        $Response = Invoke-RestMethod -Uri 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fvault.azure.net' -Method GET -Headers @{Metadata="true"} 
                        $KeyVaultToken = $Response.access_token
                    }
                    catch {
                        Write-Host "Either the current user or the Managed Identity of this device does not have access to the tenant hosting the Key Vault. Login as the correct user using Connect-AzAccount or add the Managed Identity of this device in Key Vault." -ForegroundColor Red
                        return;
                    }

                    try {
                        $KeyVaultURL=$PATTokenURL+"?api-version=2016-10-01"
                        $KeyVaultResponse = Invoke-RestMethod -Uri $KeyVaultURL -Method GET -Headers @{Authorization="Bearer $KeyVaultToken"}
                        $PATToken = ConvertTo-SecureString -AsPlainText -Force -String "$($KeyVaultResponse.value)"
                    }
                    catch {
                        Write-Host "Could not extract PATToken from the given key vault URL.`r`nStopping scan command." -ForegroundColor Red
                        return;
                    }                 
                  
                }
                else {
                    if ($PATTokenURL -match "^https://(?<kv>[\w]+)(?:[\.\w+]*)/secrets/(?<sn>[\w]+)/?(?<sv>[\w]*)")
                    {
                        $kvName = $Matches["kv"]
                        $secretName = $Matches["sn"]
                        $secretVersion = $Matches["sv"]

                        if (-not [String]::IsNullOrEmpty($secretVersion))
                        {
                            $kvSecret = Get-AzKeyVaultSecret -VaultName $kvName -SecretName $secretName -Version $secretVersion
                        }
                        else
                        {
                            $kvSecret = Get-AzKeyVaultSecret -VaultName $kvName -SecretName $secretName
                        }

                        if ($null -eq $kvSecret)
                        {
                            Write-Host "Could not extract PATToken from the given key vault URL.`r`nStopping scan command." -ForegroundColor Red
                            return;
                        }
                        $PATToken = $kvSecret.SecretValue;
                    }
                    else {
                        Write-Host "Could not extract PATToken from the given key vault URL.`r`nStopping scan command." -ForegroundColor Red
                        return;
                    }
                }
			}

            $ContextHelper = [ContextHelper]::new($true);
            $Context = $null
            if($PATToken)
            {
                $Context = $ContextHelper.SetContext($OrganizationName,$PATToken)
            }
            else 
            {
                Write-Host "Could not access PATToken of the user. Stopping the command. " -ForegroundColor Red;
                return;
            }
            [BatchScanManager] $batchScanMngr = [BatchScanManager]:: GetInstance($Context.OrganizationName,$ProjectName)
            if($batchScanMngr.isBatchScanInProgress($Context.OrganizationName,$ProjectName) -eq $false){
                $batchScanMngr.CreateBatchMasterList();
            }
            else {
                $batchScanMngr.UpdateBatchMasterList();
            }
            $commandForNextBatch ='ipmo \"{0}\"; BatchScan ' -f $ModulePath;
            $PSCmdlet.MyInvocation.BoundParameters.GetEnumerator() | foreach-object {
                $commandForNextBatch += '-{0} \"{1}\" ' -f $_.key, $_.value 
            }

            $parametersForGads = $PSCmdlet.MyInvocation.BoundParameters;
            $parametersForGads.Add("UsePartialCommits", $true);
            $parametersForGads.Add("AllowLongRunningScan", $true);
            $parametersForGads.Add("BatchScan",$true);
            $parametersForGads.Remove("BatchSize") | Out-Null;
            $parametersForGads.Remove("ModulePath") | Out-Null;
            $parametersForGads.Remove("PATTokenURL") | Out-Null;

            $rh = $false #Whether to keep each console open after gads completes.
            if ($rh)
            {
                $commandForNextBatch+= '; Read-Host '
            }

            GADS @parametersForGads

            if($ResourceTypeName -eq "Build" -and [string]::IsNullOrEmpty($batchScanMngr.GetBuildContinuationToken()) -and $batchScanMngr.GetBatchScanState() -eq [BatchScanState]::COMP){
                #TODO all batches complete
                Write-Host "No unscanned builds found. Scan is complete. " -ForegroundColor Green
                $batchScanMngr.RemoveBatchScanData();
            }
            elseif($ResourceTypeName -eq "Release" -and [string]::IsNullOrEmpty($batchScanMngr.GetReleaseContinuationToken()) -and $batchScanMngr.GetBatchScanState() -eq [BatchScanState]::COMP){
                Write-Host "No unscanned releases found. Scan is complete. " -ForegroundColor Green
                $batchScanMngr.RemoveBatchScanData();
            }
            elseif($ResourceTypeName -eq "Build_Release" -and [string]::IsNullOrEmpty($batchScanMngr.GetReleaseContinuationToken()) -and [string]::IsNullOrEmpty($batchScanMngr.GetBuildContinuationToken()) -and $batchScanMngr.GetBatchScanState() -eq [BatchScanState]::COMP) {
                Write-Host "No unscanned builds or releases found. Scan is complete. " -ForegroundColor Green
                $batchScanMngr.RemoveBatchScanData();
            }
            else {
               
                start-process powershell.exe -argument $commandForNextBatch 
            }
           
            
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
