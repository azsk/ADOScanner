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
        [Alias("mp")]
        $ModulePath



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

            $ContextHelper = [ContextHelper]::new()
            $Context=$ContextHelper.SetContext($OrganizationName)
            [BatchScanManager] $batchScanMngr = [BatchScanManager]:: GetInstance($Context.OrganizationName,$ProjectName)
            if($batchScanMngr.isBatchScanInProgress($Context.OrganizationName,$ProjectName) -eq $false){
                $batchScanMngr.CreateBatchMasterList();
            }
            else {
                $batchScanMngr.UpdateBatchMasterList();
            }
            $commandForNextBatch='ipmo \"{0}\" ;BatchScan -oz \"{1}\" -pn \"{2}\" -mp \"{3}\" ' -f $ModulePath,$OrganizationName,$ProjectName, $ModulePath
            if($PSBoundParameters.ContainsKey('BuildsFolderPath') -and $PSBoundParameters.ContainsKey('UseBaselineControls')){
                GADS -oz $OrganizationName -pn $ProjectName -rtn Build -BatchScan -upc -als -ubc -bp $BuildsFolderPath
                $commandForNextBatch+= '-ubc -bp \"{0}\"; Read-Host ' -f $BuildsFolderPath
            }
            elseif($PSBoundParameters.ContainsKey('BuildsFolderPath') -and $PSBoundParameters.ContainsKey('ControlIds')){
                GADS -oz $OrganizationName -pn $ProjectName -rtn Build -BatchScan -upc -als -bp $BuildsFolderPath -cids $ControlIds
                $commandForNextBatch+= '-bp \"{0}\" -cids \"{1}\"; Read-Host ' -f $BuildsFolderPath, $ControlIds
            }
            elseif($PSBoundParameters.ContainsKey('BuildsFolderPath')){
                GADS -oz $OrganizationName -pn $ProjectName -rtn Build -BatchScan -upc -als -bp $BuildsFolderPath
                $commandForNextBatch+= '-bp \"{0}\"; Read-Host ' -f $BuildsFolderPath
            }
            elseif($PSBoundParameters.ContainsKey('UseBaselineControls')){
                GADS -oz $OrganizationName -pn $ProjectName -rtn Build -BatchScan -upc -als -ubc
                $commandForNextBatch+= '-ubc; Read-Host ' 
            }
            elseif($PSBoundParameters.ContainsKey('ControlIds')){
                GADS -oz $OrganizationName -pn $ProjectName -rtn Build -BatchScan -upc -als -cids $ControlIds
                $commandForNextBatch+= '-cids \"{0}\"; Read-Host ' -f $ControlIds 
            }
            else {
                GADS -oz $OrganizationName -pn $ProjectName -rtn Build -BatchScan -upc -als 
                $commandForNextBatch+= '; Read-Host '
            }
            
            if("" -eq $batchScanMngr.GetContinuationToken() -and $batchScanMngr.GetBatchScanState() -eq [BatchScanState]::COMP){
                #TODO all batches complete
                Write-Host "No unscanned builds found. Scan is complete. " -ForegroundColor Green
                $batchScanMngr.RemoveBatchScanData();

            }
            else {
               
                start-process powershell.exe -argument $commandForNextBatch 
            }
            #start-process powershell.exe -argument 'ipmo AzSK.ADO;gads -oz "juhitiwari" -pn "adotest" -bn \"build 1\" -rtn build; Read-Host' 
            
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
