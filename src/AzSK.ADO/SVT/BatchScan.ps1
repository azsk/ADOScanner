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
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [Alias("pn")]
        $ProjectName

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
                $batchScanMngr.CreateBatchMasterList($OrganizationName,$ProjectName);
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
