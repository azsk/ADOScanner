Set-StrictMode -Version Latest
function Get-AzSKADOServiceMapping
{
    <#
    .SYNOPSIS
        This command would help users to get service mappings of various components of AzSK.ADO.
    .DESCRIPTION
        This command will fetch service mappings of AzSK.ADO components and help user to provide details of different component using single command. Refer https://aka.ms/adoscanner/docs for more information 
    .PARAMETER OrganizationName
        Organization name for which the service mapping evaluation has to be performed.
    .PARAMETER ProjectName
        Project name for which the service mapping evaluation has to be performed.
    .PARAMETER BuildMappingsFilePath
        File Path for build mappings in JSON format.
    .PARAMETER ReleaseMappingsFilePath
        File Path for release mappings in JSON format.

    .LINK
    https://aka.ms/ADOScanner 

    #>
    Param(
        [string]
        [Parameter(Mandatory = $true)]
        [Alias("oz")]
        $OrganizationName,

        [string]
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias("pns", "ProjectNames", "pn")]
        $ProjectName,

        [string]
        [Parameter(Mandatory = $true)]
        [Alias("bfp")]
        $BuildMappingsFilePath,

        [string]
        [Parameter(Mandatory = $true)]
        [Alias("rfp")]
        $ReleaseMappingsFilePath,

        [string]
        [Parameter(Mandatory = $true)]
        [Alias("rpfp")]
        $ReposMappingsFilePath,

        [ValidateSet("All", "VariableGroup", "ServiceConnection","AgentPool", "SecureFile", "Feed", "Environment")] 
        [Parameter(Mandatory = $false)]
        [Alias("mt")]
        $MappingType,

        [System.Security.SecureString]
        [Parameter(HelpMessage="Token to run scan in non-interactive mode")]
        [Alias("tk")]
        $PATToken,

        [switch]
        [Parameter(HelpMessage = "Switch to provide personal access token (PAT) using UI.")]
        [Alias("pfp")]
        $PromptForPAT,

        [string]
        [Parameter(Mandatory=$false, HelpMessage="KeyVault URL for PATToken")]
        [Alias("ptu")]
        $PATTokenURL
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
            if($PromptForPAT -eq $true)
            {
                if($null -ne $PATToken)
                {
                    Write-Host "Parameters '-PromptForPAT' and '-PATToken' can not be used simultaneously in the scan command." -ForegroundColor Red
                    return;
                }
                else
                {
                    $PATToken = Read-Host "Provide PAT for [$OrganizationName] org:" -AsSecureString
                }
            }

            if (-not [String]::IsNullOrEmpty($PATTokenURL))
            {
                # For now, if PAT URL is specified we will trigger an Azure login.
                $Context = @(Get-AzContext -ErrorAction SilentlyContinue )
                if ($Context.count -eq 0)  {
                    Write-Host "No active Azure login session found.`r`nPlease login to Azure tenant hosting the key vault..." -ForegroundColor Yellow
                    Connect-AzAccount -ErrorAction Stop
                    $Context = @(Get-AzContext -ErrorAction SilentlyContinue)
                }

                if ($null -eq $Context)  {
                    Write-Host "Login failed. Azure login context is required to use a key vault-based PAT token.`r`nStopping scan command." -ForegroundColor Red
                    return;
                }
                #Parse the key-vault-URL to determine vaultname, secretname, version
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

            $resolver = [Resolver]::new($OrganizationName, $PATToken)
            $mapping = [AzSKADOServiceMapping]::new($OrganizationName, $ProjectName, $BuildMappingsFilePath, $ReleaseMappingsFilePath, $ReposMappingsFilePath, $MappingType, $PSCmdlet.MyInvocation);

            return $mapping.InvokeFunction($mapping.GetSTmapping);
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
