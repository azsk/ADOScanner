<#
.Description
	Base class for SVT classes being called from PS commands
	Provides functionality to fire events/operations at command levels like command started, 
	command completed and perform operation like generate run-identifier, invoke auto module update, 
	open log folder at the end of commmand execution etc
#>
using namespace System.Management.Automation
Set-StrictMode -Version Latest
class ADOSVTCommandBase: SVTCommandBase {
    
    #Region Constructor
    ADOSVTCommandBase([string] $organizationName, [InvocationInfo] $invocationContext):
    Base($organizationName, $invocationContext) {

        [Helpers]::AbstractClass($this, [ADOSVTCommandBase]);
        
        #$this.CheckAndDisableAzTelemetry()
       
        $this.AttestationUniqueRunId = $(Get-Date -format "yyyyMMdd_HHmmss");
        #Fetching the resourceInventory once for each SVT command execution
        [ResourceInventory]::Clear();

         #Initiate Compliance State
         $this.InitializeControlState();

        #Force load of AzSK.json
        $cfg = [ConfigurationManager]::GetAzSKConfigData();
    }
    #EndRegion


    #Az Related command started events 
     [void] CommandStartedExt() {
         
        $this.ValidateAttestationParameters();
        #<TODO Framework: Find the purpose of function and move to respective place
        #$this.ClearSingletons();

        $this.InitializeControlState();
    }

	[void] PostCommandStartedAction()
	{
        if ([ContextHelper]::IsOAuthScan) {
            $this.PublishCustomMessage("The OAuth-based scan feature is in preview. Results for some controls may not match the regular scan results.", [MessageType]::Warning);
        }
        if([ContextHelper]::IsBatchScan){
            #TODO Should not access graph token as of now as multiple accounts may be logged in, can't select one of them at every prompt
        }
        else {
            try 
            {
                # Checking if user has graph access or not before starting control evaluation.
                [IdentityHelpers]::CheckGraphAccess();
                $controlSettingObj = [ConfigurationManager]::LoadServerConfigFile("ControlSettings.json");
                if ($controlSettingObj.GroupResolution.UseSIPFeedForAADGroupExpansion) {
                    [IdentityHelpers]::CheckSIPAccess();
                }
            }
            catch {
            #eat exception 
            }
        }

        if($this.invocationContext.MyCommand.Name -eq "Set-AzSKADOSecurityStatus")
        {
            try{
                $folderpath= Join-Path ([WriteFolderPath]::GetInstance().FolderPath) "ControlFixInfo.csv";
                [ControlHelper]::ControlFixBackup | Select-Object ResourceName,ResourceId, @{Name = "BackupDate"; Expression = { $_.Date} } ,@{Name = "ObjectToBeFixed"; Expression = { $($_.DataObject|convertto-Json)} } | Export-Csv -Path $folderpath -NoTypeInformation #-encoding utf8 #The NoTypeInformation parameter removes the #TYPE information header from the CSV output 


                #Export backup for user to confirm
                $this.PublishCustomMessage( "`nPlease review the control fix data in below file:`n$($folderpath)", [MessageType]::Warning);
                $input = ""
                while ($input -ne "y" -and $input -ne "n") {
                    if (-not [string]::IsNullOrEmpty($input)) {
                        $this.PublishCustomMessage("Please select an appropriate option.`n",[MessageType]::Warning);
                    }
                    $input = Read-Host "Enter 'Y' to continue and 'N' to exit (Y/N)"
                    $input = $input.Trim()
                }
                if ($input -eq "n") {
                    $this.PublishCustomMessage( "Exiting the control fix process. `n",[MessageType]::Warning);
			        break;
                }
            }
            catch {
                $this.CommandError($_);
            }
        }
	}
    [void] PostPolicyComplianceTelemetry()
	{
			
    }
    
    [void] CommandErrorExt([System.Management.Automation.ErrorRecord] $exception) {

    }

    [void] CommandCompletedExt([SVTEventContext[]] $arguments) {

    }

    #ADOCleanup - remove this ComplianceData stuff...leftover from AzSK.
    [ComplianceStateTableEntity[]] FetchComplianceStateData([string] $resourceId)
	{
        [ComplianceStateTableEntity[]] $ComplianceStateData = @();
        if($this.IsLocalComplianceStoreEnabled)
        {
            if($null -ne $this.ComplianceReportHelper)
            {
                [string[]] $partitionKeys = @();                
                $partitionKey = [Helpers]::ComputeHash($resourceId.ToLower());                
                $partitionKeys += $partitionKey
                $ComplianceStateData = $this.ComplianceReportHelper.GetSubscriptionComplianceReport($partitionKeys);            
            }
        }
        return $ComplianceStateData;
	}

    [void] InitializeControlState() {
      if (-not $this.ControlStateExt) {
          #ADOTODO: Do we still need this? 
          #ADOTODO: The InvocationContext will change for each cmdlet run in a session. 
          #So what benefit is there from caching the first one with AzSKSettings? (Need to investigate)
          [AzSKSettings]::InitContexts($this.OrganizationContext, $this.InvocationContext);
          $this.ControlStateExt = [ControlStateExtension]::new($this.OrganizationContext, $this.InvocationContext);
          $this.ControlStateExt.UniqueRunId = $this.AttestationUniqueRunId
          $this.ControlStateExt.Initialize($false);
          $this.UserHasStateAccess = $this.ControlStateExt.HasControlStateReadAccessPermissions();
      }
    }

    [void] PostCommandCompletedAction([SVTEventContext[]] $arguments) {
        if ($this.AttestationOptions -ne $null -and $this.AttestationOptions.AttestControls -ne [AttestControls]::None) {
            try {
                [SVTControlAttestation] $svtControlAttestation = [SVTControlAttestation]::new($arguments, $this.AttestationOptions, $this.OrganizationContext, $this.InvocationContext);
                #The current context user would be able to read the storage blob only if he has minimum of contributor access.
                if ($svtControlAttestation.controlStateExtension.HasControlStateWriteAccessPermissions()) {
                    if (-not [string]::IsNullOrWhiteSpace($this.AttestationOptions.JustificationText) -or $this.AttestationOptions.IsBulkClearModeOn) {
                        $this.PublishCustomMessage([Constants]::HashLine + "`n`nStarting Control Attestation workflow in bulk mode...`n`n");
                    }
                    else {
                        $this.PublishCustomMessage([Constants]::HashLine + "`n`nStarting Control Attestation workflow...`n`n");
                    }
                    [MessageData] $data = [MessageData]@{
                        Message     = ([Constants]::SingleDashLine + "`nWarning: `nPlease use utmost discretion when attesting controls. In particular, when choosing to not fix a failing control, you are taking accountability that nothing will go wrong even though security is not correctly/fully configured. `nAlso, please ensure that you provide an apt justification for each attested control to capture the rationale behind your decision.`n");
                        MessageType = [MessageType]::Warning;
                    };
                    $this.PublishCustomMessage($data)
                    $response = ""
                    if ($this.AttestationOptions.AttestationStatus -eq "ApprovedException" -and $this.AttestationOptions.IsExemptModeOn) {
                        $response = "Y"
                    }
                    while ($response.Trim() -ne "y" -and $response.Trim() -ne "n") {
                        if (-not [string]::IsNullOrEmpty($response)) {
                            Write-Host "Please select appropriate option."
                        }
                        $response = Read-Host "Do you want to continue (Y/N)"
                    }
                    if ($response.Trim() -eq "y") {
                        $svtControlAttestation.StartControlAttestation();
                    }
                    else {
                        $this.PublishCustomMessage("Exiting the control attestation process.")
                    }
                }
               else {
                   [MessageData] $data = [MessageData]@{
                       Message     = "You are currently logged in using PAT or you don't have the required permissions to perform control attestation. Control attestation using PAT is currently not supported. If you'd like to perform control attestation, please request your organization administrator to grant you 'Administrator' access.";
                       MessageType = [MessageType]::Error;
                   };
                   $this.PublishCustomMessage($data)
               }
            }
            catch {
                $this.CommandError($_);
            }
        }
    }

    #hidden [void] CheckAndDisableAzTelemetry()
	#{
	#	#Disable Az telemetry setting until scan is completed.
	#	#This has been added to improve the performarnce of scan commands
	#	#Telemetry will be re-enabled once scan is completed
    #    Disable-AzDataCollection  | Out-Null
#
    #}
    
    #hidden [void] CheckAndEnableAzTelemetry()
    #{
    #    #Enabled Az telemetry which got disabled at the start of command
    #    Enable-AzDataCollection  | Out-Null
    #}

    #Function to validate attestations parameters for BulkClear, multiple Control Ids, and baseline controls flag
    hidden [void] ValidateAttestationParameters()
    {
        if ($null -ne $this.AttestationOptions -and $this.AttestationOptions.AttestControls -eq [AttestControls]::NotAttested -and $this.AttestationOptions.IsBulkClearModeOn) {
            throw [SuppressedException] ("The 'BulkClear' option does not apply to 'NotAttested' controls.`n")
        }
        #check to limit multi controlids in the bulk attestation mode
        $ctrlIds = $this.ConvertToStringArray($this.ControlIdString);
        # Block scan if both ControlsIds and UBC/UPBC parameters contain values 
        if($null -ne $ctrlIds -and $ctrlIds.Count -gt 0 -and ($this.UseBaselineControls -or $this.UsePreviewBaselineControls)){
            throw [SuppressedException] ("Both the parameters 'ControlIds' and 'UseBaselineControls/UsePreviewBaselineControls' contain values. `nYou should use only one of these parameters.`n")
        }

         if ($null -ne $this.AttestationOptions -and (-not [string]::IsNullOrWhiteSpace($this.AttestationOptions.JustificationText) -or $this.AttestationOptions.IsBulkClearModeOn) -and ($ctrlIds.Count -gt 1 -or $this.UseBaselineControls)) {
			if($this.UseBaselineControls)
			{
				throw [SuppressedException] ("UseBaselineControls flag should not be passed in case of Bulk attestation. This results in multiple controls. `nBulk attestation mode supports only one controlId at a time.`n")
			}
			else
			{
				throw [SuppressedException] ("Multiple controlIds specified. `nBulk attestation mode supports only one controlId at a time.`n")
			}	
        }
    }
}