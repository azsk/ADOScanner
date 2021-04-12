Set-StrictMode -Version Latest

class SVTEvent
{
    #First level event

    #Command level event
    static [string] $CommandStarted = "AzSK.SVT.Command.Started"; #Initialize listeners #Function execution started
    static [string] $CommandCompleted = "AzSK.SVT.Command.Completed"; #Cleanup listeners #Function execution completed
    static [string] $CommandError = "AzSK.SVT.Command.Error";

    #Second level event for every resource
    static [string] $EvaluationStarted = "AzSK.SVT.Evaluation.Started"; #Individual Resource execution started
    static [string] $EvaluationCompleted = "AzSK.SVT.Evaluation.Completed"; #Individual Resource execution completed
    static [string] $EvaluationError = "AzSK.SVT.Evaluation.Error";

    #Control level events
    static [string] $ControlStarted = "AzSK.SVT.Control.Started"; #Individual control execution started
    static [string] $ControlCompleted = "AzSK.SVT.Control.Completed"; #Individual control execution completed
    static [string] $ControlError = "AzSK.SVT.Control.Error"; #Error while control execution
    static [string] $ControlDisabled = "AzSK.SVT.Control.Disabled"; #Event if control is in disabled mode

	#Resource and Control Level event
	static [string] $WriteInventory = "AzSK.SVT.WriteInventory"; #Custom event to write resource inventory
	static [string] $PostCredHygiene = "AzSK.SVT.Control.PostCredHygiene";
}

#Class for resource details 
class ResourceContext
{
	[string] $ResourceId =""
    [string] $ResourceGroupName = ""
    [string] $ResourceName = ""
    [string] $ResourceType = ""
	[hashtable] $ResourceMetadata = @{}
	[string] $ResourceTypeName = ""
	[hashtable] $ResourceGroupTags = @{}
	[PSObject] $ResourceDetails
	[psobject] $ResourceGroupDetails
}

class ControlResult
{
    [string] $ChildResourceName = "";

    [VerificationResult] $VerificationResult = [VerificationResult]::Manual;
    [VerificationResult] $ActualVerificationResult = [VerificationResult]::Manual;
	[SessionContext] $CurrentSessionContext = [SessionContext]::new();
	[AttestationStatus] $AttestationStatus = [AttestationStatus]::None;

	[StateManagement] $StateManagement = [StateManagement]::new();
	hidden [PSObject] $FixControlParameters = $null;
	hidden [bool] $EnableFixControl = $false;
	[bool] $IsControlInGrace;
	[DateTime] $FirstFailedOn = [Constants]::AzSKDefaultDateTime;
	[DateTime] $FirstScannedOn = [Constants]::AzSKDefaultDateTime;
	[int] $MaximumAllowedGraceDays=0;
	[String] $UserComments	
	[MessageData[]] $Messages = @();
	[int] $TimeTakenInMs	
	[DateTime] $ScanStartDateTime
	[DateTime] $ScanEndDateTime
	[String[]] $AdditionalInfo
	[bool] $IsResourceActive = $true;
	# If there is no usage history for resource or if it is Org/Project/User control then default value is set to -1.
	[int] $InactiveFromDays = -1;
	[String[]] $Exception = ""

	[void] LogException([System.Management.Automation.ErrorRecord] $exception)
	{
		$this.Exception = $exception[0].ToString() + $exception[0].InvocationInfo.PositionMessage
	}

    [void] AddMessage([MessageData] $messageData)
    {
        if((-not [string]::IsNullOrEmpty($messageData.Message)) -or ($null -ne $messageData.DataObject))
        {
            $this.Messages += $messageData;
        }
    }

    [void] AddMessage([VerificationResult] $result, [MessageData] $messageData)
    {
        $this.VerificationResult = $result;
        $this.AddMessage($messageData);
    }

    [void] AddMessage([VerificationResult] $result, [string] $message, [PSObject] $dataObject)
    {
        $this.VerificationResult = $result;
        $this.AddMessage([MessageData]::new($message, $dataObject));
    }

	[void] AddMessage([string] $message, [PSObject] $dataObject)
    {
        $this.AddMessage([MessageData]::new($message, $dataObject));
    }

	[void] AddMessage([PSObject] $dataObject)
    {
        $this.AddMessage([MessageData]::new($dataObject));
    }
	[void] AddMessage([string] $message)
    {
        $this.AddMessage([MessageData]::new($message));
    }

    [void] AddError([System.Management.Automation.ErrorRecord] $exception)
    {
        $this.AddMessage([MessageData]::new($exception, [MessageType]::Error));
    }

	[void] SetStateData([string] $message, [PSObject] $dataObject)
	{
		# We will convert state data to b64 here itself and use it in the same format throughout the framework for comparison with attested state data read from repo.
		$stateData = $dataObject | ConvertTo-Json -Depth 10
        $encodedStateData =[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($stateData))
		
		$this.StateManagement.CurrentStateData = [StateData]::new($message, $encodedStateData);
	}
}

class SessionContext
{
	[UserPermissions] $Permissions = [UserPermissions]::new();
	[bool] $IsLatestPSModule
}

class UserPermissions
{
	[bool] $HasAttestationWritePermissions = $false
	[bool] $HasAttestationReadPermissions = $false
	[bool] $HasRequiredAccess = $true;
}

class StateManagement
{
	[StateData] $AttestedStateData;
	[StateData] $CurrentStateData;
}

class Metadata
{
	[string] $Reference = ""
}

class StateData: MessageDataBase
{
	[string] $Justification = "";
	[string] $AttestedBy =""
	[DateTime] $AttestedDate
	[string] $ExpiryDate =""
	[string] $ApprovedExceptionID =""
	StateData()
	{
	}

	StateData([string] $message, [PSObject] $dataObject) :
		Base($message, $dataObject)
	{
	}
}

class SVTEventContext: AzSKRootEventArgument
{
	[string] $FeatureName = ""
    [Metadata] $Metadata
	[string] $PartialScanIdentifier;
    [ResourceContext] $ResourceContext;
	[ControlItem] $ControlItem;
    [ControlResult[]] $ControlResults = @();

	[bool] IsResource()
	{
		if($this.ResourceContext)
		{
			return $true;
		}
		else
		{
			return $false;
		}
	}

	[string] GetUniqueId()
	{
		$uniqueId = "";
		if($this.IsResource())
		{
			$uniqueId = $this.ResourceContext.ResourceId;
		}
		else
		{
			$uniqueId = $this.OrganizationContext.Scope;
		}

		# Unique Id validation
		if([string]::IsNullOrWhiteSpace($uniqueId))
		{
			throw "Error while evaluating Unique Id. The parameter 'ResourceContext.ResourceId' OR 'OrganizationContext.Scope' is null or empty."
		}

		return $uniqueId;
	}
}

#Keeping here temporarily (Aug2020) to remove dependency of AzSK (Azure) PS1 files (e.g., SubscriptionCore)
#Get rid/move to another place if still needed.
class TelemetryRBAC
{
	[string] $OrganizationName="";
	[string] $Scope="";
	[string] $DisplayName="";
	[string] $MemberType="";
	[string] $ObjectId="";
	[string] $ObjectType="";
	[string] $RoleAssignmentId="";
	[string] $RoleDefinitionId="";
	[string] $RoleDefinitionName="";
	[bool] $IsPIMEnabled;
	
}