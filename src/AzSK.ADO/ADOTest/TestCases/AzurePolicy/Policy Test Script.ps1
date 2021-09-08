$GitRepoPath = "" # Enter your local machine's policies github repo path
$ARMTemplatePath = "" # Enter your arm template folder path
$ResourceTypeNameList = @() # Enter resource type to be tested as an array eg. @("AnalysisServices", "Storage")
$SubscriptionId = "" # Enter sub id for creating test resources in azure
$CustomRGName = "" # Enter rg name for creating new resources. This rg name is used by arm template. Note that a "ptest-" prefix will be added to this name for identification. 

################### NO NEED TO UPDATE THIS: Creating custom variable for testing #################
# Custom RG name
$ResourceGroupName = "ptest-" + $CustomRGName + "-dev"
Write-Host "Your RG: $($ResourceGroupName)"
$ControlIdList = Get-ControlId-List-by-Resource-Type-Name -ResourceTypeNameList $ResourceTypeNameList
################### NO NEED TO UPDATE THIS: Creating custom variable for testing #################

# OPTION 1: Test policy definition for a single scope
$Scope = "/subscriptions/$($SubscriptionId)/resourceGroups/$($ResourceGroupName)"
$PolicyContext = Get-Policy-for-Controls -ControlIdList $ControlIdList -Scope $Scope -GitRepoPath $GitRepoPath


# OPTION 2: Test policy definition for a custom scope 
# $ControlIdListWithScope = @() # Enter control id and the scope for which you want test this control.
<#
    .Example

    Here is a sample value of ControlIdListWithScope

    ControlID                                                      Scope                                       
    ---------                                                      -----                                       
    Azure_LoadBalancer_Audit_Enable_Diagnostics_Log                /subscriptions/xxxxxxx-xxxx-xxxx-xxxx-xx...
    Azure_LoadBalancer_NetSec_Justify_PublicIPs                    /subscriptions/xxxxxxx-xxxx-xxxx-xxxx-xx...
    Azure_VNet_NetSec_Justify_PublicIPs                            /subscriptions/xxxxxxx-xxxx-xxxx-xxxx-xx...

    On converting ControlIdListWithScope PSobject to json..

    [
        {
            "ControlID":  "Azure_LoadBalancer_Audit_Enable_Diagnostics_Log",
            "Scope":  "/subscriptions/xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/ptest-policy-dev-rg"
        },
        {
            "ControlID":  "Azure_LoadBalancer_NetSec_Justify_PublicIPs",
            "Scope":  "/subscriptions/xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/resourceGroups/ptest-policy-dev-rg"
        }
    ]
#>
# Get policy context
# Note: Use ControlIdListWithScope to define custom scope of individual resources
# $ControlJson = ' [
#         {
#             "ControlID":  "Azure_LoadBalancer_Audit_Enable_Diagnostics_Log",
#             "Scope":  "/subscriptions/xxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
#         }
#     ]'
# 
# $ControlIdListWithScope = $ControlJson | ConvertFrom-Json
# $PolicyContext = Get-Policy-for-Controls -ControlIdListWithScope $ControlIdListWithScope -GitRepoPath $GitRepoPath



# Reset and prepare resource for testing
Reset-Target-Scope-for-Fresh-Test -ResetScope PolicyContext -DeleteResourceSetupForTesting -ResourceGroupName $ResourceGroupName -PolicyContexts $PolicyContext
Prepare-Resource-for-Testing-Policy -SubscriptionId $SubscriptionId -templateRoot $ARMTemplatePath -ResourceGroupName $ResourceGroupName -ControlIdList $ControlIdList #-AsJob #$ControlIdListWithScope.ControlID


# Reset policy definition and assignment for testing
# Reset-Target-Scope-for-Fresh-Test -ResetScope Subscription -DeleteDefinitionsAndAssignments -SubscriptionId $SubscriptionId 
Reset-Target-Scope-for-Fresh-Test -ResetScope PolicyContext -DeleteDefinitionsAndAssignments -PolicyContexts $PolicyContext #-Force
$DefinitionNames = Create-Policy-Definition-for-Policy-Context -PolicyContexts $PolicyContext
$AssignmentNames = Deploy-Policy-Context-To-Target-Scope -PolicyContexts $PolicyContext

# Trigger policy compliance scan and GRS scan [This step can take 5-10 minutes to complete]
# The trigger function runs scan as a job. Re-run this function to check status of the job. Once the job is complete, continue to next step (fetching policy and grs scan result).
# Note: To test pass/fail scenario, retrigger the scan from here. 
Trigger-Policy-Eval-For-Policy-Context -PolicyContexts $PolicyContext #-Force
$UpdatedPolicyContext = Trigger-GRS-Scan-for-Target-Scope-for-Policy-Context -PolicyContexts $PolicyContext #-Force

# Fetch result
$PolicyResult = Fetch-Policy-Status-of-Policy-Context -PolicyContexts $PolicyContext
# Note: UpdatedPolicyContext is required here. This updated context contains grs output folder to fetch scan result
$GRSResult = Get-GRS-Scan-Result-of-Policy-Context -PolicyContexts $UpdatedPolicyContext

Compare-and-Report -GrsResult $GRSResult -PolicyResult $PolicyResult
