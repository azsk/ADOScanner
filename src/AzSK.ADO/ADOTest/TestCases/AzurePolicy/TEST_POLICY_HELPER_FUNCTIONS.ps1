
<# 
    .Description
    This function returns an object which contains control name, policy rule (json format), parameters (json format) file and deployment scope for specified controls
    This function accepts multiple control id as an array (Sample $Obj = "" | Select-Object ControlId, Scope)
#>
function Get-Policy-for-Controls
{ 

    param (
        [Parameter(Mandatory = $true, ParameterSetName = "OnlyControls")]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $ControlIdList,

        [Parameter(Mandatory = $true, ParameterSetName = "OnlyControls")]
        [ValidateNotNullOrEmpty()]
        [String]
        $Scope,

        [Parameter(Mandatory = $true, ParameterSetName = "ControlsWithScope")]
        [ValidateNotNullOrEmpty()]
        [PSObject]
        $ControlIdListWithScope,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] 
        $GitRepoPath
    )
    $PoliciesObj = @()

    #region 1: Get all policy files in specified repo path
    if (-not [String]::IsNullOrEmpty($GitRepoPath))
    {
        # Get all file
        if (Test-Path -Path $GitRepoPath)
        {
            $Filelist = Get-ChildItem -Path $GitRepoPath -Recurse -File
            If ($null -ne $Filelist)
            {
                $Filelist = $Filelist.FullName
            }
            else
            {
                Write-Host "Policy json file not found." -ForegroundColor Red
                break;
            }
        }
        else
        {
            Write-Host "Git repo path is incorrect." -ForegroundColor Red
            break;
        }
    } 
    #endregion 1: Get all policy files in specified repo path

    #region 2: Map control id and scope if not done
    if (($ControlIdListWithScope | Measure-Object).Count -eq 0)
    {
        $ControlIdListWithScope = @()

        $ControlIdList | ForEach-Object { 
            $ControlId = $_
            $TempObj = "" | Select-Object ControlId, Scope
            $TempObj.ControlId = $ControlId
            if (-not [String]::IsNullOrEmpty($Scope))
            {
                $TempObj.Scope = $Scope
            }
            $ControlIdListWithScope += $TempObj
        }
        
    }
    #endregion 2: Map control id and scope if not done

    #region 3: Find file with matching control id and create obj to map control id, json path and scope 
    if (($ControlIdListWithScope.Count -gt 0) -and ($ControlIdListWithScope | Measure-Object).Count -gt 0)
    {
        $ControlIdListWithScope | ForEach-Object {
            # Reseting variable
            $ControlId = $null
            $_Scope = $null
            
            $ControlId = $_.ControlId
            $_Scope = $_.Scope
            if (-not [String]::IsNullOrEmpty($ControlId))
            {
                $MatchingFileList = $Filelist -match "$($ControlId)"
                if ($null -ne $MatchingFileList)
                {
                    $MatchingFileList | ForEach-Object {
                        $TempObj = [PolicyContext]::new()
                        $TempObj.ControlId = $ControlId
                        $TempObj.JsonPath = $_
                        $TempObj.Scope = $_Scope
    
                        $PoliciesObj += $TempObj
    
                    }
                }
                else
                {
                    $TempObj = [PolicyContext]::new()
                    $TempObj.ControlId = $ControlId
                    $TempObj.JsonPath = "Not Found."
                    $TempObj.Scope = $_Scope
    
                    $PoliciesObj += $TempObj
                }
            }
            
        }
    }
    #endregion 3: Find file with matching control id and create obj to map control id, json path and scope

    #region 4: Add policy rules, parameters, definition name and assignment name
    if (($PoliciesObj | Measure-Object).Count -gt 0)
    {
        $ReturnObj = @()
        $PoliciesObj | ForEach-Object {

            # Determine definition and assignment name
            if (-not [String]::IsNullOrEmpty($_.ControlId))
            {
                $_.DefinitionName = Get-Custom-Definition-Name -Name $_.ControlId   
            }
            else
            {
                Write-Host "Control id is null."
            }
            
            # Read policy json
            $JsonPath = $_.JsonPath
            #$Policy = "" | Select-Object PolicyRule, Parameter
            if (Test-Path -Path "$($JsonPath)")
            {
                $PolicyContent = Get-Content -Path $JsonPath -Raw | ConvertFrom-Json
                if ($PolicyContent | Get-Member -Name policyRule)
                {
                    $PolicyRule = ($PolicyContent.policyRule | ConvertTo-Json -Depth 10).ToString()
                    $_.PolicyRule = $PolicyRule
                }

                if ($PolicyContent | Get-Member -Name parameters)
                {
                    $Parameters = ($PolicyContent.parameters | ConvertTo-Json -Depth 10).ToString()
                    $_.Parameters = $Parameters
                }
            }
            
        }
    }
    else
    {
        Write-Host "File not found for the specified control id." -ForegroundColor Red
    }
    #endregion 4: Add policy rules, parameters, definition name and assignment name

    return $PoliciesObj

}

<#
    .Description
     This function removes definition and assignment created for testing
     Delete all the assignment and definition containing "PTest_" alias 
     Currently, this function deletes only the definition created at subscription and rg level. (management group not supported)

     In this function, user has the option to reset resources based on:
     1. subscription id specified in policycontext 
     2. a specific subscription id 
#>
function Reset-Target-Scope-for-Fresh-Test
{

    param (

        [Parameter(Mandatory = $true)]
        [ValidateSet("Subscription", "PolicyContext")]
        $ResetScope,

        [Parameter(Mandatory = $false, ParameterSetName = "ResetAllInSubscription")]
        [Parameter(Mandatory = $false, ParameterSetName = "ResetAllInPolicyContext")]
        [switch]
        $DeleteDefinitionsAndAssignments,

        [Parameter(Mandatory = $false, ParameterSetName = "ResetAllInSubscription")]
        [Parameter(Mandatory = $false, ParameterSetName = "ResetAllInPolicyContext")]
        [switch]
        $DeleteResourceSetupForTesting,

        [Parameter(Mandatory = $true, ParameterSetName = "ResetAllInSubscription")]
        [ValidateNotNullOrEmpty()]
        [String]
        $SubscriptionId,

        [Parameter(Mandatory = $true, ParameterSetName = "ResetAllInPolicyContext")]
        [ValidateNotNullOrEmpty()]
        [PSObject]
        $PolicyContexts,

        [ValidateNotNullOrEmpty()]
        [String]
        $ResourceGroupName,

        [switch]
        $Force
    )

    switch ($ResetScope)
    {
        "PolicyContext"
        { 
            #region Reset by policy context
            if (($PolicyContexts | Measure-Object).Count -gt 0)
            {
                $ScopeList = $PolicyContexts | Select-Object Scope -Unique
                $SubscriptionIdList = @()
                if (($ScopeList | Measure-Object).Count -gt 0)
                {
                    $ScopeList | ForEach-Object { 
                        $Scope = $_.Scope
                        if (-not [String]::IsNullOrEmpty($Scope))
                        {
                            $SubscriptionIdList += Get-Subscription-Id-From-Scope -Scope $Scope    
                        }
                    }
                }
                else
                {
                    Write-Host "Scope not found for the given policy context. "
                }
                
            }
            else
            {
                Write-Host "Policy context not found." -ForegroundColor Red
            }

            # Reset definitions and assignments created for testing
            if ($DeleteDefinitionsAndAssignments)
            {
                
                if (($ScopeList | Measure-Object).Count -gt 0)
                {
                    Write-Host "`n`r-------------------------------------------------------------------------"
                    # Remove assignment
                    $ScopeList | ForEach-Object { 
                        $Scope = $_.Scope
                        Reset-Assignments-for-Fresh-Test -Scope $Scope -Force:$Force
                    }
                    Write-Host "-------------------------------------------------------------------------"
                }
                
                
        
                if (($SubscriptionIdList | Measure-Object).Count -gt 0)
                {
                    Write-Host "`n`r-------------------------------------------------------------------------"
                    # Remove definition
                    $SubscriptionIdList | Select-Object -Unique | ForEach-Object { 
                        $SubscriptionId = $_
                        Reset-Definitions-for-Fresh-Test -SubscriptionId $SubscriptionId -Force:$Force
                    }
                    Write-Host "-------------------------------------------------------------------------"
                }
                
        
            }
   
            # Reset resources created for testing
            if ($DeleteResourceSetupForTesting)
            {
                if (($SubscriptionIdList | Measure-Object).Count -gt 0)
                {
                    # Remove definition
                    $SubscriptionIdList | Select-Object -Unique | ForEach-Object {
                        $SubscriptionId = $_
                        # TODO: Change logic
                        if (-not [String]::IsNullOrEmpty($ResourceGroupName))
                        {
                            Reset-Resource-Setup-for-Fresh-Test -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -Force:$Force
                        }
                        else
                        {
                            Reset-Resource-Setup-for-Fresh-Test -SubscriptionId $SubscriptionId -Force:$Force
                        }
                        
                    }
                }
                else
                {
                    Write-Host "Unable to reset scope. Subscription id not found." -ForegroundColor Red
                }
        
            }
            #endregion Reset by policy context

        }
        "Subscription"
        {
            if (-not [String]::IsNullOrEmpty($SubscriptionId))
            {
                # Reset definitions and assignments created for testing
                if ($DeleteDefinitionsAndAssignments)
                {
                    $ListOfDefinitionToBeDeleted = Get-Definitions-Created-For-Target-Scope -SubscriptionId $SubscriptionId
                    if (($ListOfDefinitionToBeDeleted | Measure-Object).Count -gt 0)
                    {
                        $ListOfAssignmentToBeDeleted = Get-Assignments-By-Policy-Definition-Id -PolicyDefinitionIds $ListOfDefinitionToBeDeleted.PolicyDefinitionId
                        if(($ListOfAssignmentToBeDeleted | Measure-Object).Count -gt 0)
                        {
                            Reset-Assignments-for-Fresh-Test -ListOfAssignmentToBeDeleted $ListOfAssignmentToBeDeleted -Force:$Force
                        }
                        Reset-Definitions-for-Fresh-Test -ListOfDefinitionToBeDeleted $ListOfDefinitionToBeDeleted -Force:$Force
                    }
                }
                # Reset resources created for testing
                if ($DeleteResourceSetupForTesting)
                {
                    # TODO: Change logic
                    if (-not [String]::IsNullOrEmpty($ResourceGroupName))
                    {
                        Reset-Resource-Setup-for-Fresh-Test -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -Force:$Force
                    }
                    else
                    {
                        Reset-Resource-Setup-for-Fresh-Test -SubscriptionId $SubscriptionId -Force:$Force
                    } 
                }
            }
            else
            {
                Write-Host "Subscription id not found." -ForegroundColor Red
            }
        }
    }

}

<#
    .Description
    Use this function to delete assignment.

    .Parameters

    ListOfAssignmentToBeDeleted
    This is an object which contains assignment details. Use Get-AzPolicyAssignment to fetch assignment details.

#>

function Reset-Assignments-for-Fresh-Test
{
    param (
        [Parameter(Mandatory = $true,ParameterSetName = "ByScope")]
        [ValidateNotNullOrEmpty()]
        [String]
        $Scope,

        [Parameter(Mandatory = $true, ParameterSetName = "ByAssignment")]
        [ValidateNotNullOrEmpty()]
        [PSObject[]]
        $ListOfAssignmentToBeDeleted,

        [switch]
        $Force
    )

    # ListOfAssignmentToBeDeleted is an object which contains assignment details. Use Get-AzPolicyAssignment to fetch assignment details.
    try
    {
        if (($ListOfAssignmentToBeDeleted | Measure-Object).Count -eq 0)
        {
            $ListOfAssignmentToBeDeleted = Get-Assignments-Created-For-Target-Scope -Scope $Scope;
        }
        $IsAssignmentPresent = ($ListOfAssignmentToBeDeleted | Measure-Object).Count -gt 0
        $UserInput = ''
        if (-not $Force -and ($IsAssignmentPresent))
        {
            Write-Host "`n`rDo you want to delete the listed assignment" -ForegroundColor Yellow -NoNewline
            $UserInput = Read-Host " [Y|N]" 
        }

        if ($UserInput -eq "Y" -or $Force) 
        {
            # Remove assignment
            if ($IsAssignmentPresent)
            {
                Write-Host "`n`r[+] Deleting assignment(s)..." -ForegroundColor Cyan
                $ListOfAssignmentToBeDeleted | ForEach-Object {
                    $Status = ''
                    $Status = Remove-AzPolicyAssignment -Name $($_.Name) -Scope $($_.Properties.scope) -ErrorAction Continue
                    Write-Host "$($_.Name): $($Status)"
                }
        
            }
        }
    }
    catch
    {
        Write-Host "$($_.Expection.Message)"
    }
    
}


<#
    .Description
    Use this function to get assignments created for a target scope.
#>
function Get-Assignments-Created-For-Target-Scope
{
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Scope       
    )

    # Verify scope in not null and is valid
    if (Test-Scope-Validity -Scope $Scope)
    {
        
        $ListOfAssignmentToBeDeleted = @()
        # List assignment id to be deleted

        # Fetch Assignments
        try
        {
            Write-Host "`n`r[+] Fetching assignment for [$Scope] scope..." -ForegroundColor Cyan
            $ExistingAssignment = Get-AzPolicyAssignment -Scope $Scope -ErrorAction Stop
        }
        catch
        {
            Write-Host "Please check that you specified a valid scope.`n`r$($_.Exception.Message)" -ForegroundColor Red
        }
        if (($ExistingAssignment | Measure-Object).Count -gt 0)
        {
            $ListOfAssignmentToBeDeleted = $ExistingAssignment | Where { $_.Name -match "PTest_" }
        }

        # List Assignments
        Write-Host "[-] Assignments to be deleted:" -ForegroundColor Cyan
        $IsAssignmentPresent = ($ListOfAssignmentToBeDeleted | Measure-Object).Count -gt 0
        if ($IsAssignmentPresent)
        {
            $ListOfAssignmentToBeDeleted.Name | Out-Host;
            return $ListOfAssignmentToBeDeleted
        }
        else
        {
            Write-Host "No assignment found." -ForegroundColor Yellow
            return $null
        }
    }

    
}


<#
    .Description
    Use this function to get assignments by policy definition ids.
#>
function Get-Assignments-By-Policy-Definition-Id
{
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $PolicyDefinitionIds       
    )

    $ListOfAssignmentToBeDeleted = @()
        # List assignment id to be deleted

        # Fetch Assignments
        try
        {
            $ExistingAssignment = @()
            Write-Host "`n`r[+] Fetching assignment by definition id..." -ForegroundColor Cyan
            $PolicyDefinitionIds | ForEach-Object {
                $PolicyDefinitionId = $_
                $ExistingAssignment += Get-AzPolicyAssignment -PolicyDefinitionId $PolicyDefinitionId -ErrorAction Continue
            }
            
        }
        catch
        {
            Write-Host "Please check that you specified a valid scope.`n`r$($_.Exception.Message)" -ForegroundColor Red
        }
        if (($ExistingAssignment | Measure-Object).Count -gt 0)
        {
            $ListOfAssignmentToBeDeleted = $ExistingAssignment | Where { $_.Name -match "PTest_" }
        }

        # List Assignments
        Write-Host "[-] Assignments to be deleted:" -ForegroundColor Cyan
        $IsAssignmentPresent = ($ListOfAssignmentToBeDeleted | Measure-Object).Count -gt 0
        if ($IsAssignmentPresent)
        {
            $ListOfAssignmentToBeDeleted.Name | Out-Host;
            return $ListOfAssignmentToBeDeleted
        }
        else
        {
            Write-Host "No assignment found." -ForegroundColor Yellow
            return $null
        }

    
}


<#
    .Description
    Use this function to delete definitions created in a subscription
    
    .Parameters

    ListOfDefinitionToBeDeleted
    This is an object which contains definition details. Use Get-AzPolicyDefinition to fetch definition details.

#>
function Reset-Definitions-for-Fresh-Test
{
    param (
        [Parameter(Mandatory = $true, ParameterSetName = "BySubscriptionId")]
        [ValidateNotNullOrEmpty()]
        [String]
        $SubscriptionId,

        [Parameter(Mandatory = $true, ParameterSetName = "ByDefinition")]
        [ValidateNotNullOrEmpty()]
        [PSObject[]]
        $ListOfDefinitionToBeDeleted,

        [switch]
        $Force
    )

    try
    {
        # List definition id to be deleted

        if ((($ListOfDefinitionToBeDeleted | Measure-Object).Count -eq 0) -and (-not [String]::IsNullOrEmpty($SubscriptionId)))
        {
            $ListOfDefinitionToBeDeleted = Get-Definitions-Created-For-Target-Scope -SubscriptionId $SubscriptionId; 
        }
        $IsDefinitionPresent = ($ListOfDefinitionToBeDeleted | Measure-Object).Count -gt 0
        $UserInput = ''
        if (-not $Force -and ($IsDefinitionPresent))
        {
            Write-Host "`n`rDo you want to delete the listed defintion" -ForegroundColor Yellow -NoNewline
            $UserInput = Read-Host " [Y|N]" 
        }

        if ($UserInput -eq "Y" -or $Force) 
        {
            # Remove definition
            if ($IsDefinitionPresent)
            {
                Write-Host "`n`r[+] Deleting definition(s)..." -ForegroundColor Cyan
                $ListOfDefinitionToBeDeleted | ForEach-Object {
                    $Status = Remove-AzPolicyDefinition -Name $_.Name -SubscriptionId $_.SubscriptionId -Force -ErrorAction Continue
                    Write-Host "$($_.Name): $($Status)"
                }
            }
        }
    }
    catch
    {
        Write-Host "$($_.Expection.Message)"
    }
}

<#
    .Description
    Use this function to get policy definition in a subscription
#>
function Get-Definitions-Created-For-Target-Scope
{
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $SubscriptionId        
    )

    $ListOfDefinitionToBeDeleted = @()

    #Validate sub id
    if (-not [String]::IsNullOrEmpty($SubscriptionId))
    {
        $SubDetails = Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
        if (($SubDetails | Measure-Object).Count -eq 0)
        {
            Write-Host "Unable to read subscription context. Please check that the specified scope is correct and you have access to the subscription." -ForegroundColor Red                
        }
        else
        {
            # List definition id to be deleted

            # Fetch Definitions
            Write-Host "`n`r[+] Fetching definition created at [$SubscriptionId] subscription level..." -ForegroundColor Cyan
            $ExistingDefinition = Get-AzPolicyDefinition -SubscriptionId $SubscriptionId
            if (($ExistingDefinition | Measure-Object).Count -gt 0)
            {
                $ListOfDefinitionToBeDeleted = $ExistingDefinition | Where { $_.Name -match "PTest_" }
            }

            # List Definitions
            Write-Host "[-] Definitions to be deleted:" -ForegroundColor Cyan
            $IsDefinitionPresent = ($ListOfDefinitionToBeDeleted | Measure-Object).Count -gt 0
            if ($IsDefinitionPresent)
            {
                $ListOfDefinitionToBeDeleted.Name | Out-Host ;
                return $ListOfDefinitionToBeDeleted 
            }
            else
            {
                Write-Host "No definition found." -ForegroundColor Yellow
                return $null
            }
        }
    }
}


<#
    .Description
    Use this function to delete resources created for testing
#>
function Reset-Resource-Setup-for-Fresh-Test
{
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $SubscriptionId,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ResourceGroupName,

        [switch]
        $Force
    )

    Set-AzContext -SubscriptionId $SubscriptionId
    if (-not [String]::IsNullOrEmpty($ResourceGroupName))
    {
        $RGList = Get-AzResourceGroup -Name "$($ResourceGroupName)" -ErrorAction SilentlyContinu
    }
    else
    {
        $RGList = Get-AzResourceGroup -Name "ptest-*" -ErrorAction SilentlyContinu
    }
    
    if (($RGList | Measure-Object).Count -gt 0)
    {
        Write-Host "`n`r[+] Deleting the below resource group:" -ForegroundColor Cyan
        $($RGList.ResourceGroupName) | Out-Host
        $UserInput = ''
        if (-not $Force)
        {
            Write-Host "`n`rDo you want to delete the listed resource group" -ForegroundColor Yellow -NoNewline
            $UserInput = Read-Host " [Y|N]" 
        }
        if ($UserInput -eq "Y" -or $Force) 
        {
            $RGList | Remove-AzResourceGroup -Force
        }
    }
    else
    {
        Write-Host "RG not found." -ForegroundColor Yellow
    }
}

function Test-Scope-Validity
{
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Scope,

        [switch]
        $ExitIfNotExist
    )

    $IsValid = $false
    
    if (($Scope -match "/resourceGroups/") -and ($Scope.Split("/").Count -ge 5 ))
    {
        # Check if user has access to the resource group in scope
        $ResourceGroupName = $Scope.Split("/")[4]

        if (-not [String]::IsNullOrEmpty($ResourceGroupName))
        {
            $RGDetails = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
            if (($RGDetails | Measure-Object).Count -eq 0)
            {
                Write-Host "Unable to find resource group. Please check that the specified scope is correct and you have access to the resource group." -ForegroundColor Red
                if ($ExitIfNotExist)
                {
                    break;
                }
                
            }
            else
            {
                $IsValid = $true
            }
        }
    }
    
    elseif (-not [String]::IsNullOrEmpty($Scope) -and ($Scope.Split("/").Count -ge 3))
    {
        # Check if user has access to the subscription in scope
        $SubscriptionId = $Scope.Split("/")[2]
        if (-not [String]::IsNullOrEmpty($SubscriptionId))
        {
            $SubDetails = Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
            if (($SubDetails | Measure-Object).Count -eq 0)
            {
                Write-Host "Unable to read subscription context. Please check that the specified scope is correct and you have access to the subscription." -ForegroundColor Red
                if ($ExitIfNotExist)
                {
                    break;
                }
                
            }
            else
            {
                $IsValid = $true
            }
        }
    }
    else
    {
        Write-Host "Please enter a valid scope" -ForegroundColor Red
        if ($ExitIfNotExist)
        {
            break;
        }
    }

    return $IsValid
    
}

function Get-Subscription-Id-From-Scope
{
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Scope,

        [switch]
        $ExitIfNotExist
    )

    # Verify scope in not null and read sub id from scope
    if (-not [String]::IsNullOrEmpty($Scope) -and ($Scope.Split("/").Count -ge 3))
    {
        $SubscriptionId = $Scope.Split("/")[2]
        if (-not [String]::IsNullOrEmpty($SubscriptionId))
        {
            $SubDetails = Get-AzSubscription -SubscriptionId $SubscriptionId -ErrorAction SilentlyContinue
            if (($SubDetails | Measure-Object).Count -eq 0)
            {
                Write-Host "Unable to read subscription context. Please check that the specified scope is correct and you have access to the subscription." -ForegroundColor Red
                if ($ExitIfNotExist)
                {
                    break;
                }
                
            }
            else
            {
                return $SubDetails.Id
            }
        }
    }
    else
    {
        Write-Host "Please enter a valid scope" -ForegroundColor Red
        if ($ExitIfNotExist)
        {
            break;
        }
    }
    
}

function Get-Resource-Group-Name-From-Scope
{
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Scope,

        [switch]
        $ExitIfNotExist
    )

    # Verify scope in not null and read sub id from scope
    if (-not [String]::IsNullOrEmpty($Scope))
    {
        if (($Scope -match "/resourceGroups/") -and ($Scope.Split("/").Count -ge 5 ))
        {
            $ResourceGroupName = $Scope.Split("/")[4]
        }
        
        if (-not [String]::IsNullOrEmpty($ResourceGroupName))
        {
            $RGDetails = Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue
            if (($RGDetails | Measure-Object).Count -eq 0)
            {
                Write-Host "Unable to find resource group. Please check that the specified scope is correct and you have access to the resource group." -ForegroundColor Red
                if ($ExitIfNotExist)
                {
                    break;
                }
                
            }
            else
            {
                return $RGDetails.ResourceGroupName
            }
        }
    }
    else
    {
        Write-Host "Please enter a valid scope" -ForegroundColor Red
        if ($ExitIfNotExist)
        {
            break;
        }
    }
    
}

# Create policy definition
# Required inputs: policy rule json and subscription id
# Optional input: parameters json for policy, definition name and description.
# If definition name is not provide, the defintion is created as "PTest_Definition_XXX"
function Create-Policy-Definition
{
    param (
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DefinitionName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $SubscriptionId,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $PolicyRule,
        
        [String]
        [ValidateNotNullOrEmpty()]
        $Parameters,

        [String]
        [ValidateNotNullOrEmpty()]
        $Description
        
    )
 
    try
    {

        # Policy definition name
        if ($DefinitionName -notmatch "PTest_")
        {
            $DefinitionName = Get-Custom-Definition-Name -Name $DefinitionName
        }

        if ([String]::IsNullOrEmpty($Description))
        {
            $Description = "This is a test policy"
        }
        
        # Create a policy definition
        Write-Host "[+] Creating policy definition [$($DefinitionName)].." -ForegroundColor Cyan
        
        # $DefinitionObject = New-AzPolicyDefinition -Mode All -Name $DefinitionName `
        #     -DisplayName $DefinitionName `
        #     -Description $Description `
        #     -Policy $PolicyRule `
        #     -SubscriptionId $SubscriptionId `
        #     -ErrorAction Stop

        # Add support for parameters
        if (-not [String]::IsNullOrEmpty($Parameters))
        {
            $DefinitionObject = New-AzPolicyDefinition -Mode All -Name $DefinitionName `
                -DisplayName $DefinitionName `
                -Description $Description `
                -Policy $PolicyRule `
                -Parameter $Parameters `
                -SubscriptionId $SubscriptionId `
                -ErrorAction Stop
        }
        else
        {
            $DefinitionObject = New-AzPolicyDefinition -Mode All -Name $DefinitionName `
                -DisplayName $DefinitionName `
                -Description $Description `
                -Policy $PolicyRule `
                -SubscriptionId $SubscriptionId `
                -ErrorAction Stop
        }

        
        
    }
    catch
    {
        Write-Host "Failed to create policy defintion. $($_.Exception.Message)" -ForegroundColor Red
    }    
    
    if (($DefinitionObject | Measure-Object).Count -gt 0)
    {
        Write-Host "Successfully created the definition" -ForegroundColor Green
        return $DefinitionObject.Name
    }
    
}

function Create-Policy-Definition-for-Policy-Context
{
    param (
        [Parameter(Mandatory = $true)]
        [PSObject[]]
        $PolicyContexts
    )

    $DefinitionList = @()
    Write-Host "`n`r[+] Creating definition for the specified policy context...`n`r" -ForegroundColor Cyan
    if ( ($PolicyContexts | Measure-Object).Count -gt 0)
    {
        $PolicyContexts | ForEach-Object {

            Write-Host "-------------------------------------------------------------------------"

            if ((-not [String]::IsNullOrEmpty($_.Scope)))
            {
                $SubscriptionId = Get-Subscription-Id-From-Scope -Scope $_.Scope
            }
            
            if ((-not [String]::IsNullOrEmpty($SubscriptionId)) -and (-not [String]::IsNullOrEmpty($_.DefinitionName)) -and (-not [String]::IsNullOrEmpty($_.PolicyRule)))
            {
                $Command = "Create-Policy-Definition -SubscriptionId $($SubscriptionId) -DefinitionName $($_.DefinitionName) -PolicyRule '" + $($_.PolicyRule) + "'";
                if (-not [String]::IsNullOrEmpty($_.Parameters) -and (($_.Parameters | ConvertFrom-Json | GM -MemberType NoteProperty | Measure-Object).Count -gt 0))
                {
                    $Command += " -Parameters '" + $($_.Parameters) + "'"
                }
                $DefinitionList += Invoke-Expression -Command $Command
            }
            else
            {
                Write-Host "`n`r[-] Definition [$($_.DefinitionName)] not created.`n`r[-] One of subscription id, definition name or policy rule is null." -ForegroundColor Red
            }
            Write-Host "-------------------------------------------------------------------------"
        }
    }
    else
    {
        Write-Host "No data found in policy context." -ForegroundColor Red
    }
    return $DefinitionList
}

function Deploy-Policy-To-Target-Scope
{
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Scope,        

        [Parameter(Mandatory = $true)]
        [String[]]
        $DefinitionNames
    )

    $SuccessfullyAssignedPolicies = @()
    if (($DefinitionNames | Measure-Object).Count -gt 0)
    {
        $DefinitionNames | ForEach-Object { 
            try
            {
                $DefinitionName = $_
                $PolicyDefinition = Get-AzPolicyDefinition -Name $DefinitionName -ErrorAction SilentlyContinue
                if ($null -ne $PolicyDefinition)
                {
                    Write-Host "[+] Assigning policy definition [$($DefinitionName)] to [$($Scope)].." -ForegroundColor Cyan
                    $AssignmentName = $DefinitionName + "_A"
                    $Description = "This is a test policy"
                    $AssignmentObject = New-AzPolicyAssignment -Name $AssignmentName `
                        -Scope $Scope `
                        -Description $Description `
                        -PolicyDefinition $PolicyDefinition -ErrorAction Stop
                }
                else
                {
                    Write-Host "[+] Failed to assign policy. Policy definition [$($DefinitionName)] not found." -ForegroundColor Red
                }
            }
            catch
            {
                Write-Host "[+] Failed to assign policy. $($_.Exception.Message)" -ForegroundColor Red
            }

            if (($AssignmentObject | Measure-Object).Count -gt 0)
            {
                Write-Host "Successfully assigned the policy" -ForegroundColor Green
                $SuccessfullyAssignedPolicies += $AssignmentObject.Name
            }
        }
    }

    return $SuccessfullyAssignedPolicies
}

function Deploy-Policy-Context-To-Target-Scope
{
    param (
        [Parameter(Mandatory = $true)]
        [PSObject[]]
        $PolicyContexts
    )

    $SuccessfullyAssignedPolicies = @()
    Write-Host "`n`r[+] Assigning policy to the specified scope for the specified policy context...`n`r" -ForegroundColor Cyan
    if (($PolicyContexts | Measure-Object).Count -gt 0)
    {
        $PolicyContexts | ForEach-Object {
            Write-Host "-------------------------------------------------------------------------"
            if (-not [String]::IsNullOrEmpty($_.Scope))
            {
                $SuccessfullyAssignedPolicies += Deploy-Policy-To-Target-Scope -Scope $_.Scope -DefinitionNames $_.DefinitionName
            }
            else
            {
                Write-Host "[-] Assignment not created as the scope is null." -ForegroundColor Red
            }
            
            Write-Host "-------------------------------------------------------------------------"
        }
    }
    return $SuccessfullyAssignedPolicies
}

# On demand policy trigger 
# It can take 5 minutes to trigger policy
function Trigger-Policy-Eval-For-Target-Scope
{ 
    param (
        
        [Parameter(Mandatory = $true)]
        [Alias("sid")]
        [String]
        $SubscriptionId,
        
        [Alias("rgn")]
        [String]
        $ResourceGroupName,

        [Switch]
        $Force

    ) 
    
    #region    : Script block to trigger policy evaluation
    $ScriptBlock = { 
        
        param (
            [String]
            $Uri
        )
        try
        {
            Write-Host "[+] Triggering evalution scan.." -ForegroundColor Cyan
            $accessToken = Get-AzSKAccessToken -ResourceAppIdURI "https://management.azure.com/"
            if (-not [String]::IsNullOrEmpty($accessToken))
            {
                $AsynTriggerResponse = Invoke-WebRequest -UseBasicParsing `
                    -Uri $Uri `
                    -Headers @{"Authorization" = "Bearer $accessToken" } `
                    -Method Post -ErrorAction Stop

                Write-Host "[-] It can take 5 minutes for resource evaluation to complete.." -ForegroundColor Cyan

                if (($AsynTriggerResponse | Measure-Object).Count -gt 0)
                {
                    $continue = $true
                    $loopCount = 1
                    while ($continue)
                    {
                        $Uri = $AsynTriggerResponse.Headers.Location
                        $LocationAPIResponse = Invoke-WebRequest -UseBasicParsing `
                            -Uri $Uri `
                            -Headers @{"Authorization" = "Bearer $accessToken" } `
                            -Method Get -ErrorAction Stop

                        if (($LocationAPIResponse | Measure-Object).Count -gt 0)
                        {
                            switch ($LocationAPIResponse.StatusCode)
                            {
                                200
                                { 
                                    Write-Host "`n`rEvaluation of resources completed successfully." -ForegroundColor Green
                                    $continue = $false
                                }
                                202
                                {
                                    Write-Host "$($loopCount).." -NoNewline
                                    $continue = $true
                                    sleep 60
                                    
                                    $loopCount = $loopCount + 1
                                    
                                }
                                Default
                                {
                                    Write-Host "`n`rSomething went wrong while policy evaluation. Please try again." -ForegroundColor Red
                                    $LocationAPIResponse;
                                    $continue = $false
                                }
                            }
                        }
                    }
        
                }   
            }
            else
            {
                Write-Host "Access token could not be generated for Rest API." -ForegroundColor Red
            }
        }
        catch
        {
            Write-Host "$($_.Exception.Message)" -ForegroundColor Red
        }
    }
    #endregion : Script block to trigger policy evaluation

    $JobName = "OnDemandEvaluationScan"
    if (-not [String]::IsNullOrEmpty($ResourceGroupName))
    {
        $JobName = $JobName + "-" + $ResourceGroupName
        $Uri = "https://management.azure.com/subscriptions/$($SubscriptionId)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.PolicyInsights/policyStates/latest/triggerEvaluation?api-version=2018-07-01-preview"
    }
    else
    {
        $JobName = $JobName + "-" + $SubscriptionId
        $Uri = "https://management.azure.com/subscriptions/$($SubscriptionId)/providers/Microsoft.PolicyInsights/policyStates/latest/triggerEvaluation?api-version=2018-07-01-preview"
    }
    if ($(Get-Job -Name $JobName -ErrorAction SilentlyContinue) -and (-not $Force))
    {
        Get-Job -Name $JobName | FT Id, State, Name | Out-Host
        # Removing old jobs
        $OldJobs = Get-Job -Name $JobName | Sort-Object PSBeginTime -Descending | Select -Skip 1 
        if (($OldJobs | Measure-Object).Count -gt 0)
        {
            $OldJobs | Remove-Job -ErrorAction SilentlyContinue
        }
         
    }
    else
    {
        Start-Job -Name $JobName -ScriptBlock $ScriptBlock -ArgumentList $Uri | FT Id, State, Name | Out-Host
    } 
}

function Trigger-Policy-Eval-For-Policy-Context
{
    param (
        [Parameter(Mandatory = $true)]
        [PSObject[]]
        $PolicyContexts,

        [switch]
        $Force
    )

    if (($PolicyContexts | Measure-Object).Count -gt 0)
    {
        $ScopeList = $PolicyContexts | Where-Object { -not [String]::IsNullOrEmpty($_.Scope) } | Select-Object Scope -Unique
        if (($ScopeList.Scope | Measure-Object).Count -gt 0) {
            $ScopeList.Scope | ForEach-Object { 
                $Scope = $_
                $SubscriptionId = Get-Subscription-Id-From-Scope -Scope $Scope
                if (($Scope.Split("/").Count -ge 5) -and ($Scope.Split("/") -contains "resourceGroups"))
                {
                    $ResourceGroupName = Get-Resource-Group-Name-From-Scope -Scope $Scope
                }
                
                if (-not [String]::IsNullOrEmpty($SubscriptionId) -and -not [String]::IsNullOrEmpty($ResourceGroupName))
                {
                    Trigger-Policy-Eval-For-Target-Scope -SubscriptionId $($SubscriptionId) -ResourceGroupName $($ResourceGroupName) -Force:$Force
                }
                elseif (-not [String]::IsNullOrEmpty($SubscriptionId))
                {
                    Trigger-Policy-Eval-For-Target-Scope -SubscriptionId $($SubscriptionId) -Force:$Force
                }
            
            }
        }
        else {
            Write-Host  "Policy not triggered as the scope is null."
        }
        
    }
    
}

function Fetch-Policy-Status-For-Target-Scope
{
    param (

        [Parameter(Mandatory = $false, ParameterSetName = "AssignmentName")]
        [Parameter(Mandatory = $true, ParameterSetName = "Assignment")]
        [String[]]
        $AssignmentNames,

        [Parameter(Mandatory = $false, ParameterSetName = "Assignment")]
        [String]
        $SubscriptionId,

        [Parameter(Mandatory = $false, ParameterSetName = "Assignment")]
        [String]
        $ResourceGroupName,

        [Parameter(Mandatory = $true, ParameterSetName = "ResourceId")]
        [String]
        $ResourceId,

        [Parameter(Mandatory = $true, ParameterSetName = "ManagementGroupName")]
        [String]
        $ManagementGroupName
    )
 
    $PolicyResult = @()
    $Command = "Get-AzPolicyState"

    if (-not [String]::IsNullOrEmpty($ManagementGroupName))
    {
        $Command += " -ManagementGroupName $($ManagementGroupName)"
    }
    
    if (-not [String]::IsNullOrEmpty($SubscriptionId))
    {
        $Command += " -SubscriptionId $($SubscriptionId)"
    }
    
    if (-not [String]::IsNullOrEmpty($ResourceGroupName))
    {
        $Command += " -ResourceGroupName $($ResourceGroupName)"
    }

    if (-not [String]::IsNullOrEmpty($ResourceId))
    {
        $Command += " -ResourceId $($ResourceId)"
    }

    Write-Host "-------------------------------------------------------------------------"
    if (($AssignmentNames | Measure-Object).Count -gt 0)
    {
        $AssignmentNames | ForEach-Object {
            $AssignmentName = $_
            if (-not [String]::IsNullOrEmpty($AssignmentName))
            {
                $Command += " -PolicyAssignmentName $($AssignmentName)"
                Write-Host "[+] Fetching policy status of [$($AssignmentName)] assignment..." -ForegroundColor Cyan
                $PolicyResult += Invoke-Expression -Command $Command
            }
        }

    }

    if (($PolicyResult | Measure-Object).Count -eq 0)
    {
        Write-Host "[-] No resources were scanned." -ForegroundColor Red
    }
    else
    {
        Write-Host "[-] Completed fetching policy result. Total count of the result returned: $(($PolicyResult | Measure-Object).Count)" -ForegroundColor Green  
    }

    Write-Host "-------------------------------------------------------------------------"

    return $PolicyResult 
}

function Fetch-Policy-Status-of-Policy-Context
{
    param (
        [Parameter(Mandatory = $true)]
        [PSObject[]]
        $PolicyContexts
    )

    $policyResult = @()
    if (($PolicyContexts | Measure-Object).Count -gt 0)
    {
        $PolicyContexts | ForEach-Object {

            # Reseting the variables for next assignment scan
            $SubscriptionId = $null
            $ResourceGroupName = $null
            $Scope = $null
            $Command = $null

            $Scope = $_.Scope
            $SubscriptionId = Get-Subscription-Id-From-Scope -Scope $Scope
            if (($Scope.Split("/").Count -ge 5) -and ($Scope.Split("/") -contains "resourceGroups"))
            {
                $ResourceGroupName = Get-Resource-Group-Name-From-Scope -Scope $Scope
            }
            $AssignmentName = $($_.DefinitionName + "_A")
            if (-not [String]::IsNullOrEmpty($SubscriptionId))
            {
                $Command = "Fetch-Policy-Status-For-Target-Scope -SubscriptionId $($SubscriptionId) -AssignmentName $($AssignmentName)"
                if (-not [String]::IsNullOrEmpty($ResourceGroupName))
                {
                    $Command += " -ResourceGroupName $($ResourceGroupName)"
                }
                $policyResult += Invoke-Expression -Command $Command
            }
        }
    }
    return $policyResult
}

<#
    .Description
    Use this function to trigger GRS scan for a given scope
    The scan is triggered as a background job. Once the job completes, this function returns output folder path
    Use -Force to trigger a fresh scan for a given scope
#>

function Trigger-GRS-Scan-for-Target-Scope
{
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $SubscriptionId,
        
        [String[]]
        $ControlIdList,

        [ValidateNotNullOrEmpty()]
        [String]
        $ResourceNames,

        [ValidateNotNullOrEmpty()]
        [String]
        $ResourceGroupNames,

        [Switch]
        $Force

    )

    $Command = "Get-AzSKAzureServicesSecurityStatus -SubscriptionId $($SubscriptionId)"
    $JobName = "GRSScan_Sub_" + $($SubscriptionId.Substring(0, 8))

    if (-not [String]::IsNullOrEmpty($ResourceGroupNames))
    {
        $Command += " -ResourceGroupNames $($ResourceGroupNames)"
        $JobName = "GRSScan_Rg_" + $($ResourceGroupNames) 
    }

    if (-not [String]::IsNullOrEmpty($ResourceNames))
    {
        $Command += " -ResourceNames $($ResourceNames)"
        $JobName = "GRSScan_Resource_" + $($ResourceNames)
    }

    if (($ControlIdList | Measure-Object).Count -gt 0)
    {
        $ControlIds = $ControlIdList -join ","
        $Command += " -ControlIds '" + $($ControlIds) + "'"
        $JobName = $JobName + "_Control_" + $($ControlIds)
    }

    $ScriptBlock = {
        param (
            [String]
            $Command
        )
        Write-Host "[+] Triggering GRS scan.." -ForegroundColor Cyan
        $grsoutput = Invoke-Expression -Command $Command
        return $grsoutput
    }
    
    Write-host "COMMAND: $($Command)" -ForegroundColor Cyan
    Write-host "WARNING: If the job fails, you copy the above command re-run in your current powershell session" -ForegroundColor Yellow
    Write-host "To fetch scan result, run - `$GRSResult = Get-Content -Path '<GRSCMDLET_OUTPUTPATH>\XXXXXXXXX_XXXXXX_GRS\SecurityReport-XXXXXXXX_XXXXXX.csv' | ConvertFrom-Csv" -ForegroundColor Yellow

    if ($(Get-Job -Name $JobName -ErrorAction SilentlyContinue) -and (-not $Force))
    {
        try
        {
            $CompletedJob = Get-Job -Name "$($JobName)" | Where-Object { $_.State -eq "Completed" } | Sort-Object PSBeginTime -Descending | Select -First 1
        }
        catch
        {
            # This block is intentionally left blank to handle exception while fetching job details
        }
        
        if (($CompletedJob | Measure-Object).Count -gt 0)
        {
            Write-Host "GRS scan completed. Returning result..." -ForegroundColor Green
            $Job = Receive-Job -Id $CompletedJob.Id -Keep -OutVariable outputFolder
            return $outputFolder
        }
        else
        {
            Write-Host "[+] Found existing job. Here is the job status:" -ForegroundColor Cyan
            $Job = Get-Job -Name "$($JobName)" | Sort-Object PSBeginTime -Descending | Select -First 1
            $Job | FT Id, State, Name | Out-Host
            return $null
        }
       
    }
    else
    {
        Write-Host "[+] Starting GRS scan for the specified scope..." -ForegroundColor Cyan
        if (Get-Job -Name "$($JobName)" -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Completed" })
        {
            Get-Job -Name "$($JobName)" -ErrorAction SilentlyContinue | Where-Object { $_.State -eq "Completed" } | Remove-Job -ErrorAction SilentlyContinue
        }
        
        $Job = Start-Job -Name $JobName -ScriptBlock $ScriptBlock -ArgumentList $Command
        $Job | FT Id, State, Name | Out-Host
        # Sleep mode is being used here to avoid creating same folder name for two grs scan
        Write-Host "Waiting 60 seconds before triggering next job..." -ForegroundColor Yellow
        sleep 60
        return $null
    }
    
}

function Trigger-GRS-Scan-for-Target-Scope-for-Policy-Context
{
    param (
        [Parameter(Mandatory = $true)]
        [PSObject[]]
        $PolicyContexts,

        [switch]
        $Force
    )

    $SuccessCounter = 0
    if (($PolicyContexts | Measure-Object).Count -gt 0)
    {
        $PolicyContexts | Group-Object Scope | ForEach-Object {

            Write-Host "`n`r-------------------------------------------------------------------------"
            Write-Host "[+] Triggering GRS scan for [$($_.Name)]..." -ForegroundColor Cyan
            $Scope = $_.Name
            $ControlIdList = @()
            $_.Group | ForEach-Object { $ControlIdList += $_.ControlId }
            $ControlIdList = $ControlIdList | Select-Object -Unique
            if (-not [String]::IsNullOrEmpty($Scope))
            {
                $SubscriptionId = Get-Subscription-Id-From-Scope -Scope $Scope
                if (($Scope.Split("/").Count -ge 5) -and ($Scope.Split("/") -contains "resourceGroups"))
                {
                    $ResourceGroupName = Get-Resource-Group-Name-From-Scope -Scope $Scope
                }
            }

            if (-not [String]::IsNullOrEmpty($SubscriptionId) -and (($ControlIdList | Measure-Object).Count -gt 0))
            {
                if (-not [String]::IsNullOrEmpty($ResourceGroupName))
                {
                    $GRSOutputFolder = Trigger-GRS-Scan-for-Target-Scope -SubscriptionId $($SubscriptionId) -ControlIdList $($ControlIdList)  -ResourceGroupName $($ResourceGroupName) -Force:$Force
                }
                else
                {
                    $GRSOutputFolder = Trigger-GRS-Scan-for-Target-Scope -SubscriptionId $($SubscriptionId) -ControlIdList $($ControlIdList) -Force:$Force
                }
                if (-not [String]::IsNullOrEmpty($GRSOutputFolder))
                {
                    $PolicyContexts | Where-Object { $_.Scope -eq $Scope } | ForEach-Object {
                        if ($_ | GM -MemberType NoteProperty -Name "GRSOutputFolder")
                        {
                            $_.GRSOutputFolder = $GRSOutputFolder
                            $SuccessCounter = $SuccessCounter + 1
                        }
                        else
                        {
                            $_ | Add-Member -MemberType NoteProperty -Name GRSOutputFolder -Value $GRSOutputFolder
                            $SuccessCounter = $SuccessCounter + 1
                        }
                    }
                }

                
            }
            Write-Host "-------------------------------------------------------------------------"       

        }
    }
    Write-Host "`n`r[-] [$($SuccessCounter)/$($PolicyContexts.Count)] scan completed."
    return $PolicyContexts
    
}

<#
    .Description
    Use this function to fetch the csv scan result as a PS object
    This function allows you to filter scan results based on RG, resource, and control id

#>
function Get-GRS-Scan-Result
{
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $GRSOutput,

        [ValidateNotNullOrEmpty()]
        [String]
        $ResourceGroupNames,

        [ValidateNotNullOrEmpty()]
        [String]
        $ResourceNames,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $ControlIdList
    )

    if (-not (Test-Path -Path "$($grsoutput)"))
    {
        Write-Host "Invalid folder path. Please check the path specified by you."
        break;
    }

    $csvpath = (Get-ChildItem -Path "$($grsoutput)" -Filter "SecurityReport-*.csv" -File).FullName
    if (-not [String]::IsNullOrEmpty($csvpath))
    {
        $GrsResult = Get-Content -Path $csvpath | ConvertFrom-Csv
    }

    if ($($GrsResult | Measure-Object).Count -gt 0)
    {
        #FilterBy ResourceGroupName
        if (-not [String]::IsNullOrEmpty($ResourceGroupNames))
        {

            $ResourceGroupNames = $ResourceGroupNames.Split(",").Trim("")
            $filteredResult = $ResourceGroupNames | ForEach-Object {
                $ResourceGroupName = $_
                $GrsResult | Where-Object { $_.ResourceGroupName -eq $ResourceGroupName }
            } 
        
            $GrsResult = $filteredResult
    
        }
    

        #FilterBy ResourceName

        if (-not [String]::IsNullOrEmpty($ResourceNames))
        {

            $ResourceNames = $ResourceNames.Split(",").Trim("")
            $filteredResult = $ResourceNames | ForEach-Object {
                $ResourceName = $_
                $GrsResult | Where-Object { $_.ResourceName -eq $ResourceName }
            } 
        
            $GrsResult = $filteredResult
    
        } 

        #FilterBy ControlID

        if (($ControlIdList | Measure-Object).Count -gt 0)
        {
            $filteredResult = $ControlIdList | ForEach-Object {
                $ControlId = $_
                $GrsResult | Where-Object { $_.ControlID -eq $ControlId }
            } 
        
            $GrsResult = $filteredResult
    
        }
    }
    else
    {
        Write-Host "CSV scan result not found at the specified path." -ForegroundColor Red
    }


    Write-Host "[-] Count of matching results found: $($($GrsResult | Measure-Object).Count)" -ForegroundColor Cyan
    return $GrsResult
}

function Get-GRS-Scan-Result-of-Policy-Context
{
    param (
        [Parameter(Mandatory = $true)]
        [PSObject[]]
        $PolicyContexts
    )

    $GRSResult = @()
    if (($PolicyContexts | Measure-Object).Count -gt 0)
    {
        $PolicyContexts | ForEach-Object { 
            $PolicyContext = $_
            $Scope = $_.Scope
            $ControlId = $_.ControlId
            if ($_ | GM -MemberType NoteProperty -Name "GRSOutputFolder")
            {
                $outputFolder = $_.GRSOutputFolder
            }
            if ((-not [String]::IsNullOrEmpty($Scope)) -and ($Scope.Split("/").Count -ge 5) -and ($Scope.Split("/") -contains "resourceGroups"))
            {
                $ResourceGroupName = Get-Resource-Group-Name-From-Scope -Scope $Scope
            }
            if (-not [String]::IsNullOrEmpty($outputFolder))
            {
                $Command = "Get-GRS-Scan-Result -GRSOutput '" + $($outputFolder) + "'"
                if (-not [String]::IsNullOrEmpty($ResourceGroupName))
                {
                    $Command += " -ResourceGroupName $($ResourceGroupName)"
                }
                if (-not [String]::IsNullOrEmpty($ControlId))
                {
                    $Command += " -ControlIdList '" + $($ControlId) + "'"
                }
                $GRSResult += Invoke-Expression -Command $Command 
                
            }
        }
    }
    return $GRSResult
}

<#
    .Description
    This function compare GRS and Policy scan result fetched using the following functions
    1. Get-GRS-Scan-Result
    2. Fetch-Policy-Status-For-Target-Scope

    For every <control id- resource id> pair found in GRS scan result, this function check if there is any matching policy result 
    
    In this function, we are matching the result based on control id 
#>
function Compare-and-Report
{
    param (

        [Parameter(Mandatory = $true)]
        [PSObject]
        $GrsResult,

        [Parameter(Mandatory = $true)]
        [PSObject]
        $PolicyResult
    )

    $ReturnObj = @()

    # This loops is to validate policy status for each <control id- resource id> pair in GRS scan result
    $GrsResult | ForEach-Object {

        $resourceScanObj = $_
        $ComparisonResult = "" | Select ResourceName, ChildResourceName, ControlId, PolicyAssignmentName, ComparisonResult, GRSScanResult, PolicyScanResult, ResourceId
        $ComparisonResult.ResourceName = $resourceScanObj.ResourceName
        $ComparisonResult.ControlId = $resourceScanObj.ControlId
        $ComparisonResult.ResourceId = $resourceScanObj.ResourceId

        # All non-passed status in GRS scan, will be considered as failed
        # This is required as policy status can only be true or false
        if ($resourceScanObj.Status -eq "Passed")
        {
            $ComparisonResult.GRSScanResult = "Passed"
        }
        else
        {
            $ComparisonResult.GRSScanResult = "Failed"
        }
        
        # Get definition name based on control id to map the result
        $DefinitionMapping = Get-Custom-Definition-Name -Name $resourceScanObj.ControlId
        $DefinitionMapping = $DefinitionMapping -replace "_[0-9]{3}$", ''

        # find policy assignment details for a specified control id -resource id
        # IsMapped is being used to maintain record of policy assignment for which mapping was not found
        $IsMapped = $false
        $PolicyResult | Where-Object { ($_.PolicyDefinitionName -match "$($DefinitionMapping)") -and (($_.ResourceId -eq $resourceScanObj.ResourceId) -or ($_.ResourceId.Tolower().StartsWith($resourceScanObj.ResourceId.Tolower().ToString()))) } | ForEach-Object { 
            $ComparisonResult.PolicyAssignmentName = $_.PolicyAssignmentName
            if(($_.ResourceId.Tolower().StartsWith($resourceScanObj.ResourceId.Tolower().ToString())))
            {
                $ComparisonResult.ChildResourceName = $_.ResourceId -replace $resourceScanObj.ResourceId, ""
            }
            
            if ($_.IsCompliant -eq $true)
            {
                $ComparisonResult.PolicyScanResult = "Passed"
            }
            else
            {
                $ComparisonResult.PolicyScanResult = "Failed"
            }

            if ( $ComparisonResult.GRSScanResult -eq $ComparisonResult.PolicyScanResult)
            {
                $ComparisonResult.ComparisonResult = "Passed"
            }
            else
            {
                $ComparisonResult.ComparisonResult = "Failed"
            }

            # Add result to return object
            $ReturnObj += $ComparisonResult
            $_ | Add-Member -MemberType NoteProperty -Name IsMapped -Value $true -Force
            $IsMapped = $true
        }

        if ($IsMapped -eq $false)
        {
            # If assignment not found
            $ComparisonResult.PolicyAssignmentName = "Not Found"
            $ComparisonResult.ComparisonResult = "Not Found"
            $ComparisonResult.PolicyScanResult = "Not Found"

            # Add result to return object
            $ReturnObj += $ComparisonResult
        }
    }

    $PolicyResult | Where-Object { $_.PolicyAssignmentName -match "^PTest_" } | Where-Object { -not ($_ | Get-Member -Name IsMapped -MemberType NoteProperty) } | ForEach-Object {
    
        $ComparisonResult = "" | Select ResourceName, ChildResourceName, ControlId, PolicyAssignmentName, ComparisonResult, GRSScanResult, PolicyScanResult, ResourceId
        $ComparisonResult.ResourceName = $_.ResourceId.Split("/")[-1]
        $ComparisonResult.ControlId = "Not Found"
        $ComparisonResult.PolicyAssignmentName = $_.PolicyAssignmentName
        $ComparisonResult.ComparisonResult = "Not Found"
        $ComparisonResult.GRSScanResult = "Not Found"
        if ($_.IsCompliant -eq $true)
        {
            $ComparisonResult.PolicyScanResult = "Passed"
        }
        else
        {
            $ComparisonResult.PolicyScanResult = "Failed"
        }
        $ComparisonResult.ResourceId = $_.ResourceId

        $ReturnObj += $ComparisonResult
    }


    # export result
    $filepath = "$(Prepare-And-Return-Directory-For-Logs)\AzSK_Policy_Comparison_Result_$(Get-Date -format "yyyyMMdd_HHmmss").csv"
    $ReturnObj | Export-Csv $filepath -NoTypeInformation -Force

    # open output folder
    try
    {
        Invoke-Item -Path $filepath;
    }
    catch
    {
        #ignore if any exception occurs
    }

    return $ReturnObj
    
}

function Prepare-And-Return-Directory-For-Logs
{

    # Create directory to store logs
    $PolicyLogFolderPath = "$($env:LOCALAPPDATA)\Microsoft\AzSKPolicyLogs"
    if (-not (Get-Item -Path $PolicyLogFolderPath -ErrorAction SilentlyContinue))
    {
        New-Item -Path "$($env:LOCALAPPDATA)\Microsoft" -Name "AzSKPolicyLogs" -ItemType Directory
    }

    return $PolicyLogFolderPath
    
}
function Get-Custom-Definition-Name
{
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $Name
    )

    $maxchar = 50
    if ($Name.Length -gt $maxchar)
    {
        $Alias = $Name.Substring(0, $($Name.Length) - ($($Name.Length) - $($maxchar)))
    }
    else
    {
        $Alias = $Name
    }
    $Alias = "PTest_" + $Alias + "_" + $(100..900 | Get-Random)

    return $Alias
}


function Get-Base-Template-For-Deployment
{
    Param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet("mastertemplate", "resourcetemplate")]
        [string]
        $Type
    )
    
    # master template 

    switch ($Type)
    {
        "mastertemplate"
        {
            $mastertemplate = '{
                "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "contentVersion": "1.0.0.0",
                "parameters": { },
                "variables": { },
                "resources": [ #resourcesList# ],
                "outputs": { }
            }'
            return  $mastertemplate 
        }
        "resourcetemplate"
        {
            $resourcetemplate = '{
                "apiVersion": "2019-08-01",
                "name": "#resourcename#",
                "type": "Microsoft.Resources/deployments",
                "properties": {
                    "mode": "Incremental",
                    "expressionEvaluationOptions": {
                        "scope": "inner"
                    },
                    "template": #template#,
                    "parameters": #parameters#
                    }
                }'
            return  $resourcetemplate
        }
    }
    
    

    

}

function Prepare-Nested-Template-For-Deployment
{
    param (
        [String]
        [ValidateNotNullOrEmpty()]
        $templateRoot,

        [PSObject]
        $ResourceTypeNames
    )

    if (Test-Path -Path $templateRoot)
    {
        Write-Host "`n`r[+] Preparing nested template for deployment..." -ForegroundColor Cyan
        $ResourceTypeNames | ForEach-Object {
            $ResourceTypeName = $_
            $templateFiles += Get-ChildItem -Path $templateRoot -Recurse -Filter "*$($ResourceTypeName)*" -File | Where-Object { $_.Fullname -match "\\$($ResourceTypeName)\\" }  
        }

        if (($templateFiles | Measure-Object).Count -gt 0)
        {
            $resourcesList = @()
            $nestedTemplateNameTracker = @()
            $templateFiles | Where-Object { $_.BaseName -notmatch ".parameters" } | ForEach-Object { 

                $IsEmptyTemplate = $false

                # Get template and param file path
                $TemplateFileName = $_.BaseName
                $TemplateFilePath = $_.FullName
                $ParameterFilePath = $templateFiles | Where-Object { $_.BaseName -eq "$($TemplateFileName).parameters" } | Select-Object FullName
                if (($ParameterFilePath | Measure-Object).Count -gt 0)
                {
                    $ParameterFilePath = $ParameterFilePath.FullName
                }

                # Prepare command for deployment
                do
                {
                    $resourcesTemplateName = "nestedTemplate" + $( (100..200) | Get-Random )

                }while ($nestedTemplateNameTracker -contains $resourcesTemplateName)
                # $resourcesTemplateName = "nestedTemplate" + $( (100..200) | Get-Random )
                $nestedTemplateNameTracker += $resourcesTemplateName
                $resourceTemplate = Get-Base-Template-For-Deployment -Type resourcetemplate
                $resourceTemplate = $resourceTemplate -replace "#resourcename#", $resourcesTemplateName
                if (-not [String]::IsNullOrEmpty($TemplateFilePath) -and (Test-Path -Path $TemplateFilePath))
                {
                    $templateContent = $(Get-Content -Path "$($TemplateFilePath)")
                    if (-not [String]::IsNullOrEmpty($templateContent))
                    {
                        $resourceTemplate = $resourceTemplate -replace "#template#", $templateContent
                    }
                    else
                    {
                        $IsEmptyTemplate = $true

                    }
                    # $resourceTemplate = $resourceTemplate -replace "#template#", 
                    # $resourceTemplate.properties.template = Get-Content -Path "$($TemplateFilePath)"
                }
                else
                {
                    $resourceTemplate = $resourceTemplate -replace "#template#", "{}"
                    # TODO: remove -> Write-Host  "Template file path not found for $($ResourceTypeName)" -ForegroundColor Red
                    
                }

                if (-not [String]::IsNullOrEmpty($ParameterFilePath) -and (Test-Path -Path $ParameterFilePath))
                {
                    
                    # Read only parameters block from the template
                    $parametersTemplate = $(Get-Content -Path "$($ParameterFilePath)") | ConvertFrom-Json 
                    $parameters = $parametersTemplate.parameters | ConvertTo-Json -Depth 100 | ForEach-Object { [System.Text.RegularExpressions.Regex]::Unescape($_) }

                    if (-not [String]::IsNullOrEmpty($parameters))
                    {
                        $resourceTemplate = $resourceTemplate -replace "#parameters#", "$($parameters)"
                    }
                    else
                    {
                        $resourceTemplate = $resourceTemplate -replace "#parameters#", "{}"

                    }

                    # $resourceTemplate.properties.parameters = Get-Content -Path "$($ParameterFilePath)"
                }
                else
                {
                    $resourceTemplate = $resourceTemplate -replace "#parameters#", "{}"
                }

                if (-not $IsEmptyTemplate)
                {
                    $resourcesList += $resourceTemplate
                }

                
            }
        }

        $mastertemplate = Get-Base-Template-For-Deployment -Type mastertemplate
        $mastertemplate = $mastertemplate -replace "#resourcesList#", $($resourcesList -join ",")

    }
    else
    {
        Write-Host "Invalid root path" -ForegroundColor Red
        
    }

    if (-not [String]::IsNullOrEmpty($mastertemplate))
    {
        $MasterTemplateFilePath = "$(Prepare-And-Return-Directory-For-Logs)\mastertemplate-$(Get-Date -format "yyyyMMdd_HHmmss").json"
        $mastertemplate | Out-File $MasterTemplateFilePath
        Write-Host "[-] Created nested template for deployment.`n`r[-] Template name: $($($MasterTemplateFilePath.Split("\")[-1]))" -ForegroundColor Cyan
        return $MasterTemplateFilePath
    }
    else
    {
        return $null
    }
        
}


function Prepare-Resource-for-Testing-Policy
{
    param (

        [String]
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $SubscriptionId,

        [String]
        [ValidateNotNullOrEmpty()]
        $ResourceGroupName = "rg",

        [String[]]
        [ValidateNotNullOrEmpty()]
        $ControlIdList,

        [String]
        [ValidateNotNullOrEmpty()]
        $Location = "EastUs",

        [String]
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        $templateRoot,

        [switch]
        $AsJob,

        [switch]
        $SkipTemplateParameterPrompt
    )

    # Set context and create rg if not exists
    Set-AzContext -SubscriptionId $SubscriptionId
    Write-Host "`n`r[+] Preparing resource group for deployment..." -ForegroundColor Cyan
    if (-not $ResourceGroupName.StartsWith("ptest-"))
    {
        $ResourceGroupName = "ptest-" + $ResourceGroupName
    }
    
    if (-not (Get-AzResourceGroup -Name $ResourceGroupName -ErrorAction SilentlyContinue))
    {
        try
        {
            New-AzResourceGroup -Name $ResourceGroupName -Location $Location
        }
        catch
        {
            Write-Host "Failed to create resource group." -ForegroundColor Red   
        }
        
    }

    # Prepare and get the master template for deployment    
    $ResourceTypeNames = @()
    $ResourceTypeNames = $ControlIdList | Select-Object -Unique | ForEach-Object { $_.Split("_")[1] } | Select-Object -Unique

    if (($ResourceTypeNames | Measure-Object).Count -eq 0)
    {
        $ResourceTypeNames += "*"
    }

    if (Test-Path $templateRoot)
    {
        $MasterTemplateFilePath = Prepare-Nested-Template-For-Deployment -templateRoot $templateRoot -ResourceTypeNames $ResourceTypeNames
    }
    

    # Deploy resources using master template
    if (-not [String]::IsNullOrEmpty($MasterTemplateFilePath) -and (Test-Path -Path $MasterTemplateFilePath))
    {
        # Test template before deployment
        $TemplateValidationResult = Test-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Mode Incremental -TemplateFile $MasterTemplateFilePath

        if (($TemplateValidationResult | Measure-Object).Count -gt 0)
        {
            Write-Host "`n`r[+] Invalid template: $($MasterTemplateFilePath.Split("\")[-1])" -ForegroundColor Red
            $TemplateValidationResult | Out-Host
            $TemplateValidationResult | ForEach-Object { $_.Details } | Out-Host
        }
        else
        {
            # Deploy resources using master template
            Write-Host "`n`r[+] Deploying resources to [$($ResourceGroupName)] resource group..." -ForegroundColor Cyan
            $DeploymentName = "testdeployment" + $(100..900 | Get-Random)
            try
            {
                if ($AsJob.IsPresent -and $SkipTemplateParameterPrompt.IsPresent)
                {
                    New-AzResourceGroupDeployment -Name $DeploymentName -ResourceGroupName $ResourceGroupName -Mode Incremental -TemplateFile $MasterTemplateFilePath  -AsJob:$AsJob  -SkipTemplateParameterPrompt:$SkipTemplateParameterPrompt
                }
                elseif ($AsJob.IsPresent)
                {
                    New-AzResourceGroupDeployment -Name $DeploymentName -ResourceGroupName $ResourceGroupName -Mode Incremental -TemplateFile $MasterTemplateFilePath  -AsJob:$AsJob
                }
                elseif ($SkipTemplateParameterPrompt.IsPresent)
                {
                    New-AzResourceGroupDeployment -Name $DeploymentName -ResourceGroupName $ResourceGroupName -Mode Incremental -TemplateFile $MasterTemplateFilePath  -SkipTemplateParameterPrompt:$SkipTemplateParameterPrompt
                }
                else {
                    New-AzResourceGroupDeployment -Name $DeploymentName -ResourceGroupName $ResourceGroupName -Mode Incremental -TemplateFile $MasterTemplateFilePath
                }
            }
            catch
            {
                Write-Host "$($_.Exception.Message)" -ForegroundColor Red
            }
        }

        
    }
    
}

function Get-ControlId-List-by-Resource-Type-Name
{
    param (
        [PSObject]
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        $ResourceTypeNameList
    )

    $FilteredControlInfo = @()
    $OutputFolder = Get-AzSKInfo -InfoType ControlInfo -DoNotOpenOutputFolder 6>$null
    if(-not [String]::IsNullOrEmpty($OutputFolder))
    {
        $ControlInfoFile = (Get-ChildItem -Path $OutputFolder -Filter "Control_Details_*.csv").FullName
        if(-not [String]::IsNullOrEmpty($ControlInfoFile))
        {
            $ControlInfo = Get-Content -Path $ControlInfoFile | ConvertFrom-Csv
            if (($ResourceTypeNameList | Measure-Object).Count -gt 0)
            {
                $ResourceTypeNameList | Select -Unique | ForEach-Object {
                    $ResourceTypeName = $_
                    $FilteredControlInfo += $ControlInfo | where { $_.FeatureName -eq $($ResourceTypeName) }       
                }
            }
            else
            {
                $FilteredControlInfo += $ControlInfo
            }
        }
    }
    
    return $FilteredControlInfo.ControlID
}

    
class PolicyContext
{
    [String] $ControlId;
    [String] $JsonPath;
    [String] $Scope;
    [String] $PolicyRule;
    [String] $Parameters;
    [String] $DefinitionName; 
}