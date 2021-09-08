Set-StrictMode -Version Latest 
class CATestContextHelper
{
    [PSObject] $CATestContext
    static [bool] $IsCAInstalled = $true #This is a one time acitivity
    static [bool] $IsRunbookTriggered = $true #This is a one time acitivity
    CATestContextHelper([String] $CATestContextPath)
    {
        $this.CATestContext = Get-Content $CATestContextPath | ConvertFrom-Json
    }
    
    [void] SetCATestContext([String] $CATestContextPath)
    {
        $this.CATestContext = Get-Content $CATestContextPath | ConvertFrom-Json
    }

    [PSObject] GetInputObject($CAType)
    {
        $inputObject = $this.CATestContext.Properties | Where { $_.Type -eq $CAType }
        return $inputObject;
    }
    
    [PSObject] GetExistingCA([String] $CAType)
	{
        $inputObject = $this.GetInputObject($CAType)
        $AutomationAccountName = $inputObject.AutomationAccountName
        $AutomationAccountRGName = $inputObject.AutomationAccountRGName
		$CAAccount = Get-AzAutomationAccount -Name $AutomationAccountName -ResourceGroupName $AutomationAccountRGName -ErrorAction SilentlyContinue
		return $CAAccount
    }
    
    [void] CleanUpCARG([String] $AutomationAccountRGName, [bool] $DeleteAzSKRG)
    {
        if($DeleteAzSKRG)
        {
            Remove-AzResourceGroup -Name $AutomationAccountRGName
        }
        else
        {
            $ResourceList = Get-AzResource -ResourceGroupName $AutomationAccountRGName
            $ResourceList  = $ResourceList | Where-Object { -not $($_.ResourceType -eq "Microsoft.Storage/storageAccounts" -and $_.Name -match "azsk*") }
            $ResourceList | ForEach-Object { 
                Remove-AzResource -ResourceId $_.ResourceId -Force -ErrorAction SilentlyContinue
            }
        }
    }

    [void] RunInstallCAInternalPrerequisite([String] $CAType, [PSObject] $testContext, [bool] $ForceInstall)
    {
        $inputObject = $this.GetInputObject($CAType)
        $this.InstallCA($CAType,$testContext, $inputObject,$ForceInstall)
    }

    [PSObject] InstallCA([String] $CAType, [PSObject] $testContext, [PSObject] $inputObject, [bool] $ForceInstall)
    {
        $result = "" | Select TestStatus, Message
        $result.TestStatus = [TestStatus]::ScanInterrupted
        $SubscriptionId = $testContext.TestResources.SubscriptionId
        $AutomationAccountName = $inputObject.AutomationAccountName
        $AutomationAccountRGName = $inputObject.AutomationAccountRGName
        $AutomationAccountLocation = $inputObject.AutomationAccountLocation
        $LAWSId = $testContext.AzSKSettings.endpoints.LAWSId
        $LAWSSharedKey = $testContext.AzSKSettings.endpoints.LAWSSharedKey
        $ExistingCA = $this.GetExistingCA($CAType)
        if($($null -eq $ExistingCA) -or $ForceInstall -or [CATestContextHelper]::IsCAInstalled)
		{
            $Command = ""
            if($null -ne $ExistingCA)
            {
                $this.CleanUpCARG($AutomationAccountRGName, $false)
            }
			switch ($CAType) {
                'Solo'
                {
                    $Command = "Install-AzSKContinuousAssurance -SubscriptionId $($SubscriptionId) `
                                    -ResourceGroupNames * `
                                    -LAWSId $($LAWSId) `
                                    -LAWSSharedKey $($LAWSSharedKey)"
                }
                'MultiCentral' {                 
                    $Command = "Install-AzSKContinuousAssurance -SubscriptionId $($SubscriptionId) `
                        -ResourceGroupNames * `
                        -LAWSId $($LAWSId) `
                        -LAWSSharedKey $($LAWSSharedKey) `
                        -TargetSubscriptionIds $($SubscriptionId) `
                        -CentralScanMode `
                        -LoggingOption CentralSub `
                        -SkipTargetSubscriptionConfig `
                        -AutomationAccountName $($AutomationAccountName) `
                        -AutomationAccountRGName $($AutomationAccountRGName) `
                        -AutomationAccountLocation $($AutomationAccountLocation)"
                }
                'Central' {
                    $Command = "Install-AzSKContinuousAssurance -SubscriptionId $($SubscriptionId) `
                        -ResourceGroupNames * `
                        -LAWSId $($LAWSId) `
                        -LAWSSharedKey $($LAWSSharedKey) `
                        -TargetSubscriptionIds $($SubscriptionId) `
                        -CentralScanMode `
                        -LoggingOption CentralSub `
                        -SkipTargetSubscriptionConfig"
                }
            }

            $result.TestStatus = [TestHelper]::RunAzSKCommand($Command , $("ICA_" + $($CAType)), $Command, "Prerequisite_InstallCA" ,$testContext)
            $result.Message = "INSTALL CA: $($Result.TestStatus)"
            [CATestContextHelper]::IsCAInstalled = $false
        }
        return $result
    }

    [void] TriggerCAScanRunbook([String] $CAType, [string] $CARunbook, [bool] $forceTrigger)
    {
        if($forceTrigger -or [CATestContextHelper]::IsRunbookTriggered)
        {
            $inputObject = $this.GetInputObject($CAType)
            $AutomationAccountName = $inputObject.AutomationAccountName
            $RGName = $inputObject.AutomationAccountRGName
            if(Get-AzAutomationRunbook -Name $CARunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $RGName)
            {
                # Stop active job
                $Jobs = Get-AzAutomationJob -AutomationAccountName $AutomationAccountName -ResourceGroupName $RGName -RunbookName $CARunbook
                $Jobs = $Jobs | Where-Object { ($_.Status -ne 'Completed' -and $_.Status -ne 'Failed' -and $_.Status -ne 'Stopped' -and $_.Status -ne 'Suspended') }
                if(($Jobs | Measure-Object).Count -gt 0)
                {
                    $Jobs | ForEach-Object { Stop-AzAutomationJob -Id $_.JobId -ResourceGroupName $_.ResourceGroupName -AutomationAccountName $_.AutomationAccountName }
                }

                # Start runbook
                $NewJob = Start-AzAutomationRunbook -Name $CARunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $RGName
                $JobId = $NewJob.JobId
                $Job = Get-AzAutomationJob -Id $JobId -AutomationAccountName $AutomationAccountName -ResourceGroupName $RGName

                $i = 0
                [CommonHelper]::Log("`r`nEntering the loop to trigger $($CARunbook) runbook.`n`rThis loop is set to run 4 times. Please wait while the job completes.", [MessageType]::Information)
                While ($i -lt 3)
                {   
                    [CommonHelper]::Log("`r`n[+] [$($i)] Running automation job...", [MessageType]::Information)
                    While ($Job.Status -ne 'Completed' -and $Job.Status -ne 'Failed' -and $Job.Status -ne 'Stopped' -and $Job.Status -ne 'Suspended')
                    {
                        Start-Sleep 30
                        [CommonHelper]::Log("[-] [$($i)] Waiting for automation job to complete..." , [MessageType]::Information)
                        $Job = Get-AzAutomationJob -Id $JobId -AutomationAccountName $AutomationAccountName -ResourceGroupName $RGName
                        $Job.Status
                    }
                    [CommonHelper]::Log("[-] [$($i)] Job status: $($Job.Status)" , [MessageType]::Information)
                    $NewJob = Start-AzAutomationRunbook -Name $CARunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $RGName
                    $JobId = $NewJob.JobId
                    $Job = Get-AzAutomationJob -Id $JobId -AutomationAccountName $AutomationAccountName -ResourceGroupName $RGName
                    $i++;
                }
            }
            else
            {
                [CommonHelper]::Log("`n`r Failed to trigger the runbook. [$($CARunbook)] runbook not found.", [MessageType]::Information)
            }
            [CATestContextHelper]::IsRunbookTriggered = $false
        }
    }

    # Check runbooks
    [PSObject] WereRunbooksCreated([String] $AutomationAccountName, [String] $RGName, [PSObject] $Runbooks)
    {
        $result = "" | Select-Object Status, Message
        $result.Status = $false
        
        try
        {
            $cmdOutput = Get-AzAutomationRunbook -AutomationAccountName $AutomationAccountName -ResourceGroupName $RGName;

            #if cmdOutput not empty
            if ( ($cmdOutput | Measure-Object).Count -gt 0)
            {
                #verify result
                $compareResult = Compare-Object $cmdOutput.Name $Runbooks -IncludeEqual
                $MissingRunbook = $compareResult | Where-Object { $_.SideIndicator -eq "=>" }
                $AdditionalRunbook = $compareResult | Where-Object { $_.SideIndicator -eq "<=" }
                if ($MissingRunbook)
                {
                    $result.Message += "List of missing runbooks: $($MissingRunbook.InputObject -join ', ')"
                }
                else
                {
                    $result.Status = $true
                    $result.Message += "Found runbooks: $($($compareResult| Where-Object { $_.SideIndicator -eq "==" }).InputObject -join ', ')"
                }
                if ($AdditionalRunbook)
                {
                    $result.Message += "List of additional runbooks: $($AdditionalRunbook.InputObject -join ', ')"
                }    
            }
            else
            {
                $result.Message += "Runbook not found!" # Add this if required - [Type: $($Type)] [CAName: $($AutomationAccountName)] [RGName: $($RGName)] 
            }
        }
        catch
        {
            $result.Message += "Could not test runbooks in CA. Please verify this manually."
        }
        
        return $result
    }
    
    # Check CA schedule
    [PSObject] WereAllSchedulesCreated([String] $AutomationAccountName, [String] $RGName, [PSObject] $Schedules)
    {
        $result = "" | Select-Object Status, Message
        $result.Status = $false        

        $bPass1 = $this.WasCAScanScheduleCreated($AutomationAccountName, $RGName, $Schedules)
        $bPass2 = $this.WereAllCAHelperScheduleCreated($AutomationAccountName, $RGName, $Schedules)

        $result.Message += "CA Scan Schedule: $($bPass1[1])"
        $result.Message += "`nCA Helper Schedule: $($bPass2[1])" 

        if ($bPass1[0] -and $bPass2[0])
        {
            $result.Status = $true
        }

        return $result
    }

    # Check CA scan schedule
    [PSObject] WasCAScanScheduleCreated([String] $AutomationAccountName, [String] $RGName, [PSObject] $Schedules)
    {
        $result = $false
        $msg = @()
        
        try
        {
            $cmdOutput = Get-AzAutomationSchedule -AutomationAccountName $AutomationAccountName -ResourceGroupName $RGName;

            #if cmdOutput not empty
            if ( ($cmdOutput | Measure-Object).Count -gt 0)
            {
                #verify result
                $IsCAScanSchedulePresent = $cmdOutput.Name -contains $Schedules.Primary                
                if ($IsCAScanSchedulePresent)
                {
                    $result = $true
                    $msg += "CA scan schedule is present."
                }
                else
                {
                    $msg += "CA scan schedule not found."
                }
            }
            else
            {
                $msg += "CA scan schedule not found."
            }
        }
        catch
        {
            $msg += "Could not test schedules in CA. Please verify this manually."
        }
        
        return @($result, $msg)
    }

    #Check CA helper schedule
    [PSObject] WereAllCAHelperScheduleCreated([String] $AutomationAccountName, [String] $RGName, [PSObject] $Schedules)
    {
        $result = $false
        $msg = @()
       
        try
        {
            $cmdOutput = Get-AzAutomationSchedule -AutomationAccountName $AutomationAccountName -ResourceGroupName $RGName;

            #if cmdOutput not empty
            if ( ($cmdOutput | Measure-Object).Count -gt 0)
            {
                #verify result
                $CAHelperScheduleCount = ($cmdOutput.Name | Where-Object { $_ -match "$($Schedules.Secondary)" }| Measure-Object).Count
                if ($CAHelperScheduleCount -eq 0)
                {
                    $result = $false
                    $msg += "CA helper schedule not found."
                }
                elseif ($CAHelperScheduleCount -eq 4)
                {
                    $result = $true
                    $msg += "Found $($CAHelperScheduleCount) helper schedule"
                }
                elseif ($CAHelperScheduleCount -gt 0)
                {
                    $result = $true
                    $msg += "Found $($CAHelperScheduleCount) helper schedule"
                }   
            }
            else
            {
                $msg += "CA helper schedule not found."
            }
        }
        catch
        {
            $msg += "Could not test schedules in CA. Please verify this manually."
        }
        
        return @($result, $msg)
    }
    
    # Check SPN RBAC
    [PSObject] WasCASPNGrantedRBACAccess([String] $AutomationAccountName, [String] $RGName)
    {
        $result = "" | Select-Object Status, Message
        $result.Status = $false
        $spId = ""
        $haveSubscriptionAccess = $false
        $haveRGAccess = $false
        $runAsConnection = $this.GetRunAsConnection($AutomationAccountName, $RGName)
        if ($runAsConnection)
        {			
            $CAAadApplicationID = $runAsConnection.FieldDefinitionValues.ApplicationId
            $spObject = Get-AzADServicePrincipal -ServicePrincipalName $CAAadApplicationID -ErrorAction SilentlyContinue
            if ($spObject)
            {
                $spId = $spObject.Id
            }
            $spPermissions = Get-AzRoleAssignment -ObjectId $spId
            $currentContext = Get-AzContext
            
            #Check subscription access
            if (($spPermissions|measure-object).count -gt 0)
            {
                $haveSubscriptionAccess = ($spPermissions | Where-Object {$_.scope -eq "/subscriptions/$($currentContext.Subscription.Id)" -and $_.RoleDefinitionName -eq "Reader"}|Measure-Object).count -gt 0
                $rgObj = Get-AzResourceGroup -Name $RGName -ErrorAction SilentlyContinue
                if (($rgObj | Measure-Object).Count -eq 1)
                {
                    $haveRGAccess = ($spPermissions | Where-Object {$_.scope -eq $rgObj.ResourceId -and $_.RoleDefinitionName -eq "Contributor" }|measure-object).count -gt 0    
                }
            }
        }

        if ($haveSubscriptionAccess -and $haveRGAccess)
        {
            $result.Status = $true
            $result.Message += "CA SPN RBAC found at subscription and resource group level."
        }
        else
        {
            if (-not $haveSubscriptionAccess)
            {
                $result.Status = $false
                $result.Message += "CA SPN RBAC not found at subscription level."
            }
            if (-not $haveRGAccess)
            {
                $result.Status = $false
                $result.Message += "CA SPN RBAC not found at resource group level."
            }
        }
        
        return $result

    }

    #get connection
    [PSObject] GetRunAsConnection([String] $AutomationAccountName, [String] $RGName)
    {
        $connection = Get-AzAutomationConnection -AutomationAccountName $AutomationAccountName `
            -Name 'AzureRunAsConnection' -ResourceGroupName  $RGName
        if ((Get-Member -InputObject $connection -Name FieldDefinitionValues -MemberType Properties) -and $connection.FieldDefinitionValues.ContainsKey("ApplicationId"))
        {
            $connection = $connection|Select-Object Name, Description, ConnectionTypeName, FieldDefinitionValues
            return $connection
        }
        else
        {
            return $null
        }
    }

    # Check for latest AzSK module
    [PSObject] WasAzSKModuleInstalled([String] $AutomationAccountName, [String] $RGName, [String] $AzSKModule)
    {
        $result = "" | Select-Object Status, Message
        $result.Status = $false
        $automationModule = Get-AzAutomationModule -AutomationAccountName $AutomationAccountName -ResourceGroupName $RGName | Where-Object { $_.Name -match 'AzSK' } 
        $LatestModule = Find-Module -Name $AzSKModule
        if (($automationModule | Measure-Object).Count -eq 1 -and ($automationModule.ProvisioningState -eq "Succeeded") -and ($automationModule.Version -eq $($LatestModule.Version.ToString())))
        {
            $result.Status = $true   
        }
        else
        {
            $result.Message += "AzSK module is either not installed or the installed version does not match the expected version $($LatestModule.Version.ToString())."
        }
        $result.Message += $automationModule | Out-String
        return $result
    }

}