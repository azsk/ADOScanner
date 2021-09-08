Set-StrictMode -Version Latest 
class ParallelScan
{ 
	static [PSCustomObject[]] $Jobs = @()
	static [PSCustomObject[]] LoadParallelScanCommand([string] $AzSKModule, [string] $AzSKModulePath,[string] $SubscriptionId, [TestContext] $testContext)
	{

		$ScriptBlock1 = {
							param
									(
									  [Parameter(Mandatory=$true)]
									  [String]$AzSKModule,

									  [Parameter(Mandatory=$false)]
									  [PSObject]$Parameters

									)
                            Import-Module -Name $AzSKModule -Scope Global
							$Parameters
						}

		$ScriptBlock2 = {
							$i = 0
							$ArchivedPSOutputError = $Error | Select-Object -Unique | ForEach-Object { $i++; "$($i): $($_.CategoryInfo.Activity)`n`r $($_.ScriptStackTrace) `n`r";  }
							Out-File -FilePath ($output + "ArchivedPSOutputError.LOG") -InputObject $ArchivedPSOutputError
							return $output
						}

		[PSCustomObject] $ParallelScan = @()
		
		#GRS
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "GRS";
		$ParallelScan.Command = {
                                    # ***Warning: The following commented code scans only one resource of each type in a subscription. Updating the GRS cmdlet to scan full subscription.
									## $AzureRmResourceList = Get-AzResource;
									## [PSCustomObject] $RList = $AzureRmResourceList | Select-Object Kind,ResourceGroupName, Name,ResourceType | Group-Object ResourceType, Kind| ForEach-Object {
									## 		$_ | Select-Object -ExpandProperty Group | Select-Object -First 1
									## 	} | Sort-Object ResourceType;
									## $output = Get-AzSKAzureServicesSecurityStatus -SubscriptionId (Get-AzContext).Subscription.Id -ResourceNames $($RList.Name -join ",") -ResourceGroupNames $($RList.ResourceGroupName -join ",");
									Set-AzSKMonitoringSettings -Source "VSO";
									CSS;
                                    $output = Get-AzSKAzureServicesSecurityStatus -SubscriptionId (Get-AzContext).Subscription.Id;
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		# ***Warning: The following commented code can be used when scanning one resource of each type in a subscription. Updating the GRS cmdlet to scan full subscription.
		# $ParallelScan.Description = "Run command 'Get-AzSKAzureServicesSecurityStatus' to scan one control of each resource type in the subscription."
		$ParallelScan.Description = "Run command 'Get-AzSKAzureServicesSecurityStatus' to scan subscription (Source: VSO)."
		[ParallelScan]::Jobs +=$ParallelScan
		
		#GSS
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "GSS";
		$ParallelScan.Command = {
									Set-AzSKMonitoringSettings -Source "SDL";
									CSS;
									$output = Get-AzSKSubscriptionSecurityStatus -SubscriptionId (Get-AzContext).Subscription.Id;
								}
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Get-AzSKSubscriptionSecurityStatus' to scan subscription (Source: SDL)."
		[ParallelScan]::Jobs +=$ParallelScan

		#GACS
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "GACS";
		$ParallelScan.Command = {
									$AzureRmResourceList = Get-AzResource;
									[PSCustomObject] $RList = $AzureRmResourceList | Select-Object Kind,ResourceGroupName, Name,ResourceType | Group-Object ResourceType, Kind| ForEach-Object {
											$_ | Select-Object -ExpandProperty Group | Select-Object -First 1
										} | Sort-Object ResourceType;
									$output = Get-AzSKControlsStatus -SubscriptionId (Get-AzContext).Subscription.Id -ResourceNames $($RList.Name -join ",") -ResourceGroupNames $($RList.ResourceGroupName -join ",");
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Get-AzSKControlsStatus'to scan both subscription and one control of each resource type in the subscription."
		[ParallelScan]::Jobs +=$ParallelScan

		#GES
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "GES";
		$ParallelScan.Command = {
									$output = Get-AzSKExpressRouteNetworkSecurityStatus -SubscriptionId (Get-AzContext).Subscription.Id
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Get-AzSKExpressRouteNetworkSecurityStatus'."
		[ParallelScan]::Jobs +=$ParallelScan
		
		#GAI_SubscriptionInfo
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "GAI_SubscriptionInfo";
		$ParallelScan.Command = {
									$output = Get-AzSKInfo -InfoType SubscriptionInfo -SubscriptionId (Get-AzContext).Subscription.Id;
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Get-AzSKInfo -InfoType SubscriptionInfo'."
		[ParallelScan]::Jobs +=$ParallelScan

		#GAI_ControlInfo
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "GAI_ControlInfo";
		$ParallelScan.Command = {
									$output = Get-AzSKInfo -InfoType ControlInfo -ResourceTypeName All -UseBaselineControls;
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Get-AzSKInfo -InfoType ControlInfo -ResourceTypeName All -UseBaselineControls'."
		[ParallelScan]::Jobs +=$ParallelScan

		#GAI_AttestationInfo
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "GAI_AttestationInfo";
		$ParallelScan.Command = {
									$output = Get-AzSKInfo -InfoType AttestationInfo -SubscriptionId (Get-AzContext).Subscription.Id -ResourceTypeName All -UseBaselineControls
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Get-AzSKInfo -InfoType AttestationInfo -ResourceTypeName All -UseBaselineControls'."
		[ParallelScan]::Jobs +=$ParallelScan

		#GAI_HostInfo
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "GAI_HostInfo";
		$ParallelScan.Command = {
									$output = Get-AzSKInfo -InfoType HostInfo
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Get-AzSKInfo -InfoType HostInfo'."
		[ParallelScan]::Jobs +=$ParallelScan

		#GAI_ComplianceInfo
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "GAI_ComplianceInfo";
		$ParallelScan.Command = {
									$output = Get-AzSKInfo -InfoType ComplianceInfo -SubscriptionId (Get-AzContext).Subscription.Id;
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Get-AzSKInfo -InfoType ComplianceInfo'."
		[ParallelScan]::Jobs +=$ParallelScan

		#SAA
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "SAA";
		$ParallelScan.Parameters = "" | Select SecurityContactEmails
		$ParallelScan.Parameters.SecurityContactEmails = "abc@microsoft.com" # TODO: remove hard-coded value
		$ParallelScan.Command = {
                                    Write-Host "SecurityContactEmails" $Parameters.SecurityContactEmails;
									$output = Set-AzSKAlerts -SubscriptionId (Get-AzContext).Subscription.Id -SecurityContactEmails $Parameters.SecurityContactEmails  -Tags 'Mandatory'
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Set-AzSKAlerts -SecurityContactEmails ***'  -Tags 'Mandatory'."
		[ParallelScan]::Jobs +=$ParallelScan

		#SAP
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "SAP";
		$ParallelScan.Command = {
									$output = Set-AzSKARMPolicies -SubscriptionId (Get-AzContext).Subscription.Id  -Tags 'Mandatory'
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Set-AzSKARMPolicies  -Tags 'Mandatory''."
		[ParallelScan]::Jobs +=$ParallelScan

		#SSC
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "SSC";
		$ParallelScan.Parameters = "" | Select  SecurityContactEmails, SecurityPhoneNumber
		$ParallelScan.Parameters.SecurityContactEmails = "abc@microsoft.com" # TODO: remove hard-coded value
		$ParallelScan.Parameters.SecurityPhoneNumber = "9000035545" # TODO: remove hard-coded value
		$ParallelScan.Command = {
                                    Write-Host "SecurityContactEmails" $Parameters.SecurityContactEmails;
		                            Write-Host "SecurityPhoneNumber" $Parameters.SecurityPhoneNumber;
									$output = Set-AzSKAzureSecurityCenterPolicies -SubscriptionId (Get-AzContext).Subscription.Id -SecurityContactEmails $Parameters.SecurityContactEmails -SecurityPhoneNumber $Parameters.SecurityPhoneNumber
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Set-AzSKAzureSecurityCenterPolicies -SecurityContactEmails *** -SecurityPhoneNumber ***'."
		[ParallelScan]::Jobs +=$ParallelScan


		#SOS
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "SOS";
		$ParallelScan.Parameters = "" | Select  LAWSId, LAWSSharedKey
		$ParallelScan.Parameters.LAWSId = $testContext.AzSKSettings.endpoints.LAWSId
		$ParallelScan.Parameters.LAWSSharedKey = $testContext.AzSKSettings.endpoints.LAWSSharedKey
		$ParallelScan.Command = {
									Write-Host '$Parameters.LAWSId'  $Parameters.LAWSId
									Write-Host '$Parameters.LAWSSharedKey'  $Parameters.LAWSSharedKey
									Set-AzSKOMSSettings -LAWSId $Parameters.LAWSId -LAWSSharedKey $Parameters.LAWSSharedKey
									$output = 'None'
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Set-AzSKMonitoringSettings -LAWSId *** -LAWSSharedKey ***'."
		[ParallelScan]::Jobs +=$ParallelScan

		#SPS
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "SPS";
		$ParallelScan.Command = {
									Set-AzSKPolicySettings -AutoUpdate Off
									Set-AzSKPolicySettings -AutoUpdate On
									$output = 'None'
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Set-AzSKPolicySettings -AutoUpdate Off/On'."
		[ParallelScan]::Jobs +=$ParallelScan


		#SRB
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "SRB";
		$ParallelScan.Command = {
									$output = Set-AzSKSubscriptionRBAC -SubscriptionId (Get-AzContext).Subscription.Id  -Tags 'Mandatory' -Force
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Set-AzSKSubscriptionRBAC'  -Tags 'Mandatory'."
		[ParallelScan]::Jobs +=$ParallelScan

		#SSS
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "SSS";
		$ParallelScan.Parameters = "" | Select  SecurityContactEmails, SecurityPhoneNumber
		$ParallelScan.Parameters.SecurityContactEmails = "abc@microsoft.com" # TODO: remove hard-coded value
		$ParallelScan.Parameters.SecurityPhoneNumber = "9000035545" # TODO: remove hard-coded value
		$ParallelScan.Command = {
                                    Write-Host "SecurityContactEmails" $Parameters.SecurityContactEmails;
		                            Write-Host "SecurityPhoneNumber" $Parameters.SecurityPhoneNumber;
									$output = Set-AzSKSubscriptionSecurity -SubscriptionId (Get-AzContext).Subscription.Id -SecurityContactEmails $Parameters.SecurityContactEmails -SecurityPhoneNumber $Parameters.SecurityPhoneNumber  -Tags 'Mandatory'
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Set-AzSKSubscriptionSecurity -SecurityContactEmails *** -SecurityPhoneNumber ***  -Tags 'Mandatory''."
		[ParallelScan]::Jobs +=$ParallelScan

		#SUTL
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "SUTL";
		$ParallelScan.Command = {
									Set-AzSKUsageTelemetryLevel -Level Anonymous
									Set-AzSKUsageTelemetryLevel -Level None
									$output = 'None'
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Set-AzSKUsageTelemetryLevel -Level None/Anonymous'."
		[ParallelScan]::Jobs +=$ParallelScan

		#SUP
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "SUP";
		$ParallelScan.Command = {
									Set-AzSKUserPreference -DoNotOpenOutputFolder
									$output = 'None'
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Set-AzSKUserPreference -DoNotOpenOutputFolder'."
		[ParallelScan]::Jobs +=$ParallelScan

		#USS
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "USS";
		$ParallelScan.Command = {
									$output = Update-AzSKSubscriptionSecurity -SubscriptionId (Get-AzContext).Subscription.Id
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Update-AzSKSubscriptionSecurity'."
		[ParallelScan]::Jobs +=$ParallelScan

		#UCA
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "UCA";
		$ParallelScan.Command = {
									$output = Update-AzSKContinuousAssurance -SubscriptionId (Get-AzContext).Subscription.Id;
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Update-AzSKContinuousAssurance'."
		[ParallelScan]::Jobs +=$ParallelScan

		#IOM
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "IOM";
		$ParallelScan.Parameters = "" | Select  LASubscriptionId, LAResourceGroup, LAWSId, ViewName
		$ParallelScan.Parameters.LASubscriptionId = $testContext.TestResources.SubscriptionId
		$ParallelScan.Parameters.LAResourceGroup = $testContext.AzSKSettings.LAResourceGroup
		$ParallelScan.Parameters.LAWSId = $testContext.AzSKSettings.endpoints.LAWSId
		$ParallelScan.Parameters.ViewName = $testContext.AzSKSettings.LAViewName
		$ParallelScan.Command = {
									Write-Host '$Parameters.LASubscriptionId'  $Parameters.LASubscriptionId
									Write-Host '$Parameters.LAResourceGroup'  $Parameters.LAResourceGroup
									Write-Host '$Parameters.LAWSId'  $Parameters.LAWSId
									Write-Host '$Parameters.ViewName'  $Parameters.ViewName
									$output = Install-AzSKMonitoringSolution -LASubscriptionId $Parameters.LASubscriptionId -LAResourceGroup $Parameters.LAResourceGroup -LAWSId $Parameters.LAWSId -ViewName $Parameters.ViewName
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Install-AzSKMonitoringSolution -LASubscriptionId ** -LAResourceGroup ** -LAWSId ** -ViewName **'."
		[ParallelScan]::Jobs +=$ParallelScan


		#RAL
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "RAL";
		$ParallelScan.Command = {
									$output = Remove-AzSKAlerts -SubscriptionId (Get-AzContext).Subscription.Id -Tags 'Mandatory'
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Remove-AzSKAlerts -Tags 'Mandatory''."
		[ParallelScan]::Jobs +=$ParallelScan

		#RAP
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "RAP";
		$ParallelScan.Command = {
									$output = Remove-AzSKARMPolicies -subscriptionId (Get-AzContext).Subscription.Id  -Tags 'Mandatory'
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Remove-AzSKARMPolicies -Tags 'Mandatory''."
		[ParallelScan]::Jobs +=$ParallelScan

		#RRB
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "RRB";
		$ParallelScan.Command = {
									$output = Remove-AzSKSubscriptionRBAC -SubscriptionId (Get-AzContext).Subscription.Id  -Tags 'Mandatory'
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Remove-AzSKSubscriptionRBAC -Tags 'Mandatory''."
		[ParallelScan]::Jobs +=$ParallelScan

		#RSS
		$ParallelScan = "" | Select JobName, Command, AzSKModule, AzSKModulePath, Description, Parameters
		$ParallelScan.JobName = "RSS";
		$ParallelScan.Command = {
									$output = Remove-AzSKSubscriptionSecurity -SubscriptionId (Get-AzContext).Subscription.Id  -Tags 'Mandatory'
								};
		$ParallelScan.Command = [ScriptBlock]::Create($ScriptBlock1.ToString() + "`n" + $ParallelScan.Command.ToString() + "`n" + $ScriptBlock2.ToString());
		$ParallelScan.AzSKModule = $AzSKModule
		$ParallelScan.AzSKModulePath = $AzSKModulePath
		$ParallelScan.Description = "Run command 'Remove-AzSKSubscriptionSecurity -Tags 'Mandatory''."
		[ParallelScan]::Jobs +=$ParallelScan

		return [ParallelScan]::Jobs;
	}
}


