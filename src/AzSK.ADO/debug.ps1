Import-Module "C:\Users\Chesta Mittal\Desktop\ADOScanner\src\AzSK.ADO\AzSKStaging.ADO.psd1"
#gads -oz safetitestvso -rtn organization -ResetCredentials
#Get-AzSKADOSecurityStatus -OrganizationName  -ProjectNames  -ServiceConnectionNames "ADAuto2"
#Get-AzSKADOSecurityStatus -OrganizationName "SafetiTestVSO" -ProjectName "abcdemo" -rtn Build  #-controlids "ADO_Project_SI_Limit_Variables_Settable_At_Queue_Time" -upc -PrepareForControlFix 
#Set-AzSKADOSecurityStatus -OrganizationName "SafetiTestVSO" -ProjectName "abcdemo" -controlids "ADO_Project_SI_Limit_Variables_Settable_At_Queue_Time"
#Set-AzSKADOBaselineConfigurations -OrganizationName "SafetiTestVSO" -ProjectName "abcdemo" -ResourceTypeName Project   
#Set-AzSKADOBaselineConfigurations -OrganizationName "SafetiTestVSO" -ProjectName "AzSDKDemoRepo" -ResourceTypeName Build -BuildNames "Test2202New"
Set-AzSKADOBaselineConfigurations -OrganizationName "SafetiTestVSO" -ProjectName "AzSDKDemoRepo" -rtn project -Force
#gads -OrganizationName juhitiwari -ProjectName adotest -ResourceTypeName Project -Force -Verbose -PromptForPAT