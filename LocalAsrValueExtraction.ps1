# Author: Wittkie #
# Date: 2025-06-02 #
# Name: Local ASR Value Extraction #
# Purpose: To identify the configured Attack Surface Reduction rules in place on a Windows Device #

# Define a file output location #
$outputFilePath = "~\Desktop\Local ASR Value Extraction Results"

# Write information #
Get-Date -Format "yyyy/MM/dd HH:mm K" | Write-Output | Out-File -FilePath $outputFilePath
Write-Output "Device: $env:COMPUTERNAME`n" | Out-File -FilePath $outputFilePath -Append

# Get the ASRRules registry value and store it in a variable #
$asrRules = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "ASRRules").ASRRules

# Define the Get-AsrValue function #
function Get-AsrValue
{
    if ($asrRules -Match "$currentAsrGuid=0")
    {
        Write-Output "The value for $currentAsrRule is not configured, or set to Disabled" | Out-File -FilePath $outputFilePath -Append
    }
    elseif ($asrRules -Match "$currentAsrGuid=1")
    {
        Write-Output "The value for $currentAsrRule is set to Block" | Out-File -FilePath $outputFilePath -Append
    }
    elseif ($asrRules -Match "$currentAsrGuid=2")
    {
        Write-Output "The value for $currentAsrRule is set to Audit" | Out-File -FilePath $outputFilePath -Append
    }
    elseif ($asrRules -Match "$currentAsrGuid=6")
    {
        Write-Output "The value for $currentAsrRule is set to Warn" | Out-File -FilePath $outputFilePath -Append
    }
    else
    {
        Write-Output "The value for $currentAsrRule was not found" | Out-File -FilePath $outputFilePath -Append
    }
}

# Block abuse of exploited vulnerable signed drivers #
$currentAsrRule = "Block abuse of exploited vulnerable signed drivers"
$currentAsrGuid = "56a863a9-875e-4185-98a7-b882c64b5ce5"
Get-AsrValue

# Block Adobe Reader from creating child processes #
$currentAsrRule = "Block Adobe Reader from creating child processes"
$currentAsrGuid = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"
Get-AsrValue

# Block all Office applications from creating child processes #
$currentAsrRule = "Block all Office applications from creating child processes"
$currentAsrGuid = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
Get-AsrValue

# Block credential stealing from the Windows local security authority subsystem (lsass.exe) #
$currentAsrRule = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
$currentAsrGuid = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
Get-AsrValue

# Block executable content from email client and webmail #
$currentAsrRule = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
$currentAsrGuid = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"
Get-AsrValue

# Block executable files from running unless they meet a prevalence, age, or trusted list criterion #
$currentAsrRule = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
$currentAsrGuid = "01443614-cd74-433a-b99e-2ecdc07bfc25"
Get-AsrValue

# Block execution of potentially obfuscated scripts #
$currentAsrRule = "Block execution of potentially obfuscated scripts"
$currentAsrGuid = "5beb7efe-fd9a-4556-801d-275e5ffc04cc"
Get-AsrValue

# Block JavaScript or VBScript from launching downloaded executable content #
$currentAsrRule = "Block JavaScript or VBScript from launching downloaded executable content"
$currentAsrGuid = "d3e037e1-3eb8-44c8-a917-57927947596d"
Get-AsrValue

# Block Office applications from creating executable content #
$currentAsrRule = "Block Office applications from creating executable content"
$currentAsrGuid = "3b576869-a4ec-4529-8536-b80a7769e899"
Get-AsrValue

# Block Office applications from injecting code into other processes #
$currentAsrRule = "Block Office applications from injecting code into other processes"
$currentAsrGuid = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"
Get-AsrValue

# Block Office communication application from creating child processes #
$currentAsrRule = "Block Office communication application from creating child processes"
$currentAsrGuid = "26190899-1602-49e8-8b27-eb1d0a1ce869"
Get-AsrValue

# Block persistence through WMI event subscription #
$currentAsrRule = "Block persistence through WMI event subscription"
$currentAsrGuid = "e6db77e5-3df2-4cf1-b95a-636979351e5b"
Get-AsrValue

# Block process creations originating from PSExec and WMI commands #
$currentAsrRule = "Block process creations originating from PSExec and WMI commands"
$currentAsrGuid = "d1e49aac-8f56-4280-b9ba-993a6d77406c"
Get-AsrValue

# Block rebooting machine in Safe Mode #
$currentAsrRule = "Block rebooting machine in Safe Mode"
$currentAsrGuid = "33ddedf1-c6e0-47cb-833e-de6133960387"
Get-AsrValue

# Block untrusted and unsigned processes that run from USB #
$currentAsrRule = "Block untrusted and unsigned processes that run from USB"
$currentAsrGuid = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"
Get-AsrValue

# Block use of copied or impersonated system tools #
$currentAsrRule = "Block use of copied or impersonated system tools"
$currentAsrGuid = "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb"
Get-AsrValue

# Block Webshell creation for Servers #
$currentAsrRule = "Block Webshell creation for Servers"
$currentAsrGuid = "a8f5898e-1dc8-49a9-9878-85004b8a61e6"
Get-AsrValue

# Block Win32 API calls from Office macros #
$currentAsrRule = "Block Win32 API calls from Office macros"
$currentAsrGuid = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"
Get-AsrValue

# Use advanced protection against ransomware #
$currentAsrRule = "Use advanced protection against ransomware"
$currentAsrGuid = "c1db55ab-c21a-4637-bb3f-a12568109d35"
Get-AsrValue

# Append raw data to end of the file #

# Output the value for ASRRules #
Write-Output "`nASRRules: $asrRules" | Out-File -FilePath $outputFilePath -Append

# Get the ASROnlyExclusions registry value and store it in a variable #
$asrOnlyExclusions = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "ASROnlyExclusions").ASROnlyExclusions

# Output the value for ASROnlyExclusions #
Write-Output "`nASROnlyExclusions: $asrOnlyExclusions" | Out-File -FilePath $outputFilePath -Append

# Get the ASROnlyPerRuleExclusions registry value and store it in a variable #
$asrOnlyPerRuleExclusions = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "ASROnlyPerRuleExclusions").ASROnlyPerRuleExclusions

# Output the value for ASROnlyPerRuleExclusions #
Write-Output "`nASROnlyPerRuleExclusions: $asrOnlyPerRuleExclusions" | Out-File -FilePath $outputFilePath -Append