<#
Script Info

Author: Wittkie
Repo: https://github.com/Wittkie/LocalAsrValueExtraction 

Disclaimer:
This sample script is not supported under any Microsoft standard support program or service. 
The sample script is provided AS IS without warranty of any kind. Microsoft further disclaims 
all implied warranties including, without limitation, any implied warranties of merchantability 
or of fitness for a particular purpose. The entire risk arising out of the use or performance of 
the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, 
or anyone else involved in the creation, production, or delivery of the scripts be liable for any 
damages whatsoever (including, without limitation, damages for loss of business profits, business 
interruption, loss of business information, or other pecuniary loss) arising out of the use of or 
inability to use the sample scripts or documentation, even if Microsoft has been advised of the 
possibility of such damages
#>

<#
.Synopsis
    Local ASR Value Extraction

.DESCRIPTION
    To identify the configured Attack Surface Reduction rules in place on a Windows Device.
    The script needs to run as an administrator.

.EXAMPLE
    .\Get-LocalAsrValueExtraction.ps1
 
.INPUTS
    No inputs.

.OUTPUTS
   It generates a file on the current user's desktop called Local ASR Value Extraction Results.txt.
   It also displays all the output in the current console.

.NOTES
    Version 1.0 - 2025-06-02
        - First public realese
    Version 2.0 - 2025-06-17
        - Overengineered update
        - Stop if the script does not run as an administrator
        - Correct bugs:
            - Incorrect name for ASR rule be9ba2d9-53ea-4cdc-84e5-9b1eeee46550
            - Silently fails if exception paths do not exist
#>

# Exits if not ran as an administrator #
if (-not ([Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "The script needs to run as an administrator"
}

# Define a file output location #
$outputFilePath = "~\Desktop\Local ASR Value Extraction Results.txt"

# Write information #
Get-Date -Format "yyyy/MM/dd HH:mm K" | Tee-Object -FilePath $outputFilePath
Write-Output "Device: $env:COMPUTERNAME`n" | Tee-Object -FilePath $outputFilePath -Append

# Define the list of ASR Rules to check for #
$asrRuleList = @(
    [pscustomobject]@{
        Name = "Block abuse of exploited vulnerable signed drivers"
        Guid = "56a863a9-875e-4185-98a7-b882c64b5ce5"
    },
    [pscustomobject]@{
        Name = "Block Adobe Reader from creating child processes"
        Guid = "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c"
    },
    [pscustomobject]@{
        Name = "Block all Office applications from creating child processes"
        Guid = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
    },
    [pscustomobject]@{
        Name = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
        Guid = "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2"
    },
    [pscustomobject]@{
        Name = "Block executable content from email client and webmail"
        Guid = "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550"
    },
    [pscustomobject]@{
        Name = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
        Guid = "01443614-cd74-433a-b99e-2ecdc07bfc25"
    },
    [pscustomobject]@{
        Name = "Block JavaScript or VBScript from launching downloaded executable content"
        Guid = "d3e037e1-3eb8-44c8-a917-57927947596d"
    },
    [pscustomobject]@{
        Name = "Block Office applications from creating executable content"
        Guid = "3b576869-a4ec-4529-8536-b80a7769e899"
    },
    [pscustomobject]@{
        Name = "Block Office applications from injecting code into other processes"
        Guid = "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84"
    },
    [pscustomobject]@{
        Name = "Block Office communication application from creating child processes"
        Guid = "26190899-1602-49e8-8b27-eb1d0a1ce869"
    },
    [pscustomobject]@{
        Name = "Block persistence through WMI event subscription"
        Guid = "e6db77e5-3df2-4cf1-b95a-636979351e5b"
    },
    [pscustomobject]@{
        Name = "Block process creations originating from PSExec and WMI commands"
        Guid = "d1e49aac-8f56-4280-b9ba-993a6d77406c"
    },
    [pscustomobject]@{
        Name = "Block rebooting machine in Safe Mode"
        Guid = "33ddedf1-c6e0-47cb-833e-de6133960387"
    },
    [pscustomobject]@{
        Name = "Block untrusted and unsigned processes that run from USB"
        Guid = "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4"
    },
    [pscustomobject]@{
        Name = "Block use of copied or impersonated system tools"
        Guid = "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb"
    },
    [pscustomobject]@{
        Name = "Block Webshell creation for Servers"
        Guid = "a8f5898e-1dc8-49a9-9878-85004b8a61e6"
    },
    [pscustomobject]@{
        Name = "Block Win32 API calls from Office macros"
        Guid = "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"
    },
    [pscustomobject]@{
        Name = "Use advanced protection against ransomware"
        Guid = "c1db55ab-c21a-4637-bb3f-a12568109d35"
    }
)

# Get the ASRRules registry value and store it in a variable #
$asrRules = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "ASRRules").ASRRules

# Parse the effective ASR rules #
$asrRuleList | ForEach-Object {
    $currentAsrGuid = $_.Guid
    $currentAsrRule = $_.Name
    switch -regex ($asrRules) {
        "$currentAsrGuid=0" { Write-Output "The value for $currentAsrRule is not configured, or set to Disabled" | Tee-Object -FilePath $outputFilePath -Append  }
        "$currentAsrGuid=1" { Write-Output "The value for $currentAsrRule is set to Block" | Tee-Object -FilePath $outputFilePath -Append}
        "$currentAsrGuid=2" { Write-Output "The value for $currentAsrRule is set to Audit" | Tee-Object -FilePath $outputFilePath -Append}
        "$currentAsrGuid=6" { Write-Output "The value for $currentAsrRule is is set to Warn" | Tee-Object -FilePath $outputFilePath -Append}
        default {"The value for $currentAsrRule was not found" | Tee-Object -FilePath $outputFilePath -Append}
    }
}


# Append raw data to end of the file #
# Output the value for ASRRules #
Write-Output "`nASRRules: $asrRules" | Tee-Object -FilePath $outputFilePath -Append

# Get the ASROnlyExclusions registry value and store it in a variable#
$asrOnlyExclusions = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "ASROnlyExclusions" -ErrorAction SilentlyContinue).ASROnlyExclusions
Write-Output "`nASROnlyExclusions: $asrOnlyExclusions" | Tee-Object -FilePath $outputFilePath -Append

# Get the ASROnlyPerRuleExclusions registry value and store it in a variable #
$asrOnlyPerRuleExclusions = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Policy Manager" -Name "ASROnlyPerRuleExclusions" -ErrorAction SilentlyContinue).ASROnlyPerRuleExclusions
Write-Output "`nASROnlyPerRuleExclusions: $asrOnlyPerRuleExclusions" | Tee-Object -FilePath $outputFilePath -Append