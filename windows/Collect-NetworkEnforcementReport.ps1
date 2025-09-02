# WiFi/Policy Enforcement Diagnostic – All-in-one
# Save as: Collect-NetworkEnforcementReport.ps1
# Run in elevated PowerShell

$Stamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$OutDir  = Join-Path $env:USERPROFILE "Desktop\WiFi_Enforcement_Report_$Stamp"
$null = New-Item -ItemType Directory -Path $OutDir -Force

$Txt = Join-Path $OutDir "Summary_$Stamp.txt"
function Add-Section($title) {
    "`n==================== $title ====================`n" | Out-File -Append -FilePath $Txt -Encoding UTF8
}

"WiFi/Policy Enforcement Report  -  $((Get-Date).ToString())" | Out-File $Txt -Encoding UTF8
"Output folder: $OutDir" | Out-File -Append $Txt

# Helper: run command and tee to file + summary
function Run-Capture {
    param(
        [Parameter(Mandatory)] [string]$Title,
        [Parameter(Mandatory)] [string]$FileName,
        [Parameter(Mandatory)] [scriptblock]$Script
    )
    Add-Section $Title
    $path = Join-Path $OutDir $FileName
    try {
        $out = & $Script | Out-String
        $out | Out-File -FilePath $path -Encoding UTF8
        ("Saved -> {0}" -f $FileName) | Out-File -Append $Txt
    } catch {
        ("ERROR running {0}: {1}" -f $Title, $_) | Out-File -Append $Txt
    }
}

# 1) System / OS
Run-Capture -Title "System & OS" -FileName "01_System.txt" -Script {
    $ci = Get-ComputerInfo
    $ci | Select-Object CsName, OsName, OsVersion, WindowsVersion, OsArchitecture, BiosFirmwareType, CsTotalPhysicalMemory
}

# 2) Network adapters & drivers
Run-Capture -Title "Net Adapters & Drivers" -FileName "02_NetAdapters.txt" -Script {
    Get-NetAdapter | Sort-Object ifIndex | Format-Table -Auto Name, InterfaceDescription, Status, MacAddress, LinkSpeed, DriverInformation
    ""
    "---- Detailed PnP ----"
    Get-PnpDevice -Class Net -PresentOnly | ForEach-Object {
        $drvVer = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_DriverVersion' -ErrorAction SilentlyContinue).Data
        $drvProv = (Get-PnpDeviceProperty -InstanceId $_.InstanceId -KeyName 'DEVPKEY_Device_DriverProvider' -ErrorAction SilentlyContinue).Data
        [pscustomobject]@{ Name=$_.FriendlyName; Class=$_.Class; Status=$_.Status; DriverProvider=$drvProv; DriverVersion=$drvVer; InstanceId=$_.InstanceId }
    } | Format-List
}

# 3) DNS config, routes, ARP, listeners
Run-Capture -Title "DNS Config" -FileName "03_DNS.txt" -Script {
    Get-DnsClientServerAddress | Format-Table -Auto
    ""
    Get-DnsClientGlobalSetting | Format-List
}
Run-Capture -Title "Routing Table" -FileName "04_Routes.txt" -Script { route print }
Run-Capture -Title "ARP Table"   -FileName "05_ARP.txt"    -Script { arp -a }
Run-Capture -Title "Active Listeners" -FileName "06_Netstat.txt" -Script { netstat -abno }

# 4) WLAN: visible networks, profiles, filters, settings
Run-Capture -Title "WLAN Visible Networks (BSSID)" -FileName "10_WLAN_BSSID_INITIAL.txt" -Script { netsh wlan show networks mode=bssid }
Run-Capture -Title "WLAN Profiles" -FileName "11_WLAN_Profiles.txt" -Script { netsh wlan show profiles }
Run-Capture -Title "WLAN Filters"  -FileName "12_WLAN_Filters.txt"  -Script { netsh wlan show filters }
Run-Capture -Title "WLAN Settings" -FileName "13_WLAN_Settings.txt" -Script { netsh wlan show settings }

# 5) Group Policy results (HTML + text)
Add-Section "Group Policy Results"
$gpHtml = Join-Path $OutDir "20_GPResult.html"
$gpTxt  = Join-Path $OutDir "21_GPResult.txt"
try {
    gpresult /h "$gpHtml" /f | Out-Null
    "Saved -> 20_GPResult.html" | Out-File -Append $Txt
} catch { "ERROR: gpresult /h failed: $_" | Out-File -Append $Txt }
try {
    gpresult /r /scope computer > "$gpTxt"
    gpresult /r /scope user    >> "$gpTxt"
    "Saved -> 21_GPResult.txt" | Out-File -Append $Txt
} catch { "ERROR: gpresult /r failed: $_" | Out-File -Append $Txt }

# 6) MDM / AAD join state
Run-Capture -Title "AAD/MDM (dsregcmd)" -FileName "30_dsregcmd_status.txt" -Script { dsregcmd /status }

# 7) Services (running, with paths)
Run-Capture -Title "Running Services (with ImagePath)" -FileName "40_Services.txt" -Script {
    Get-WmiObject Win32_Service | Where-Object { $_.State -eq 'Running' } |
      Select-Object Name, DisplayName, StartMode, State, StartName, PathName |
      Sort-Object Name | Format-Table -Auto
}

# 8) Startup items (Run keys, Startup folders)
Run-Capture -Title "Startup Items (All)" -FileName "41_Startup.txt" -Script {
    Get-CimInstance Win32_StartupCommand |
      Select-Object Name, Command, Location, User |
      Sort-Object Name | Format-Table -Auto
}

# 9) Scheduled Tasks (full + focused network/WLAN view)
Run-Capture -Title "Scheduled Tasks (full list)" -FileName "50_Tasks_All.txt" -Script {
    Get-ScheduledTask | ForEach-Object {
        $info = [pscustomobject]@{
            TaskName   = $_.TaskName
            Path       = $_.TaskPath
            State      = ($_ | Get-ScheduledTaskInfo).State
            Triggers   = ($_.Triggers | Out-String).Trim()
            Actions    = ($_.Actions  | Out-String).Trim()
        }
        $info
    } | Sort-Object TaskName | Format-List
}
Run-Capture -Title "Scheduled Tasks (Network/WLAN focused)" -FileName "51_Tasks_Focused.txt" -Script {
    $rx = '(wlan|wifi|wireless|network|npcap|killer|intel|qualcomm|supplicant|watchdog|proxy|filter|policy|mdm)'
    Get-ScheduledTask | Where-Object {
        $_.TaskName -match $rx -or $_.TaskPath -match $rx -or
        (($_.Actions | Out-String) -match $rx) -or
        (($_.Triggers| Out-String) -match $rx)
    } | ForEach-Object {
        [pscustomobject]@{
            TaskName = $_.TaskName
            Path     = $_.TaskPath
            State    = ($_ | Get-ScheduledTaskInfo).State
            Triggers = ($_.Triggers | Out-String).Trim()
            Actions  = ($_.Actions  | Out-String).Trim()
        }
    } | Sort-Object TaskName | Format-List
}

# 10) Hosts file copy
try {
    Copy-Item "$env:SystemRoot\System32\drivers\etc\hosts" (Join-Path $OutDir "60_hosts_copy.txt") -Force
    Add-Section "Hosts file"
    "Saved -> 60_hosts_copy.txt" | Out-File -Append $Txt
} catch { "ERROR copying hosts: $_" | Out-File -Append $Txt }

# 11) 30-minute WLAN visibility logger (every 60s)
Add-Section "WLAN Visibility Logger (30 minutes)"
$LogPath = Join-Path $OutDir "WLAN_BSSID_TIMELINE.log"
"Starting 30-minute logger -> $LogPath" | Out-File -Append $Txt
$ScriptBlock = {
    param($Path)
    for ($i=1; $i -le 30; $i++) {
        "===== $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') =====" | Out-File -Append -FilePath $Path -Encoding UTF8
        try {
            netsh wlan show networks mode=bssid | Out-File -Append -FilePath $Path -Encoding UTF8
        } catch {
            "ERROR: $_" | Out-File -Append -FilePath $Path -Encoding UTF8
        }
        Start-Sleep -Seconds 60
    }
}
$job = Start-Job -ScriptBlock $ScriptBlock -ArgumentList $LogPath
"Background Job Id: $($job.Id). It will stop automatically after ~30 minutes." | Out-File -Append $Txt

# 12) Final notes
Add-Section "How to review"
@"
• Open $Txt for a quick index.
• Open 20_GPResult.html in a browser to inspect applied policies (look for Wireless/WLAN policies).
• Compare 10_WLAN_BSSID_INITIAL.txt vs WLAN_BSSID_TIMELINE.log to catch the “everything → one SSID” change.
• Check 51_Tasks_Focused.txt for any task that runs at logon/startup touching WLAN/Network.
• Check 40_Services.txt and 41_Startup.txt for unknown executables/paths.
"@ | Out-File -Append $Txt -Encoding UTF8

Write-Host "Done. Report folder -> $OutDir"
