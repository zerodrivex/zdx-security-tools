# === WSL/Hyper-V/Network/MDM/VPN Deep Audit ===
# Runs read-only checks and writes a report to Desktop.
$ts = Get-Date -Format 'yyyyMMdd_HHmmss'
$Out = "$env:USERPROFILE\Desktop\WSL_HV_Audit_$ts.txt"
"==== WSL / Hyper-V / Network / MDM / VPN Audit ====" | Out-File $Out -Encoding UTF8

Function Run-Cmd {
    param([string]$Cmd, [string[]]$Args)
    "`n--- $Cmd $($Args -join ' ') ---" | Out-File $Out -Append
    try {
        $p = Start-Process -FilePath $Cmd -ArgumentList $Args -NoNewWindow -PassThru -Wait -RedirectStandardOutput "$env:TEMP\__out.txt" -RedirectStandardError "$env:TEMP\__err.txt"
        if (Test-Path "$env:TEMP\__out.txt") { Get-Content "$env:TEMP\__out.txt" | Out-File $Out -Append }
        if (Test-Path "$env :TEMP\__err.txt") { "`n[stderr]:" | Out-File $Out -Append; Get-Content "$env:TEMP\__err.txt" | Out-File $Out -Append }
    } catch {
        "Error running $Cmd: $($_.Exception.Message)" | Out-File $Out -Append
    } finally {
        Remove-Item "$env:TEMP\__out.txt","$env:TEMP\__err.txt" -ErrorAction SilentlyContinue
    }
}

"== Basic system ==" | Out-File $Out -Append
(Get-ComputerInfo | Select-Object WindowsProductName,WindowsVersion,OsBuildNumber,OsArchitecture) | Format-List | Out-File $Out -Append

"== Accounts: local users and admin group ==" | Out-File $Out -Append
try {
  Get-LocalUser | Select-Object Name,Enabled,LastLogon | Format-Table -Auto | Out-File $Out -Append
  "`n-- Administrators group members --" | Out-File $Out -Append
  Get-LocalGroupMember -Group 'Administrators' | Select-Object Name, ObjectClass, PrincipalSource | Format-Table -Auto | Out-File $Out -Append
} catch { "Local user APIs not available: $($_.Exception.Message)" | Out-File $Out -Append }

"== WSL distros ==" | Out-File $Out -Append
Run-Cmd wsl.exe @('--list','--verbose')
Run-Cmd wsl.exe @('--status')

"== Hyper-V footprint (if present) ==" | Out-File $Out -Append
try {
  Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V* | Out-File $Out -Append
  Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform | Out-File $Out -Append
  Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux | Out-File $Out -Append
} catch {}

"`n-- Hyper-V switches --" | Out-File $Out -Append
try { Get-VMSwitch | Format-Table Name,SwitchType,NetAdapterInterfaceDescription | Out-File $Out -Append } catch { "Get-VMSwitch not available." | Out-File $Out -Append }

"`n-- Processes related to virtualization --" | Out-File $Out -Append
Get-Process vmmem,vmwp,vmcompute -ErrorAction SilentlyContinue |
  Select-Object Name, Id, CPU, WS, PM, StartTime |
  Sort-Object Name | Format-Table -Auto | Out-File $Out -Append

"== Network adapters & IP config ==" | Out-File $Out -Append
Get-NetAdapter | Sort-Object ifIndex | Format-Table ifIndex,Name,InterfaceDescription,Status,MacAddress,LinkSpeed -Auto | Out-File $Out -Append
"`n-- IP configuration --" | Out-File $Out -Append
Get-NetIPConfiguration | Format-List | Out-File $Out -Append
"`n-- Routes (IPv4) --" | Out-File $Out -Append
Get-NetRoute -AddressFamily IPv4 | Sort-Object DestinationPrefix,InterfaceIndex | Format-Table -Auto | Out-File $Out -Append
"`n-- Routes (IPv6) --" | Out-File $Out -Append
Get-NetRoute -AddressFamily IPv6 | Sort-Object DestinationPrefix,InterfaceIndex | Format-Table -Auto | Out-File $Out -Append

"`n-- Listening ports (top 100 by process)" | Out-File $Out -Append
Get-NetTCPConnection -State Listen | Group-Object OwningProcess | Sort-Object Count -Descending |
  Select-Object -First 100 |
  ForEach-Object {
    $p = Get-Process -Id $_.Name -ErrorAction SilentlyContinue
    [PSCustomObject]@{ Proc=$p.ProcessName; PID=$_.Name; Listeners=$_.Count }
  } | Format-Table -Auto | Out-File $Out -Append

"`n-- DNS client settings --" | Out-File $Out -Append
Get-DnsClientGlobalSetting | Out-File $Out -Append
Get-DnsClientServerAddress | Sort-Object InterfaceIndex | Format-Table InterfaceAlias,ServerAddresses -Auto | Out-File $Out -Append

"`n-- NCSI / Proxy / WinHTTP --" | Out-File $Out -Append
Run-Cmd netsh @('winhttp','show','proxy')
Run-Cmd reg.exe @('query','HKLM\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet','/s')

"`n-- VPN profiles --" | Out-File $Out -Append
try {
  Get-VpnConnection -AllUserConnection -ErrorAction SilentlyContinue | Format-List | Out-File $Out -Append
  Get-VpnConnection -ErrorAction SilentlyContinue | Format-List | Out-File $Out -Append
} catch { "VPN cmdlets not available: $($_.Exception.Message)" | Out-File $Out -Append }

"`n== Device Management / MDM / AAD join state ==" | Out-File $Out -Append
Run-Cmd dsregcmd.exe @('/status')
Run-Cmd powershell @('-NoProfile','-Command','Get-ScheduledTask | ? {$_.TaskName -match "Device|MDM|Enrollment|Intune|Enterprise"} | Select TaskName,TaskPath,State | Format-Table -Auto')

"`n== Installed network filter drivers (NDIS) ==" | Out-File $Out -Append
Run-Cmd pnputil.exe @('/enum-drivers')

"`n== Root certificates (Top 40 by nearest expiry) ==" | Out-File $Out -Append
Get-ChildItem Cert:\LocalMachine\Root | Sort-Object NotAfter |
  Select-Object -First 40 Subject, NotAfter, Thumbprint | Format-Table -Auto | Out-File $Out -Append

"`n== Services of interest (capture/virtualization/update) ==" | Out-File $Out -Append
$svc = 'npcap','WinPcap','HvHost','vmcompute','LxssManager','WlanSvc','dnscache','IKEEXT','MDM','DiagTrack','W32Time'
Get-Service | Where-Object { $svc -contains $_.Name } | Format-Table Name,Status,StartType,DisplayName -Auto | Out-File $Out -Append

"`n== Scheduled tasks likely to touch networking/virtualization ==" | Out-File $Out -Append
Get-ScheduledTask | Where-Object {
    $_.TaskName -match 'wsl|hyper|vm|network|vpn|update|trace|telemetry|diagnostic|npcap|nvidia'
} | Select-Object TaskName,TaskPath,State | Sort-Object TaskPath,TaskName | Format-Table -Auto | Out-File $Out -Append

"`n[Report written to] $Out" | Out-File $Out -Append
Write-Host "Done. Report: $Out"
