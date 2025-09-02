runnfirst:

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\WiFi-RogueAP-Report.ps1


# WiFi-RogueAP-Report.ps1
$ts   = Get-Date -Format "yyyyMMdd_HHmmss"
$base = Join-Path $env:USERPROFILE "Desktop\WiFi_RogueAP_$ts"
$txt  = "$base.txt"
$csv  = "$base.csv"

function Write-Head($h){ "`n===== $h =====`n" | Out-File -FilePath $txt -Append -Encoding UTF8 }
function Cap($title,$scriptBlock){
  Write-Head $title
  & $scriptBlock 2>&1 | Out-File -FilePath $txt -Append -Encoding UTF8
}

# 1) Machine & adapter info
Cap "Computer / OS"        { Get-ComputerInfo | Select-Object OsName,OsVersion,OsBuildNumber,WindowsProductName,WindowsEditionId }
Cap "Adapters (Get-NetAdapter)" { Get-NetAdapter | Sort-Object ifIndex | Format-List * }
Cap "WLAN Driver Capabilities (netsh wlan show drivers)" { netsh wlan show drivers }
Cap "Current WLAN Interfaces (netsh wlan show interfaces)" { netsh wlan show interfaces }
Cap "Saved WLAN Profiles (netsh wlan show profiles)" { netsh wlan show profiles }

# 2) Live scan of nearby networks (same command you used)
$scanRaw = netsh wlan show networks mode=bssid
Cap "Nearby Networks (netsh wlan show networks mode=bssid)" { $scanRaw }

# 3) Parse the scan into structured objects so we can analyze
$ssid = $null; $bssid = $null
$items = New-Object System.Collections.Generic.List[object]

foreach($line in $scanRaw){
  if($line -match '^\s*SSID\s+\d+\s*:\s*(.+)$'){ $ssid = $Matches[1].Trim(); continue }
  if($line -match '^\s*BSSID\s+\d+\s*:\s*([0-9A-Fa-f:]{17})'){ $bssid = $Matches[1].ToLower(); $obj = [ordered]@{SSID=$ssid;BSSID=$bssid}; $items.Add([pscustomobject]$obj); continue }
  if($items.Count -gt 0){
    $cur = $items[$items.Count-1]
    if($line -match '^\s*Signal\s*:\s*(\d+)\%'){ $cur.Signal=[int]$Matches[1] }
    elseif($line -match '^\s*Radio type\s*:\s*(.+)$'){ $cur.RadioType=$Matches[1].Trim() }
    elseif($line -match '^\s*Band\s*:\s*(.+)$'){ $cur.Band=$Matches[1].Trim() }
    elseif($line -match '^\s*Channel\s*:\s*(\d+)'){ $cur.Channel=[int]$Matches[1] }
    elseif($line -match '^\s*Details\s*:\s*\((.+)\)'){ $cur.Details=$Matches[1].Trim() }
    elseif($line -match '^\s*Basic rates .*:\s*(.+)$'){ $cur.BasicRates=$Matches[1].Trim() }
    elseif($line -match '^\s*Other rates .*:\s*(.+)$'){ $cur.OtherRates=$Matches[1].Trim() }
  }
}

# 4) Save structured scan to CSV
$items | Sort-Object SSID,Band,Channel,BSSID | Export-Csv -NoTypeInformation -Path $csv -Encoding UTF8

# 5) Simple anomaly checks
Write-Head "Heuristics / Potential Anomalies"
$alerts = @()

# A) Multiple 6GHz BSSIDs for same SSID on same channel
$dup6 = $items | Where-Object { $_.Band -match '6\s*GHz' } |
        Group-Object SSID,Channel |
        Where-Object { $_.Count -gt 1 }
foreach($g in $dup6){
  $alerts += "Multiple 6GHz BSSIDs on Channel $($g.Group[0].Channel) for SSID '$($g.Group[0].SSID)': " +
             ($g.Group | ForEach-Object { "$($_.BSSID) (${($_.Signal)}%)" } -join "; ")
}

# B) Mixed H2E support differences (can indicate different implementations)
$byssid = $items | Group-Object SSID
foreach($g in $byssid){
  $details = $g.Group | Where-Object { $_.Details } | Select-Object -ExpandProperty Details -Unique
  if($details.Count -gt 1){
    $alerts += "Different 'Details' flags for SSID '$($g.Name)': " + ($details -join " | ")
  }
}

if($alerts.Count -eq 0){
  "No obvious anomalies found by simple rules." | Out-File -FilePath $txt -Append -Encoding UTF8
}else{
  $alerts | Out-File -FilePath $txt -Append -Encoding UTF8
}

# 6) Routing/ARP context (useful if a rogue AP is bridging)
Cap "Route Print" { route print }
Cap "ARP Table (arp -a)" { arp -a }

"`nReport written:`n $txt`n $csv" | Write-Host
