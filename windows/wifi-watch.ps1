# wifi-watch.ps1  — continuous Wi‑Fi scan & diff reporter
# Press Ctrl+C to stop. Change $IntervalSeconds as you like.

$IntervalSeconds = 120
$logDir = "$env:USERPROFILE\WiFiWatch"
$new = New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$csvPath = Join-Path $logDir "wifi_scans.csv"
$txtPath = Join-Path $logDir "wifi_report.txt"

function Get-CurrentBssid {
  $if = (netsh wlan show interfaces) -join "`n"
  if ($if -match '^\s*BSSID\s*:\s*(?<bssid>[0-9A-Fa-f:-]{17})') { $Matches.bssid } else { $null }
}

function Parse-NetshScan {
  $raw = (netsh wlan show networks mode=bssid) -join "`n"
  $records = @()
  $ssid = $null
  $now = Get-Date
  foreach ($line in $raw -split "`n") {
    if ($line -match '^\s*SSID\s+\d+\s*:\s*(?<ssid>.+)$') { $ssid = $Matches.ssid.Trim(); continue }
    if ($line -match '^\s*BSSID\s+\d+\s*:\s*(?<bssid>[0-9A-Fa-f:-]{17})') { $bssid = $Matches.bssid.ToLower(); $rec = [ordered]@{Time=$now; SSID=$ssid; BSSID=$bssid; Vendor=$null; BandGHz=$null; Channel=$null; SignalPct=$null}; $records += New-Object psobject -Property $rec; continue }
    if ($records.Count -gt 0) {
      $last = $records[-1]
      if ($line -match '^\s*Signal\s*:\s*(?<sig>\d+)\s*%') { $last.SignalPct = [int]$Matches.sig }
      elseif ($line -match '^\s*Radio type\s*:\s*(?<rt>.+)$') {
        $rt = $Matches.rt.Trim().ToLower()
        $last.BandGHz = if ($rt -match '6\w*e') { 6.0 } elseif ($rt -match '802\.11a|ac|ax') { 5.0 } elseif ($rt -match '802\.11b|g|n') { 2.4 } else { $null }
      }
      elseif ($line -match '^\s*Channel\s*:\s*(?<ch>\d+)') { $last.Channel = [int]$Matches.ch }
    }
  }
  # Add vendor OUI for quick eyeballing
  foreach ($r in $records) {
    $oui = ($r.BSSID -replace '[:-]','').Substring(0,6).ToUpper()
    $r.Vendor = $oui
  }
  return ,$records
}

function Append-Csv($rows) {
  $exists = Test-Path $csvPath
  $rows | Export-Csv -Path $csvPath -NoTypeInformation -Append:($exists) -Force
}

function Diff-And-Report($prev, $curr) {
  $t = Get-Date
  $prevSet = $prev | ForEach-Object { $_.BSSID } | Sort-Object -Unique
  $currSet = $curr | ForEach-Object { $_.BSSID } | Sort-Object -Unique
  $newB = Compare-Object $prevSet $currSet | Where-Object { $_.SideIndicator -eq '=>' } | ForEach-Object { $_.InputObject }
  $goneB = Compare-Object $prevSet $currSet | Where-Object { $_.SideIndicator -eq '<=' } | ForEach-Object { $_.InputObject }

  $currBySsid = $curr | Group-Object SSID
  $ssidCollisions = @()
  foreach ($g in $currBySsid) {
    $ouis = ($g.Group | Select-Object -ExpandProperty Vendor | Sort-Object -Unique)
    if ($ouis.Count -gt 1) {
      $ssidCollisions += [pscustomobject]@{SSID=$g.Name; OUIs=($ouis -join ','); BSSIDs=($g.Group.BSSID -join ',')}
    }
  }

  $lines = @()
  $lines += "===== WiFiWatch @ $t ====="
  $lines += "Current connected BSSID: $(Get-CurrentBssid)"
  $lines += "Visible SSIDs: $($currBySsid.Count) | BSSIDs: $($curr.Count)"
  if ($newB.Count) { $lines += "NEW BSSIDs:  $($newB -join ', ')" }
  if ($goneB.Count){ $lines += "REMOVED BSSIDs:  $($goneB -join ', ')" }
  if ($ssidCollisions.Count){
    $lines += "SSID collisions (same SSID, different OUIs):"
    foreach ($c in $ssidCollisions){ $lines += "  - $($c.SSID): OUIs {$($c.OUIs)} | BSSIDs {$($c.BSSIDs)}" }
  }
  $lines += "Top by signal:"
  $lines += ($curr | Sort-Object SignalPct -Descending | Select-Object -First 10 |
    ForEach-Object { "  {0,-24} {1,-17} ch {2,-3} band {3,4}GHz  {4,3}%" -f $_.SSID, $_.BSSID, $_.Channel, $_.BandGHz, $_.SignalPct })

  Add-Content -Path $txtPath -Value ($lines -join "`r`n")
}

Write-Host "WiFiWatch logging to:`n  $csvPath`n  $txtPath`nPress Ctrl+C to stop." -ForegroundColor Cyan

$prev = @()
while ($true) {
  $curr = Parse-NetshScan
  Append-Csv $curr
  if ($prev.Count) { Diff-And-Report $prev $curr } else { Add-Content -Path $txtPath -Value "===== WiFiWatch started $(Get-Date) =====" }
  $prev = $curr
  Start-Sleep -Seconds $IntervalSeconds
}
