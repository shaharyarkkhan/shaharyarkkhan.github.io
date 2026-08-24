<#
.SYNOPSIS
    Cross-Platform System Health & Security Audit Script

.DESCRIPTION
    Checks common things an IT support / help desk technician looks at when
    diagnosing "why is this machine slow" or "is this machine secure":
      - Disk space
      - Memory usage
      - Admin/root-level group membership (security check)
      - Firewall status
      - Last OS update check
    Works on both macOS and Windows via PowerShell 7 — detects the OS with
    $IsMacOS / $IsWindows and runs the right checks for each.
    Outputs a colour-coded HTML report.

.AUTHOR
    Shaharyar Khan

.NOTES
    Run with PowerShell 7 (pwsh), not the old Windows PowerShell 5.
    On Mac:      pwsh ./SystemHealthAudit.ps1
    On Windows:  .\SystemHealthAudit.ps1
    If scripts are blocked on Windows, run once:
        Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
#>

# ---------------------------------------------------------------------------
# SETUP
# ---------------------------------------------------------------------------
$reportPath = Join-Path $PSScriptRoot "HealthReport_$(Get-Date -Format 'yyyy-MM-dd_HHmm').html"
$results = @()

# Helper function: adds one row of results to our $results array.
# Learning note: functions stop us repeating the same code for every check.
function Add-Result {
    param(
        [string]$Category,
        [string]$Detail,
        [string]$Status   # "OK", "WARNING", or "FAIL"
    )
    $script:results += [PSCustomObject]@{
        Category = $Category
        Detail   = $Detail
        Status   = $Status
    }
}

Write-Host "Running system health audit on $(if ($IsMacOS) {'macOS'} elseif ($IsWindows) {'Windows'} else {'Linux'})..." -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# CHECK 1: DISK SPACE
# Get-PSDrive is built into PowerShell itself, so it works identically on
# every OS — no need to branch this check by platform.
# ---------------------------------------------------------------------------
$drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Used -gt 0 }
foreach ($drive in $drives) {
    $totalGB = [math]::Round(($drive.Used + $drive.Free) / 1GB, 1)
    if ($totalGB -eq 0) { continue }
    $freeGB  = [math]::Round($drive.Free / 1GB, 1)
    $freePercent = [math]::Round(($drive.Free / ($drive.Used + $drive.Free)) * 100, 1)

    $status = if ($freePercent -lt 10) { "FAIL" }
              elseif ($freePercent -lt 15) { "WARNING" }
              else { "OK" }

    Add-Result -Category "Disk Space" `
        -Detail "$($drive.Name): — $freeGB GB free of $totalGB GB ($freePercent% free)" `
        -Status $status
}

# ---------------------------------------------------------------------------
# CHECK 2: MEMORY USAGE
# Windows and macOS report memory completely differently, so this check
# branches by OS.
# ---------------------------------------------------------------------------
if ($IsMacOS) {
    # vm_stat gives memory stats in "pages". Default page size is 4096 bytes.
    $vmStat = vm_stat
    $pageSize = 4096
    $free = ($vmStat | Select-String "Pages free:\s+(\d+)").Matches.Groups[1].Value
    $active = ($vmStat | Select-String "Pages active:\s+(\d+)").Matches.Groups[1].Value
    $wired = ($vmStat | Select-String "Pages wired down:\s+(\d+)").Matches.Groups[1].Value

    $freeGB = [math]::Round(($free * $pageSize) / 1GB, 1)
    $usedGB = [math]::Round((($active + $wired) * $pageSize) / 1GB, 1)
    $totalGB = [math]::Round($freeGB + $usedGB, 1)
    $usedPercent = [math]::Round(($usedGB / $totalGB) * 100, 1)
}
elseif ($IsWindows) {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
    $freeGB  = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
    $usedPercent = [math]::Round((($totalGB - $freeGB) / $totalGB) * 100, 1)
}

$memStatus = if ($usedPercent -gt 90) { "FAIL" }
             elseif ($usedPercent -gt 80) { "WARNING" }
             else { "OK" }

Add-Result -Category "Memory" `
    -Detail "$usedPercent% used ($freeGB GB free of $totalGB GB)" `
    -Status $memStatus

# ---------------------------------------------------------------------------
# CHECK 3: ADMIN GROUP MEMBERSHIP (security check)
# Anyone in this group can make system-wide changes — worth knowing who.
# ---------------------------------------------------------------------------
if ($IsMacOS) {
    try {
        $adminUsers = dscl . -read /Groups/admin GroupMembership 2>$null
        Add-Result -Category "Security" -Detail "macOS admin group: $adminUsers" -Status "OK"
    } catch {
        Add-Result -Category "Security" -Detail "Could not read admin group" -Status "WARNING"
    }
}
elseif ($IsWindows) {
    try {
        $admins = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name
        Add-Result -Category "Security" -Detail "Local Administrators: $($admins -join ', ')" -Status "OK"
    } catch {
        Add-Result -Category "Security" -Detail "Could not read Administrators group (needs admin rights)" -Status "WARNING"
    }
}

# ---------------------------------------------------------------------------
# CHECK 4: FIREWALL STATUS
# ---------------------------------------------------------------------------
if ($IsMacOS) {
    try {
        $fwState = /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
        $fwStatus = if ($fwState -match "enabled") { "OK" } else { "FAIL" }
        Add-Result -Category "Firewall" -Detail "macOS Firewall: $fwState" -Status $fwStatus
    } catch {
        Add-Result -Category "Firewall" -Detail "Could not read firewall status" -Status "WARNING"
    }
}
elseif ($IsWindows) {
    try {
        $fwProfiles = Get-NetFirewallProfile
        foreach ($fw in $fwProfiles) {
            $fwStatus = if ($fw.Enabled) { "OK" } else { "FAIL" }
            Add-Result -Category "Firewall" -Detail "$($fw.Name) profile enabled: $($fw.Enabled)" -Status $fwStatus
        }
    } catch {
        Add-Result -Category "Firewall" -Detail "Could not read firewall status" -Status "WARNING"
    }
}

# ---------------------------------------------------------------------------
# CHECK 5: LAST OS UPDATE CHECK
# ---------------------------------------------------------------------------
if ($IsMacOS) {
    try {
        $swUpdate = softwareupdate --history | Select-Object -Last 3
        Add-Result -Category "OS Updates" -Detail "Recent update history: $($swUpdate -join ' | ')" -Status "OK"
    } catch {
        Add-Result -Category "OS Updates" -Detail "Could not read update history" -Status "WARNING"
    }
}
elseif ($IsWindows) {
    try {
        $lastUpdate = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
        if ($lastUpdate) {
            $daysSince = (Get-Date) - $lastUpdate.InstalledOn
            $updateStatus = if ($daysSince.Days -gt 60) { "WARNING" } else { "OK" }
            Add-Result -Category "OS Updates" `
                -Detail "Last update installed: $($lastUpdate.InstalledOn.ToShortDateString()) ($($daysSince.Days) days ago)" `
                -Status $updateStatus
        }
    } catch {
        Add-Result -Category "OS Updates" -Detail "Could not read update history" -Status "WARNING"
    }
}
# ---------------------------------------------------------------------------
# CHECK 6: BATTERY HEALTH (Mac laptops only — no equivalent needed on desktops)
# ---------------------------------------------------------------------------
if ($IsMacOS) {
    try {
        $batteryInfo = system_profiler SPPowerDataType 2>$null

        if ($batteryInfo -match "Cycle Count") {
            $cycleCount = ($batteryInfo | Select-String "Cycle Count:\s+(\d+)").Matches.Groups[1].Value
            $condition  = ($batteryInfo | Select-String "Condition:\s+(.+)").Matches.Groups[1].Value.Trim()
            $chargePct  = (pmset -g batt | Select-String "(\d+)%").Matches.Groups[1].Value

            $battStatus = if ($condition -ne "Normal") { "WARNING" }
                          elseif ([int]$cycleCount -gt 1000) { "WARNING" }
                          else { "OK" }

            Add-Result -Category "Battery" `
                -Detail "Charge: $chargePct% | Cycle count: $cycleCount | Condition: $condition" `
                -Status $battStatus
        } else {
            Add-Result -Category "Battery" -Detail "No battery detected (desktop Mac)" -Status "OK"
        }
    } catch {
        Add-Result -Category "Battery" -Detail "Could not read battery info" -Status "WARNING"
    }
}
# ---------------------------------------------------------------------------
# BUILD THE HTML REPORT
# ---------------------------------------------------------------------------
$rows = $results | ForEach-Object {
    $colour = switch ($_.Status) {
        "OK"      { "#d4edda" }
        "WARNING" { "#fff3cd" }
        "FAIL"    { "#f8d7da" }
    }
    "<tr style='background-color:$colour'><td>$($_.Category)</td><td>$($_.Detail)</td><td><b>$($_.Status)</b></td></tr>"
}

$osName = if ($IsMacOS) { "macOS" } elseif ($IsWindows) { "Windows" } else { "Linux" }

$html = @"
<html>
<head>
<title>System Health Report</title>
<style>
  body { font-family: Segoe UI, Arial, sans-serif; margin: 40px; }
  table { border-collapse: collapse; width: 100%; }
  td, th { border: 1px solid #ccc; padding: 8px 12px; text-align: left; }
  th { background-color: #333; color: white; }
</style>
</head>
<body>
  <h1>System Health & Security Audit</h1>
  <p>Host: $(hostname) &nbsp;|&nbsp; OS: $osName &nbsp;|&nbsp; Generated: $(Get-Date)</p>
  <table>
    <tr><th>Category</th><th>Detail</th><th>Status</th></tr>
    $($rows -join "`n")
  </table>
</body>
</html>
"@

$html | Out-File -FilePath $reportPath -Encoding UTF8

Write-Host "Report saved to: $reportPath" -ForegroundColor Green

if ($IsMacOS) { open $reportPath }
elseif ($IsWindows) { Invoke-Item $reportPath }
