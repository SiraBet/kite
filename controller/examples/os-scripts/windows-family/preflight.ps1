<#
'preflight' stage script for the Windows family (Server 2016/2019/
2022/2025, Windows 10/11). Upload the same content under each os_family
key you actually see hosts report (e.g. win2019, win2022, win10, win11)
— one row per exact os_family string is required, the content can be
identical.

Goal: catch anything that would waste a maintenance window on a host
that was doomed to fail before Windows Update ever ran, and surface a
clear go/no-go summary in the Progress screen/audit log. Only genuinely
blocking conditions exit non-zero; everything else is a warning that
still lets the job proceed to 'excludes'/'patch'.

Threshold env vars (set as machine-level environment variables on the
host, or bake into a copy of this script per-fleet):
  KITE_MIN_C_FREE_GB (default 3)

Contract: exit 0 = stage succeeded, any other exit code = stage failed.
Combined stdout+stderr is captured and shown in the Progress screen/audit
log. Available env vars: KITE_JOB_ID, KITE_HOSTNAME,
KITE_STAGE, KITE_EXCLUDES, KITE_PINS (see patch.ps1 for the
full list).
#>

$ErrorActionPreference = "Continue"
$minFreeGB = if ($env:KITE_MIN_C_FREE_GB) { [double]$env:KITE_MIN_C_FREE_GB } else { 3 }

$notes = New-Object System.Collections.Generic.List[string]
$fail = $false
function Note([string]$msg) { $notes.Add($msg); Write-Output $msg }
function Blocking([string]$msg) { $notes.Add("BLOCKING: $msg"); Write-Output "BLOCKING: $msg"; $script:fail = $true }

Write-Output "== preflight: $($env:KITE_HOSTNAME) (job $($env:KITE_JOB_ID)) =="

# --- Windows Update service must at least be startable ---
$svc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
if (-not $svc) {
    Blocking "wuauserv (Windows Update) service not found on this host"
} elseif ($svc.StartType -eq "Disabled") {
    Blocking "wuauserv is set to Disabled - Windows Update cannot run"
} else {
    Note "wuauserv status: $($svc.Status), start type: $($svc.StartType)"
}

$bits = Get-Service -Name BITS -ErrorAction SilentlyContinue
if ($bits -and $bits.StartType -eq "Disabled") {
    Blocking "BITS service is Disabled - update downloads will fail"
} elseif ($bits) {
    Note "BITS status: $($bits.Status)"
}

# --- disk space ---
$drive = Get-PSDrive -Name C -ErrorAction SilentlyContinue
if ($drive) {
    $freeGB = [Math]::Round($drive.Free / 1GB, 1)
    if ($freeGB -lt $minFreeGB) {
        Blocking "C: has only ${freeGB}GB free, need ${minFreeGB}GB (cumulative updates and their rollback data are large)"
    } else {
        Note "C: free space: ${freeGB}GB (min ${minFreeGB}GB) - ok"
    }
} else {
    Note "could not read free space on C:"
}

# --- is a previous servicing operation still busy? ---
$tiworker = Get-Process -Name TiWorker -ErrorAction SilentlyContinue
if ($tiworker) {
    Note "TrustedInstaller (TiWorker.exe) is currently active - a servicing operation may already be in progress"
}

# --- WSUS reachability, if this host is pointed at one ---
$wsusServer = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name WUServer -ErrorAction SilentlyContinue).WUServer
if ($wsusServer) {
    try {
        $uri = [Uri]$wsusServer
        $test = Test-NetConnection -ComputerName $uri.Host -Port $uri.Port -WarningAction SilentlyContinue -ErrorAction Stop
        if ($test.TcpTestSucceeded) {
            Note "WSUS server reachable: $wsusServer"
        } else {
            Blocking "WSUS server configured ($wsusServer) but not reachable on $($uri.Port)"
        }
    } catch {
        Note "could not test WSUS reachability for $wsusServer - $($_.Exception.Message)"
    }
} else {
    Note "no WSUS policy configured - using Windows Update / Microsoft Update directly"
}

# --- how much work is 'patch' actually about to do (best-effort - needs PSWindowsUpdate) ---
if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
    try {
        Import-Module PSWindowsUpdate -ErrorAction Stop
        $pending = Get-WindowsUpdate -ErrorAction Stop
        Note "pending updates: $($pending.Count)"
    } catch {
        Note "could not enumerate pending updates: $($_.Exception.Message)"
    }
} else {
    Note "PSWindowsUpdate not installed yet - update count unavailable (will be installed automatically at the 'excludes'/'patch' stage)"
}

# --- reboot already outstanding from before this job even starts ---
$rebootPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
)
$pendingReboot = $false
foreach ($p in $rebootPaths) { if (Test-Path $p) { $pendingReboot = $true } }
if ($pendingReboot) {
    Note "host already has a reboot outstanding from before this job (unrelated prior change) - the 'reboot' stage will handle it after patching"
}

Write-Output "== preflight summary =="
$notes | ForEach-Object { Write-Output $_ }

if ($fail) {
    Write-Output "preflight FAILED - see BLOCKING lines above"
    exit 1
}
Write-Output "preflight OK"
exit 0
