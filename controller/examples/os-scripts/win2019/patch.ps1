<#
'patch' stage script for the Windows family (Server 2016/2019/2022/
2025, Windows 10/11).

Retries only on a detected transient Windows Update error (another
servicing session in progress, BITS transfer hiccup) — a real failure
(blocked update, disk space, corrupt component store) is not retried,
so it fails fast and visibly instead of masking the real problem behind
3x the wait. Never reboots — that's the separate, non-scriptable
'reboot' stage the agent handles itself after this stage reports done.

Available env vars (set by the agent before running this):
  KITE_JOB_ID    - the run's job id
  KITE_HOSTNAME  - this host's hostname
  KITE_STAGE     - always "patch" for this script
  KITE_EXCLUDES  - space-separated skip-mode KB-id/title patterns
  KITE_PINS      - space-separated "pattern=version" pin-mode entries
                       (Windows has no version-pin mechanism - these are
                       applied as plain excludes, same as skip-mode)

Contract: exit 0 = stage succeeded, any other exit code = stage failed.
Combined stdout+stderr is captured (last 4000 chars) and shown in the
Progress screen/audit log. The agent enforces a hard 3600s timeout on
this script regardless of anything set here.
#>

$ErrorActionPreference = "Continue"
$excludesStatePath = "C:\ProgramData\kite\wu_excludes.json"
$maxAttempts = 3
$retrySeconds = 30

Write-Output "== patch: $($env:KITE_HOSTNAME) (job $($env:KITE_JOB_ID)) =="
Write-Output "excludes: [$($env:KITE_EXCLUDES)]"
$driveBefore = Get-PSDrive -Name C -ErrorAction SilentlyContinue
if ($driveBefore) { Write-Output "disk free before: $([Math]::Round($driveBefore.Free / 1GB, 1))GB" }

if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Output "PSWindowsUpdate module not found - installing..."
    try {
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force -Scope AllUsers | Out-Null
        }
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted -ErrorAction SilentlyContinue
        Install-Module -Name PSWindowsUpdate -Force -Scope AllUsers -ErrorAction Stop
    } catch {
        Write-Output "failed to install PSWindowsUpdate: $($_.Exception.Message)"
        exit 1
    }
}
Import-Module PSWindowsUpdate -ErrorAction Stop

$excludePatterns = @()
if (Test-Path $excludesStatePath) {
    try { $excludePatterns = @(Get-Content $excludesStatePath -Raw | ConvertFrom-Json) } catch { $excludePatterns = @() }
}
$kbPatterns = @($excludePatterns | Where-Object { $_ -match '^KB\d+$' })
$titlePatterns = @($excludePatterns | Where-Object { $_ -notmatch '^KB\d+$' })

$installArgs = @{ AcceptAll = $true; IgnoreReboot = $true; Confirm = $false }
if ($kbPatterns.Count -gt 0) { $installArgs.NotKBArticleID = $kbPatterns }
if ($titlePatterns.Count -gt 0) { $installArgs.NotTitle = $titlePatterns }

function Test-TransientWuError([string]$message) {
    return $message -match 'another (installation|process|session)|0x8024001E|0x80240022|BITS|being shut down|resource temporarily'
}

$attempt = 1
$succeeded = $false
$lastOutput = ""
while ($attempt -le $maxAttempts -and -not $succeeded) {
    Write-Output "Install-WindowsUpdate attempt $attempt/$maxAttempts"
    try {
        $result = Install-WindowsUpdate @installArgs -Verbose 4>&1 | Out-String
        $lastOutput = $result.Trim()
        $succeeded = $true
    } catch {
        $lastOutput = $_.Exception.Message
        if ((Test-TransientWuError $lastOutput) -and $attempt -lt $maxAttempts) {
            Write-Output "transient Windows Update error detected - retrying in ${retrySeconds}s: $lastOutput"
            Start-Sleep -Seconds $retrySeconds
            $attempt++
            continue
        }
        Write-Output "Install-WindowsUpdate FAILED: $lastOutput"
        exit 1
    }
}

if (-not $succeeded) {
    Write-Output "Install-WindowsUpdate did not succeed after $maxAttempts attempts"
    exit 1
}

Write-Output "== patch summary =="
Write-Output $lastOutput
$driveAfter = Get-PSDrive -Name C -ErrorAction SilentlyContinue
if ($driveAfter) { Write-Output "disk free after: $([Math]::Round($driveAfter.Free / 1GB, 1))GB" }

$pendingRebootPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
)
foreach ($p in $pendingRebootPaths) {
    if (Test-Path $p) {
        Write-Output "note: a reboot is now pending - the 'reboot' stage will pick this up"
        break
    }
}

Write-Output "patch OK"
exit 0
