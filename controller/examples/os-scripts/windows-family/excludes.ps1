<#
'excludes' stage script for the Windows family (Server 2016/2019/2022/
2025, Windows 10/11).

Windows Update has no way to pin a package to an exact version and keep
it there across future updates — a security update either applies
cleanly or it doesn't. Pin-mode and skip-mode entries are therefore
treated identically here: both just keep that KB-id/title pattern out
of what 'patch' installs.

Installs the PSWindowsUpdate module if missing, validates each pattern
against what's currently pending (warns, doesn't fail, on a pattern
that matches zero pending updates — it might legitimately not be
offered yet), and persists the reconciled pattern list to
C:\ProgramData\kite\wu_excludes.json for the 'patch' stage to read.

Contract: exit 0 = stage succeeded, any other exit code = stage failed.
See patch.ps1 for the full KITE_* env var contract.
#>

$ErrorActionPreference = "Continue"
$excludesStatePath = "C:\ProgramData\kite\wu_excludes.json"

Write-Output "== excludes: $($env:KITE_HOSTNAME) (job $($env:KITE_JOB_ID)) =="

$skipPatterns = @()
if ($env:KITE_EXCLUDES) { $skipPatterns += ($env:KITE_EXCLUDES -split '\s+' | Where-Object { $_ }) }
$pinPatterns = @()
if ($env:KITE_PINS) {
    foreach ($entry in ($env:KITE_PINS -split '\s+' | Where-Object { $_ })) {
        # pattern=version - Windows can't pin to a version, so just take the pattern
        $pinPatterns += ($entry -split '=')[0]
    }
}
$allPatterns = @($skipPatterns + $pinPatterns) | Select-Object -Unique

if ($allPatterns.Count -eq 0) {
    Write-Output "no exclude rules to apply"
    "[]" | Set-Content -Path $excludesStatePath -Encoding UTF8
    Write-Output "excludes OK"
    exit 0
}

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
Import-Module PSWindowsUpdate -ErrorAction SilentlyContinue

$pending = $null
try { $pending = Get-WindowsUpdate -ErrorAction Stop } catch {
    Write-Output "warning: could not enumerate pending updates to validate patterns against - $($_.Exception.Message)"
}

foreach ($pattern in $allPatterns) {
    $mode = if ($skipPatterns -contains $pattern) { "skip" } else { "pin(treated as skip)" }
    if ($pending) {
        $hits = $pending | Where-Object { $_.KB -eq $pattern -or $_.Title -like "*$pattern*" }
        if ($hits.Count -eq 0) {
            Write-Output "note: exclude pattern '$pattern' ($mode) matches no currently-pending update - may be a typo, or it's simply not offered right now"
        } else {
            Write-Output "exclude pattern '$pattern' ($mode) matches $($hits.Count) pending update(s): $(($hits | Select-Object -ExpandProperty Title) -join '; ')"
        }
    } else {
        Write-Output "exclude pattern '$pattern' ($mode) - not validated (no pending-update list available)"
    }
}

$allPatterns | ConvertTo-Json | Set-Content -Path $excludesStatePath -Encoding UTF8
Write-Output "persisted $($allPatterns.Count) exclude pattern(s) to $excludesStatePath"
Write-Output "excludes OK"
exit 0
