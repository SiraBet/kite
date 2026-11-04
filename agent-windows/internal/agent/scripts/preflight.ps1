# Is this host in a fit state to be patched?
$ErrorActionPreference = 'Stop'
$notes = New-Object System.Collections.Generic.List[string]

$svc = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
if (-not $svc) { Write-Output 'Windows Update service (wuauserv) not found on this host'; exit 1 }
$notes.Add("Windows Update service: $($svc.Status)")

$drive = Get-PSDrive -Name C -ErrorAction SilentlyContinue
if ($drive) {
    $freeGB = [Math]::Round($drive.Free / 1GB, 1)
    $notes.Add("C: free ${freeGB}GB")
    # A cumulative update needs room to stage and to keep a rollback
    # copy; running out part-way is how a host ends up unbootable.
    if ($freeGB -lt 3) { Write-Output (($notes -join '; ') + ' -- BLOCKING: under 3GB free on C:'); exit 1 }
}

$pending = $false
foreach ($p in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) {
    if (Test-Path $p) { $pending = $true }
}
if ($pending) { $notes.Add('a reboot was already outstanding before this job; the reboot stage will handle it') }

Write-Output ($notes -join '; ')
exit 0
