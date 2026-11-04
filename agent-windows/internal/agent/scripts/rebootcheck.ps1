# Does this host owe a reboot? Prints 'yes' or 'no'.
foreach ($p in @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired')) {
    if (Test-Path $p) { Write-Output 'yes'; exit 0 }
}
if (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' `
        -Name PendingFileRenameOperations -ErrorAction SilentlyContinue) { Write-Output 'yes'; exit 0 }
Write-Output 'no'
