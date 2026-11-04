# Post-patch sanity check: services set to start automatically that have
# failed. The Windows counterpart of `systemctl --failed`.
#
# "Automatic but not running" alone is not a failure on Windows:
#   - trigger-start services run only when something needs them (Group
#     Policy Client on a machine outside a domain sits stopped);
#   - a service that finished its work and stopped cleanly has exit code 0;
#   - delayed-start services only start ~2 minutes after boot, and this
#     check often runs straight after the reboot stage.
# So: wait until the machine has been up 3 minutes, then report automatic,
# non-trigger services that stopped with an error or never started.
$ErrorActionPreference = 'Stop'

$uptime = (Get-Date) - (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
$wait = 180 - [int]$uptime.TotalSeconds
if ($wait -gt 0) { Start-Sleep -Seconds $wait }

# Known to stop on their own on a healthy machine.
$ignore = @('gupdate','gupdatem','MapsBroker','RemoteRegistry','sppsvc','TrustedInstaller','edgeupdate','edgeupdatem')

$failed = foreach ($s in Get-CimInstance Win32_Service -Filter "StartMode='Auto' AND State!='Running'") {
    if ($s.Name -in $ignore) { continue }
    if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($s.Name)\TriggerInfo") { continue }
    if ($s.ExitCode -eq 0) { continue }
    "$($s.DisplayName) (exit $($s.ExitCode))"
}
if ($failed) { Write-Output ("automatic services failed: " + ($failed -join ', ')); exit 1 }
Write-Output 'no automatic service has failed'
exit 0
