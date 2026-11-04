# Everything installed, for the controller to match against vulnerability
# data. Read-only: the uninstall registry (what Programs and Features
# lists, for 64- and 32-bit programs), installed updates, and the exact
# OS build. One JSON line; ok=false means "could not tell".
$ErrorActionPreference = 'Stop'
try {
    $items = @()
    $keys = @(
        @{ path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; arch = 'x64' },
        @{ path = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; arch = 'x86' }
    )
    foreach ($k in $keys) {
        foreach ($p in @(Get-ItemProperty -Path $k.path -ErrorAction SilentlyContinue)) {
            # What Programs and Features shows: named, not a hidden system
            # component, not an update or a part of something else.
            if (-not $p.DisplayName -or $p.SystemComponent -eq 1 -or $p.ParentKeyName -or $p.ReleaseType) { continue }
            $items += [pscustomobject]@{ kind = 'app'; name = [string]$p.DisplayName; version = [string]$p.DisplayVersion
                                         publisher = [string]$p.Publisher; arch = $k.arch }
        }
    }
    foreach ($q in @(Get-CimInstance Win32_QuickFixEngineering -ErrorAction SilentlyContinue)) {
        if ($q.HotFixID) { $items += [pscustomobject]@{ kind = 'kb'; name = [string]$q.HotFixID; version = ''; publisher = 'Microsoft'; arch = '' } }
    }
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $build = "$($cv.CurrentMajorVersionNumber).$($cv.CurrentMinorVersionNumber).$($cv.CurrentBuild).$($cv.UBR)"
    # The machine's own architecture (AMD64 / ARM64 / x86), not this process's, and Client / Server / Server Core:
    # together they name the Windows product Microsoft's security data is listed under.
    $arch = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -ErrorAction SilentlyContinue).PROCESSOR_ARCHITECTURE
    $items += [pscustomobject]@{ kind = 'os'; name = [string]$cv.ProductName; version = $build; publisher = [string]$cv.DisplayVersion
                                 arch = [string]$arch; source_name = [string]$cv.InstallationType }
    [pscustomobject]@{ ok = $true; error = ''; items = $items } | ConvertTo-Json -Depth 4 -Compress
} catch {
    [pscustomobject]@{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
