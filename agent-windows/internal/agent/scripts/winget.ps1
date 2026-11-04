# Report third-party apps with an available upgrade, via the Windows
# Package Manager (winget).
#
# winget covers software Windows Update never sees -- Chrome, Notepad++,
# Zoom and the like. It has no stable machine-readable output for
# `upgrade`, so its table is parsed by the column offsets its own header
# row declares, which survives localised text and version strings far
# better than splitting on whitespace would.
#
# Emits one JSON object. `present` is false on a host with no winget,
# which is not a failure: there is simply nothing for winget to manage,
# and a phantom failing source there would alarm forever. `ok` is false
# only when winget IS present but the query itself failed -- a real "we
# could not tell", distinct from "nothing is upgradable".
$ErrorActionPreference = 'Stop'

function Emit($obj) { $obj | ConvertTo-Json -Depth 4 -Compress }

# winget is an App Installer alias on each user's PATH; the agent runs as
# SYSTEM, which has none, so look where Windows installs it too and take
# the newest version there.
$winget = Get-Command winget -ErrorAction SilentlyContinue
if (-not $winget) {
    $found = Resolve-Path "$env:ProgramFiles\WindowsApps\Microsoft.DesktopAppInstaller_*_x64__8wekyb3d8bbwe\winget.exe" -ErrorAction SilentlyContinue |
        Sort-Object { [version](($_.Path -split '_')[1]) } -ErrorAction SilentlyContinue | Select-Object -Last 1
    if ($found) { $winget = Get-Command $found.Path -ErrorAction SilentlyContinue }
}
if (-not $winget) {
    Emit([pscustomobject]@{ present = $false; ok = $false; error = 'winget (App Installer) is not installed'; updates = @() })
    exit 0
}

try {
    # UTF-8 so app names with non-ASCII characters are not mangled, and
    # --disable-interactivity so no progress spinner is interleaved into
    # the table we are about to parse.
    $prev = [Console]::OutputEncoding
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    try {
        $raw = & $winget.Source upgrade --include-unknown --accept-source-agreements --disable-interactivity 2>&1
    } finally {
        [Console]::OutputEncoding = $prev
    }
    $lines = @($raw | ForEach-Object { $_.ToString() })

    # The header row is the one naming the columns. Everything above it is
    # source-agreement chatter; the row of dashes right below it is the
    # separator, and the data rows follow until a blank line or a summary
    # line like "N upgrades available".
    $headerIdx = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '^\s*Name\s+Id\s+Version\s+Available\s+Source') { $headerIdx = $i; break }
    }
    if ($headerIdx -lt 0) {
        # No header means winget listed nothing upgradable -- a clean
        # result, not a failure.
        Emit([pscustomobject]@{ present = $true; ok = $true; error = ''; updates = @() })
        exit 0
    }

    $header = $lines[$headerIdx]
    # Column start offsets, taken from where each title begins in the
    # header. Slicing by these offsets is what keeps a name with spaces in
    # the Name column instead of spilling into Id.
    $cId   = $header.IndexOf('Id')
    $cVer  = $header.IndexOf('Version')
    $cAvl  = $header.IndexOf('Available')
    $cSrc  = $header.IndexOf('Source')

    function Slice($line, $start, $end) {
        if ($start -ge $line.Length) { return '' }
        if ($end -lt 0 -or $end -gt $line.Length) { $end = $line.Length }
        ($line.Substring($start, $end - $start)).Trim()
    }

    $updates = @()
    for ($i = $headerIdx + 2; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ([string]::IsNullOrWhiteSpace($line)) { break }
        # A trailing summary line ("N upgrades available.") has no column
        # structure; stop at it.
        if ($line -match '^\s*\d+\s+upgrades?\s+available') { break }
        if ($line -notmatch '\S') { continue }

        $name = Slice $line 0 $cId
        $id   = Slice $line $cId $cVer
        $cur  = Slice $line $cVer $cAvl
        $avl  = Slice $line $cAvl $cSrc
        if (-not $name -or -not $avl) { continue }

        $updates += [pscustomobject]@{
            package         = $name
            new_version     = $avl
            current_version = $cur
            # The winget package id (e.g. Google.Chrome) is what a later
            # phase will pass to `winget upgrade --id` to actually update.
            advisory        = $id
            # winget carries no security rating; leaving these neutral is
            # honest rather than guessing one.
            severity        = 'none'
            is_security     = $false
        }
    }

    Emit([pscustomobject]@{ present = $true; ok = $true; error = ''; updates = $updates })
} catch {
    Emit([pscustomobject]@{ present = $true; ok = $false; error = $_.Exception.Message; updates = @() })
}
