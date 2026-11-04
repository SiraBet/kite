# Report pending Windows updates with their severity.
#
# Uses the Windows Update Agent COM API, which is present on every
# supported Windows host. Deliberately NOT PSWindowsUpdate: that module
# has to be installed from PSGallery first, which needs internet access
# to a host that may have none, and turns "assess this machine" into
# "install software on this machine".
#
# Emits one JSON object so the caller does not have to parse prose.
$ErrorActionPreference = 'Stop'
try {
    $session  = New-Object -ComObject Microsoft.Update.Session
    $searcher = $session.CreateUpdateSearcher()
    # IsInstalled=0 and IsHidden=0: what is actually outstanding, minus
    # anything an administrator has deliberately hidden.
    $result   = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software' and BrowseOnly=0")

    $updates = @()
    foreach ($u in $result.Updates) {
        # MsrcSeverity is Microsoft's own rating and is empty for
        # non-security updates. Left as 'none' rather than guessed at.
        $severity = if ($u.MsrcSeverity) { $u.MsrcSeverity.ToLower() } else { 'none' }
        $kb = ($u.KBArticleIDs | ForEach-Object { "KB$_" }) -join ','
        $updates += [pscustomobject]@{
            package     = $u.Title
            new_version = $kb
            advisory    = $kb
            severity    = $severity
            is_security = [bool]$u.MsrcSeverity
        }
    }
    [pscustomobject]@{ ok = $true; error = ''; updates = $updates } | ConvertTo-Json -Depth 4 -Compress
} catch {
    # An unreachable WSUS or a stopped service is "we could not tell",
    # which is not the same as "nothing is pending". The caller must not
    # report this host as fully patched.
    [pscustomobject]@{ ok = $false; error = $_.Exception.Message; updates = @() } | ConvertTo-Json -Depth 4 -Compress
}
