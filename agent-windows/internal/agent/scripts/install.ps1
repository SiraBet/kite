# Download and install pending Windows updates.
#
# $Exclude is a comma-separated list of title/KB patterns to skip, and
# $Severity narrows to Microsoft's own MsrcSeverity ratings ('' = all,
# 'security' = anything rated, otherwise a comma-separated list).
param([string]$Exclude = '', [string]$Severity = '')
$ErrorActionPreference = 'Stop'
$notes = New-Object System.Collections.Generic.List[string]

$patterns = @()
if ($Exclude) { $patterns = $Exclude.Split(',') | Where-Object { $_ } }
$levels = @()
if ($Severity -and $Severity -ne 'security') { $levels = $Severity.Split(',') | ForEach-Object { $_.Trim().ToLower() } }

$session  = New-Object -ComObject Microsoft.Update.Session
$searcher = $session.CreateUpdateSearcher()
# Software updates Windows Update offers on its own: no drivers, and no
# optional or preview updates (BrowseOnly), the same set search.ps1 lists.
$result   = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software' and BrowseOnly=0")

$wanted = New-Object -ComObject Microsoft.Update.UpdateColl
foreach ($u in $result.Updates) {
    $skip = $false
    foreach ($p in $patterns) {
        if ($u.Title -like "*$p*") { $skip = $true; $notes.Add("skipped by rule '$p': $($u.Title)"); break }
    }
    if ($skip) { continue }

    $sev = if ($u.MsrcSeverity) { $u.MsrcSeverity.ToLower() } else { '' }
    if ($Severity -eq 'security' -and -not $sev) { $notes.Add("skipped, not a security update: $($u.Title)"); continue }
    if ($levels.Count -gt 0 -and ($levels -notcontains $sev)) { $notes.Add("skipped, severity '$sev': $($u.Title)"); continue }

    if (-not $u.EulaAccepted) { $u.AcceptEula() }
    $wanted.Add($u) | Out-Null
}

if ($wanted.Count -eq 0) {
    $notes.Add('No updates matched; nothing installed.')
    Write-Output ($notes -join "`n"); exit 0
}

$downloader = $session.CreateUpdateDownloader()
$downloader.Updates = $wanted
$dl = $downloader.Download()
$notes.Add("download result code: $($dl.ResultCode)")

$installer = $session.CreateUpdateInstaller()
$installer.Updates = $wanted
$install = $installer.Install()
$notes.Add("install result code: $($install.ResultCode)  reboot required: $($install.RebootRequired)")
# Each update's own result: 2 installed, 3 installed with errors, 4
# failed, 5 aborted. Listed as they ended, not all as installed.
$failed = 0
for ($i = 0; $i -lt $wanted.Count; $i++) {
    $code = $install.GetUpdateResult($i).ResultCode
    $title = $wanted.Item($i).Title
    switch ($code) {
        2 { $notes.Add("installed: $title") }
        3 { $notes.Add("installed with errors: $title"); $failed++ }
        default { $notes.Add("failed (result $code): $title"); $failed++ }
    }
}

Write-Output ($notes -join "`n")
# Anything short of every update installing cleanly fails the stage
# (2 is the only clean result), so a partial patch run isn't reported as
# a complete one. Updates that did install stay installed.
if ($install.ResultCode -ne 2 -or $failed -gt 0) {
    Write-Output "$failed of $($wanted.Count) updates didn't install cleanly; the others are installed."
    exit 1
}
exit 0
