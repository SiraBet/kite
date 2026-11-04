# One line describing this host, for the Fleet page.
try { (Get-CimInstance Win32_OperatingSystem).Caption.Trim() } catch { 'Windows' }
