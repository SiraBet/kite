# This machine's SMBIOS UUID: the hardware id the controller binds its
# enrollment to, and matches against Proxmox VMs' smbios1 uuid.
try { (Get-CimInstance Win32_ComputerSystemProduct).UUID.Trim().ToLower() } catch { '' }
