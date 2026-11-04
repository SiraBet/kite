# This host on the network: adapters and their addresses, the default
# gateway, and the sockets it listens on with the owning process. Read
# only, from the NetTCPIP cmdlets every supported Windows ships. One JSON
# line; ok=false means "could not tell", not "nothing open".
$ErrorActionPreference = 'Stop'
try {
    $names = @{}
    foreach ($p in Get-Process) { $names[[int]$p.Id] = $p.ProcessName }

    $interfaces = @()
    foreach ($a in Get-NetAdapter) {
        $addrs = @(Get-NetIPAddress -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike 'fe80*' -and $_.IPAddress -notlike '169.254.*' } |
            ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength)" })
        $interfaces += [pscustomobject]@{
            name = $a.Name; mac = [string]$a.MacAddress; up = ($a.Status -eq 'Up')
            kind = $(if ($a.Virtual) { 'virtual' } else { '' }); addresses = $addrs
        }
    }

    $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric | Select-Object -First 1
    $gateway = $(if ($route) { [string]$route.NextHop } else { '' })

    $listening = @()
    foreach ($c in Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue) {
        $listening += [pscustomobject]@{ proto = 'tcp'; address = [string]$c.LocalAddress; port = [int]$c.LocalPort
                                         process = [string]$names[[int]$c.OwningProcess] }
    }
    foreach ($u in Get-NetUDPEndpoint -ErrorAction SilentlyContinue) {
        $listening += [pscustomobject]@{ proto = 'udp'; address = [string]$u.LocalAddress; port = [int]$u.LocalPort
                                         process = [string]$names[[int]$u.OwningProcess] }
    }

    [pscustomobject]@{ ok = $true; error = ''; interfaces = $interfaces; default_gateway = $gateway
                       listening = $listening } | ConvertTo-Json -Depth 4 -Compress
} catch {
    [pscustomobject]@{ ok = $false; error = $_.Exception.Message } | ConvertTo-Json -Compress
}
