<#
.SYNOPSIS
    Watches an OctoWoW login server and tells you the moment it starts answering again.
    Optionally launches the client for you when it does.

.DESCRIPTION
    OctoWoW sits behind DDoS scrubbing, and while an attack is being filtered your packets are
    silently dropped rather than refused - which is why the client sits there and times out
    instead of giving you a real error. The outage is usually intermittent: the path comes back
    on its own once the scrubber settles.

    Rather than alt-tabbing to retry the login over and over, this polls the login port every
    few seconds and reports the moment a TCP handshake completes. It tracks how long the
    current state has held, so you can see whether things are improving or getting worse.

    The server's addresses change from time to time, so they come from OctoWoW's own DNS
    server (37.156.68.20) - never from the hosts file, which only knows what the hosts
    updater pinned the last time it ran - and are looked up again every minute. When they
    move, it says so. And since the client connects to whatever THIS PC resolves, hosts file
    first, it warns when that points somewhere the server no longer is: that is the moment to
    run "Update OctoWoW Hosts".

    A server can have more than one address - normal.octowow.st is round-robin - so every
    address is probed at once each round, and the report says how many are answering and which.

    A plain TCP connect is all this does - it never sends credentials and never touches the
    auth handshake, so it is safe to leave running.

.PARAMETER HostName
    The server to watch. Defaults to play.octowow.st, which is what the realmlist uses;
    "Watch OctoWoW Normal.cmd" passes normal.octowow.st.

.PARAMETER DnsServer
    Where the current addresses come from. Defaults to 37.156.68.20, OctoWoW's resolver - the
    same one the hosts updater asks. If it does not answer, this PC's own lookup is used.

.PARAMETER ResolveEverySeconds
    How often the addresses are looked up again. Defaults to 60.

.PARAMETER Address
    Fixed addresses to watch instead - nothing is looked up.

.PARAMETER Port
    Login port. Defaults to 3724.

.PARAMETER IntervalSeconds
    Seconds between probes. Defaults to 5. Do not set this very low - hammering a host that is
    already under attack is both rude and counterproductive.

.PARAMETER TimeoutSeconds
    How long each probe waits for an answer. Defaults to 4.

.PARAMETER Launch
    Path to WoW.exe. When set, the client is started automatically on the first success and
    the script exits.

.PARAMETER Quiet
    Do not beep when the server comes back.

.EXAMPLE
    .\Wait-ForOctoWow.ps1
    Polls play.octowow.st until it answers, then beeps and tells you to log in.

.EXAMPLE
    .\Wait-ForOctoWow.ps1 -HostName normal.octowow.st
    The same for normal.octowow.st, every one of its addresses at once.

.EXAMPLE
    .\Wait-ForOctoWow.ps1 -Launch "D:\stuff\client - Copy (2)\WoW.exe"
    Polls, then launches the client for you the moment the server is reachable.
#>
[CmdletBinding()]
param(
    [string]   $HostName            = 'play.octowow.st',
    [string]   $DnsServer           = '37.156.68.20',
    [int]      $ResolveEverySeconds = 60,
    [string[]] $Address,
    [int]      $Port                = 3724,
    [int]      $IntervalSeconds     = 5,
    [int]      $TimeoutSeconds      = 4,
    [string]   $Launch,
    [switch]   $Quiet
)

$ErrorActionPreference = 'Stop'
$ipv4Pattern = '^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$'

# The addresses OctoWoW's DNS gives right now, sorted - never the hosts file's. Asked the same
# way the hosts updater asks, so the two tools can never disagree about where the server is.
function Resolve-Current {
    param([string] $Name, [string] $Server)
    $found = @()
    if (Get-Command -Name Resolve-DnsName -ErrorAction SilentlyContinue) {
        try {
            # -DnsOnly skips LLMNR/NetBIOS; -NoHostsFile is the point: the file may be stale.
            $answers = Resolve-DnsName -Name $Name -Type A -Server $Server -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop
            foreach ($a in $answers) {
                if ($a.PSObject.Properties['IPAddress']) { $found += $a.IPAddress }
            }
        } catch {
            return @()
        }
    } else {
        # Fallback for hosts without the DnsClient module.
        $raw = & nslookup.exe "-type=A" $Name $Server 2>$null
        $lines = @($raw) -split "`r?`n"
        $start = -1
        for ($i = 0; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^\s*Name:') { $start = $i; break }
        }
        if ($start -lt 0) { return @() }
        for ($i = $start; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^\s*Address(?:es)?:\s*(.+)$') {
                $found += ($matches[1] -split '[,\s]+')
            } elseif ($lines[$i] -match '^\s{2,}(\S+)\s*$') {
                $found += $matches[1]
            }
        }
    }
    @($found | Where-Object { $_ -match $ipv4Pattern } | Select-Object -Unique | Sort-Object { [version]$_ })
}

# Where the CLIENT will connect: this PC's own lookup, which reads the hosts file first.
function Resolve-ForClient {
    param([string] $Name)
    try {
        @([System.Net.Dns]::GetHostAddresses($Name) | Where-Object AddressFamily -eq 'InterNetwork' |
          ForEach-Object IPAddressToString | Sort-Object { [version]$_ })
    } catch {
        @()
    }
}

# Every address at once: a round of three silent addresses costs one timeout, not three.
function Get-AnsweringAddress {
    param([string[]] $Ips, [int] $Port, [int] $TimeoutSeconds)
    $probes = foreach ($ip in $Ips) {
        $client = New-Object System.Net.Sockets.TcpClient
        [pscustomobject]@{ Ip = $ip; Client = $client; Task = $client.ConnectAsync($ip, $Port) }
    }
    try {
        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        foreach ($p in $probes) {
            $left = [int][Math]::Max(0, ($deadline - (Get-Date)).TotalMilliseconds)
            # A refusal throws here. It means something is there, but nothing is accepting
            # logins on that port, so it does not count as answering.
            try { [void]$p.Task.Wait($left) } catch { }
        }
        @($probes | Where-Object { $_.Task.Status -eq 'RanToCompletion' -and $_.Client.Connected } |
          ForEach-Object Ip)
    } finally {
        foreach ($p in $probes) { $p.Client.Close() }
    }
}

# The hosts updater leaves out addresses that never answer, so the client using FEWER addresses
# than DNS gives is normal. Using one DNS no longer gives - or none at all - is not.
function Test-ClientStale {
    param([string[]] $ClientIps, [string[]] $CurrentIps)
    if (-not $ClientIps -or $ClientIps.Count -eq 0) { return $true }
    foreach ($ip in $ClientIps) {
        if ($CurrentIps -notcontains $ip) { return $true }
    }
    return $false
}

$static = [bool]$Address
$clientIps = @()
$source = 'fixed by -Address'
if (-not $static) {
    $Address = @(Resolve-Current -Name $HostName -Server $DnsServer)
    $source = "OctoWoW's DNS ($DnsServer)"
    if ($Address.Count -eq 0) {
        $Address = @(Resolve-ForClient -Name $HostName)
        $source = "this PC's lookup - $DnsServer did not answer"
    }
    if ($Address.Count -eq 0) {
        throw "Could not resolve $HostName, on $DnsServer or on this PC. Pass -Address to watch known addresses."
    }
    $clientIps = @(Resolve-ForClient -Name $HostName)
}

Write-Host ''
Write-Host 'Watching the OctoWoW login server' -ForegroundColor Cyan
if (-not $static) {
    Write-Host ('  server   : {0}' -f $HostName)
    Write-Host ('  address  : {0}   (from {1}, looked up again every {2}s)' -f ($Address -join ', '), $source, $ResolveEverySeconds)
} else {
    Write-Host ('  address  : {0}' -f ($Address -join ', '))
}
Write-Host ('  port     : {0}' -f $Port)
Write-Host ('  interval : every {0}s' -f $IntervalSeconds)
Write-Host '  Ctrl+C to stop.'
Write-Host ''

$staleShown = ''
function Show-ClientWarning {
    # Said once per distinct problem, not every minute.
    $key = $clientIps -join ','
    if (Test-ClientStale -ClientIps $clientIps -CurrentIps $Address) {
        if ($key -ne $script:staleShown) {
            $where = if ($clientIps.Count -gt 0) { $clientIps -join ', ' } else { 'nowhere - it cannot resolve the name' }
            Write-Host ('           your client would connect to {0}, which is not where {1} is now.' -f $where, $HostName) -ForegroundColor Yellow
            Write-Host '           run "Update OctoWoW Hosts" before logging in.' -ForegroundColor Yellow
            $script:staleShown = $key
        }
    } else {
        $script:staleShown = ''
    }
}
if (-not $static) { Show-ClientWarning }

$lastState    = $null
$stateSince   = Get-Date
$lastResolved = Get-Date
$attempts     = 0
$successes    = 0

while ($true) {
    # The addresses move now and then: look again every so often, and say when they have.
    if (-not $static -and ((Get-Date) - $lastResolved).TotalSeconds -ge $ResolveEverySeconds) {
        $lastResolved = Get-Date
        $fresh = @(Resolve-Current -Name $HostName -Server $DnsServer)
        if ($fresh.Count -gt 0) {
            if (($fresh -join ',') -ne ($Address -join ',')) {
                Write-Host ('[{0:HH:mm:ss}] MOVED - {1} is now {2} (was {3})' -f (Get-Date), $HostName,
                            ($fresh -join ', '), ($Address -join ', ')) -ForegroundColor Magenta
                $Address = $fresh
                $lastState = $null   # report afresh for the new addresses
            }
            $clientIps = @(Resolve-ForClient -Name $HostName)
            Show-ClientWarning
        }
    }

    $answering = @(Get-AnsweringAddress -Ips $Address -Port $Port -TimeoutSeconds $TimeoutSeconds)
    $up = $answering.Count -gt 0
    $state = $answering -join ','
    $attempts++
    if ($up) { $successes++ }

    $now = Get-Date
    if ($state -ne $lastState) {
        # Report only on change, so a long outage does not scroll away the useful history.
        $held = if ($null -eq $lastState) { '' }
                else { ' (previous state held {0:n0}s)' -f ($now - $stateSince).TotalSeconds }
        $wasUp = ($null -ne $lastState) -and ($lastState -ne '')

        if ($up) {
            $which = ''
            if ($Address.Count -gt 1) {
                $which = ' - {0} of {1}: {2}' -f $answering.Count, $Address.Count, ($answering -join ', ')
            }
            Write-Host ('[{0:HH:mm:ss}] UP - login server is answering{1}{2}' -f $now, $which, $held) -ForegroundColor Green

            # Up, but not where the client will go: logging in would still fail.
            $clientReaches = $static -or ($clientIps | Where-Object { $answering -contains $_ })
            if (-not $clientReaches) {
                Write-Host '           but not at an address your client uses - run "Update OctoWoW Hosts" first.' -ForegroundColor Yellow
            }

            # Only coming back up is news; one more address answering while up is not.
            if (-not $wasUp) {
                if (-not $Quiet) { [Console]::Beep(880, 200); [Console]::Beep(1320, 300) }

                if ($Launch -and $clientReaches) {
                    if (Test-Path $Launch) {
                        Write-Host ('           launching {0}' -f $Launch) -ForegroundColor Green
                        Start-Process -FilePath $Launch -WorkingDirectory (Split-Path -Parent $Launch)
                        break
                    }
                    Write-Host ('           cannot find {0}' -f $Launch) -ForegroundColor Yellow
                } elseif ($clientReaches) {
                    Write-Host '           go log in now.' -ForegroundColor Green
                }
            }
        } else {
            Write-Host ('[{0:HH:mm:ss}] DOWN - packets dropped, no answer{1}' -f $now, $held) -ForegroundColor Yellow
        }

        $lastState  = $state
        $stateSince = $now
    }

    Start-Sleep -Seconds $IntervalSeconds
}

Write-Host ''
Write-Host ('Probes: {0} / {1} succeeded ({2:n0}% reachable).' -f
            $successes, $attempts, (100 * $successes / [Math]::Max($attempts, 1))) -ForegroundColor Cyan
