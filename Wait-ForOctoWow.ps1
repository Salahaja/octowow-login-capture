<#
.SYNOPSIS
    Watches the OctoWoW login server and tells you the moment it starts answering again.
    Optionally launches the client for you when it does.

.DESCRIPTION
    OctoWoW sits behind DDoS scrubbing, and while an attack is being filtered your packets are
    silently dropped rather than refused - which is why the client sits there and times out
    instead of giving you a real error. The outage is usually intermittent: the path comes back
    on its own once the scrubber settles.

    Rather than alt-tabbing to retry the login over and over, this polls the login port every
    few seconds and reports the moment a TCP handshake completes. It tracks how long the
    current state has held, so you can see whether things are improving or getting worse.

    A plain TCP connect is all this does - it never sends credentials and never touches the
    auth handshake, so it is safe to leave running.

.PARAMETER Address
    Server addresses to watch. Defaults to the current play.octowow.st address, resolved live.

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
    Polls until the login server answers, then beeps and tells you to log in.

.EXAMPLE
    .\Wait-ForOctoWow.ps1 -Launch "D:\stuff\client - Copy (2)\WoW.exe"
    Polls, then launches the client for you the moment the server is reachable.
#>
[CmdletBinding()]
param(
    [string[]] $Address,
    [int]      $Port            = 3724,
    [int]      $IntervalSeconds = 5,
    [int]      $TimeoutSeconds  = 4,
    [string]   $Launch,
    [switch]   $Quiet
)

$ErrorActionPreference = 'Stop'

if (-not $Address) {
    try {
        $Address = [System.Net.Dns]::GetHostAddresses('play.octowow.st') |
                   Where-Object AddressFamily -eq 'InterNetwork' |
                   ForEach-Object IPAddressToString
    } catch {
        throw 'Could not resolve play.octowow.st. Re-run the hosts updater, or pass -Address.'
    }
}
if (-not $Address) { throw 'No addresses to watch.' }

function Test-LoginPort {
    param([string] $Ip, [int] $Port, [int] $TimeoutSeconds)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        if ($client.ConnectAsync($Ip, $Port).Wait($TimeoutSeconds * 1000) -and $client.Connected) {
            return $true
        }
        return $false
    } catch {
        # A refusal means something answered, which still tells us the path is open.
        return $false
    } finally {
        $client.Close()
    }
}

Write-Host ''
Write-Host 'Watching the OctoWoW login server' -ForegroundColor Cyan
Write-Host ('  target   : {0}:{1}' -f ($Address -join ', '), $Port)
Write-Host ('  interval : every {0}s' -f $IntervalSeconds)
Write-Host '  Ctrl+C to stop.'
Write-Host ''

$lastState  = $null
$stateSince = Get-Date
$attempts   = 0
$successes  = 0

while ($true) {
    $up = $false
    foreach ($ip in $Address) {
        if (Test-LoginPort -Ip $ip -Port $Port -TimeoutSeconds $TimeoutSeconds) { $up = $true; break }
    }
    $attempts++
    if ($up) { $successes++ }

    $now = Get-Date
    if ($up -ne $lastState) {
        # Report only on change, so a long outage does not scroll away the useful history.
        $held = if ($null -eq $lastState) { '' }
                else { ' (previous state held {0:n0}s)' -f ($now - $stateSince).TotalSeconds }

        if ($up) {
            Write-Host ('[{0:HH:mm:ss}] UP - login server is answering{1}' -f $now, $held) -ForegroundColor Green
            if (-not $Quiet) { [Console]::Beep(880, 200); [Console]::Beep(1320, 300) }

            if ($Launch) {
                if (Test-Path $Launch) {
                    Write-Host ('           launching {0}' -f $Launch) -ForegroundColor Green
                    Start-Process -FilePath $Launch -WorkingDirectory (Split-Path -Parent $Launch)
                    break
                }
                Write-Host ('           cannot find {0}' -f $Launch) -ForegroundColor Yellow
            } else {
                Write-Host '           go log in now.' -ForegroundColor Green
            }
        } else {
            Write-Host ('[{0:HH:mm:ss}] DOWN - packets dropped, no answer{1}' -f $now, $held) -ForegroundColor Yellow
        }

        $lastState  = $up
        $stateSince = $now
    }

    Start-Sleep -Seconds $IntervalSeconds
}

Write-Host ''
Write-Host ('Probes: {0} / {1} succeeded ({2:n0}% reachable).' -f
            $successes, $attempts, (100 * $successes / [Math]::Max($attempts, 1))) -ForegroundColor Cyan
