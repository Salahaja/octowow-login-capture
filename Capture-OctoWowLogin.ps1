<#
.SYNOPSIS
    Captures the traffic between this PC and the OctoWoW login server, then tells you whether
    your packets are getting an answer. Run it and you are done - it elevates itself.

.DESCRIPTION
    A tcpdump for the WoW login handshake, built on pktmon, which ships with Windows - there is
    nothing to install. It filters on the OctoWoW realm addresses so the capture stays small,
    waits while you reproduce the failed login, then stops and writes three files:

      * <name>.etl     raw capture, the native format
      * <name>.pcapng  open this in Wireshark if you want a full decode
      * <name>.txt     plain-text packet list, readable without any extra tooling

    It finishes by counting packets in each direction and printing a verdict, because that one
    fact - did anything come back - is what separates a local problem from a server problem:

      * nothing sent          the client never tried; realmlist or the client is at fault
      * sent, nothing back    packets leave and die upstream; the path or the server
      * sent and received     the connection works at the IP layer, so the failure is in the
                              auth handshake itself - read the .txt or the .pcapng

.PARAMETER Address
    Server addresses to capture. Defaults to the current play/normal.octowow.st addresses,
    resolved live so a re-pinned IP is picked up automatically.

.PARAMETER Seconds
    Capture for this many seconds instead of waiting for a keypress. For unattended runs.

.PARAMETER OutputDirectory
    Where to write the capture files. Defaults to the folder this script lives in.

.PARAMETER KeepEtl
    Keep the raw .etl after conversion. By default it is deleted once the other two exist.

.EXAMPLE
    .\Capture-OctoWowLogin.ps1
    Starts capturing, waits while you launch WoW and fail a login, stops on a keypress.

.EXAMPLE
    .\Capture-OctoWowLogin.ps1 -Seconds 45
    Captures for 45 seconds unattended.

.NOTES
    pktmon requires Administrator rights, so this script re-launches itself elevated.
#>
[CmdletBinding()]
param(
    [string[]] $Address,
    [int]      $Seconds = 0,
    [string]   $OutputDirectory,
    [switch]   $KeepEtl
)

$ErrorActionPreference = 'Stop'

# --- elevate ------------------------------------------------------------------------------
$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host 'pktmon needs Administrator rights - re-launching elevated...' -ForegroundColor Yellow
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath)
    if ($Address)         { $argList += @('-Address', ($Address -join ',')) }
    if ($Seconds)         { $argList += @('-Seconds', $Seconds) }
    if ($OutputDirectory) { $argList += @('-OutputDirectory', $OutputDirectory) }
    if ($KeepEtl)         { $argList += '-KeepEtl' }
    Start-Process -FilePath (Get-Process -Id $PID).Path -Verb RunAs -ArgumentList $argList
    return
}

if (-not $OutputDirectory) { $OutputDirectory = Split-Path -Parent $PSCommandPath }
if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

$stamp  = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$base   = Join-Path $OutputDirectory "octowow-login_$stamp"
$etl    = "$base.etl"
$pcapng = "$base.pcapng"
$txt    = "$base.txt"

# --- work out what to capture -------------------------------------------------------------
if (-not $Address) {
    $Address = @()
    foreach ($name in 'play.octowow.st', 'normal.octowow.st') {
        try {
            $Address += ([System.Net.Dns]::GetHostAddresses($name) |
                         Where-Object AddressFamily -eq 'InterNetwork' |
                         ForEach-Object IPAddressToString)
        } catch {
            Write-Host "  could not resolve $name - skipping" -ForegroundColor DarkYellow
        }
    }
    $Address = $Address | Sort-Object -Unique
}
if (-not $Address) {
    throw 'No server addresses to capture. Re-run the hosts updater, or pass -Address.'
}

Write-Host ''
Write-Host 'OctoWoW login capture' -ForegroundColor Cyan
Write-Host ('  addresses : ' + ($Address -join ', '))
Write-Host ('  output    : ' + $OutputDirectory)
Write-Host ''

# --- clear anything a previous run left behind ---------------------------------------------
& pktmon stop          2>&1 | Out-Null
& pktmon filter remove 2>&1 | Out-Null

foreach ($ip in $Address) {
    & pktmon filter add "OctoWoW-$ip" -i $ip 2>&1 | Out-Null
}
Write-Host ('Filters set for {0} address(es).' -f $Address.Count) -ForegroundColor DarkGray

# --- capture -------------------------------------------------------------------------------
# --comp nics records one copy per packet at the adapter rather than one per network-stack
# layer, which otherwise makes every packet appear several times over.
& pktmon start --capture --comp nics --pkt-size 0 --file-name $etl --file-size 256 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    & pktmon filter remove 2>&1 | Out-Null
    throw "pktmon failed to start (exit $LASTEXITCODE)."
}

Write-Host ''
Write-Host 'CAPTURING.' -ForegroundColor Green
Write-Host '  Launch WoW now and try to log in, all the way through to the error.' -ForegroundColor Green
if ($Seconds -gt 0) {
    Write-Host ('  Stopping automatically in {0} seconds...' -f $Seconds) -ForegroundColor Green
    Start-Sleep -Seconds $Seconds
} else {
    Write-Host '  Then press any key here to stop.' -ForegroundColor Green
    $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}

& pktmon stop          2>&1 | Out-Null
& pktmon filter remove 2>&1 | Out-Null
Write-Host ''
Write-Host 'Stopped. Converting...' -ForegroundColor Cyan

# --- convert -------------------------------------------------------------------------------
& pktmon etl2pcap $etl -o $pcapng 2>&1 | Out-Null
if (-not (Test-Path $pcapng)) {
    Write-Host '  pcapng conversion produced nothing.' -ForegroundColor DarkYellow
}
# This build names the text converter etl2txt; older docs call it 'format'.
& pktmon etl2txt $etl -o $txt --timestamp 2>&1 | Out-Null

# --- verdict -------------------------------------------------------------------------------
# pktmon prints each packet as "<source> > <destination>, ...", so where the server address
# falls relative to the '>' tells us which way that packet was travelling.
$sent = 0
$recv = 0
if (Test-Path $txt) {
    foreach ($line in [System.IO.File]::ReadLines($txt)) {
        $arrow = $line.IndexOf('>')
        if ($arrow -lt 0) { continue }
        foreach ($ip in $Address) {
            $idx = $line.IndexOf($ip)
            if ($idx -lt 0) { continue }
            if ($idx -gt $arrow) { $sent++ } else { $recv++ }
            break
        }
    }
}

Write-Host ''
Write-Host '--------------------------------------------------------------' -ForegroundColor Cyan
Write-Host ('  packets sent TO   the server : {0}' -f $sent)
Write-Host ('  packets back FROM the server : {0}' -f $recv)
Write-Host '--------------------------------------------------------------' -ForegroundColor Cyan

$txtLines = if (Test-Path $txt) { (Get-Item $txt).Length } else { 0 }

if ($sent -eq 0 -and $recv -eq 0 -and $txtLines -gt 0) {
    # Packets were logged but no line matched "src > dst" - do not guess, point at the files.
    Write-Host 'VERDICT: could not classify direction from the text output.' -ForegroundColor Yellow
    Write-Host '         The capture itself is fine - open the pcapng in Wireshark and filter on'
    Write-Host ('         ip.addr == {0}' -f $Address[0])
} elseif ($sent -eq 0) {
    Write-Host 'VERDICT: the client never sent anything to these addresses.' -ForegroundColor Yellow
    Write-Host '         Check realmlist.wtf, and that you really hit Login while it was capturing.'
} elseif ($recv -eq 0) {
    Write-Host 'VERDICT: your packets leave but nothing ever comes back.' -ForegroundColor Yellow
    Write-Host '         The server is unreachable from this network. No client-side setting fixes'
    Write-Host '         this - re-run the hosts updater in case the address moved, and if the'
    Write-Host '         server is up for everyone else, get out of this network path (VPN).'
} else {
    Write-Host 'VERDICT: the server is answering, so the network path is fine.' -ForegroundColor Green
    Write-Host '         The failure is inside the auth handshake - open the pcapng in Wireshark,'
    Write-Host '         or read the txt, and look at what follows the first exchange.'
}

Write-Host ''
Write-Host 'Files:' -ForegroundColor Cyan
Write-Host "  $pcapng"
Write-Host "  $txt"
if ($KeepEtl) { Write-Host "  $etl" } else { Remove-Item $etl -ErrorAction SilentlyContinue }

Write-Host ''
Write-Host 'Press any key to close...' -ForegroundColor DarkGray
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
