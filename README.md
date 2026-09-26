# OctoWoW login capture

Two small Windows tools for when the OctoWoW client sits at "Connecting…" and times
out instead of logging in. Nothing to install: both are PowerShell scripts, and each
has a double-click launcher.

## Watch OctoWoW Login.cmd / Watch OctoWoW Normal.cmd — wait for the server to come back

OctoWoW sits behind DDoS scrubbing. While an attack is being filtered your packets are
silently dropped rather than refused, which is why the client times out instead of
giving you an error — and the outage usually clears up on its own.

Rather than retrying the login over and over, this polls the login port (3724) every
few seconds and beeps the moment it answers, showing how long the current state has
lasted. It only ever opens a plain TCP connection: it never sends credentials and never
touches the login handshake, so it is safe to leave running.

- **Watch OctoWoW Login.cmd** watches `play.octowow.st`, the address the realmlist uses.
- **Watch OctoWoW Normal.cmd** watches `normal.octowow.st` — worth knowing when play is
  down. It has several addresses (round-robin), so all of them are probed at once and the
  report says how many answer and which.

**The addresses change now and then**, so they come from OctoWoW's own DNS server
(`37.156.68.20`, the one the hosts updater asks) rather than your hosts file, and are
looked up again every minute. When the server moves it says **MOVED** and carries on
watching the new addresses. And because your client connects to whatever the hosts file
says, it warns when that points somewhere the server no longer is — and won't tell you to
log in while it does. That's the moment to run **Update OctoWoW Hosts**.

```
.\Wait-ForOctoWow.ps1                              watch play.octowow.st until it answers
.\Wait-ForOctoWow.ps1 -HostName normal.octowow.st  the same for normal.octowow.st
.\Wait-ForOctoWow.ps1 -Launch "D:\...\WoW.exe"     start the client when it does
```

Options: `-HostName`, `-DnsServer`, `-ResolveEverySeconds` (default 60), `-Address`
(fixed addresses, nothing looked up), `-Port`, `-IntervalSeconds` (default 5 — please
don't set it very low against a host under attack), `-TimeoutSeconds`, `-Launch`,
`-Quiet`.

## Capture OctoWoW Login.cmd — find out where a failed login dies

A capture of the traffic between your PC and the login server, using `pktmon`, which
ships with Windows. It elevates itself, captures while you reproduce the failed login,
then prints a verdict from one fact — did anything come back:

| Verdict | Means |
| --- | --- |
| nothing sent | the client never tried: the realmlist or the client is at fault |
| sent, nothing back | packets leave and die on the way: the network path or the server |
| sent and received | the connection works, so the failure is in the login handshake itself |

It writes `octowow-login_<timestamp>.pcapng` (open in Wireshark) and `.txt` (readable as
is) next to the script. Options: `-Address`, `-Seconds` (capture unattended),
`-OutputDirectory`, `-KeepEtl`.

**Captures contain your account name** — the login handshake sends it unencrypted. The
repository's `.gitignore` keeps them out of git; don't post them anywhere public.
