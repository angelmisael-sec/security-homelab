# Incident Response Plan — security-homelab

Owner: Angel Diaz Freytes · Version 1.0 · 2026-11-05 · Review: every quarter and after every incident

Framework: NIST SP 800-61 (incident handling lifecycle), mapped to the NIST CSF 2.0 *Respond* and *Recover* functions.

## 1. Scope

| Asset | Role | Why it matters |
|---|---|---|
| DC01 (10.10.0.10) | Domain controller `lab.local`, DNS, event collector | Owns every identity; compromise = whole domain |
| WS01 (10.10.0.30) | Domain workstation | The likely first foothold (user activity) |
| LNX01 (10.10.0.40 + NAT) | Analysis VM: Nmap, Greenbone, NTP for the lab | Dual-homed: the only lab box with Internet |
| Host (Hyper-V) | Runs all VMs, holds `E:\Lab` (credentials, evidence) | Out-of-band control: PowerShell Direct, NIC isolation |

Out of scope: my employer's network, tenant and accounts (never used for practice), and my home network.

## 2. Roles

One-person lab, so I hold every role. Written out anyway, because in a company these are different people:

| Role | Lab | In a company |
|---|---|---|
| Incident handler / lead | Me | SOC lead or IR manager |
| Analyst (triage, evidence) | Me | SOC tier 1–2 |
| System owner (approves downtime) | Me | Server / app owner |
| Communications, legal | — | Management, legal, PR, regulator if data is involved |

## 3. Severity

| Level | Meaning | Lab example | Start within |
|---|---|---|---|
| **SEV-1** | Identity or domain compromise, or data leaving | Unknown account added to Domain Admins (4732), lsass read by an unknown process (Sysmon 10) on DC01 | Immediately |
| **SEV-2** | One host compromised, or a security control down | Malware on WS01; **log forwarding dead** (we go blind) | Same day |
| **SEV-3** | Suspicious, not confirmed; hardening gap | Failed-logon burst, new medium finding in Greenbone | Within a week |

## 4. Detection sources

Sysmon (DC01, WS01) · Windows Security log · Windows Event Forwarding to DC01 `ForwardedEvents` · Greenbone and Nmap scans from LNX01 · hunting queries (`13-threat-hunting.ps1`).
**Known gap:** nothing alerts on its own until the SIEM (week 14). Until then, check weekly that every source is alive: `wecutil gr LabForward` on DC01, and compare the newest forwarded event with the current time.

## 5. Response, phase by phase

**Preparation** — Scripts and credentials ready (`E:\Lab\credenciales-lab.txt`, never in the repo). Evidence folder `E:\Lab\evidence\`. Clean VM checkpoints to restore from. This plan, tested with a tabletop exercise every quarter.

**Detection and analysis** — Confirm it is real (false positive?), decide severity, open a record in `docs/incidents/IR-YYYY-NNN.md` with a timeline in UTC. Questions: what happened, which host, which account, since when, is it still active?

**Containment** — Capture volatile evidence first, then isolate:
```powershell
.\scripts\19-ir-triage.ps1 -VM WS01 -Isolate   # connections + processes, unplug NICs, then sessions/admins/tasks/logs, SHA-256 hashes
```
PowerShell Direct keeps working while the VM is unplugged. If an account is involved: disable it and reset its password (twice for `krbtgt`, with replication time between resets). Take a VM checkpoint before changing anything.

**Eradication** — Remove the cause: the malicious file, task, service or account. Patch or reconfigure what let it in. Prefer rebuilding a workstation from a known-good image over cleaning it.

**Recovery** — `.\scripts\19-ir-triage.ps1 -VM WS01 -Reconnect`, then verify: the service works, **log forwarding resumed with fresh events**, a Greenbone/Nmap re-scan shows the gap closed. Watch the host closely for a week.

**Post-incident** — Within a week: write the lessons learned (template below), update this plan, the scripts and the hunting queries. Blameless: the question is what in the system let it happen, not who.

## 6. Evidence handling

- Order of volatility: memory and network connections → running processes → logged-on sessions → disk and logs.
- Evidence lives in `E:\Lab\evidence\<host>-<UTC time>\`, never in the repository.
- `00-custody.txt` records who collected it, when (UTC), from which host and whether it was isolated; `hashes.txt` holds the SHA-256 of every file. Re-hash before using the evidence to prove it was not changed.

## 7. Post-incident report template

`docs/incidents/IR-YYYY-NNN.md`: summary · severity · timeline (UTC) · detection (how was it found, how long did it take) · root cause · impact · what worked / what did not · actions (owner, date) · plan or control changes.

## 8. Incident log

| ID | Date | Severity | Summary |
|---|---|---|---|
| [IR-2026-001](incidents/IR-2026-001-wef-outage.md) | 2026-11-01 → 11-05 | SEV-2 | Event forwarding from WS01 silently dead for 4 days |
