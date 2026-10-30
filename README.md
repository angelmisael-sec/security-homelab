# Security Homelab

Hands-on lab where I build, attack, and defend a small corporate network, following a 9-month path from IT support to security analyst and cloud security engineer.

## Lab network

Isolated Hyper-V internal switch, no route to my home network.

```mermaid
flowchart LR
  subgraph LAB["Lab network 10.10.0.0/24 (Hyper-V internal switch)"]
    subgraph SRV["Servers 10.10.0.0/26"]
      DC["DC01 · Windows Server 2025<br/>AD DS, DNS · lab.local"]
      UB["UB01 · Ubuntu Server 24.04<br/>Linux target, Docker"]
    end
    subgraph CLI["Clients 10.10.0.64/26"]
      W11["WS01 · Windows 11 Enterprise<br/>domain-joined"]
    end
    subgraph SOC["Monitoring 10.10.0.128/26"]
      SIEM["Wazuh SIEM (Phase 2)"]
    end
  end
  W11 --> DC
  UB --> DC
  DC -. logs .-> SIEM
  W11 -. logs .-> SIEM
  UB -. logs .-> SIEM
```

## Roadmap

| Phase | Weeks | Focus | Milestone |
|---|---|---|---|
| 1 · Foundations | 1–13 | Networking, AD & GPO hardening, Linux, scripting, Docker | CompTIA Security+ |
| 2 · Defense | 14–25 | SIEM (Wazuh, Sentinel/KQL), Sysmon, AD attacks & detection, incident response | Microsoft SC-200 |
| 3 · Cloud | 26–38 | Entra ID hardening, Terraform, Kubernetes, Defender for Cloud | Cloud security cert |

## Weekly log

- [x] **Week 01** — Lab design, Hyper-V setup, OSI/TCP-IP and subnetting
- [x] **Week 02** — Packet analysis with Wireshark (NTLM vs Kerberos, see findings below)
- [x] **Week 03** — Active Directory from scratch: OUs, groups, users, service account, WS01 domain join
- [x] **Week 04** — GPO hardening: password/lockout policy, RC4 off (AES only), LLMNR off, SMB signing, advanced audit
- [x] **Week 05** — Validated the AES-only control: requested a service ticket, confirmed AES (not RC4) in the ticket and in 4769, hardened the service account to AES-only
- [x] **Week 06** — Windows LAPS: each workstation's local-admin password is now unique, rotated, and stored encrypted in AD
- [ ] Week 07 — Centralize logs (Sysmon on the endpoints, forward events) — Phase 2 begins

## Build log

| Script | What it does |
|---|---|
| [`01-new-dc01.ps1`](scripts/01-new-dc01.ps1) | Private Hyper-V switch (no path to host or home network) + DC01 VM, Gen 2 with Secure Boot |
| [`02-install-dc01.ps1`](scripts/02-install-dc01.ps1) | Installs Windows Server 2025 without the wizard: DISM image apply + `unattend.xml` |
| [`03-promote-dc01.ps1`](scripts/03-promote-dc01.ps1) | Static IP 10.10.0.10/26 and promotion to first DC of `lab.local`, all through PowerShell Direct |
| [`04-new-ws01.ps1`](scripts/04-new-ws01.ps1) | WS01, Windows 11 Pro with vTPM, built end to end; static IP 10.10.0.30 (servers /26 until the lab router exists) |
| [`05-capture-ws01-dc01.ps1`](scripts/05-capture-ws01-dc01.ps1) | Week 2: `pktmon` capture inside WS01 while generating DNS, LDAP, SMB and ICMP to DC01 (`-Tag w03` reruns it after the join) |
| [`06-ad-structure.ps1`](scripts/06-ad-structure.ps1) | Week 3: OU tree, `GG-*` department groups, 4 staff users, a separate `adm.*` admin account, `svc_sql` with an SPN; `redircmp` so new computers land in an OU where GPOs apply |
| [`07-join-ws01.ps1`](scripts/07-join-ws01.ps1) | Week 3: joins WS01 to `lab.local`, reboots, checks the secure channel and `nltest /dsgetdc` |
| [`08-gpo-hardening.ps1`](scripts/08-gpo-hardening.ps1) | Week 4: four baseline GPOs — AES-only Kerberos (kills RC4), LLMNR off, SMB signing, advanced audit + 4688 command line |
| [`09-validate-aes-control.ps1`](scripts/09-validate-aes-control.ps1) | Week 5: requests a service ticket from WS01, confirms it is issued as AES-256 (not RC4) in the ticket and in event 4769, then pins the service account to AES-only |
| [`10-windows-laps.ps1`](scripts/10-windows-laps.ps1) | Week 6: Windows LAPS — extend schema, grant computer self-write, GPO to back up the local-admin password to AD, force WS01 to rotate, read it back |

### Week 02 findings (WS01 not domain-joined yet)

- No Kerberos at all: auth fell back to **NTLM** because WS01 is not joined and the account was given as `LAB\Administrator`.
- DC01 logged `4625` for `WS01\labadmin` with SubStatus `0xc0000064` (user does not exist): Windows first tried the workstation's own local account, then `4624` type 3 for `LAB\Administrator`.
- DC01 requires SMB signing (`RequireSecuritySignature: True`), which blocks NTLM relay over SMB.
- Open question: mapping `\\dc01\SYSVOL` returned *Access is denied* even after a successful `4624`. The capture shows the SMB side worked (DFS referral `STATUS_NOT_FOUND`, then Tree Connect to SYSVOL `STATUS_SUCCESS`); right after, the client fell back to WebDAV on TCP 80 and got 5 unanswered SYNs (1/2/4/8 s backoff, DC firewall drops). The error is client-side, not a share permission. To retest after the domain join.

### Week 03 findings (after the domain join)

- Same traffic, now **Kerberos**: 18 Kerberos packets and DC01 logs `4768` (TGT) + `4769` (service tickets for `ldap/dc01` and `cifs/DC01`), with `4624` showing `Kerberos` instead of `NTLM`.
- First AS-REQ gets `KDC_ERR_PREAUTH_REQUIRED` (error 25) on purpose: the client must prove it knows the password first. Accounts with pre-auth disabled are the AS-REP roasting target.
- Tickets use etype 18 (AES256), but the KDC still advertises 23 (RC4) as an option: RC4 tickets are what Kerberoasting cracks fastest.
- `\\dc01\SYSVOL` now mounts fine: the week 2 *Access is denied* was tied to the non-joined NTLM path.
- `svc_sql` has a deliberately weak password and an SPN, kept for the Kerberoasting exercise in Phase 2.

### Week 04 findings (GPO hardening)

- Four GPOs linked at the domain root; verified applied on WS01 with `gpresult /r`.
- `SupportedEncryptionTypes = 0x18` (24): Kerberos now negotiates **AES only**. RC4 — the fast Kerberoasting path from week 3 — is gone from the offer.
- LLMNR off (`EnableMulticast = 0`): removes the multicast name-resolution request that Responder-style tools poison to capture hashes.
- SMB signing required on client and server: blocks NTLM-over-SMB relay.
- Advanced audit baseline + `ProcessCreationIncludeCmdLine_Enabled = 1`, so 4688 records the full command line — the single most useful event for threat hunting.
- Password policy follows NIST guidance: 14-char minimum, lockout after 5 tries, length over forced rotation (365-day max age).

### Week 05 findings (validating the AES-only control)

- A domain user on WS01 requested a service ticket for `MSSQLSvc/sql01.lab.local:1433`. The KDC issued it as **AES-256**, and `klist` confirmed `KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96`.
- DC01 logged **4769** with `TicketEncryptionType = 0x12` (AES256). `0x17` would have been RC4 — the fast offline-cracking path that week 3's capture showed being offered.
- The service account had `msDS-SupportedEncryptionTypes` unset (AES only by Server 2025 default). Pinned it explicitly to `0x18` (AES128+AES256) so RC4 can never be negotiated even if the GPO changes — the standard mitigation for this class of attack, alongside long/managed service-account passwords (gMSA).
- Done entirely with built-in Windows tools from a box already on the isolated switch; no extra VM needed.

### Week 06 findings (Windows LAPS)

- `Update-LapsADSchema` added the LAPS attributes; `Set-LapsADComputerSelfPermission` lets a computer write (not read) its own password.
- GPO on the Workstations OU: back up to AD, manage the local `labadmin` account, 20-char password, 30-day rotation.
- After `Invoke-LapsPolicyProcessing`, WS01's local-admin password was rotated and stored in AD. `Get-LapsADPassword -Identity WS01` reads it back as a domain admin — length 20, with the next expiry recorded.
- Consequence to remember: WS01's local `labadmin` password is now LAPS-managed, so the value in the lab creds file is stale — retrieve the current one from AD on demand.
- This kills lateral movement via a shared local-admin password: every machine ends up with a different one.

Lessons so far:
- Defender's ASR rule *Block abuse of exploited vulnerable signed drivers* fired while DISM wrote `KslD.sys` into the VM disk. Benign in context (OS image apply), but it is the same rule that stops BYOVD attacks.
- `hypervisorlaunchtype` was `Off` in the host's BCD, so VMs could not start even with SVM enabled in BIOS.
- An `unattend.xml` left in `C:\Windows\Panther` holds the local admin password (MITRE ATT&CK T1552.001). Kept on purpose in this lab to hunt for it in Phase 2.

## Rules

- All attack techniques run only inside this isolated lab.
- No real credentials, company data, or production systems.
