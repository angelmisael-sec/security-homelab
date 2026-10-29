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
- [ ] Week 02 — Packet analysis with Wireshark
- [ ] Week 03 — Active Directory from scratch (DC01 already built: see below)

## Build log

| Script | What it does |
|---|---|
| [`01-new-dc01.ps1`](scripts/01-new-dc01.ps1) | Private Hyper-V switch (no path to host or home network) + DC01 VM, Gen 2 with Secure Boot |
| [`02-install-dc01.ps1`](scripts/02-install-dc01.ps1) | Installs Windows Server 2025 without the wizard: DISM image apply + `unattend.xml` |
| [`03-promote-dc01.ps1`](scripts/03-promote-dc01.ps1) | Static IP 10.10.0.10/26 and promotion to first DC of `lab.local`, all through PowerShell Direct |

Lessons so far:
- Defender's ASR rule *Block abuse of exploited vulnerable signed drivers* fired while DISM wrote `KslD.sys` into the VM disk. Benign in context (OS image apply), but it is the same rule that stops BYOVD attacks.
- `hypervisorlaunchtype` was `Off` in the host's BCD, so VMs could not start even with SVM enabled in BIOS.
- An `unattend.xml` left in `C:\Windows\Panther` holds the local admin password (MITRE ATT&CK T1552.001). Kept on purpose in this lab to hunt for it in Phase 2.

## Rules

- All attack techniques run only inside this isolated lab.
- No real credentials, company data, or production systems.
