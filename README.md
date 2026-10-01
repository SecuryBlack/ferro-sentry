# FerroSentry

Open source Rust agent for host security auditing, findings and explicitly requested remediation. Reports to SecuryBlack Cloud through the supported transport configuration.

## Use with SecuryBlack

SecuryBlack is a hosted panel for server metrics, security findings and alerts. This repository contains the native agent; the hosted panel is a separate part of the product.

[Watch the 42-second product demo](https://securyblack.com/en?utm_source=github&utm_medium=referral&utm_campaign=agent_readme&utm_content=ferro-sentry#how-it-works) · [Open the hosted panel](https://app.securyblack.com) · [Installation documentation](https://securyblack.com/en/docs/installation)

[![SecuryBlack product demo](https://securyblack.com/videos/securyblack-launch-en.png)](https://securyblack.com/en?utm_source=github&utm_medium=referral&utm_campaign=agent_readme&utm_content=ferro-sentry#how-it-works)

Follow the agent-specific installation and configuration instructions below. Use the hosted panel to obtain connection settings for your server.

[![Website](https://img.shields.io/badge/Website-ferrosentry.dev-F43F5E?style=flat-square)](https://ferrosentry.dev)
[![Ecosystem](https://img.shields.io/badge/Ecosystem-SecuryBlack-33E1BF?style=flat-square)](https://securyblack.com)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/built%20with-Rust-orange.svg)](https://www.rust-lang.org/)

> **Part of the SecuryBlack ecosystem:**
> [OxiPulse (Metrics)](https://github.com/securyblack/oxi-pulse) · **FerroSentry (Security)** · [CupraFlow (Networking/HA development)](https://github.com/securyblack/cupra-flow) · [CromoForge (Docker/PostgreSQL)](https://github.com/securyblack/cromo-forge) · [TitanVault (Backups)](https://github.com/securyblack/titan-vault) · [SecuryBlack Cloud](https://securyblack.com)

> **Scope:** Audit and command-handling code is implemented. Remediation requires an explicit action and applicable configuration safeguards. Expanded EDR and automated response descriptions are development references, not a guarantee that every capability below is available.

---

## 🛡️ Philosophy

- **Native Rust:** Native implementation focused on efficient resource use. Resource consumption depends on the workload; no benchmark is asserted here.
- **Independent Modules:** Each security sensor runs inside its own isolated `tokio` async task.
- **Dual Output Modes:** Transmits events locally via **Conduit / Nexus** (bidirectional tunnel) or **direct** to the SecuryBlack API.
- **Real-Time Alerts + Scheduled Audits:** Combines event-driven threat detection with recurring posture scans.
- **Cross-Platform:** Linux and Windows first-class support.

---

## 📋 Modules & Capabilities

### 🔴 Real-Time Threat Detection (EDR)

| Module | Detection Scope |
|---|---|
| **Process Sentinel** | Newly spawned processes, shell children, execution from `/tmp` or temp paths, orphaned processes, memory injection, running deleted binaries (`/proc/[pid]/exe` dangling). |
| **File Integrity Monitor (FIM)** | Unauthorized changes to `/etc/passwd`, system binaries, critical configuration files, certificates. Cryptographic baseline tracking using SHA-256 snapshots. |
| **Network Watch** | Suspicious outbound connections, reverse shells, C2 beaconing, internal network scanning, connections to known Tor/proxy/threat IPs. |
| **Auth Guard** | Failed SSH logins, brute-force mitigation, sudo abuse, newly added user accounts, password modifications, off-hour authentications. |
| **Persistence Hunter** | Unauthorized cron jobs, systemd services, Windows scheduled tasks, startup run keys, modified `.bashrc`/`.profile`, Windows DLL hijacking. |
| **Log Watcher** | Real-time tailing of system logs (`auth.log`, `journald`, Windows Event Log) matching external YAML regex rules. |

### 🔵 Posture & Hardening Audits (Light Host CSPM)

| Module | Audit Scope |
|---|---|
| **Port Scanner** | Open ports on local interfaces, services listening on `0.0.0.0` unnecessarily, non-standard listening ports. Rapid SYN scan of localhost. |
| **Firewall Auditor** | `iptables`/`nftables`/`ufw` (Linux) and Windows Firewall rule verification. Detects overly permissive rules (`ANY/ANY`, `0.0.0.0/0`), missing stateful inspection, missing default drop policies. |
| **Vulnerability Scanner** | Installed software versions vs CVE database, insecure service configs (SSH root login, TLS 1.0/1.1, SMBv1), pending kernel security updates. |
| **SSL/TLS Auditor** | Expired certificates, self-signed certs, weak cipher suites (RC4/DES, small DH parameters), certificates nearing expiration. |
| **SSH Auditor** | Hardening audit of `sshd_config`: `PermitRootLogin`, `PasswordAuthentication`, non-standard port, `X11Forwarding`, missing `AllowUsers`, obsolete versions. |
| **Permission Auditor** | Suspicious SUID/SGID binaries, world-writable files in critical system directories, duplicate UID 0 users, unauthorized `sudo`/`wheel` memberships. |
| **Secrets Hunter** | Plaintext credentials in configuration files (`.env`, `.yml`, `.json`), API keys, unencrypted private keys, tokens leaked into log files. |
| **Kernel Security** | Kernel mitigation status (`ASLR`, `NX`, `seccomp`, `AppArmor`/`SELinux`, `KPTI`, `SMEP`/`SMAP`), unpatched kernel vulnerabilities. |
| **Listening Services** | Unauthenticated services, exposed databases (`MongoDB`, `Redis`, `Elasticsearch` without auth), legacy plaintext protocols (`Telnet`, `FTP`). |
| **Container Security** | Privileged Docker containers, exposed `/var/run/docker.sock`, outdated base images, containers with `--net=host`, cloud metadata abuse (`169.254.169.254`). |
| **Backup Finder** | Exposed database dumps (`.sql`, `.tar.gz`, `.zip`, `.bak`) stored in public web paths or with weak file permissions. |
| **Network Topology** | Interfaces running in promiscuous mode, suspicious static routes, unauthorized overlay tunnels (WireGuard, OpenVPN, GRE), ARP spoofing. |
| **Malware Scanner** | YARA signature scanning across critical temporary directories (`/tmp`, `/var/tmp`, `$HOME`), known disk IoCs. |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            SECURYBLACK CLOUD                                │
│  ┌──────────────┐      ┌──────────────────────────────┐                     │
│  │  Dashboard   │◄─────┤  Security Events API         │                     │
│  │  (Alerts)    │      │  / Posture Findings API      │                     │
│  └──────────────┘      └──────────────────────────────┘                     │
└─────────────────────────────────────────────────────────────────────────────┘
                               ▲
                               │ Security Events (JSON / OTLP Logs)
                    ┌─────────┴──────────┐
                    │  Conduit / Tunnel  │   ← default
                    └─────────┬──────────┘
┌─────────────────────────────┼───────────────────────────────┐
│     CLIENT SERVER           │                               │
│                             │                               │
│  ┌──────────────────────────┴─────────────────────────┐     │
│  │  FerroSentry (Rust Daemon)                         │     │
│  │                                                    │     │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │     │
│  │  │ REAL-TIME   │  │ AUDIT       │  │ SCHEDULER  │ │     │
│  │  │ SENSORS     │  │ SCANNERS    │  │ (cron)     │ │     │
│  │  │             │  │             │  │            │ │     │
│  │  │ • Process   │  │ • PortScan  │  │ • Daily    │ │     │
│  │  │ • FIM       │  │ • Firewall  │  │ • Hourly   │ │     │
│  │  │ • Network   │  │ • VulnScan  │  │ • OnDemand │ │     │
│  │  │ • Auth      │  │ • SSH       │  │            │ │     │
│  │  │ • Persist   │  │ • Secrets   │  │            │ │     │
│  │  │ • Logs      │  │ • Perms     │  │            │ │     │
│  │  └──────┬──────┘  └──────┬──────┘  └─────┬──────┘ │     │
│  │         └─────────────────┴───────────────┘        │     │
│  │  ┌────────────────────────────────────────────────┐ │     │
│  │  │           EVENT ENGINE                         │ │     │
│  │  │  • Deduplication (5-minute sliding window)     │ │     │
│  │  │  • Enrichment (host, user, SHA-256 hash, geo)  │ │     │
│  │  │  • Severity scoring                            │ │     │
│  │  │  • Throttling / rate limiting                  │ │     │
│  │  └────────────────────┬───────────────────────────┘ │     │
│  │  ┌────────────────────┴───────────────────────────┐ │     │
│  │  │           OUTPUT LAYER                         │ │     │
│  │  │  → Local Conduit (gRPC / HTTP)   [default]     │ │     │
│  │  │  → Direct SecuryBlack API        [fallback]    │ │     │
│  │  │  → Local JSONL Log File          [debug]       │ │     │
│  │  └────────────────────────────────────────────────┘ │     │
│  └─────────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### Event Payload Formats

**Security Event** (Real-time alert):
```json
{
  "event_type": "process_spawn",
  "category": "intrusion_detection",
  "severity": "critical",
  "timestamp": "2026-04-28T16:45:00Z",
  "host": "web-server-01",
  "agent": "ferro-sentry",
  "module": "process_sentinel",
  "details": {
    "pid": 1337,
    "command": "/tmp/.xmrig --donate-level 1",
    "parent_pid": 1,
    "parent_command": "systemd",
    "user": "www-data",
    "hash_sha256": "aabbcc...",
    "rule": "process_from_tmp"
  }
}
```

**Posture Finding** (Audit scan finding):
```json
{
  "event_type": "finding",
  "category": "posture",
  "severity": "high",
  "timestamp": "2026-04-28T16:45:00Z",
  "host": "web-server-01",
  "agent": "ferro-sentry",
  "module": "ssh_auditor",
  "details": {
    "finding": "PermitRootLogin=yes",
    "recommendation": "Set PermitRootLogin=no or prohibit-password",
    "file": "/etc/ssh/sshd_config",
    "benchmark": "CIS-5.2.8"
  }
}
```

---

## 🚀 Quickstart & Installation

### Linux — One-line Install
```bash
curl -fsSL https://install.ferrosentry.dev | sudo bash
```

### Windows — PowerShell (Administrator)
```powershell
irm https://install.ferrosentry.dev | iex
```

### Standalone Interactive TUI
Inspect security posture, active alerts, and firewall rules in real time without needing a cloud connection:
```bash
ferrosentry tui
```

---

## 🦀 Rust Technology Stack

| Layer | Crate |
|---|---|
| Async runtime | `tokio` (full) |
| Logging / tracing | `tracing` + `tracing-subscriber` + `tracing-appender` |
| Serialization | `serde` + `serde_json` + `serde_yaml` (detection rules) + `chrono` |
| System processes | `sysinfo` |
| File system monitoring | `notify` (inotify, ReadDirectoryChangesW) |
| Hashing (FIM) | `sha2` + `hex` |
| Pattern matching | `regex` |
| Unix accounts | `uzers` |
| Windows APIs | `windows` + `winreg` |
| HTTP client | `reqwest` |
| gRPC / OTLP Logs | `tonic` + `opentelemetry` + `opentelemetry-otlp` |
| Network inspection | `tokio::net` + raw sockets |
| Malware inspection | `yara` (optional) |
| Terminal UI | `ratatui` + `crossterm` |
| Configuration | `toml` + `serde` |

---

## 🌐 SecuryBlack Open Source Ecosystem

FerroSentry is the security and EDR pillar of the SecuryBlack modular agent suite:

| Agent | Core Focus | Official Website | Repository |
| :--- | :--- | :--- | :--- |
| **OxiPulse** | Server telemetry and OTLP metrics | [oxipulse.dev](https://oxipulse.dev) | [securyblack/oxi-pulse](https://github.com/securyblack/oxi-pulse) |
| **FerroSentry** | Lightweight EDR, auditd, brute-force mitigation & firewall | [ferrosentry.dev](https://ferrosentry.dev) | [securyblack/ferro-sentry](https://github.com/securyblack/ferro-sentry) |
| **CupraFlow** | Networking/HA development (not operationally verified) | [cupraflow.dev](https://cupraflow.dev) | [securyblack/cupra-flow](https://github.com/securyblack/cupra-flow) |
| **CromoForge** | Docker containers, logs & PostgreSQL management | [cromoforge.dev](https://cromoforge.dev) | [securyblack/cromo-forge](https://github.com/securyblack/cromo-forge) |
| **TitanVault** | Streaming backups (restore workflow not verified) | [titanvault.dev](https://titanvault.dev) | [securyblack/titan-vault](https://github.com/securyblack/titan-vault) |

All agents can be centrally managed with unified observability by connecting them to [SecuryBlack Cloud](https://securyblack.com).

---

## License

FerroSentry is licensed under the [Apache License, Version 2.0](LICENSE).

## Maintainer context (workspace)

English is the primary language for this repository's public documentation. Shared product decisions, commercial terms and the backlog live in the [workspace wiki](../sb-wiki/Índice.md), [current state](../sb-wiki/Producto/Estado%20actual.md) and [product log](../sb-wiki/Producto/Bitácora.md). These links require `sb-wiki` as a sibling checkout. Keep agent-specific usage and technical contracts here; update shared decisions in the wiki.
