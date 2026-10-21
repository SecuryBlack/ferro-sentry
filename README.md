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
> [OxiPulse (Metrics)](https://github.com/securyblack/oxi-pulse) · **FerroSentry (Security)** · [CromoForge (Docker/PostgreSQL)](https://github.com/securyblack/cromo-forge) · [TitanVault (Backups)](https://github.com/securyblack/titan-vault) · [SecuryBlack Cloud](https://securyblack.com)

> **Scope:** this README lists what the code does today. Every audit runs on a schedule (hourly); there is no real-time sensor yet. Remediation only runs when you ask for it from the panel.

---

## What it does

- **Hourly host audit.** Twelve modules check the server and report findings. Firewall, intrusion prevention, permission, process and update findings close on their own once the condition is gone.
- **Remediation on request.** From the SecuryBlack panel you can harden SSH, enable unattended upgrades, install and manage fail2ban, manage UFW rules and CrowdSec. Critical actions require Sudo Mode (passkey) in the panel.
- **Signed self-updates** through `sb-agent-core`: daily check, ed25519-signed releases.

## Audit modules

All modules run on Linux. The Windows build only runs the port scanner and file integrity checks.

| Module | What it checks | Rules |
|---|---|---|
| **SSH Auditor** | `sshd_config` and `sshd_config.d`: root login, password authentication, port 22, X11 forwarding, `MaxAuthTries` | SSH-001 … SSH-005 |
| **Firewall Auditor** | UFW inactive, iptables `INPUT` policy `ACCEPT`, Docker publishing ports that bypass UFW | FW-001 … FW-003 |
| **Intrusion Prevention** | Neither fail2ban nor CrowdSec running, fail2ban `sshd` jail not covering the real SSH port, CrowdSec without a bouncer | IPS-001 … IPS-003 |
| **Port Scanner** | Listening sockets (`/proc/net` on Linux): sensitive or often-unauthenticated services exposed on all interfaces, Telnet/FTP | — |
| **Vulnerability Scanner** | Pending package updates (and how many are security updates), pending reboot, `unattended-upgrades` missing or off (apt) | VULN-001 |
| **Permission Auditor** | SUID/SGID binaries in `/tmp`, `/var/tmp`, `/dev/shm`; world-writable critical files in `/etc`; sudo commands not logged | PERM-001 … PERM-003 |
| **Persistence Hunter** | Entries in `/etc/crontab` and `/etc/cron.d` that run from temporary directories or download payloads | PERSIST-001 |
| **Process Sentinel** | Processes running from temporary directories; processes whose binary was deleted (stale after an upgrade, or suspicious) | PROC-001, PROC-002 |
| **File Integrity** | SHA-256 changes between scans in `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `sshd_config`, `/etc/crontab`, `/etc/hosts` | FIM-001 |
| **Auth Monitor** | Failed logins in `/var/log/auth.log` since the previous scan | AUTH-001 |
| **SSL Auditor** | Lists certificates in `/etc/letsencrypt/live` (informational; expiry is checked externally by SecuryBlack uptime monitoring) | SSL-001 |

## Output modes

Set `mode` in `/etc/ferro-sentry/config.toml`:

| Mode | Where events go |
|---|---|
| `agent` | Nexus Agent on `127.0.0.1:4317` (gRPC), which tunnels them to SecuryBlack. This is how the SecuryBlack panel installs it. |
| `direct` | HTTPS `POST {api_url}/agents/me/security-events` with the agent token. |
| `local_file` | JSON lines in `local_file_path`. The default when there is no config. |

---

## Installation

### With SecuryBlack

Use the install command from the panel. It installs Nexus Agent, which runs this installer with `--mode agent`.

### Standalone

```bash
curl -fsSL https://install.ferrosentry.dev | sudo bash
```

Windows (PowerShell as Administrator):

```powershell
irm https://install.ferrosentry.dev | iex
```

Check it with `journalctl -u ferro-sentry -f`.

---

## Built with

`tokio`, `tonic`/`prost` (gRPC to Nexus), `reqwest` with rustls (direct mode), `serde`, `sha2` (file integrity), `tracing`, and `sb-agent-core` (signed updater, command intake).

---

## 🌐 SecuryBlack Open Source Ecosystem

FerroSentry is the security pillar of the SecuryBlack modular agent suite:

| Agent | Core Focus | Official Website | Repository |
| :--- | :--- | :--- | :--- |
| **OxiPulse** | Server telemetry and OTLP metrics | [oxipulse.dev](https://oxipulse.dev) | [securyblack/oxi-pulse](https://github.com/securyblack/oxi-pulse) |
| **FerroSentry** | Security audits, firewall and fail2ban/CrowdSec management | [ferrosentry.dev](https://ferrosentry.dev) | [securyblack/ferro-sentry](https://github.com/securyblack/ferro-sentry) |
| **CromoForge** | Docker containers, logs & PostgreSQL management | [cromoforge.dev](https://cromoforge.dev) | [securyblack/cromo-forge](https://github.com/securyblack/cromo-forge) |
| **TitanVault** | Streaming backups (restore workflow not verified) | [titanvault.dev](https://titanvault.dev) | [securyblack/titan-vault](https://github.com/securyblack/titan-vault) |

All agents can be centrally managed with unified observability by connecting them to [SecuryBlack Cloud](https://securyblack.com).

---

## License

FerroSentry is licensed under the [Apache License, Version 2.0](LICENSE).
