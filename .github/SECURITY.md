# Security Policy

## Supported Versions

SecuryBlack actively maintains the latest minor release line of FerroSentry with security updates.

| Version | Supported          | Status |
| ------- | ------------------ | ------ |
| 0.2.x   | :white_check_mark: | Active support (0.2.26+ only installs signed updates) |
| < 0.2.0 | :x:                | End of life |

---

## Privileges and network access

You should know exactly what an agent does before running its installer with `sudo`. This section describes the current behaviour of FerroSentry, including its limitations.

### Installation (Linux)

The install script needs root to:

- place the binary at `/usr/local/bin/ferro-sentry`;
- write `/etc/ferro-sentry/config.toml` (directory mode `0700`, file mode `0600`, because it contains your auth token);
- register and start the systemd unit `ferro-sentry.service`.

It downloads the release archive from GitHub Releases and verifies it against the published SHA-256 checksum before installing it.

### Runtime

- **The service runs as root.** Its audits read root-only files (`sshd_config`, firewall rules, auth logs, SUID binaries) and the self-updater replaces the binary in `/usr/local/bin`.
- **Audits are read-only.** Every hour FerroSentry runs its audit modules (ports, packages, SSH, file integrity, permissions, persistence, processes, firewall, fail2ban/CrowdSec, failed logins, TLS certificates). They read files and run read-only system commands; they do not change the system.
- **Changes only on an explicit command.** Remediation (UFW rules, SSH hardening, unattended upgrades, installing and managing fail2ban or CrowdSec, OS package upgrades) only runs when a command arrives on the local command intake: a Unix socket under `/run/sb-agent/` (named pipe on Windows) that requires the machine's shared intake token (`/etc/sb-agent/intake.token`, root-only). In practice these commands are forwarded by the SecuryBlack companion agent (Nexus) from the panel. These handlers run system tools (`ufw`, `systemctl`, `fail2ban-client`, `cscli`, the package manager) as root.
- **Signed commands.** Since 0.2.28 commands carry an ed25519 signature from the SecuryBlack API, bound to your token, the target agent, an expiry time and the payload, and a `command_id` is never executed twice. During the transition, a command whose signature is missing, invalid or expired is still accepted with a warning in the log; enforcement will be switched on in a later release.
- **OS upgrades need your consent on the server.** `os_upgrade` is refused unless `allow_remote_os_upgrade = true` in `config.toml` (default `false`). It never reboots unless the command explicitly asks for it.

### Outbound connections

| Destination | When | What is sent |
|---|---|---|
| Your `api_url` (default `https://api.securyblack.com`), path `/agents/me/security-events` | With `mode = "direct"` (the installer's default), for each finding after every hourly scan | The security event as JSON: type, category, severity, module, host name and finding details (paths, ports, package names, IP addresses from auth logs). Your `token` as `Authorization: Bearer` |
| `127.0.0.1:4317` (gRPC, local only) | With `mode = "agent"` / `"local_agent"`, for each finding | The same event JSON, handed to the local SecuryBlack companion agent, which forwards it |
| `api.github.com` / GitHub Releases | 60 s after start and then once a day, and on an `update_now` command | A request for the latest release; if there is a newer one, downloads it over HTTPS and replaces the binary. Since 0.2.26 the updater only installs archives signed with one of SecuryBlack's offline ed25519 release keys built into the binary and rejects anything else. There is currently no setting to disable it |
| `127.0.0.1` (TCP) | Every hourly scan | Connection attempts to a fixed list of well-known ports on localhost, to find listening services |
| Your distribution's package repositories | Only when an install/upgrade command is received | Package downloads through `apt-get` / `dnf` / `yum` / other package managers |
| `packagecloud.io` | Only on an `install_crowdsec` command | Downloads and runs CrowdSec's official repository setup script, then installs CrowdSec from that repository |

With `mode = "local_file"` (the built-in default when there is no config file), findings are only written to a local JSONL file; the update check and the localhost port scan still run.

---

## Reporting a Vulnerability

We take the security of FerroSentry and our users' infrastructure seriously. If you discover a security vulnerability in FerroSentry, please report it responsibly.

**Please DO NOT open public GitHub issues, discussions, or pull requests for security vulnerabilities.**

Instead, please send an email to:
**security@securyblack.com**

Please include in your report:
- Description of the issue and potential impact
- Reproduction steps or minimal PoC
- System environment (OS, kernel, architecture `x86_64` / `aarch64`) and FerroSentry version
- Suggested mitigations, if known

### Response Timeline

- **Acknowledgment**: Within 48 hours.
- **Triage & Assessment**: Within 5 business days.
- **Fix & Public Advisory**: Coordinated patch release with proper attribution.
