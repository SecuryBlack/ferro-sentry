# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.31] - 2026-11-14

### Security
- **Dependencies**: sb-agent-core 0.4.3 (`zip` 9.x and `self_update` 1.3.3), and `rustls` 0.23.46. This closes the Dependabot alerts for `zip` (critical) and `rustls`.

### Fixed
- **SSH hardening**: The fix now closes password login on cloud images too (Ubuntu with cloud-init and `ssh_pwauth`). Its file was `99-securyblack-hardening.conf`, read after `50-cloud-init.conf`, and sshd keeps the first value it reads, so `PasswordAuthentication yes` stayed on while the panel reported success. The file is now `00-securyblack-hardening.conf` (the old one is removed), and after writing it the agent checks with `sshd -T` that every setting took effect; if one did not, it rolls everything back and says which.
- **SSH audit**: Findings use the settings sshd actually applies (`sshd -T`), not a guess from the files, which picked up whichever value came last. Without root it reads the files in sshd's order. The fail2ban port check uses the same value.
- **Fail2ban**: Installing fail2ban from the panel now applies its configuration. The package starts fail2ban with its defaults, and the agent wrote `jail.local` afterwards without restarting the service, so the 1-hour ban and the SSH port were never loaded (bans lasted 10 minutes, and with SSH on a port other than 22 the jail watched the wrong one) while the panel reported success. The agent now restarts fail2ban after writing the file, reports an error if the file cannot be written, and checks with `fail2ban-client` that the sshd jail watches the SSH port and uses the 1-hour ban.
- **Firewall**: Adding a `deny` or `reject` rule now refuses to close the SSH port to everyone (the port SSH actually listens on, including ranges like `1:65535` and the `ssh`/`OpenSSH` names), so the owner cannot lock themselves out from the panel. Blocking one source IP, `limit` and UDP-only rules are still allowed.

## [0.2.30] - 2026-10-29

### Security
- **Fail2ban**: The whitelist only accepts IP addresses and CIDR ranges, and `bantime`/`findtime` only accept a number with an optional unit (`10m`, `1h`, `1w`, `-1`). Before, a value with line breaks could add new sections or actions to `jail.local`, which fail2ban runs as root. If any entry is invalid, the whole change is rejected and nothing is written.

## [0.2.29] - 2026-10-23

### Added
- **Signed commands (S4)**: Before running each order, the agent reports whether its signature checks out (`sig:ok` or the reason it does not) (sb-agent-core 0.4.2). Unsigned orders are still accepted: this only measures the fleet before signatures become mandatory.

### Fixed
- **Logs**: Old log files are deleted again; only the last 7 days are kept (sb-agent-core 0.4.1). Rotated files (`ferro-sentry.log.YYYY-MM-DD`) were never removed.

## [0.2.28] - 2026-10-16

### Security
- **Commands**: Verify S4 signed commands (ed25519 signature, expiry, replay protection) via `sb-agent-core` `command_intake`. During the transition any verification failure (unsigned, invalid or expired) is accepted with a warning.

## [0.2.27] - 2026-10-15

### Changed
- No functional changes. First release that agents on 0.2.26 install through the signature-verifying updater.

## [0.2.26] - 2026-10-14

### Security
- **Auto-update**: Only installs ed25519-signed releases (`sb-agent-core` 0.3).

## [0.2.25] - 2026-09-16

### Added
- **CrowdSec**: Implement CrowdSec management commands (decisions, bouncers status, security scenarios).

## [0.2.24] - 2026-09-16

### Added
- **Fail2ban**: Add `get_logs`, `get_config`, `set_config` commands and attack ranking insights.

## [0.2.23] - 2026-09-16

### Fixed
- **Fail2ban**: Prevent byte offset panic during jail status regex parsing.

## [0.2.22] - 2026-09-16

### Added
- **Fail2ban**: Implement remote command intake for ban/unban IP operations and jail status reporting.

## [0.2.21] - 2026-09-16

### Fixed
- **Windows**: Incorporate `sb-agent-core` Windows Server 2019 compatibility and UTF-8 installer fixes.

## [0.2.20] - 2026-09-15

### Added
- **Remediations**: Implement 1-click automated security remediations for SSH hardening, unattended updates, and fail2ban setup.

## [0.2.19] - 2026-09-13

### Added
- **Firewall**: Automated detection and alerting for Docker UFW bypass.

## [0.2.18] - 2026-09-13

### Fixed
- **Firewall**: Emit resolved finding event automatically once UFW firewall is active.

## [0.2.17] - 2026-09-13

### Added
- **Firewall**: Remote unattended UFW installation command.

## [0.2.16] - 2026-09-13

### Added
- **Firewall**: Remote UFW rule management with anti-lockout protection.

## [0.2.15] - 2026-09-13

### Added
- **Process Sentinel**: Consolidate findings by executable path and add scan cache reset.

[Unreleased]: https://github.com/SecuryBlack/ferro-sentry/compare/v0.2.26...HEAD
[0.2.26]: https://github.com/SecuryBlack/ferro-sentry/compare/v0.2.25...v0.2.26
[0.2.25]: https://github.com/SecuryBlack/ferro-sentry/compare/v0.2.24...v0.2.25
[0.2.24]: https://github.com/SecuryBlack/ferro-sentry/compare/v0.2.23...v0.2.24
[0.2.23]: https://github.com/SecuryBlack/ferro-sentry/compare/v0.2.22...v0.2.23
[0.2.22]: https://github.com/SecuryBlack/ferro-sentry/compare/v0.2.21...v0.2.22
[0.2.21]: https://github.com/SecuryBlack/ferro-sentry/compare/v0.2.20...v0.2.21
[0.2.20]: https://github.com/SecuryBlack/ferro-sentry/compare/v0.2.19...v0.2.20
[0.2.19]: https://github.com/SecuryBlack/ferro-sentry/compare/v0.2.18...v0.2.19
[0.2.18]: https://github.com/SecuryBlack/ferro-sentry/compare/v0.2.17...v0.2.18
[0.2.17]: https://github.com/SecuryBlack/ferro-sentry/compare/v0.2.16...v0.2.17
[0.2.16]: https://github.com/SecuryBlack/ferro-sentry/compare/v0.2.15...v0.2.16
[0.2.15]: https://github.com/SecuryBlack/ferro-sentry/releases/tag/v0.2.15
