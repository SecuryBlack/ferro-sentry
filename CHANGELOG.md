# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/SecuryBlack/ferro-sentry/compare/v0.2.25...HEAD
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
