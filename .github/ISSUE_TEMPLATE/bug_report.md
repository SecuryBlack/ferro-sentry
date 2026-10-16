---
name: Bug report
about: Create a report to help us improve FerroSentry
title: '[BUG] '
labels: 'bug'
assignees: ''

---

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Agent configuration used (`config.toml` or env vars with sensitive tokens redacted)
2. Command run / Service state (`systemctl status ferro-sentry` or `Get-Service FerroSentry`)
3. See error in logs (`journalctl -u ferro-sentry` or Event Viewer)

**Expected behavior**
A clear and concise description of what you expected to happen.

**Environment (please complete the following information):**
 - FerroSentry Version: [e.g. 0.2.28]
 - OS & Architecture: [e.g. Ubuntu 22.04 LTS x86_64, Windows Server 2022 AMD64]
 - Deployment Mode: [e.g. systemd service, Windows service, local_agent, direct]

**Logs / Screenshots**
If applicable, attach relevant log snippets from `ferro-sentry`.

**Additional context**
Add any other context about the problem here.

