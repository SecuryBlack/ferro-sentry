use crate::engine::{EventEngine, SecurityEvent, Severity};
use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

pub async fn scan(engine: &EventEngine) -> Result<Vec<SecurityEvent>> {
    let mut findings = Vec::new();

    let sshd_configs = find_sshd_configs();
    if sshd_configs.is_empty() {
        tracing::debug!("No sshd_config found on host");
        return Ok(findings);
    }

    // Prefer what sshd actually uses; fall back to reading the files ourselves.
    let parsed_config =
        effective_sshd_config().unwrap_or_else(|| parse_sshd_configs(&sshd_configs));

    // Rule 1: PermitRootLogin
    if let Some(val) = parsed_config.get("permitrootlogin") {
        let val_lower = val.to_lowercase();
        if val_lower == "yes" {
            let details = json!({
                "rule_id": "SSH-001",
                "title": "SSH Root Login Enabled",
                "setting": "PermitRootLogin",
                "current_value": val,
                "recommended_value": "prohibit-password or no",
                "summary": "Root user is allowed to log in directly via SSH, exposing the server to privilege escalation brute-force attacks.",
                "remediation": "Edit /etc/ssh/sshd_config and set 'PermitRootLogin prohibit-password' or 'PermitRootLogin no', then restart sshd service."
            });
            findings.push(
                engine
                    .build_event(
                        "finding",
                        "posture",
                        Severity::High,
                        "ssh_auditor",
                        details,
                        Some("ssh_root_login_enabled"),
                    )
                    .await,
            );
        }
    }

    // Rule 2: PasswordAuthentication
    if let Some(val) = parsed_config.get("passwordauthentication") {
        let val_lower = val.to_lowercase();
        if val_lower == "yes" {
            let details = json!({
                "rule_id": "SSH-002",
                "title": "SSH Password Authentication Enabled",
                "setting": "PasswordAuthentication",
                "current_value": val,
                "recommended_value": "no",
                "summary": "Password-based authentication is enabled for SSH. Key-based authentication is strongly recommended to eliminate credential stuffing risks.",
                "remediation": "Ensure SSH public keys are configured, then set 'PasswordAuthentication no' in /etc/ssh/sshd_config."
            });
            findings.push(
                engine
                    .build_event(
                        "finding",
                        "posture",
                        Severity::Medium,
                        "ssh_auditor",
                        details,
                        Some("ssh_password_auth_enabled"),
                    )
                    .await,
            );
        }
    }

    // Rule 3: SSH Standard Port 22
    let port_val = parsed_config
        .get("port")
        .map(|s| s.as_str())
        .unwrap_or("22");
    if port_val == "22" {
        let details = json!({
            "rule_id": "SSH-003",
            "title": "SSH Running on Standard Port 22",
            "setting": "Port",
            "current_value": "22",
            "recommended_value": "Custom high port (e.g. 2222)",
            "summary": "SSH daemon is listening on standard port 22, making it an easy target for automated botnet scanners.",
            "remediation": "Consider changing 'Port 22' to a custom non-standard port in /etc/ssh/sshd_config."
        });
        findings.push(
            engine
                .build_event(
                    "finding",
                    "posture",
                    Severity::Low,
                    "ssh_auditor",
                    details,
                    Some("ssh_standard_port"),
                )
                .await,
        );
    }

    // Rule 4: X11Forwarding Enabled
    if let Some(val) = parsed_config.get("x11forwarding") {
        let val_lower = val.to_lowercase();
        if val_lower == "yes" {
            let details = json!({
                "rule_id": "SSH-004",
                "title": "SSH X11 Forwarding Enabled",
                "setting": "X11Forwarding",
                "current_value": val,
                "recommended_value": "no",
                "summary": "X11 forwarding allows remote SSH clients to interact with local X displays, posing risk if a session is compromised.",
                "remediation": "Set 'X11Forwarding no' in /etc/ssh/sshd_config unless explicitly required for GUI applications."
            });
            findings.push(
                engine
                    .build_event(
                        "finding",
                        "posture",
                        Severity::Low,
                        "ssh_auditor",
                        details,
                        Some("ssh_x11_forwarding_enabled"),
                    )
                    .await,
            );
        }
    }

    // Rule 5: MaxAuthTries
    let max_tries: Option<u32> = parsed_config
        .get("maxauthtries")
        .and_then(|v| v.parse().ok());
    if max_tries.unwrap_or(6) > 4 {
        let current_str = max_tries
            .map(|v| v.to_string())
            .unwrap_or_else(|| "Default (6)".to_string());
        let details = json!({
            "rule_id": "SSH-005",
            "title": "SSH Max Authentication Tries Excessive",
            "setting": "MaxAuthTries",
            "current_value": current_str,
            "recommended_value": "3 or 4",
            "summary": "High MaxAuthTries setting allows more password or key attempts per connection before dropping, increasing brute-force efficiency.",
            "remediation": "Set 'MaxAuthTries 3' in /etc/ssh/sshd_config."
        });
        findings.push(
            engine
                .build_event(
                    "finding",
                    "posture",
                    Severity::Low,
                    "ssh_auditor",
                    details,
                    Some("ssh_max_auth_tries_high"),
                )
                .await,
        );
    }

    Ok(findings)
}
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn detect_ssh_port() -> u16 {
    let map = effective_sshd_config().unwrap_or_else(|| parse_sshd_configs(&find_sshd_configs()));
    map.get("port")
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(22)
}

fn find_sshd_configs() -> Vec<String> {
    let mut files = Vec::new();

    let main_paths = [
        "/etc/ssh/sshd_config",
        r"C:\ProgramData\ssh\sshd_config",
        r"C:\Program Files\OpenSSH\sshd_config",
    ];

    for path in main_paths {
        if Path::new(path).exists() {
            files.push(path.to_string());
        }
    }

    // Drop-ins go first: Debian/Ubuntu/RHEL put `Include sshd_config.d/*.conf`
    // at the top of sshd_config, sshd reads them in name order and keeps the
    // first value it sees.
    if let Ok(entries) = fs::read_dir("/etc/ssh/sshd_config.d") {
        let mut dropins: Vec<String> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().is_some_and(|ext| ext == "conf"))
            .filter_map(|p| p.to_str().map(str::to_string))
            .collect();
        dropins.sort();
        files.splice(0..0, dropins);
    }

    files
}

/// Effective settings as reported by `sshd -T` (needs root). `None` if sshd
/// is missing or refuses the config.
pub fn effective_sshd_config() -> Option<HashMap<String, String>> {
    ["sshd", "/usr/sbin/sshd", "/sbin/sshd"]
        .iter()
        .find_map(|bin| {
            let out = std::process::Command::new(bin).arg("-T").output().ok()?;
            out.status.success().then(|| {
                let mut map = HashMap::new();
                parse_directives(&String::from_utf8_lossy(&out.stdout), &mut map);
                map
            })
        })
}

fn parse_sshd_configs(paths: &[String]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for path in paths {
        if let Ok(content) = fs::read_to_string(path) {
            parse_directives(&content, &mut map);
        }
    }
    map
}

/// `Key value` lines, keys lowercased; like sshd, the first value of a key wins.
fn parse_directives(content: &str, map: &mut HashMap<String, String>) {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() >= 2 {
            map.entry(parts[0].to_lowercase())
                .or_insert_with(|| parts[1..].join(" "));
        }
    }
}
