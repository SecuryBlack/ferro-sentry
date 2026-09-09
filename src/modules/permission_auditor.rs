use crate::engine::{EventEngine, SecurityEvent};
use anyhow::Result;

#[cfg(target_os = "linux")]
use crate::engine::Severity;
#[cfg(target_os = "linux")]
use serde_json::json;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt;

pub async fn scan(engine: &EventEngine) -> Result<Vec<SecurityEvent>> {
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // 1. Audit SUID/SGID binaries in /tmp, /var/tmp, or /dev/shm
        let check_dirs = ["/tmp", "/var/tmp", "/dev/shm"];
        for dir in check_dirs {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_file() {
                        if let Ok(metadata) = path.metadata() {
                            let mode = metadata.permissions().mode();
                            // SUID bit = 0o4000, SGID bit = 0o2000
                            if (mode & 0o4000) != 0 || (mode & 0o2000) != 0 {
                                let path_str = path.to_string_lossy().to_string();
                                let details = json!({
                                    "rule_id": "PERM-001",
                                    "title": "Suspicious SUID/SGID Binary in Temporary Directory",
                                    "file_path": path_str,
                                    "mode_octal": format!("{:o}", mode),
                                    "summary": format!("Executable '{}' in temporary directory '{}' has SUID/SGID permissions enabled.", path_str, dir),
                                    "remediation": format!("Remove SUID/SGID bits via 'chmod u-s,g-s {}' or delete the file if unauthorized.", path_str)
                                });

                                findings.push(
                                    engine
                                        .build_event(
                                            "finding",
                                            "permission",
                                            Severity::High,
                                            "permission_auditor",
                                            details,
                                            Some(&format!(
                                                "suid_temp_{}",
                                                path_str.replace(['/', '\\', ':'], "_")
                                            )),
                                        )
                                        .await,
                                );
                            }
                        }
                    }
                }
            }
        }

        // 2. Check world-writable files in /etc
        if let Ok(entries) = fs::read_dir("/etc") {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() {
                    if let Ok(metadata) = path.metadata() {
                        let mode = metadata.permissions().mode();
                        // World-writable bit = 0o0002
                        if (mode & 0o0002) != 0 {
                            let path_str = path.to_string_lossy().to_string();
                            let details = json!({
                                "rule_id": "PERM-002",
                                "title": "World-Writable Critical File in /etc",
                                "file_path": path_str,
                                "mode_octal": format!("{:o}", mode),
                                "summary": format!("System configuration file '{}' is world-writable (permissions: {:o}). Any local user can tamper with it.", path_str, mode),
                                "remediation": format!("Revoke world-write permissions using 'chmod o-w {}'.", path_str)
                            });

                            findings.push(
                                engine
                                    .build_event(
                                        "finding",
                                        "permission",
                                        Severity::High,
                                        "permission_auditor",
                                        details,
                                        Some(&format!(
                                            "world_writable_{}",
                                            path_str.replace(['/', '\\', ':'], "_")
                                        )),
                                    )
                                    .await,
                            );
                        }
                    }
                }
            }
        }

        // 3. Sudo command logging
        if !sudo_logging_configured() {
            let details = json!({
                "rule_id": "PERM-003",
                "title": "Sudo Commands Are Not Being Logged",
                "auditd_active": is_active("auditd"),
                "summary": "No execve auditing (auditd) or sudo I/O logging was found. Privileged commands run via sudo are not being recorded for later audit.",
                "remediation": "Enable auditd with an execve rule ('auditctl -a always,exit -F arch=b64 -S execve -k sudo_log') or set 'Defaults log_output' + 'Defaults logfile' in /etc/sudoers."
            });

            findings.push(
                engine
                    .build_event(
                        "finding",
                        "permission",
                        Severity::Medium,
                        "permission_auditor",
                        details,
                        Some("sudo_logging_not_configured"),
                    )
                    .await,
            );
        } else {
            findings.push(
                engine
                    .build_resolved_event("permission_auditor", "sudo_logging_not_configured")
                    .await,
            );
        }
    }

    let _ = engine;

    Ok(findings)
}

/// Sudo logging se considera cubierto por cualquiera de dos vías: auditd
/// vigilando `execve` (la más completa, captura argumentos de cualquier
/// comando, no solo los lanzados directamente por sudo), o logging propio de
/// sudo vía `Defaults log_output`/`logfile` en sudoers. En Ubuntu/Debian el
/// syslog captura por defecto la línea "sudo: user : COMMAND=..." vía
/// authpriv, pero eso ya lo cubre auth_monitor indirectamente — aquí nos
/// interesa la auditoría explícita, no el logging incidental de syslog.
#[cfg(target_os = "linux")]
fn sudo_logging_configured() -> bool {
    if is_active("auditd") {
        if let Ok(output) = std::process::Command::new("auditctl").arg("-l").output() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains("execve") {
                return true;
            }
        }
    }

    for path in ["/etc/sudoers"] {
        if let Ok(content) = fs::read_to_string(path) {
            if content.lines().any(|l| {
                let t = l.trim();
                !t.starts_with('#') && (t.contains("log_output") || t.contains("logfile"))
            }) {
                return true;
            }
        }
    }

    if let Ok(entries) = fs::read_dir("/etc/sudoers.d") {
        for entry in entries.flatten() {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                if content.lines().any(|l| {
                    let t = l.trim();
                    !t.starts_with('#') && (t.contains("log_output") || t.contains("logfile"))
                }) {
                    return true;
                }
            }
        }
    }

    false
}

#[cfg(target_os = "linux")]
fn is_active(service: &str) -> bool {
    std::process::Command::new("systemctl")
        .args(&["is-active", service])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false)
}
