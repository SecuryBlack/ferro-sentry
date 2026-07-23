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
                                            Some(&format!("suid_temp_{}", path_str.replace(['/', '\\', ':'], "_"))),
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
                                        Some(&format!("world_writable_{}", path_str.replace(['/', '\\', ':'], "_"))),
                                    )
                                    .await,
                            );
                        }
                    }
                }
            }
        }
    }

    let _ = engine;

    Ok(findings)
}
