use crate::engine::{EventEngine, SecurityEvent};
use anyhow::Result;

#[cfg(target_os = "linux")]
use crate::engine::Severity;
#[cfg(target_os = "linux")]
use serde_json::json;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::path::Path;

pub async fn scan(engine: &EventEngine) -> Result<Vec<SecurityEvent>> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // Scan /proc for running process executables
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if let Some(pid_str) = name.to_str() {
                    if pid_str.chars().all(|c| c.is_ascii_digit()) {
                        let exe_link = format!("/proc/{}/exe", pid_str);
                        if let Ok(target_path) = fs::read_link(&exe_link) {
                            let path_str = target_path.to_string_lossy().to_string();

                            // 1. Process running from temporary path
                            if path_str.starts_with("/tmp") || path_str.starts_with("/var/tmp") || path_str.starts_with("/dev/shm") {
                                let details = json!({
                                    "rule_id": "PROC-001",
                                    "title": "Process Executing from Temporary Directory",
                                    "pid": pid_str,
                                    "exe_path": path_str,
                                    "summary": format!("Process PID {} is running from temporary path '{}'. Malware often executes out of /tmp.", pid_str, path_str),
                                    "remediation": format!("Inspect process details with 'ls -l /proc/{}/' and terminate via 'kill -9 {}'.", pid_str, pid_str)
                                });

                                findings.push(
                                    engine
                                        .build_event(
                                            "finding",
                                            "process",
                                            Severity::High,
                                            "process_sentinel",
                                            details,
                                            Some(&format!("proc_temp_exec_{}", pid_str)),
                                        )
                                        .await,
                                );
                            }

                            // 2. Dangling binary handle (deleted binary running)
                            if path_str.contains("(deleted)") {
                                let details = json!({
                                    "rule_id": "PROC-002",
                                    "title": "Process Running with Deleted Binary (Dangling Handle)",
                                    "pid": pid_str,
                                    "exe_path": path_str,
                                    "summary": format!("Process PID {} executable file was deleted from disk while continuing execution, a common stealth evasion technique.", pid_str),
                                    "remediation": format!("Investigate PID {} immediately and kill process via 'kill -9 {}'.", pid_str, pid_str)
                                });

                                findings.push(
                                    engine
                                        .build_event(
                                            "finding",
                                            "process",
                                            Severity::High,
                                            "process_sentinel",
                                            details,
                                            Some(&format!("proc_deleted_exec_{}", pid_str)),
                                        )
                                        .await,
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    let _ = engine;

    Ok(findings)
}
