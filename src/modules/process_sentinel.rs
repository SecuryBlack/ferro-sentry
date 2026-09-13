use crate::engine::{EventEngine, SecurityEvent};
use anyhow::Result;

#[cfg(target_os = "linux")]
use crate::engine::Severity;
#[cfg(target_os = "linux")]
use serde_json::json;
#[cfg(target_os = "linux")]
use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::fs;
#[cfg(target_os = "linux")]
use std::sync::Mutex;

#[cfg(target_os = "linux")]
static PREVIOUS_PROCESS_RULES: Mutex<Option<HashSet<String>>> = Mutex::new(None);

pub async fn scan(engine: &EventEngine) -> Result<Vec<SecurityEvent>> {
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        let mut current_rules = HashSet::new();

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
                            if path_str.starts_with("/tmp")
                                || path_str.starts_with("/var/tmp")
                                || path_str.starts_with("/dev/shm")
                            {
                                let rule = format!("proc_temp_exec_{}", pid_str);
                                current_rules.insert(rule.clone());

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
                                            Some(&rule),
                                        )
                                        .await,
                                );
                            }

                            // 2. Dangling binary handle (deleted binary running)
                            if path_str.contains("(deleted)") {
                                let rule = format!("proc_deleted_exec_{}", pid_str);
                                current_rules.insert(rule.clone());

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
                                            Some(&rule),
                                        )
                                        .await,
                                );
                            }
                        }
                    }
                }
            }
        }

        // Auto-resolución: si una regla de proceso detectada en el escaneo anterior
        // ya no está presente (el proceso murió o ya no tiene un handle borrado),
        // emitir un evento 'resolved' para que se cierre el hallazgo activo en la base de datos.
        let mut prev_lock = PREVIOUS_PROCESS_RULES.lock().unwrap();
        if let Some(ref prev) = *prev_lock {
            for old_rule in prev {
                if !current_rules.contains(old_rule) {
                    findings.push(
                        engine
                            .build_resolved_event("process_sentinel", old_rule)
                            .await,
                    );
                }
            }
        }
        *prev_lock = Some(current_rules);
    }

    let _ = engine;

    Ok(findings)
}
