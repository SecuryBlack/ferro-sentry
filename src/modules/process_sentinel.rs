use crate::engine::{EventEngine, SecurityEvent};
use anyhow::Result;

#[cfg(target_os = "linux")]
use crate::engine::Severity;
#[cfg(target_os = "linux")]
use serde_json::json;
#[cfg(target_os = "linux")]
use std::collections::{HashMap, HashSet};
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
        let mut temp_exec_map: HashMap<String, Vec<String>> = HashMap::new();
        let mut deleted_bin_map: HashMap<String, Vec<String>> = HashMap::new();

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
                                temp_exec_map
                                    .entry(path_str.clone())
                                    .or_default()
                                    .push(pid_str.to_string());
                            }

                            // 2. Dangling binary handle (deleted binary running)
                            if path_str.contains("(deleted)") {
                                let clean_path = path_str
                                    .replace("(deleted)", "")
                                    .trim()
                                    .to_string();
                                deleted_bin_map
                                    .entry(clean_path)
                                    .or_default()
                                    .push(pid_str.to_string());
                            }
                        }
                    }
                }
            }
        }

        // Emit consolidated events for temporary directory executables
        for (exe_path, mut pids) in temp_exec_map {
            pids.sort();
            let safe_suffix = exe_path
                .replace('/', "_")
                .replace('.', "_")
                .replace('-', "_");
            let rule = format!("proc_temp_exec_{}", safe_suffix);
            current_rules.insert(rule.clone());

            let pids_display = pids.join(", ");
            let first_pid = pids.first().cloned().unwrap_or_default();
            let count = pids.len();

            let details = json!({
                "rule_id": "PROC-001",
                "title": "Process Executing from Temporary Directory",
                "exe_path": exe_path,
                "pid": first_pid,
                "pids": pids,
                "process_count": count,
                "summary": format!("{} process(es) (PID: {}) running from temporary path '{}'. Malware often executes out of /tmp.", count, pids_display, exe_path),
                "remediation": format!("Inspect process details with 'ls -l /proc/{}/' and terminate via 'kill -9 {}'.", first_pid, pids_display)
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

        // Emit consolidated events for deleted binaries
        for (exe_path, mut pids) in deleted_bin_map {
            pids.sort();
            let safe_suffix = exe_path
                .replace('/', "_")
                .replace('.', "_")
                .replace('-', "_");
            let rule = format!("proc_deleted_bin_{}", safe_suffix);
            current_rules.insert(rule.clone());

            let pids_display = pids.join(", ");
            let first_pid = pids.first().cloned().unwrap_or_default();
            let count = pids.len();

            // Diferenciar si es un binario legítimo del sistema tras actualización (apt/dnf)
            let is_system_bin = exe_path.starts_with("/usr/")
                || exe_path.starts_with("/bin/")
                || exe_path.starts_with("/sbin/");

            let (severity, category, title, summary, remediation) = if is_system_bin {
                (
                    Severity::Medium,
                    "posture",
                    "Service Running Outdated Binary After Package Upgrade",
                    format!("{} process(es) (PID: {}) are executing '{}' whose binary was updated on disk. The old binary is still loaded in memory.", count, pids_display, exe_path),
                    format!("Restart the corresponding service(s) to load the updated binary, or terminate PID(s): {}.", pids_display)
                )
            } else {
                (
                    Severity::High,
                    "process",
                    "Process Running with Deleted Binary (Dangling Handle)",
                    format!("{} process(es) (PID: {}) executable file '{}' was deleted from disk while continuing execution (stealth evasion technique).", count, pids_display, exe_path),
                    format!("Investigate PID(s) {} immediately and terminate via 'kill -9 {}'.", pids_display, pids_display)
                )
            };

            let details = json!({
                "rule_id": "PROC-002",
                "title": title,
                "exe_path": exe_path,
                "pid": first_pid,
                "pids": pids,
                "process_count": count,
                "summary": summary,
                "remediation": remediation
            });

            findings.push(
                engine
                    .build_event(
                        "finding",
                        category,
                        severity,
                        "process_sentinel",
                        details,
                        Some(&rule),
                    )
                    .await,
            );
        }

        // Auto-resolución: si una regla de proceso detectada en el escaneo anterior
        // ya no está presente (todos los procesos de ese ejecutable murieron o se reiniciaron),
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
