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
        // 1. Audit /etc/crontab and /etc/cron.d
        let cron_paths = ["/etc/crontab", "/etc/cron.d"];
        for cron_path in cron_paths {
            let path = Path::new(cron_path);
            if path.is_file() {
                if let Ok(content) = fs::read_to_string(path) {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            if trimmed.contains("/tmp") || trimmed.contains("/var/tmp") || trimmed.contains("curl ") || trimmed.contains("wget ") || trimmed.contains("python -c") {
                                let details = json!({
                                    "rule_id": "PERSIST-001",
                                    "title": "Suspicious Cron Persistence Detected",
                                    "cron_file": cron_path,
                                    "cron_entry": trimmed,
                                    "summary": format!("Cron entry in '{}' executes commands from temporary directories or downloads external payloads.", cron_path),
                                    "remediation": format!("Inspect and remove unauthorized cron entry in '{}'.", cron_path)
                                });

                                findings.push(
                                    engine
                                        .build_event(
                                            "finding",
                                            "persistence",
                                            Severity::High,
                                            "persistence_hunter",
                                            details,
                                            Some(&format!("cron_suspicious_{}", trimmed.replace(['/', '\\', ' ', ':'], "_"))),
                                        )
                                        .await,
                                );
                            }
                        }
                    }
                }
            } else if path.is_dir() {
                if let Ok(entries) = fs::read_dir(path) {
                    for entry in entries.flatten() {
                        let fpath = entry.path();
                        if fpath.is_file() {
                            if let Ok(content) = fs::read_to_string(&fpath) {
                                for line in content.lines() {
                                    let trimmed = line.trim();
                                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                                        if trimmed.contains("/tmp") || trimmed.contains("/var/tmp") || trimmed.contains("curl ") || trimmed.contains("wget ") {
                                            let fpath_str = fpath.to_string_lossy().to_string();
                                            let details = json!({
                                                "rule_id": "PERSIST-001",
                                                "title": "Suspicious Cron Persistence Detected",
                                                "cron_file": fpath_str,
                                                "cron_entry": trimmed,
                                                "summary": format!("Cron entry in '{}' executes suspicious commands.", fpath_str),
                                                "remediation": format!("Inspect and remove unauthorized cron entry in '{}'.", fpath_str)
                                            });

                                            findings.push(
                                                engine
                                                    .build_event(
                                                        "finding",
                                                        "persistence",
                                                        Severity::High,
                                                        "persistence_hunter",
                                                        details,
                                                        Some(&format!("cron_dir_suspicious_{}", trimmed.replace(['/', '\\', ' ', ':'], "_"))),
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
            }
        }
    }

    let _ = engine;

    Ok(findings)
}
