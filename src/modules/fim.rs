use crate::engine::{EventEngine, SecurityEvent, Severity};
use anyhow::Result;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::Mutex;

static FIM_BASELINE: Mutex<Option<HashMap<String, String>>> = Mutex::new(None);

pub async fn scan(engine: &EventEngine) -> Result<Vec<SecurityEvent>> {
    let mut findings = Vec::new();
    let targets = get_target_files();

    let mut current_hashes = HashMap::new();
    for target in &targets {
        if Path::new(target).exists() {
            if let Ok(hash) = compute_sha256(target) {
                current_hashes.insert(target.to_string(), hash);
            }
        }
    }

    let mut lock = FIM_BASELINE.lock().unwrap();
    if lock.is_none() {
        // First run: Establish baseline
        tracing::info!(file_count = current_hashes.len(), "FIM baseline established");
        *lock = Some(current_hashes);
        return Ok(findings);
    }

    let baseline = lock.as_ref().unwrap();

    for (file_path, current_hash) in &current_hashes {
        if let Some(expected_hash) = baseline.get(file_path) {
            if expected_hash != current_hash {
                let details = json!({
                    "rule_id": "FIM-001",
                    "title": "Critical File Content Modified",
                    "file_path": file_path,
                    "expected_hash": expected_hash,
                    "actual_hash": current_hash,
                    "summary": format!("The integrity of critical system file '{}' has been compromised or modified.", file_path),
                    "remediation": format!("Verify recent administrator changes to '{}'. If unexpected, audit system logs and restore from a verified backup.", file_path)
                });

                findings.push(
                    engine
                        .build_event(
                            "finding",
                            "integrity",
                            Severity::High,
                            "fim",
                            details,
                            Some(&format!("fim_modified_{}", file_path.replace(['/', '\\', ':'], "_"))),
                        )
                        .await,
                );
            }
        }
    }

    // Update baseline to prevent alert storm on single modification
    *lock = Some(current_hashes);

    Ok(findings)
}

fn get_target_files() -> Vec<String> {
    let mut files = Vec::new();
    let linux_targets = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/crontab",
        "/etc/hosts",
    ];

    let windows_targets = [
        r"C:\Windows\System32\drivers\etc\hosts",
        r"C:\ProgramData\ssh\sshd_config",
    ];

    for path in linux_targets {
        if Path::new(path).exists() {
            files.push(path.to_string());
        }
    }

    for path in windows_targets {
        if Path::new(path).exists() {
            files.push(path.to_string());
        }
    }

    files
}

fn compute_sha256(path: &str) -> Result<String> {
    let bytes = fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("{:x}", hasher.finalize()))
}
