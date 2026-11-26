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

    let baseline = {
        let mut lock = FIM_BASELINE.lock().unwrap();
        if lock.is_none() {
            // First run: Establish baseline
            tracing::info!(
                file_count = current_hashes.len(),
                "FIM baseline established"
            );
            *lock = Some(current_hashes);
            return Ok(findings);
        }
        lock.clone().unwrap()
    };

    for (file_path, current_hash) in &current_hashes {
        let expected_hash = baseline.get(file_path);
        if expected_hash == Some(current_hash) {
            continue;
        }
        // Un fichero que no estaba en la base es nuevo: en `authorized_keys`
        // es justo la persistencia que deja quien entra con una clave robada.
        let created = expected_hash.is_none();
        let is_keys = file_path.contains("authorized_keys");
        let (title, summary, remediation) = match (created, is_keys) {
            (true, true) => (
                "New SSH Authorized Keys File",
                format!("A new SSH authorized keys file appeared at '{}': someone can now log in with a key that was not there before.", file_path),
                format!("Check every key in '{}'. If you did not add it, remove it, rotate credentials and review recent logins.", file_path),
            ),
            (false, true) => (
                "SSH Authorized Keys Modified",
                format!("The SSH authorized keys at '{}' changed: a key may have been added to log in without a password.", file_path),
                format!("Check every key in '{}'. If you did not add it, remove it, rotate credentials and review recent logins.", file_path),
            ),
            (true, false) => (
                "Critical File Created",
                format!("Critical system file '{}' appeared since the last scan.", file_path),
                format!("Verify recent administrator changes to '{}'. If unexpected, audit system logs.", file_path),
            ),
            (false, false) => (
                "Critical File Content Modified",
                format!("The integrity of critical system file '{}' has been compromised or modified.", file_path),
                format!("Verify recent administrator changes to '{}'. If unexpected, audit system logs and restore from a verified backup.", file_path),
            ),
        };
        let details = json!({
            "rule_id": "FIM-001",
            "title": title,
            "change": if created { "created" } else { "modified" },
            "file_path": file_path,
            "expected_hash": expected_hash,
            "actual_hash": current_hash,
            "summary": summary,
            "remediation": remediation
        });

        findings.push(
            engine
                .build_event(
                    "finding",
                    "integrity",
                    Severity::High,
                    "fim",
                    details,
                    Some(&format!(
                        "fim_{}_{}",
                        if created { "created" } else { "modified" },
                        file_path.replace(['/', '\\', ':'], "_")
                    )),
                )
                .await,
        );
    }

    // Update baseline to prevent alert storm on single modification
    *FIM_BASELINE.lock().unwrap() = Some(current_hashes);

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
        r"C:\ProgramData\ssh\administrators_authorized_keys",
    ];

    // ponytail: solo la ruta por defecto; un `AuthorizedKeysFile` propio en
    // sshd_config no se vigila. Leerlo de `sshd -T` si algún cliente lo usa.
    for home in super::home_dirs() {
        for name in ["authorized_keys", "authorized_keys2"] {
            let path = home.join(".ssh").join(name);
            if path.is_file() {
                files.push(path.to_string_lossy().to_string());
            }
        }
    }

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
