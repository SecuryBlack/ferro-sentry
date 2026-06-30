use crate::engine::{EventEngine, SecurityEvent};
#[cfg(target_os = "linux")]
use crate::engine::Severity;
#[cfg(target_os = "linux")]
use serde_json::json;
use anyhow::Result;

#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
pub async fn scan(engine: &EventEngine) -> Result<Vec<SecurityEvent>> {
    let mut findings = Vec::new();

    // 1. Detect package manager and count updates
    let mut total_updates = 0;
    let mut security_updates = 0;
    let mut package_manager = "unknown";
    let mut raw_output = String::new();

    if has_command("apt-get") {
        package_manager = "apt";
        if let Ok((total, security, out)) = check_apt_updates() {
            total_updates = total;
            security_updates = security;
            raw_output = out;
        }
    } else if has_command("dnf") {
        package_manager = "dnf";
        if let Ok((total, security, out)) = check_dnf_updates() {
            total_updates = total;
            security_updates = security;
            raw_output = out;
        }
    } else if has_command("yum") {
        package_manager = "yum";
        if let Ok((total, security, out)) = check_yum_updates() {
            total_updates = total;
            security_updates = security;
            raw_output = out;
        }
    }

    if package_manager != "unknown" && total_updates > 0 {
        let severity = if security_updates > 0 {
            Severity::High
        } else {
            Severity::Medium
        };

        let details = json!({
            "package_manager": package_manager,
            "total_updates": total_updates,
            "security_updates": security_updates,
            "summary": format!("Found {} pending updates ({} security-related)", total_updates, security_updates),
            "raw_output_snippet": raw_output.lines().take(20).collect::<Vec<&str>>().join("\n")
        });

        findings.push(
            engine
                .build_event(
                    "finding",
                    "posture",
                    severity,
                    "vuln_scanner",
                    details,
                    Some("pending_os_updates"),
                )
                .await,
        );
    }

    Ok(findings)
}

#[cfg(not(target_os = "linux"))]
pub async fn scan(_engine: &EventEngine) -> Result<Vec<SecurityEvent>> {
    // Non-linux is a no-op for now
    Ok(Vec::new())
}

#[cfg(target_os = "linux")]
fn has_command(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn check_apt_updates() -> Result<(usize, usize, String)> {
    // Run simulated upgrade
    let output = Command::new("apt-get")
        .args(&["-s", "upgrade"])
        .env("LANG", "C")
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut total = 0;
    let mut security = 0;

    for line in stdout.lines() {
        if line.starts_with("Inst ") {
            total += 1;
            if line.contains("security") || line.contains("-sec") {
                security += 1;
            }
        }
    }

    Ok((total, security, stdout.into_owned()))
}

#[cfg(target_os = "linux")]
fn check_dnf_updates() -> Result<(usize, usize, String)> {
    // Get all updates
    let output = Command::new("dnf")
        .args(&["check-update", "-q"])
        .output()?;
    
    // dnf check-update returns 100 if updates are available, 0 if none, 1 on error
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    let mut total = 0;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with("Last metadata expiration check") {
            total += 1;
        }
    }

    // Check security updates count
    let sec_output = Command::new("dnf")
        .args(&["check-update", "--security", "-q"])
        .output()?;
    let sec_stdout = String::from_utf8_lossy(&sec_output.stdout);
    let mut security = 0;
    for line in sec_stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with("Last metadata expiration check") {
            security += 1;
        }
    }

    Ok((total, security, stdout.into_owned()))
}

#[cfg(target_os = "linux")]
fn check_yum_updates() -> Result<(usize, usize, String)> {
    let output = Command::new("yum")
        .args(&["check-update", "-q"])
        .output()?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    let mut total = 0;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with("Last metadata expiration check") {
            total += 1;
        }
    }

    // Yum security updates check
    let sec_output = Command::new("yum")
        .args(&["check-update", "--security", "-q"])
        .output()?;
    let sec_stdout = String::from_utf8_lossy(&sec_output.stdout);
    let mut security = 0;
    for line in sec_stdout.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with("Last metadata expiration check") {
            security += 1;
        }
    }

    Ok((total, security, stdout.into_owned()))
}
