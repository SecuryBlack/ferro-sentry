use crate::engine::{EventEngine, SecurityEvent};
use anyhow::Result;

#[cfg(target_os = "linux")]
use crate::engine::Severity;
#[cfg(target_os = "linux")]
use serde_json::json;
#[cfg(target_os = "linux")]
use std::process::Command;

pub async fn scan(engine: &EventEngine) -> Result<Vec<SecurityEvent>> {
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        // 1. Check ufw status if available
        if has_command("ufw") {
            if let Ok(output) = Command::new("ufw").arg("status").output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains("Status: inactive") {
                    let details = json!({
                        "rule_id": "FW-001",
                        "title": "Uncomplicated Firewall (UFW) is Inactive",
                        "firewall_type": "ufw",
                        "status": "inactive",
                        "summary": "The UFW host firewall is installed but currently inactive, leaving open ports unfiltered.",
                        "remediation": "Enable the firewall using 'sudo ufw enable' after configuring necessary SSH allow rules."
                    });

                    findings.push(
                        engine
                            .build_event(
                                "finding",
                                "firewall",
                                Severity::High,
                                "firewall_auditor",
                                details,
                                Some("ufw_inactive"),
                            )
                            .await,
                    );
                }
            }
        } else if has_command("iptables") {
            // Check default INPUT policy
            if let Ok(output) = Command::new("iptables").args(&["-L", "INPUT", "-n"]).output() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                if stdout.contains("Chain INPUT (policy ACCEPT)") {
                    let details = json!({
                        "rule_id": "FW-002",
                        "title": "Default iptables INPUT Policy is ACCEPT",
                        "firewall_type": "iptables",
                        "policy": "ACCEPT",
                        "summary": "The default iptables INPUT chain policy is set to ACCEPT, meaning non-explicitly dropped traffic is permitted.",
                        "remediation": "Set default policy to DROP: 'iptables -P INPUT DROP' (ensure SSH port is explicitly allowed first)."
                    });

                    findings.push(
                        engine
                            .build_event(
                                "finding",
                                "firewall",
                                Severity::Medium,
                                "firewall_auditor",
                                details,
                                Some("iptables_default_accept"),
                            )
                            .await,
                    );
                }
            }
        }
    }

    let _ = engine;

    Ok(findings)
}

#[cfg(target_os = "linux")]
fn has_command(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}
