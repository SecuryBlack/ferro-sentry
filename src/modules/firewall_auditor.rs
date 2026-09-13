use crate::engine::{EventEngine, SecurityEvent};
use anyhow::Result;

#[cfg(target_os = "linux")]
use crate::engine::Severity;
#[cfg(target_os = "linux")]
use serde_json::json;
#[cfg(target_os = "linux")]
use std::process::Command;

pub async fn scan(engine: &EventEngine) -> Result<Vec<SecurityEvent>> {
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
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
                } else if stdout.contains("Status: active") {
                    findings.push(
                        engine
                            .build_resolved_event("firewall_auditor", "ufw_inactive")
                            .await,
                    );
                }
            }
        } else if has_command("iptables") {
            // Check default INPUT policy
            if let Ok(output) = Command::new("iptables")
                .args(&["-L", "INPUT", "-n"])
                .output()
            {
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
                } else if stdout.contains("Chain INPUT (policy DROP)") || stdout.contains("Chain INPUT (policy REJECT)") {
                    findings.push(
                        engine
                            .build_resolved_event("firewall_auditor", "iptables_default_accept")
                            .await,
                    );
                }
            }
        }

        // 3. Check if Docker bypasses UFW
        let ufw_is_active = if has_command("ufw") {
            if let Ok(output) = Command::new("ufw").arg("status").output() {
                String::from_utf8_lossy(&output.stdout).contains("Status: active")
            } else {
                false
            }
        } else {
            false
        };

        if ufw_is_active && (has_command("docker") || std::path::Path::new("/var/run/docker.sock").exists()) {
            let mut docker_user_configured = false;
            if let Ok(output) = Command::new("iptables").args(&["-S", "DOCKER-USER"]).output() {
                let s = String::from_utf8_lossy(&output.stdout);
                let lines: Vec<&str> = s.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect();
                let has_filter_rules = lines.iter().any(|line| {
                    line.contains("DROP")
                        || line.contains("REJECT")
                        || line.contains("ufw-")
                        || (!line.contains("RETURN") && line.starts_with("-A"))
                });
                if has_filter_rules {
                    docker_user_configured = true;
                }
            }

            let mut exposed_ports: Vec<String> = Vec::new();
            if let Ok(output) = Command::new("docker")
                .args(&["ps", "--format", "{{.Names}}: {{.Ports}}"])
                .output()
            {
                let s = String::from_utf8_lossy(&output.stdout);
                for line in s.lines() {
                    let trimmed = line.trim();
                    if trimmed.contains("0.0.0.0:") || trimmed.contains(":::") || trimmed.contains("[::]:") {
                        exposed_ports.push(trimmed.to_string());
                    }
                }
            }

            if !docker_user_configured && !exposed_ports.is_empty() {
                let details = json!({
                    "rule_id": "FW-003",
                    "title": "Docker Bypasses Host Firewall (UFW)",
                    "firewall_type": "ufw",
                    "status": "unprotected_docker",
                    "exposed_containers": exposed_ports,
                    "summary": "Docker creates its own iptables NAT rules that route traffic before UFW's INPUT chain, exposing container ports directly to the internet.",
                    "remediation": "Configure the DOCKER-USER chain in /etc/ufw/after.rules or bind internal container ports explicitly to 127.0.0.1 (e.g. 127.0.0.1:5432:5432)."
                });

                findings.push(
                    engine
                        .build_event(
                            "finding",
                            "firewall",
                            Severity::High,
                            "firewall_auditor",
                            details,
                            Some("docker_ufw_bypass"),
                        )
                        .await,
                );
            } else if docker_user_configured || exposed_ports.is_empty() {
                findings.push(
                    engine
                        .build_resolved_event("firewall_auditor", "docker_ufw_bypass")
                        .await,
                );
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
