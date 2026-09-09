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
        let fail2ban_active = is_active("fail2ban");
        let crowdsec_active = is_active("crowdsec");

        // Rule 1: ni fail2ban ni CrowdSec están corriendo
        if !fail2ban_active && !crowdsec_active {
            let details = json!({
                "rule_id": "IPS-001",
                "title": "No Intrusion Prevention Service Running",
                "fail2ban_active": false,
                "crowdsec_active": false,
                "summary": "Neither fail2ban nor CrowdSec is active. Brute-force and scanning traffic is not being auto-blocked.",
                "remediation": "Install and enable fail2ban ('apt install fail2ban && systemctl enable --now fail2ban') or CrowdSec."
            });
            findings.push(
                engine
                    .build_event(
                        "finding",
                        "posture",
                        Severity::High,
                        "intrusion_prevention_auditor",
                        details,
                        Some("no_intrusion_prevention"),
                    )
                    .await,
            );
        } else {
            findings.push(
                engine
                    .build_resolved_event("intrusion_prevention_auditor", "no_intrusion_prevention")
                    .await,
            );
        }

        // Rule 2: fail2ban activo, pero el jail sshd no cubre el puerto SSH real
        if fail2ban_active {
            match fail2ban_sshd_port_mismatch() {
                Some((configured_port, jail_ports)) => {
                    let details = json!({
                        "rule_id": "IPS-002",
                        "title": "fail2ban sshd Jail Does Not Cover Active SSH Port",
                        "ssh_port": configured_port,
                        "jail_ports": jail_ports,
                        "summary": format!(
                            "SSH is configured on port {} but the fail2ban 'sshd' jail only watches: {}. Brute-force attempts on the real port are not being banned.",
                            configured_port, jail_ports
                        ),
                        "remediation": format!(
                            "Add 'port = {}' to the [sshd] jail in /etc/fail2ban/jail.local and restart fail2ban.",
                            configured_port
                        )
                    });
                    findings.push(
                        engine
                            .build_event(
                                "finding",
                                "posture",
                                Severity::Medium,
                                "intrusion_prevention_auditor",
                                details,
                                Some("fail2ban_ssh_port_mismatch"),
                            )
                            .await,
                    );
                }
                None => {
                    findings.push(
                        engine
                            .build_resolved_event(
                                "intrusion_prevention_auditor",
                                "fail2ban_ssh_port_mismatch",
                            )
                            .await,
                    );
                }
            }
        }

        // Rule 3: CrowdSec activo pero sin bouncers registrados (detecta pero no bloquea)
        if crowdsec_active {
            if has_command("cscli") {
                if let Ok(output) = Command::new("cscli")
                    .args(&["bouncers", "list", "-o", "json"])
                    .output()
                {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    let bouncer_count = serde_json::from_str::<serde_json::Value>(&stdout)
                        .ok()
                        .and_then(|v| v.as_array().map(|a| a.len()))
                        .unwrap_or(0);

                    if bouncer_count == 0 {
                        let details = json!({
                            "rule_id": "IPS-003",
                            "title": "CrowdSec Running Without Any Bouncer",
                            "bouncer_count": 0,
                            "summary": "CrowdSec is detecting threats but has no registered bouncer, so decisions are never enforced (no traffic is actually blocked).",
                            "remediation": "Install a bouncer, e.g. 'apt install crowdsec-firewall-bouncer-iptables' and verify with 'cscli bouncers list'."
                        });
                        findings.push(
                            engine
                                .build_event(
                                    "finding",
                                    "posture",
                                    Severity::Medium,
                                    "intrusion_prevention_auditor",
                                    details,
                                    Some("crowdsec_no_bouncer"),
                                )
                                .await,
                        );
                    } else {
                        findings.push(
                            engine
                                .build_resolved_event(
                                    "intrusion_prevention_auditor",
                                    "crowdsec_no_bouncer",
                                )
                                .await,
                        );
                    }
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

#[cfg(target_os = "linux")]
fn is_active(service: &str) -> bool {
    Command::new("systemctl")
        .args(&["is-active", service])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
        .unwrap_or(false)
}

/// Compara el puerto SSH configurado (mismo parseo simple que `ssh_auditor`)
/// contra los puertos que vigila el jail `sshd` de fail2ban. Devuelve
/// `Some((puerto_ssh, puertos_jail))` solo si hay desalineación real —
/// `None` si el jail no existe (nada que comparar, no es un false-positive
/// de esta regla) o si los puertos coinciden.
#[cfg(target_os = "linux")]
fn fail2ban_sshd_port_mismatch() -> Option<(String, String)> {
    let configured_port = configured_ssh_port();

    let output = Command::new("fail2ban-client")
        .args(&["get", "sshd", "port"])
        .output()
        .ok()?;
    if !output.status.success() {
        // Jail "sshd" no existe en este fail2ban — nada que comparar.
        return None;
    }
    let jail_ports_raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if jail_ports_raw.is_empty() {
        return None;
    }

    // fail2ban-client devuelve algo como "ssh,sftp" o "22" o "2222".
    // Resolvemos los alias de servicio conocidos y comparamos como conjunto.
    let jail_ports: Vec<String> = jail_ports_raw
        .split(',')
        .map(|p| p.trim())
        .map(|p| match p {
            "ssh" | "sftp" => "22".to_string(),
            other => other.to_string(),
        })
        .collect();

    if jail_ports.iter().any(|p| p == &configured_port) {
        None
    } else {
        Some((configured_port, jail_ports_raw))
    }
}

#[cfg(target_os = "linux")]
fn configured_ssh_port() -> String {
    let main_paths = ["/etc/ssh/sshd_config"];
    let mut port = "22".to_string();

    for path in main_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 && parts[0].eq_ignore_ascii_case("port") {
                    port = parts[1].to_string();
                }
            }
        }
    }

    if let Ok(entries) = std::fs::read_dir("/etc/ssh/sshd_config.d") {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().is_some_and(|ext| ext == "conf") {
                if let Ok(content) = std::fs::read_to_string(&p) {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if parts.len() >= 2 && parts[0].eq_ignore_ascii_case("port") {
                            port = parts[1].to_string();
                        }
                    }
                }
            }
        }
    }

    port
}
