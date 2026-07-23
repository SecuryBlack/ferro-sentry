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
        // Audit Let's Encrypt certificates if present
        let le_path = Path::new("/etc/letsencrypt/live");
        if le_path.is_dir() {
            if let Ok(entries) = fs::read_dir(le_path) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        let domain = path.file_name().unwrap_or_default().to_string_lossy().to_string();
                        let cert_file = path.join("cert.pem");
                        if cert_file.is_file() {
                            // Check certificate validity / file existence
                            let details = json!({
                                "rule_id": "SSL-001",
                                "title": "SSL Certificate Monitored",
                                "domain": domain,
                                "cert_path": cert_file.to_string_lossy(),
                                "summary": format!("SSL/TLS Certificate configured for domain '{}'.", domain),
                                "remediation": "Ensure certbot auto-renewal timer is active: 'systemctl status certbot.timer'."
                            });

                            // Only register informational / posture status
                            findings.push(
                                engine
                                    .build_event(
                                        "finding",
                                        "ssl",
                                        Severity::Info,
                                        "ssl_auditor",
                                        details,
                                        Some(&format!("ssl_cert_{}", domain)),
                                    )
                                    .await,
                            );
                        }
                    }
                }
            }
        }
    }

    let _ = engine;

    Ok(findings)
}
