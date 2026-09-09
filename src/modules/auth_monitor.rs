use crate::engine::{EventEngine, SecurityEvent};
use anyhow::Result;

#[cfg(target_os = "linux")]
use crate::engine::Severity;
#[cfg(target_os = "linux")]
use serde_json::json;
#[cfg(target_os = "linux")]
use std::sync::Mutex;

/// Offset en bytes hasta donde ya se ha leído `/var/log/auth.log`. Igual que
/// el patrón de baseline de `fim`: vive en memoria del proceso, no en disco —
/// en un reinicio del agente se relee desde 0 y el primer escaneo solo
/// establece el offset sin generar hallazgo, para no reportar de golpe todo
/// el histórico del fichero como si hubiera pasado en la última hora.
#[cfg(target_os = "linux")]
static AUTH_LOG_OFFSET: Mutex<Option<u64>> = Mutex::new(None);

#[cfg(target_os = "linux")]
const AUTH_LOG_PATH: &str = "/var/log/auth.log";

pub async fn scan(engine: &EventEngine) -> Result<Vec<SecurityEvent>> {
    #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
    let mut findings = Vec::new();

    #[cfg(target_os = "linux")]
    {
        use std::io::{Read, Seek, SeekFrom};

        let Ok(mut file) = std::fs::File::open(AUTH_LOG_PATH) else {
            // Sin auth.log (p.ej. distro que solo usa journald sin
            // persistencia a fichero) — no es un fallo, simplemente no hay
            // nada que auditar con este mecanismo todavía.
            return Ok(findings);
        };

        let current_len = file.metadata().map(|m| m.len()).unwrap_or(0);

        let mut offset_lock = AUTH_LOG_OFFSET.lock().unwrap();
        let start_offset = match *offset_lock {
            None => {
                // Primer escaneo: establecer baseline sin contar histórico.
                *offset_lock = Some(current_len);
                tracing::info!(offset = current_len, "auth_monitor baseline establecido");
                return Ok(findings);
            }
            // Log rotado/truncado (offset guardado ya no cabe en el fichero actual) — releer desde el principio.
            Some(prev) if prev > current_len => 0,
            Some(prev) => prev,
        };

        let mut content = String::new();
        if file.seek(SeekFrom::Start(start_offset)).is_ok() {
            let _ = file.read_to_string(&mut content);
        }
        *offset_lock = Some(current_len);
        drop(offset_lock);

        let mut failed_password = 0u32;
        let mut invalid_user = 0u32;
        let mut sample_ips: Vec<String> = Vec::new();

        for line in content.lines() {
            if line.contains("Failed password") || line.contains("authentication failure") {
                failed_password += 1;
                if let Some(ip) = extract_ip(line) {
                    if !sample_ips.contains(&ip) && sample_ips.len() < 10 {
                        sample_ips.push(ip);
                    }
                }
            }
            if line.contains("Invalid user") {
                invalid_user += 1;
            }
        }

        let total_failed = failed_password + invalid_user;

        if total_failed > 0 {
            let severity = if total_failed >= 100 {
                Severity::Critical
            } else if total_failed >= 20 {
                Severity::High
            } else {
                Severity::Low
            };

            let details = json!({
                "rule_id": "AUTH-001",
                "title": "Failed Login Attempts Detected",
                "failed_password_count": failed_password,
                "invalid_user_count": invalid_user,
                "total_failed": total_failed,
                "window_bytes_scanned": content.len(),
                "sample_source_ips": sample_ips,
                "summary": format!(
                    "{} failed login attempts detected since the last scan ({} failed password, {} invalid user) — possible brute-force activity.",
                    total_failed, failed_password, invalid_user
                ),
                "remediation": "Verify fail2ban/CrowdSec are banning the source IPs above; consider key-only auth if not already enforced."
            });

            findings.push(
                engine
                    .build_event(
                        "finding",
                        "posture",
                        severity,
                        "auth_monitor",
                        details,
                        Some("failed_login_attempts"),
                    )
                    .await,
            );
        }
    }

    let _ = engine;

    Ok(findings)
}

#[cfg(target_os = "linux")]
fn extract_ip(line: &str) -> Option<String> {
    let idx = line.find("from ")?;
    let rest = &line[idx + 5..];
    let ip = rest.split_whitespace().next()?;
    Some(ip.to_string())
}
