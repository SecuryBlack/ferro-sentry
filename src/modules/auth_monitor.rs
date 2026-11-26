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

        let mut known = load_known_logins();
        // Primera vez en este servidor: aprender las IPs del auth.log entero
        // sin avisar, para no dar por nuevas las de siempre.
        let learn_only = known.is_none();

        // Lock breve: nunca debe llegar a los .await de más abajo.
        let previous = AUTH_LOG_OFFSET.lock().unwrap().replace(current_len);
        let start_offset = match previous {
            None if learn_only => 0,
            None => {
                // Primer escaneo: establecer baseline sin contar histórico.
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

        // ─── AUTH-002: inicio de sesión correcto desde un sitio nunca visto ───
        // Con credenciales robadas el acceso es *correcto*; los fallidos de
        // AUTH-001 no lo ven.
        let known_set = known.get_or_insert_with(Default::default);
        let mut new_logins = Vec::new();
        for login in content.lines().filter_map(parse_accepted) {
            if known_set.insert(login.key()) {
                new_logins.push(login);
            }
        }
        if learn_only || !new_logins.is_empty() {
            save_known_logins(known_set);
        }
        if learn_only {
            tracing::info!(
                count = known_set.len(),
                "auth_monitor: accesos conocidos aprendidos"
            );
            return Ok(findings);
        }

        if new_logins.len() > MAX_NEW_LOGIN_FINDINGS {
            tracing::warn!(
                total = new_logins.len(),
                "auth_monitor: demasiados accesos nuevos, se avisa solo de los primeros"
            );
        }
        for login in new_logins.into_iter().take(MAX_NEW_LOGIN_FINDINGS) {
            // Con contraseña es peor: es lo que se roba y se reutiliza.
            let severity = if login.method == "password" {
                Severity::High
            } else {
                Severity::Medium
            };
            let details = json!({
                "rule_id": "AUTH-002",
                "title": "Successful Login From A New Address",
                "user": login.user,
                "source_ip": login.ip,
                "method": login.method,
                "key_fingerprint": login.key_fingerprint,
                "summary": format!(
                    "User '{}' logged in successfully via {} from {}, an address never seen for this user on this server.",
                    login.user, login.method, login.ip
                ),
                "remediation": "If this was not you or your team, the credentials or SSH key may be stolen: kill the session, remove the key or change the password, and review what was done (last, auth.log, shell history)."
            });
            findings.push(
                engine
                    .build_event(
                        "finding",
                        "access",
                        severity,
                        "auth_monitor",
                        details,
                        Some(&format!("new_login_ip:{}", login.key())),
                    )
                    .await,
            );
        }

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

/// Pares `usuario@ip` que ya han entrado alguna vez. En disco, no en memoria:
/// si no, cada reinicio o autoactualización del agente daría todas las IPs
/// por nuevas. `None` = fichero ausente (primera vez en este servidor).
#[cfg(target_os = "linux")]
const KNOWN_LOGINS_PATH: &str = "/var/lib/ferro-sentry/known_logins.json";

/// Tope de avisos AUTH-002 por escaneo: un CI que entra por SSH desde IPs
/// variables no debe llenar el panel. El resto se aprende igualmente.
#[cfg(target_os = "linux")]
const MAX_NEW_LOGIN_FINDINGS: usize = 20;

#[cfg(target_os = "linux")]
fn load_known_logins() -> Option<std::collections::BTreeSet<String>> {
    let raw = std::fs::read_to_string(KNOWN_LOGINS_PATH).ok()?;
    // Corrupto = vacío pero ya inicializado: mejor algún aviso de más que
    // volver a aprender en silencio lo que haya pasado.
    Some(serde_json::from_str(&raw).unwrap_or_default())
}

#[cfg(target_os = "linux")]
fn save_known_logins(known: &std::collections::BTreeSet<String>) {
    let path = std::path::Path::new(KNOWN_LOGINS_PATH);
    let result = path
        .parent()
        .map_or(Ok(()), std::fs::create_dir_all)
        .and_then(|_| std::fs::write(path, serde_json::to_vec(known).unwrap_or_default()));
    if let Err(e) = result {
        tracing::warn!(error = %e, "auth_monitor: no se pudo guardar {}", KNOWN_LOGINS_PATH);
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Debug, PartialEq)]
struct AcceptedLogin {
    user: String,
    ip: String,
    method: String,
    key_fingerprint: Option<String>,
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl AcceptedLogin {
    fn key(&self) -> String {
        format!("{}@{}", self.user, self.ip)
    }
}

/// Línea de sshd `Accepted <método> for <usuario> from <ip> port <n> ssh2[: <clave>]`.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_accepted(line: &str) -> Option<AcceptedLogin> {
    let rest = &line[line.find("Accepted ")? + "Accepted ".len()..];
    let mut words = rest.split_whitespace();
    let method = words.next()?;
    if words.next()? != "for" {
        return None;
    }
    let user = words.next()?;
    if words.next()? != "from" {
        return None;
    }
    let ip = words.next()?;
    Some(AcceptedLogin {
        user: user.to_string(),
        ip: ip.to_string(),
        method: method.to_string(),
        key_fingerprint: rest.split_once("ssh2: ").map(|(_, k)| k.trim().to_string()),
    })
}

#[cfg(target_os = "linux")]
fn extract_ip(line: &str) -> Option<String> {
    let idx = line.find("from ")?;
    let rest = &line[idx + 5..];
    let ip = rest.split_whitespace().next()?;
    Some(ip.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepted_clave_y_contrasena() {
        let l = "2026-11-26T12:00:01.123+00:00 srv sshd[42]: Accepted publickey for root from 100.101.1.2 port 51234 ssh2: ED25519 SHA256:abcDEF";
        let a = parse_accepted(l).unwrap();
        assert_eq!(a.user, "root");
        assert_eq!(a.ip, "100.101.1.2");
        assert_eq!(a.method, "publickey");
        assert_eq!(a.key_fingerprint.as_deref(), Some("ED25519 SHA256:abcDEF"));
        assert_eq!(a.key(), "root@100.101.1.2");

        let p = parse_accepted("Nov 26 12:00:01 srv sshd[42]: Accepted password for mikel from 2001:db8::1 port 22 ssh2").unwrap();
        assert_eq!(
            (p.user.as_str(), p.ip.as_str(), p.method.as_str()),
            ("mikel", "2001:db8::1", "password")
        );
        assert_eq!(p.key_fingerprint, None);

        assert!(
            parse_accepted("sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2").is_none()
        );
        assert!(parse_accepted("sudo: Accepted something weird").is_none());
    }
}
