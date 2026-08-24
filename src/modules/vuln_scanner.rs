#[cfg(target_os = "linux")]
use crate::engine::Severity;
use crate::engine::{EventEngine, SecurityEvent};
use anyhow::Result;
#[cfg(target_os = "linux")]
use serde_json::json;

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

    if package_manager != "unknown" {
        let reboot_required = reboot_required_packages();
        let cache_age_secs = (package_manager == "apt").then(apt_cache_age_secs).flatten();

        if total_updates > 0 {
            let severity = if security_updates > 0 {
                Severity::High
            } else {
                Severity::Medium
            };

            let details = json!({
                "package_manager": package_manager,
                "total_updates": total_updates,
                "security_updates": security_updates,
                "reboot_required": !reboot_required.is_empty(),
                "reboot_required_packages": reboot_required,
                "cache_age_secs": cache_age_secs,
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
        } else if !reboot_required.is_empty() {
            // Sin updates pendientes pero con un reinicio ya pedido por una
            // instalación anterior (p.ej. unattended-upgrades) — igual de
            // relevante para decidir una ventana de mantenimiento.
            let details = json!({
                "package_manager": package_manager,
                "total_updates": 0,
                "security_updates": 0,
                "reboot_required": true,
                "reboot_required_packages": reboot_required,
                "cache_age_secs": cache_age_secs,
                "summary": "System reboot required to finish applying a previous update",
            });

            findings.push(
                engine
                    .build_event(
                        "finding",
                        "posture",
                        Severity::Medium,
                        "vuln_scanner",
                        details,
                        Some("reboot_required"),
                    )
                    .await,
            );
        }
    }

    Ok(findings)
}

/// Paquetes que motivaron `/var/run/reboot-required` (Debian/Ubuntu). Lista
/// vacía si no hay reinicio pendiente o el fichero no existe (RHEL/Fedora no
/// tienen este mecanismo; `dnf needs-restarting` sería el equivalente, no
/// implementado todavía).
#[cfg(target_os = "linux")]
pub(crate) fn reboot_required_packages() -> Vec<String> {
    let marker = std::path::Path::new("/var/run/reboot-required");
    if !marker.exists() {
        return Vec::new();
    }
    std::fs::read_to_string("/var/run/reboot-required.pkgs")
        .map(|s| s.lines().map(str::to_string).collect())
        .unwrap_or_default()
}

/// Antigüedad de la caché de `apt` en segundos, vía el mismo stamp que usa
/// `apt`/`unattended-upgrades` para saber cuándo se corrió `apt-get update`
/// por última vez con éxito. `None` si el stamp no existe todavía (sistema
/// recién instalado) — el llamante decide cómo tratarlo, no lo asumimos aquí.
#[cfg(target_os = "linux")]
fn apt_cache_age_secs() -> Option<u64> {
    let stamp = std::fs::metadata("/var/lib/apt/periodic/update-success-stamp").ok()?;
    let modified = stamp.modified().ok()?;
    std::time::SystemTime::now().duration_since(modified).ok().map(|d| d.as_secs())
}

#[cfg(not(target_os = "linux"))]
pub async fn scan(_engine: &EventEngine) -> Result<Vec<SecurityEvent>> {
    // Non-linux is a no-op for now
    Ok(Vec::new())
}

#[cfg(target_os = "linux")]
pub(crate) fn has_command(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn check_apt_updates() -> Result<(usize, usize, String)> {
    // `-s dist-upgrade` (no `upgrade`): `upgrade` excluye paquetes que
    // requieren instalar o quitar dependencias, así que subestima el total
    // real de pendientes. Sigue siendo una simulación (`-s`), no toca nada.
    let output = Command::new("apt-get")
        .args(&["-s", "dist-upgrade"])
        .env("LANG", "C")
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut total = 0;
    let mut security = 0;

    for line in stdout.lines() {
        if line.starts_with("Inst ") {
            total += 1;
            if is_security_pocket(line) {
                security += 1;
            }
        }
    }

    Ok((total, security, stdout.into_owned()))
}

/// Una línea `Inst` de `apt-get -s` tiene forma:
/// `Inst libssl1.1 [1.1.1f-1ubuntu2] (1.1.1f-1ubuntu2.16 Ubuntu:20.04/focal-security [amd64])`
/// El nombre del paquete puede contener "security" (ej. `libsecurity-foo`),
/// así que solo miramos dentro del paréntesis final, que es donde apt
/// reporta el origen/pocket real (`focal-security`, `noble-security`, etc.).
#[cfg(target_os = "linux")]
fn is_security_pocket(line: &str) -> bool {
    match line.rfind('(') {
        Some(idx) => line[idx..].to_ascii_lowercase().contains("security"),
        None => false,
    }
}

/// Nombres de los paquetes con actualización pendiente por el pocket de
/// seguridad, vía la misma simulación que usa la detección (`apt-get -s
/// dist-upgrade`, no toca nada). Lo usa `management::commands::os_upgrade`
/// para instalar solo esos paquetes cuando el modo pedido es
/// `"security_only"`, en vez de fiarse de un flag de apt que no cubre todas
/// las distros por igual.
#[cfg(target_os = "linux")]
pub(crate) fn list_security_package_names() -> Result<Vec<String>> {
    let output = Command::new("apt-get").args(&["-s", "dist-upgrade"]).env("LANG", "C").output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    let names = stdout
        .lines()
        .filter(|line| line.starts_with("Inst ") && is_security_pocket(line))
        .filter_map(|line| line.strip_prefix("Inst ")?.split_whitespace().next())
        .map(str::to_string)
        .collect();

    Ok(names)
}

#[cfg(target_os = "linux")]
fn check_dnf_updates() -> Result<(usize, usize, String)> {
    // Get all updates
    let output = Command::new("dnf").args(&["check-update", "-q"]).output()?;

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
    let output = Command::new("yum").args(&["check-update", "-q"]).output()?;

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
