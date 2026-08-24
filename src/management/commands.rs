//! Handlers registrados en el intake de comandos: `os_upgrade` y
//! `set_allow_remote_os_upgrade`.
//!
//! Decisiones de producto ya cerradas (ver documento de diseño) que este
//! código respeta:
//! - Alcance: todos los tipos de actualización, no solo seguridad — el
//!   `mode` del payload deja elegir, pero `"all"` no está tratado como caso
//!   especial peligroso.
//! - Reinicio: nunca automático salvo que el llamante lo pida explícitamente
//!   en el propio comando (`allow_reboot: true`). Si no lo pide, se detecta
//!   y se informa en el resultado, no se ejecuta.
//! - Consentimiento del cliente: `allow_remote_os_upgrade` en config.toml,
//!   `false` por defecto — independiente de que la nube ofrezca el botón.
//!   Antes solo se podía cambiar a mano por SSH; `set_allow_remote_os_upgrade`
//!   deja que el propio dueño del servidor lo active/desactive desde la app,
//!   sin dejar de vivir en su config.toml (la nube nunca lo activa por su
//!   cuenta — solo reenvía lo que el dueño pide).

use sb_agent_core::command_intake::{CommandOutcome, CommandRegistry, ProgressSender};
use sb_agent_core::status::StatusHandle;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// Reconstruye el `details` del status socket a partir del estado
/// compartido. `set_details` reemplaza el JSON entero (no hace merge), así
/// que cualquier sitio que quiera tocar un campo tiene que pasar por aquí
/// para no pisar el otro.
pub fn publish_status_details(status_handle: &StatusHandle, allow_remote_os_upgrade: &AtomicBool, last_scan_unix: &AtomicU64) {
    status_handle.set_details(serde_json::json!({
        "last_scan_unix": last_scan_unix.load(Ordering::Relaxed),
        "allow_remote_os_upgrade": allow_remote_os_upgrade.load(Ordering::Relaxed),
    }));
}

/// Registra todos los handlers de FerroSentry en el intake de comandos.
/// `allow_remote_os_upgrade` es compartido (no capturado por valor una sola
/// vez): `set_allow_remote_os_upgrade` lo actualiza en caliente, sin
/// necesidad de reiniciar el proceso para que `os_upgrade` vea el cambio.
pub fn register(
    registry: &CommandRegistry,
    allow_remote_os_upgrade: Arc<AtomicBool>,
    status_handle: StatusHandle,
    last_scan_unix: Arc<AtomicU64>,
) {
    let os_upgrade_flag = allow_remote_os_upgrade.clone();
    registry.register("os_upgrade", move |payload, progress| {
        os_upgrade::handle(payload, progress, os_upgrade_flag.clone())
    });

    registry.register("set_allow_remote_os_upgrade", move |payload, _progress| {
        let flag = allow_remote_os_upgrade.clone();
        let status_handle = status_handle.clone();
        let last_scan_unix = last_scan_unix.clone();
        async move { set_config::handle_set_allow_remote_os_upgrade(payload, flag, status_handle, last_scan_unix).await }
    });

    registry.register("sync_direct_token", move |payload, _progress| async move { set_config::handle_sync_direct_token(payload).await });
}

mod set_config {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Payload {
        enabled: bool,
    }

    /// Escribe `allow_remote_os_upgrade` en `config.toml` (vía
    /// `sync_bool_field`, no a mano — eso fue justo lo que rompió el
    /// servicio en producción una vez), actualiza el flag en memoria que
    /// `os_upgrade` consulta, y republica el status socket para que la app
    /// no tenga que asumir que el comando funcionó — puede releer el estado
    /// real.
    pub async fn handle_set_allow_remote_os_upgrade(
        payload: serde_json::Value,
        flag: Arc<AtomicBool>,
        status_handle: StatusHandle,
        last_scan_unix: Arc<AtomicU64>,
    ) -> CommandOutcome {
        let request: Payload = match serde_json::from_value(payload) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed(format!("invalid payload: {e}")),
        };

        let config_path = sb_agent_core::config::default_config_path("ferro-sentry");
        if let Err(e) = sb_agent_core::config::sync_bool_field(&config_path, "allow_remote_os_upgrade", request.enabled) {
            return CommandOutcome::failed(format!("could not write config.toml: {e}"));
        }

        flag.store(request.enabled, Ordering::Relaxed);
        publish_status_details(&status_handle, &flag, &last_scan_unix);

        CommandOutcome::ok(serde_json::json!({ "allow_remote_os_upgrade": request.enabled }).to_string())
    }

    #[derive(Debug, Deserialize)]
    struct TokenPayload {
        token: String,
    }

    /// Se dispara cuando la nube regenera `servers.token` (p.ej. al reanudar
    /// una instalación desde la app): sin esto, el `token` guardado en
    /// `config.toml` se queda desincronizado con la base de datos y
    /// `DirectOutput` empieza a fallar con 401 en todas sus llamadas, en
    /// silencio (no hay reintento con backoff que lo saque a superficie, y
    /// el buffering de `tracing` puede tapar el aviso en journalctl). Llega
    /// por el túnel de comandos, que usa una autenticación distinta a
    /// `servers.token` — así que sigue funcionando aunque el token directo ya
    /// esté roto.
    ///
    /// Reinicia el servicio tras escribir el fichero en vez de intentar una
    /// actualización en caliente del cliente HTTP: `DirectOutput` ya está
    /// construido con el token viejo capturado por valor, y no vale la pena
    /// duplicar el patrón de estado compartido que usa
    /// `allow_remote_os_upgrade` solo para esto. El propio `systemctl
    /// restart` no se lanza hasta pasado un margen, igual que el reinicio de
    /// SO en `os_upgrade`, para dar tiempo a que la respuesta de este
    /// comando salga por el intake antes de que el reinicio corte la
    /// conexión.
    pub async fn handle_sync_direct_token(payload: serde_json::Value) -> CommandOutcome {
        let request: TokenPayload = match serde_json::from_value(payload) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed(format!("invalid payload: {e}")),
        };

        if request.token.trim().is_empty() {
            return CommandOutcome::failed("token must not be empty");
        }

        let config_path = sb_agent_core::config::default_config_path("ferro-sentry");
        if let Err(e) = sb_agent_core::config::sync_string_field(&config_path, "token", &request.token) {
            return CommandOutcome::failed(format!("could not write config.toml: {e}"));
        }

        schedule_restart();

        CommandOutcome::ok(serde_json::json!({ "restarting": true }).to_string())
    }

    #[cfg(target_os = "linux")]
    fn schedule_restart() {
        let _ = std::process::Command::new("sh")
            .args(["-c", "sleep 2 && systemctl restart ferro-sentry"])
            .spawn();
    }

    #[cfg(not(target_os = "linux"))]
    fn schedule_restart() {
        tracing::warn!("sync_direct_token: config.toml actualizado, pero el reinicio automático solo está implementado en Linux — reinicia el servicio a mano");
    }
}

#[cfg(target_os = "linux")]
mod os_upgrade {
    use super::*;
    use crate::modules::vuln_scanner;
    use serde::Deserialize;
    use std::process::Stdio;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;

    #[derive(Debug, Deserialize)]
    struct Payload {
        #[serde(default = "default_mode")]
        mode: String,
        #[serde(default)]
        allow_reboot: bool,
    }

    fn default_mode() -> String {
        "security_only".to_string()
    }

    pub async fn handle(payload: serde_json::Value, progress: ProgressSender, allow_remote_os_upgrade: Arc<AtomicBool>) -> CommandOutcome {
        if !allow_remote_os_upgrade.load(Ordering::Relaxed) {
            return CommandOutcome::failed(
                "os_upgrade rejected: allow_remote_os_upgrade is disabled in this agent's config.toml",
            );
        }

        let request: Payload = match serde_json::from_value(payload) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed(format!("invalid payload: {e}")),
        };

        if request.mode != "security_only" && request.mode != "all" {
            return CommandOutcome::failed(format!(
                "invalid mode '{}': expected 'security_only' or 'all'",
                request.mode
            ));
        }

        if !vuln_scanner::has_command("apt-get") {
            return CommandOutcome::failed(
                "os_upgrade only supports apt-based systems for now (dnf/yum not implemented)",
            );
        }

        send(&progress, "starting", "Resolving pending packages", 0);

        // `security_only`: instala exactamente los paquetes que la propia
        // detección identifica por pocket de seguridad, en vez de fiarse de
        // un flag de apt (no todas las distros lo soportan igual). `all`:
        // dist-upgrade completo — misma orden que usa la detección para
        // contar, así lo que se aplica coincide con lo que se reportó.
        let mut cmd = Command::new("apt-get");
        cmd.env("DEBIAN_FRONTEND", "noninteractive").env("LANG", "C");

        if request.mode == "security_only" {
            let package_names = match vuln_scanner::list_security_package_names() {
                Ok(names) => names,
                Err(e) => return CommandOutcome::failed(format!("could not list security updates: {e}")),
            };
            if package_names.is_empty() {
                return CommandOutcome::ok(
                    serde_json::json!({
                        "packages_upgraded": 0,
                        "reboot_required": false,
                        "rebooted": false,
                        "summary": "No pending security updates",
                    })
                    .to_string(),
                );
            }
            cmd.arg("install").arg("-y").args(&package_names);
        } else {
            cmd.arg("dist-upgrade").arg("-y");
        }

        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

        send(&progress, "applying", "Running apt-get", -1);

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => return CommandOutcome::failed(format!("failed to spawn apt-get: {e}")),
        };

        // Hay que drenar stdout y stderr a la vez, no uno tras otro: si
        // `apt-get` escribe suficientes avisos a stderr mientras nosotros
        // solo leemos stdout, el pipe de stderr se llena y el proceso se
        // queda bloqueado escribiendo — el comando se colgaría sin llegar
        // nunca a `child.wait()`.
        let mut stdout_lines = BufReader::new(child.stdout.take().expect("stdout is piped")).lines();
        let mut stderr_lines = BufReader::new(child.stderr.take().expect("stderr is piped")).lines();
        let mut packages_upgraded: u32 = 0;
        let mut stderr_buf = String::new();
        let mut stdout_done = false;
        let mut stderr_done = false;

        while !stdout_done || !stderr_done {
            tokio::select! {
                line = stdout_lines.next_line(), if !stdout_done => {
                    match line {
                        Ok(Some(line)) => {
                            if let Some(pkg) = line.strip_prefix("Setting up ") {
                                packages_upgraded += 1;
                                send(&progress, "applying", &format!("Configured {pkg}"), -1);
                            }
                        }
                        _ => stdout_done = true,
                    }
                }
                line = stderr_lines.next_line(), if !stderr_done => {
                    match line {
                        Ok(Some(line)) => {
                            stderr_buf.push_str(&line);
                            stderr_buf.push('\n');
                        }
                        _ => stderr_done = true,
                    }
                }
            }
        }

        let status = match child.wait().await {
            Ok(s) => s,
            Err(e) => return CommandOutcome::failed(format!("apt-get did not exit cleanly: {e}")),
        };

        if !status.success() {
            return CommandOutcome {
                success: false,
                stdout: String::new(),
                stderr: if stderr_buf.is_empty() { format!("apt-get exited with {status}") } else { stderr_buf },
                exit_code: status.code().unwrap_or(1),
            };
        }

        send(&progress, "verifying", "Checking reboot requirement", -1);
        let reboot_required_pkgs = vuln_scanner::reboot_required_packages();
        let reboot_required = !reboot_required_pkgs.is_empty();
        let mut rebooted = false;

        if reboot_required && request.allow_reboot {
            send(&progress, "rebooting", "Reboot required and requested — rebooting now", 100);
            rebooted = true;
            // Fire-and-forget con margen de 1 minuto: da tiempo a que este
            // `CommandResponse` salga por el intake antes de que el propio
            // reinicio corte la conexión. El reinicio no depende de que
            // nadie lea la respuesta.
            let _ = tokio::process::Command::new("shutdown").args(["-r", "+1"]).spawn();
        }

        CommandOutcome::ok(
            serde_json::json!({
                "packages_upgraded": packages_upgraded,
                "reboot_required": reboot_required,
                "reboot_required_packages": reboot_required_pkgs,
                "rebooted": rebooted,
            })
            .to_string(),
        )
    }
}

#[cfg(not(target_os = "linux"))]
mod os_upgrade {
    use super::*;

    pub async fn handle(_payload: serde_json::Value, _progress: ProgressSender, _allow_remote_os_upgrade: Arc<AtomicBool>) -> CommandOutcome {
        CommandOutcome::failed("os_upgrade is not implemented on this platform yet")
    }
}

#[cfg(target_os = "linux")]
fn send(tx: &ProgressSender, stage: &str, message: &str, percent: i32) {
    let _ = tx.send(sb_agent_core::command_intake::CommandProgress {
        // El core (`CommandRegistry::dispatch`) sella el `command_id` real
        // antes de reenviar — el handler no lo conoce y no debería tener
        // que pasarlo por aquí.
        command_id: String::new(),
        stage: stage.to_string(),
        message: message.to_string(),
        percent,
    });
}
