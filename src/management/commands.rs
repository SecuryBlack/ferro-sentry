//! Handlers registrados en el intake de comandos. Hoy solo `os_upgrade`.
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

use sb_agent_core::command_intake::{CommandOutcome, CommandRegistry, ProgressSender};

/// Registra todos los handlers de FerroSentry en el intake de comandos.
/// `allow_remote_os_upgrade` viene de `Config` y se captura una vez al
/// arrancar — como el resto del proceso, se relee reiniciando el agente.
pub fn register(registry: &CommandRegistry, allow_remote_os_upgrade: bool) {
    registry.register("os_upgrade", move |payload, progress| {
        os_upgrade::handle(payload, progress, allow_remote_os_upgrade)
    });
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

    pub async fn handle(
        payload: serde_json::Value,
        progress: ProgressSender,
        allow_remote_os_upgrade: bool,
    ) -> CommandOutcome {
        if !allow_remote_os_upgrade {
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

    pub async fn handle(
        _payload: serde_json::Value,
        _progress: ProgressSender,
        _allow_remote_os_upgrade: bool,
    ) -> CommandOutcome {
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
