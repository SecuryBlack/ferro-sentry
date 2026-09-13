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
pub fn publish_status_details(
    status_handle: &StatusHandle,
    allow_remote_os_upgrade: &AtomicBool,
    last_scan_unix: &AtomicU64,
) {
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
        async move {
            set_config::handle_set_allow_remote_os_upgrade(
                payload,
                flag,
                status_handle,
                last_scan_unix,
            )
            .await
        }
    });

    registry.register("sync_direct_token", move |payload, _progress| async move {
        set_config::handle_sync_direct_token(payload).await
    });

    registry.register("update_now", move |_payload, _progress| async move {
        update_now::handle().await
    });

    registry.register("firewall_get_status", move |_payload, _progress| async move {
        firewall::handle_get_status().await
    });

    registry.register("firewall_toggle", move |payload, _progress| async move {
        firewall::handle_toggle(payload).await
    });

    registry.register("firewall_add_rule", move |payload, _progress| async move {
        firewall::handle_add_rule(payload).await
    });

    registry.register("firewall_delete_rule", move |payload, _progress| async move {
        firewall::handle_delete_rule(payload).await
    });

    registry.register("firewall_install_ufw", move |_payload, _progress| async move {
        firewall::handle_install_ufw().await
    });
}

mod update_now {
    use super::*;

    /// Dispara `sb_agent_core::updater::check_now` de inmediato en vez de
    /// esperar al chequeo diario — para el botón "Actualizar" de la app.
    /// Misma política de reinicio que el loop de fondo: si hay actualización,
    /// el binario ya quedó reemplazado en disco por `self_update`, así que
    /// hay que salir para que el gestor de servicios (systemd/SCM,
    /// `Restart=always`) relance el proceso con el nuevo binario — el exit se
    /// retrasa un momento para que esta misma respuesta salga por el intake
    /// antes de que el reinicio corte la conexión.
    pub async fn handle() -> CommandOutcome {
        let cfg = sb_agent_core::updater::UpdaterConfig::new(
            "securyblack",
            "ferro-sentry",
            "ferro-sentry",
            env!("CARGO_PKG_VERSION"),
        );

        let result =
            tokio::task::spawn_blocking(move || sb_agent_core::updater::check_now(&cfg)).await;

        match result {
            Ok(Ok(true)) => {
                std::thread::spawn(|| {
                    std::thread::sleep(std::time::Duration::from_secs(2));
                    std::process::exit(0);
                });
                CommandOutcome::ok(serde_json::json!({ "updated": true, "previous_version": env!("CARGO_PKG_VERSION") }).to_string())
            }
            Ok(Ok(false)) => CommandOutcome::ok(
                serde_json::json!({ "updated": false, "current_version": env!("CARGO_PKG_VERSION") }).to_string(),
            ),
            Ok(Err(e)) => CommandOutcome::failed(format!("update check failed: {e}")),
            Err(e) => CommandOutcome::failed(format!("update task panicked: {e}")),
        }
    }
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
        if let Err(e) = sb_agent_core::config::sync_bool_field(
            &config_path,
            "allow_remote_os_upgrade",
            request.enabled,
        ) {
            return CommandOutcome::failed(format!("could not write config.toml: {e}"));
        }

        flag.store(request.enabled, Ordering::Relaxed);
        publish_status_details(&status_handle, &flag, &last_scan_unix);

        CommandOutcome::ok(
            serde_json::json!({ "allow_remote_os_upgrade": request.enabled }).to_string(),
        )
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
        if let Err(e) =
            sb_agent_core::config::sync_string_field(&config_path, "token", &request.token)
        {
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

    pub async fn handle(
        payload: serde_json::Value,
        progress: ProgressSender,
        allow_remote_os_upgrade: Arc<AtomicBool>,
    ) -> CommandOutcome {
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
        cmd.env("DEBIAN_FRONTEND", "noninteractive")
            .env("LANG", "C");

        if request.mode == "security_only" {
            let package_names = match vuln_scanner::list_security_package_names() {
                Ok(names) => names,
                Err(e) => {
                    return CommandOutcome::failed(format!("could not list security updates: {e}"))
                }
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
        let mut stdout_lines =
            BufReader::new(child.stdout.take().expect("stdout is piped")).lines();
        let mut stderr_lines =
            BufReader::new(child.stderr.take().expect("stderr is piped")).lines();
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
                stderr: if stderr_buf.is_empty() {
                    format!("apt-get exited with {status}")
                } else {
                    stderr_buf
                },
                exit_code: status.code().unwrap_or(1),
            };
        }

        send(&progress, "verifying", "Checking reboot requirement", -1);
        let reboot_required_pkgs = vuln_scanner::reboot_required_packages();
        let reboot_required = !reboot_required_pkgs.is_empty();
        let mut rebooted = false;

        if reboot_required && request.allow_reboot {
            send(
                &progress,
                "rebooting",
                "Reboot required and requested — rebooting now",
                100,
            );
            rebooted = true;
            // Fire-and-forget con margen de 1 minuto: da tiempo a que este
            // `CommandResponse` salga por el intake antes de que el propio
            // reinicio corte la conexión. El reinicio no depende de que
            // nadie lea la respuesta.
            let _ = tokio::process::Command::new("shutdown")
                .args(["-r", "+1"])
                .spawn();
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
        _allow_remote_os_upgrade: Arc<AtomicBool>,
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

mod firewall {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[allow(dead_code)]
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct UfwRule {
        pub index: u32,
        pub to: String,
        pub action: String,
        pub from: String,
        pub comment: Option<String>,
    }

    #[allow(dead_code)]
    #[derive(Debug, Serialize, Deserialize)]
    pub struct FirewallStatus {
        pub supported: bool,
        pub firewall_type: String,
        pub installed: bool,
        pub active: bool,
        pub default_incoming: String,
        pub default_outgoing: String,
        pub rules: Vec<UfwRule>,
        pub ssh_port: u16,
        pub ssh_protected: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub message: Option<String>,
    }

    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    struct TogglePayload {
        enabled: bool,
    }

    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    struct AddRulePayload {
        port: String,
        proto: Option<String>,
        action: String,
        from: Option<String>,
        comment: Option<String>,
    }

    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    struct DeleteRulePayload {
        rule_number: u32,
    }

    #[cfg(target_os = "linux")]
    pub async fn handle_get_status() -> CommandOutcome {
        tokio::task::spawn_blocking(get_status_linux)
            .await
            .unwrap_or_else(|e| CommandOutcome::failed(format!("task panicked: {e}")))
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn handle_get_status() -> CommandOutcome {
        CommandOutcome::ok(
            serde_json::json!({
                "supported": false,
                "firewall_type": "none",
                "installed": false,
                "active": false,
                "default_incoming": "deny",
                "default_outgoing": "allow",
                "rules": [],
                "ssh_port": 22,
                "ssh_protected": true,
                "message": "Firewall management is currently only supported on Linux (UFW)"
            })
            .to_string(),
        )
    }

    #[cfg(target_os = "linux")]
    pub async fn handle_toggle(payload: serde_json::Value) -> CommandOutcome {
        tokio::task::spawn_blocking(move || toggle_linux(payload))
            .await
            .unwrap_or_else(|e| CommandOutcome::failed(format!("task panicked: {e}")))
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn handle_toggle(_payload: serde_json::Value) -> CommandOutcome {
        CommandOutcome::failed(
            "Firewall management is currently only supported on Linux (UFW)".to_string(),
        )
    }

    #[cfg(target_os = "linux")]
    pub async fn handle_add_rule(payload: serde_json::Value) -> CommandOutcome {
        tokio::task::spawn_blocking(move || add_rule_linux(payload))
            .await
            .unwrap_or_else(|e| CommandOutcome::failed(format!("task panicked: {e}")))
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn handle_add_rule(_payload: serde_json::Value) -> CommandOutcome {
        CommandOutcome::failed(
            "Firewall management is currently only supported on Linux (UFW)".to_string(),
        )
    }

    #[cfg(target_os = "linux")]
    pub async fn handle_delete_rule(payload: serde_json::Value) -> CommandOutcome {
        tokio::task::spawn_blocking(move || delete_rule_linux(payload))
            .await
            .unwrap_or_else(|e| CommandOutcome::failed(format!("task panicked: {e}")))
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn handle_delete_rule(_payload: serde_json::Value) -> CommandOutcome {
        CommandOutcome::failed(
            "Firewall management is currently only supported on Linux (UFW)".to_string(),
        )
    }

    #[cfg(target_os = "linux")]
    pub async fn handle_install_ufw() -> CommandOutcome {
        tokio::task::spawn_blocking(install_ufw_linux)
            .await
            .unwrap_or_else(|e| CommandOutcome::failed(format!("task panicked: {e}")))
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn handle_install_ufw() -> CommandOutcome {
        CommandOutcome::failed(
            "UFW installation is only supported on Linux".to_string(),
        )
    }

    #[cfg(target_os = "linux")]
    fn get_status_linux() -> CommandOutcome {
        use std::process::Command;

        let which_ufw = Command::new("which").arg("ufw").output();
        let has_ufw = which_ufw.map(|o| o.status.success()).unwrap_or(false);
        if !has_ufw {
            return CommandOutcome::ok(
                serde_json::json!({
                    "supported": true,
                    "firewall_type": "ufw",
                    "installed": false,
                    "active": false,
                    "default_incoming": "deny",
                    "default_outgoing": "allow",
                    "rules": [],
                    "ssh_port": crate::modules::ssh_auditor::detect_ssh_port(),
                    "ssh_protected": false,
                    "message": "UFW is not installed on this host"
                })
                .to_string(),
            );
        }

        let verbose_output = Command::new("ufw").args(["status", "verbose"]).output();
        let verbose_str = match verbose_output {
            Ok(ref o) => String::from_utf8_lossy(&o.stdout).to_string(),
            Err(e) => return CommandOutcome::failed(format!("failed to run ufw status: {e}")),
        };

        let active = verbose_str.contains("Status: active");

        let mut default_incoming = "deny".to_string();
        let mut default_outgoing = "allow".to_string();

        for line in verbose_str.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Default:") {
                if trimmed.contains("allow (incoming)") {
                    default_incoming = "allow".to_string();
                } else if trimmed.contains("reject (incoming)") {
                    default_incoming = "reject".to_string();
                }
                if trimmed.contains("deny (outgoing)") {
                    default_outgoing = "deny".to_string();
                } else if trimmed.contains("reject (outgoing)") {
                    default_outgoing = "reject".to_string();
                }
            }
        }

        let mut rules = Vec::new();
        if active {
            if let Ok(numbered_output) = Command::new("ufw").args(["status", "numbered"]).output() {
                let num_str = String::from_utf8_lossy(&numbered_output.stdout);
                rules = parse_ufw_numbered(&num_str);
            }
        }

        let ssh_port = crate::modules::ssh_auditor::detect_ssh_port();
        let ssh_port_str = ssh_port.to_string();
        let ssh_protected = rules.iter().any(|r| {
            let act = r.action.to_uppercase();
            if !act.starts_with("ALLOW") && !act.starts_with("LIMIT") {
                return false;
            }
            let to_lower = r.to.to_lowercase();
            to_lower.starts_with(&ssh_port_str)
                || to_lower.starts_with("22/tcp")
                || to_lower == "22"
                || to_lower == "ssh"
                || to_lower == "openssh"
        });

        let status = FirewallStatus {
            supported: true,
            firewall_type: "ufw".to_string(),
            installed: true,
            active,
            default_incoming,
            default_outgoing,
            rules,
            ssh_port,
            ssh_protected,
            message: None,
        };

        CommandOutcome::ok(serde_json::to_string(&status).unwrap_or_default())
    }

    #[cfg(target_os = "linux")]
    fn parse_ufw_numbered(output: &str) -> Vec<UfwRule> {
        let mut rules = Vec::new();
        for line in output.lines() {
            let trimmed = line.trim();
            if !trimmed.starts_with('[') {
                continue;
            }
            let Some(close_bracket) = trimmed.find(']') else {
                continue;
            };
            let num_part = trimmed[1..close_bracket].trim();
            let Ok(index) = num_part.parse::<u32>() else {
                continue;
            };
            let rest = trimmed[close_bracket + 1..].trim();

            let (rule_body, comment) = if let Some(hash_pos) = rest.find('#') {
                let c = rest[hash_pos + 1..].trim().to_string();
                (&rest[..hash_pos], Some(c))
            } else {
                (rest, None)
            };

            let parts: Vec<&str> = rule_body.split_whitespace().collect();
            if parts.len() < 3 {
                continue;
            }

            let action_pos = parts.iter().position(|p| {
                let u = p.to_uppercase();
                u == "ALLOW" || u == "DENY" || u == "REJECT" || u == "LIMIT"
            });

            if let Some(idx) = action_pos {
                let to = parts[0..idx].join(" ");
                let (action, from_start) = if parts.get(idx + 1).is_some_and(|p| {
                    let u = p.to_uppercase();
                    u == "IN" || u == "OUT" || u == "FWD"
                }) {
                    (format!("{} {}", parts[idx], parts[idx + 1]), idx + 2)
                } else {
                    (parts[idx].to_string(), idx + 1)
                };
                let from = parts[from_start..].join(" ");

                rules.push(UfwRule {
                    index,
                    to,
                    action,
                    from,
                    comment,
                });
            }
        }
        rules
    }

    #[cfg(target_os = "linux")]
    fn toggle_linux(payload: serde_json::Value) -> CommandOutcome {
        use std::process::Command;
        let req: TogglePayload = match serde_json::from_value(payload) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed(format!("invalid payload: {e}")),
        };

        if req.enabled {
            let ssh_port = crate::modules::ssh_auditor::detect_ssh_port();
            let ssh_port_str = ssh_port.to_string();

            let mut ssh_allowed = false;
            if let Ok(output) = Command::new("ufw").args(["status", "numbered"]).output() {
                let num_str = String::from_utf8_lossy(&output.stdout);
                let rules = parse_ufw_numbered(&num_str);
                ssh_allowed = rules.iter().any(|r| {
                    let act = r.action.to_uppercase();
                    if !act.starts_with("ALLOW") && !act.starts_with("LIMIT") {
                        return false;
                    }
                    let to_lower = r.to.to_lowercase();
                    to_lower.starts_with(&ssh_port_str)
                        || to_lower.starts_with("22/tcp")
                        || to_lower == "22"
                        || to_lower == "ssh"
                        || to_lower == "openssh"
                });
            }

            let mut ssh_rule_added = false;
            if !ssh_allowed {
                let _ = Command::new("ufw")
                    .args(["allow", &format!("{ssh_port}/tcp"), "comment", "SecuryBlack Anti-Lockout"])
                    .output();
                ssh_rule_added = true;
            }

            let enable_res = Command::new("ufw").args(["--force", "enable"]).output();
            match enable_res {
                Ok(o) if o.status.success() => {
                    CommandOutcome::ok(serde_json::json!({
                        "active": true,
                        "ssh_rule_added": ssh_rule_added,
                        "ssh_port": ssh_port
                    }).to_string())
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    CommandOutcome::failed(format!("ufw enable failed: {stderr}"))
                }
                Err(e) => CommandOutcome::failed(format!("failed to execute ufw: {e}")),
            }
        } else {
            let disable_res = Command::new("ufw").arg("disable").output();
            match disable_res {
                Ok(o) if o.status.success() => {
                    CommandOutcome::ok(serde_json::json!({ "active": false }).to_string())
                }
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    CommandOutcome::failed(format!("ufw disable failed: {stderr}"))
                }
                Err(e) => CommandOutcome::failed(format!("failed to execute ufw: {e}")),
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn add_rule_linux(payload: serde_json::Value) -> CommandOutcome {
        use std::process::Command;
        let req: AddRulePayload = match serde_json::from_value(payload) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed(format!("invalid payload: {e}")),
        };

        let port = req.port.trim();
        if port.is_empty() || !port.chars().all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '-') {
            return CommandOutcome::failed("invalid port specification".to_string());
        }

        let action = match req.action.to_lowercase().as_str() {
            "allow" => "allow",
            "deny" => "deny",
            "reject" => "reject",
            "limit" => "limit",
            _ => return CommandOutcome::failed("invalid action, must be allow, deny, reject, or limit".to_string()),
        };

        let proto = req.proto.as_deref().map(|p| p.to_lowercase());
        if let Some(ref p) = proto {
            if p != "tcp" && p != "udp" {
                return CommandOutcome::failed("invalid proto, must be tcp or udp".to_string());
            }
        }

        let mut args = vec![action.to_string()];

        if let Some(from) = req.from.as_deref().map(|f| f.trim()).filter(|f| !f.is_empty() && *f != "any" && *f != "Anywhere") {
            if !from.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == ':' || c == '/') {
                return CommandOutcome::failed("invalid from address".to_string());
            }
            args.push("from".to_string());
            args.push(from.to_string());
            args.push("to".to_string());
            args.push("any".to_string());
            args.push("port".to_string());
            args.push(port.to_string());
            if let Some(ref p) = proto {
                args.push("proto".to_string());
                args.push(p.clone());
            }
        } else {
            let port_spec = if let Some(ref p) = proto {
                format!("{port}/{p}")
            } else {
                port.to_string()
            };
            args.push(port_spec);
        }

        if let Some(comment) = req.comment.as_deref().map(|c| c.trim()).filter(|c| !c.is_empty()) {
            let clean_comment: String = comment.chars().filter(|c| c.is_ascii_alphanumeric() || c.is_whitespace() || *c == '-' || *c == '_').take(60).collect();
            if !clean_comment.is_empty() {
                args.push("comment".to_string());
                args.push(clean_comment);
            }
        }

        let res = Command::new("ufw").args(&args).output();
        match res {
            Ok(o) if o.status.success() => {
                CommandOutcome::ok(serde_json::json!({ "success": true, "args": args }).to_string())
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                let stdout = String::from_utf8_lossy(&o.stdout);
                CommandOutcome::failed(format!("ufw command failed: {stderr} {stdout}"))
            }
            Err(e) => CommandOutcome::failed(format!("failed to execute ufw: {e}")),
        }
    }

    #[cfg(target_os = "linux")]
    fn delete_rule_linux(payload: serde_json::Value) -> CommandOutcome {
        use std::process::Command;
        let req: DeleteRulePayload = match serde_json::from_value(payload) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed(format!("invalid payload: {e}")),
        };

        if req.rule_number == 0 {
            return CommandOutcome::failed("rule_number must be greater than 0".to_string());
        }

        let res = Command::new("ufw")
            .args(["--force", "delete", &req.rule_number.to_string()])
            .output();

        match res {
            Ok(o) if o.status.success() => {
                CommandOutcome::ok(serde_json::json!({ "success": true, "deleted_rule": req.rule_number }).to_string())
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                let stdout = String::from_utf8_lossy(&o.stdout);
                CommandOutcome::failed(format!("ufw delete failed: {stderr} {stdout}"))
            }
            Err(e) => CommandOutcome::failed(format!("failed to execute ufw: {e}")),
        }
    }

    #[cfg(target_os = "linux")]
    fn install_ufw_linux() -> CommandOutcome {
        use std::process::Command;

        let check_cmd = |name: &str| -> bool {
            Command::new("which")
                .arg(name)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };

        if check_cmd("ufw") {
            return CommandOutcome::ok(
                serde_json::json!({ "success": true, "message": "UFW is already installed" }).to_string(),
            );
        }

        let res = if check_cmd("apt-get") {
            Command::new("apt-get")
                .env("DEBIAN_FRONTEND", "noninteractive")
                .env("LANG", "C")
                .args(["install", "-y", "ufw"])
                .output()
        } else if check_cmd("dnf") {
            Command::new("dnf").args(["install", "-y", "ufw"]).output()
        } else if check_cmd("yum") {
            Command::new("yum").args(["install", "-y", "ufw"]).output()
        } else if check_cmd("pacman") {
            Command::new("pacman").args(["-Sy", "--noconfirm", "ufw"]).output()
        } else if check_cmd("zypper") {
            Command::new("zypper").args(["--non-interactive", "install", "ufw"]).output()
        } else if check_cmd("apk") {
            Command::new("apk").args(["add", "ufw"]).output()
        } else {
            return CommandOutcome::failed(
                "No supported package manager found to install UFW (apt-get, dnf, yum, pacman, zypper, apk)".to_string(),
            );
        };

        match res {
            Ok(o) if o.status.success() => {
                if check_cmd("ufw") {
                    CommandOutcome::ok(
                        serde_json::json!({
                            "success": true,
                            "message": "UFW installed successfully"
                        })
                        .to_string(),
                    )
                } else {
                    CommandOutcome::failed(
                        "Installation command succeeded but 'ufw' binary was not found in PATH".to_string(),
                    )
                }
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                let stdout = String::from_utf8_lossy(&o.stdout);
                CommandOutcome::failed(format!("Failed to install UFW: {stderr} {stdout}"))
            }
            Err(e) => CommandOutcome::failed(format!("Failed to execute installer: {e}")),
        }
    }
}
