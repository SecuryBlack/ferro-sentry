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

    registry.register("ssh_hardening", move |payload, _progress| async move {
        ssh_hardening::handle(payload).await
    });

    registry.register("configure_unattended_upgrades", move |_payload, _progress| async move {
        auto_upgrades::handle().await
    });

    registry.register("install_fail2ban", move |_payload, _progress| async move {
        intrusion_prevention::handle().await
    });

    registry.register("fail2ban_get_status", move |_payload, _progress| async move {
        fail2ban::handle_get_status().await
    });

    registry.register("fail2ban_toggle", move |payload, _progress| async move {
        fail2ban::handle_toggle(payload).await
    });

    registry.register("fail2ban_unban_ip", move |payload, _progress| async move {
        fail2ban::handle_unban_ip(payload).await
    });

    registry.register("fail2ban_ban_ip", move |payload, _progress| async move {
        fail2ban::handle_ban_ip(payload).await
    });

    registry.register("fail2ban_set_whitelist", move |payload, _progress| async move {
        fail2ban::handle_set_whitelist(payload).await
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

mod ssh_hardening {
    use super::*;

    #[derive(serde::Deserialize, Default)]
    #[allow(dead_code)]
    pub struct SshHardeningPayload {
        #[serde(default = "default_true")]
        pub disable_password_auth: bool,
        #[serde(default = "default_true")]
        pub disable_root_login: bool,
        #[serde(default = "default_true")]
        pub disable_x11_forwarding: bool,
        #[serde(default = "default_max_auth_tries")]
        pub max_auth_tries: u32,
    }

    fn default_true() -> bool {
        true
    }

    fn default_max_auth_tries() -> u32 {
        3
    }

    pub async fn handle(payload: serde_json::Value) -> CommandOutcome {
        tokio::task::spawn_blocking(move || {
            let opts: SshHardeningPayload = serde_json::from_value(payload).unwrap_or_default();
            apply_ssh_hardening(opts)
        })
        .await
        .unwrap_or_else(|e| CommandOutcome::failed(format!("Task panicked: {e}")))
    }

    #[cfg(target_os = "linux")]
    fn apply_ssh_hardening(opts: SshHardeningPayload) -> CommandOutcome {
        use std::fs;
        use std::path::Path;
        use std::process::Command;

        // Anti-lockout check: if disable_password_auth is requested, check if any authorized_keys exist
        if opts.disable_password_auth && !has_authorized_keys() {
            return CommandOutcome::failed(
                "Anti-lockout abort: No authorized SSH public keys found on this server. Configure an SSH key before disabling password authentication.".to_string(),
            );
        }

        // Locate sshd binary to test syntax
        let sshd_bin = match find_sshd_binary() {
            Some(bin) => bin,
            None => return CommandOutcome::failed("sshd binary not found to validate configuration".to_string()),
        };

        let mut directives = Vec::new();
        if opts.disable_password_auth {
            directives.push("PasswordAuthentication no".to_string());
            directives.push("KbdInteractiveAuthentication no".to_string());
            directives.push("ChallengeResponseAuthentication no".to_string());
        }
        if opts.disable_root_login {
            directives.push("PermitRootLogin prohibit-password".to_string());
        }
        if opts.disable_x11_forwarding {
            directives.push("X11Forwarding no".to_string());
        }
        let max_tries = opts.max_auth_tries.clamp(1, 6);
        directives.push(format!("MaxAuthTries {max_tries}"));

        let content_to_apply = format!(
            "# SecuryBlack SSH Hardening - Generated automatically\n{}\n",
            directives.join("\n")
        );

        let sshd_config_d = Path::new("/etc/ssh/sshd_config.d");
        let dropin_file = sshd_config_d.join("99-securyblack-hardening.conf");
        let main_config = Path::new("/etc/ssh/sshd_config");
        let main_backup = Path::new("/etc/ssh/sshd_config.sb-bak");

        // Backup main config if it exists
        if main_config.exists() {
            if let Err(e) = fs::copy(main_config, main_backup) {
                return CommandOutcome::failed(format!("Failed to backup /etc/ssh/sshd_config: {e}"));
            }
        }

        let keys_to_override = [
            "passwordauthentication",
            "kbdinteractiveauthentication",
            "challengeresponseauthentication",
            "permitrootlogin",
            "x11forwarding",
            "maxauthtries",
        ];

        let used_dropin = sshd_config_d.is_dir();

        if main_config.exists() {
            // Comment out conflicting directives in main sshd_config so drop-in or appended settings win
            if let Ok(content) = fs::read_to_string(main_config) {
                let mut modified_lines = Vec::new();
                let mut has_include = false;
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.starts_with("Include ") && trimmed.contains("sshd_config.d") {
                        has_include = true;
                    }
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        let parts: Vec<&str> = trimmed.split_whitespace().collect();
                        if !parts.is_empty() && keys_to_override.contains(&parts[0].to_lowercase().as_str()) {
                            modified_lines.push(format!("# [SecuryBlack hardened] {line}"));
                            continue;
                        }
                    }
                    modified_lines.push(line.to_string());
                }

                if used_dropin && !has_include {
                    modified_lines.insert(0, "Include /etc/ssh/sshd_config.d/*.conf".to_string());
                } else if !used_dropin {
                    modified_lines.push(String::new());
                    modified_lines.push(content_to_apply.clone());
                }

                let new_main_content = modified_lines.join("\n") + "\n";
                if let Err(e) = fs::write(main_config, new_main_content) {
                    if main_backup.exists() {
                        let _ = fs::copy(main_backup, main_config);
                    }
                    return CommandOutcome::failed(format!("Failed to write /etc/ssh/sshd_config: {e}"));
                }
            }
        }

        if used_dropin {
            if let Err(e) = fs::write(&dropin_file, &content_to_apply) {
                if main_backup.exists() {
                    let _ = fs::copy(main_backup, main_config);
                }
                return CommandOutcome::failed(format!("Failed to write drop-in configuration: {e}"));
            }
        }

        // Validate syntax with sshd -t
        let test_res = Command::new(&sshd_bin).arg("-t").output();
        let valid = match test_res {
            Ok(ref out) => out.status.success(),
            Err(_) => false,
        };

        if !valid {
            // Rollback immediately
            if used_dropin {
                let _ = fs::remove_file(&dropin_file);
            }
            if main_backup.exists() {
                let _ = fs::copy(main_backup, main_config);
            }
            let err_msg = test_res
                .map(|o| {
                    format!(
                        "{} {}",
                        String::from_utf8_lossy(&o.stderr),
                        String::from_utf8_lossy(&o.stdout)
                    )
                })
                .unwrap_or_else(|e| e.to_string());
            return CommandOutcome::failed(format!(
                "SSH configuration test (sshd -t) failed, rolled back changes: {err_msg}"
            ));
        }

        // Clean up backup file upon success
        if main_backup.exists() {
            let _ = fs::remove_file(main_backup);
        }

        // Reload ssh daemon cleanly without dropping active connections
        let reload_res = Command::new("systemctl")
            .args(["reload", "ssh"])
            .output()
            .or_else(|_| Command::new("systemctl").args(["reload", "sshd"]).output())
            .or_else(|_| Command::new("service").args(["ssh", "reload"]).output())
            .or_else(|_| Command::new("service").args(["sshd", "reload"]).output());

        match reload_res {
            Ok(o) if o.status.success() => CommandOutcome::ok(
                serde_json::json!({
                    "success": true,
                    "message": "SSH configuration hardened and sshd reloaded successfully",
                    "directives": directives,
                })
                .to_string(),
            ),
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                let stdout = String::from_utf8_lossy(&o.stdout);
                CommandOutcome::failed(format!("SSH config validated but service reload failed: {stderr} {stdout}"))
            }
            Err(e) => CommandOutcome::failed(format!("Failed to reload SSH service: {e}")),
        }
    }

    #[cfg(target_os = "linux")]
    fn find_sshd_binary() -> Option<String> {
        use std::path::Path;
        use std::process::Command;

        if Command::new("sshd").arg("-V").output().is_ok() {
            return Some("sshd".to_string());
        }
        for path in ["/usr/sbin/sshd", "/sbin/sshd", "/usr/bin/sshd"] {
            if Path::new(path).exists() {
                return Some(path.to_string());
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn has_authorized_keys() -> bool {
        use std::fs;
        use std::path::Path;

        let check_key_file = |path: &Path| -> bool {
            if let Ok(content) = fs::read_to_string(path) {
                for line in content.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }
                    if trimmed.len() >= 20
                        && (trimmed.contains("ssh-rsa")
                            || trimmed.contains("ssh-ed25519")
                            || trimmed.contains("ecdsa-sha2-nistp")
                            || trimmed.contains("sk-ssh-ed25519")
                            || trimmed.contains("sk-ecdsa-sha2-nistp"))
                    {
                        return true;
                    }
                }
            }
            false
        };

        // 1. Root authorized_keys
        if check_key_file(Path::new("/root/.ssh/authorized_keys")) {
            return true;
        }

        // 2. Scan /home/*/.ssh/authorized_keys
        if let Ok(entries) = fs::read_dir("/home") {
            for entry in entries.flatten() {
                let key_path = entry.path().join(".ssh").join("authorized_keys");
                if check_key_file(&key_path) {
                    return true;
                }
            }
        }

        false
    }

    #[cfg(not(target_os = "linux"))]
    fn apply_ssh_hardening(_opts: SshHardeningPayload) -> CommandOutcome {
        CommandOutcome::failed("SSH hardening remediation is only supported on Linux hosts".to_string())
    }
}

mod auto_upgrades {
    use super::*;

    pub async fn handle() -> CommandOutcome {
        tokio::task::spawn_blocking(configure_auto_upgrades)
            .await
            .unwrap_or_else(|e| CommandOutcome::failed(format!("Task panicked: {e}")))
    }

    #[cfg(target_os = "linux")]
    fn configure_auto_upgrades() -> CommandOutcome {
        use std::fs;
        use std::path::Path;
        use std::process::Command;

        let check_cmd = |name: &str| -> bool {
            Command::new("which")
                .arg(name)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };

        if check_cmd("apt-get") {
            // 1. Install unattended-upgrades if needed
            if !check_cmd("unattended-upgrade") {
                let install_res = Command::new("apt-get")
                    .env("DEBIAN_FRONTEND", "noninteractive")
                    .env("LANG", "C")
                    .args(["install", "-y", "unattended-upgrades"])
                    .output();
                match install_res {
                    Ok(o) if o.status.success() => {}
                    Ok(o) => {
                        let stderr = String::from_utf8_lossy(&o.stderr);
                        return CommandOutcome::failed(format!("Failed to install unattended-upgrades: {stderr}"));
                    }
                    Err(e) => return CommandOutcome::failed(format!("Failed to run apt-get install: {e}")),
                }
            }

            // 2. Write /etc/apt/apt.conf.d/20auto-upgrades
            let conf_dir = Path::new("/etc/apt/apt.conf.d");
            if !conf_dir.exists() {
                let _ = fs::create_dir_all(conf_dir);
            }
            let auto_conf = "APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n";
            if let Err(e) = fs::write("/etc/apt/apt.conf.d/20auto-upgrades", auto_conf) {
                return CommandOutcome::failed(format!("Failed to write /etc/apt/apt.conf.d/20auto-upgrades: {e}"));
            }

            // 3. Enable and start systemd service/timers
            let _ = Command::new("systemctl")
                .args(["enable", "--now", "unattended-upgrades"])
                .output();
            let _ = Command::new("systemctl")
                .args(["enable", "--now", "apt-daily.timer", "apt-daily-upgrade.timer"])
                .output();

            CommandOutcome::ok(
                serde_json::json!({
                    "success": true,
                    "message": "Unattended security upgrades successfully configured and enabled (Debian/Ubuntu)"
                })
                .to_string(),
            )
        } else if check_cmd("dnf") {
            let install_res = Command::new("dnf")
                .args(["install", "-y", "dnf-automatic"])
                .output();
            if let Ok(o) = install_res {
                if o.status.success() {
                    let _ = Command::new("systemctl")
                        .args(["enable", "--now", "dnf-automatic.timer"])
                        .output();
                    return CommandOutcome::ok(
                        serde_json::json!({
                            "success": true,
                            "message": "Automatic security updates configured via dnf-automatic (RHEL/Fedora)"
                        })
                        .to_string(),
                    );
                }
            }
            CommandOutcome::failed("Failed to configure automatic updates via dnf".to_string())
        } else if check_cmd("yum") {
            let install_res = Command::new("yum")
                .args(["install", "-y", "yum-cron"])
                .output();
            if let Ok(o) = install_res {
                if o.status.success() {
                    let _ = Command::new("systemctl")
                        .args(["enable", "--now", "yum-cron"])
                        .output();
                    return CommandOutcome::ok(
                        serde_json::json!({
                            "success": true,
                            "message": "Automatic security updates configured via yum-cron (CentOS/RHEL)"
                        })
                        .to_string(),
                    );
                }
            }
            CommandOutcome::failed("Failed to configure automatic updates via yum".to_string())
        } else {
            CommandOutcome::failed(
                "No supported package manager found for unattended upgrades (apt-get, dnf, yum)".to_string(),
            )
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn configure_auto_upgrades() -> CommandOutcome {
        CommandOutcome::failed("Unattended upgrades remediation is only supported on Linux hosts".to_string())
    }
}

mod intrusion_prevention {
    use super::*;

    pub async fn handle() -> CommandOutcome {
        tokio::task::spawn_blocking(install_and_configure_fail2ban)
            .await
            .unwrap_or_else(|e| CommandOutcome::failed(format!("Task panicked: {e}")))
    }

    #[cfg(target_os = "linux")]
    fn install_and_configure_fail2ban() -> CommandOutcome {
        use std::fs;
        use std::path::Path;
        use std::process::Command;

        let check_cmd = |name: &str| -> bool {
            Command::new("which")
                .arg(name)
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        };

        // 1. Install fail2ban if not present
        if !check_cmd("fail2ban-client") && !check_cmd("fail2ban-server") {
            let res = if check_cmd("apt-get") {
                Command::new("apt-get")
                    .env("DEBIAN_FRONTEND", "noninteractive")
                    .env("LANG", "C")
                    .args(["install", "-y", "fail2ban"])
                    .output()
            } else if check_cmd("dnf") {
                Command::new("dnf").args(["install", "-y", "fail2ban"]).output()
            } else if check_cmd("yum") {
                Command::new("yum").args(["install", "-y", "epel-release", "fail2ban"]).output()
            } else if check_cmd("pacman") {
                Command::new("pacman").args(["-Sy", "--noconfirm", "fail2ban"]).output()
            } else if check_cmd("zypper") {
                Command::new("zypper").args(["--non-interactive", "install", "fail2ban"]).output()
            } else if check_cmd("apk") {
                Command::new("apk").args(["add", "fail2ban"]).output()
            } else {
                return CommandOutcome::failed(
                    "No supported package manager found to install fail2ban (apt-get, dnf, yum, pacman, zypper, apk)".to_string(),
                );
            };

            match res {
                Ok(o) if o.status.success() => {}
                Ok(o) => {
                    let stderr = String::from_utf8_lossy(&o.stderr);
                    let stdout = String::from_utf8_lossy(&o.stdout);
                    return CommandOutcome::failed(format!("Failed to install fail2ban: {stderr} {stdout}"));
                }
                Err(e) => return CommandOutcome::failed(format!("Failed to execute installer for fail2ban: {e}")),
            }
        }

        // 2. Configure /etc/fail2ban/jail.local with the active SSH port
        let ssh_port = crate::modules::ssh_auditor::detect_ssh_port();
        let jail_local = Path::new("/etc/fail2ban/jail.local");

        let jail_content = if jail_local.exists() {
            let mut existing = fs::read_to_string(jail_local).unwrap_or_default();
            if !existing.contains("[sshd]") {
                existing.push_str(&format!(
                    "\n[sshd]\nenabled = true\nport = {ssh_port}\nmaxretry = 5\nbantime = 1h\nfindtime = 10m\n"
                ));
            }
            existing
        } else {
            format!(
                "[DEFAULT]\nbantime = 1h\nfindtime = 10m\nmaxretry = 5\n\n[sshd]\nenabled = true\nport = {ssh_port}\n"
            )
        };

        if Path::new("/etc/fail2ban").is_dir() {
            let _ = fs::write(jail_local, jail_content);
        }

        // 3. Enable and start fail2ban service
        let enable_res = Command::new("systemctl")
            .args(["enable", "--now", "fail2ban"])
            .output()
            .or_else(|_| Command::new("service").args(["fail2ban", "restart"]).output());

        match enable_res {
            Ok(o) if o.status.success() => {
                CommandOutcome::ok(
                    serde_json::json!({
                        "success": true,
                        "message": format!("fail2ban installed and active, protecting SSH on port {ssh_port}"),
                        "ssh_port": ssh_port,
                    })
                    .to_string(),
                )
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                let stdout = String::from_utf8_lossy(&o.stdout);
                CommandOutcome::failed(format!("fail2ban installed but failed to start service: {stderr} {stdout}"))
            }
            Err(e) => CommandOutcome::failed(format!("Failed to start fail2ban service: {e}")),
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn install_and_configure_fail2ban() -> CommandOutcome {
        CommandOutcome::failed("Intrusion prevention remediation is only supported on Linux hosts".to_string())
    }
}

mod fail2ban {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[allow(dead_code)]
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct Fail2banJail {
        pub name: String,
        pub currently_failed: u32,
        pub total_failed: u32,
        pub currently_banned: u32,
        pub total_banned: u32,
        pub file_list: Vec<String>,
        pub banned_ips: Vec<String>,
    }

    #[allow(dead_code)]
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct BannedIpEntry {
        pub ip: String,
        pub jail: String,
    }

    #[allow(dead_code)]
    #[derive(Debug, Serialize, Deserialize)]
    pub struct Fail2banStatus {
        pub supported: bool,
        pub installed: bool,
        pub active: bool,
        pub version: Option<String>,
        pub total_banned: u32,
        pub total_failed: u32,
        pub jails: Vec<Fail2banJail>,
        pub all_banned_ips: Vec<BannedIpEntry>,
        pub ignore_ips: Vec<String>,
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
    struct UnbanPayload {
        ip: String,
        jail: Option<String>,
    }

    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    struct BanPayload {
        ip: String,
        jail: Option<String>,
    }

    #[allow(dead_code)]
    #[derive(Debug, Deserialize)]
    struct SetWhitelistPayload {
        ips: Vec<String>,
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
                "installed": false,
                "active": false,
                "version": null,
                "total_banned": 0,
                "total_failed": 0,
                "jails": [],
                "all_banned_ips": [],
                "ignore_ips": [],
                "message": "Fail2Ban management is only supported on Linux hosts"
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
        CommandOutcome::failed("Fail2Ban management is only supported on Linux hosts".to_string())
    }

    #[cfg(target_os = "linux")]
    pub async fn handle_unban_ip(payload: serde_json::Value) -> CommandOutcome {
        tokio::task::spawn_blocking(move || unban_ip_linux(payload))
            .await
            .unwrap_or_else(|e| CommandOutcome::failed(format!("task panicked: {e}")))
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn handle_unban_ip(_payload: serde_json::Value) -> CommandOutcome {
        CommandOutcome::failed("Fail2Ban management is only supported on Linux hosts".to_string())
    }

    #[cfg(target_os = "linux")]
    pub async fn handle_ban_ip(payload: serde_json::Value) -> CommandOutcome {
        tokio::task::spawn_blocking(move || ban_ip_linux(payload))
            .await
            .unwrap_or_else(|e| CommandOutcome::failed(format!("task panicked: {e}")))
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn handle_ban_ip(_payload: serde_json::Value) -> CommandOutcome {
        CommandOutcome::failed("Fail2Ban management is only supported on Linux hosts".to_string())
    }

    #[cfg(target_os = "linux")]
    pub async fn handle_set_whitelist(payload: serde_json::Value) -> CommandOutcome {
        tokio::task::spawn_blocking(move || set_whitelist_linux(payload))
            .await
            .unwrap_or_else(|e| CommandOutcome::failed(format!("task panicked: {e}")))
    }

    #[cfg(not(target_os = "linux"))]
    pub async fn handle_set_whitelist(_payload: serde_json::Value) -> CommandOutcome {
        CommandOutcome::failed("Fail2Ban management is only supported on Linux hosts".to_string())
    }

    #[cfg(target_os = "linux")]
    fn get_status_linux() -> CommandOutcome {
        use std::process::Command;

        let which_cmd = Command::new("which").arg("fail2ban-client").output();
        let has_fail2ban = which_cmd.map(|o| o.status.success()).unwrap_or(false);

        if !has_fail2ban {
            return CommandOutcome::ok(
                serde_json::to_string(&Fail2banStatus {
                    supported: true,
                    installed: false,
                    active: false,
                    version: None,
                    total_banned: 0,
                    total_failed: 0,
                    jails: Vec::new(),
                    all_banned_ips: Vec::new(),
                    ignore_ips: Vec::new(),
                    message: Some("Fail2Ban is not installed on this host".to_string()),
                })
                .unwrap_or_default(),
            );
        }

        let is_active_cmd = Command::new("systemctl").args(["is-active", "fail2ban"]).output();
        let active = is_active_cmd
            .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active")
            .unwrap_or(false);

        if !active {
            // Also check via fail2ban-client ping in case it's managed without systemd
            let ping = Command::new("fail2ban-client").arg("ping").output();
            let is_ping_ok = ping.map(|o| String::from_utf8_lossy(&o.stdout).contains("Server replied: pong")).unwrap_or(false);

            if !is_ping_ok {
                return CommandOutcome::ok(
                    serde_json::to_string(&Fail2banStatus {
                        supported: true,
                        installed: true,
                        active: false,
                        version: get_version(),
                        total_banned: 0,
                        total_failed: 0,
                        jails: Vec::new(),
                        all_banned_ips: Vec::new(),
                        ignore_ips: get_ignore_ips(&[]),
                        message: Some("Fail2Ban service is stopped".to_string()),
                    })
                    .unwrap_or_default(),
                );
            }
        }

        let version = get_version();

        // Query active jails
        let status_out = Command::new("fail2ban-client").arg("status").output();
        let status_str = status_out.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
        let jail_names = parse_jail_list(&status_str);

        let mut jails = Vec::new();
        let mut all_banned_ips = Vec::new();
        let mut total_banned = 0;
        let mut total_failed = 0;

        for jail_name in &jail_names {
            if let Ok(j_out) = Command::new("fail2ban-client").args(["status", jail_name]).output() {
                let j_str = String::from_utf8_lossy(&j_out.stdout);
                let jail_info = parse_jail_status(jail_name, &j_str);
                total_banned += jail_info.currently_banned;
                total_failed += jail_info.total_failed;
                for ip in &jail_info.banned_ips {
                    all_banned_ips.push(BannedIpEntry {
                        ip: ip.clone(),
                        jail: jail_name.clone(),
                    });
                }
                jails.push(jail_info);
            }
        }

        let ignore_ips = get_ignore_ips(&jail_names);

        let status = Fail2banStatus {
            supported: true,
            installed: true,
            active: true,
            version,
            total_banned,
            total_failed,
            jails,
            all_banned_ips,
            ignore_ips,
            message: None,
        };

        CommandOutcome::ok(serde_json::to_string(&status).unwrap_or_default())
    }

    #[cfg(target_os = "linux")]
    fn get_version() -> Option<String> {
        use std::process::Command;
        let out = Command::new("fail2ban-client").arg("version").output().ok()?;
        if out.status.success() {
            let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !v.is_empty() {
                return Some(v);
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    fn parse_jail_list(output: &str) -> Vec<String> {
        let mut jails = Vec::new();
        for line in output.lines() {
            let trimmed = line.trim();
            if let Some(pos) = trimmed.to_lowercase().find("jail list:") {
                let rest = trimmed[pos + "jail list:".len()..].trim();
                for part in rest.split(',') {
                    let j = part.trim();
                    if !j.is_empty() {
                        jails.push(j.to_string());
                    }
                }
            }
        }
        jails
    }

    #[cfg(target_os = "linux")]
    fn parse_jail_status(name: &str, output: &str) -> Fail2banJail {
        let mut currently_failed = 0;
        let mut total_failed = 0;
        let mut currently_banned = 0;
        let mut total_banned = 0;
        let mut file_list = Vec::new();
        let mut banned_ips = Vec::new();

        for line in output.lines() {
            let lower = line.to_lowercase();
            let trimmed = line.trim();

            if lower.contains("currently failed:") {
                if let Some(pos) = lower.find("currently failed:") {
                    let val_str = trimmed[pos + "currently failed:".len()..].trim();
                    currently_failed = val_str.parse::<u32>().unwrap_or(0);
                }
            } else if lower.contains("total failed:") {
                if let Some(pos) = lower.find("total failed:") {
                    let val_str = trimmed[pos + "total failed:".len()..].trim();
                    total_failed = val_str.parse::<u32>().unwrap_or(0);
                }
            } else if lower.contains("file list:") {
                if let Some(pos) = lower.find("file list:") {
                    let val_str = trimmed[pos + "file list:".len()..].trim();
                    file_list = val_str
                        .split_whitespace()
                        .map(|s| s.trim_matches(',').to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
            } else if lower.contains("currently banned:") {
                if let Some(pos) = lower.find("currently banned:") {
                    let val_str = trimmed[pos + "currently banned:".len()..].trim();
                    currently_banned = val_str.parse::<u32>().unwrap_or(0);
                }
            } else if lower.contains("total banned:") {
                if let Some(pos) = lower.find("total banned:") {
                    let val_str = trimmed[pos + "total banned:".len()..].trim();
                    total_banned = val_str.parse::<u32>().unwrap_or(0);
                }
            } else if lower.contains("banned ip list:") {
                if let Some(pos) = lower.find("banned ip list:") {
                    let val_str = trimmed[pos + "banned ip list:".len()..].trim();
                    banned_ips = val_str
                        .split_whitespace()
                        .map(|s| s.trim_matches(',').to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
            }
        }

        Fail2banJail {
            name: name.to_string(),
            currently_failed,
            total_failed,
            currently_banned,
            total_banned,
            file_list,
            banned_ips,
        }
    }

    #[cfg(target_os = "linux")]
    fn get_ignore_ips(jail_names: &[String]) -> Vec<String> {
        use std::process::Command;
        use std::fs;
        use std::path::Path;

        // Try getting from first active jail via client
        if let Some(first_jail) = jail_names.first() {
            if let Ok(out) = Command::new("fail2ban-client").args(["get", first_jail, "ignoreip"]).output() {
                if out.status.success() {
                    let raw = String::from_utf8_lossy(&out.stdout);
                    let mut ips = Vec::new();
                    for line in raw.lines() {
                        let trimmed = line.trim().trim_start_matches(|c| c == '|' || c == '-' || c == '`' || c == ' ' || c == '\t');
                        if !trimmed.is_empty() && !trimmed.to_lowercase().contains("ignored") {
                            for part in trimmed.split_whitespace() {
                                let clean = part.trim_matches(',');
                                if !clean.is_empty() && !ips.contains(&clean.to_string()) {
                                    ips.push(clean.to_string());
                                }
                            }
                        }
                    }
                    if !ips.is_empty() {
                        return ips;
                    }
                }
            }
        }

        // Fallback: parse /etc/fail2ban/jail.local or /etc/fail2ban/jail.conf
        for path_str in &["/etc/fail2ban/jail.local", "/etc/fail2ban/jail.conf"] {
            let p = Path::new(path_str);
            if p.exists() {
                if let Ok(content) = fs::read_to_string(p) {
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("ignoreip") {
                            if let Some(pos) = trimmed.find('=') {
                                let ips_part = trimmed[pos + 1..].trim();
                                let mut ips = Vec::new();
                                for part in ips_part.split_whitespace() {
                                    let clean = part.trim_matches(',');
                                    if !clean.is_empty() && !ips.contains(&clean.to_string()) {
                                        ips.push(clean.to_string());
                                    }
                                }
                                if !ips.is_empty() {
                                    return ips;
                                }
                            }
                        }
                    }
                }
            }
        }

        vec!["127.0.0.1/8".to_string(), "::1".to_string()]
    }

    #[cfg(target_os = "linux")]
    fn toggle_linux(payload: serde_json::Value) -> CommandOutcome {
        use std::process::Command;
        let req: TogglePayload = match serde_json::from_value(payload) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed(format!("invalid payload: {e}")),
        };

        let res = if req.enabled {
            Command::new("systemctl")
                .args(["enable", "--now", "fail2ban"])
                .output()
                .or_else(|_| Command::new("service").args(["fail2ban", "start"]).output())
        } else {
            Command::new("systemctl")
                .args(["stop", "fail2ban"])
                .output()
                .or_else(|_| Command::new("service").args(["fail2ban", "stop"]).output())
        };

        match res {
            Ok(o) if o.status.success() => {
                CommandOutcome::ok(serde_json::json!({ "active": req.enabled }).to_string())
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                let stdout = String::from_utf8_lossy(&o.stdout);
                CommandOutcome::failed(format!("Failed to toggle fail2ban: {stderr} {stdout}"))
            }
            Err(e) => CommandOutcome::failed(format!("Failed to execute toggle command: {e}")),
        }
    }

    #[cfg(target_os = "linux")]
    fn unban_ip_linux(payload: serde_json::Value) -> CommandOutcome {
        use std::process::Command;
        let req: UnbanPayload = match serde_json::from_value(payload) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed(format!("invalid payload: {e}")),
        };

        let ip = req.ip.trim();
        if ip.is_empty() {
            return CommandOutcome::failed("IP address cannot be empty".to_string());
        }

        let jail = req.jail.as_deref().unwrap_or("").trim();

        let mut success = false;
        let mut last_err = String::new();

        if !jail.is_empty() && jail != "all" {
            // Unban in specific jail
            let res = Command::new("fail2ban-client")
                .args(["set", jail, "unbanip", ip])
                .output();
            match res {
                Ok(o) if o.status.success() => {
                    success = true;
                }
                Ok(o) => {
                    last_err = format!("{} {}", String::from_utf8_lossy(&o.stderr), String::from_utf8_lossy(&o.stdout));
                    // Try generic unban
                    if let Ok(o2) = Command::new("fail2ban-client").args(["unban", ip]).output() {
                        if o2.status.success() {
                            success = true;
                        }
                    }
                }
                Err(e) => last_err = e.to_string(),
            }
        } else {
            // Unban across all jails
            let res = Command::new("fail2ban-client").args(["unban", ip]).output();
            match res {
                Ok(o) if o.status.success() => {
                    success = true;
                }
                _ => {
                    // Fallback: query jails and unban on each
                    if let Ok(st) = Command::new("fail2ban-client").arg("status").output() {
                        let st_str = String::from_utf8_lossy(&st.stdout);
                        let jails = parse_jail_list(&st_str);
                        for j in jails {
                            let _ = Command::new("fail2ban-client").args(["set", &j, "unbanip", ip]).output();
                        }
                        success = true;
                    }
                }
            }
        }

        if success {
            CommandOutcome::ok(serde_json::json!({ "unbanned": ip, "jail": jail }).to_string())
        } else {
            CommandOutcome::failed(format!("Failed to unban IP {ip}: {last_err}"))
        }
    }

    #[cfg(target_os = "linux")]
    fn ban_ip_linux(payload: serde_json::Value) -> CommandOutcome {
        use std::process::Command;
        let req: BanPayload = match serde_json::from_value(payload) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed(format!("invalid payload: {e}")),
        };

        let ip = req.ip.trim();
        if ip.is_empty() {
            return CommandOutcome::failed("IP address cannot be empty".to_string());
        }

        let jail = req.jail.as_deref().unwrap_or("sshd").trim();
        let target_jail = if jail.is_empty() { "sshd" } else { jail };

        let res = Command::new("fail2ban-client")
            .args(["set", target_jail, "banip", ip])
            .output();

        match res {
            Ok(o) if o.status.success() => {
                CommandOutcome::ok(serde_json::json!({ "banned": ip, "jail": target_jail }).to_string())
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                let stdout = String::from_utf8_lossy(&o.stdout);
                CommandOutcome::failed(format!("Failed to ban IP {ip} in jail {target_jail}: {stderr} {stdout}"))
            }
            Err(e) => CommandOutcome::failed(format!("Failed to execute fail2ban-client banip: {e}")),
        }
    }

    #[cfg(target_os = "linux")]
    fn set_whitelist_linux(payload: serde_json::Value) -> CommandOutcome {
        use std::fs;
        use std::path::Path;
        use std::process::Command;

        let req: SetWhitelistPayload = match serde_json::from_value(payload) {
            Ok(p) => p,
            Err(e) => return CommandOutcome::failed(format!("invalid payload: {e}")),
        };

        let mut cleaned_ips = Vec::new();
        // Always include localhost loopback
        cleaned_ips.push("127.0.0.1/8".to_string());
        cleaned_ips.push("::1".to_string());

        for ip in req.ips {
            let trimmed = ip.trim().to_string();
            if !trimmed.is_empty() && !cleaned_ips.contains(&trimmed) {
                cleaned_ips.push(trimmed);
            }
        }

        let jail_local = Path::new("/etc/fail2ban/jail.local");
        let ignoreip_line = format!("ignoreip = {}", cleaned_ips.join(" "));

        let new_content = if jail_local.exists() {
            let existing = fs::read_to_string(jail_local).unwrap_or_default();
            let mut lines: Vec<String> = Vec::new();
            let mut found_ignoreip = false;
            let mut in_default = false;

            for line in existing.lines() {
                let trimmed = line.trim();
                if trimmed.starts_with('[') && trimmed.ends_with(']') {
                    in_default = trimmed.eq_ignore_ascii_case("[default]");
                }
                if in_default && trimmed.starts_with("ignoreip") {
                    lines.push(ignoreip_line.clone());
                    found_ignoreip = true;
                } else {
                    lines.push(line.to_string());
                }
            }

            if !found_ignoreip {
                // Prepend or append to [DEFAULT]
                if let Some(pos) = lines.iter().position(|l| l.trim().eq_ignore_ascii_case("[default]")) {
                    lines.insert(pos + 1, ignoreip_line.clone());
                } else {
                    lines.insert(0, format!("[DEFAULT]\n{ignoreip_line}\n"));
                }
            }

            lines.join("\n")
        } else {
            format!("[DEFAULT]\n{ignoreip_line}\n\n[sshd]\nenabled = true\n")
        };

        if let Err(e) = fs::write(jail_local, new_content) {
            return CommandOutcome::failed(format!("Failed to write /etc/fail2ban/jail.local: {e}"));
        }

        // Reload fail2ban
        let reload_res = Command::new("fail2ban-client").arg("reload").output();
        match reload_res {
            Ok(o) if o.status.success() => {
                CommandOutcome::ok(serde_json::json!({ "success": true, "ignore_ips": cleaned_ips }).to_string())
            }
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                CommandOutcome::failed(format!("Failed to reload fail2ban configuration: {stderr}"))
            }
            Err(e) => CommandOutcome::failed(format!("Failed to execute fail2ban-client reload: {e}")),
        }
    }
}


