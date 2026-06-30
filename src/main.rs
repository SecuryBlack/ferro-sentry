mod config;
mod engine;
mod modules;
mod output;

use anyhow::Result;
use engine::{EventEngine, Severity};
use output::{sb_agent::SbAgentOutput, direct::DirectOutput, local_file::LocalFileOutput, Output};
use std::sync::Arc;
use tracing_subscriber::{fmt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    // Intentar cargar config del sistema; si falla, intentar config local para desarrollo
    let cfg = config::Config::load()
        .or_else(|_| {
            tracing::warn!("Config del sistema no encontrada, intentando ./config.toml");
            let mut local = std::env::current_dir()?;
            local.push("config.toml");
            if local.exists() {
                let contents = std::fs::read_to_string(&local)?;
                let mut api_url = config::default_api_url();
                let mut token: Option<String> = None;
                let mut mode = config::default_mode();
                let mut local_file_path = config::default_local_path();
                let mut log_level = config::default_log_level();

                let file: toml::Value = toml::from_str(&contents)?;
                if let Some(v) = file.get("api_url").and_then(|v| v.as_str()) {
                    api_url = v.to_string();
                }
                if let Some(v) = file.get("token").and_then(|v| v.as_str()) {
                    token = Some(v.to_string());
                }
                if let Some(v) = file.get("mode").and_then(|v| v.as_str()) {
                    mode = v.to_string();
                }
                if let Some(v) = file.get("local_file_path").and_then(|v| v.as_str()) {
                    local_file_path = v.to_string();
                }
                if let Some(v) = file.get("log_level").and_then(|v| v.as_str()) {
                    log_level = v.to_string();
                }

                anyhow::ensure!(token.is_some(), "token requerido en config.toml");
                Ok(config::Config {
                    api_url,
                    token: token.unwrap(),
                    mode,
                    local_file_path,
                    log_level,
                })
            } else {
                Err(anyhow::anyhow!(
                    "No se encontró config.toml en el sistema ni en el directorio actual"
                ))
            }
        })?;

    // Inicializar logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cfg.log_level));

    fmt::fmt().with_env_filter(filter).init();

    tracing::info!(mode = %cfg.mode, "Ferro-Sentry iniciando");

    // Crear output según modo
    let output: Arc<dyn Output> = match cfg.mode.as_str() {
        "direct" => Arc::new(DirectOutput::new(&cfg.api_url, &cfg.token)),
        "agent" => Arc::new(SbAgentOutput::new()),
        _ => Arc::new(LocalFileOutput::new(&cfg.local_file_path)),
    };

    let engine = EventEngine::new();

    // ─── Port Scanner (Fase 1) ───
    tracing::info!("Ejecutando Port Scanner…");
    match modules::port_scanner::scan(&engine).await {
        Ok(findings) => {
            tracing::info!(count = findings.len(), "Port Scanner completado");
            for event in findings {
                if let Some(event) = engine.process(event).await {
                    if let Err(e) = output.send(event).await {
                        tracing::error!(error = %e, "Error enviando evento");
                    }
                }
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "Port Scanner falló");
        }
    }

    // ─── Vulnerability Scanner (Fase 1/3) ───
    tracing::info!("Ejecutando Vulnerability Scanner…");
    match modules::vuln_scanner::scan(&engine).await {
        Ok(findings) => {
            tracing::info!(count = findings.len(), "Vulnerability Scanner completado");
            for event in findings {
                if let Some(event) = engine.process(event).await {
                    if let Err(e) = output.send(event).await {
                        tracing::error!(error = %e, "Error enviando evento");
                    }
                }
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "Vulnerability Scanner falló");
        }
    }

    // ─── Eventos de prueba legacy (Fase 0) ───
    let test_events = vec![
        engine
            .build_event(
                "finding",
                "posture",
                Severity::High,
                "ssh_auditor",
                serde_json::json!({
                    "finding": "PermitRootLogin=yes",
                    "recommendation": "Set PermitRootLogin=no",
                    "file": "/etc/ssh/sshd_config"
                }),
                Some("cis_ssh_root_login"),
            )
            .await,
        engine
            .build_event(
                "finding",
                "posture",
                Severity::Critical,
                "permission_auditor",
                serde_json::json!({
                    "file": "/usr/bin/passwd",
                    "suid": true,
                    "owner": "root",
                    "recommendation": "Review SUID binaries"
                }),
                Some("suid_binary_detected"),
            )
            .await,
    ];

    for event in test_events {
        if let Some(event) = engine.process(event).await {
            if let Err(e) = output.send(event).await {
                tracing::error!(error = %e, "Error enviando evento");
            }
        }
    }

    tracing::info!("Ferro-Sentry Fase 0 completada exitosamente");
    Ok(())
}
