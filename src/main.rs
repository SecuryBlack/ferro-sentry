mod config;
mod engine;
mod modules;
mod output;

use engine::{EventEngine, Severity};
use output::{sb_agent::SbAgentOutput, direct::DirectOutput, local_file::LocalFileOutput, Output};
use std::sync::Arc;

async fn run(mut shutdown: tokio::sync::oneshot::Receiver<()>) {
    // Config se carga antes que logging (al revés que antes) porque
    // cfg.log_level ahora sí se usa de verdad como nivel por defecto —
    // previamente init_logging("info") se llamaba primero con un nivel fijo
    // y log_level se cargaba después sin aplicarse nunca a nada.
    let cfg = match config::Config::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ferro-sentry] Fallo al cargar la configuración: {}", e);
            std::process::exit(1);
        }
    };

    let log_dir = sb_agent_core::config::default_config_path("ferro-sentry")
        .parent()
        .expect("config path always has a parent")
        .to_path_buf();
    sb_agent_core::logging::init("ferro-sentry", &log_dir, &cfg.log_level);

    tracing::info!(mode = %cfg.mode, version = %cfg.version, log_level = %cfg.log_level, "Ferro-Sentry iniciando");

    let status_handle = sb_agent_core::status::StatusHandle::new("ferro-sentry", env!("CARGO_PKG_VERSION"));
    sb_agent_core::status::spawn_server(
        status_handle.clone(),
        sb_agent_core::status::default_socket_path("ferro-sentry"),
    );
    status_handle.set_state("running");

    // Iniciar chequeo diario de actualizaciones en segundo plano.
    // Mismo STARTUP_DELAY (60s) que ya tenía FerroSentry — coincide con
    // OxiPulse, no con los 300s de nexus-agent (ese fue el drift original
    // que motivó mover esto a sb-agent-core).
    sb_agent_core::updater::start_daily_check(sb_agent_core::updater::UpdaterConfig::new(
        "securyblack",
        "ferro-sentry",
        "ferro-sentry",
        env!("CARGO_PKG_VERSION"),
    ));

    // Crear output según modo
    let output: Arc<dyn Output> = match cfg.mode.as_str() {
        "direct" => Arc::new(DirectOutput::new(&cfg.api_url, &cfg.token)),
        "agent" | "local_agent" => Arc::new(SbAgentOutput::new()),
        _ => Arc::new(LocalFileOutput::new(&cfg.local_file_path)),
    };

    let engine = EventEngine::new();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // Escaneo cada hora

    loop {
        tokio::select! {
            _ = interval.tick() => {
                tracing::info!("Iniciando escaneos de seguridad...");

                // ─── Port Scanner (Fase 1) ───
                tracing::info!("Ejecutando Port Scanner…");
                match modules::port_scanner::scan(&engine).await {
                    Ok(findings) => {
                        tracing::info!(count = findings.len(), "Port Scanner completado");
                        for event in findings {
                            if let Some(event) = engine.process(event).await {
                                if let Err(e) = output.send(event).await {
                                    tracing::error!(error = %e, "Error enviando evento de Port Scanner");
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
                                    tracing::error!(error = %e, "Error enviando evento de Vulnerability Scanner");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Vulnerability Scanner falló");
                    }
                }

                // ─── SSH Auditor ───
                tracing::info!("Ejecutando SSH Auditor…");
                match modules::ssh_auditor::scan(&engine).await {
                    Ok(findings) => {
                        tracing::info!(count = findings.len(), "SSH Auditor completado");
                        for event in findings {
                            if let Some(event) = engine.process(event).await {
                                if let Err(e) = output.send(event).await {
                                    tracing::error!(error = %e, "Error enviando evento de SSH Auditor");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "SSH Auditor falló");
                    }
                }

                // ─── File Integrity Monitor (FIM) ───
                tracing::info!("Ejecutando File Integrity Monitor (FIM)…");
                match modules::fim::scan(&engine).await {
                    Ok(findings) => {
                        tracing::info!(count = findings.len(), "FIM completado");
                        for event in findings {
                            if let Some(event) = engine.process(event).await {
                                if let Err(e) = output.send(event).await {
                                    tracing::error!(error = %e, "Error enviando evento de FIM");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "FIM falló");
                    }
                }

                // ─── Permission Auditor ───
                tracing::info!("Ejecutando Permission Auditor…");
                match modules::permission_auditor::scan(&engine).await {
                    Ok(findings) => {
                        tracing::info!(count = findings.len(), "Permission Auditor completado");
                        for event in findings {
                            if let Some(event) = engine.process(event).await {
                                if let Err(e) = output.send(event).await {
                                    tracing::error!(error = %e, "Error enviando evento de Permission Auditor");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Permission Auditor falló");
                    }
                }

                // ─── Persistence Hunter ───
                tracing::info!("Ejecutando Persistence Hunter…");
                match modules::persistence_hunter::scan(&engine).await {
                    Ok(findings) => {
                        tracing::info!(count = findings.len(), "Persistence Hunter completado");
                        for event in findings {
                            if let Some(event) = engine.process(event).await {
                                if let Err(e) = output.send(event).await {
                                    tracing::error!(error = %e, "Error enviando evento de Persistence Hunter");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Persistence Hunter falló");
                    }
                }

                // ─── Process Sentinel ───
                tracing::info!("Ejecutando Process Sentinel…");
                match modules::process_sentinel::scan(&engine).await {
                    Ok(findings) => {
                        tracing::info!(count = findings.len(), "Process Sentinel completado");
                        for event in findings {
                            if let Some(event) = engine.process(event).await {
                                if let Err(e) = output.send(event).await {
                                    tracing::error!(error = %e, "Error enviando evento de Process Sentinel");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Process Sentinel falló");
                    }
                }

                // ─── Firewall Auditor ───
                tracing::info!("Ejecutando Firewall Auditor…");
                match modules::firewall_auditor::scan(&engine).await {
                    Ok(findings) => {
                        tracing::info!(count = findings.len(), "Firewall Auditor completado");
                        for event in findings {
                            if let Some(event) = engine.process(event).await {
                                if let Err(e) = output.send(event).await {
                                    tracing::error!(error = %e, "Error enviando evento de Firewall Auditor");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Firewall Auditor falló");
                    }
                }

                // ─── SSL/TLS Auditor ───
                tracing::info!("Ejecutando SSL/TLS Auditor…");
                match modules::ssl_auditor::scan(&engine).await {
                    Ok(findings) => {
                        tracing::info!(count = findings.len(), "SSL/TLS Auditor completado");
                        for event in findings {
                            if let Some(event) = engine.process(event).await {
                                if let Err(e) = output.send(event).await {
                                    tracing::error!(error = %e, "Error enviando evento de SSL/TLS Auditor");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "SSL/TLS Auditor falló");
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
                            tracing::error!(error = %e, "Error enviando evento de prueba");
                        }
                    }
                }

                tracing::info!("Escaneos de seguridad completados exitosamente");
                status_handle.set_details(serde_json::json!({
                    "last_scan_unix": std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                }));
            }
            _ = &mut shutdown => {
                tracing::info!("Señal de apagado recibida, deteniendo Ferro-Sentry");
                status_handle.set_state("stopping");
                break;
            }
        }
    }
}

fn check_version_arg() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && (args[1] == "--version" || args[1] == "-V") {
        println!("ferro-sentry {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
}

#[cfg(windows)]
fn main() {
    check_version_arg();
    // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (1063): process was not started
    // by the SCM, so run in console mode instead.
    match sb_agent_core::service::windows::run_service("FerroSentry", |rx| run(rx)) {
        Ok(_) => {}
        Err(e) if sb_agent_core::service::windows::is_not_started_by_scm(&e) => {
            sb_agent_core::service::run_console(run);
        }
        Err(e) => {
            eprintln!("[ferro-sentry] service error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(windows))]
fn main() {
    check_version_arg();
    sb_agent_core::service::run_console(run);
}
