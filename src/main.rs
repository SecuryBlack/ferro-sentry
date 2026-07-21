mod config;
mod engine;
mod modules;
mod output;

use anyhow::Result;
use engine::{EventEngine, Severity};
use output::{sb_agent::SbAgentOutput, direct::DirectOutput, local_file::LocalFileOutput, Output};
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[cfg(windows)]
fn init_logging(log_level: &str) {
    let log_dir = r"C:\ProgramData\ferro-sentry";
    let write_test_path = format!(r"{}\.write_test", log_dir);

    let use_stdout = std::env::var("FERRO_SENTRY_LOG_STDOUT").is_ok()
        || std::fs::create_dir_all(log_dir).is_err()
        || std::fs::write(&write_test_path, "").is_err();

    let _ = std::fs::remove_file(&write_test_path);

    if use_stdout {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(log_level))
            .init();
    } else {
        let file_appender = tracing_appender::rolling::daily(log_dir, "ferro-sentry.log");
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new(log_level))
            .with_writer(file_appender)
            .with_ansi(false)
            .init();
    }
}

#[cfg(not(windows))]
fn init_logging(log_level: &str) {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(log_level))
        .init();
}

async fn run(mut shutdown: tokio::sync::oneshot::Receiver<()>) {
    // Inicializar logging primero para registrar cualquier posible error de inicio/configuración
    init_logging("info");

    let cfg = match config::Config::load() {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("Fallo al cargar la configuración: {}", e);
            std::process::exit(1);
        }
    };

    tracing::info!(mode = %cfg.mode, version = %cfg.version, "Ferro-Sentry iniciando");

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
            }
            _ = &mut shutdown => {
                tracing::info!("Señal de apagado recibida, deteniendo Ferro-Sentry");
                break;
            }
        }
    }
}

// ── Windows Service Support ──────────────────────────────────────────────────

#[cfg(windows)]
mod service {
    use std::ffi::OsString;
    use std::time::Duration;
    use windows_service::{
        define_windows_service,
        service::{
            ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
            ServiceType,
        },
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };

    const SERVICE_NAME: &str = "FerroSentry";

    define_windows_service!(ffi_service_main, service_main);

    pub fn start() -> Result<(), windows_service::Error> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main)
    }

    fn service_main(_arguments: Vec<OsString>) {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let shutdown_tx = std::sync::Mutex::new(Some(shutdown_tx));

        let status_handle = service_control_handler::register(
            SERVICE_NAME,
            move |control_event| match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    if let Ok(mut guard) = shutdown_tx.lock() {
                        if let Some(tx) = guard.take() {
                            let _ = tx.send(());
                        }
                    }
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            },
        )
        .expect("failed to register service control handler");

        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Running,
                controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .expect("failed to set service status Running");

        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime");

        rt.block_on(super::run(shutdown_rx));

        let _ = status_handle.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });
    }
}

#[cfg(windows)]
fn run_console() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");

    rt.block_on(async {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            tokio::signal::ctrl_c().await.ok();
            let _ = shutdown_tx.send(());
        });
        run(shutdown_rx).await;
    });
}

fn check_version_arg() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && (args[1] == "--version" || args[1] == "-V") {
        println!("ferro-sentry {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
}

#[cfg(windows)]
fn main() -> Result<()> {
    check_version_arg();
    // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (1063): process was not started
    // by the SCM, so run in console mode instead.
    match service::start() {
        Ok(_) => {}
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1063) => {
            run_console();
        }
        Err(e) => {
            eprintln!("[ferro-sentry] service error: {e}");
            std::process::exit(1);
        }
    }
    Ok(())
}

#[cfg(not(windows))]
#[tokio::main]
async fn main() -> Result<()> {
    check_version_arg();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        let _ = shutdown_tx.send(());
    });
    run(shutdown_rx).await;
    Ok(())
}
