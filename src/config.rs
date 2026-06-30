use anyhow::{Context, Result};
use serde::Deserialize;
use std::{env, fs, path::Path};

#[derive(Debug, Deserialize)]
pub struct Config {
    /// URL base de la API de SecuryBlack (fallback si no hay Conduit)
    #[serde(default = "default_api_url")]
    pub api_url: String,

    /// Token de autenticación para la API
    pub token: String,

    /// Modo de salida: "direct", "local_file", "agent"
    #[serde(default = "default_mode")]
    pub mode: String,

    /// Ruta del archivo de salida local (solo si mode = "local_file")
    #[serde(default = "default_local_path")]
    pub local_file_path: String,

    /// Nivel de log: trace, debug, info, warn, error
    #[serde(default = "default_log_level")]
    pub log_level: String,
}

pub fn default_api_url() -> String {
    "https://api.securyblack.com".to_string()
}

pub fn default_mode() -> String {
    "local_file".to_string()
}

pub fn default_local_path() -> String {
    "ferro-sentry_events.jsonl".to_string()
}

pub fn default_log_level() -> String {
    "info".to_string()
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path();

        let mut api_url = default_api_url();
        let mut token: Option<String> = None;
        let mut mode = default_mode();
        let mut local_file_path = default_local_path();
        let mut log_level = default_log_level();

        // Cargar desde archivo si existe
        if Path::new(&config_path).exists() {
            let contents = fs::read_to_string(&config_path)
                .with_context(|| format!("No se pudo leer {}", config_path))?;
            let file: toml::Value = toml::from_str(&contents)
                .with_context(|| "Error parseando config.toml")?;

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
        }

        // Override con env vars
        if let Ok(v) = env::var("FERRO_SENTRY_API_URL") {
            api_url = v;
        }
        if let Ok(v) = env::var("FERRO_SENTRY_TOKEN") {
            token = Some(v);
        }
        if let Ok(v) = env::var("FERRO_SENTRY_MODE") {
            mode = v;
        }
        if let Ok(v) = env::var("FERRO_SENTRY_LOCAL_FILE_PATH") {
            local_file_path = v;
        }
        if let Ok(v) = env::var("FERRO_SENTRY_LOG_LEVEL") {
            log_level = v;
        }

        let token = token.with_context(|| {
            "Token no configurado. Usa config.toml o la env var FERRO_SENTRY_TOKEN"
        })?;

        Ok(Config {
            api_url,
            token,
            mode,
            local_file_path,
            log_level,
        })
    }

    pub fn config_path() -> String {
        #[cfg(target_os = "windows")]
        return r"C:\ProgramData\ferro-sentry\config.toml".to_string();

        #[cfg(not(target_os = "windows"))]
        return "/etc/ferro-sentry/config.toml".to_string();
    }
}
