use anyhow::{Context, Result};
use serde::Deserialize;
use std::{env, fs, path::Path};

#[derive(Debug, Deserialize)]
pub struct Config {
    /// Versión del agente
    #[serde(default = "default_version")]
    pub version: String,

    /// URL base de la API de SecuryBlack (fallback si no hay Conduit)
    #[serde(default = "default_api_url")]
    pub api_url: String,

    /// Token de autenticación para la API
    #[serde(default)]
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

pub fn default_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
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
        let current_pkg_version = env!("CARGO_PKG_VERSION").to_string();

        let mut version_in_file: Option<String> = None;
        let mut api_url = default_api_url();
        let mut token = String::new();
        let mut mode = default_mode();
        let mut local_file_path = default_local_path();
        let mut log_level = default_log_level();

        // Cargar desde archivo si existe
        if Path::new(&config_path).exists() {
            if let Ok(contents) = fs::read_to_string(&config_path) {
                if let Ok(file) = toml::from_str::<toml::Value>(&contents) {
                    if let Some(v) = file.get("version").and_then(|v| v.as_str()) {
                        version_in_file = Some(v.to_string());
                    }
                    if let Some(v) = file.get("api_url").and_then(|v| v.as_str()) {
                        api_url = v.to_string();
                    }
                    if let Some(v) = file.get("token").and_then(|v| v.as_str()) {
                        token = v.to_string();
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
            }
        }

        // Override con env vars
        if let Ok(v) = env::var("FERRO_SENTRY_API_URL") {
            api_url = v;
        }
        if let Ok(v) = env::var("FERRO_SENTRY_TOKEN") {
            token = v;
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

        let version = current_pkg_version.clone();

        // Actualizar/escribir versión en config.toml si ha cambiado, no existía en el archivo, o el archivo no existía
        if version_in_file.as_deref() != Some(&current_pkg_version) || !Path::new(&config_path).exists() {
            Self::write_config(&config_path, &version, &api_url, &token, &mode, &local_file_path, &log_level);
        }

        Ok(Config {
            version,
            api_url,
            token,
            mode,
            local_file_path,
            log_level,
        })
    }

    pub fn write_config(path: &str, version: &str, api_url: &str, token: &str, mode: &str, local_file_path: &str, log_level: &str) {
        if let Some(parent) = Path::new(path).parent() {
            let _ = fs::create_dir_all(parent);
        }

        let content = format!(
            "# Ferro-Sentry configuration\nversion = \"{}\"\nmode = \"{}\"\napi_url = \"{}\"\ntoken = \"{}\"\nlog_level = \"{}\"\nlocal_file_path = \"{}\"\n",
            version, mode, api_url, token, log_level, local_file_path
        );
        let _ = fs::write(path, content);
    }

    pub fn config_path() -> String {
        #[cfg(target_os = "windows")]
        return r"C:\ProgramData\ferro-sentry\config.toml".to_string();

        #[cfg(not(target_os = "windows"))]
        return "/etc/ferro-sentry/config.toml".to_string();
    }
}
