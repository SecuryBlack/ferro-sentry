use serde::Deserialize;
use std::env;

/// Carga de fichero + versión ahora vienen de `sb-agent-core`; lo que sigue
/// siendo propio de FerroSentry son estos campos y sus variables de entorno
/// (`FERRO_SENTRY_*`).
#[derive(Debug, Deserialize)]
pub struct Config {
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

impl Default for Config {
    fn default() -> Self {
        Config {
            version: default_version(),
            api_url: default_api_url(),
            token: String::new(),
            mode: default_mode(),
            local_file_path: default_local_path(),
            log_level: default_log_level(),
        }
    }
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
    /// Carga `config.toml` (vía `sb_agent_core::config::load`, que hace
    /// `T::default()` si el fichero no existe) y aplica overrides de entorno.
    ///
    /// Cambio de comportamiento respecto a la versión anterior: si el fichero
    /// no existe, ya no se escribe uno nuevo con los valores por defecto — se
    /// devuelven en memoria y ya está, igual que hacen OxiPulse/CromoForge.
    /// El instalador siempre deja el fichero escrito, así que este caso solo
    /// se da si alguien lo borra a mano.
    pub fn load() -> anyhow::Result<Self> {
        let config_path = sb_agent_core::config::default_config_path("ferro-sentry");
        let mut cfg: Config = sb_agent_core::config::load(&config_path)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        if let Ok(v) = env::var("FERRO_SENTRY_API_URL") {
            cfg.api_url = v;
        }
        if let Ok(v) = env::var("FERRO_SENTRY_TOKEN") {
            cfg.token = v;
        }
        if let Ok(v) = env::var("FERRO_SENTRY_MODE") {
            cfg.mode = v;
        }
        if let Ok(v) = env::var("FERRO_SENTRY_LOCAL_FILE_PATH") {
            cfg.local_file_path = v;
        }
        if let Ok(v) = env::var("FERRO_SENTRY_LOG_LEVEL") {
            cfg.log_level = v;
        }

        cfg.version = env!("CARGO_PKG_VERSION").to_string();
        let _ = sb_agent_core::config::sync_version_field(&config_path, &cfg.version);

        Ok(cfg)
    }
}
