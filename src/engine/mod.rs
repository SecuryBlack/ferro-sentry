use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    pub event_type: String,
    pub category: String,
    pub severity: Severity,
    pub timestamp: DateTime<Utc>,
    pub host: String,
    pub agent: String,
    pub module: String,
    pub details: serde_json::Value,
    pub rule_triggered: Option<String>,
}

impl SecurityEvent {
    pub fn signature(&self) -> String {
        // Firma simple para deduplicación. Para reglas donde el conteo en
        // `details` es el dato relevante (no solo si el hallazgo existe),
        // se incluye en la firma — si no, un cambio de 3 a 30 paquetes
        // pendientes se descartaría como duplicado del primer reporte.
        let extra = match self.rule_triggered.as_deref() {
            Some("pending_os_updates") | Some("reboot_required") => format!(
                ":{}:{}:{}",
                self.details.get("total_updates").and_then(|v| v.as_u64()).unwrap_or(0),
                self.details.get("security_updates").and_then(|v| v.as_u64()).unwrap_or(0),
                self.details.get("reboot_required").and_then(|v| v.as_bool()).unwrap_or(false),
            ),
            _ => String::new(),
        };

        format!(
            "{}:{}:{}:{}{}",
            self.event_type,
            self.module,
            self.host,
            self.rule_triggered.as_deref().unwrap_or("none"),
            extra
        )
    }
}

pub struct EventEngine {
    seen: Mutex<HashSet<String>>,
    hostname: String,
}

impl EventEngine {
    pub fn new() -> Self {
        let hostname = hostname::get()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        Self {
            seen: Mutex::new(HashSet::new()),
            hostname,
        }
    }

    pub async fn process(&self, mut event: SecurityEvent) -> Option<SecurityEvent> {
        // Enriquecer
        event.host = self.hostname.clone();
        event.agent = "ferro-sentry".to_string();
        event.timestamp = Utc::now();

        let sig = event.signature();
        let mut seen = self.seen.lock().await;

        if seen.contains(&sig) {
            tracing::debug!(signature = %sig, "Evento duplicado descartado");
            return None;
        }

        seen.insert(sig);

        // TODO: throttling, scoring más avanzado
        Some(event)
    }

    pub async fn build_event(
        &self,
        event_type: &str,
        category: &str,
        severity: Severity,
        module: &str,
        details: serde_json::Value,
        rule: Option<&str>,
    ) -> SecurityEvent {
        SecurityEvent {
            event_type: event_type.to_string(),
            category: category.to_string(),
            severity,
            timestamp: Utc::now(),
            host: self.hostname.clone(),
            agent: "ferro-sentry".to_string(),
            module: module.to_string(),
            details,
            rule_triggered: rule.map(|s| s.to_string()),
        }
    }

    /// Señala que una regla que antes disparaba un hallazgo ya no aplica
    /// (p.ej. `pending_os_updates` cuando `total_updates` vuelve a 0).
    ///
    /// Sin esto, un módulo nunca vuelve a mandar nada para esa regla en
    /// cuanto la condición desaparece — no hay ningún evento que decirle a
    /// `api-internal` "esto ya no está pasando", así que el hallazgo activo
    /// se queda huérfano en la base de datos para siempre, mostrando datos
    /// de hace semanas aunque el estado real ya haya cambiado. `event_type:
    /// "resolved"` le dice al backend que cierre el hallazgo abierto para
    /// (module, rule) en vez de crear/actualizar uno.
    pub async fn build_resolved_event(&self, module: &str, rule: &str) -> SecurityEvent {
        self.build_event("resolved", "posture", Severity::Info, module, serde_json::json!({}), Some(rule)).await
    }
}
