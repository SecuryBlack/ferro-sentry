use crate::engine::SecurityEvent;
use crate::output::Output;
use anyhow::{Context, Result};
use async_trait::async_trait;
use proto::security_service_client::SecurityServiceClient;
use proto::SecurityEventRequest;

pub mod proto {
    tonic::include_proto!("securyblack.tunnel.v1");
}

pub struct SbAgentOutput;

impl SbAgentOutput {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Output for SbAgentOutput {
    async fn send(&self, event: SecurityEvent) -> Result<()> {
        let event_json = serde_json::to_string(&event)
            .context("Fallo al serializar evento a JSON")?;

        tracing::debug!("Enviando evento de seguridad a sb-agent (gRPC)...");

        // Conectar al proxy gRPC local
        let mut client = SecurityServiceClient::connect("http://127.0.0.1:4317")
            .await
            .context("No se pudo conectar al agente local en 127.0.0.1:4317")?;

        let request = tonic::Request::new(SecurityEventRequest {
            event_json,
        });

        let response = client.send_event(request)
            .await
            .context("Error enviando evento vía gRPC al agente local")?;

        if response.into_inner().success {
            tracing::info!(event_type = %event.event_type, "Evento enviado correctamente a sb-agent");
        } else {
            tracing::warn!(event_type = %event.event_type, "sb-agent reportó fallo al recibir el evento");
        }

        Ok(())
    }
}
