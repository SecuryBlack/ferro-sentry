use crate::engine::SecurityEvent;
use crate::output::Output;
use anyhow::Result;
use async_trait::async_trait;

pub struct SbAgentOutput;

impl SbAgentOutput {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Output for SbAgentOutput {
    async fn send(&self, event: SecurityEvent) -> Result<()> {
        // TODO: Implementar envío real a SecuryBlack Agent vía gRPC/HTTP local
        tracing::info!(
            event_type = %event.event_type,
            "[STUB] Evento enviado a sb-agent (no implementado aún)"
        );
        Ok(())
    }
}
