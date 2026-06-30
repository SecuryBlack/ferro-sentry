use crate::engine::SecurityEvent;
use crate::output::Output;
use anyhow::Result;
use async_trait::async_trait;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

pub struct LocalFileOutput {
    path: String,
}

impl LocalFileOutput {
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }
}

#[async_trait]
impl Output for LocalFileOutput {
    async fn send(&self, event: SecurityEvent) -> Result<()> {
        let line = serde_json::to_string(&event)?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await?;

        file.write_all(line.as_bytes()).await?;
        file.write_all(b"\n").await?;
        file.flush().await?;

        tracing::info!(path = %self.path, event_type = %event.event_type, "Evento escrito a archivo local");

        Ok(())
    }
}
