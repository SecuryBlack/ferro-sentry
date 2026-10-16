use crate::engine::SecurityEvent;
use anyhow::Result;
use async_trait::async_trait;

pub mod direct;
pub mod local_file;
pub mod sb_agent;

// async_trait repeats #[must_use] on the boxed future (clippy 1.99).
#[allow(clippy::double_must_use)]
#[async_trait]
pub trait Output: Send + Sync {
    async fn send(&self, event: SecurityEvent) -> Result<()>;
}
