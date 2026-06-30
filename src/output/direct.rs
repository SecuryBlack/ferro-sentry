use crate::engine::SecurityEvent;
use crate::output::Output;
use anyhow::Result;
use async_trait::async_trait;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};

pub struct DirectOutput {
    client: reqwest::Client,
    url: String,
    token: String,
}

impl DirectOutput {
    pub fn new(api_url: &str, token: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: format!("{}/agents/me/security-events", api_url.trim_end_matches('/')),
            token: token.to_string(),
        }
    }
}

#[async_trait]
impl Output for DirectOutput {
    async fn send(&self, event: SecurityEvent) -> Result<()> {
        let mut headers = HeaderMap::new();
        let auth = HeaderValue::from_str(&format!("Bearer {}", self.token))?;
        headers.insert(AUTHORIZATION, auth);

        let body = serde_json::to_string(&event)?;

        tracing::debug!(url = %self.url, body = %body, "Enviando evento directo a API");

        let res = self
            .client
            .post(&self.url)
            .headers(headers)
            .json(&event)
            .send()
            .await;

        match res {
            Ok(response) => {
                if response.status().is_success() {
                    tracing::info!(event_type = %event.event_type, "Evento enviado correctamente");
                } else {
                    tracing::warn!(status = %response.status(), "API respondió con error");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "Fallo al enviar evento a API");
            }
        }

        Ok(())
    }
}
