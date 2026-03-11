//! Async HTTP client for the Airlock Gateway API.

use crate::errors::GatewayError;
use crate::models::*;
use reqwest::Client as HttpClient;
use serde_json::json;
use std::collections::HashMap;
use uuid::Uuid;

/// Async client for the Airlock Gateway.
///
/// ```no_run
/// # async fn demo() -> Result<(), airlock_gateway::GatewayError> {
/// let client = airlock_gateway::AirlockGatewayClient::new(
///     "https://gw.example.com",
///     Some("my-bearer-token"),
/// );
/// let request_id = client.submit_artifact(airlock_gateway::ArtifactSubmitRequest {
///     enforcer_id: "e1".into(),
///     artifact_hash: "abc".into(),
///     ciphertext: airlock_gateway::CiphertextRef {
///         alg: "aes-256-gcm".into(), data: "enc".into(),
///         nonce: None, tag: None, aad: None,
///     },
///     artifact_type: None, expires_at: None,
///     metadata: None, request_id: None,
/// }).await?;
/// # Ok(())
/// # }
/// ```
pub struct AirlockGatewayClient {
    base_url: String,
    token: Option<String>,
    http: HttpClient,
}

impl AirlockGatewayClient {
    /// Create a new client.
    pub fn new(base_url: impl Into<String>, token: Option<impl Into<String>>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.map(|t| t.into()),
            http: HttpClient::new(),
        }
    }

    /// Create a new client with a custom reqwest::Client (useful for testing).
    pub fn with_http_client(
        base_url: impl Into<String>,
        token: Option<impl Into<String>>,
        http: HttpClient,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.map(|t| t.into()),
            http,
        }
    }

    // ── Discovery ───────────────────────────────────────────────

    /// GET /echo — Gateway discovery and health.
    pub async fn echo(&self) -> Result<EchoResponse, GatewayError> {
        self.get("/echo").await
    }

    // ── Artifacts ───────────────────────────────────────────────

    /// POST /v1/artifacts — Submit an artifact for approval. Returns the request ID.
    pub async fn submit_artifact(
        &self,
        request: ArtifactSubmitRequest,
    ) -> Result<String, GatewayError> {
        let request_id = request
            .request_id
            .unwrap_or_else(|| format!("req-{}", Uuid::new_v4()));
        let expires_at = request
            .expires_at
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        let artifact_type = request
            .artifact_type
            .unwrap_or_else(|| "command-approval".to_string());

        let envelope = json!({
            "msgId": format!("msg-{}", Uuid::new_v4()),
            "msgType": "artifact.submit",
            "requestId": &request_id,
            "createdAt": chrono::Utc::now().to_rfc3339(),
            "sender": { "enforcerId": &request.enforcer_id },
            "body": {
                "artifactType": artifact_type,
                "artifactHash": &request.artifact_hash,
                "ciphertext": &request.ciphertext,
                "expiresAt": expires_at,
                "metadata": &request.metadata,
            }
        });

        self.post_void("/v1/artifacts", &envelope).await?;
        Ok(request_id)
    }

    // ── Exchanges ───────────────────────────────────────────────

    /// GET /v1/exchanges/{requestId} — Get exchange status.
    pub async fn get_exchange_status(
        &self,
        request_id: &str,
    ) -> Result<ExchangeStatusResponse, GatewayError> {
        self.get(&format!("/v1/exchanges/{}", request_id)).await
    }

    /// GET /v1/exchanges/{requestId}/wait — Long-poll for decision.
    /// Returns None on 204 (no decision yet).
    pub async fn wait_for_decision(
        &self,
        request_id: &str,
        timeout_seconds: u32,
    ) -> Result<Option<DecisionDeliverEnvelope>, GatewayError> {
        let timeout = timeout_seconds.max(1).min(60);
        let url = format!(
            "{}/v1/exchanges/{}/wait?timeout={}",
            self.base_url, request_id, timeout
        );

        let mut req_builder = self.http.get(&url);
        if let Some(token) = &self.token {
            req_builder = req_builder.bearer_auth(token);
        }

        let response = req_builder.send().await?;

        if response.status().as_u16() == 204 {
            return Ok(None);
        }

        let status = response.status().as_u16();
        let body = response.text().await?;
        check_status(status, &body)?;

        let envelope: DecisionDeliverEnvelope = serde_json::from_str(&body)?;
        Ok(Some(envelope))
    }

    /// POST /v1/exchanges/{requestId}/withdraw — Withdraw a pending exchange.
    pub async fn withdraw_exchange(&self, request_id: &str) -> Result<(), GatewayError> {
        self.post_void(
            &format!("/v1/exchanges/{}/withdraw", request_id),
            &json!(null),
        )
        .await
    }

    // ── Acknowledgements ────────────────────────────────────────

    /// POST /v1/acks — Acknowledge an inbox message.
    pub async fn acknowledge(
        &self,
        msg_id: &str,
        enforcer_id: &str,
    ) -> Result<(), GatewayError> {
        let envelope = json!({
            "msgId": format!("msg-{}", Uuid::new_v4()),
            "msgType": "ack.submit",
            "requestId": format!("ack-{}", Uuid::new_v4()),
            "createdAt": chrono::Utc::now().to_rfc3339(),
            "sender": { "enforcerId": enforcer_id },
            "body": {
                "msgId": msg_id,
                "status": "acknowledged",
                "ackAt": chrono::Utc::now().to_rfc3339(),
            }
        });
        self.post_void("/v1/acks", &envelope).await
    }

    // ── Pairing ─────────────────────────────────────────────────

    /// POST /v1/pairing/initiate — Start a new pairing session.
    pub async fn initiate_pairing(
        &self,
        request: &PairingInitiateRequest,
    ) -> Result<PairingInitiateResponse, GatewayError> {
        self.post_json("/v1/pairing/initiate", request).await
    }

    /// GET /v1/pairing/resolve/{code} — Resolve a pairing code.
    pub async fn resolve_pairing(
        &self,
        code: &str,
    ) -> Result<PairingResolveResponse, GatewayError> {
        self.get(&format!("/v1/pairing/resolve/{}", code)).await
    }

    /// GET /v1/pairing/{nonce}/status — Poll pairing status.
    pub async fn get_pairing_status(
        &self,
        nonce: &str,
    ) -> Result<PairingStatusResponse, GatewayError> {
        self.get(&format!("/v1/pairing/{}/status", nonce)).await
    }

    /// POST /v1/pairing/complete — Complete pairing from approver side.
    pub async fn complete_pairing(
        &self,
        request: &PairingCompleteRequest,
    ) -> Result<PairingCompleteResponse, GatewayError> {
        self.post_json("/v1/pairing/complete", request).await
    }

    /// POST /v1/pairing/revoke — Revoke a pairing.
    pub async fn revoke_pairing(
        &self,
        routing_token: &str,
    ) -> Result<PairingRevokeResponse, GatewayError> {
        self.post_json("/v1/pairing/revoke", &json!({"routingToken": routing_token}))
            .await
    }

    /// POST /v1/pairing/status-batch — Batch check pairing statuses.
    pub async fn get_pairing_status_batch(
        &self,
        routing_tokens: &[String],
    ) -> Result<PairingStatusBatchResponse, GatewayError> {
        self.post_json(
            "/v1/pairing/status-batch",
            &json!({"routingTokens": routing_tokens}),
        )
        .await
    }

    // ── Presence ────────────────────────────────────────────────

    /// POST /v1/presence/heartbeat — Send a presence heartbeat.
    pub async fn send_heartbeat(
        &self,
        request: &PresenceHeartbeatRequest,
    ) -> Result<(), GatewayError> {
        self.post_void("/v1/presence/heartbeat", request).await
    }

    /// GET /v1/presence/enforcers — List online enforcers.
    pub async fn list_enforcers(&self) -> Result<Vec<EnforcerPresenceRecord>, GatewayError> {
        self.get("/v1/presence/enforcers").await
    }

    /// GET /v1/presence/enforcers/{id} — Get a single enforcer's presence.
    pub async fn get_enforcer_presence(
        &self,
        enforcer_device_id: &str,
    ) -> Result<EnforcerPresenceRecord, GatewayError> {
        self.get(&format!("/v1/presence/enforcers/{}", enforcer_device_id))
            .await
    }

    // ── HTTP Helpers ────────────────────────────────────────────

    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, GatewayError> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.get(&url);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }

        let response = req.send().await?;
        let status = response.status().as_u16();
        let body = response.text().await?;
        check_status(status, &body)?;
        Ok(serde_json::from_str(&body)?)
    }

    async fn post_void(
        &self,
        path: &str,
        payload: &impl serde::Serialize,
    ) -> Result<(), GatewayError> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.post(&url).json(payload);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }

        let response = req.send().await?;
        let status = response.status().as_u16();
        let body = response.text().await?;
        check_status(status, &body)?;
        Ok(())
    }

    async fn post_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        payload: &impl serde::Serialize,
    ) -> Result<T, GatewayError> {
        let url = format!("{}{}", self.base_url, path);
        let mut req = self.http.post(&url).json(payload);
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }

        let response = req.send().await?;
        let status = response.status().as_u16();
        let body = response.text().await?;
        check_status(status, &body)?;
        Ok(serde_json::from_str(&body)?)
    }
}

fn check_status(status: u16, body: &str) -> Result<(), GatewayError> {
    if (200..300).contains(&status) {
        return Ok(());
    }

    let mut error_code = None;
    let mut error_message = None;
    let mut request_id = None;

    if let Ok(data) = serde_json::from_str::<serde_json::Value>(body) {
        // HARP error envelope: { body: { code, message, requestId } }
        if let Some(body_obj) = data.get("body").and_then(|b| b.as_object()) {
            error_code = body_obj
                .get("code")
                .and_then(|v| v.as_str())
                .map(String::from);
            error_message = body_obj
                .get("message")
                .and_then(|v| v.as_str())
                .map(String::from);
            request_id = body_obj
                .get("requestId")
                .and_then(|v| v.as_str())
                .map(String::from);
        } else {
            error_code = data
                .get("error")
                .and_then(|v| v.as_str())
                .map(String::from);
            error_message = data
                .get("message")
                .and_then(|v| v.as_str())
                .map(String::from);
        }
    }

    Err(GatewayError::Api {
        status_code: status,
        error_code,
        message: error_message.unwrap_or_else(|| format!("Gateway returned {}", status)),
        response_body: Some(body.to_string()),
        request_id,
    })
}
