//! Async HTTP client for the Airlock Integrations Gateway API.

use crate::errors::GatewayError;
use crate::models::*;
use reqwest::Client as HttpClient;
use serde_json::json;
use uuid::Uuid;

/// Async client for the Airlock Integrations Gateway.
///
/// Supports both Bearer token and enforcer app (ClientId/ClientSecret) auth.
///
/// ```no_run
/// # async fn demo() -> Result<(), airlock_gateway::GatewayError> {
/// let client = airlock_gateway::AirlockGatewayClient::new(
///     "https://igw.example.com",
///     Some("my-bearer-token"),
/// );
/// let echo = client.echo().await?;
/// # Ok(())
/// # }
/// ```
pub struct AirlockGatewayClient {
    base_url: String,
    token: Option<String>,
    pat: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    http: HttpClient,
}

impl AirlockGatewayClient {
    /// Create a new client with Bearer token auth.
    pub fn new(base_url: impl Into<String>, token: Option<impl Into<String>>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: token.map(|t| t.into()),
            pat: None,
            client_id: None,
            client_secret: None,
            http: HttpClient::new(),
        }
    }

    /// Create a new client with enforcer app (ClientId/ClientSecret) auth.
    pub fn with_credentials(
        base_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: None,
            pat: None,
            client_id: Some(client_id.into()),
            client_secret: Some(client_secret.into()),
            http: HttpClient::new(),
        }
    }

    /// Set (or clear) the user Bearer token for dual-auth scenarios.
    pub fn set_bearer_token(&mut self, token: Option<impl Into<String>>) {
        self.token = token.map(|t| t.into());
    }

    /// Set (or clear) the Personal Access Token (PAT).
    /// PAT is the recommended user identity — sends X-PAT header.
    pub fn set_pat(&mut self, pat: Option<impl Into<String>>) {
        self.pat = pat.map(|t| t.into());
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
            pat: None,
            client_id: None,
            client_secret: None,
            http,
        }
    }

    /// Create a new client with enforcer app credentials AND a custom reqwest::Client.
    /// Useful for self-signed certificate scenarios in development.
    pub fn with_credentials_and_http_client(
        base_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        http: HttpClient,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            token: None,
            pat: None,
            client_id: Some(client_id.into()),
            client_secret: Some(client_secret.into()),
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
        req_builder = self.apply_auth(req_builder);

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

    // ── Pairing ─────────────────────────────────────────────────

    /// POST /v1/pairing/initiate — Start a new pairing session.
    pub async fn initiate_pairing(
        &self,
        request: &PairingInitiateRequest,
    ) -> Result<PairingInitiateResponse, GatewayError> {
        self.post_json("/v1/pairing/initiate", request).await
    }

    /// GET /v1/pairing/{nonce}/status — Poll pairing status.
    pub async fn get_pairing_status(
        &self,
        nonce: &str,
    ) -> Result<PairingStatusResponse, GatewayError> {
        self.get(&format!("/v1/pairing/{}/status", nonce)).await
    }

    /// POST /v1/pairing/revoke — Revoke a pairing.
    pub async fn revoke_pairing(
        &self,
        routing_token: &str,
    ) -> Result<PairingRevokeResponse, GatewayError> {
        self.post_json("/v1/pairing/revoke", &json!({"routingToken": routing_token}))
            .await
    }

    /// POST /v1/pairing/claim — Claim a pre-generated pairing code.
    pub async fn claim_pairing(
        &self,
        request: &PairingClaimRequest,
    ) -> Result<PairingClaimResponse, GatewayError> {
        self.post_json("/v1/pairing/claim", request).await
    }

    // ── Presence ────────────────────────────────────────────────

    /// POST /v1/presence/heartbeat — Send a presence heartbeat.
    pub async fn send_heartbeat(
        &self,
        request: &PresenceHeartbeatRequest,
    ) -> Result<(), GatewayError> {
        self.post_void("/v1/presence/heartbeat", request).await
    }

    // ── DND (Do Not Disturb) Policies ────────────────────────────

    /// GET /v1/policy/dnd/effective — Fetch effective DND policies.
    pub async fn get_effective_dnd_policies(
        &self,
        enforcer_id: &str,
        workspace_id: &str,
        session_id: Option<&str>,
    ) -> Result<DndEffectiveResponse, GatewayError> {
        let mut params = vec![
            ("enforcerId", enforcer_id.to_string()),
            ("workspaceId", workspace_id.to_string()),
        ];
        if let Some(sid) = session_id {
            params.push(("sessionId", sid.to_string()));
        }

        let query: String = params
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join("&");

        self.get(&format!("/v1/policy/dnd/effective?{}", query)).await
    }

    // ── Consent ─────────────────────────────────────────────────

    /// GET /v1/consent/status — Check if the user has consented to this enforcer app.
    /// Returns the consent status string (e.g. "approved").
    /// Returns GatewayError with error_code "app_consent_required", "app_consent_pending",
    /// or "app_consent_denied" if consent is not granted.
    pub async fn check_consent(&self) -> Result<String, GatewayError> {
        let resp: serde_json::Value = self.get("/v1/consent/status").await?;
        Ok(resp.get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string())
    }

    // ── HTTP Helpers ────────────────────────────────────────────

    fn apply_auth(&self, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(pat) = &self.pat {
            req = req.header("X-PAT", pat);
        }
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        if let Some(client_id) = &self.client_id {
            req = req.header("X-Client-Id", client_id);
        }
        if let Some(client_secret) = &self.client_secret {
            req = req.header("X-Client-Secret", client_secret);
        }
        req
    }

    async fn get<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, GatewayError> {
        let url = format!("{}{}", self.base_url, path);
        let req = self.apply_auth(self.http.get(&url));

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
        let req = self.apply_auth(self.http.post(&url).json(payload));

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
        let req = self.apply_auth(self.http.post(&url).json(payload));

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
