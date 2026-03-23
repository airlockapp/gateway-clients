//! Data models for the Airlock Gateway wire protocol.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── HARP Envelope ────────────────────────────────────────────────

/// Sender information in a HARP envelope.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SenderInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approver_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_id: Option<String>,
}

/// Recipient information in a HARP envelope.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RecipientInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approver_id: Option<String>,
}

/// HARP Gateway Wire Envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarpEnvelope {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg_id: Option<String>,
    pub msg_type: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<SenderInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<RecipientInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<serde_json::Value>,
}

// ── Artifact Submit ─────────────────────────────────────────────

use crate::crypto::EncryptedPayload;

/// Body of an artifact.submit envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactSubmitBody {
    pub artifact_type: String,
    pub artifact_hash: String,
    pub ciphertext: EncryptedPayload,
    pub expires_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<HashMap<String, String>>,
}

/// Options for building an artifact submission request.
#[derive(Debug, Clone)]
pub struct ArtifactSubmitRequest {
    pub enforcer_id: String,
    pub artifact_type: Option<String>,
    pub artifact_hash: String,
    pub ciphertext: EncryptedPayload,
    pub expires_at: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
    pub request_id: Option<String>,
}

/// Options for encrypt-and-submit: JCS canonicalize → SHA-256 → AES-256-GCM → [`submit_artifact`](crate::AirlockGatewayClient::submit_artifact).
#[derive(Debug, Clone)]
pub struct EncryptedArtifactRequest {
    pub enforcer_id: String,
    pub artifact_type: Option<String>,
    pub plaintext_payload: String,
    pub encryption_key_base64url: String,
    pub expires_at: Option<String>,
    pub metadata: Option<HashMap<String, String>>,
    pub request_id: Option<String>,
}

// ── Decision ────────────────────────────────────────────────────

/// Body of a decision.deliver envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionDeliverBody {
    pub artifact_hash: String,
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision_hash: Option<String>,
}

impl DecisionDeliverBody {
    /// True if the decision is "approve".
    pub fn is_approved(&self) -> bool {
        self.decision.eq_ignore_ascii_case("approve")
    }

    /// True if the decision is "reject".
    pub fn is_rejected(&self) -> bool {
        self.decision.eq_ignore_ascii_case("reject")
    }
}

/// Envelope wrapping a decision.deliver response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionDeliverEnvelope {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub msg_id: Option<String>,
    pub msg_type: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<DecisionDeliverBody>,
}

// ── Exchange Status ─────────────────────────────────────────────

/// Body of an exchange.status response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeStatusBody {
    pub request_id: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<serde_json::Value>,
}

/// GET /v1/exchanges/{id} response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeStatusResponse {
    pub msg_type: String,
    pub request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<ExchangeStatusBody>,
}

// ── Pairing ─────────────────────────────────────────────────────

/// POST /v1/pairing/initiate request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingInitiateRequest {
    pub device_id: String,
    pub enforcer_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x25519_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcer_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_name: Option<String>,
}

/// POST /v1/pairing/initiate response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingInitiateResponse {
    pub pairing_nonce: String,
    pub pairing_code: String,
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// GET /v1/pairing/{nonce}/status response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingStatusResponse {
    pub pairing_nonce: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// POST /v1/pairing/revoke response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingRevokeResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcer_id: Option<String>,
}

/// POST /v1/pairing/claim request body.
/// Used to claim a pre-generated pairing code created by the approver.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingClaimRequest {
    pub pairing_code: String,
    pub device_id: String,
    pub enforcer_id: String,
    pub enforcer_label: String,
    pub workspace_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x25519_public_key: Option<String>,
}

/// POST /v1/pairing/claim response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingClaimResponse {
    pub pairing_nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

// ── Presence ────────────────────────────────────────────────────

/// POST /v1/presence/heartbeat request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PresenceHeartbeatRequest {
    pub enforcer_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcer_label: Option<String>,
}

// ── Echo ────────────────────────────────────────────────────────

/// GET /echo response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EchoResponse {
    pub utc: String,
    pub local: String,
    pub timezone: String,
    pub offset_minutes: i32,
}

// ── DND (Do Not Disturb) Policies ────────────────────────────────

/// DND policy object as returned by the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DndPolicy {
    pub request_id: String,
    pub object_type: String,
    pub workspace_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub enforcer_id: String,
    pub policy_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_artifact_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_selector: Option<HashMap<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selector_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    pub expires_at: String,
}

/// GET /v1/policy/dnd/effective response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DndEffectiveResponse {
    pub msg_type: String,
    pub request_id: String,
    pub body: Vec<DndPolicy>,
}

// ── Auth (Device Authorization Grant) ───────────────────────────

/// Essential OIDC discovery endpoints
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscoveryResult {
    pub token_endpoint: String,
    pub device_authorization_endpoint: String,
    #[serde(default)]
    pub revocation_endpoint: String,
    pub authorization_endpoint: String,
}

/// Start of DeviceAuth flow payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodeInfo {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: i32,
    pub interval: Option<i32>,
}

/// Token returned by OIDC
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i32,
    #[serde(default)]
    pub scope: String,
}

/// Extracted consent error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsentErrorInfo {
    pub error: String,
    pub message: String,
    pub consent_url: Option<String>,
    pub app_name: Option<String>,
    pub app_id: Option<String>,
}

// ── Auth Code + PKCE ───────────────────────────────────────────────

/// Result of building an authorization URL for the Auth Code + PKCE flow.
#[derive(Debug, Clone)]
pub struct AuthCodeRequest {
    pub authorization_url: String,
    pub state: String,
    pub code_verifier: String,
    pub redirect_uri: String,
}
