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

/// Encrypted payload reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiphertextRef {
    pub alg: String,
    pub data: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad: Option<String>,
}

/// Body of an artifact.submit envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ArtifactSubmitBody {
    pub artifact_type: String,
    pub artifact_hash: String,
    pub ciphertext: CiphertextRef,
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
    pub ciphertext: CiphertextRef,
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

// ── Ack ─────────────────────────────────────────────────────────

/// Body of an ack.submit envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AckSubmitBody {
    pub msg_id: String,
    pub status: String,
    pub ack_at: String,
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

/// GET /v1/pairing/resolve/{code} response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingResolveResponse {
    pub pairing_nonce: String,
    pub device_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x25519_public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcer_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_name: Option<String>,
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

/// POST /v1/pairing/complete request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingCompleteRequest {
    pub pairing_nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_json: Option<String>,
}

/// POST /v1/pairing/complete response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingCompleteResponse {
    pub status: String,
    pub pairing_nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing_token: Option<String>,
}

/// POST /v1/pairing/revoke response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingRevokeResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcer_id: Option<String>,
}

/// POST /v1/pairing/status-batch response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingStatusBatchResponse {
    pub statuses: HashMap<String, String>,
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

/// An enforcer's presence record.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnforcerPresenceRecord {
    pub enforcer_device_id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<HashMap<String, String>>,
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
