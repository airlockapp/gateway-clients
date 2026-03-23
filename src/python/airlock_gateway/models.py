"""Pydantic models for the Airlock Gateway wire protocol."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# ── HARP Envelope ────────────────────────────────────────────────


class SenderInfo(BaseModel):
    enforcer_id: Optional[str] = Field(None, alias="enforcerId")
    approver_id: Optional[str] = Field(None, alias="approverId")
    gateway_id: Optional[str] = Field(None, alias="gatewayId")

    model_config = {"populate_by_name": True}


class RecipientInfo(BaseModel):
    enforcer_id: Optional[str] = Field(None, alias="enforcerId")
    approver_id: Optional[str] = Field(None, alias="approverId")

    model_config = {"populate_by_name": True}


class HarpEnvelope(BaseModel):
    msg_id: Optional[str] = Field(None, alias="msgId")
    msg_type: str = Field(..., alias="msgType")
    request_id: str = Field(..., alias="requestId")
    created_at: Optional[datetime] = Field(None, alias="createdAt")
    expires_at: Optional[datetime] = Field(None, alias="expiresAt")
    sender: Optional[SenderInfo] = None
    recipient: Optional[RecipientInfo] = None
    body: Optional[Any] = None

    model_config = {"populate_by_name": True}


# ── Artifact Submit ──────────────────────────────────────────────


class EncryptedPayload(BaseModel):
    alg: str = ""
    data: str = ""
    nonce: Optional[str] = None
    tag: Optional[str] = None
    aad: Optional[str] = None


class ArtifactSubmitRequest(BaseModel):
    """Options for building an artifact submission request."""

    enforcer_id: str = Field(..., alias="enforcerId")
    artifact_type: str = Field("command-approval", alias="artifactType")
    artifact_hash: str = Field(..., alias="artifactHash")
    ciphertext: EncryptedPayload
    expires_at: Optional[datetime] = Field(None, alias="expiresAt")
    metadata: Optional[Dict[str, str]] = None
    request_id: Optional[str] = Field(None, alias="requestId")

    model_config = {"populate_by_name": True}


class EncryptedArtifactRequest(BaseModel):
    """Plaintext JSON to encrypt (JCS + SHA-256 + AES-256-GCM) then submit."""

    enforcer_id: str = Field(..., alias="enforcerId")
    artifact_type: str = Field("command-approval", alias="artifactType")
    plaintext_payload: str = Field(..., alias="plaintextPayload")
    encryption_key_base64url: str = Field(..., alias="encryptionKeyBase64Url")
    expires_at: Optional[datetime] = Field(None, alias="expiresAt")
    metadata: Optional[Dict[str, str]] = None
    request_id: Optional[str] = Field(None, alias="requestId")

    model_config = {"populate_by_name": True}


# ── Decision ─────────────────────────────────────────────────────


class DecisionDeliverBody(BaseModel):
    artifact_hash: str = Field("", alias="artifactHash")
    decision: str = ""
    reason: Optional[str] = None
    signer_key_id: Optional[str] = Field(None, alias="signerKeyId")
    nonce: Optional[str] = None
    signature: Optional[str] = None
    decision_hash: Optional[str] = Field(None, alias="decisionHash")

    model_config = {"populate_by_name": True}

    @property
    def is_approved(self) -> bool:
        return self.decision.lower() == "approve"

    @property
    def is_rejected(self) -> bool:
        return self.decision.lower() == "reject"


# ── Exchange Status ──────────────────────────────────────────────


class ExchangeStatusBody(BaseModel):
    request_id: str = Field("", alias="requestId")
    state: str = ""
    created_at: Optional[datetime] = Field(None, alias="createdAt")
    expires_at: Optional[datetime] = Field(None, alias="expiresAt")
    artifact_hash: Optional[str] = Field(None, alias="artifactHash")
    decision: Optional[Any] = None

    model_config = {"populate_by_name": True}


class ExchangeStatusResponse(BaseModel):
    msg_type: str = Field("", alias="msgType")
    request_id: str = Field("", alias="requestId")
    body: Optional[ExchangeStatusBody] = None

    model_config = {"populate_by_name": True}


class DecisionDeliverEnvelope(BaseModel):
    msg_id: Optional[str] = Field(None, alias="msgId")
    msg_type: str = Field("", alias="msgType")
    request_id: str = Field("", alias="requestId")
    body: Optional[DecisionDeliverBody] = None

    model_config = {"populate_by_name": True}


# ── Pairing ──────────────────────────────────────────────────────


class PairingInitiateRequest(BaseModel):
    device_id: str = Field(..., alias="deviceId")
    enforcer_id: str = Field(..., alias="enforcerId")
    gateway_url: Optional[str] = Field(None, alias="gatewayUrl")
    x25519_public_key: Optional[str] = Field(None, alias="x25519PublicKey")
    enforcer_label: Optional[str] = Field(None, alias="enforcerLabel")
    workspace_name: Optional[str] = Field(None, alias="workspaceName")

    model_config = {"populate_by_name": True}


class PairingInitiateResponse(BaseModel):
    pairing_nonce: str = Field("", alias="pairingNonce")
    pairing_code: str = Field("", alias="pairingCode")
    device_id: str = Field("", alias="deviceId")
    gateway_url: Optional[str] = Field(None, alias="gatewayUrl")
    expires_at: Optional[datetime] = Field(None, alias="expiresAt")

    model_config = {"populate_by_name": True}


class PairingStatusResponse(BaseModel):
    pairing_nonce: str = Field("", alias="pairingNonce")
    state: str = ""
    response_json: Optional[str] = Field(None, alias="responseJson")
    routing_token: Optional[str] = Field(None, alias="routingToken")
    expires_at: Optional[datetime] = Field(None, alias="expiresAt")

    model_config = {"populate_by_name": True}


class PairingRevokeResponse(BaseModel):
    status: str = ""
    enforcer_id: Optional[str] = Field(None, alias="enforcerId")

    model_config = {"populate_by_name": True}


class PairingClaimRequest(BaseModel):
    """Request for POST /v1/pairing/claim — claim a pre-generated pairing code."""

    pairing_code: str = Field(..., alias="pairingCode")
    device_id: str = Field(..., alias="deviceId")
    enforcer_id: str = Field(..., alias="enforcerId")
    enforcer_label: str = Field(..., alias="enforcerLabel")
    workspace_name: str = Field(..., alias="workspaceName")
    gateway_url: Optional[str] = Field(None, alias="gatewayUrl")
    x25519_public_key: Optional[str] = Field(None, alias="x25519PublicKey")

    model_config = {"populate_by_name": True}


class PairingClaimResponse(BaseModel):
    """Response from POST /v1/pairing/claim."""

    pairing_nonce: str = Field("", alias="pairingNonce")
    expires_at: Optional[datetime] = Field(None, alias="expiresAt")

    model_config = {"populate_by_name": True}


# ── Presence ─────────────────────────────────────────────────────


class PresenceHeartbeatRequest(BaseModel):
    enforcer_id: str = Field(..., alias="enforcerId")
    workspace_name: Optional[str] = Field(None, alias="workspaceName")
    enforcer_label: Optional[str] = Field(None, alias="enforcerLabel")

    model_config = {"populate_by_name": True}


# ── Echo ─────────────────────────────────────────────────────────


class EchoResponse(BaseModel):
    utc: str = ""
    local: str = ""
    timezone: str = ""
    offset_minutes: int = Field(0, alias="offsetMinutes")

    model_config = {"populate_by_name": True}


# ── DND (Do Not Disturb) Policies ─────────────────────────────────


class DndPolicyWire(BaseModel):
    """DND policy object as returned by the gateway."""

    request_id: str = Field(..., alias="requestId")
    object_type: str = Field(..., alias="objectType")
    workspace_id: str = Field(..., alias="workspaceId")
    session_id: Optional[str] = Field(None, alias="sessionId")
    enforcer_id: str = Field(..., alias="enforcerId")
    policy_mode: str = Field(..., alias="policyMode")
    target_artifact_type: Optional[str] = Field(
        None, alias="targetArtifactType"
    )
    action_selector: Optional[Dict[str, Any]] = Field(
        None, alias="actionSelector"
    )
    selector_hash: Optional[str] = Field(None, alias="selectorHash")
    created_at: Optional[datetime] = Field(None, alias="createdAt")
    expires_at: datetime = Field(..., alias="expiresAt")

    model_config = {"populate_by_name": True}


class DndEffectiveResponse(BaseModel):
    """Response for GET /v1/policy/dnd/effective."""

    msg_type: str = Field("", alias="msgType")
    request_id: str = Field("", alias="requestId")
    body: List[DndPolicyWire] = []

    model_config = {"populate_by_name": True}


# ── Auth (Device Authorization Grant) ────────────────────────────


class DeviceCodeInfo:
    def __init__(self, data: Dict[str, Any]):
        self.device_code: str = data.get("device_code", "")
        self.user_code: str = data.get("user_code", "")
        self.verification_uri: str = data.get("verification_uri", "")
        self.verification_uri_complete: Optional[str] = data.get("verification_uri_complete")
        self.expires_in: int = data.get("expires_in", 600)
        self.interval: int = data.get("interval", 5)


class TokenResponse:
    def __init__(self, data: Dict[str, Any]):
        self.access_token: str = data.get("access_token", "")
        self.refresh_token: str = data.get("refresh_token", "")
        self.token_type: str = data.get("token_type", "")
        self.expires_in: int = data.get("expires_in", 0)
        self.scope: str = data.get("scope", "")


class ConsentErrorInfo:
    def __init__(self, data: Dict[str, Any]):
        self.error: str = data.get("error", "")
        self.message: Optional[str] = data.get("message")
        self.consent_url: Optional[str] = data.get("consentUrl")
        self.app_name: Optional[str] = data.get("appName")
        self.app_id: Optional[str] = data.get("appId")
