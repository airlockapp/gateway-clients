"""Tests for model serialization and validation."""

from __future__ import annotations

import json

import pytest

from airlock_gateway.models import (
    ArtifactSubmitRequest,
    CiphertextRef,
    DecisionDeliverBody,
    EchoResponse,
    HarpEnvelope,
    PairingInitiateRequest,
    PresenceHeartbeatRequest,
    SenderInfo,
)


def test_harp_envelope_round_trips():
    envelope = HarpEnvelope(
        msg_id="msg-1",
        msg_type="artifact.submit",
        request_id="req-1",
        sender=SenderInfo(enforcer_id="e1"),
    )

    data = envelope.model_dump(by_alias=True, exclude_none=True)
    restored = HarpEnvelope.model_validate(data)

    assert restored.msg_id == "msg-1"
    assert restored.msg_type == "artifact.submit"
    assert restored.sender is not None
    assert restored.sender.enforcer_id == "e1"


def test_harp_envelope_from_camel_case_json():
    raw = '{"msgId":"m1","msgType":"test","requestId":"r1","sender":{"enforcerId":"e1"}}'
    envelope = HarpEnvelope.model_validate_json(raw)

    assert envelope.msg_id == "m1"
    assert envelope.msg_type == "test"


def test_artifact_submit_body_all_fields():
    body = ArtifactSubmitRequest(
        enforcer_id="e1",
        artifact_type="command-approval",
        artifact_hash="hash123",
        ciphertext=CiphertextRef(
            alg="aes-256-gcm", data="enc", nonce="n1", tag="t1", aad="a1"
        ),
        metadata={"routingToken": "rt-1"},
    )

    data = body.model_dump(by_alias=True, exclude_none=True)
    assert data["artifactType"] == "command-approval"
    assert data["artifactHash"] == "hash123"
    assert data["ciphertext"]["alg"] == "aes-256-gcm"
    assert data["metadata"]["routingToken"] == "rt-1"


def test_artifact_submit_nullable_metadata():
    body = ArtifactSubmitRequest(
        enforcer_id="e1",
        artifact_hash="h1",
        ciphertext=CiphertextRef(alg="aes-256-gcm", data="d"),
    )

    data = body.model_dump(by_alias=True, exclude_none=True)
    assert "metadata" not in data


def test_decision_deliver_body_helpers():
    approve = DecisionDeliverBody(decision="approve")
    assert approve.is_approved
    assert not approve.is_rejected

    reject = DecisionDeliverBody(decision="reject")
    assert not reject.is_approved
    assert reject.is_rejected

    upper = DecisionDeliverBody(decision="APPROVE")
    assert upper.is_approved


def test_decision_deliver_body_round_trips():
    body = DecisionDeliverBody(
        artifact_hash="h1",
        decision="approve",
        reason="Safe",
        signer_key_id="key-1",
        nonce="n1",
        signature="sig1",
    )

    data = body.model_dump(by_alias=True)
    restored = DecisionDeliverBody.model_validate(data)

    assert restored.artifact_hash == "h1"
    assert restored.decision == "approve"
    assert restored.reason == "Safe"
    assert restored.signer_key_id == "key-1"


def test_pairing_initiate_request_serializes():
    request = PairingInitiateRequest(
        device_id="dev-1",
        enforcer_id="e-1",
        enforcer_label="Cursor",
        workspace_name="my-project",
    )

    data = request.model_dump(by_alias=True, exclude_none=True)
    assert data["deviceId"] == "dev-1"
    assert data["enforcerId"] == "e-1"
    assert data["enforcerLabel"] == "Cursor"


def test_echo_response_deserializes():
    raw = '{"utc":"2025-01-01T00:00:00Z","local":"x","timezone":"Europe/Istanbul","offsetMinutes":180}'
    result = EchoResponse.model_validate_json(raw)

    assert result.timezone == "Europe/Istanbul"
    assert result.offset_minutes == 180


def test_presence_heartbeat_round_trips():
    request = PresenceHeartbeatRequest(
        enforcer_id="e-1", workspace_name="proj", enforcer_label="Agent"
    )

    data = request.model_dump(by_alias=True)
    assert data["enforcerId"] == "e-1"

    restored = PresenceHeartbeatRequest.model_validate(data)
    assert restored.enforcer_id == "e-1"


