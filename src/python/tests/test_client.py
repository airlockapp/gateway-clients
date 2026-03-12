"""Tests for AirlockGatewayClient — all endpoint methods."""

from __future__ import annotations

import httpx
import pytest
import respx

from airlock_gateway.client import AirlockGatewayClient
from airlock_gateway.exceptions import AirlockGatewayError
from airlock_gateway.models import (
    ArtifactSubmitRequest,
    CiphertextRef,
    PairingCompleteRequest,
    PairingInitiateRequest,
    PresenceHeartbeatRequest,
)


# ── Echo ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_echo_returns_server_time(client, mock_api):
    mock_api.get("/echo").respond(
        200,
        json={
            "utc": "2025-01-01T00:00:00Z",
            "local": "2025-01-01T03:00:00+03:00",
            "timezone": "Europe/Istanbul",
            "offsetMinutes": 180,
        },
    )

    result = await client.echo()

    assert result.utc == "2025-01-01T00:00:00Z"
    assert result.timezone == "Europe/Istanbul"
    assert result.offset_minutes == 180


# ── Submit Artifact ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_submit_artifact_posts_envelope(client, mock_api):
    route = mock_api.post("/v1/artifacts").respond(
        202, json={"msgType": "artifact.accepted"}
    )

    request_id = await client.submit_artifact(
        ArtifactSubmitRequest(
            enforcer_id="enforcer-1",
            artifact_hash="abc123",
            ciphertext=CiphertextRef(alg="aes-256-gcm", data="encrypted"),
            request_id="req-test123",
        )
    )

    assert request_id == "req-test123"
    assert route.called
    body = route.calls[0].request.content
    assert b"artifact.submit" in body
    assert b"enforcer-1" in body


@pytest.mark.asyncio
async def test_submit_artifact_generates_request_id(client, mock_api):
    mock_api.post("/v1/artifacts").respond(202, json={})

    request_id = await client.submit_artifact(
        ArtifactSubmitRequest(
            enforcer_id="e1",
            artifact_hash="h1",
            ciphertext=CiphertextRef(alg="aes-256-gcm", data="d"),
        )
    )

    assert request_id.startswith("req-")


@pytest.mark.asyncio
async def test_submit_artifact_raises_on_no_approver(client, mock_api):
    mock_api.post("/v1/artifacts").respond(
        422,
        json={
            "msgType": "error",
            "body": {"code": "no_approver", "message": "No approver available."},
        },
    )

    with pytest.raises(AirlockGatewayError) as exc_info:
        await client.submit_artifact(
            ArtifactSubmitRequest(
                enforcer_id="e1",
                artifact_hash="h1",
                ciphertext=CiphertextRef(alg="aes-256-gcm", data="d"),
            )
        )

    assert exc_info.value.error_code == "no_approver"
    assert exc_info.value.status_code == 422


@pytest.mark.asyncio
async def test_submit_artifact_raises_on_quota_exceeded(client, mock_api):
    mock_api.post("/v1/artifacts").respond(
        429,
        json={
            "msgType": "error",
            "body": {"code": "quota_exceeded", "message": "Monthly quota exceeded"},
        },
    )

    with pytest.raises(AirlockGatewayError) as exc_info:
        await client.submit_artifact(
            ArtifactSubmitRequest(
                enforcer_id="e1",
                artifact_hash="h1",
                ciphertext=CiphertextRef(alg="aes-256-gcm", data="d"),
            )
        )

    assert exc_info.value.is_quota_exceeded


@pytest.mark.asyncio
async def test_submit_artifact_raises_on_conflict(client, mock_api):
    mock_api.post("/v1/artifacts").respond(
        409,
        json={
            "msgType": "error",
            "body": {"code": "AlreadyExistsConflict", "message": "Duplicate"},
        },
    )

    with pytest.raises(AirlockGatewayError) as exc_info:
        await client.submit_artifact(
            ArtifactSubmitRequest(
                enforcer_id="e1",
                artifact_hash="h1",
                ciphertext=CiphertextRef(alg="aes-256-gcm", data="d"),
            )
        )

    assert exc_info.value.is_conflict


# ── Exchange Status ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_exchange_status(client, mock_api):
    mock_api.get("/v1/exchanges/req-1").respond(
        200,
        json={
            "msgType": "exchange.status",
            "requestId": "req-1",
            "body": {"requestId": "req-1", "state": "PendingApproval"},
        },
    )

    result = await client.get_exchange_status("req-1")

    assert result.msg_type == "exchange.status"
    assert result.body is not None
    assert result.body.state == "PendingApproval"


@pytest.mark.asyncio
async def test_get_exchange_status_not_found(client, mock_api):
    mock_api.get("/v1/exchanges/req-x").respond(
        404, json={"error": "NotFound", "message": "Exchange not found"}
    )

    with pytest.raises(AirlockGatewayError) as exc_info:
        await client.get_exchange_status("req-x")

    assert exc_info.value.status_code == 404


# ── Wait for Decision ────────────────────────────────────────────


@pytest.mark.asyncio
async def test_wait_for_decision_returns_decision(client, mock_api):
    mock_api.get("/v1/exchanges/req-1/wait").respond(
        200,
        json={
            "msgId": "msg-1",
            "msgType": "decision.deliver",
            "requestId": "req-1",
            "body": {
                "artifactHash": "abc",
                "decision": "approve",
                "reason": "Looks good",
            },
        },
    )

    result = await client.wait_for_decision("req-1", 30)

    assert result is not None
    assert result.msg_type == "decision.deliver"
    assert result.body is not None
    assert result.body.is_approved
    assert result.body.reason == "Looks good"


@pytest.mark.asyncio
async def test_wait_for_decision_returns_none_on_204(client, mock_api):
    mock_api.get("/v1/exchanges/req-1/wait").respond(204)

    result = await client.wait_for_decision("req-1", 5)

    assert result is None


@pytest.mark.asyncio
async def test_wait_for_decision_clamps_timeout(client, mock_api):
    route = mock_api.get("/v1/exchanges/req-1/wait").respond(204)

    await client.wait_for_decision("req-1", 200)

    assert "timeout=60" in str(route.calls[0].request.url)


# ── Withdraw ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_withdraw_exchange(client, mock_api):
    route = mock_api.post("/v1/exchanges/req-1/withdraw").respond(200, json={})

    await client.withdraw_exchange("req-1")

    assert route.called


@pytest.mark.asyncio
async def test_withdraw_raises_on_conflict(client, mock_api):
    mock_api.post("/v1/exchanges/req-1/withdraw").respond(
        409, json={"body": {"code": "already_resolved"}}
    )

    with pytest.raises(AirlockGatewayError) as exc_info:
        await client.withdraw_exchange("req-1")

    assert exc_info.value.is_conflict


# ── Acknowledge ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_acknowledge(client, mock_api):
    route = mock_api.post("/v1/acks").respond(200, json={})

    await client.acknowledge("msg-123", "enforcer-1")

    assert route.called
    body = route.calls[0].request.content
    assert b"ack.submit" in body
    assert b"msg-123" in body


@pytest.mark.asyncio
async def test_get_effective_dnd_policies(client, mock_api):
    route = mock_api.get("/v1/policy/dnd/effective").respond(
        200,
        json={
            "msgType": "dnd.policy.effective",
            "requestId": "dnd-effective-1",
            "body": [
                {
                    "requestId": "p1",
                    "objectType": "airlock.dnd.workspace",
                    "workspaceId": "ws-1",
                    "enforcerId": "enf-1",
                    "policyMode": "approve_all",
                    "expiresAt": "2099-01-01T00:00:00Z",
                }
            ],
        },
    )

    resp = await client.get_effective_dnd_policies(
        enforcer_id="enf-1", workspace_id="ws-1"
    )

    assert route.called
    assert resp.msg_type == "dnd.policy.effective"
    assert len(resp.body) == 1
    assert resp.body[0].policy_mode == "approve_all"


# ── Pairing ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_initiate_pairing(client, mock_api):
    mock_api.post("/v1/pairing/initiate").respond(
        201,
        json={
            "pairingNonce": "nonce-1",
            "pairingCode": "ABC123",
            "deviceId": "dev-1",
        },
    )

    result = await client.initiate_pairing(
        PairingInitiateRequest(device_id="dev-1", enforcer_id="e-1")
    )

    assert result.pairing_nonce == "nonce-1"
    assert result.pairing_code == "ABC123"


@pytest.mark.asyncio
async def test_resolve_pairing(client, mock_api):
    mock_api.get("/v1/pairing/resolve/ABC123").respond(
        200,
        json={
            "pairingNonce": "nonce-1",
            "deviceId": "dev-1",
            "enforcerLabel": "Cursor",
        },
    )

    result = await client.resolve_pairing("ABC123")

    assert result.pairing_nonce == "nonce-1"
    assert result.enforcer_label == "Cursor"


@pytest.mark.asyncio
async def test_get_pairing_status(client, mock_api):
    mock_api.get("/v1/pairing/nonce-1/status").respond(
        200,
        json={
            "pairingNonce": "nonce-1",
            "state": "Completed",
            "routingToken": "rt-xyz",
        },
    )

    result = await client.get_pairing_status("nonce-1")

    assert result.state == "Completed"
    assert result.routing_token == "rt-xyz"


@pytest.mark.asyncio
async def test_complete_pairing(client, mock_api):
    mock_api.post("/v1/pairing/complete").respond(
        200,
        json={
            "status": "completed",
            "pairingNonce": "nonce-1",
            "routingToken": "rt-xyz",
        },
    )

    result = await client.complete_pairing(
        PairingCompleteRequest(pairing_nonce="nonce-1")
    )

    assert result.status == "completed"
    assert result.routing_token == "rt-xyz"


@pytest.mark.asyncio
async def test_revoke_pairing(client, mock_api):
    mock_api.post("/v1/pairing/revoke").respond(
        200, json={"status": "revoked", "enforcerId": "e-1"}
    )

    result = await client.revoke_pairing("rt-xyz")
    assert result.status == "revoked"


@pytest.mark.asyncio
async def test_get_pairing_status_batch(client, mock_api):
    mock_api.post("/v1/pairing/status-batch").respond(
        200,
        json={"statuses": {"rt-1": "Completed", "rt-2": "Revoked"}},
    )

    result = await client.get_pairing_status_batch(["rt-1", "rt-2"])

    assert result.statuses["rt-1"] == "Completed"
    assert result.statuses["rt-2"] == "Revoked"


@pytest.mark.asyncio
async def test_resolve_pairing_raises_on_expired(client, mock_api):
    mock_api.get("/v1/pairing/resolve/OLD").respond(
        410, json={"error": "expired", "message": "Pairing code expired"}
    )

    with pytest.raises(AirlockGatewayError) as exc_info:
        await client.resolve_pairing("OLD")

    assert exc_info.value.is_expired


# ── Presence ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_send_heartbeat(client, mock_api):
    route = mock_api.post("/v1/presence/heartbeat").respond(200, json={})

    await client.send_heartbeat(
        PresenceHeartbeatRequest(
            enforcer_id="e-1", workspace_name="proj", enforcer_label="Cursor"
        )
    )

    assert route.called


@pytest.mark.asyncio
async def test_list_enforcers(client, mock_api):
    mock_api.get("/v1/presence/enforcers").respond(
        200,
        json=[
            {"enforcerDeviceId": "e1", "status": "online"},
            {"enforcerDeviceId": "e2", "status": "online"},
        ],
    )

    result = await client.list_enforcers()

    assert len(result) == 2
    assert result[0].enforcer_device_id == "e1"


@pytest.mark.asyncio
async def test_get_enforcer_presence(client, mock_api):
    mock_api.get("/v1/presence/enforcers/e1").respond(
        200,
        json={"enforcerDeviceId": "e1", "status": "online", "enforcerLabel": "Cursor"},
    )

    result = await client.get_enforcer_presence("e1")

    assert result.status == "online"
    assert result.enforcer_label == "Cursor"


@pytest.mark.asyncio
async def test_get_enforcer_presence_not_found(client, mock_api):
    mock_api.get("/v1/presence/enforcers/e-unknown").respond(
        404, json={"error": "Not found"}
    )

    with pytest.raises(AirlockGatewayError) as exc_info:
        await client.get_enforcer_presence("e-unknown")

    assert exc_info.value.status_code == 404


# ── Error edge cases ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_raises_on_non_json_error(client, mock_api):
    mock_api.get("/echo").respond(500, text="Internal Server Error")

    with pytest.raises(AirlockGatewayError) as exc_info:
        await client.echo()

    assert exc_info.value.status_code == 500


@pytest.mark.asyncio
async def test_raises_on_unauthorized(client, mock_api):
    mock_api.get("/echo").respond(401, text="")

    with pytest.raises(AirlockGatewayError) as exc_info:
        await client.echo()

    assert exc_info.value.status_code == 401


# ── Context manager ──────────────────────────────────────────────


@pytest.mark.asyncio
async def test_async_context_manager():
    with respx.mock(base_url="https://gw.test") as router:
        router.get("/echo").respond(
            200, json={"utc": "x", "local": "x", "timezone": "Z", "offsetMinutes": 0}
        )

        async with AirlockGatewayClient(
            "https://gw.test", token="test-token"
        ) as client:
            result = await client.echo()
            assert result.timezone == "Z"
