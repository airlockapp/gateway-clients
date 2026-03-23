"""Async HTTP client for the Airlock Integrations Gateway API."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from airlock_gateway.exceptions import AirlockGatewayError
from airlock_gateway.models import (
    ArtifactSubmitRequest,
    DecisionDeliverEnvelope,
    DndEffectiveResponse,
    EchoResponse,
    ExchangeStatusResponse,
    PairingClaimRequest,
    PairingClaimResponse,
    PairingInitiateRequest,
    PairingInitiateResponse,
    PairingRevokeResponse,
    PairingStatusResponse,
    PresenceHeartbeatRequest,
)


class AirlockGatewayClient:
    """
    Async HTTP client for the Airlock Integrations Gateway.

    Supports both Bearer token and enforcer app (ClientId/ClientSecret) auth.

    Usage with Bearer token::

        async with AirlockGatewayClient("https://igw.example.com", token="...") as client:
            request_id = await client.submit_artifact(request)
            decision = await client.wait_for_decision(request_id)

    Usage with ClientId/ClientSecret::

        async with AirlockGatewayClient(
            "https://igw.example.com",
            client_id="my-client-id",
            client_secret="my-client-secret",
        ) as client:
            echo = await client.echo()
    """

    def __init__(
        self,
        base_url: str,
        *,
        token: Optional[str] = None,
        pat: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        timeout: float = 90.0,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        headers: Dict[str, str] = {}
        if pat:
            headers["X-PAT"] = pat
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if client_id:
            headers["X-Client-Id"] = client_id
        if client_secret:
            headers["X-Client-Secret"] = client_secret

        if http_client is not None:
            self._client = http_client
            self._owns_client = False
        else:
            self._client = httpx.AsyncClient(
                base_url=base_url.rstrip("/"),
                headers=headers,
                timeout=timeout,
            )
            self._owns_client = True

    async def __aenter__(self) -> "AirlockGatewayClient":
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()

    async def close(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    def set_bearer_token(self, token: Optional[str] = None) -> None:
        """Set (or clear) the user Bearer token for dual-auth scenarios."""
        if token:
            self._client.headers["Authorization"] = f"Bearer {token}"
        else:
            self._client.headers.pop("Authorization", None)

    def set_pat(self, pat: Optional[str] = None) -> None:
        """Set (or clear) the Personal Access Token (PAT).

        PAT is the recommended user identity — sends X-PAT header.
        """
        if pat:
            self._client.headers["X-PAT"] = pat
        else:
            self._client.headers.pop("X-PAT", None)

    # ── Discovery ────────────────────────────────────────────────

    async def echo(self) -> EchoResponse:
        """GET /echo — Gateway discovery and health."""
        data = await self._get("/echo")
        return EchoResponse.model_validate(data)

    # ── Artifacts ────────────────────────────────────────────────

    async def submit_artifact(self, request: ArtifactSubmitRequest) -> str:
        """POST /v1/artifacts — Submit an artifact for approval.

        Returns the request ID.
        """
        request_id = request.request_id or f"req-{uuid.uuid4().hex}"
        expires_at = request.expires_at or datetime.now(timezone.utc)

        envelope = {
            "msgId": f"msg-{uuid.uuid4().hex}",
            "msgType": "artifact.submit",
            "requestId": request_id,
            "createdAt": datetime.now(timezone.utc).isoformat(),
            "sender": {"enforcerId": request.enforcer_id},
            "body": {
                "artifactType": request.artifact_type,
                "artifactHash": request.artifact_hash,
                "ciphertext": request.ciphertext.model_dump(by_alias=False),
                "expiresAt": expires_at.isoformat(),
                "metadata": request.metadata,
            },
        }

        await self._post("/v1/artifacts", envelope)
        return request_id

    # ── Exchanges ────────────────────────────────────────────────

    async def get_exchange_status(self, request_id: str) -> ExchangeStatusResponse:
        """GET /v1/exchanges/{requestId} — Get exchange status."""
        data = await self._get(f"/v1/exchanges/{request_id}")
        return ExchangeStatusResponse.model_validate(data)

    async def wait_for_decision(
        self, request_id: str, timeout_seconds: int = 30
    ) -> Optional[DecisionDeliverEnvelope]:
        """GET /v1/exchanges/{requestId}/wait — Long-poll for decision.

        Returns the decision envelope, or None on timeout (204).
        """
        timeout_seconds = max(1, min(60, timeout_seconds))
        url = f"/v1/exchanges/{request_id}/wait?timeout={timeout_seconds}"

        response = await self._client.get(url)

        if response.status_code == 204:
            return None

        self._raise_for_status(response)
        return DecisionDeliverEnvelope.model_validate(response.json())

    async def withdraw_exchange(self, request_id: str) -> None:
        """POST /v1/exchanges/{requestId}/withdraw — Withdraw a pending exchange."""
        await self._post(f"/v1/exchanges/{request_id}/withdraw", None)

    # ── Pairing ──────────────────────────────────────────────────

    async def initiate_pairing(
        self, request: PairingInitiateRequest
    ) -> PairingInitiateResponse:
        """POST /v1/pairing/initiate — Start a new pairing session."""
        data = await self._post_json(
            "/v1/pairing/initiate",
            request.model_dump(by_alias=True, exclude_none=True),
        )
        return PairingInitiateResponse.model_validate(data)

    async def get_pairing_status(self, nonce: str) -> PairingStatusResponse:
        """GET /v1/pairing/{nonce}/status — Poll pairing status."""
        data = await self._get(f"/v1/pairing/{nonce}/status")
        return PairingStatusResponse.model_validate(data)

    async def revoke_pairing(self, routing_token: str) -> PairingRevokeResponse:
        """POST /v1/pairing/revoke — Revoke a pairing."""
        data = await self._post_json(
            "/v1/pairing/revoke", {"routingToken": routing_token}
        )
        return PairingRevokeResponse.model_validate(data)

    async def claim_pairing(
        self, request: PairingClaimRequest
    ) -> PairingClaimResponse:
        """POST /v1/pairing/claim — Claim a pre-generated pairing code."""
        data = await self._post_json(
            "/v1/pairing/claim",
            request.model_dump(by_alias=True, exclude_none=True),
        )
        return PairingClaimResponse.model_validate(data)

    # ── Presence ─────────────────────────────────────────────────

    async def send_heartbeat(self, request: PresenceHeartbeatRequest) -> None:
        """POST /v1/presence/heartbeat — Send a presence heartbeat."""
        await self._post(
            "/v1/presence/heartbeat",
            request.model_dump(by_alias=True, exclude_none=True),
        )

    # ── Consent ──────────────────────────────────────────────────

    async def check_consent(self) -> str:
        """GET /v1/consent/status — Check if the user has consented to this enforcer app.

        Returns the consent status string (e.g. "approved").
        Raises AirlockGatewayError with error_code "app_consent_required",
        "app_consent_pending", or "app_consent_denied" if consent is not granted.
        """
        data = await self._get("/v1/consent/status")
        return data.get("status", "unknown")

    # ── DND (Do Not Disturb) Policies ──────────────────────────────

    async def get_effective_dnd_policies(
        self,
        *,
        enforcer_id: str,
        workspace_id: str,
        session_id: Optional[str] = None,
    ) -> DndEffectiveResponse:
        """GET /v1/policy/dnd/effective — Fetch effective DND policies."""
        params: Dict[str, str] = {
            "enforcerId": enforcer_id,
            "workspaceId": workspace_id,
        }
        if session_id:
            params["sessionId"] = session_id

        response = await self._client.get("/v1/policy/dnd/effective", params=params)
        self._raise_for_status(response)
        return DndEffectiveResponse.model_validate(response.json())

    # ── HTTP Helpers ─────────────────────────────────────────────

    async def _get(self, path: str) -> Any:
        response = await self._client.get(path)
        self._raise_for_status(response)
        return response.json()

    async def _post(self, path: str, payload: Any) -> None:
        if payload is not None:
            response = await self._client.post(path, json=payload)
        else:
            response = await self._client.post(path)
        self._raise_for_status(response)

    async def _post_json(self, path: str, payload: Any) -> Any:
        response = await self._client.post(path, json=payload)
        self._raise_for_status(response)
        return response.json()

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        if 200 <= response.status_code < 300:
            return

        error_code: Optional[str] = None
        error_message: Optional[str] = None
        request_id: Optional[str] = None

        try:
            data = response.json()
            # HARP error envelope: { body: { code, message, requestId } }
            if "body" in data and isinstance(data["body"], dict):
                body = data["body"]
                error_code = body.get("code")
                error_message = body.get("message")
                request_id = body.get("requestId")
            else:
                error_code = data.get("error")
                error_message = data.get("message")
        except Exception:
            pass

        message = error_message or f"Gateway returned {response.status_code}"
        raise AirlockGatewayError(
            message,
            status_code=response.status_code,
            error_code=error_code,
            response_body=response.text,
            request_id=request_id,
        )
