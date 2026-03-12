# airlock-gateway (Python)

An async Python client SDK for the Airlock Gateway API.

## Installation

```bash
pip install airlock-gateway
```

## Quick Start

```python
import asyncio
from airlock_gateway import (
    AirlockGatewayClient,
    ArtifactSubmitRequest,
    CiphertextRef,
)


async def main():
    async with AirlockGatewayClient(
        "https://gw.example.com", token="your-token"
    ) as client:
        # Submit an artifact for approval
        request_id = await client.submit_artifact(
            ArtifactSubmitRequest(
                enforcer_id="my-enforcer",
                artifact_hash="sha256-hash",
                ciphertext=CiphertextRef(
                    alg="aes-256-gcm",
                    data="base64-encrypted-content",
                    nonce="nonce",
                    tag="tag",
                ),
                metadata={"routingToken": "rt-abc"},
            )
        )

        # Wait for a decision (long-poll)
        decision = await client.wait_for_decision(request_id, timeout_seconds=30)
        if decision and decision.body and decision.body.is_approved:
            print(f"Approved: {decision.body.reason}")


asyncio.run(main())
```

## API Reference

| Method | Description |
|--------|-------------|
| `echo()` | Gateway discovery/health |
| `submit_artifact(request)` | Submit artifact for approval |
| `get_exchange_status(request_id)` | Get exchange status |
| `wait_for_decision(request_id, timeout)` | Long-poll for decision |
| `withdraw_exchange(request_id)` | Withdraw pending exchange |
| `acknowledge(msg_id, enforcer_id)` | Acknowledge inbox message |
| `initiate_pairing(request)` | Start pairing session |
| `resolve_pairing(code)` | Resolve pairing code |
| `get_pairing_status(nonce)` | Poll pairing status |
| `complete_pairing(request)` | Complete pairing |
| `revoke_pairing(routing_token)` | Revoke a pairing |
| `get_pairing_status_batch(tokens)` | Batch check pairings |
| `send_heartbeat(request)` | Presence heartbeat |
| `list_enforcers()` | List online enforcers |
| `get_enforcer_presence(id)` | Get enforcer presence |
| `submit_dnd_policy(policy)` | Submit signed DND policy (`POST /v1/policy/dnd`) |
| `get_effective_dnd_policies(enforcer_id, workspace_id, session_id=None)` | Fetch effective DND policies (`GET /v1/policy/dnd/effective`) |

## Error Handling

All errors raise `AirlockGatewayError` with helper properties:

```python
from airlock_gateway import AirlockGatewayError

try:
    await client.submit_artifact(request)
except AirlockGatewayError as e:
    if e.is_quota_exceeded:
        print("Quota exceeded")
    elif e.is_pairing_revoked:
        print("Pairing revoked")
    elif e.is_conflict:
        print("Idempotency conflict")
    else:
        print(f"Error {e.status_code}: {e}")
```

## Requirements

- Python 3.9+
- httpx >= 0.25.0
- pydantic >= 2.0.0

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT
