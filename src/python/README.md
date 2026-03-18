# airlock-gateway (Python)

An async Python client SDK for the Airlock Integrations Gateway API.

## Installation

```bash
pip install airlock-gateway
```

## Quick Start

### With Bearer Token

```python
import asyncio
from airlock_gateway import (
    AirlockGatewayClient,
    ArtifactSubmitRequest,
    EncryptedPayload,
)


async def main():
    async with AirlockGatewayClient(
        "https://igw.airlocks.io", token="your-token"
    ) as client:
        # Submit an artifact for approval
        request_id = await client.submit_artifact(
            ArtifactSubmitRequest(
                enforcer_id="my-enforcer",
                artifact_hash="sha256-hash",
                ciphertext=EncryptedPayload(
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

### With Enforcer App Credentials

```python
async with AirlockGatewayClient(
    "https://igw.airlocks.io",
    client_id="your-client-id",
    client_secret="your-client-secret",
) as client:
    echo = await client.echo()
```

### Dual Auth (set_bearer_token)

After creating a client with credentials, set a user's Bearer token to enable user-scoped operations:

```python
# After user login (Device Auth Grant or Auth Code + PKCE)
client.set_bearer_token(access_token)
```

### Authentication by Enforcer App Kind

| EnforcerAppKind | OAuth2 Flow | SDK Methods | Reason |
|---|---|---|---|
| **Agent** | Device Authorization Grant (RFC 8628) | `login(on_user_code)` | Headless/CLI — no embedded browser, user opens URL + enters code separately |
| **Desktop** | Device Authorization Grant (RFC 8628) | `login(on_user_code)` | Desktop app — delegates to external browser for user code entry |
| **VsCodeExtension** | Device Authorization Grant (RFC 8628) | `login(on_user_code)` | VS Code extension — no embedded browser, uses device code flow |
| **Web** | Auth Code + PKCE (RFC 7636) | `login_with_auth_code(on_browser_url, port)` or `get_authorization_url(redirect_uri)` + `exchange_code(code, redirect_uri, verifier)` | Browser-capable — can handle redirects and local callback |
| **Mobile** | Auth Code + PKCE (RFC 7636) | `get_authorization_url(redirect_uri)` + `exchange_code(code, redirect_uri, verifier)` | Uses system browser + deep-link callback (manages redirect externally) |

## API Reference

| Method | Description |
|--------|-------------|
| `echo()` | Gateway discovery/health |
| `submit_artifact(request)` | Submit artifact for approval |
| `get_exchange_status(request_id)` | Get exchange status |
| `wait_for_decision(request_id, timeout)` | Long-poll for decision |
| `withdraw_exchange(request_id)` | Withdraw pending exchange |
| `initiate_pairing(request)` | Start pairing session |
| `get_pairing_status(nonce)` | Poll pairing status |
| `revoke_pairing(routing_token)` | Revoke a pairing |
| `send_heartbeat(request)` | Presence heartbeat |
| `get_effective_dnd_policies(enforcer_id, workspace_id, session_id=None)` | Fetch effective DND policies |
| `check_consent()` | Check app consent status |

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

## Encryption

The SDK includes `crypto_helpers` for **X25519 ECDH key exchange** and **AES-256-GCM** encryption/decryption using [cryptography](https://cryptography.io/):

- `generate_x25519_keypair()` — generates a raw 32-byte X25519 keypair (base64url encoded)
- `derive_shared_key(my_private, peer_public)` — derives a shared AES-256 key via ECDH + HKDF-SHA256 (info: `HARP-E2E-AES256GCM`)
- `aes_gcm_encrypt(key, plaintext)` / `aes_gcm_decrypt(key, payload)` — AES-256-GCM with detached nonce and tag

During pairing, the test enforcer generates an X25519 keypair, sends the public key in the `PairingInitiateRequest`, and derives the shared encryption key from the approver's public key returned in `PairingStatusResponse.response_json`.

## Test Enforcer CLI

A fully interactive TUI application that demonstrates the complete enforcer lifecycle — setup wizard, Device Auth Grant sign-in, consent check, workspace pairing, background presence heartbeat, artifact submission with decision polling, withdrawal, unpairing, and sign-out.

### Prerequisites

- Python 3.9+
- A running Airlock platform (Gateway + Keycloak)

### Run

```bash
# From the repo root
cd src/python

# Create and activate virtual environment (required once)
python -m venv .venv
.venv\Scripts\Activate.ps1   # Windows PowerShell
# source .venv/bin/activate  # macOS / Linux

# Install dependencies (required once)
pip install -r requirements.txt

# Run the test enforcer
python test_enforcer.py
```

On first run, the setup wizard will prompt for Gateway URL, Client ID, Client Secret, Enforcer ID, and Workspace Name. Configuration is saved to `~/.airlock/test-enforcer-python.json` and restored on subsequent runs.

## License

MIT
