# airlock-gateway (Python)

An async Python client SDK for the Airlock Integrations Gateway API.

## Installation

**PyPI:** [airlock-gateway](https://pypi.org/project/airlock-gateway/)

```bash
pip install airlock-gateway
```

## API reference

### `AirlockGatewayClient` (Integrations Gateway)

| HTTP | Method |
|------|--------|
| `GET /echo` | `echo` |
| `POST /v1/artifacts` | `submit_artifact` |
| `GET /v1/exchanges/{requestId}` | `get_exchange_status` |
| `GET /v1/exchanges/{requestId}/wait` | `wait_for_decision` |
| `POST /v1/exchanges/{requestId}/withdraw` | `withdraw_exchange` |
| `POST /v1/pairing/initiate` | `initiate_pairing` |
| `GET /v1/pairing/{nonce}/status` | `get_pairing_status` |
| `POST /v1/pairing/revoke` | `revoke_pairing` |
| `POST /v1/pairing/claim` | `claim_pairing` |
| `POST /v1/presence/heartbeat` | `send_heartbeat` |
| `GET /v1/policy/dnd/effective` | `get_effective_dnd_policies` |
| `GET /v1/consent/status` | `check_consent` |

**Helper:** `encrypt_and_submit_artifact` — canonicalizes, encrypts, and submits via `POST /v1/artifacts`. Lower-level crypto helpers live in `airlock_gateway.crypto_helpers`.

### `AirlockAuthClient` (IdP / OAuth)

| Purpose | Method |
|---------|--------|
| OIDC discovery | `discover` |
| Device code login | `login` |
| Auth code + PKCE (local callback) | `login_with_auth_code` |
| Auth code + PKCE (manual redirect) | `get_authorization_url`, `exchange_code` |
| Tokens | `refresh_token`, `get_access_token` |
| Sign out | `logout` |

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

### With Personal Access Token (PAT)

PAT is the recommended authentication for user-scoped operations. It replaces the Bearer token and is sent via the `X-PAT` header:

```python
# After obtaining a PAT from the mobile app (Settings → Access Tokens)
client.set_pat("airlock_pat_...")

# Clear PAT when no longer needed
client.set_pat(None)
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

## Pairing

### Standard Pairing (Enforcer-Initiated)

```python
from airlock_gateway import PairingInitiateRequest

# 1. Initiate a pairing session
resp = await client.initiate_pairing(PairingInitiateRequest(
    enforcer_id="my-enforcer",
    workspace_name="my-project",
    x25519_public_key=my_public_key,
))

# 2. Display pairing code to user
print(f"Pairing code: {resp.pairing_code}")

# 3. Poll for approval from the mobile app
status = await client.get_pairing_status(resp.nonce)
# status.state == "Completed" → save status.routing_token
```

### Pre-Generated Code Pairing (Approver-Initiated)

When the mobile app pre-generates a pairing code, the enforcer claims it:

```python
from airlock_gateway import PairingClaimRequest

claim = await client.claim_pairing(PairingClaimRequest(
    code="ABCD-1234",
    enforcer_id="my-enforcer",
    workspace_name="my-project",
    x25519_public_key=my_public_key,
))
# claim.routing_token is ready to use
```

## Consent Check

Enforcer apps must verify user consent before submitting artifacts:

```python
from airlock_gateway import AirlockGatewayError

try:
    status = await client.check_consent()
    # status == "approved" — proceed normally
except AirlockGatewayError as e:
    if e.error_code == "app_consent_required":
        print("User hasn't granted consent")
    elif e.error_code == "app_consent_pending":
        print("Consent request sent, waiting for approval")
```

## API Reference

| Method | Description |
|--------|-------------|
| `echo()` | Gateway discovery/health |
| `set_pat(pat)` | Set Personal Access Token (X-PAT header) |
| `set_bearer_token(token)` | Set Bearer token for user-scoped operations |
| `check_consent()` | Check if user has consented to this enforcer app |
| `submit_artifact(request)` | Submit artifact for approval |
| `get_exchange_status(request_id)` | Get exchange status |
| `wait_for_decision(request_id, timeout)` | Long-poll for decision |
| `withdraw_exchange(request_id)` | Withdraw pending exchange |
| `initiate_pairing(request)` | Start pairing session |
| `claim_pairing(request)` | Claim a pre-generated pairing code |
| `get_pairing_status(nonce)` | Poll pairing status |
| `revoke_pairing(routing_token)` | Revoke a pairing |
| `send_heartbeat(request)` | Presence heartbeat |
| `get_effective_dnd_policies(enforcer_id, workspace_id, session_id=None)` | Fetch effective DND policies |

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

## Encryption

The SDK includes `crypto_helpers` for **X25519 ECDH key exchange** and **AES-256-GCM** encryption/decryption using [cryptography](https://cryptography.io/):

- `generate_x25519_keypair()` — generates a raw 32-byte X25519 keypair (base64url encoded)
- `derive_shared_key(my_private, peer_public)` — derives a shared AES-256 key via ECDH + HKDF-SHA256 (info: `HARP-E2E-AES256GCM`)
- `aes_gcm_encrypt(key, plaintext)` / `aes_gcm_decrypt(key, payload)` — AES-256-GCM with detached nonce and tag

During pairing, the enforcer generates an X25519 keypair, sends the public key in the pairing request, and derives the shared encryption key from the approver's public key returned in the pairing response.

## Test Enforcer CLI

A fully interactive TUI application that demonstrates the complete enforcer lifecycle — setup wizard, Device Auth Grant sign-in, PAT configuration, consent check, workspace pairing (both standard and pre-generated code), background presence heartbeat, artifact submission with decision polling, withdrawal, unpairing, and sign-out.

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
