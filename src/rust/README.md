# airlock-gateway (Rust)

An async Rust client SDK for the Airlock Integrations Gateway API.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
airlock-gateway = "0.1"
```

## Quick Start

### With Bearer Token

```rust
use airlock_gateway::*;

#[tokio::main]
async fn main() -> Result<(), GatewayError> {
    let client = AirlockGatewayClient::new(
        "https://igw.airlocks.io",
        Some("your-token"),
    );

    // Submit an artifact for approval
    let request_id = client.submit_artifact(ArtifactSubmitRequest {
        enforcer_id: "my-enforcer".into(),
        artifact_hash: "sha256-hash".into(),
        ciphertext: EncryptedPayload {
            alg: "aes-256-gcm".into(),
            data: "base64-encrypted-content".into(),
            nonce: Some("nonce".into()),
            tag: Some("tag".into()),
            aad: None,
        },
        artifact_type: None,
        expires_at: None,
        metadata: None,
        request_id: None,
    }).await?;

    // Wait for a decision (long-poll)
    if let Some(decision) = client.wait_for_decision(&request_id, 30).await? {
        if let Some(body) = &decision.body {
            if body.is_approved() {
                println!("Approved: {:?}", body.reason);
            }
        }
    }

    Ok(())
}
```

### With Enforcer App Credentials

```rust
let client = AirlockGatewayClient::with_credentials(
    "https://igw.airlocks.io",
    "your-client-id",
    "your-client-secret",
);
```

### With Personal Access Token (PAT)

PAT is the recommended authentication for user-scoped operations. It replaces the Bearer token and is sent via the `X-PAT` header:

```rust
// After obtaining a PAT from the mobile app (Settings → Access Tokens)
client.set_pat(Some("airlock_pat_..."));

// Clear PAT when no longer needed
client.set_pat(None::<String>);
```

### Dual Auth (set_bearer_token)

After creating a client with credentials, set a user's Bearer token to enable user-scoped operations:

```rust
// After user login (Device Auth Grant or Auth Code + PKCE)
client.set_bearer_token(Some(access_token));
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

```rust
// 1. Initiate a pairing session
let resp = client.initiate_pairing(PairingInitiateRequest {
    enforcer_id: "my-enforcer".into(),
    workspace_name: Some("my-project".into()),
    x25519_public_key: Some(my_public_key),
}).await?;

// 2. Display pairing code to user
println!("Pairing code: {}", resp.pairing_code);

// 3. Poll for approval from the mobile app
let status = client.get_pairing_status(&resp.nonce).await?;
// status.state == "Completed" → save status.routing_token
```

### Pre-Generated Code Pairing (Approver-Initiated)

When the mobile app pre-generates a pairing code, the enforcer claims it:

```rust
let claim = client.claim_pairing(PairingClaimRequest {
    code: "ABCD-1234".into(),
    enforcer_id: "my-enforcer".into(),
    workspace_name: Some("my-project".into()),
    x25519_public_key: Some(my_public_key),
}).await?;
// claim.routing_token is ready to use
```

## Consent Check

Enforcer apps must verify user consent before submitting artifacts:

```rust
match client.check_consent().await {
    Ok(status) => println!("Consent: {status}"), // "approved"
    Err(e) if e.error_code() == Some("app_consent_required") => {
        eprintln!("User hasn't granted consent");
    }
    Err(e) if e.error_code() == Some("app_consent_pending") => {
        eprintln!("Consent request sent, waiting for approval");
    }
    Err(e) => return Err(e),
}
```

## API Reference

| Method | Description |
|--------|-------------|
| `echo()` | Gateway discovery/health |
| `set_pat(pat)` | Set Personal Access Token (X-PAT header) |
| `set_bearer_token(token)` | Set Bearer token for user-scoped operations |
| `check_consent()` | Check if user has consented to this enforcer app |
| `submit_artifact(req)` | Submit artifact for approval |
| `get_exchange_status(id)` | Get exchange status |
| `wait_for_decision(id, timeout)` | Long-poll for decision |
| `withdraw_exchange(id)` | Withdraw pending exchange |
| `initiate_pairing(req)` | Start pairing session |
| `claim_pairing(req)` | Claim a pre-generated pairing code |
| `get_pairing_status(nonce)` | Poll pairing status |
| `revoke_pairing(token)` | Revoke a pairing |
| `send_heartbeat(req)` | Presence heartbeat |
| `get_effective_dnd_policies(enforcer_id, workspace_id, session_id)` | Fetch effective DND policies |

## Error Handling

All errors return `GatewayError` with helper methods:

```rust
match client.submit_artifact(req).await {
    Ok(id) => println!("Submitted: {id}"),
    Err(e) if e.is_quota_exceeded() => eprintln!("Quota exceeded"),
    Err(e) if e.is_pairing_revoked() => eprintln!("Pairing revoked"),
    Err(e) if e.is_conflict() => eprintln!("Idempotency conflict"),
    Err(e) => eprintln!("Error: {e}"),
}
```

## Encryption

The SDK includes crypto helpers for **X25519 ECDH key exchange** and **AES-256-GCM** encryption/decryption using `x25519_dalek` and `aes-gcm`:

- `generate_x25519_keypair()` — generates a raw 32-byte X25519 keypair (base64url encoded)
- `derive_shared_key(my_private, peer_public)` — derives a shared AES-256 key via ECDH + HKDF-SHA256 (info: `HARP-E2E-AES256GCM`)
- `aes_gcm_encrypt(key, plaintext)` / `aes_gcm_decrypt(key, payload)` — AES-256-GCM with detached nonce and tag

During pairing, the enforcer generates an X25519 keypair, sends the public key in the pairing request, and derives the shared encryption key from the approver's public key returned in the pairing response.

## Test Enforcer CLI

A fully interactive TUI application that demonstrates the complete enforcer lifecycle — setup wizard, Device Auth Grant sign-in, PAT configuration, consent check, workspace pairing (both standard and pre-generated code), background presence heartbeat, artifact submission with decision polling, withdrawal, unpairing, and sign-out.

### Prerequisites

- Rust 2021 edition (1.56+)
- A running Airlock platform (Gateway + Keycloak)

### Run

```bash
# From the repo root
cd src/rust

# Run the test enforcer
cargo run --bin test_enforcer
```

On first run, the setup wizard will prompt for Gateway URL, Client ID, Client Secret, Enforcer ID, and Workspace Name. Configuration is saved to `~/.airlock/test-enforcer-rust.json` and restored on subsequent runs.

## Requirements

- Rust 2021 edition
- Async runtime (tokio recommended)

## Development

```bash
cargo test
```

## License

MIT
