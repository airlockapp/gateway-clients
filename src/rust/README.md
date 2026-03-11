# airlock-gateway (Rust)

An async Rust client SDK for the Airlock Gateway API.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
airlock-gateway = "0.1"
```

## Quick Start

```rust
use airlock_gateway::*;

#[tokio::main]
async fn main() -> Result<(), GatewayError> {
    let client = AirlockGatewayClient::new(
        "https://gw.example.com",
        Some("your-token"),
    );

    // Submit an artifact for approval
    let request_id = client.submit_artifact(ArtifactSubmitRequest {
        enforcer_id: "my-enforcer".into(),
        artifact_hash: "sha256-hash".into(),
        ciphertext: CiphertextRef {
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

## API Reference

| Method | Description |
|--------|-------------|
| `echo()` | Gateway discovery/health |
| `submit_artifact(req)` | Submit artifact for approval |
| `get_exchange_status(id)` | Get exchange status |
| `wait_for_decision(id, timeout)` | Long-poll for decision |
| `withdraw_exchange(id)` | Withdraw pending exchange |
| `acknowledge(msg_id, enforcer_id)` | Acknowledge inbox message |
| `initiate_pairing(req)` | Start pairing session |
| `resolve_pairing(code)` | Resolve pairing code |
| `get_pairing_status(nonce)` | Poll pairing status |
| `complete_pairing(req)` | Complete pairing |
| `revoke_pairing(token)` | Revoke a pairing |
| `get_pairing_status_batch(tokens)` | Batch check pairings |
| `send_heartbeat(req)` | Presence heartbeat |
| `list_enforcers()` | List online enforcers |
| `get_enforcer_presence(id)` | Get enforcer presence |

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

## Requirements

- Rust 2021 edition
- Async runtime (tokio recommended)

## Development

```bash
cargo test
```

## License

MIT
