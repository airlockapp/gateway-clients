# airlock-gateway-sdk-go

A Go client SDK for the Airlock Integrations Gateway API. Uses the standard library only — no external dependencies.

## Installation

```bash
go get github.com/airlockapp/gateway-clients/src/go/airlock
```

## Quick Start

### With Bearer Token

```go
package main

import (
    "fmt"
    "log"

    "github.com/airlockapp/gateway-clients/src/go/airlock"
)

func main() {
    client := airlock.NewClient("https://igw.airlocks.io", "your-token")

    // Submit an artifact for approval
    requestID, err := client.SubmitArtifact(airlock.ArtifactSubmitRequest{
        EnforcerID:   "my-enforcer",
        ArtifactHash: "sha256-hash",
        Ciphertext: airlock.EncryptedPayload{
            Alg:   "aes-256-gcm",
            Data:  "base64-encrypted-content",
            Nonce: "nonce",
            Tag:   "tag",
        },
        Metadata: map[string]string{"routingToken": "rt-abc"},
    })
    if err != nil {
        log.Fatal(err)
    }

    // Wait for a decision (long-poll)
    decision, err := client.WaitForDecision(requestID, 30)
    if err != nil {
        log.Fatal(err)
    }
    if decision != nil && decision.Body.IsApproved() {
        fmt.Printf("Approved: %s\n", decision.Body.Reason)
    }
}
```

### With Enforcer App Credentials

```go
client := airlock.NewClientWithCredentials(
    "https://igw.airlocks.io",
    "your-client-id",
    "your-client-secret",
)
```

### Dual Auth (SetBearerToken)

After creating a client with credentials, set a user's Bearer token to enable user-scoped operations:

```go
// After user login (Device Auth Grant or Auth Code + PKCE)
client.SetBearerToken(accessToken)
```

### Authentication by Enforcer App Kind

| EnforcerAppKind | OAuth2 Flow | SDK Methods | Reason |
|---|---|---|---|
| **Agent** | Device Authorization Grant (RFC 8628) | `Login(ctx, onUserCode)` | Headless/CLI — no embedded browser, user opens URL + enters code separately |
| **Desktop** | Device Authorization Grant (RFC 8628) | `Login(ctx, onUserCode)` | Desktop app — delegates to external browser for user code entry |
| **VsCodeExtension** | Device Authorization Grant (RFC 8628) | `Login(ctx, onUserCode)` | VS Code extension — no embedded browser, uses device code flow |
| **Web** | Auth Code + PKCE (RFC 7636) | `LoginWithAuthCode(ctx, onBrowserURL, port)` or `GetAuthorizationURL(ctx, redirectURI)` + `ExchangeCode(ctx, code, redirectURI, verifier)` | Browser-capable — can handle redirects and local callback |
| **Mobile** | Auth Code + PKCE (RFC 7636) | `GetAuthorizationURL(ctx, redirectURI)` + `ExchangeCode(ctx, code, redirectURI, verifier)` | Uses system browser + deep-link callback (manages redirect externally) |

## API Reference

| Method | Description |
|--------|-------------|
| `Echo()` | Gateway discovery/health |
| `SubmitArtifact(req)` | Submit artifact for approval |
| `GetExchangeStatus(requestID)` | Get exchange status |
| `WaitForDecision(requestID, timeout)` | Long-poll for decision |
| `WithdrawExchange(requestID)` | Withdraw pending exchange |
| `InitiatePairing(req)` | Start pairing session |
| `GetPairingStatus(nonce)` | Poll pairing status |
| `RevokePairing(routingToken)` | Revoke a pairing |
| `SendHeartbeat(req)` | Presence heartbeat |
| `GetEffectiveDndPolicies(enforcerID, workspaceID, sessionID)` | Fetch effective DND policies |
| `CheckConsent()` | Check app consent status |

## Error Handling

All errors return `*GatewayError` with helper methods:

```go
_, err := client.SubmitArtifact(req)
if gwErr, ok := err.(*airlock.GatewayError); ok {
    if gwErr.IsQuotaExceeded() {
        // Handle 429 / quota_exceeded
    }
    if gwErr.IsPairingRevoked() {
        // Handle pairing_revoked
    }
    if gwErr.IsConflict() {
        // Handle 409 conflict
    }
    fmt.Printf("Error %d: %s\n", gwErr.StatusCode, gwErr.Message)
}
```

## Requirements

- Go 1.21+
- Standard library only (no external dependencies)

## Development

```bash
go test ./airlock/...
```

## Encryption

The SDK includes crypto helpers for **X25519 ECDH key exchange** and **AES-256-GCM** encryption/decryption:

- `GenerateX25519KeyPair()` — generates a raw 32-byte X25519 keypair using `crypto/ecdh`
- `DeriveSharedKey(myPrivate, peerPublic)` — derives a shared AES-256 key via ECDH + HKDF-SHA256 (info: `HARP-E2E-AES256GCM`)
- `AesGcmEncrypt(key, plaintext)` / `AesGcmDecrypt(key, payload)` — AES-256-GCM with detached nonce and tag

During pairing, the test enforcer generates an X25519 keypair, sends the public key in the `PairingInitiateRequest`, and derives the shared encryption key from the approver's public key returned in `PairingStatusResponse.ResponseJSON`.

## Test Enforcer CLI

A fully interactive TUI application that demonstrates the complete enforcer lifecycle — setup wizard, Device Auth Grant sign-in, consent check, workspace pairing, background presence heartbeat, artifact submission with decision polling, withdrawal, unpairing, and sign-out.

### Prerequisites

- Go 1.21+
- A running Airlock platform (Gateway + Keycloak)

### Run

```bash
# From the repo root
cd src/go

# Run the test enforcer
go run ./cmd/test-enforcer
```

On first run, the setup wizard will prompt for Gateway URL, Client ID, Client Secret, Enforcer ID, and Workspace Name. Configuration is saved to `~/.airlock/test-enforcer-go.json` and restored on subsequent runs.

## License

MIT
