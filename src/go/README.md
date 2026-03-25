# airlock-gateway (Go)

A Go client SDK for the Airlock Integrations Gateway API.

## Installation

**Module:** `github.com/airlockapp/gateway-clients/src/go/airlock` — **docs:** [pkg.go.dev](https://pkg.go.dev/github.com/airlockapp/gateway-clients/src/go/airlock)

```bash
go get github.com/airlockapp/gateway-clients/src/go/airlock
```

## API reference

### `airlock.Client` (Integrations Gateway)

| HTTP | Method |
|------|--------|
| `GET /echo` | `Echo` |
| `POST /v1/artifacts` | `SubmitArtifact` |
| `GET /v1/exchanges/{requestId}` | `GetExchangeStatus` |
| `GET /v1/exchanges/{requestId}/wait` | `WaitForDecision` |
| `POST /v1/exchanges/{requestId}/withdraw` | `WithdrawExchange` |
| `POST /v1/pairing/initiate` | `InitiatePairing` |
| `GET /v1/pairing/{nonce}/status` | `GetPairingStatus` |
| `POST /v1/pairing/revoke` | `RevokePairing` |
| `POST /v1/pairing/claim` | `ClaimPairing` |
| `POST /v1/presence/heartbeat` | `SendHeartbeat` |
| `GET /v1/policy/dnd/effective` | `GetEffectiveDndPolicies` |
| `GET /v1/consent/status` | `CheckConsent` |

**Helper:** `EncryptAndSubmitArtifact` — canonicalizes, encrypts, and calls `POST /v1/artifacts`. **Client configuration:** `NewClient`, `NewClientWithCredentials`, `SetBearerToken`, `SetPat`, `WithHTTPClient`.

### `airlock.AirlockAuthClient` (IdP / OAuth)

| Purpose | Method |
|---------|--------|
| OIDC discovery | `Discover` |
| Device code login | `Login` |
| Auth code + PKCE (local callback) | `LoginWithAuthCode` |
| Auth code + PKCE (manual redirect) | `GetAuthorizationURL`, `ExchangeCode` |
| Tokens | `RefreshToken`, `GetAccessToken` |
| Session helpers | `CurrentAccessToken`, `IsLoggedIn`, `IsTokenExpired`, `RestoreTokens`, `GetTokenState` |
| Sign out | `Logout` |

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

### Payload Schema for Mobile Display

The `Ciphertext.Data` content you encrypt is shown to the mobile approver. Any valid JSON string is supported — the mobile app renders every top-level key as a labelled row. Nested objects and arrays are pretty-printed. Non-JSON strings are displayed as plain monospace text.

> **Note:** The `extensions` field is reserved for HARP protocol extensions (e.g., `org.harp.requestedActions` for custom action buttons). Do not include it manually if using the enforcer SDK's built-in action support.

### With Enforcer App Credentials

```go
client := airlock.NewClientWithCredentials(
    "https://igw.airlocks.io",
    "your-client-id",
    "your-client-secret",
)
```

### With Personal Access Token (PAT)

PAT is the recommended authentication for user-scoped operations. It replaces the Bearer token and is sent via the `X-PAT` header:

```go
// After obtaining a PAT from the mobile app (Settings → Access Tokens)
client.SetPat("airlock_pat_...")

// Clear PAT when no longer needed
client.SetPat("")
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

## Pairing

### Standard Pairing (Enforcer-Initiated)

```go
// 1. Initiate a pairing session
resp, err := client.InitiatePairing(airlock.PairingInitiateRequest{
    EnforcerID:    "my-enforcer",
    WorkspaceName: "my-project",
    X25519PublicKey: myPublicKey,
})

// 2. Display pairing code to user
fmt.Printf("Pairing code: %s\n", resp.PairingCode)

// 3. Poll for approval from the mobile app
status, err := client.GetPairingStatus(resp.Nonce)
// status.State == "Completed" → save status.RoutingToken
```

### Pre-Generated Code Pairing (Approver-Initiated)

When the mobile app pre-generates a pairing code, the enforcer claims it:

```go
claim, err := client.ClaimPairing(airlock.PairingClaimRequest{
    Code:            "ABCD-1234",
    EnforcerID:      "my-enforcer",
    WorkspaceName:   "my-project",
    X25519PublicKey:  myPublicKey,
})
// claim.RoutingToken is ready to use
```

## Consent Check

Enforcer apps must verify user consent before submitting artifacts:

```go
status, err := client.CheckConsent()
if gwErr, ok := err.(*airlock.GatewayError); ok {
    if gwErr.ErrorCode == "app_consent_required" {
        // User hasn't granted consent
    } else if gwErr.ErrorCode == "app_consent_pending" {
        // Consent request sent, waiting for approval
    }
}
// status == "approved" — proceed normally
```

## API Reference

| Method | Description |
|--------|-------------|
| `Echo()` | Gateway discovery/health |
| `SetPat(pat)` | Set Personal Access Token (X-PAT header) |
| `SetBearerToken(token)` | Set Bearer token for user-scoped operations |
| `CheckConsent()` | Check if user has consented to this enforcer app |
| `SubmitArtifact(req)` | Submit artifact for approval |
| `GetExchangeStatus(requestID)` | Get exchange status |
| `WaitForDecision(requestID, timeout)` | Long-poll for decision |
| `WithdrawExchange(requestID)` | Withdraw pending exchange |
| `InitiatePairing(req)` | Start pairing session |
| `ClaimPairing(req)` | Claim a pre-generated pairing code |
| `GetPairingStatus(nonce)` | Poll pairing status |
| `RevokePairing(routingToken)` | Revoke a pairing |
| `SendHeartbeat(req)` | Presence heartbeat |
| `GetEffectiveDndPolicies(enforcerID, workspaceID, sessionID)` | Fetch effective DND policies |

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

## Encryption

The SDK includes crypto helpers for **X25519 ECDH key exchange** and **AES-256-GCM** encryption/decryption:

- `GenerateX25519KeyPair()` — generates a raw 32-byte X25519 keypair using `crypto/ecdh`
- `DeriveSharedKey(myPrivate, peerPublic)` — derives a shared AES-256 key via ECDH + HKDF-SHA256 (info: `HARP-E2E-AES256GCM`)
- `AesGcmEncrypt(key, plaintext)` / `AesGcmDecrypt(key, payload)` — AES-256-GCM with detached nonce and tag

During pairing, the enforcer generates an X25519 keypair, sends the public key in the pairing request, and derives the shared encryption key from the approver's public key returned in the pairing response.

## Test Enforcer CLI

A fully interactive TUI application that demonstrates the complete enforcer lifecycle — setup wizard, Device Auth Grant sign-in, PAT configuration, consent check, workspace pairing (both standard and pre-generated code), background presence heartbeat, artifact submission with decision polling, withdrawal, unpairing, and sign-out.

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

## Requirements

- Go 1.25+
- golang.org/x/crypto (ECDH + HKDF)

## Development

```bash
go test ./airlock/...
```

## License

MIT

## Documentation & Resources

For full integration tutorials, conceptual overviews, and detailed API references, please visit the official Airlock Documentation:
- **[Airlock Developer Guide](https://airlockapp.io/docs/developer-guide/)**
- **[Airlock SDK Reference & Setup](https://airlockapp.io/docs/sdk/)**
