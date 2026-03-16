# airlock-gateway-sdk-go

A Go client SDK for the Airlock Integrations Gateway API. Uses the standard library only — no external dependencies.

## Installation

```bash
go get github.com/AirlockHQ/airlock-gateway-sdk-go/airlock
```

## Quick Start

### With Bearer Token

```go
package main

import (
    "fmt"
    "log"

    "github.com/AirlockHQ/airlock-gateway-sdk-go/airlock"
)

func main() {
    client := airlock.NewClient("https://igw.airlocks.io", "your-token")

    // Submit an artifact for approval
    requestID, err := client.SubmitArtifact(airlock.ArtifactSubmitRequest{
        EnforcerID:   "my-enforcer",
        ArtifactHash: "sha256-hash",
        Ciphertext: airlock.CiphertextRef{
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

## License

MIT
