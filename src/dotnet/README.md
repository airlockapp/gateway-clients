# Airlock.Gateway.Sdk (.NET)

A .NET Standard 2.0 client SDK for the Airlock Integrations Gateway API.

## Installation

```bash
dotnet add package Airlock.Gateway.Sdk
```

## Quick Start

### With Bearer Token

```csharp
using Airlock.Gateway.Sdk;
using Airlock.Gateway.Sdk.Models;

var client = new AirlockGatewayClient("https://igw.airlocks.io", bearerToken: "your-jwt-token");
```

### With Enforcer App Credentials

```csharp
var client = new AirlockGatewayClient(
    "https://igw.airlocks.io",
    clientId: "your-client-id",
    clientSecret: "your-client-secret");
```

### Dual Auth (SetBearerToken)

After creating a client with credentials, you can set a user's Bearer token to enable user-scoped operations (e.g. consent-aware requests):

```csharp
// After user login (Device Auth Grant or Auth Code + PKCE)
client.SetBearerToken(accessToken);
```

### Authentication by Enforcer App Kind

| EnforcerAppKind | OAuth2 Flow | SDK Methods | Reason |
|---|---|---|---|
| **Agent** | Device Authorization Grant (RFC 8628) | `LoginAsync(onUserCode)` | Headless/CLI — no embedded browser, user opens URL + enters code separately |
| **Desktop** | Device Authorization Grant (RFC 8628) | `LoginAsync(onUserCode)` | Desktop app — delegates to external browser for user code entry |
| **VsCodeExtension** | Device Authorization Grant (RFC 8628) | `LoginAsync(onUserCode)` | VS Code extension — no embedded browser, uses device code flow |
| **Web** | Auth Code + PKCE (RFC 7636) | `LoginWithAuthCodeAsync(onBrowserUrl)` or `GetAuthorizationUrlAsync()` + `ExchangeCodeAsync()` | Browser-capable — can handle redirects and local callback |
| **Mobile** | Auth Code + PKCE (RFC 7636) | `GetAuthorizationUrlAsync()` + `ExchangeCodeAsync()` | Uses system browser + deep-link callback (manages redirect externally) |

### Submit and Poll

```csharp
// Submit an artifact for approval
var requestId = await client.SubmitArtifactAsync(new ArtifactSubmitRequest
{
    EnforcerId = "my-enforcer",
    ArtifactHash = "sha256-hash",
    Ciphertext = new EncryptedPayload
    {
        Alg = "aes-256-gcm",
        Data = "base64-encrypted-content",
        Nonce = "nonce",
        Tag = "tag"
    },
    Metadata = new Dictionary<string, string>
    {
        ["routingToken"] = "rt-abc"
    }
});

// Wait for a decision (long-poll)
var decision = await client.WaitForDecisionAsync(requestId, timeoutSeconds: 30);
if (decision?.Body?.IsApproved == true)
{
    Console.WriteLine($"Approved: {decision.Body.Reason}");
}
```

## API Reference

| Method | Description |
|--------|-------------|
| `EchoAsync()` | Gateway discovery/health |
| `SubmitArtifactAsync(request)` | Submit artifact for approval |
| `GetExchangeStatusAsync(requestId)` | Get exchange status |
| `WaitForDecisionAsync(requestId, timeout)` | Long-poll for decision |
| `WithdrawExchangeAsync(requestId)` | Withdraw pending exchange |
| `InitiatePairingAsync(request)` | Start pairing session |
| `GetPairingStatusAsync(nonce)` | Poll pairing status |
| `RevokePairingAsync(routingToken)` | Revoke a pairing |
| `SendHeartbeatAsync(request)` | Presence heartbeat |
| `GetEffectiveDndPoliciesAsync(enforcerId, workspaceId, sessionId)` | Fetch effective DND policies |

## Error Handling

All errors throw `AirlockGatewayException` with helper properties:

```csharp
try
{
    await client.SubmitArtifactAsync(request);
}
catch (AirlockGatewayException ex) when (ex.IsQuotaExceeded)
{
    // Handle quota exceeded (429)
}
catch (AirlockGatewayException ex) when (ex.IsPairingRevoked)
{
    // Handle revoked pairing (403)
}
catch (AirlockGatewayException ex) when (ex.IsConflict)
{
    // Handle idempotency conflict (409)
}
```

## Requirements

- .NET Standard 2.0+ (.NET Core 2.0+, .NET Framework 4.6.1+, .NET 5+)
- System.Text.Json 9.0+

## Building

```bash
dotnet build
dotnet test
```

## Encryption

The SDK includes `CryptoHelpers` for **X25519 ECDH key exchange** and **AES-256-GCM** encryption/decryption using [NSec.Cryptography](https://nsec.rocks/):

- `GenerateX25519KeyPair()` — generates a raw 32-byte X25519 keypair (base64url encoded)
- `DeriveSharedKey(myPrivate, peerPublic)` — derives a shared AES-256 key via ECDH + HKDF-SHA256 (info: `HARP-E2E-AES256GCM`)
- `AesGcmEncrypt(key, plaintext)` / `AesGcmDecrypt(key, payload)` — AES-256-GCM with detached nonce and tag

During pairing, the test enforcer generates an X25519 keypair, sends the public key in the `PairingInitiateRequest`, and derives the shared encryption key from the approver's public key returned in `PairingStatusResponse.ResponseJson`.

## Test Enforcer CLI

A fully interactive TUI application that demonstrates the complete enforcer lifecycle — setup wizard, Device Auth Grant sign-in, consent check, workspace pairing, background presence heartbeat, artifact submission with decision polling, withdrawal, unpairing, and sign-out.

### Prerequisites

- .NET 10 SDK
- A running Airlock platform (Gateway + Keycloak)

### Run

```bash
# From the repo root
cd src/dotnet

# Run the test enforcer
dotnet run --project Airlock.Gateway.Sdk.TestEnforcer
```

On first run, the setup wizard will prompt for Gateway URL, Client ID, Client Secret, Enforcer ID, and Workspace Name. Configuration is saved to `~/.airlock/test-enforcer-dotnet.json` and restored on subsequent runs.

## License

MIT
