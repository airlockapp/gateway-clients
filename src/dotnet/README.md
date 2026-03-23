# Airlock.Gateway.Sdk (.NET)

A .NET 8+ client SDK for the Airlock Integrations Gateway API.

## Installation

**NuGet:** [Airlock.Gateway.Sdk](https://www.nuget.org/packages/Airlock.Gateway.Sdk)

```bash
dotnet add package Airlock.Gateway.Sdk
```

## API reference

### `AirlockGatewayClient` (Integrations Gateway)

| HTTP | `AirlockGatewayClient` method |
|------|-------------------------------|
| `GET /echo` | `EchoAsync` |
| `POST /v1/artifacts` | `SubmitArtifactAsync` |
| `GET /v1/exchanges/{requestId}` | `GetExchangeStatusAsync` |
| `GET /v1/exchanges/{requestId}/wait` | `WaitForDecisionAsync` |
| `POST /v1/exchanges/{requestId}/withdraw` | `WithdrawExchangeAsync` |
| `POST /v1/pairing/initiate` | `InitiatePairingAsync` |
| `GET /v1/pairing/{nonce}/status` | `GetPairingStatusAsync` |
| `POST /v1/pairing/revoke` | `RevokePairingAsync` |
| `POST /v1/pairing/claim` | `ClaimPairingAsync` |
| `POST /v1/presence/heartbeat` | `SendHeartbeatAsync` |
| `GET /v1/policy/dnd/effective` | `GetEffectiveDndPoliciesAsync` |
| `GET /v1/consent/status` | `CheckConsentAsync` |

**Helpers (not extra HTTP):** `EncryptAndSubmitArtifactAsync` (builds the HARP envelope and calls `POST /v1/artifacts`), `VerifyDecision` (local Ed25519 / binding checks on a decision envelope).

### `AirlockAuthClient` (IdP / OAuth — Keycloak)

Used for Device Authorization Grant and Auth Code + PKCE against your IdP (after you obtain `token_endpoint` etc., typically via gateway discovery in app code).

| Purpose | Method |
|---------|--------|
| Load OIDC discovery | `DiscoverAsync` |
| Device code login | `LoginAsync` |
| Auth code + PKCE (local callback) | `LoginWithAuthCodeAsync` |
| Auth code + PKCE (manual redirect) | `GetAuthorizationUrlAsync`, `ExchangeCodeAsync` |
| Refresh / access token | `RefreshTokenAsync`, `GetAccessTokenAsync` |
| Sign out (revoke) | `LogoutAsync` |

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

### With Personal Access Token (PAT)

PAT is the recommended authentication for user-scoped operations. It replaces the Bearer token and is sent via the `X-PAT` header:

```csharp
// After obtaining a PAT from the mobile app (Settings → Access Tokens)
client.SetPat("airlock_pat_...");

// Clear PAT when no longer needed
client.SetPat(null);
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

## Pairing

### Standard Pairing (Enforcer-Initiated)

```csharp
// 1. Initiate a pairing session
var pairing = await client.InitiatePairingAsync(new PairingInitiateRequest
{
    EnforcerId = "my-enforcer",
    WorkspaceName = "my-project",
    X25519PublicKey = myPublicKey, // For E2E encryption key exchange
});

// 2. Display pairing code to user (or show QR)
Console.WriteLine($"Pairing code: {pairing.PairingCode}");

// 3. Poll for approval from the mobile app
var status = await client.GetPairingStatusAsync(pairing.Nonce);
if (status.State == "Completed")
{
    var routingToken = status.RoutingToken; // Save for future requests
}
```

### Pre-Generated Code Pairing (Approver-Initiated)

When the mobile app pre-generates a pairing code, the enforcer claims it:

```csharp
// Claim a pre-generated code from the mobile app
var claim = await client.ClaimPairingAsync(new PairingClaimRequest
{
    Code = "ABCD-1234",             // Code from the mobile app
    EnforcerId = "my-enforcer",
    WorkspaceName = "my-project",
    X25519PublicKey = myPublicKey,
});

// The response contains the routing token and pairing details
var routingToken = claim.RoutingToken;
```

## Consent Check

Enforcer apps must verify user consent before submitting artifacts:

```csharp
try
{
    var status = await client.CheckConsentAsync();
    // status == "approved" — proceed normally
}
catch (AirlockGatewayException ex) when (ex.ErrorCode == "app_consent_required")
{
    // User hasn't granted consent — prompt them to approve in the mobile app
}
catch (AirlockGatewayException ex) when (ex.ErrorCode == "app_consent_pending")
{
    // Consent request sent, waiting for user approval
}
```

## Submit and Poll

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

### Transparent Encryption (Encrypt + Submit)

The SDK can handle canonicalization, hashing, encryption, and HARP envelope construction in one call:

```csharp
var requestId = await client.EncryptAndSubmitArtifactAsync(new EncryptedArtifactRequest
{
    EnforcerId = "my-enforcer",
    Plaintext = "the content to approve",
    RoutingToken = "rt-abc",
    EncryptionKey = sharedAesKey, // Derived from X25519 ECDH during pairing
});
```

### Decision Verification

Verify a decision envelope's Ed25519 signature, artifact binding, and expiry:

```csharp
var result = client.VerifyDecision(decision, expectedArtifactHash, signerPublicKeyBase64Url);
if (result.IsValid)
{
    Console.WriteLine($"Verified decision: {result.Decision}");
}
else
{
    Console.WriteLine($"Verification failed: {result.FailureReason}");
}
```

## API Reference

| Method | Description |
|--------|-------------|
| `EchoAsync()` | Gateway discovery/health |
| `SetPat(pat)` | Set Personal Access Token (X-PAT header) |
| `SetBearerToken(token)` | Set Bearer token for user-scoped operations |
| `CheckConsentAsync()` | Check if user has consented to this enforcer app |
| `SubmitArtifactAsync(request)` | Submit artifact for approval |
| `EncryptAndSubmitArtifactAsync(request)` | Encrypt plaintext and submit as artifact |
| `GetExchangeStatusAsync(requestId)` | Get exchange status |
| `WaitForDecisionAsync(requestId, timeout)` | Long-poll for decision |
| `VerifyDecision(decision, hash, publicKey)` | Verify decision signature and binding |
| `WithdrawExchangeAsync(requestId)` | Withdraw pending exchange |
| `InitiatePairingAsync(request)` | Start pairing session |
| `ClaimPairingAsync(request)` | Claim a pre-generated pairing code |
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

## Encryption

The SDK includes `CryptoHelpers` for **X25519 ECDH key exchange** and **AES-256-GCM** encryption/decryption using [NSec.Cryptography](https://nsec.rocks/):

- `GenerateX25519KeyPair()` — generates a raw 32-byte X25519 keypair (base64url encoded)
- `DeriveSharedKey(myPrivate, peerPublic)` — derives a shared AES-256 key via ECDH + HKDF-SHA256 (info: `HARP-E2E-AES256GCM`)
- `AesGcmEncrypt(key, plaintext)` / `AesGcmDecrypt(key, payload)` — AES-256-GCM with detached nonce and tag

During pairing, the enforcer generates an X25519 keypair, sends the public key in the pairing request, and derives the shared encryption key from the approver's public key returned in the pairing response.

## Test Enforcer CLI

A fully interactive TUI application that demonstrates the complete enforcer lifecycle — setup wizard, Device Auth Grant sign-in, PAT configuration, consent check, workspace pairing (both standard and pre-generated code), background presence heartbeat, artifact submission with decision polling, withdrawal, unpairing, and sign-out.

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

On first run, the setup wizard will prompt for Gateway URL, Client ID, Client Secret, Enforcer ID, and Workspace Name. Configuration is saved to `~/.airlock/test-enforcer.json` and restored on subsequent runs.

## Requirements

- .NET 8.0+
- System.Text.Json 9.0+
- NSec.Cryptography 25.4+
- jsoncanonicalizer 1.0+

## Building

```bash
dotnet build
dotnet test
```

## License

MIT
