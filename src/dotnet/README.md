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

### Submit and Poll

```csharp
// Submit an artifact for approval
var requestId = await client.SubmitArtifactAsync(new ArtifactSubmitRequest
{
    EnforcerId = "my-enforcer",
    ArtifactHash = "sha256-hash",
    Ciphertext = new CiphertextRef
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

## License

MIT
