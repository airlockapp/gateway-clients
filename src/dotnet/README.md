# Airlock.Gateway.Sdk (.NET)

A .NET Standard 2.0 client SDK for the Airlock Gateway API.

## Installation

```bash
dotnet add package Airlock.Gateway.Sdk
```

## Quick Start

```csharp
using Airlock.Gateway.Sdk;
using Airlock.Gateway.Sdk.Models;

var httpClient = new HttpClient
{
    BaseAddress = new Uri("https://gw.example.com")
};
httpClient.DefaultRequestHeaders.Authorization =
    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", "your-token");

var client = new AirlockGatewayClient(httpClient);

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
| `AcknowledgeAsync(msgId, enforcerId)` | Acknowledge inbox message |
| `InitiatePairingAsync(request)` | Start pairing session |
| `ResolvePairingAsync(code)` | Resolve pairing code |
| `GetPairingStatusAsync(nonce)` | Poll pairing status |
| `CompletePairingAsync(request)` | Complete pairing |
| `RevokePairingAsync(routingToken)` | Revoke a pairing |
| `GetPairingStatusBatchAsync(tokens)` | Batch check pairings |
| `SendHeartbeatAsync(request)` | Presence heartbeat |
| `ListEnforcersAsync()` | List online enforcers |
| `GetEnforcerPresenceAsync(id)` | Get enforcer presence |

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
