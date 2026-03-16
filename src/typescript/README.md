# @airlock/gateway-sdk (TypeScript)

A zero-dependency TypeScript client SDK for the Airlock Integrations Gateway API. Uses the native `fetch` API — works in Node.js 18+ and modern browsers.

## Installation

```bash
npm install @airlock/gateway-sdk
```

## Quick Start

### With Bearer Token

```typescript
import { AirlockGatewayClient } from "@airlock/gateway-sdk";

const client = new AirlockGatewayClient({
    baseUrl: "https://igw.airlocks.io",
    token: "your-token",
});
```

### With Enforcer App Credentials

```typescript
const client = new AirlockGatewayClient({
    baseUrl: "https://igw.airlocks.io",
    clientId: "your-client-id",
    clientSecret: "your-client-secret",
});
```

### Submit and Poll

```typescript
// Submit an artifact for approval
const requestId = await client.submitArtifact({
    enforcerId: "my-enforcer",
    artifactHash: "sha256-hash",
    ciphertext: {
        alg: "aes-256-gcm",
        data: "base64-encrypted-content",
        nonce: "nonce",
        tag: "tag",
    },
    metadata: { routingToken: "rt-abc" },
});

// Wait for a decision (long-poll)
const decision = await client.waitForDecision(requestId, 30);
if (decision?.body?.decision === "approve") {
    console.log(`Approved: ${decision.body.reason}`);
}
```

## API Reference

| Method | Description |
|--------|-------------|
| `echo()` | Gateway discovery/health |
| `submitArtifact(request)` | Submit artifact for approval |
| `getExchangeStatus(requestId)` | Get exchange status |
| `waitForDecision(requestId, timeout)` | Long-poll for decision |
| `withdrawExchange(requestId)` | Withdraw pending exchange |
| `initiatePairing(request)` | Start pairing session |
| `getPairingStatus(nonce)` | Poll pairing status |
| `revokePairing(routingToken)` | Revoke a pairing |
| `sendHeartbeat(request)` | Presence heartbeat |
| `getEffectiveDndPolicies(enforcerId, workspaceId, sessionId?)` | Fetch effective DND policies |

## Error Handling

All errors throw `AirlockGatewayError` with helper getters:

```typescript
import { AirlockGatewayError } from "@airlock/gateway-sdk";

try {
    await client.submitArtifact(request);
} catch (e) {
    if (e instanceof AirlockGatewayError) {
        if (e.isQuotaExceeded) { /* 429 */ }
        if (e.isPairingRevoked) { /* 403 pairing_revoked */ }
        if (e.isConflict) { /* 409 */ }
        console.error(`Error ${e.statusCode}: ${e.message}`);
    }
}
```

## Custom Fetch

You can provide a custom `fetch` implementation for testing or intercepting requests:

```typescript
const client = new AirlockGatewayClient({
    baseUrl: "https://igw.airlocks.io",
    fetch: myCustomFetch,
});
```

## Requirements

- Node.js 18+ (native `fetch`) or modern browser
- Zero runtime dependencies

## Development

```bash
npm install
npm run build
npm test
```

## License

MIT
