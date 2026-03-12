# @airlock/gateway-sdk (TypeScript)

A zero-dependency TypeScript client SDK for the Airlock Gateway API. Uses the native `fetch` API — works in Node.js 18+ and modern browsers.

## Installation

```bash
npm install @airlock/gateway-sdk
```

## Quick Start

```typescript
import { AirlockGatewayClient } from "@airlock/gateway-sdk";

const client = new AirlockGatewayClient({
    baseUrl: "https://gw.example.com",
    token: "your-token",
});

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
| `acknowledge(msgId, enforcerId)` | Acknowledge inbox message |
| `initiatePairing(request)` | Start pairing session |
| `resolvePairing(code)` | Resolve pairing code |
| `getPairingStatus(nonce)` | Poll pairing status |
| `completePairing(request)` | Complete pairing |
| `revokePairing(routingToken)` | Revoke a pairing |
| `getPairingStatusBatch(tokens)` | Batch check pairings |
| `sendHeartbeat(request)` | Presence heartbeat |
| `listEnforcers()` | List online enforcers |
| `getEnforcerPresence(id)` | Get enforcer presence |
| `submitDndPolicy(policy)` | Submit signed DND policy (`POST /v1/policy/dnd`) |
| `getEffectiveDndPolicies(enforcerId, workspaceId, sessionId?)` | Fetch effective DND policies (`GET /v1/policy/dnd/effective`) |

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
    baseUrl: "https://gw.example.com",
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
