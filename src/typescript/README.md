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

### Dual Auth (setBearerToken)

After creating a client with credentials, set a user's Bearer token to enable user-scoped operations:

```typescript
// After user login (Device Auth Grant or Auth Code + PKCE)
client.setBearerToken(accessToken);
```

### Authentication by Enforcer App Kind

| EnforcerAppKind | OAuth2 Flow | SDK Methods | Reason |
|---|---|---|---|
| **Agent** | Device Authorization Grant (RFC 8628) | `login(onUserCode)` | Headless/CLI — no embedded browser, user opens URL + enters code separately |
| **Desktop** | Device Authorization Grant (RFC 8628) | `login(onUserCode)` | Desktop app — delegates to external browser for user code entry |
| **VsCodeExtension** | Device Authorization Grant (RFC 8628) | `login(onUserCode)` | VS Code extension — no embedded browser, uses device code flow |
| **Web** | Auth Code + PKCE (RFC 7636) | `loginWithAuthCode(onBrowserUrl, port?)` or `getAuthorizationUrl(redirectUri)` + `exchangeCode(code, redirectUri, verifier)` | Browser-capable — can handle redirects and local callback |
| **Mobile** | Auth Code + PKCE (RFC 7636) | `getAuthorizationUrl(redirectUri)` + `exchangeCode(code, redirectUri, verifier)` | Uses system browser + deep-link callback (manages redirect externally) |

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
| `checkConsent()` | Check app consent status |

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

## Encryption

The test enforcer uses **X25519 ECDH key exchange** via [libsodium-wrappers-sumo](https://github.com/nickovs/libsodium-wrappers-sumo):

- `sodium.crypto_box_keypair()` — generates an X25519 keypair
- `sodium.crypto_scalarmult(privateKey, peerPublicKey)` — X25519 ECDH scalar multiplication
- `crypto.hkdfSync('sha256', sharedSecret, ...)` — HKDF-SHA256 key derivation (info: `HARP-E2E-AES256GCM`)

During pairing, the test enforcer generates an X25519 keypair, sends the public key in the `PairingInitiateRequest`, and derives the shared encryption key from the approver's public key returned in `PairingStatusResponse.responseJson`.

## Test Enforcer CLI

A fully interactive TUI application that demonstrates the complete enforcer lifecycle — setup wizard, Device Auth Grant sign-in, consent check, workspace pairing, background presence heartbeat, artifact submission with decision polling, withdrawal, unpairing, and sign-out.

### Prerequisites

- Node.js 18+
- A running Airlock platform (Gateway + Keycloak)

### Run

```bash
# From the repo root — build the SDK first (required once)
cd src/typescript
npm install
npm run build

# Run the test enforcer
cd test-enforcer
npm install
npm start
```

On first run, the setup wizard will prompt for Gateway URL, Client ID, Client Secret, Enforcer ID, and Workspace Name. Configuration is saved to `~/.airlock/test-enforcer-typescript.json` and restored on subsequent runs.

## License

MIT
