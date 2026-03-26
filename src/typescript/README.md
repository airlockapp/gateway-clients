# @airlockapp/gateway-sdk (TypeScript)

A zero-dependency TypeScript client SDK for the Airlock Integrations Gateway API. Uses the native `fetch` API — works in Node.js 18+ and modern browsers.

## Installation

**npm:** [@airlockapp/gateway-sdk](https://www.npmjs.com/package/@airlockapp/gateway-sdk)

```bash
npm install @airlockapp/gateway-sdk
```

## API reference

### `AirlockGatewayClient` (Integrations Gateway)

| HTTP | Method |
|------|--------|
| `GET /echo` | `echo` |
| `POST /v1/artifacts` | `submitArtifact` |
| `GET /v1/exchanges/{requestId}` | `getExchangeStatus` |
| `GET /v1/exchanges/{requestId}/wait` | `waitForDecision` |
| `POST /v1/exchanges/{requestId}/withdraw` | `withdrawExchange` |
| `POST /v1/acks` | `submitAck` |
| `POST /v1/pairing/initiate` | `initiatePairing` |
| `GET /v1/pairing/{nonce}/status` | `getPairingStatus` |
| `POST /v1/pairing/revoke` | `revokePairing` |
| `POST /v1/pairing/claim` | `claimPairing` |
| `POST /v1/presence/heartbeat` | `sendHeartbeat` |
| `GET /v1/policy/dnd/effective` | `getEffectiveDndPolicies` |
| `GET /v1/consent/status` | `checkConsent` |

**Helper:** `encryptAndSubmitArtifact` — builds the request and calls `POST /v1/artifacts`.

### `AirlockAuthClient` (IdP / OAuth)

| Purpose | Method |
|---------|--------|
| OIDC discovery | `discover` |
| Device code login | `login` |
| Auth code + PKCE (local callback) | `loginWithAuthCode` |
| Auth code + PKCE (manual redirect) | `getAuthorizationUrl`, `exchangeCode` |
| Tokens | `refreshTokenAsync`, `getAccessToken` |
| Sign out | `logout` |

## Quick Start

### With Bearer Token

```typescript
import { AirlockGatewayClient } from "@airlockapp/gateway-sdk";

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

### With Personal Access Token (PAT)

PAT is the recommended authentication for user-scoped operations. It replaces the Bearer token and is sent via the `X-PAT` header:

```typescript
// After obtaining a PAT from the mobile app (Settings → Access Tokens)
client.setPat("airlock_pat_...");

// Clear PAT when no longer needed
client.setPat(undefined);
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

## Pairing

### Standard Pairing (Enforcer-Initiated)

```typescript
// 1. Initiate a pairing session
const resp = await client.initiatePairing({
    enforcerId: "my-enforcer",
    workspaceName: "my-project",
    x25519PublicKey: myPublicKey,
});

// 2. Display pairing code to user
console.log(`Pairing code: ${resp.pairingCode}`);

// 3. Poll for approval from the mobile app
const status = await client.getPairingStatus(resp.nonce);
// status.state === "Completed" → save status.routingToken
```

### Pre-Generated Code Pairing (Approver-Initiated)

When the mobile app pre-generates a pairing code, the enforcer claims it:

```typescript
const claim = await client.claimPairing({
    code: "ABCD-1234",
    enforcerId: "my-enforcer",
    workspaceName: "my-project",
    x25519PublicKey: myPublicKey,
});
// claim.routingToken is ready to use
```

## Consent Check

Enforcer apps must verify user consent before submitting artifacts:

```typescript
import { AirlockGatewayError } from "@airlockapp/gateway-sdk";

try {
    const status = await client.checkConsent();
    // status === "approved" — proceed normally
} catch (e) {
    if (e instanceof AirlockGatewayError) {
        if (e.errorCode === "app_consent_required") {
            // User hasn't granted consent
        } else if (e.errorCode === "app_consent_pending") {
            // Consent request sent, waiting for approval
        }
    }
}
```

## Submit and Poll

### Encrypt and submit (Node.js)

`encryptAndSubmitArtifact` runs RFC 8785 JSON canonicalization, SHA-256 of the canonical bytes, AES-256-GCM encryption with your pairing-derived key, then `submitArtifact`. It uses `node:crypto` and is loaded only when you call this method (dynamic import).

```typescript
const requestId = await client.encryptAndSubmitArtifact({
    enforcerId: "my-enforcer",
    plaintextPayload: JSON.stringify({ kind: "shell", cmd: "npm publish" }),
    encryptionKeyBase64Url: derivedAes256KeyFromPairing,
    metadata: { routingToken: "rt-abc" },
});
```

### Payload Schema for Mobile Display

The `plaintextPayload` is encrypted end-to-end and shown to the mobile approver. Any valid JSON object is supported — the mobile app renders every top-level key as a labelled row. Nested objects and arrays are pretty-printed. Non-JSON strings are displayed as plain monospace text.

> **Note:** The `extensions` field is reserved for HARP protocol extensions (e.g., `org.harp.requestedActions` for custom action buttons). Do not include it manually if using the enforcer SDK's built-in action support.

For custom flows, the package also exports `canonicalizeJson`, `sha256Hex`, and `aesGcmEncrypt` (all Node-only).

### Manual ciphertext

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
| `setPat(pat)` | Set Personal Access Token (X-PAT header) |
| `setBearerToken(token)` | Set Bearer token for user-scoped operations |
| `checkConsent()` | Check if user has consented to this enforcer app |
| `submitArtifact(request)` | Submit artifact for approval |
| `encryptAndSubmitArtifact(request)` | JCS + SHA-256 + AES-GCM encrypt, then submit (Node.js) |
| `getExchangeStatus(requestId)` | Get exchange status |
| `waitForDecision(requestId, timeout)` | Long-poll for decision |
| `withdrawExchange(requestId)` | Withdraw pending exchange |
| `submitAck(msgId, [requestId])` | Acknowledge receipt of a decision (fire-and-forget) |
| `initiatePairing(request)` | Start pairing session |
| `claimPairing(request)` | Claim a pre-generated pairing code |
| `getPairingStatus(nonce)` | Poll pairing status |
| `revokePairing(routingToken)` | Revoke a pairing |
| `sendHeartbeat(request)` | Presence heartbeat |
| `getEffectiveDndPolicies(enforcerId, workspaceId, sessionId?)` | Fetch effective DND policies |

## Error Handling

All errors throw `AirlockGatewayError` with helper getters:

```typescript
import { AirlockGatewayError } from "@airlockapp/gateway-sdk";

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

## Encryption

The test enforcer uses **X25519 ECDH key exchange** via [libsodium-wrappers-sumo](https://github.com/nickovs/libsodium-wrappers-sumo):

- `sodium.crypto_box_keypair()` — generates an X25519 keypair
- `sodium.crypto_scalarmult(privateKey, peerPublicKey)` — X25519 ECDH scalar multiplication
- `crypto.hkdfSync('sha256', sharedSecret, ...)` — HKDF-SHA256 key derivation (info: `HARP-E2E-AES256GCM`)

During pairing, the enforcer generates an X25519 keypair, sends the public key in the pairing request, and derives the shared encryption key from the approver's public key returned in the pairing response.

## Test Enforcer CLI

A fully interactive TUI application that demonstrates the complete enforcer lifecycle — setup wizard, Device Auth Grant sign-in, PAT configuration, consent check, workspace pairing (both standard and pre-generated code), background presence heartbeat, artifact submission with decision polling, withdrawal, unpairing, and sign-out.

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

## Requirements

- Node.js 18+ (native `fetch`) or modern browser for HTTP client use
- `encryptAndSubmitArtifact` / `aesGcmEncrypt` require Node.js (`node:crypto`)
- Zero npm runtime dependencies for the HTTP client

## Development

```bash
npm install
npm run build
npm test
```

## License

MIT

## Documentation & Resources

For full integration tutorials, conceptual overviews, and detailed API references, please visit the official Airlock Documentation:
- **[Airlock Developer Guide](https://airlockapp.io/docs/developer-guide/)**
- **[Airlock SDK Reference & Setup](https://airlockapp.io/docs/sdk/)**
