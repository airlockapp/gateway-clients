# Airlock Integrations Gateway Client SDKs

Multi-language client SDKs for the [Airlock Integrations Gateway](https://airlock.dev) — the enforcer-facing API for human-in-the-loop AI agent approval.

This repository (**[airlockapp/gateway-clients](https://github.com/airlockapp/gateway-clients)**) is the **standalone** home for these SDKs. The same sources are also maintained under `gateway_sdk/` in the main Airlock product repository for integrated development; changes are synced from there into this repo.

Published names, install commands, and registry links are summarized on **[Gateway Client SDKs](https://airlockapp.io/docs/sdk/)** (airlockapp.io).

> **Note:** These SDKs cover only the enforcer-safe endpoints exposed by the Integrations Gateway.
> Approver-facing operations (decision submission, inbox management, pairing resolution/completion) are not available through this surface.

## Available SDKs

| Language | Path | Package |
|----------|------|---------|
| .NET C# | [`src/dotnet/`](src/dotnet/) | [`Airlock.Gateway.Sdk`](https://www.nuget.org/packages/Airlock.Gateway.Sdk) (NuGet) |
| Python | [`src/python/`](src/python/) | [`airlock-gateway`](https://pypi.org/project/airlock-gateway/) (PyPI) |
| TypeScript | [`src/typescript/`](src/typescript/) | [`@airlockapp/gateway-sdk`](https://www.npmjs.com/package/@airlockapp/gateway-sdk) (npm) |
| Go | [`src/go/`](src/go/) | [`airlock-gateway`](https://pkg.go.dev/github.com/airlockapp/gateway-clients/src/go/airlock) — `go get github.com/airlockapp/gateway-clients/src/go/airlock` |
| Rust | [`src/rust/`](src/rust/) | [`airlock-gateway`](https://crates.io/crates/airlock-gateway) (crates.io) |

## Gateway API Surface

All SDKs cover the **enforcer-side** endpoints:

| Endpoint | Method |
|----------|--------|
| `GET /echo` | Gateway discovery and health |
| `POST /v1/artifacts` | Submit an artifact for approval |
| `GET /v1/exchanges/{requestId}` | Get exchange status |
| `GET /v1/exchanges/{requestId}/wait` | Long-poll for decision |
| `POST /v1/exchanges/{requestId}/withdraw` | Withdraw a pending exchange |
| `POST /v1/pairing/initiate` | Start a new pairing session |
| `GET /v1/pairing/{nonce}/status` | Poll pairing status |
| `POST /v1/pairing/revoke` | Revoke a pairing |
| `POST /v1/pairing/pre-generate` | Pre-generate a pairing code (30-min TTL) |
| `POST /v1/pairing/claim` | Enforcer claims a pre-generated code |
| `POST /v1/presence/heartbeat` | Send a presence heartbeat |
| `GET /v1/policy/dnd/effective` | Fetch effective DND policies |
| `GET /v1/consent/status` | Check user consent for the enforcer app |

## Authentication

The SDKs support three user identity modes. PAT is the **recommended** method.

### Personal Access Token (PAT) — Recommended

The simplest and most secure option. Create a PAT from the Platform App or Mobile Approver, then set it on the client:

```python
client = AirlockGatewayClient(
    "https://igw.airlocks.io",
    client_id="your-client-id",
    client_secret="your-client-secret",
)
client.set_pat("airpat_...")
```

The SDK sends the PAT via the `X-PAT` header. PATs are prefixed with `airpat_` and can be created with a custom expiry date (max 1 year).

### Bearer Token (OAuth fallback)

Pass a JWT token issued by the Airlock Keycloak identity provider via Device Authorization Grant:

```python
client = AirlockGatewayClient("https://igw.airlocks.io", token="your-jwt-token")
```

### Enforcer App Credentials (ClientId / ClientSecret)

For third-party enforcer apps registered through the Developer Programme:

```python
client = AirlockGatewayClient(
    "https://igw.airlocks.io",
    client_id="your-client-id",
    client_secret="your-client-secret",
)
```

The SDK sends these as `X-Client-Id` and `X-Client-Secret` HTTP headers on every request.

### Dual Auth (Credentials + User Bearer Token)

Third-party enforcers that need user-scoped requests (e.g. consent-aware operations)
can authenticate with credentials **and** set a user's Bearer token after login:

```python
# 1. Create client with enforcer credentials
client = AirlockGatewayClient("https://igw.airlocks.io",
    client_id="your-client-id", client_secret="your-client-secret")

# 2. After user logs in (Device Auth Grant), set their token
client.set_bearer_token(access_token)
```

When both are present, the user's identity (PAT or Bearer token) takes precedence for user-scoped
operations, while credentials are still sent via `X-Client-Id` / `X-Client-Secret`.

> **Auth priority:** Gateway checks `X-PAT` first, then `Authorization: Bearer`, then app credentials.

> **Architecture Constraint:** Third-party enforcers must communicate **only** with the
> Integrations Gateway (`igw.airlocks.io`). The mobile app must communicate **only** with
> the Gateway (`gw.airlocks.io`). Direct backend access is not permitted for either.

## HARP Envelope Format

Artifact submission messages use the HARP Gateway Wire Envelope:

```json
{
  "msgId": "msg-...",
  "msgType": "artifact.submit",
  "requestId": "req-...",
  "createdAt": "2025-01-01T00:00:00Z",
  "sender": { "enforcerId": "..." },
  "body": { ... }
}
```

See each SDK's README for language-specific usage examples.

## Pairing & End-to-End Encryption

During workspace pairing, the enforcer generates an **X25519 keypair** and sends the public key in the `PairingInitiateRequest`. When pairing completes, the gateway returns the approver's X25519 public key in the `responseJson` field of the `PairingStatusResponse`. The SDK then:

1. **ECDH key agreement** — computes the shared secret via X25519 scalar multiplication
2. **HKDF-SHA256** — derives a 32-byte AES-256 key using info string `HARP-E2E-AES256GCM`
3. **Saves** the derived key as `encryptionKey` in the enforcer configuration

This key is used for AES-256-GCM artifact encryption and decision decryption.

### Crypto Dependencies

| SDK | Library | X25519 | HKDF |
|-----|---------|--------|------|
| .NET | `NSec.Cryptography` | `KeyAgreementAlgorithm.X25519` | `HkdfSha256.DeriveBytes` |
| Go | `crypto/ecdh` (stdlib) | `ecdh.X25519()` | `golang.org/x/crypto/hkdf` |
| Python | `cryptography` | `X25519PrivateKey` | `HKDF(SHA256)` |
| Rust | `x25519_dalek` | `StaticSecret::diffie_hellman` | `hkdf::Hkdf<Sha256>` |
| TypeScript | `libsodium-wrappers-sumo` | `crypto_scalarmult` | `crypto.hkdfSync` |

> **Note:** All implementations follow the patterns in [harp-protocol/samples](https://github.com/harp-protocol/samples).

## Building & CI/CD

**Local builds:** Use each language’s tooling from `src/{dotnet,python,typescript,go,rust}/` — see the per-SDK READMEs (build, test, and optional pack commands).

**CI/CD:** Automated build, test, and release publishing are handled by **GitHub Actions** (workflows under [`.github/workflows`](.github/workflows) in this repository).

| SDK | Typical local build | Registry (releases) |
|-----|---------------------|---------------------|
| .NET | `dotnet build` / `dotnet test` on `Airlock.Gateway.Sdk` | nuget.org |
| Python | `pip install -e ".[dev]"` / `pytest` | PyPI |
| TypeScript | `npm install` / `npm run build` / `npm test` | npm |
| Go | `go test ./airlock/...` | pkg.go.dev (module tags) |
| Rust | `cargo build` / `cargo test` | crates.io |

## Test Enforcer CLIs

Each SDK includes a fully interactive TUI test enforcer application that demonstrates the complete enforcer lifecycle — setup, sign-in, consent, pairing, heartbeat, artifact submission, decision polling, withdrawal, unpairing, and sign-out.

| Language | Path | Run Command |
|----------|------|-------------|
| .NET | [`src/dotnet/`](src/dotnet/) | `dotnet run --project Airlock.Gateway.Sdk.TestEnforcer` |
| TypeScript | [`src/typescript/test-enforcer/`](src/typescript/test-enforcer/) | `npm start` (build SDK first: `npm run build` in parent) |
| Go | [`src/go/`](src/go/) | `go run ./cmd/test-enforcer` |
| Python | [`src/python/`](src/python/) | `python test_enforcer.py` |
| Rust | [`src/rust/`](src/rust/) | `cargo run --bin test_enforcer` |

Configuration is persisted to `~/.airlock/test-enforcer-{language}.json` and restored automatically on subsequent runs.

All test enforcers default to **PAT as the recommended authentication** method, with OAuth Device Auth Grant as a fallback. The menu shows "Set PAT (recommended)" first.

See each SDK's README for detailed prerequisites and setup instructions.

## Roadmap

### SDK Enhancements (v2)

- **WebSocket / SSE real-time connections** — enforcer live streams, presence events
- ~~**E2E encryption helpers**~~ ✅ Delivered — X25519 ECDH key exchange, HKDF-SHA256, AES-256-GCM encrypt/decrypt
- **Retry / backoff policies** — built-in exponential backoff for `WaitForDecision` polling loops

### Quality & Documentation

- **API reference docs** — auto-generated per language (DocFX, Sphinx, TypeDoc, godoc, rustdoc)
- **Integration tests** — test suites running against a live gateway
- **CI/CD pipeline** — GitHub Actions workflow for automated build, test, and publish on tag

### Usage Examples

- **Per-language sample projects** — real-world enforcer client demonstrating artifact submission, decision polling, and pairing flow
- **Multi-SDK interop demo** — cross-language scenario showing the same workflow in all 5 SDKs
