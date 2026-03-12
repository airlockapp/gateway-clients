# Airlock Gateway Client SDKs

Multi-language client SDKs for communicating with the [Airlock Gateway](https://airlock.dev) — the central routing service for human-in-the-loop AI agent approval.

## Available SDKs

| Language | Path | Package |
|----------|------|---------|
| .NET C# | [`src/dotnet/`](src/dotnet/) | `Airlock.Gateway.Sdk` (NuGet) |
| Python | [`src/python/`](src/python/) | `airlock-gateway` (PyPI) |
| TypeScript | [`src/typescript/`](src/typescript/) | `@airlock/gateway-sdk` (NPM) |
| Go | [`src/go/`](src/go/) | `github.com/AirlockHQ/airlock-gateway-sdk-go` |
| Rust | [`src/rust/`](src/rust/) | `airlock-gateway-sdk` (crates.io) |

## Gateway API Surface

All SDKs cover the **enforcer-side** API:

- **Artifact Submission** — `POST /v1/artifacts`
- **Exchange Status** — `GET /v1/exchanges/{requestId}`
- **Decision Polling** — `GET /v1/exchanges/{requestId}/wait`
- **Exchange Withdrawal** — `POST /v1/exchanges/{requestId}/withdraw`
- **Acknowledgement** — `POST /v1/acks`
- **Pairing** — initiate, resolve, status, complete, revoke, batch-status
- **Presence** — heartbeat, list enforcers, get enforcer
- **DND Policies** — submit and query DND rules:
  - `POST /v1/policy/dnd`
  - `GET /v1/policy/dnd/effective?enforcerId=...&workspaceId=...&sessionId=...`
- **Discovery** — `GET /echo`

## Authentication

All authenticated endpoints require a **Bearer JWT token** issued by the Airlock Keycloak identity provider. Pass this token when constructing the client.

## HARP Envelope Format

All artifact/decision/ack messages use the HARP Gateway Wire Envelope:

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

## Building & Packaging

A unified PowerShell script handles building, testing, packaging, and publishing all SDKs:

```powershell
# Build and package all SDKs
.\gateway_sdk\scripts\package-sdks.ps1 -Sdk all -Version 0.1.0

# Build a single SDK
.\gateway_sdk\scripts\package-sdks.ps1 -Sdk dotnet -Version 0.1.0

# Build and push to registries
.\gateway_sdk\scripts\package-sdks.ps1 -Sdk all -Version 0.1.0 -Push `
    -NuGetApiKey "your-key" `
    -PyPiToken "your-token" `
    -NpmToken "your-token" `
    -CratesToken "your-token"
```

Output packages are placed in `gateway_sdk/dist/{language}/`.

| SDK | Registry | Command |
|-----|----------|---------|
| .NET | nuget.org | `dotnet nuget push` |
| Python | PyPI | `twine upload` |
| TypeScript | NPM | `npm publish` |
| Go | pkg.go.dev | `git tag` + `git push` |
| Rust | crates.io | `cargo publish` |

## Roadmap

### SDK Enhancements (v2)

- **Approver-side endpoints** — inbox listing, decision submission, workspace management
- **WebSocket / SSE real-time connections** — enforcer and approver live streams, presence events
- **E2E encryption helpers** — key exchange, artifact encrypt/decrypt, signature verification
- **Retry / backoff policies** — built-in exponential backoff for `WaitForDecision` polling loops

### Quality & Documentation

- **API reference docs** — auto-generated per language (DocFX, Sphinx, TypeDoc, godoc, rustdoc)
- **Integration tests** — test suites running against a live gateway (via .NET Aspire test infrastructure)
- **CI/CD pipeline** — GitHub Actions workflow for automated build, test, and publish on tag

### Usage Examples

- **Per-language sample projects** — real-world enforcer client demonstrating artifact submission, decision polling, and pairing flow
- **Multi-SDK interop demo** — cross-language scenario showing the same workflow in all 5 SDKs
