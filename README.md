# Airlock Gateway Client SDKs

Multi-language client SDKs for the [Airlock Gateway](https://airlockapp.io) — the central routing service for human-in-the-loop AI agent approval, built on the [HARP protocol](https://harp-protocol.github.io).

> **HARP** (Human Approval Routing Protocol) is an open standard for secure, human-verified AI agent actions.
> See the [HARP specification](https://github.com/harp-protocol/harp-spec) for protocol details.

## Available SDKs

| Language | Path | Package |
|----------|------|---------|
| .NET C# | [`src/dotnet/`](src/dotnet/) | `Airlock.Gateway.Sdk` (NuGet) |
| Python | [`src/python/`](src/python/) | `airlock-gateway` (PyPI) |
| TypeScript | [`src/typescript/`](src/typescript/) | `@airlock/gateway-sdk` (NPM) |
| Go | [`src/go/`](src/go/) | `github.com/AirlockHQ/airlock-gateway-sdk-go` |
| Rust | [`src/rust/`](src/rust/) | `airlock-gateway` (crates.io) |

## Gateway API Surface

All SDKs cover the **enforcer-side** API:

- **Artifact Submission** — `POST /v1/artifacts`
- **Exchange Status** — `GET /v1/exchanges/{requestId}`
- **Decision Polling** — `GET /v1/exchanges/{requestId}/wait`
- **Exchange Withdrawal** — `POST /v1/exchanges/{requestId}/withdraw`
- **Acknowledgement** — `POST /v1/acks`
- **Pairing** — initiate, resolve, status, complete, revoke, batch-status
- **Presence** — heartbeat, list enforcers, get enforcer
- **Discovery** — `GET /echo`

## Authentication

All authenticated endpoints require a **Bearer JWT token** issued by the Airlock identity provider. Pass this token when constructing the client.

## HARP Envelope Format

All artifact/decision/ack messages use the [HARP Gateway Wire Envelope](https://github.com/harp-protocol/harp-spec):

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
.\scripts\package-sdks.ps1 -Sdk all -Version 0.1.0

# Build a single SDK
.\scripts\package-sdks.ps1 -Sdk dotnet -Version 0.1.0

# Build and push to registries
.\scripts\package-sdks.ps1 -Sdk all -Version 0.1.0 -Push `
    -NuGetApiKey "your-key" `
    -PyPiToken "your-token" `
    -NpmToken "your-token" `
    -CratesToken "your-token"
```

Output packages are placed in `dist/{language}/`.

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
- **Integration tests** — test suites running against a live gateway
- **CI/CD pipeline** — GitHub Actions workflow for automated build, test, and publish on tag

### Usage Examples

- **Per-language sample projects** — real-world enforcer client demonstrating artifact submission, decision polling, and pairing flow
- **Multi-SDK interop demo** — cross-language scenario showing the same workflow in all 5 SDKs

## Related Projects

- [Airlock](https://airlockapp.io) — Human-in-the-loop approval platform for AI agents
- [HARP Protocol](https://harp-protocol.github.io) — Open standard for human approval routing
- [HARP Specification](https://github.com/harp-protocol/harp-spec) — Protocol reference and specification

## License

This project is licensed under the [MIT License](LICENSE).
