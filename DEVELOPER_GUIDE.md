# Airlock Developer Programme & Enforcer App Guide

> **Audience:** Developers who want to build third-party enforcer applications that integrate with the Airlock security gateway for human-in-the-loop AI agent approval.

> **Where this document lives:** It ships with the SDK sources in the **airlock-gateway-clients** repository. The same guide is mirrored under `gateway_sdk/DEVELOPER_GUIDE.md` in the main Airlock application monorepo.

---

## Table of Contents

- [Overview](#overview)
- [Step 1 — Join the Developer Programme](#step-1--join-the-developer-programme)
- [Step 2 — Register an Enforcer App](#step-2--register-an-enforcer-app)
  - [App Kind Reference](#app-kind-reference)
  - [Authentication Methods](#authentication-methods)
- [Step 3 — Integrate Using the Gateway SDK](#step-3--integrate-using-the-gateway-sdk)
  - [Install the SDK](#install-the-sdk)
  - [Initialize the Client](#initialize-the-client)
- [Step 4 — Implement the Enforcer Lifecycle](#step-4--implement-the-enforcer-lifecycle)
  - [1. Discovery](#1-discovery)
  - [2a. PAT Authentication (Recommended)](#2a-pat-authentication-recommended)
  - [2b. User Authentication (Device Auth Grant — Fallback)](#2b-user-authentication-device-auth-grant--fallback)
  - [3. Consent Check](#3-consent-check)
  - [4. Workspace Pairing](#4-workspace-pairing)
  - [4b. Pre-generated Pairing Code](#4b-pre-generated-pairing-code)
  - [5. Presence Heartbeat](#5-presence-heartbeat)
  - [6. Artifact Submission & Decision Polling](#6-artifact-submission--decision-polling)
  - [7. Unpairing & Sign-Out](#7-unpairing--sign-out)
- [Step 5 — Manage Your App](#step-5--manage-your-app)
- [User Consent Flow](#user-consent-flow)
- [Architecture Constraints](#architecture-constraints)
- [Test Enforcer Reference Implementations](#test-enforcer-reference-implementations)
- [Gateway SDK Reference](#gateway-sdk-reference)

---

## Overview

Airlock is a security platform that enables **human-in-the-loop approval** for AI agent operations. An **enforcer** is software that intercepts agent actions (commands, code changes, API calls) and routes them through Airlock for human review before execution.

To build a third-party enforcer, you need to:

1. **Join the Developer Programme** — register as a developer via the Airlock Platform.
2. **Register an Enforcer App** — create an app entry to receive API credentials.
3. **Integrate the Gateway SDK** — use one of the multi-language SDKs to communicate with the Integrations Gateway.
4. **Implement the enforcer lifecycle** — discovery, auth, consent, pairing, heartbeat, artifact submission, and decision polling.

---

## Step 1 — Join the Developer Programme

Before you can create enforcer apps, you must apply to the Airlock Developer Programme.

### How to Apply

1. Sign in to the **Airlock Platform** at your organization's platform URL.
2. Navigate to **Developer Programme** in the sidebar.
3. Fill in the application form:

| Field | Required | Description |
|-------|----------|-------------|
| **Full Name / Organization Name** | ✅ | Your name or company name. Publicly visible to end users who authorize your apps. |
| **Contact Email** | ✅ | Developer contact email. Publicly visible to end users. |
| **Web Page** | ❌ | Your website or project page. Publicly visible. |
| **Intended Use Description** | ✅ | Describe your use case, what you plan to build, and how it will interact with the Airlock gateway. Max 2000 characters. |

> ⚠️ **Public Visibility Notice:** Your Contact Email, Name/Organization, and Web Page will be displayed to end users when they are asked to authorize your applications (in the mobile app, consent emails, and the platform web UI).

4. Submit your application. An Airlock administrator will review it.
5. You will be notified when your application is approved or rejected.

### Application States

| Status | Meaning |
|--------|---------|
| **Pending** | Submitted, awaiting admin review |
| **Approved** | You can now create enforcer apps |
| **Rejected** | Application denied — you may re-apply |
| **Suspended** | Developer access temporarily revoked — contact support |

---

## Step 2 — Register an Enforcer App

Once approved, you can create one or more enforcer apps from the Platform web UI under **Developer Programme → My Apps**.

### Create App — Required Fields

| Field | Description |
|-------|-------------|
| **Name** | Display name for your app. Must be unique system-wide. Max 128 characters. |
| **Kind** | The type of enforcer application (see [App Kind Reference](#app-kind-reference) below). |
| **Is Open Source** | Whether your enforcer's source code is publicly available. |
| **Description** | What your app does and how it works. Max 2000 characters. |
| **Home Page URL** | *(Optional)* Link to your app's website or documentation. |
| **Allowed Origins** | *(Public clients only)* JSON array of allowed origins for CORS, e.g. `["https://myapp.com", "http://localhost:3000"]`. |

### What You Receive

When you create an app, the system generates:

- **App ID** — A human-readable identifier in the format `ABC-1234567` (3 uppercase letters + 7 digits).
- **Client ID** — A 20-character alphanumeric credential (used for API authentication).
- **Client Secret** — A 40-character secret (shown only once at creation — save it!). You can rotate the secret later but the original cannot be retrieved.
- **Secret Prefix** — The first 4 characters of the secret, displayed for identification (e.g. `abcd••••`).

### App Kind Reference

The `Kind` determines the **client type** (Public vs Confidential), which in turn determines how your app authenticates with the Integrations Gateway.

| Kind | Client Type | Auth Method | Typical Use Case |
|------|------------|-------------|------------------|
| **Web** | Public | Client ID + Origin validation | Browser-based enforcer UIs, web dashboards |
| **Mobile** | Public | Client ID + Origin validation | Mobile enforcer apps |
| **Agent** | Confidential | Client ID + Client Secret | AI agent plugins, autonomous enforcers |
| **Desktop** | Confidential | Client ID + Client Secret | Desktop IDE plugins, CLI tools |
| **VsCodeExtension** | Confidential | Client ID + Client Secret | VS Code / IDE extension enforcers |

### Authentication Methods

#### Public Clients (Web, Mobile)

Public clients cannot store secrets safely. They authenticate using:

- **`X-Client-Id`** header — your app's Client ID.
- **Origin validation** — the gateway checks the `Origin` header against your app's allowed origins list.

```http
GET /v1/exchanges/req-123 HTTP/1.1
Host: igw.airlocks.io
X-Client-Id: ABCDEFGHJKLMNPRSTUVWXYZabc
Origin: https://myapp.com
Authorization: Bearer <user-jwt>
```

#### Confidential Clients (Agent, Desktop, VsCodeExtension)

Confidential clients authenticate using both credentials:

- **`X-Client-Id`** header — your app's Client ID.
- **`X-Client-Secret`** header — your app's Client Secret (SHA-256 verified server-side).

```http
POST /v1/artifacts HTTP/1.1
Host: igw.airlocks.io
X-Client-Id: ABCDEFGHJKLMNPRSTUVWXYZabc
X-Client-Secret: abcdEFGH1234567890abcdEFGH1234567890abcd
Authorization: Bearer <user-jwt>
```

#### Dual Authentication (Credentials + User Token)

Most enforcer operations are **user-scoped** — they act on behalf of a specific user. The full authentication flow uses **both**:

1. **App credentials** (`X-Client-Id` + `X-Client-Secret` or Origin) — identifies your app.
2. **User identity** — one of:
   - **`X-PAT` header** (recommended) — a Personal Access Token created from the Platform App or Mobile Approver.
   - **`Authorization: Bearer <jwt>`** — a JWT obtained via the Device Authorization Grant flow.

> **Auth priority:** The gateway checks `X-PAT` first. If not present, it falls back to the `Authorization: Bearer` JWT.

When both are present:
- The `X-PAT` or `Authorization` header identifies the user.
- The `X-Client-Id` / `X-Client-Secret` headers identify the app.
- The gateway verifies both independently.

---

## Step 3 — Integrate Using the Gateway SDK

### Install the SDK

| Language | Install Command | Package |
|----------|----------------|---------|
| .NET C# | `dotnet add package Airlock.Gateway.Sdk` | [NuGet](https://nuget.org) |
| Python | `pip install airlock-gateway` | [PyPI](https://pypi.org) |
| TypeScript | `npm install @airlock/gateway-sdk` | [NPM](https://npmjs.com) |
| Go | `go get github.com/AirlockHQ/airlock-gateway-sdk-go` | [Go Modules](https://pkg.go.dev) |
| Rust | `cargo add airlock-gateway-sdk` | [crates.io](https://crates.io) |

### Initialize the Client

All SDKs follow the same initialization pattern — provide the gateway URL plus your credentials.

**Python:**
```python
from airlock_gateway import AirlockGatewayClient

client = AirlockGatewayClient(
    "https://igw.airlocks.io",
    client_id="your-client-id",
    client_secret="your-client-secret",
)
```

**.NET C#:**
```csharp
var httpClient = new HttpClient { BaseAddress = new Uri("https://igw.airlocks.io") };
httpClient.DefaultRequestHeaders.Add("X-Client-Id", "your-client-id");
httpClient.DefaultRequestHeaders.Add("X-Client-Secret", "your-client-secret");

var client = new AirlockGatewayClient(httpClient);
```

**TypeScript:**
```typescript
import { AirlockGatewayClient } from '@airlock/gateway-sdk';

const client = new AirlockGatewayClient(
  'https://igw.airlocks.io',
  { clientId: 'your-client-id', clientSecret: 'your-client-secret' }
);
```

**Go:**
```go
client := airlock.NewClient(
    "https://igw.airlocks.io",
    airlock.WithClientCredentials("your-client-id", "your-client-secret"),
)
```

---

## Step 4 — Implement the Enforcer Lifecycle

A fully functional enforcer follows this lifecycle:

```
Discovery → Set PAT (or Sign In) → Consent Check → Pair → Heartbeat ↺
                                                              ↓
                                                  Submit Artifact → Wait for Decision
                                                              ↓
                                                      Unpair → Sign Out
```

### 1. Discovery

Discover the gateway's identity provider (IdP) configuration:

```
GET /v1/integrations/discovery
```

Response:
```json
{
  "idp": {
    "baseUrl": "https://auth.airlocks.io/realms/airlock",
    "clientId": "airlock-integrations"
  },
  "auth": {
    "patSupported": true
  }
}
```

Use the discovered `baseUrl` and `clientId` for the OIDC Device Authorization Grant flow (if not using PAT).

### 2a. PAT Authentication (Recommended)

The simplest way to authenticate. The user creates a PAT from the **Platform App** (Settings → Access Tokens) or the **Mobile Approver**.

PATs are prefixed with `airpat_`, have a configurable expiry (max 1 year), and can be revoked at any time.

```python
# Set the PAT on the client
client.set_pat("airpat_...")
```

The SDK sends the PAT via the `X-PAT` header on every request. No OIDC discovery or token refresh is needed.

> **Tip:** PAT is the recommended auth method for all enforcer types. Use Device Auth Grant only when you need interactive browser-based login.

### 2b. User Authentication (Device Auth Grant — Fallback)

Third-party enforcers authenticate end users via the **OAuth 2.0 Device Authorization Grant** (RFC 8628). This is the same flow used by tools like the GitHub CLI.

**Flow:**

1. Request a device code from the discovered Keycloak endpoint.
2. Display the `verification_uri_complete` and `user_code` to the user.
3. The user opens the URL in a browser and enters the code (or clicks the complete URL).
4. Poll the token endpoint until the user authorizes.
5. Receive `access_token` and `refresh_token`.
6. Set the access token on the SDK client:

```python
# After obtaining the access token
client.set_bearer_token(access_token)
```

> **OIDC Client ID:** Use `airlock-integrations` as the `client_id` for the Device Auth Grant. This is the public Keycloak client configured for enforcer integrations.

### 3. Consent Check

Before an enforcer can interact with a user's workspaces, the user must **consent** to your app's access. After the user signs in, check consent status:

```
GET /v1/consents/check
```

Possible outcomes:

| Response | Meaning | Action |
|----------|---------|--------|
| `200 OK` with status `"Allowed"` | User has already consented | Continue to pairing |
| `403` with error `app_consent_required` | First-time consent needed | A consent request was automatically sent to the user's mobile app and email. Wait for them to approve. |
| `403` with error `app_consent_pending` | Consent previously requested but not yet granted | Wait for the user to approve via mobile app or email |

The consent request shows your **developer profile** (name, contact email, web page) and **app details** (name, description, kind, open source status) to the end user so they can make an informed decision.

### 4. Workspace Pairing

After consent is granted, pair the enforcer to a user's workspace:

```python
response = client.initiate_pairing(
    device_id="dev-my-machine",
    enforcer_id="my-enforcer",
    enforcer_label="My Custom Enforcer",
    workspace_name="default",
)

# Display the pairing code to the user
print(f"Pairing code: {response.pairing_code}")
print("Enter this code in the Airlock mobile app.")
```

The user enters the pairing code in their mobile app. Poll for completion:

```python
status = client.get_pairing_status(response.pairing_nonce)
if status.state == "completed":
    routing_token = status.routing_token
    # Save this token — you'll need it for all subsequent requests
```

The **routing token** is your key to the paired workspace. Include it in artifact submission metadata.

### 4b. Pre-generated Pairing Code

As an alternative to the standard pairing flow, an approver can **pre-generate a pairing code** from the Mobile Approver. The enforcer then **claims** the code without needing to initiate a fresh pairing session.

**Approver generates code** (from Mobile Approver):
```
POST /v1/pairing/pre-generate
```
This creates a pairing session with a 30-minute TTL and returns a pairing code.

**Enforcer claims the code:**
```python
response = client.claim_pairing(
    pairing_code="ABCD-1234",
    enforcer_id="my-enforcer",
    enforcer_label="My Custom Enforcer",
    workspace_name="default",
)
routing_token = response.routing_token
```

Once claimed, the enforcer receives the routing token immediately — no polling needed.

### 5. Presence Heartbeat

While paired, send periodic heartbeats to maintain online presence:

```python
client.send_heartbeat(
    enforcer_id="my-enforcer",
    enforcer_label="My Custom Enforcer",
    workspace_name="default",
)
```

**Recommendation:** Send heartbeats every 30 seconds in a background thread/task.

### 6. Artifact Submission & Decision Polling

This is the core enforcement loop. When your enforcer intercepts an agent action:

**Submit the artifact:**
```python
request_id = client.submit_artifact(
    enforcer_id="my-enforcer",
    artifact_type="command.review",
    artifact_hash="sha256-of-content",
    ciphertext={
        "alg": "xchacha20-poly1305",
        "data": "<base64-encrypted-payload>",
        "nonce": "<base64-nonce>",
        "tag": "<base64-auth-tag>",
    },
    metadata={
        "routingToken": routing_token,
        "workspaceName": "default",
    },
)
```

**Wait for the decision (long-poll):**
```python
decision = client.wait_for_decision(request_id, timeout_seconds=25)

if decision and decision.body:
    if decision.body.decision == "approve":
        # Execute the agent's action
        pass
    else:
        # Block the agent's action
        reason = decision.body.reason  # Optional reason from the approver
```

**Withdraw a pending request (if the agent cancels or times out):**
```python
client.withdraw_exchange(request_id)
```

### 7. Unpairing & Sign-Out

**Unpair from the workspace:**
```python
client.revoke_pairing(routing_token)
```

**Sign out the user** by revoking the refresh token at the Keycloak endpoint.

---

## Step 5 — Manage Your App

From the Platform UI, you can:

| Action | Description |
|--------|-------------|
| **View credentials** | See your Client ID and secret prefix |
| **Rotate secret** | Generate a new Client Secret (invalidates the previous one) |
| **Update allowed origins** | Change CORS origins for Public clients |
| **Revoke app** | Permanently deactivate the app (irreversible) |

---

## User Consent Flow

When your enforcer first checks consent for a user, Airlock automatically:

1. Creates a **consent request** associated with your app and the user.
2. Sends a **push notification** to the user's paired mobile device.
3. Sends a **consent request email** to the user, containing:
   - Your app name, description, and kind
   - Your developer profile (name, contact email, web page)
   - One-click **Allow** / **Deny** buttons

The user can manage app authorizations from:
- **Mobile app** → Settings → Authorized Apps
- **Platform web UI** → Authorized Apps

Consent states:

| Status | Meaning |
|--------|---------|
| **Pending** | Awaiting user action |
| **Allowed** | User granted access |
| **Denied** | User explicitly denied access |
| **Revoked** | User revoked previously granted access |

Users can **re-authorize** (re-allow) a previously denied or revoked app at any time.

---

## Architecture Constraints

> 🔒 **Important:** Third-party enforcers must communicate **only** with the **Integrations Gateway** (`igw.airlocks.io`). Direct access to the backend API is not permitted.

```
┌─────────────────┐     HTTPS       ┌──────────────────────┐
│  Your Enforcer   │ ──────────────→ │ Integrations Gateway │
│  (3rd-party app) │                 │  (igw.airlocks.io)   │
└─────────────────┘                  └──────────┬───────────┘
                                                │
                                     Internal routing
                                                │
                                     ┌──────────▼───────────┐
                                     │   Platform Backend    │
                                     │   (not accessible     │
                                     │    to enforcers)      │
                                     └──────────────────────┘
```

- **Integrations Gateway** validates your app credentials, enforces rate limits, and proxies requests to the backend.
- **Rate limiting** is applied per-app. Default: 60 requests per 60-second window. Admins can customize per-app limits or grant exemptions.

---

## Test Enforcer Reference Implementations

The SDK repository includes **test enforcer CLI applications** that demonstrate the complete enforcer lifecycle. These are working implementations you can use as a starting point for your own enforcer.

### Available Test Enforcers

| Language | Path | Entry Point |
|----------|------|-------------|
| **.NET C#** | [`src/dotnet/Airlock.Gateway.Sdk.TestEnforcer/`](src/dotnet/Airlock.Gateway.Sdk.TestEnforcer/) | `Program.cs` |
| **TypeScript** | [`src/typescript/test-enforcer/`](src/typescript/test-enforcer/) | `index.ts` |
| **Go** | [`src/go/cmd/test-enforcer/`](src/go/cmd/test-enforcer/) | `main.go` |
| **Python** | [`src/python/test_enforcer.py`](src/python/test_enforcer.py) | `test_enforcer.py` |

### Scenarios & Flows Covered

All test enforcers implement the same set of scenarios:

#### 🔧 Setup & Configuration
- **Interactive setup wizard** — prompts for Gateway URL, Client ID, Client Secret, Enforcer ID, and Workspace Name.
- **Persistent configuration** — each test enforcer uses its own file under `~/.airlock/` so CLIs do not overwrite each other: .NET `test-enforcer.json`, Go `test-enforcer-go.json`, TypeScript `test-enforcer-typescript.json`, Python `test-enforcer-python.json`, Rust `test-enforcer-rust.json`.
- **Reconfigure** — re-run the setup wizard at any time from the menu.

#### 🔑 Authentication
- **Gateway discovery** — calls `GET /v1/integrations/discovery` to auto-discover the Keycloak IdP URL and OIDC client ID.
- **Device Auth Grant sign-in** — initiates the OAuth 2.0 Device Authorization Grant, displays the verification URL and user code, and polls for token issuance.
- **Session restore** — on startup, restores a previously saved session by refreshing the access token using the stored refresh token.
- **Token refresh** — automatically refreshes expired tokens before making API calls.
- **Sign out** — revokes the refresh token and clears the local session.

#### ✅ Consent
- **Consent check** — calls `GET /v1/consents/check` after sign-in to verify the user has authorized the app.
- **Consent flow handling** — gracefully handles `app_consent_required` (first time) and `app_consent_pending` (awaiting approval) responses with user-friendly messages.

#### 🔗 Workspace Pairing
- **Initiate pairing** — calls `POST /v1/pairing/initiate` to create a new pairing session and displays the pairing code.
- **Poll for pairing completion** — polls `GET /v1/pairing/{nonce}/status` until the mobile app user approves, rejects, or the request expires.
- **Routing token persistence** — saves the routing token on successful pairing for later use.
- **Handle pairing rejection/expiration** — displays appropriate messages when pairing is revoked or times out.

#### 📡 Presence
- **Background heartbeat** — starts a background loop sending `POST /v1/presence/heartbeat` every 30 seconds to maintain online presence status.
- **Heartbeat lifecycle management** — starts on successful pairing, stops on unpair or sign-out.

#### 📦 Artifact Submission & Decision Polling
- **Submit artifact** — creates a HARP-format artifact envelope with encrypted payload (simulated xchacha20-poly1305 ciphertext) and submits via `POST /v1/artifacts`.
- **Long-poll for decision** — calls `GET /v1/exchanges/{requestId}/wait` in a loop with a 25-second timeout per poll, up to a 2-minute total deadline.
- **Decision display** — shows the approval/rejection decision along with optional reason and signer key ID.
- **Auto-withdraw on timeout** — if no decision arrives within the deadline, automatically withdraws the pending request.
- **Manual withdrawal** — withdraw a specific request by ID at any time.

#### 🔓 Unpairing
- **Revoke pairing** — calls `POST /v1/pairing/revoke` to disconnect from the workspace.
- **Stale token handling** — gracefully handles cases where the routing token is invalid (e.g. after a server-side DB reset) by clearing the local pairing state regardless of the server response.

#### 🖥️ Context-Aware TUI Menu
- **Adaptive menu** — menu options change based on current state:
  - Not authenticated → `Set PAT (recommended)`, `Sign In (OAuth)`, `Reconfigure`, `Exit`
  - Authenticated, not paired → `Pair Device`, `Sign Out`, `Reconfigure`, `Exit`
  - Authenticated and paired → `Submit Artifact`, `Withdraw`, `Unpair`, `Sign Out`, `Reconfigure`, `Exit`
- **PAT-first** — PAT is the recommended and default authentication method.
- **Session restore** — on startup, restores PAT first; falls back to OAuth token refresh.
- **Status display** — shows current configuration, auth state (PAT or OAuth), and pairing state in a formatted table.

### Running the .NET Test Enforcer

```bash
cd src/dotnet/Airlock.Gateway.Sdk.TestEnforcer
dotnet run
```

### Running the TypeScript Test Enforcer

```bash
cd src/typescript/test-enforcer
npm install
npx ts-node index.ts
```

### Running the Go Test Enforcer

```bash
cd src/go
go run ./cmd/test-enforcer
```

### Running the Python Test Enforcer

```bash
cd src/python
pip install -e .
python test_enforcer.py
```

### Running the Rust Test Enforcer

```bash
cd src/rust
cargo run --bin test_enforcer
```

---

## Gateway SDK Reference

For detailed API documentation per language, see:

| Language | SDK Source | README |
|----------|-----------|--------|
| .NET C# | [`src/dotnet/Airlock.Gateway.Sdk/`](src/dotnet/Airlock.Gateway.Sdk/) | [`src/dotnet/README.md`](src/dotnet/README.md) |
| Python | [`src/python/airlock_gateway/`](src/python/airlock_gateway/) | [`src/python/README.md`](src/python/README.md) |
| TypeScript | [`src/typescript/`](src/typescript/) | [`src/typescript/README.md`](src/typescript/README.md) |
| Go | [`src/go/`](src/go/) | [`src/go/README.md`](src/go/README.md) |
| Rust | [`src/rust/`](src/rust/) | [`src/rust/README.md`](src/rust/README.md) |

### API Endpoints Summary

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /v1/integrations/discovery` | Discovery | Gateway and IdP configuration |
| `GET /echo` | Health | Gateway connectivity check |
| `POST /v1/artifacts` | Submit | Submit an artifact for approval |
| `GET /v1/exchanges/{requestId}` | Status | Get exchange status |
| `GET /v1/exchanges/{requestId}/wait` | Long-poll | Wait for decision (25s timeout) |
| `POST /v1/exchanges/{requestId}/withdraw` | Withdraw | Cancel a pending exchange |
| `POST /v1/pairing/initiate` | Pairing | Start a new pairing session |
| `GET /v1/pairing/{nonce}/status` | Pairing | Poll pairing completion status |
| `POST /v1/pairing/revoke` | Pairing | Revoke (unpair) a paired session |
| `POST /v1/pairing/pre-generate` | Pairing | Pre-generate a pairing code (30-min TTL) |
| `POST /v1/pairing/claim` | Pairing | Enforcer claims a pre-generated code |
| `POST /v1/presence/heartbeat` | Presence | Send an enforcer heartbeat |
| `GET /v1/policy/dnd/effective` | Policy | Fetch effective DND policies |
| `GET /v1/consents/check` | Consent | Check user consent for your app |
