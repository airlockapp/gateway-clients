# Airlock + OpenClaw + Telegram — Demo Guide

**AI agent on Telegram, gated by Airlock mobile approval**

Chat with your OpenClaw AI agent via Telegram. When the agent wants to execute a dangerous action (run a shell command, deploy code, access a file), Airlock intercepts the tool call and sends an encrypted approval request to your phone. You approve or reject from the **Airlock mobile app** — all in real-time.

This demonstrates the full Airlock value proposition: **human-in-the-loop control for autonomous AI agents over a messaging channel.**

---

## Architecture

```
┌─────────────┐    ┌──────────────────┐    ┌─────────────────────┐    ┌─────────────────┐
│  Telegram   │───▶│  OpenClaw Agent   │───▶│  Airlock Plugin     │───▶│ Airlock Gateway │
│  User Chat  │    │  (VPS)           │    │  (enforcer)         │    │ (igw.airlocks.io)│
└─────────────┘    └──────────────────┘    └─────────────────────┘    └────────┬────────┘
                          ▲                                                     │
                          │                                                     ▼
                          │                                           ┌─────────────────┐
                          └───────────────────────────────────────────│ Airlock Mobile   │
                                        decision (approve/reject)     │ App (phone)      │
                                                                      └─────────────────┘
```

**Security:** All payloads are end-to-end encrypted using **X25519 ECDH + AES-256-GCM**. The gateway only routes ciphertext — it never sees your commands.

---

## Prerequisites

| Component | Requirement |
|-----------|-------------|
| **OpenClaw VPS** | Installed and running (e.g., [DigitalOcean Marketplace](https://marketplace.digitalocean.com/apps/openclaw)) |
| **Telegram Bot** | Created via [@BotFather](https://t.me/BotFather), token configured in OpenClaw |
| **Airlock Account** | Registered at [airlockapp.io](https://airlockapp.io) with an enforcer app |
| **Airlock Mobile App** | Installed on your phone ([iOS](https://apps.apple.com/app/airlock) / [Android](https://play.google.com/store/apps/details?id=io.airlockapp.mobile)) |
| **Airlock Plugin** | Deployed to the OpenClaw extensions directory — install via npm (`npm install @airlockapp/openclaw-airlock`) or build from source (see [INSTALL.md](./INSTALL.md)) |

---

## Step 1: Configure the Airlock Plugin

Add the Airlock plugin to your OpenClaw configuration (`~/.openclaw/openclaw.json`):

```json
{
  "plugins": {
    "entries": {
      "airlock": {
        "enabled": true,
        "config": {
          "gatewayUrl": "https://igw.airlocks.io",
          "enforcerId": "my-enforcer-001",
          "pat": "airpat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
          "clientId": "your-client-id",
          "clientSecret": "your-client-secret",
          "pairingCode": "XXXXXX",
          "protectedTools": [
            "exec",
            "shell.*",
            "computer.*",
            "*"
          ]
        }
      }
    }
  }
}
```

### Protected Tools for the Demo

| Pattern | What it catches |
|---------|-----------------|
| `exec` | OpenClaw's built-in shell/bash execution tool |
| `shell.*` | Tools in the `shell.*` namespace (exec, read, write variants) |
| `computer.*` | Screen capture, mouse/keyboard control |
| `*` | Every tool call, regardless of name (recommended for maximum coverage) |

Restart the service after editing:

```bash
systemctl restart openclaw
```

### Verify Plugin Loaded

```bash
journalctl -u openclaw --no-pager | grep -i airlock
# Expected: [Airlock] Plugin loaded — enforcer=my-enforcer-001, failMode=closed, protectedTools=shell.exec,shell.*,computer.*
```

---

## Step 2: User Consent (Mobile App — Authorized Apps)

Before pairing, the user must authorize the enforcer app in the Airlock mobile app.

### CLI Command

```bash
openclaw airlock consent
```

### What Happens

1. The CLI calls `GET /v1/consent/status` on the Airlock Gateway
2. The gateway sends a **push notification** to the user's Airlock mobile app
3. The CLI polls every 5 seconds, waiting for approval

### On the Mobile App

1. Open the **Airlock** mobile app
2. You'll see a notification or banner: **"New app requesting access"**
3. Navigate to **Settings → Authorized Apps** (or tap the notification)
4. Review the app details:
   - **App Name:** Your enforcer app name
   - **App ID:** The `clientId` from your config
   - **Requested permissions:** Tool call enforcement
5. Tap **"Authorize"** to grant consent

### CLI Output

```
Airlock Consent
════════════════════════════════════════

Enforcer ID:  my-enforcer-001
Gateway:      https://igw.airlocks.io

Checking consent status...

┌─ Consent Required ──────────────────────────────┐
│ A consent request has been sent to the user's
│ Airlock mobile app. Please approve it there.
└─────────────────────────────────────────────────┘

Waiting for consent approval...
  Waiting... (5s elapsed, status: pending)
  Waiting... (10s elapsed, status: pending)
  Waiting... (15s elapsed, status: pending)

✓ Consent granted! (after 15s)
  You can now proceed with 'openclaw airlock pair'.
```

### Consent States

| Status | Meaning |
|--------|---------|
| `approved` | User authorized the app — proceed to pairing |
| `required` | First contact — push notification sent to mobile app |
| `pending` | Notification sent, waiting for user to respond |
| `denied` | User rejected the app — cannot proceed |

---

## Step 3: Pair with Mobile App

After consent is granted, pair the enforcer with the Airlock mobile app.

### Generate a Pairing Code

1. Open the **Airlock mobile app**
2. Navigate to **Workspaces** → your workspace
3. Tap **"Pre-generated Pairing Codes"** or **"Add Enforcer"**
4. Generate a new code (e.g., `4RKBF5`)
5. Set it in your OpenClaw config:

```bash
# Edit openclaw.json and set pairingCode to the generated code
# Then restart:
systemctl restart openclaw
```

### Claim the Pairing Code

```bash
openclaw airlock pair
```

### What Happens

1. The CLI validates consent status (must be `approved`)
2. Generates an **X25519 keypair** for end-to-end encryption
3. Sends a **claim request** to the gateway with the pairing code
4. The mobile app shows the pairing confirmation
5. On completion, the gateway returns:
   - A **routing token** (identifies this enforcer)
   - The approver's **X25519 public key** for ECDH key agreement
6. The CLI derives the shared encryption key via **HKDF-SHA256**
7. Everything is persisted to `~/.openclaw/.airlock/pairing-state.json`

### CLI Output

```
Airlock Pairing
════════════════════════════════════════
Gateway:      https://igw.airlocks.io
Enforcer ID:  my-enforcer-001
Workspace:    OpenClaw Workspace
Pairing Code: 4RKBF5

Claiming pairing code (X25519 ECDH key exchange)...

✓ Pairing successful!
  Routing Token: rt_a3b7c9d1...
  Encryption:    ✓ Key derived (X25519 ECDH + HKDF-SHA256)
  State File:    ✓ Persisted to ~/.openclaw/.airlock/pairing-state.json

  Airlock is now ready to enforce approvals.
```

### On the Mobile App

After pairing completes:
1. Navigate to **Workspaces** → your workspace
2. The enforcer appears as **"Online"** with a green status indicator
3. The workspace name and enforcer ID are displayed

---

## Step 4: Pair Telegram (DM Access)

Set up Telegram access to your OpenClaw agent:

1. Send any message to your bot on Telegram (e.g., `@openclaw_airlock_testbot`)
2. The bot replies with a **pairing code**
3. Approve the Telegram pairing on the server:

```bash
openclaw pairing approve telegram <code>
```

---

## Step 5: Verify Everything

```bash
openclaw airlock setup
```

Expected output:
```
Airlock Setup
════════════════════════════════════════

Gateway URL:    https://igw.airlocks.io
Enforcer ID:    my-enforcer-001
Workspace:      OpenClaw Workspace
Fail Mode:      closed
Auth (PAT):     ✓
Auth (Client):  ✓

Testing gateway connectivity...
✓ Connected to https://igw.airlocks.io
  Server time: 2026-04-01T18:26:29.730Z

✓ App consent: approved

✓ Paired — ready to enforce

Protected tools (3):
  • shell.exec
  • shell.*
  • computer.*

✓ Setup complete
```

---

## Demo Scenario 1: "Approve a Dangerous Command"

> **Story:** You ask the AI agent to check disk usage. The agent needs `shell.exec` — a protected tool.

### Steps

1. **On Telegram**, send to the bot:
   > "Check disk usage on this server and tell me if we're running low"

2. **Agent thinks** → decides to call `shell.exec` with `df -h`

3. **Airlock intercepts** → encrypts the request payload and submits it to the gateway

4. **On your phone**, the **Airlock mobile app** shows a push notification:

   ```
   🔒 Approval Request
   ──────────────────────────────
   Tool:      exec
   Command:   df -h
   Workspace: OpenClaw Workspace
   Enforcer:  my-enforcer-001
   ──────────────────────────────
   [  Approve  ]    [  Reject  ]
   ```

5. **Tap "Approve"** on the mobile app

6. **Back on Telegram**, the agent receives the approval, runs the command, and replies:
   > "Here's your disk usage: / is at 45% (2.1GB/4.7GB). You have plenty of space."

### What If You Reject?

If you tap **"Reject"**, the agent responds on Telegram:
> "The disk usage check was blocked by the approver. I cannot run shell commands without approval."

### What If You Don't Respond?

After 5 minutes (default timeout), the request expires. In **fail-closed** mode (default), the tool call is **blocked**:
> "The approval request timed out. The action was not executed."

---

## Demo Scenario 2: "Block a Risky Operation"

> **Story:** The agent wants to run `rm -rf /tmp/*` — you reject it.

### Steps

1. **On Telegram**, send:
   > "Clean up all temporary files in /tmp"

2. **Agent decides** to call `shell.exec` with `rm -rf /tmp/*`

3. **Push notification arrives** on your phone — you see the full command

4. **Tap "Reject"** — this is clearly too risky without reviewing what's in /tmp

5. **Agent responds** on Telegram:
   > "The cleanup was rejected. Would you like me to first list what's in /tmp so you can review before deleting?"

---

## Demo Scenario 3: "Explicit Approval Tool"

> **Story:** The agent uses `airlock_request_approval` explicitly for a high-stakes decision.

### Steps

1. **On Telegram**, send:
   > "I want you to create a new user account called 'demo-user' on this server"

2. **Agent recognizes** this is sensitive and calls `airlock_request_approval` with:
   ```json
   {
     "action": "Create system user account",
     "details": "useradd -m demo-user && passwd demo-user",
     "risk": "Creates a new user with shell access"
   }
   ```

3. **Mobile notification** → you review the full payload including the risk assessment

4. **Approve or Reject** from the app

5. **Agent proceeds or explains** the decision on Telegram

---

## Demo Talking Points

| Point | Detail |
|-------|--------|
| **E2E Encryption** | Payloads use X25519 ECDH + AES-256-GCM. The gateway only routes ciphertext — it never sees your commands. |
| **Fail-Closed** | If the phone is off or timeout expires (5 min), the action is **blocked** by default. |
| **Glob Patterns** | `shell.*` catches all shell variants. Configure as broad or narrow as needed. |
| **Works Everywhere** | Same Airlock plugin works in Claude Code, Cursor, Windsurf, Copilot, and now OpenClaw + Telegram. |
| **DND Policies** | Gateway can auto-approve low-risk requests during business hours (Do Not Disturb mode). |
| **Consent Flow** | Users must explicitly authorize enforcer apps before they can enforce — no silent installation. |
| **Audit Trail** | Every approval/rejection is logged with timestamps, signer key IDs, and reasons. |

---

## Complete Flow Summary

```
┌───────────────────────────────────────────────────────────────────────┐
│                        SETUP (one-time)                               │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  1. Deploy plugin ──► openclaw extensions directory                   │
│  2. Configure      ──► openclaw.json (credentials + protectedTools)   │
│  3. Consent        ──► openclaw airlock consent  ──► Mobile: Authorize│
│  4. Pair           ──► openclaw airlock pair      ──► Mobile: Confirm │
│  5. Verify         ──► openclaw airlock setup                         │
│                                                                       │
├───────────────────────────────────────────────────────────────────────┤
│                        RUNTIME (per tool call)                        │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  User ──telegram──► Agent ──tool call──► Airlock Plugin               │
│                                              │                        │
│                                              ▼                        │
│                                    Encrypt (AES-256-GCM)              │
│                                              │                        │
│                                              ▼                        │
│                                    Airlock Gateway                     │
│                                              │                        │
│                                              ▼                        │
│                                    Mobile Push Notification            │
│                                              │                        │
│                                         ┌────┴────┐                   │
│                                     Approve    Reject                 │
│                                         │         │                   │
│                                         ▼         ▼                   │
│  User ◄──telegram──◄ Agent ◄── tool proceeds / tool blocked          │
│                                                                       │
└───────────────────────────────────────────────────────────────────────┘
```
