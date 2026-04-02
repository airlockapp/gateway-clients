# Airlock Plugin for OpenClaw — Installation Guide

This guide covers installing and configuring the **Airlock** plugin for [OpenClaw](https://docs.openclaw.ai), enabling human-in-the-loop approval for AI agent tool calls via the [Airlock](https://airlockapp.io) mobile app.

## Prerequisites

- **OpenClaw** installed and running (e.g., via the [DigitalOcean Marketplace](https://marketplace.digitalocean.com/apps/openclaw))
- **Airlock account** with an enforcer app configured at [airlockapp.io](https://airlockapp.io)
- **Airlock mobile app** installed on your phone
- **Node.js 18+** (for npm install or building from source)

## 1. Install the Plugin

### Option A: Install from npm (Recommended)

```bash
ssh root@<server-ip> "mkdir -p ~/.openclaw/extensions/airlock && cd ~/.openclaw/extensions/airlock && npm init -y && npm install @airlockapp/openclaw-airlock"
```

The npm package is available at: [npmjs.com/package/@airlockapp/openclaw-airlock](https://www.npmjs.com/package/@airlockapp/openclaw-airlock)

### Option B: Build from Source

```bash
cd src/openclaw-airlock
npm install
npx tsc
```

This produces the `dist/` directory with compiled JavaScript.

## 2. Deploy to the Server

If you installed via npm (Option A), the files are already on the server. Skip to Step 3.

If you built from source (Option B), copy the extension to the server:

```bash
# Create the extension directory
ssh root@<server-ip> "mkdir -p /root/.openclaw/extensions/airlock"

# Copy the required files
scp -r dist package.json openclaw.plugin.json node_modules \
  root@<server-ip>:~/.openclaw/extensions/airlock/

# Fix file ownership (required — OpenClaw blocks plugins with unexpected ownership)
ssh root@<server-ip> "chown -R root:root ~/.openclaw/extensions/airlock/"
```

### Dual-User Setup (DigitalOcean)

On DigitalOcean droplets, the CLI runs as `root` but the service runs as the `openclaw` user. Both paths must contain the extension files:

```bash
ssh root@<server-ip> "
  cp -r /root/.openclaw/extensions/airlock /home/openclaw/.openclaw/extensions/
  chown -R openclaw:openclaw /home/openclaw/.openclaw/extensions/airlock
"
```

## 3. Configure the Plugin

Edit the OpenClaw configuration file (`~/.openclaw/openclaw.json`) and add the Airlock plugin under `plugins.entries`:

```json
{
  "plugins": {
    "entries": {
      "airlock": {
        "enabled": true,
        "config": {
          "gatewayUrl": "https://igw.airlocks.io",
          "enforcerId": "<your-enforcer-id>",
          "pat": "<your-personal-access-token>",
          "clientId": "<your-client-id>",
          "clientSecret": "<your-client-secret>",
          "pairingCode": "<your-pairing-code>",
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

### Configuration Reference

| Field | Required | Description |
|-------|----------|-------------|
| `gatewayUrl` | Yes | Airlock Gateway URL (default: `https://igw.airlocks.io`) |
| `enforcerId` | Yes | Your enforcer identifier (e.g., `my-enforcer-001`) |
| `pat` | Yes | Personal Access Token from the Airlock dashboard (`airpat_...`) |
| `clientId` | Yes | Enforcer app Client ID |
| `clientSecret` | Yes | Enforcer app Client Secret |
| `pairingCode` | Yes* | Pre-generated pairing code from the Airlock dashboard or mobile app. *Only needed before initial pairing.* |
| `protectedTools` | No | Array of tool name patterns to require approval for. Supports wildcards (e.g., `shell.*`). If empty, use the explicit `airlock_request_approval` tool. |
| `failMode` | No | `"closed"` (default, block on failure) or `"open"` (allow on failure) |
| `workspaceName` | No | Workspace name (default: `"OpenClaw Workspace"`) |

> **Important:** If OpenClaw runs as a different user, update the config in **both** `/root/.openclaw/openclaw.json` and `/home/openclaw/.openclaw/openclaw.json`.

## 4. Restart the Service

```bash
systemctl restart openclaw

# Verify the plugin loaded:
journalctl -u openclaw --no-pager | grep -i airlock
# Expected: [Airlock] Plugin loaded — enforcer=<id>, failMode=closed, protectedTools=...
```

## 5. Grant User Consent

Before pairing, the Airlock gateway requires the user to consent to this enforcer app. Run:

```bash
openclaw airlock consent
```

This will:
1. Call `GET /v1/consent/status` on the Airlock Gateway
2. Trigger a push notification to the user's **Airlock mobile app**
3. Poll every 5 seconds until the user approves (up to 5 minutes)

**Output:**
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

✓ Consent granted! (after 15s)
```

## 6. Pair the Enforcer

Once consent is granted, pair with the Airlock mobile app:

```bash
openclaw airlock pair
```

This will:
1. Verify consent status
2. Claim the pairing code configured in step 3
3. Perform X25519 ECDH key exchange for end-to-end encryption
4. Persist the routing token and encryption key to `~/.openclaw/.airlock/pairing-state.json`

**Output:**
```
Airlock Pairing
════════════════════════════════════════
Gateway:      https://igw.airlocks.io
Enforcer ID:  my-enforcer-001
Workspace:    OpenClaw Workspace
Pairing Code: XXXXXX

Claiming pairing code (X25519 ECDH key exchange)...

✓ Pairing successful!
  Routing Token: rt_xxxxxxxx...
  Encryption:    ✓ Key derived (X25519 ECDH + HKDF-SHA256)
  State File:    ✓ Persisted to ~/.openclaw/.airlock/pairing-state.json

  Airlock is now ready to enforce approvals.
```

## 7. Verify Setup

Run the setup command to confirm everything is working:

```bash
openclaw airlock setup
```

**Expected output:**
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

## CLI Command Reference

| Command | Description |
|---------|-------------|
| `openclaw airlock setup` | Validate config, test connectivity, show consent/pairing status |
| `openclaw airlock consent` | Trigger user consent flow and poll until approved |
| `openclaw airlock pair` | Claim pairing code and establish encrypted channel |

## How It Works

Once configured and paired, Airlock intercepts tool calls matching `protectedTools` patterns:

1. **Agent requests a tool** (e.g., `shell.exec("rm -rf /tmp/data")`)
2. **Airlock encrypts** the request payload (AES-256-GCM) and submits it to the gateway
3. **User receives a push notification** on the Airlock mobile app
4. **User reviews and approves/rejects** the request
5. **Airlock receives the decision** and allows or blocks the tool call

```
Agent ──► Airlock Plugin ──► Airlock Gateway ──► Mobile App
                                                    │
Agent ◄── Airlock Plugin ◄── Airlock Gateway ◄── approve/reject
```

## Persistence

The plugin persists pairing state to:
```
~/.openclaw/.airlock/pairing-state.json
```

This file contains:
- `routingToken` — identifies this enforcer to the gateway
- `encryptionKeyBase64Url` — derived encryption key for E2E encryption
- `enforcerId` — the enforcer identity

The state survives service restarts. Re-pairing is only needed if the pairing is revoked.

## Troubleshooting

### Plugin not loading — "suspicious ownership"
```
blocked plugin candidate: suspicious ownership (uid=XXXX, expected uid=0 or root)
```
OpenClaw rejects plugin files not owned by `root`. Fix with:
```bash
chown -R root:root ~/.openclaw/extensions/airlock/
systemctl restart openclaw
```
This commonly happens when files are uploaded from a non-root system (Windows, another Linux user, etc.).

### "Not paired" after restart
Ensure the extension files exist in **both** user directories:
- `/root/.openclaw/extensions/airlock/` (CLI)
- `/home/openclaw/.openclaw/extensions/airlock/` (service)

### Consent denied
The user denied the consent request in the mobile app. Ask them to re-approve, then run `openclaw airlock consent` again.

### Gateway connectivity issues
```bash
# Test directly:
curl -s https://igw.airlocks.io/echo
```

### Rate limiting
If you see "too many failed authentication attempts", wait 5 minutes and retry. The Airlock gateway rate-limits repeated auth failures.

## Generating a New Pairing Code

Pairing codes are single-use. To generate a new one:

1. Open the **Airlock dashboard** at [airlockapp.io](https://airlockapp.io)
2. Navigate to your enforcer app → **Pre-generated Codes**
3. Generate a new code
4. Update `pairingCode` in your OpenClaw config
5. Run `openclaw airlock pair`

Alternatively, generate a code from the **Airlock mobile app** under the workspace settings.
