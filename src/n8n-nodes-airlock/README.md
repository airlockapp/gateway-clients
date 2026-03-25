# @airlockapp/n8n-nodes-airlock

Integration for Airlock Gateway within n8n. This package provides two nodes to seamlessly integrate your automated workflows with the human-in-the-loop approvals via the Airlock Mobile App.

## 1. Credentials Configuration (Airlock Gateway API)
Before using the nodes, configure exactly one `Airlock Gateway API` credential to securely connect your workflows to the Airlock cloud.

### General Settings
- **Gateway URL**: Base URL of your Airlock Integrations Gateway.
- **Enforcer ID**: A unique identifier for this n8n instance or specific workflow context.
- **Workspace & Repository Name** (Optional): Text displayed in the Mobile App context card so the approver knows exactly which n8n instance they are interacting with.
- **Wait Timeout (Seconds)**: Maximum time to wait for a mobile approver to make a decision (defaults to 60).
- **Fail Mode**: 
  - `Fail Closed (Deny/Stop)`: Halts your workflow and throws a standard node error upon timeouts or connection failures.
  - `Fail Open (Allow/Continue)`: Safely ignores the error, fakes an "Allow" decision, and lets your workflow proceed without missing a beat.

### Secure Parameters
- **Personal Access Token (PAT)**: Your Airlock user token (or service account token). This is structurally mutually exclusive to Client Credentials; use PAT by default for easiest setup.
- **Client ID & Client Secret**: Application credentials reserved for strict machine-to-machine integrations without a tied user.
- **Device Code**: Used strictly during the one-time pairing flow.
- **Encryption Key & Routing Token**: Do not set these manually! Run the **Airlock Echo** node in Pair mode to auto-populate these fields via End-to-End Encryption key negotiation.

---

## 2. Airlock Echo Node (Setup & Connectivity)
The Echo node serves two essential operational purposes in the ecosystem.

### A. Pair Device (One-Time Initialization)
1. Type the *Pre-generated Device Code* (acquired from your mobile app) into your n8n Gateway Credentials.
2. Run the Echo node in **Pair Device** mode.
3. It securely communicates the X25519 pairing flow, establishes an E2EE shared secret, and **automatically saves the resulting Encryption Key and Routing Token back into your n8n Credentials**.

### B. Echo / Consent Check (Connectivity Auditing)
Used inside live workflows to verify that the Gateway is online, avoiding mid-air crashes if connections sever.
- If `Fail If Consent Not Approved` is enabled, the node halts execution directly if your Enforcer hasn't been granted global permission via the mobile app.

---

## 3. Airlock Enforcer Node (Human Approvals)
This node halts n8n execution, sends an encrypted payload to your mobile device, polls the server with heartbeats while it blocks, and resumes execution strictly once you approve or deny the request.

### Node Configuration
- **Artifact Type & Request Label**: Categorizes the prompt dynamically displayed on your app.
- **Payload Mode**: 
  - **Raw Text**: Displays standard monospace payload information to the user.
  - **JSON**: When valid JSON is provided via an expression (e.g., `={{ $json }}`), the mobile app intelligently parses it and dynamically displays every top-level key as a cleanly labeled row on the screen.
- **Requested Actions (Buttons)**:
  - You can use standard presets like *Allow/Deny* or build **Custom** action palettes (e.g., *Execute Trade (Primary)*, *Cancel Trade (Danger)*).

---

## 4. Sample Scenario: Algorithmic Trading Desk

This sample workflow automatically runs every minute. It randomly generates a synthetic stock trading signal calculating ticker, price, quantity, and risk.
Low-risk signals route to a "Standard Trade Approval" enforcer, while high-risk signals (>$50,000 value) route to a specialized "Compliance Committee Enforcer" with custom `Execute/Cancel` actions. Finally, if the approver allowed the trade, it "Executes".

You can copy and **paste this JSON array directly into a blank n8n canvas** to import the whole workflow.

```json
{
  "nodes": [
    {
      "parameters": {
        "rule": {
          "interval": [
            {
              "field": "minutes",
              "minutesInterval": 1
            }
          ]
        }
      },
      "name": "Schedule (Every Minute)",
      "type": "n8n-nodes-base.scheduleTrigger",
      "typeVersion": 1,
      "position": [0, 300]
    },
    {
      "parameters": {
        "operation": "echo",
        "failOnConsent": true,
        "includeRaw": false
      },
      "name": "Check Airlock Connectivity & Consent",
      "type": "@airlockapp/n8n-nodes-airlock.airlockEcho",
      "typeVersion": 1,
      "position": [220, 300],
      "notesInFlow": true,
      "notes": "Verify Gateway is online"
    },
    {
      "parameters": {
        "jsCode": "const tickers = ['AAPL', 'MSFT', 'TSLA', 'NVDA', 'AMZN'];\nconst actions = ['BUY', 'SELL'];\n\nconst ticker = tickers[Math.floor(Math.random() * tickers.length)];\nconst action = actions[Math.floor(Math.random() * actions.length)];\nconst price = parseFloat((Math.random() * 500 + 50).toFixed(2));\nconst quantity = Math.floor(Math.random() * 900) + 100;\nconst totalValue = parseFloat((price * quantity).toFixed(2));\nconst riskLevel = totalValue >= 50000 ? 'High' : 'Low';\n\nreturn {\n  signal: `${action} ${quantity} shares of ${ticker} @ $${price}`,\n  ticker: ticker,\n  action: action,\n  price: price,\n  quantity: quantity,\n  totalValue: totalValue,\n  riskLevel: riskLevel\n};"
      },
      "name": "Generate Trade Signal",
      "type": "n8n-nodes-base.code",
      "typeVersion": 2,
      "position": [440, 300]
    },
    {
      "parameters": {
        "conditions": {
          "boolean": [
            {
              "value1": "={{ $json.totalValue >= 50000 }}",
              "value2": true
            }
          ]
        }
      },
      "name": "Is High Risk? (> $50k)",
      "type": "n8n-nodes-base.if",
      "typeVersion": 1,
      "position": [660, 300]
    },
    {
      "parameters": {
        "requestLabel": "High-Risk Trade Approval",
        "artifactType": "compliance.trade",
        "payloadMode": "json",
        "jsonPayload": "={{ $json }}",
        "actionPreset": "custom",
        "customActions": {
          "actions": [
            {
              "id": "execute",
              "caption": "Execute Trade",
              "style": "primary",
              "decision": "allow"
            },
            {
              "id": "cancel",
              "caption": "Cancel Trade",
              "style": "danger",
              "decision": "deny"
            }
          ]
        }
      },
      "name": "Compliance Committee Enforcer",
      "type": "@airlockapp/n8n-nodes-airlock.airlockEnforcer",
      "typeVersion": 1,
      "position": [920, 180]
    },
    {
      "parameters": {
        "requestLabel": "Standard Trade Approval",
        "artifactType": "trading.standard",
        "payloadMode": "json",
        "jsonPayload": "={{ $json }}",
        "actionPreset": "allow_deny"
      },
      "name": "Trading Desk Enforcer",
      "type": "@airlockapp/n8n-nodes-airlock.airlockEnforcer",
      "typeVersion": 1,
      "position": [920, 420]
    },
    {
      "parameters": {
        "conditions": {
          "string": [
            {
              "value1": "={{ $json.decision }}",
              "value2": "allow"
            }
          ]
        }
      },
      "name": "Check Final Decision",
      "type": "n8n-nodes-base.if",
      "typeVersion": 1,
      "position": [1180, 300]
    },
    {
      "parameters": {
        "keepOnlySet": true,
        "values": {
          "string": [
            {
              "name": "message",
              "value": "✅ Trade EXECUTED successfully!"
            }
          ]
        }
      },
      "name": "Execute Trade",
      "type": "n8n-nodes-base.set",
      "typeVersion": 2,
      "position": [1420, 180]
    },
    {
      "parameters": {
        "keepOnlySet": true,
        "values": {
          "string": [
            {
              "name": "message",
              "value": "❌ Trade CANCELLED by human approver."
            }
          ]
        }
      },
      "name": "Cancel Trade",
      "type": "n8n-nodes-base.set",
      "typeVersion": 2,
      "position": [1420, 420]
    }
  ],
  "connections": {
    "Schedule (Every Minute)": {
      "main": [
        [
          {
            "node": "Check Airlock Connectivity & Consent",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Check Airlock Connectivity & Consent": {
      "main": [
        [
          {
            "node": "Generate Trade Signal",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Generate Trade Signal": {
      "main": [
        [
          {
            "node": "Is High Risk? (> $50k)",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Is High Risk? (> $50k)": {
      "main": [
        [
          {
            "node": "Compliance Committee Enforcer",
            "type": "main",
            "index": 0
          }
        ],
        [
          {
            "node": "Trading Desk Enforcer",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Compliance Committee Enforcer": {
      "main": [
        [
          {
            "node": "Check Final Decision",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Trading Desk Enforcer": {
      "main": [
        [
          {
            "node": "Check Final Decision",
            "type": "main",
            "index": 0
          }
        ]
      ]
    },
    "Check Final Decision": {
      "main": [
        [
          {
            "node": "Execute Trade",
            "type": "main",
            "index": 0
          }
        ],
        [
          {
            "node": "Cancel Trade",
            "type": "main",
            "index": 0
          }
        ]
      ]
    }
  }
}
```

## Documentation & Resources

For full integration tutorials, conceptual overviews, and detailed API references, please visit the official Airlock Documentation:
- **[Airlock Developer Guide](https://airlockapp.io/docs/developer-guide/)**
- **[Airlock SDK Reference & Setup](https://airlockapp.io/docs/sdk/)**

---

## 5. Development & Local Docker Setup

If you are developing custom nodes or modifying the Airlock Enforcer logic, you can seamlessly test your changes locally using Docker by bind-mounting this project directly into an n8n container.

### A. Environment Preparation
After compiling the TypeScript codebase (`npm run build`), you need to pass an API key to the container. During the **Pair Device** flow, the Airlock Echo node intercepts the E2E public-key cryptography negotiation and securely auto-saves the resulting **Encryption Key** back into your n8n Credentials store using n8n's internal REST API.

Because the node uses this secure local pipeline, you **must set the `N8N_API_KEY`** environment variable when launching your container; otherwise, the automatic credential update process will fail.

### B. Docker Compose Example
Here is a barebones `docker-compose.yml` to safely test the custom nodes:

```yaml
version: '3.8'
services:
  n8n:
    image: docker.n8n.io/n8nio/n8n:latest
    ports:
      - "5678:5678"
    environment:
      # Exposes the API for the Echo node to auto-save Pair credentials
      - N8N_API_KEY=my-local-dev-key
      - N8N_PORT=5678
    volumes:
      - ./n8n-data:/home/node/.n8n
      # Bind-mount this repository folder directly into n8n's custom node directory
      - /absolute/path/to/n8n-nodes-airlock:/home/node/.n8n/custom/node_modules/@airlockapp/n8n-nodes-airlock
```

With this configuration, any time you run `npm run build` on your host machine to update your TS code, those `dist` changes are instantly mirrored inside the container. You simply stop and restart the n8n container to apply the hot-reloaded node changes!
