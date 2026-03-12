import { AirlockGatewayError } from "./errors.js";
import type {
    ArtifactSubmitBody,
    ArtifactSubmitRequest,
    CiphertextRef,
    DecisionDeliverEnvelope,
    DndEffectiveResponse,
    EchoResponse,
    EnforcerPresenceRecord,
    ExchangeStatusResponse,
    HarpEnvelope,
    PairingCompleteRequest,
    PairingCompleteResponse,
    PairingInitiateRequest,
    PairingInitiateResponse,
    PairingResolveResponse,
    PairingRevokeResponse,
    PairingStatusBatchResponse,
    PairingStatusResponse,
    PresenceHeartbeatRequest,
} from "./models.js";

export interface AirlockGatewayClientOptions {
    /** Gateway base URL (e.g., "https://gw.example.com"). */
    baseUrl: string;
    /** Optional Bearer token for authentication. */
    token?: string;
    /** Custom fetch implementation (defaults to global fetch). */
    fetch?: typeof globalThis.fetch;
}

/**
 * Client for the Airlock Gateway API.
 *
 * Uses the native `fetch` API — works in Node.js 18+ and modern browsers.
 */
export class AirlockGatewayClient {
    private readonly baseUrl: string;
    private readonly token?: string;
    private readonly fetchFn: typeof globalThis.fetch;

    constructor(options: AirlockGatewayClientOptions) {
        this.baseUrl = options.baseUrl.replace(/\/$/, "");
        this.token = options.token;
        this.fetchFn = options.fetch ?? globalThis.fetch;
    }

    // ── Discovery ───────────────────────────────────────────────

    /** GET /echo — Gateway discovery and health. */
    async echo(): Promise<EchoResponse> {
        return this.get<EchoResponse>("/echo");
    }

    // ── Artifacts ───────────────────────────────────────────────

    /** POST /v1/artifacts — Submit an artifact for approval. Returns the request ID. */
    async submitArtifact(request: ArtifactSubmitRequest): Promise<string> {
        const requestId = request.requestId ?? `req-${crypto.randomUUID()}`;
        const expiresAt = request.expiresAt ?? new Date(Date.now() + 10 * 60 * 1000).toISOString();

        const envelope: HarpEnvelope<ArtifactSubmitBody> = {
            msgId: `msg-${crypto.randomUUID()}`,
            msgType: "artifact.submit",
            requestId,
            createdAt: new Date().toISOString(),
            sender: { enforcerId: request.enforcerId },
            body: {
                artifactType: request.artifactType ?? "command-approval",
                artifactHash: request.artifactHash,
                ciphertext: request.ciphertext,
                expiresAt,
                metadata: request.metadata,
            },
        };

        await this.post("/v1/artifacts", envelope);
        return requestId;
    }

    // ── Exchanges ───────────────────────────────────────────────

    /** GET /v1/exchanges/{requestId} — Get exchange status. */
    async getExchangeStatus(requestId: string): Promise<ExchangeStatusResponse> {
        return this.get<ExchangeStatusResponse>(`/v1/exchanges/${encodeURIComponent(requestId)}`);
    }

    /** GET /v1/exchanges/{requestId}/wait — Long-poll for decision. Returns null on 204. */
    async waitForDecision(requestId: string, timeoutSeconds = 30): Promise<DecisionDeliverEnvelope | null> {
        timeoutSeconds = Math.max(1, Math.min(60, timeoutSeconds));
        const url = `/v1/exchanges/${encodeURIComponent(requestId)}/wait?timeout=${timeoutSeconds}`;

        const response = await this.rawFetch("GET", url);

        if (response.status === 204) return null;

        const body = await response.text();
        await this.ensureSuccess(response, body);
        return JSON.parse(body) as DecisionDeliverEnvelope;
    }

    /** POST /v1/exchanges/{requestId}/withdraw — Withdraw a pending exchange. */
    async withdrawExchange(requestId: string): Promise<void> {
        await this.post(`/v1/exchanges/${encodeURIComponent(requestId)}/withdraw`, undefined);
    }

    // ── Acknowledgements ────────────────────────────────────────

    /** POST /v1/acks — Acknowledge an inbox message. */
    async acknowledge(msgId: string, enforcerId: string): Promise<void> {
        const envelope: HarpEnvelope = {
            msgId: `msg-${crypto.randomUUID()}`,
            msgType: "ack.submit",
            requestId: `ack-${crypto.randomUUID()}`,
            createdAt: new Date().toISOString(),
            sender: { enforcerId },
            body: {
                msgId,
                status: "acknowledged",
                ackAt: new Date().toISOString(),
            },
        };
        await this.post("/v1/acks", envelope);
    }

    // ── Pairing ─────────────────────────────────────────────────

    /** POST /v1/pairing/initiate — Start a new pairing session. */
    async initiatePairing(request: PairingInitiateRequest): Promise<PairingInitiateResponse> {
        return this.postJson<PairingInitiateResponse>("/v1/pairing/initiate", request);
    }

    /** GET /v1/pairing/resolve/{code} — Resolve a pairing code. */
    async resolvePairing(code: string): Promise<PairingResolveResponse> {
        return this.get<PairingResolveResponse>(`/v1/pairing/resolve/${encodeURIComponent(code)}`);
    }

    /** GET /v1/pairing/{nonce}/status — Poll pairing status. */
    async getPairingStatus(nonce: string): Promise<PairingStatusResponse> {
        return this.get<PairingStatusResponse>(`/v1/pairing/${encodeURIComponent(nonce)}/status`);
    }

    /** POST /v1/pairing/complete — Complete pairing from approver side. */
    async completePairing(request: PairingCompleteRequest): Promise<PairingCompleteResponse> {
        return this.postJson<PairingCompleteResponse>("/v1/pairing/complete", request);
    }

    /** POST /v1/pairing/revoke — Revoke a pairing. */
    async revokePairing(routingToken: string): Promise<PairingRevokeResponse> {
        return this.postJson<PairingRevokeResponse>("/v1/pairing/revoke", { routingToken });
    }

    /** POST /v1/pairing/status-batch — Batch check pairing statuses. */
    async getPairingStatusBatch(routingTokens: string[]): Promise<PairingStatusBatchResponse> {
        return this.postJson<PairingStatusBatchResponse>("/v1/pairing/status-batch", { routingTokens });
    }

    // ── Presence ────────────────────────────────────────────────

    /** POST /v1/presence/heartbeat — Send a presence heartbeat. */
    async sendHeartbeat(request: PresenceHeartbeatRequest): Promise<void> {
        await this.post("/v1/presence/heartbeat", request);
    }

    /** GET /v1/presence/enforcers — List online enforcers. */
    async listEnforcers(): Promise<EnforcerPresenceRecord[]> {
        return this.get<EnforcerPresenceRecord[]>("/v1/presence/enforcers");
    }

    /** GET /v1/presence/enforcers/{id} — Get a single enforcer's presence. */
    async getEnforcerPresence(enforcerDeviceId: string): Promise<EnforcerPresenceRecord> {
        return this.get<EnforcerPresenceRecord>(`/v1/presence/enforcers/${encodeURIComponent(enforcerDeviceId)}`);
    }

    // ── DND (Do Not Disturb) Policies ─────────────────────────────

    /** POST /v1/policy/dnd — Submit a signed DND policy object. */
    async submitDndPolicy(policy: unknown): Promise<void> {
        await this.post("/v1/policy/dnd", policy);
    }

    /** GET /v1/policy/dnd/effective — Fetch effective DND policies for an enforcer/workspace/session. */
    async getEffectiveDndPolicies(
        enforcerId: string,
        workspaceId: string,
        sessionId?: string
    ): Promise<DndEffectiveResponse> {
        const params = new URLSearchParams({
            enforcerId,
            workspaceId,
        });
        if (sessionId) {
            params.set("sessionId", sessionId);
        }
        const path = `/v1/policy/dnd/effective?${params.toString()}`;
        return this.get<DndEffectiveResponse>(path);
    }

    // ── HTTP Helpers ────────────────────────────────────────────

    private async get<T>(path: string): Promise<T> {
        const response = await this.rawFetch("GET", path);
        const body = await response.text();
        await this.ensureSuccess(response, body);
        return JSON.parse(body) as T;
    }

    private async post(path: string, payload: unknown): Promise<void> {
        const response = await this.rawFetch("POST", path, payload);
        const body = await response.text();
        await this.ensureSuccess(response, body);
    }

    private async postJson<T>(path: string, payload: unknown): Promise<T> {
        const response = await this.rawFetch("POST", path, payload);
        const body = await response.text();
        await this.ensureSuccess(response, body);
        return JSON.parse(body) as T;
    }

    private async rawFetch(method: string, path: string, payload?: unknown): Promise<Response> {
        const headers: Record<string, string> = {};
        if (this.token) {
            headers["Authorization"] = `Bearer ${this.token}`;
        }

        const init: RequestInit = { method, headers };
        if (payload !== undefined) {
            headers["Content-Type"] = "application/json";
            init.body = JSON.stringify(payload);
        }

        return this.fetchFn(`${this.baseUrl}${path}`, init);
    }

    private async ensureSuccess(response: Response, body: string): Promise<void> {
        if (response.ok) return;

        let errorCode: string | undefined;
        let errorMessage: string | undefined;
        let requestId: string | undefined;

        try {
            const data = JSON.parse(body);
            // HARP error envelope: { body: { code, message, requestId } }
            if (data.body && typeof data.body === "object") {
                errorCode = data.body.code;
                errorMessage = data.body.message;
                requestId = data.body.requestId;
            } else {
                errorCode = data.error;
                errorMessage = data.message;
            }
        } catch {
            // Not JSON
        }

        throw new AirlockGatewayError(
            errorMessage ?? `Gateway returned ${response.status}`,
            {
                statusCode: response.status,
                errorCode,
                responseBody: body,
                requestId,
            }
        );
    }
}
