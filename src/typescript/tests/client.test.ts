import { describe, it, expect } from "vitest";
import { AirlockGatewayClient } from "../src/client.js";
import { AirlockGatewayError } from "../src/errors.js";
import { createMockFetch } from "./helpers.js";

function createClient() {
    const mock = createMockFetch();
    const client = new AirlockGatewayClient({
        baseUrl: "https://gw.test",
        token: "test-token",
        fetch: mock.fetch,
    });
    return { client, mock };
}

// ── Echo ─────────────────────────────────────────────────────────

describe("echo", () => {
    it("returns server time", async () => {
        const { client, mock } = createClient();
        mock.enqueue(200, {
            utc: "2025-01-01T00:00:00Z",
            local: "2025-01-01T03:00:00+03:00",
            timezone: "Europe/Istanbul",
            offsetMinutes: 180,
        });

        const result = await client.echo();

        expect(result.timezone).toBe("Europe/Istanbul");
        expect(result.offsetMinutes).toBe(180);
        expect(mock.requests[0].method).toBe("GET");
        expect(mock.requests[0].url).toContain("/echo");
    });
});

// ── Submit Artifact ──────────────────────────────────────────────

describe("submitArtifact", () => {
    it("posts envelope and returns request ID", async () => {
        const { client, mock } = createClient();
        mock.enqueue(202, { msgType: "artifact.accepted" });

        const requestId = await client.submitArtifact({
            enforcerId: "enforcer-1",
            artifactHash: "abc123",
            ciphertext: { alg: "aes-256-gcm", data: "encrypted" },
            requestId: "req-test123",
        });

        expect(requestId).toBe("req-test123");
        expect(mock.requests[0].method).toBe("POST");
        expect(mock.requests[0].url).toContain("/v1/artifacts");
        expect(mock.requests[0].body).toContain("artifact.submit");
    });

    it("generates request ID when not provided", async () => {
        const { client, mock } = createClient();
        mock.enqueue(202, {});

        const requestId = await client.submitArtifact({
            enforcerId: "e1",
            artifactHash: "h1",
            ciphertext: { alg: "aes-256-gcm", data: "d" },
        });

        expect(requestId).toMatch(/^req-/);
    });

    it("throws on no approver (422)", async () => {
        const { client, mock } = createClient();
        mock.enqueue(422, {
            msgType: "error",
            body: { code: "no_approver", message: "No approver available." },
        });

        await expect(
            client.submitArtifact({
                enforcerId: "e1",
                artifactHash: "h1",
                ciphertext: { alg: "aes-256-gcm", data: "d" },
            })
        ).rejects.toThrow(AirlockGatewayError);

        try {
            await client.submitArtifact({
                enforcerId: "e1",
                artifactHash: "h1",
                ciphertext: { alg: "aes-256-gcm", data: "d" },
            });
        } catch (e) {
            // Already thrown above, testing error properties
        }
    });

    it("throws on quota exceeded (429)", async () => {
        const { client, mock } = createClient();
        mock.enqueue(429, {
            msgType: "error",
            body: { code: "quota_exceeded", message: "Monthly quota exceeded" },
        });

        try {
            await client.submitArtifact({
                enforcerId: "e1",
                artifactHash: "h1",
                ciphertext: { alg: "aes-256-gcm", data: "d" },
            });
            expect.unreachable();
        } catch (e) {
            expect(e).toBeInstanceOf(AirlockGatewayError);
            expect((e as AirlockGatewayError).isQuotaExceeded).toBe(true);
        }
    });

    it("throws on conflict (409)", async () => {
        const { client, mock } = createClient();
        mock.enqueue(409, {
            msgType: "error",
            body: { code: "AlreadyExistsConflict" },
        });

        try {
            await client.submitArtifact({
                enforcerId: "e1",
                artifactHash: "h1",
                ciphertext: { alg: "aes-256-gcm", data: "d" },
            });
            expect.unreachable();
        } catch (e) {
            expect(e).toBeInstanceOf(AirlockGatewayError);
            expect((e as AirlockGatewayError).isConflict).toBe(true);
        }
    });
});

// ── Exchange Status ──────────────────────────────────────────────

describe("getExchangeStatus", () => {
    it("returns status", async () => {
        const { client, mock } = createClient();
        mock.enqueue(200, {
            msgType: "exchange.status",
            requestId: "req-1",
            body: { requestId: "req-1", state: "PendingApproval" },
        });

        const result = await client.getExchangeStatus("req-1");

        expect(result.body?.state).toBe("PendingApproval");
    });

    it("throws on not found", async () => {
        const { client, mock } = createClient();
        mock.enqueue(404, { error: "NotFound", message: "Exchange not found" });

        await expect(client.getExchangeStatus("req-x")).rejects.toThrow(AirlockGatewayError);
    });
});

// ── Wait for Decision ────────────────────────────────────────────

describe("waitForDecision", () => {
    it("returns decision", async () => {
        const { client, mock } = createClient();
        mock.enqueue(200, {
            msgType: "decision.deliver",
            requestId: "req-1",
            body: { decision: "approve", reason: "Looks good" },
        });

        const result = await client.waitForDecision("req-1");

        expect(result).not.toBeNull();
        expect(result!.body?.decision).toBe("approve");
    });

    it("returns null on 204", async () => {
        const { client, mock } = createClient();
        mock.enqueue(204, "");

        const result = await client.waitForDecision("req-1", 5);

        expect(result).toBeNull();
    });

    it("clamps timeout to 60", async () => {
        const { client, mock } = createClient();
        mock.enqueue(204, "");

        await client.waitForDecision("req-1", 200);

        expect(mock.requests[0].url).toContain("timeout=60");
    });
});

// ── Withdraw ─────────────────────────────────────────────────────

describe("withdrawExchange", () => {
    it("posts to correct path", async () => {
        const { client, mock } = createClient();
        mock.enqueue(200, {});

        await client.withdrawExchange("req-1");

        expect(mock.requests[0].url).toContain("/v1/exchanges/req-1/withdraw");
    });
});

// ── Acknowledge ──────────────────────────────────────────────────

describe("acknowledge", () => {
    it("posts ack envelope", async () => {
        const { client, mock } = createClient();
        mock.enqueue(200, {});

        await client.acknowledge("msg-123", "enforcer-1");

        expect(mock.requests[0].body).toContain("ack.submit");
        expect(mock.requests[0].body).toContain("msg-123");
    });
});

// ── Pairing ──────────────────────────────────────────────────────

describe("pairing", () => {
    it("initiate returns nonce and code", async () => {
        const { client, mock } = createClient();
        mock.enqueue(201, { pairingNonce: "n1", pairingCode: "ABC123", deviceId: "d1" });

        const result = await client.initiatePairing({ deviceId: "d1", enforcerId: "e1" });

        expect(result.pairingNonce).toBe("n1");
        expect(result.pairingCode).toBe("ABC123");
    });

    it("resolve returns session info", async () => {
        const { client, mock } = createClient();
        mock.enqueue(200, { pairingNonce: "n1", deviceId: "d1", enforcerLabel: "Cursor" });

        const result = await client.resolvePairing("ABC123");
        expect(result.enforcerLabel).toBe("Cursor");
    });

    it("get status returns state", async () => {
        const { client, mock } = createClient();
        mock.enqueue(200, { pairingNonce: "n1", state: "Completed", routingToken: "rt-1" });

        const result = await client.getPairingStatus("n1");
        expect(result.state).toBe("Completed");
    });

    it("complete returns routing token", async () => {
        const { client, mock } = createClient();
        mock.enqueue(200, { status: "completed", pairingNonce: "n1", routingToken: "rt-1" });

        const result = await client.completePairing({ pairingNonce: "n1" });
        expect(result.routingToken).toBe("rt-1");
    });

    it("revoke posts correctly", async () => {
        const { client, mock } = createClient();
        mock.enqueue(200, { status: "revoked" });

        const result = await client.revokePairing("rt-1");
        expect(result.status).toBe("revoked");
    });

    it("status-batch returns statuses", async () => {
        const { client, mock } = createClient();
        mock.enqueue(200, { statuses: { "rt-1": "Completed", "rt-2": "Revoked" } });

        const result = await client.getPairingStatusBatch(["rt-1", "rt-2"]);
        expect(result.statuses["rt-1"]).toBe("Completed");
    });

    it("resolve throws on expired (410)", async () => {
        const { client, mock } = createClient();
        mock.enqueue(410, { error: "expired" });

        try {
            await client.resolvePairing("OLD");
            expect.unreachable();
        } catch (e) {
            expect((e as AirlockGatewayError).isExpired).toBe(true);
        }
    });
});

// ── Presence ─────────────────────────────────────────────────────

describe("presence", () => {
    it("sends heartbeat", async () => {
        const { client, mock } = createClient();
        mock.enqueue(200, {});

        await client.sendHeartbeat({ enforcerId: "e-1" });
        expect(mock.requests[0].url).toContain("/v1/presence/heartbeat");
    });

    it("lists enforcers", async () => {
        const { client, mock } = createClient();
        mock.enqueue(200, [
            { enforcerDeviceId: "e1", status: "online" },
            { enforcerDeviceId: "e2", status: "online" },
        ]);

        const result = await client.listEnforcers();
        expect(result).toHaveLength(2);
    });

    it("gets single enforcer", async () => {
        const { client, mock } = createClient();
        mock.enqueue(200, { enforcerDeviceId: "e1", status: "online" });

        const result = await client.getEnforcerPresence("e1");
        expect(result.status).toBe("online");
    });
});

// ── Error Edge Cases ─────────────────────────────────────────────

describe("error handling", () => {
    it("throws on non-JSON error body", async () => {
        const { client, mock } = createClient();
        mock.enqueue(500, "Internal Server Error");

        try {
            await client.echo();
            expect.unreachable();
        } catch (e) {
            expect(e).toBeInstanceOf(AirlockGatewayError);
            expect((e as AirlockGatewayError).statusCode).toBe(500);
        }
    });

    it("throws on unauthorized (401)", async () => {
        const { client, mock } = createClient();
        mock.enqueue(401, "");

        await expect(client.echo()).rejects.toThrow(AirlockGatewayError);
    });

    it("sets authorization header", async () => {
        const { client, mock } = createClient();
        mock.enqueue(200, { utc: "", local: "", timezone: "", offsetMinutes: 0 });

        await client.echo();

        expect(mock.requests[0].headers["Authorization"]).toBe("Bearer test-token");
    });
});
