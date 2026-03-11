import { describe, it, expect } from "vitest";
import { AirlockGatewayError } from "../src/errors.js";

describe("AirlockGatewayError", () => {
    it("isQuotaExceeded is true for 429", () => {
        const err = new AirlockGatewayError("quota", { statusCode: 429 });
        expect(err.isQuotaExceeded).toBe(true);
    });

    it("isQuotaExceeded is true for quota_exceeded code", () => {
        const err = new AirlockGatewayError("quota", { errorCode: "quota_exceeded" });
        expect(err.isQuotaExceeded).toBe(true);
    });

    it("isQuotaExceeded is true for workspace_limit_exceeded code", () => {
        const err = new AirlockGatewayError("limit", { errorCode: "workspace_limit_exceeded" });
        expect(err.isQuotaExceeded).toBe(true);
    });

    it("isPairingRevoked is true for pairing_revoked code", () => {
        const err = new AirlockGatewayError("revoked", { errorCode: "pairing_revoked" });
        expect(err.isPairingRevoked).toBe(true);
    });

    it("isExpired is true for 410", () => {
        const err = new AirlockGatewayError("gone", { statusCode: 410 });
        expect(err.isExpired).toBe(true);
    });

    it("isExpired is true for expired code", () => {
        const err = new AirlockGatewayError("expired", { errorCode: "expired" });
        expect(err.isExpired).toBe(true);
    });

    it("isConflict is true for 409", () => {
        const err = new AirlockGatewayError("conflict", { statusCode: 409 });
        expect(err.isConflict).toBe(true);
    });

    it("preserves all fields", () => {
        const err = new AirlockGatewayError("test", {
            statusCode: 422,
            errorCode: "test_code",
            responseBody: '{"error":true}',
            requestId: "req-1",
        });

        expect(err.message).toBe("test");
        expect(err.statusCode).toBe(422);
        expect(err.errorCode).toBe("test_code");
        expect(err.responseBody).toBe('{"error":true}');
        expect(err.requestId).toBe("req-1");
        expect(err.name).toBe("AirlockGatewayError");
    });
});
