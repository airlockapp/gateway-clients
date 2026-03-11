/**
 * Error thrown when a Gateway API call returns an error response.
 */
export class AirlockGatewayError extends Error {
    public readonly statusCode?: number;
    public readonly errorCode?: string;
    public readonly responseBody?: string;
    public readonly requestId?: string;

    constructor(
        message: string,
        options?: {
            statusCode?: number;
            errorCode?: string;
            responseBody?: string;
            requestId?: string;
        }
    ) {
        super(message);
        this.name = "AirlockGatewayError";
        this.statusCode = options?.statusCode;
        this.errorCode = options?.errorCode;
        this.responseBody = options?.responseBody;
        this.requestId = options?.requestId;
    }

    /** True if the error is a rate-limit (429) or quota-exceeded response. */
    get isQuotaExceeded(): boolean {
        return (
            this.statusCode === 429 ||
            this.errorCode?.toLowerCase() === "quota_exceeded" ||
            this.errorCode?.toLowerCase() === "workspace_limit_exceeded"
        );
    }

    /** True if the pairing was revoked (403 pairing_revoked). */
    get isPairingRevoked(): boolean {
        return this.errorCode?.toLowerCase() === "pairing_revoked";
    }

    /** True if the error indicates an expired resource (410 or 422 expired). */
    get isExpired(): boolean {
        return (
            this.statusCode === 410 ||
            this.errorCode?.toLowerCase() === "expired"
        );
    }

    /** True if the error is an idempotency conflict (409). */
    get isConflict(): boolean {
        return this.statusCode === 409;
    }
}
