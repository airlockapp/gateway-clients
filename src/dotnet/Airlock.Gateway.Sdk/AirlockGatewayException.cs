using System;
using System.Net;

namespace Airlock.Gateway.Sdk
{
    /// <summary>
    /// Exception thrown when a Gateway API call returns an error response.
    /// </summary>
    public class AirlockGatewayException : Exception
    {
        /// <summary>HTTP status code, if available.</summary>
        public HttpStatusCode? StatusCode { get; }

        /// <summary>Error code from the gateway (e.g., "bad_request", "no_approver", "quota_exceeded").</summary>
        public string? ErrorCode { get; }

        /// <summary>The raw response body, if available.</summary>
        public string? ResponseBody { get; }

        /// <summary>The request ID associated with the failed operation.</summary>
        public string? RequestId { get; }

        public AirlockGatewayException(string message)
            : base(message) { }

        public AirlockGatewayException(string message, Exception innerException)
            : base(message, innerException) { }

        public AirlockGatewayException(
            string message,
            HttpStatusCode statusCode,
            string? errorCode = null,
            string? responseBody = null,
            string? requestId = null)
            : base(message)
        {
            StatusCode = statusCode;
            ErrorCode = errorCode;
            ResponseBody = responseBody;
            RequestId = requestId;
        }

        /// <summary>True if the error is a rate-limit (429) or quota-exceeded response.</summary>
        public bool IsQuotaExceeded =>
            StatusCode == (HttpStatusCode)429 ||
            string.Equals(ErrorCode, "quota_exceeded", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(ErrorCode, "workspace_limit_exceeded", StringComparison.OrdinalIgnoreCase);

        /// <summary>True if the pairing was revoked (403 pairing_revoked).</summary>
        public bool IsPairingRevoked =>
            string.Equals(ErrorCode, "pairing_revoked", StringComparison.OrdinalIgnoreCase);

        /// <summary>True if the error indicates an expired resource (410 or 422 expired).</summary>
        public bool IsExpired =>
            StatusCode == HttpStatusCode.Gone ||
            string.Equals(ErrorCode, "expired", StringComparison.OrdinalIgnoreCase);

        /// <summary>True if the error is an idempotency conflict (409).</summary>
        public bool IsConflict =>
            StatusCode == HttpStatusCode.Conflict;
    }
}
