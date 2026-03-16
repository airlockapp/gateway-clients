using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Airlock.Gateway.Sdk.Models
{
    // ── Pairing Initiate ────────────────────────────────────────────

    /// <summary>
    /// Request body for POST /v1/pairing/initiate.
    /// </summary>
    public class PairingInitiateRequest
    {
        [JsonPropertyName("deviceId")]
        public string DeviceId { get; set; } = "";

        [JsonPropertyName("enforcerId")]
        public string EnforcerId { get; set; } = "";

        [JsonPropertyName("gatewayUrl")]
        public string? GatewayUrl { get; set; }

        [JsonPropertyName("x25519PublicKey")]
        public string? X25519PublicKey { get; set; }

        [JsonPropertyName("enforcerLabel")]
        public string? EnforcerLabel { get; set; }

        [JsonPropertyName("workspaceName")]
        public string? WorkspaceName { get; set; }
    }

    /// <summary>
    /// Response body from POST /v1/pairing/initiate.
    /// </summary>
    public class PairingInitiateResponse
    {
        [JsonPropertyName("pairingNonce")]
        public string PairingNonce { get; set; } = "";

        [JsonPropertyName("pairingCode")]
        public string PairingCode { get; set; } = "";

        [JsonPropertyName("deviceId")]
        public string DeviceId { get; set; } = "";

        [JsonPropertyName("gatewayUrl")]
        public string? GatewayUrl { get; set; }

        [JsonPropertyName("expiresAt")]
        public DateTimeOffset ExpiresAt { get; set; }
    }

    // ── Pairing Status ──────────────────────────────────────────────

    /// <summary>
    /// Response body from GET /v1/pairing/{nonce}/status.
    /// </summary>
    public class PairingStatusResponse
    {
        [JsonPropertyName("pairingNonce")]
        public string PairingNonce { get; set; } = "";

        [JsonPropertyName("state")]
        public string State { get; set; } = "";

        [JsonPropertyName("responseJson")]
        public string? ResponseJson { get; set; }

        [JsonPropertyName("routingToken")]
        public string? RoutingToken { get; set; }

        [JsonPropertyName("expiresAt")]
        public DateTimeOffset ExpiresAt { get; set; }
    }

    // ── Pairing Revoke ──────────────────────────────────────────────

    /// <summary>
    /// Request body for POST /v1/pairing/revoke.
    /// </summary>
    public class PairingRevokeRequest
    {
        [JsonPropertyName("routingToken")]
        public string RoutingToken { get; set; } = "";
    }

    /// <summary>
    /// Response body from POST /v1/pairing/revoke.
    /// </summary>
    public class PairingRevokeResponse
    {
        [JsonPropertyName("status")]
        public string Status { get; set; } = "";

        [JsonPropertyName("enforcerId")]
        public string? EnforcerId { get; set; }
    }
}
