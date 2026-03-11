using System;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Airlock.Gateway.Sdk.Models
{
    /// <summary>
    /// Body of a decision.deliver envelope returned by long-poll or SSE.
    /// </summary>
    public class DecisionDeliverBody
    {
        [JsonPropertyName("artifactHash")]
        public string ArtifactHash { get; set; } = "";

        [JsonPropertyName("decision")]
        public string Decision { get; set; } = "";

        [JsonPropertyName("reason")]
        public string? Reason { get; set; }

        [JsonPropertyName("signerKeyId")]
        public string? SignerKeyId { get; set; }

        [JsonPropertyName("nonce")]
        public string? Nonce { get; set; }

        [JsonPropertyName("signature")]
        public string? Signature { get; set; }

        [JsonPropertyName("decisionHash")]
        public string? DecisionHash { get; set; }

        /// <summary>Returns true if the decision is "approve" (case-insensitive).</summary>
        public bool IsApproved =>
            string.Equals(Decision, "approve", StringComparison.OrdinalIgnoreCase);

        /// <summary>Returns true if the decision is "reject" (case-insensitive).</summary>
        public bool IsRejected =>
            string.Equals(Decision, "reject", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Exchange status response from GET /v1/exchanges/{requestId}.
    /// </summary>
    public class ExchangeStatusResponse
    {
        [JsonPropertyName("msgType")]
        public string MsgType { get; set; } = "";

        [JsonPropertyName("requestId")]
        public string RequestId { get; set; } = "";

        [JsonPropertyName("body")]
        public ExchangeStatusBody? Body { get; set; }
    }

    /// <summary>
    /// Body of an exchange.status response.
    /// </summary>
    public class ExchangeStatusBody
    {
        [JsonPropertyName("requestId")]
        public string RequestId { get; set; } = "";

        [JsonPropertyName("state")]
        public string State { get; set; } = "";

        [JsonPropertyName("createdAt")]
        public DateTimeOffset? CreatedAt { get; set; }

        [JsonPropertyName("expiresAt")]
        public DateTimeOffset? ExpiresAt { get; set; }

        [JsonPropertyName("artifactHash")]
        public string? ArtifactHash { get; set; }

        [JsonPropertyName("decision")]
        public JsonElement? Decision { get; set; }
    }

    /// <summary>
    /// Response from the decision.deliver long-poll endpoint.
    /// </summary>
    public class DecisionDeliverEnvelope
    {
        [JsonPropertyName("msgId")]
        public string? MsgId { get; set; }

        [JsonPropertyName("msgType")]
        public string MsgType { get; set; } = "";

        [JsonPropertyName("requestId")]
        public string RequestId { get; set; } = "";

        [JsonPropertyName("body")]
        public DecisionDeliverBody? Body { get; set; }
    }

    /// <summary>
    /// Ack submission body.
    /// </summary>
    public class AckSubmitBody
    {
        [JsonPropertyName("msgId")]
        public string MsgId { get; set; } = "";

        [JsonPropertyName("status")]
        public string Status { get; set; } = "acknowledged";

        [JsonPropertyName("ackAt")]
        public DateTimeOffset AckAt { get; set; } = DateTimeOffset.UtcNow;
    }
}
