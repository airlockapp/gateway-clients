using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Airlock.Gateway.Sdk.Models
{
    /// <summary>
    /// HARP Gateway Wire Envelope per harp-gateway-envelope.schema.json.
    /// Used for artifact.submit, decision.submit, ack.submit, and response envelopes.
    /// </summary>
    public class HarpEnvelope
    {
        [JsonPropertyName("msgId")]
        public string? MsgId { get; set; }

        [JsonPropertyName("msgType")]
        public string MsgType { get; set; } = "";

        [JsonPropertyName("requestId")]
        public string RequestId { get; set; } = "";

        [JsonPropertyName("createdAt")]
        public DateTimeOffset CreatedAt { get; set; }

        [JsonPropertyName("expiresAt")]
        public DateTimeOffset? ExpiresAt { get; set; }

        [JsonPropertyName("sender")]
        public SenderInfo? Sender { get; set; }

        [JsonPropertyName("recipient")]
        public RecipientInfo? Recipient { get; set; }

        [JsonPropertyName("body")]
        public object? Body { get; set; }
    }

    /// <summary>
    /// Identifies the sender of a HARP message.
    /// </summary>
    public class SenderInfo
    {
        [JsonPropertyName("enforcerId")]
        public string? EnforcerId { get; set; }

        [JsonPropertyName("approverId")]
        public string? ApproverId { get; set; }

        [JsonPropertyName("gatewayId")]
        public string? GatewayId { get; set; }
    }

    /// <summary>
    /// Identifies the recipient of a HARP message.
    /// </summary>
    public class RecipientInfo
    {
        [JsonPropertyName("enforcerId")]
        public string? EnforcerId { get; set; }

        [JsonPropertyName("approverId")]
        public string? ApproverId { get; set; }
    }

    /// <summary>
    /// Envelope body for error responses from the gateway.
    /// </summary>
    public class ErrorBody
    {
        [JsonPropertyName("code")]
        public string Code { get; set; } = "";

        [JsonPropertyName("message")]
        public string Message { get; set; } = "";

        [JsonPropertyName("requestId")]
        public string? RequestId { get; set; }
    }

    /// <summary>
    /// Envelope body for ack.submit messages to the gateway.
    /// </summary>
    public class AckSubmitBody
    {
        [JsonPropertyName("msgId")]
        public string MsgId { get; set; } = "";

        [JsonPropertyName("status")]
        public string Status { get; set; } = "";

        [JsonPropertyName("ackAt")]
        public DateTimeOffset AckAt { get; set; }
    }
}
