using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Airlock.Gateway.Sdk.Models
{
    /// <summary>
    /// DND policy object as returned by the gateway.
    /// Mirrors the wire shape but keeps most fields generic so the SDK
    /// does not have to understand all possible extensions.
    /// </summary>
    public class DndPolicyWire
    {
        [JsonPropertyName("requestId")]
        public string RequestId { get; set; } = "";

        [JsonPropertyName("objectType")]
        public string ObjectType { get; set; } = "";

        [JsonPropertyName("workspaceId")]
        public string WorkspaceId { get; set; } = "";

        [JsonPropertyName("sessionId")]
        public string? SessionId { get; set; }

        [JsonPropertyName("enforcerId")]
        public string EnforcerId { get; set; } = "";

        [JsonPropertyName("policyMode")]
        public string PolicyMode { get; set; } = "";

        [JsonPropertyName("targetArtifactType")]
        public string? TargetArtifactType { get; set; }

        [JsonPropertyName("actionSelector")]
        public Dictionary<string, object?>? ActionSelector { get; set; }

        [JsonPropertyName("selectorHash")]
        public string? SelectorHash { get; set; }

        [JsonPropertyName("createdAt")]
        public DateTimeOffset? CreatedAt { get; set; }

        [JsonPropertyName("expiresAt")]
        public DateTimeOffset ExpiresAt { get; set; }
    }

    /// <summary>
    /// Response for GET /v1/policy/dnd/effective.
    /// </summary>
    public class DndEffectiveResponse
    {
        [JsonPropertyName("msgType")]
        public string MsgType { get; set; } = "";

        [JsonPropertyName("requestId")]
        public string RequestId { get; set; } = "";

        [JsonPropertyName("body")]
        public List<DndPolicyWire> Body { get; set; } = new List<DndPolicyWire>();
    }
}

