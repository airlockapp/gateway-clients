using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Airlock.Gateway.Sdk.Models
{
    /// <summary>
    /// Request body for POST /v1/presence/heartbeat.
    /// </summary>
    public class PresenceHeartbeatRequest
    {
        [JsonPropertyName("enforcerId")]
        public string EnforcerId { get; set; } = "";

        [JsonPropertyName("workspaceName")]
        public string? WorkspaceName { get; set; }

        [JsonPropertyName("enforcerLabel")]
        public string? EnforcerLabel { get; set; }
    }

    /// <summary>
    /// Presence record for a connected enforcer.
    /// </summary>
    public class EnforcerPresenceRecord
    {
        [JsonPropertyName("enforcerDeviceId")]
        public string EnforcerDeviceId { get; set; } = "";

        [JsonPropertyName("status")]
        public string Status { get; set; } = "";

        [JsonPropertyName("lastSeenAt")]
        public DateTimeOffset? LastSeenAt { get; set; }

        [JsonPropertyName("transport")]
        public string? Transport { get; set; }

        [JsonPropertyName("capabilities")]
        public Dictionary<string, string>? Capabilities { get; set; }

        [JsonPropertyName("workspaceName")]
        public string? WorkspaceName { get; set; }

        [JsonPropertyName("enforcerLabel")]
        public string? EnforcerLabel { get; set; }
    }

    /// <summary>
    /// Response from the /echo discovery endpoint.
    /// </summary>
    public class EchoResponse
    {
        [JsonPropertyName("utc")]
        public string Utc { get; set; } = "";

        [JsonPropertyName("local")]
        public string Local { get; set; } = "";

        [JsonPropertyName("timezone")]
        public string Timezone { get; set; } = "";

        [JsonPropertyName("offsetMinutes")]
        public int OffsetMinutes { get; set; }
    }
}
