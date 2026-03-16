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
