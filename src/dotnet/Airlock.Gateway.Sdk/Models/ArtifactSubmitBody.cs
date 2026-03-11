using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Airlock.Gateway.Sdk.Models
{
    /// <summary>
    /// Body for an artifact.submit envelope.
    /// </summary>
    public class ArtifactSubmitBody
    {
        [JsonPropertyName("artifactType")]
        public string ArtifactType { get; set; } = "";

        [JsonPropertyName("artifactHash")]
        public string ArtifactHash { get; set; } = "";

        [JsonPropertyName("ciphertext")]
        public CiphertextRef Ciphertext { get; set; } = new();

        [JsonPropertyName("expiresAt")]
        public DateTimeOffset ExpiresAt { get; set; }

        [JsonPropertyName("metadata")]
        public Dictionary<string, string>? Metadata { get; set; }
    }

    /// <summary>
    /// Encrypted payload reference within an artifact body.
    /// </summary>
    public class CiphertextRef
    {
        [JsonPropertyName("alg")]
        public string Alg { get; set; } = "";

        [JsonPropertyName("data")]
        public string Data { get; set; } = "";

        [JsonPropertyName("nonce")]
        public string? Nonce { get; set; }

        [JsonPropertyName("tag")]
        public string? Tag { get; set; }

        [JsonPropertyName("aad")]
        public string? Aad { get; set; }
    }

    /// <summary>
    /// Options for building an artifact submission request.
    /// </summary>
    public class ArtifactSubmitRequest
    {
        /// <summary>Unique enforcer identifier.</summary>
        public string EnforcerId { get; set; } = "";

        /// <summary>Type of artifact (e.g., "command-approval").</summary>
        public string ArtifactType { get; set; } = "command-approval";

        /// <summary>SHA-256 hash of the artifact content.</summary>
        public string ArtifactHash { get; set; } = "";

        /// <summary>Encrypted artifact payload.</summary>
        public CiphertextRef Ciphertext { get; set; } = new();

        /// <summary>When the artifact expires. Defaults to 10 minutes from now.</summary>
        public DateTimeOffset? ExpiresAt { get; set; }

        /// <summary>
        /// Routing metadata. Include "routingToken" for paired routing,
        /// or "approverId" for direct routing.
        /// </summary>
        public Dictionary<string, string>? Metadata { get; set; }

        /// <summary>Optional pre-generated request ID. A new UUID is used if null.</summary>
        public string? RequestId { get; set; }
    }
}
