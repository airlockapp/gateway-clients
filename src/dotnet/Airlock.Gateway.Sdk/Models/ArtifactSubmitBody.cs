using System;
using System.Collections.Generic;
using System.Text.Json.Serialization;
using Airlock.Gateway.Sdk.Crypto;

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
        public EncryptedPayload Ciphertext { get; set; } = new();

        [JsonPropertyName("expiresAt")]
        public DateTimeOffset ExpiresAt { get; set; }

        [JsonPropertyName("metadata")]
        public Dictionary<string, string>? Metadata { get; set; }
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
        public EncryptedPayload Ciphertext { get; set; } = new();

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

    /// <summary>
    /// Options for building an encrypted artifact submission.
    /// The SDK will handle encryption, hashing, and CiphertextRef construction.
    /// </summary>
    public class EncryptedArtifactRequest
    {
        /// <summary>Unique enforcer identifier.</summary>
        public string EnforcerId { get; set; } = "";

        /// <summary>Type of artifact (e.g., "command-approval").</summary>
        public string ArtifactType { get; set; } = "command-approval";

        /// <summary>Plaintext payload JSON to encrypt.</summary>
        public string PlaintextPayload { get; set; } = "";

        /// <summary>Shared encryption key (base64url), derived from X25519 ECDH during pairing.</summary>
        public string EncryptionKeyBase64Url { get; set; } = "";

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
