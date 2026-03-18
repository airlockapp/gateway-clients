using System.Text.Json;
using Org.Webpki.JsonCanonicalizer;

namespace Airlock.Gateway.Sdk.Crypto
{
    /// <summary>
    /// RFC 8785 JSON Canonicalization Scheme (JCS).
    /// Produces deterministic JSON surface for hashing and signing.
    /// </summary>
    public static class CanonicalJson
    {
        /// <summary>
        /// Canonicalize a JSON string per RFC 8785 (JCS).
        /// </summary>
        public static string Canonicalize(string json)
        {
            var canonicalizer = new JsonCanonicalizer(json);
            return canonicalizer.GetEncodedString();
        }

        /// <summary>
        /// Serialize an object to canonical JSON (RFC 8785 JCS).
        /// </summary>
        public static string Serialize<T>(T obj, JsonSerializerOptions? options = null)
        {
            var json = JsonSerializer.Serialize(obj, options ?? DefaultOptions);
            return Canonicalize(json);
        }

        /// <summary>
        /// Compute the canonical JSON hash (SHA-256) of an object.
        /// Useful for producing artifact hashes.
        /// </summary>
        public static string HashCanonical<T>(T obj, JsonSerializerOptions? options = null)
        {
            var canonical = Serialize(obj, options);
            return CryptoHelpers.Sha256Hex(canonical);
        }

        private static readonly JsonSerializerOptions DefaultOptions = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
        };
    }
}
