using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using NSec.Cryptography;

namespace Airlock.Gateway.Sdk.Crypto
{
    /// <summary>
    /// HARP cryptographic primitives: AES-256-GCM, X25519, HKDF, Ed25519, Base64url, SHA-256.
    /// Adapted from the HARP reference implementation (harp-samples).
    /// </summary>
    public static class CryptoHelpers
    {
        private const int AesKeySize = 32;
        private const int AesNonceSize = 12;
        private const int AesTagSize = 16;

        // ── Base64url ────────────────────────────────────────────────

        /// <summary>Encode bytes to a base64url string (no padding).</summary>
        public static string ToBase64Url(byte[] bytes)
            => Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        /// <summary>Decode a base64url string (with or without padding) to bytes.</summary>
        public static byte[] FromBase64Url(string s)
        {
            s = s.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 2: s += "=="; break;
                case 3: s += "="; break;
            }
            return Convert.FromBase64String(s);
        }

        // ── SHA-256 ──────────────────────────────────────────────────

        /// <summary>Compute lowercase hex SHA-256 of a UTF-8 string.</summary>
        public static string Sha256Hex(string s)
        {
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(s));
            return Convert.ToHexString(hash).ToLowerInvariant();
        }

        // ── HKDF-SHA256 ──────────────────────────────────────────────

        /// <summary>Derive a symmetric key using HKDF-SHA256 (RFC 5869).</summary>
        public static byte[] HkdfSha256(byte[] ikm, byte[] salt, byte[] info, int length = AesKeySize)
        {
            var okm = new byte[length];
            HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, okm, salt, info);
            return okm;
        }

        // ── X25519 ECDH Key Exchange (NSec) ─────────────────────────────
        // Pattern follows harp-samples/src/csharp/Harp.Executor

        /// <summary>
        /// Generate an X25519 keypair for ECDH key agreement.
        /// Returns raw 32-byte keys as base64url (compatible with mobile/Dart).
        /// </summary>
        public static (string publicKeyBase64Url, string privateKeyBase64Url) GenerateX25519KeyPair()
        {
            var algo = KeyAgreementAlgorithm.X25519;
            using var key = new Key(algo, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            var pub = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
            var priv = key.Export(KeyBlobFormat.RawPrivateKey);
            return (ToBase64Url(pub), ToBase64Url(priv));
        }

        /// <summary>
        /// Derive a shared AES-256 key from X25519 ECDH + HKDF-SHA256.
        /// Uses info string "HARP-E2E-AES256GCM" to match the enforcer extension pattern.
        /// Both keys must be raw 32-byte base64url.
        /// </summary>
        public static string DeriveSharedKey(string myPrivateKeyBase64Url, string peerPublicKeyBase64Url)
        {
            var kxAlg = KeyAgreementAlgorithm.X25519;
            var privBytes = FromBase64Url(myPrivateKeyBase64Url);
            var pubBytes = FromBase64Url(peerPublicKeyBase64Url);

            using var privKey = Key.Import(kxAlg, privBytes, KeyBlobFormat.RawPrivateKey,
                new KeyCreationParameters { ExportPolicy = KeyExportPolicies.None });
            var pubKey = PublicKey.Import(kxAlg, pubBytes, KeyBlobFormat.RawPublicKey);

            // X25519 ECDH → shared secret
            var sharedSecret = kxAlg.Agree(privKey, pubKey)
                ?? throw new CryptographicException("X25519 key agreement failed.");

            // HKDF-SHA256: derive 32-byte AES key (same pattern as harp-samples)
            var hkdf = KeyDerivationAlgorithm.HkdfSha256;
            var info = Encoding.UTF8.GetBytes("HARP-E2E-AES256GCM");
            var derived = hkdf.DeriveBytes(sharedSecret, Array.Empty<byte>(), info, AesKeySize);

            return ToBase64Url(derived);
        }

        // ── AES-256-GCM Encrypt/Decrypt ──────────────────────────────

        /// <summary>
        /// Encrypt plaintext with AES-256-GCM (detached: separate nonce + tag).
        /// </summary>
        /// <param name="keyBase64Url">256-bit key as base64url.</param>
        /// <param name="plaintext">UTF-8 plaintext to encrypt.</param>
        /// <returns>EncryptedPayload with base64-encoded fields.</returns>
        public static EncryptedPayload AesGcmEncrypt(string keyBase64Url, string plaintext)
        {
            var key = FromBase64Url(keyBase64Url);
            if (key.Length != AesKeySize)
                throw new ArgumentException($"Key must be {AesKeySize} bytes, got {key.Length}.");

            var nonce = RandomNumberGenerator.GetBytes(AesNonceSize);
            var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
            var ciphertext = new byte[plaintextBytes.Length];
            var tag = new byte[AesTagSize];

            using var aes = new AesGcm(key, AesTagSize);
            aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);

            return new EncryptedPayload
            {
                Alg = "AES-256-GCM",
                Data = Convert.ToBase64String(ciphertext),
                Nonce = Convert.ToBase64String(nonce),
                Tag = Convert.ToBase64String(tag)
            };
        }

        /// <summary>
        /// Decrypt an AES-256-GCM encrypted payload.
        /// </summary>
        /// <param name="keyBase64Url">256-bit key as base64url.</param>
        /// <param name="payload">Encrypted payload with base64-encoded fields.</param>
        /// <returns>Decrypted UTF-8 plaintext.</returns>
        public static string AesGcmDecrypt(string keyBase64Url, EncryptedPayload payload)
        {
            var key = FromBase64Url(keyBase64Url);
            var data = Convert.FromBase64String(payload.Data);
            var nonce = Convert.FromBase64String(payload.Nonce!);
            var tag = Convert.FromBase64String(payload.Tag!);

            var plaintext = new byte[data.Length];
            using var aes = new AesGcm(key, AesTagSize);
            aes.Decrypt(nonce, data, tag, plaintext);

            return Encoding.UTF8.GetString(plaintext);
        }

        // ── Ed25519 Signing & Verification (NSec) ────────────────────

        /// <summary>Generate an Ed25519 signing keypair. Returns (publicKeyBase64Url, privateKeyBase64Url).</summary>
        public static (string publicKeyBase64Url, string privateKeyBase64Url) GenerateEd25519KeyPair()
        {
            var algo = SignatureAlgorithm.Ed25519;
            using var key = new Key(algo, new KeyCreationParameters { ExportPolicy = KeyExportPolicies.AllowPlaintextExport });
            var pub = key.PublicKey.Export(KeyBlobFormat.RawPublicKey);
            var priv = key.Export(KeyBlobFormat.RawPrivateKey);
            return (ToBase64Url(pub), ToBase64Url(priv));
        }

        /// <summary>Sign a message with Ed25519. Returns base64url signature.</summary>
        public static string Ed25519Sign(string privateKeyBase64Url, byte[] message)
        {
            var algo = SignatureAlgorithm.Ed25519;
            var privRaw = FromBase64Url(privateKeyBase64Url);
            using var key = Key.Import(algo, privRaw, KeyBlobFormat.RawPrivateKey);
            var sig = algo.Sign(key, message);
            return ToBase64Url(sig);
        }

        /// <summary>Verify an Ed25519 signature. Returns true if valid.</summary>
        public static bool Ed25519Verify(string publicKeyBase64Url, byte[] message, string signatureBase64Url)
        {
            var algo = SignatureAlgorithm.Ed25519;
            var pubRaw = FromBase64Url(publicKeyBase64Url);
            var sig = FromBase64Url(signatureBase64Url);
            var pk = PublicKey.Import(algo, pubRaw, KeyBlobFormat.RawPublicKey);
            return algo.Verify(pk, message, sig);
        }
    }

    /// <summary>
    /// Encrypted payload (AES-256-GCM) with base64-encoded fields.
    /// Wire-compatible with the CiphertextRef schema in the HARP Gateway spec.
    /// </summary>
    public sealed class EncryptedPayload
    {
        /// <summary>Algorithm identifier, always "AES-256-GCM".</summary>
        public string Alg { get; set; } = "AES-256-GCM";

        /// <summary>Base64-encoded ciphertext.</summary>
        public string Data { get; set; } = "";

        /// <summary>Base64-encoded 12-byte nonce/IV.</summary>
        public string? Nonce { get; set; }

        /// <summary>Base64-encoded 16-byte authentication tag.</summary>
        public string? Tag { get; set; }

        /// <summary>Optional Additional Authenticated Data (base64).</summary>
        public string? Aad { get; set; }
    }
}
