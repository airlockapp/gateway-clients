using System;
using System.Threading;
using System.Threading.Tasks;
using Airlock.Gateway.Sdk.Models;

namespace Airlock.Gateway.Sdk
{
    /// <summary>
    /// Client interface for the Airlock Integrations Gateway API.
    /// Covers only enforcer-safe endpoints exposed by the Integrations Gateway.
    /// </summary>
    public interface IAirlockGatewayClient
    {
        // ── Discovery ───────────────────────────────────────────────

        /// <summary>GET /echo — Gateway discovery and health.</summary>
        Task<EchoResponse> EchoAsync(CancellationToken ct = default);

        // ── Artifacts ───────────────────────────────────────────────

        /// <summary>POST /v1/artifacts — Submit an artifact for approval.</summary>
        /// <returns>The request ID of the submitted artifact.</returns>
        Task<string> SubmitArtifactAsync(ArtifactSubmitRequest request, CancellationToken ct = default);

        // ── Exchanges ───────────────────────────────────────────────

        /// <summary>POST /v1/acks — Acknowledge receipt of a decision (fire-and-forget safe).</summary>
        Task SubmitAckAsync(string msgId, string? requestId = null, CancellationToken ct = default);

        /// <summary>GET /v1/exchanges/{requestId} — Get exchange status.</summary>
        Task<ExchangeStatusResponse> GetExchangeStatusAsync(string requestId, CancellationToken ct = default);

        /// <summary>GET /v1/exchanges/{requestId}/wait — Long-poll for decision.</summary>
        /// <returns>The decision envelope, or null on timeout (204).</returns>
        Task<DecisionDeliverEnvelope?> WaitForDecisionAsync(string requestId, int timeoutSeconds = 30, CancellationToken ct = default);

        /// <summary>POST /v1/exchanges/{requestId}/withdraw — Withdraw a pending exchange.</summary>
        Task WithdrawExchangeAsync(string requestId, CancellationToken ct = default);

        // ── Pairing ─────────────────────────────────────────────────

        /// <summary>POST /v1/pairing/initiate — Start a new pairing session.</summary>
        Task<PairingInitiateResponse> InitiatePairingAsync(PairingInitiateRequest request, CancellationToken ct = default);

        /// <summary>GET /v1/pairing/{nonce}/status — Poll pairing status.</summary>
        Task<PairingStatusResponse> GetPairingStatusAsync(string nonce, CancellationToken ct = default);

        /// <summary>POST /v1/pairing/revoke — Revoke a pairing.</summary>
        Task<PairingRevokeResponse> RevokePairingAsync(string routingToken, CancellationToken ct = default);

        /// <summary>POST /v1/pairing/claim — Claim a pre-generated pairing code.</summary>
        Task<PairingClaimResponse> ClaimPairingAsync(PairingClaimRequest request, CancellationToken ct = default);

        // ── Presence ────────────────────────────────────────────────

        /// <summary>POST /v1/presence/heartbeat — Send a presence heartbeat.</summary>
        Task SendHeartbeatAsync(PresenceHeartbeatRequest request, CancellationToken ct = default);

        // ── DND (Do Not Disturb) Policies ───────────────────────────

        /// <summary>GET /v1/policy/dnd/effective — Fetch effective DND policies for an enforcer/workspace/session.</summary>
        Task<DndEffectiveResponse> GetEffectiveDndPoliciesAsync(
            string enforcerId,
            string workspaceId,
            string? sessionId = null,
            CancellationToken ct = default);

        // ── Consent ─────────────────────────────────────────────────

        /// <summary>GET /v1/consent/status — Check if the user has consented to this enforcer app.</summary>
        /// <returns>Consent status string ("approved"). Throws AirlockGatewayException with error_code
        /// "app_consent_required" or "app_consent_pending" if consent is not granted.</returns>
        Task<string> CheckConsentAsync(CancellationToken ct = default);

        // ── Transparent Encryption ──────────────────────────────────

        /// <summary>
        /// Encrypt a plaintext payload with AES-256-GCM and submit as an artifact.
        /// Handles canonicalization, hashing, encryption, and HARP envelope construction.
        /// </summary>
        /// <returns>The request ID of the submitted artifact.</returns>
        Task<string> EncryptAndSubmitArtifactAsync(EncryptedArtifactRequest request, CancellationToken ct = default);

        /// <summary>
        /// Verify a decision envelope: Ed25519 signature, artifact binding, and expiry.
        /// </summary>
        /// <param name="decision">The decision envelope from WaitForDecisionAsync.</param>
        /// <param name="expectedArtifactHash">The SHA-256 hash of the original artifact.</param>
        /// <param name="signerPublicKeyBase64Url">The signer's Ed25519 public key (base64url).</param>
        /// <returns>A verification result.</returns>
        DecisionVerificationResult VerifyDecision(
            DecisionDeliverEnvelope decision,
            string expectedArtifactHash,
            string signerPublicKeyBase64Url);
    }

    /// <summary>
    /// Result of decision verification.
    /// </summary>
    public sealed class DecisionVerificationResult
    {
        /// <summary>Whether all checks passed.</summary>
        public bool IsValid { get; init; }

        /// <summary>Reason for failure (null if valid).</summary>
        public string? FailureReason { get; init; }

        /// <summary>The decision value (approve/reject) if valid.</summary>
        public string? Decision { get; init; }

        /// <summary>Create a successful result.</summary>
        internal static DecisionVerificationResult Success(string decision)
            => new() { IsValid = true, Decision = decision };

        /// <summary>Create a failure result.</summary>
        internal static DecisionVerificationResult Failure(string reason)
            => new() { IsValid = false, FailureReason = reason };
    }
}
