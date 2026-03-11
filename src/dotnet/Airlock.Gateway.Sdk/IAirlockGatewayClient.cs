using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Airlock.Gateway.Sdk.Models;

namespace Airlock.Gateway.Sdk
{
    /// <summary>
    /// Client interface for the Airlock Gateway API.
    /// Supports dependency injection and unit-test mocking.
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

        /// <summary>GET /v1/exchanges/{requestId} — Get exchange status.</summary>
        Task<ExchangeStatusResponse> GetExchangeStatusAsync(string requestId, CancellationToken ct = default);

        /// <summary>GET /v1/exchanges/{requestId}/wait — Long-poll for decision.</summary>
        /// <returns>The decision envelope, or null on timeout (204).</returns>
        Task<DecisionDeliverEnvelope?> WaitForDecisionAsync(string requestId, int timeoutSeconds = 30, CancellationToken ct = default);

        /// <summary>POST /v1/exchanges/{requestId}/withdraw — Withdraw a pending exchange.</summary>
        Task WithdrawExchangeAsync(string requestId, CancellationToken ct = default);

        // ── Acknowledgements ────────────────────────────────────────

        /// <summary>POST /v1/acks — Acknowledge an inbox message.</summary>
        Task AcknowledgeAsync(string msgId, string enforcerId, CancellationToken ct = default);

        // ── Pairing ─────────────────────────────────────────────────

        /// <summary>POST /v1/pairing/initiate — Start a new pairing session.</summary>
        Task<PairingInitiateResponse> InitiatePairingAsync(PairingInitiateRequest request, CancellationToken ct = default);

        /// <summary>GET /v1/pairing/resolve/{code} — Resolve a pairing code.</summary>
        Task<PairingResolveResponse> ResolvePairingAsync(string code, CancellationToken ct = default);

        /// <summary>GET /v1/pairing/{nonce}/status — Poll pairing status.</summary>
        Task<PairingStatusResponse> GetPairingStatusAsync(string nonce, CancellationToken ct = default);

        /// <summary>POST /v1/pairing/complete — Complete pairing from approver side.</summary>
        Task<PairingCompleteResponse> CompletePairingAsync(PairingCompleteRequest request, CancellationToken ct = default);

        /// <summary>POST /v1/pairing/revoke — Revoke a pairing.</summary>
        Task<PairingRevokeResponse> RevokePairingAsync(string routingToken, CancellationToken ct = default);

        /// <summary>POST /v1/pairing/status-batch — Batch check pairing statuses.</summary>
        Task<PairingStatusBatchResponse> GetPairingStatusBatchAsync(List<string> routingTokens, CancellationToken ct = default);

        // ── Presence ────────────────────────────────────────────────

        /// <summary>POST /v1/presence/heartbeat — Send a presence heartbeat.</summary>
        Task SendHeartbeatAsync(PresenceHeartbeatRequest request, CancellationToken ct = default);

        /// <summary>GET /v1/presence/enforcers — List online enforcers.</summary>
        Task<List<EnforcerPresenceRecord>> ListEnforcersAsync(CancellationToken ct = default);

        /// <summary>GET /v1/presence/enforcers/{id} — Get a single enforcer's presence.</summary>
        Task<EnforcerPresenceRecord> GetEnforcerPresenceAsync(string enforcerDeviceId, CancellationToken ct = default);
    }
}
