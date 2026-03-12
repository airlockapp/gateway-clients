using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Airlock.Gateway.Sdk.Models;

namespace Airlock.Gateway.Sdk
{
    /// <summary>
    /// HTTP client for the Airlock Gateway API.
    /// Wraps all enforcer-side endpoints with typed request/response models.
    /// </summary>
    public class AirlockGatewayClient : IAirlockGatewayClient
    {
        private readonly HttpClient _http;

        private static readonly JsonSerializerOptions JsonOpts = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            PropertyNameCaseInsensitive = true,
#if NET5_0_OR_GREATER
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
#endif
        };

        /// <summary>
        /// Creates a new AirlockGatewayClient.
        /// The HttpClient should be pre-configured with BaseAddress and Authorization header.
        /// </summary>
        public AirlockGatewayClient(HttpClient httpClient)
        {
            _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        }

        /// <summary>
        /// Creates a new AirlockGatewayClient with the specified base URL and optional Bearer token.
        /// </summary>
        public AirlockGatewayClient(string baseUrl, string? bearerToken = null)
        {
            _http = new HttpClient
            {
                BaseAddress = new Uri(baseUrl.TrimEnd('/')),
                Timeout = TimeSpan.FromSeconds(90)
            };
            if (!string.IsNullOrEmpty(bearerToken))
            {
                _http.DefaultRequestHeaders.Authorization =
                    new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", bearerToken);
            }
        }

        // ── Discovery ───────────────────────────────────────────────

        /// <inheritdoc />
        public async Task<EchoResponse> EchoAsync(CancellationToken ct = default)
        {
            return await GetAsync<EchoResponse>("/echo", ct).ConfigureAwait(false);
        }

        // ── Artifacts ───────────────────────────────────────────────

        /// <inheritdoc />
        public async Task<string> SubmitArtifactAsync(ArtifactSubmitRequest request, CancellationToken ct = default)
        {
            var requestId = request.RequestId ?? ("req-" + Guid.NewGuid().ToString("N"));
            var expiresAt = request.ExpiresAt ?? DateTimeOffset.UtcNow.AddMinutes(10);

            var envelope = new HarpEnvelope
            {
                MsgId = "msg-" + Guid.NewGuid().ToString("N"),
                MsgType = "artifact.submit",
                RequestId = requestId,
                CreatedAt = DateTimeOffset.UtcNow,
                Sender = new SenderInfo { EnforcerId = request.EnforcerId },
                Body = new ArtifactSubmitBody
                {
                    ArtifactType = request.ArtifactType,
                    ArtifactHash = request.ArtifactHash,
                    Ciphertext = request.Ciphertext,
                    ExpiresAt = expiresAt,
                    Metadata = request.Metadata
                }
            };

            await PostAsync("/v1/artifacts", envelope, ct).ConfigureAwait(false);
            return requestId;
        }

        // ── Exchanges ───────────────────────────────────────────────

        /// <inheritdoc />
        public async Task<ExchangeStatusResponse> GetExchangeStatusAsync(string requestId, CancellationToken ct = default)
        {
            return await GetAsync<ExchangeStatusResponse>($"/v1/exchanges/{Uri.EscapeDataString(requestId)}", ct)
                .ConfigureAwait(false);
        }

        /// <inheritdoc />
        public async Task<DecisionDeliverEnvelope?> WaitForDecisionAsync(
            string requestId, int timeoutSeconds = 30, CancellationToken ct = default)
        {
            timeoutSeconds = Math.Max(1, Math.Min(60, timeoutSeconds));
            var url = $"/v1/exchanges/{Uri.EscapeDataString(requestId)}/wait?timeout={timeoutSeconds}";

            var response = await _http.GetAsync(url, ct).ConfigureAwait(false);

            if (response.StatusCode == HttpStatusCode.NoContent)
                return null; // No decision yet

            var body = await ReadResponseBodyAsync(response).ConfigureAwait(false);
            await EnsureSuccessAsync(response, body).ConfigureAwait(false);

            return JsonSerializer.Deserialize<DecisionDeliverEnvelope>(body, JsonOpts);
        }

        /// <inheritdoc />
        public async Task WithdrawExchangeAsync(string requestId, CancellationToken ct = default)
        {
            await PostAsync($"/v1/exchanges/{Uri.EscapeDataString(requestId)}/withdraw", null, ct)
                .ConfigureAwait(false);
        }

        // ── Acknowledgements ────────────────────────────────────────

        /// <inheritdoc />
        public async Task AcknowledgeAsync(string msgId, string enforcerId, CancellationToken ct = default)
        {
            var envelope = new HarpEnvelope
            {
                MsgId = "msg-" + Guid.NewGuid().ToString("N"),
                MsgType = "ack.submit",
                RequestId = "ack-" + Guid.NewGuid().ToString("N"),
                CreatedAt = DateTimeOffset.UtcNow,
                Sender = new SenderInfo { EnforcerId = enforcerId },
                Body = new AckSubmitBody
                {
                    MsgId = msgId,
                    Status = "acknowledged",
                    AckAt = DateTimeOffset.UtcNow
                }
            };

            await PostAsync("/v1/acks", envelope, ct).ConfigureAwait(false);
        }

        // ── Pairing ─────────────────────────────────────────────────

        /// <inheritdoc />
        public async Task<PairingInitiateResponse> InitiatePairingAsync(
            PairingInitiateRequest request, CancellationToken ct = default)
        {
            return await PostAsync<PairingInitiateResponse>("/v1/pairing/initiate", request, ct)
                .ConfigureAwait(false);
        }

        /// <inheritdoc />
        public async Task<PairingResolveResponse> ResolvePairingAsync(string code, CancellationToken ct = default)
        {
            return await GetAsync<PairingResolveResponse>($"/v1/pairing/resolve/{Uri.EscapeDataString(code)}", ct)
                .ConfigureAwait(false);
        }

        /// <inheritdoc />
        public async Task<PairingStatusResponse> GetPairingStatusAsync(string nonce, CancellationToken ct = default)
        {
            return await GetAsync<PairingStatusResponse>($"/v1/pairing/{Uri.EscapeDataString(nonce)}/status", ct)
                .ConfigureAwait(false);
        }

        /// <inheritdoc />
        public async Task<PairingCompleteResponse> CompletePairingAsync(
            PairingCompleteRequest request, CancellationToken ct = default)
        {
            return await PostAsync<PairingCompleteResponse>("/v1/pairing/complete", request, ct)
                .ConfigureAwait(false);
        }

        /// <inheritdoc />
        public async Task<PairingRevokeResponse> RevokePairingAsync(string routingToken, CancellationToken ct = default)
        {
            var request = new PairingRevokeRequest { RoutingToken = routingToken };
            return await PostAsync<PairingRevokeResponse>("/v1/pairing/revoke", request, ct)
                .ConfigureAwait(false);
        }

        /// <inheritdoc />
        public async Task<PairingStatusBatchResponse> GetPairingStatusBatchAsync(
            List<string> routingTokens, CancellationToken ct = default)
        {
            var request = new PairingStatusBatchRequest { RoutingTokens = routingTokens };
            return await PostAsync<PairingStatusBatchResponse>("/v1/pairing/status-batch", request, ct)
                .ConfigureAwait(false);
        }

        // ── Presence ────────────────────────────────────────────────

        /// <inheritdoc />
        public async Task SendHeartbeatAsync(PresenceHeartbeatRequest request, CancellationToken ct = default)
        {
            await PostAsync("/v1/presence/heartbeat", request, ct).ConfigureAwait(false);
        }

        /// <inheritdoc />
        public async Task<List<EnforcerPresenceRecord>> ListEnforcersAsync(CancellationToken ct = default)
        {
            return await GetAsync<List<EnforcerPresenceRecord>>("/v1/presence/enforcers", ct)
                .ConfigureAwait(false);
        }

        /// <inheritdoc />
        public async Task<EnforcerPresenceRecord> GetEnforcerPresenceAsync(
            string enforcerDeviceId, CancellationToken ct = default)
        {
            return await GetAsync<EnforcerPresenceRecord>(
                $"/v1/presence/enforcers/{Uri.EscapeDataString(enforcerDeviceId)}", ct)
                .ConfigureAwait(false);
        }

        // ── DND (Do Not Disturb) Policies ───────────────────────────

        /// <inheritdoc />
        public async Task SubmitDndPolicyAsync(object policy, CancellationToken ct = default)
        {
            if (policy is null) throw new ArgumentNullException(nameof(policy));
            await PostAsync("/v1/policy/dnd", policy, ct).ConfigureAwait(false);
        }

        /// <inheritdoc />
        public async Task<DndEffectiveResponse> GetEffectiveDndPoliciesAsync(
            string enforcerId,
            string workspaceId,
            string? sessionId = null,
            CancellationToken ct = default)
        {
            if (string.IsNullOrWhiteSpace(enforcerId))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(enforcerId));
            if (string.IsNullOrWhiteSpace(workspaceId))
                throw new ArgumentException("Value cannot be null or whitespace.", nameof(workspaceId));

            var query = System.Web.HttpUtility.ParseQueryString(string.Empty);
            query["enforcerId"] = enforcerId;
            query["workspaceId"] = workspaceId;
            if (!string.IsNullOrWhiteSpace(sessionId))
            {
                query["sessionId"] = sessionId;
            }

            var path = "/v1/policy/dnd/effective";
            var qs = query.ToString();
            if (!string.IsNullOrEmpty(qs))
            {
                path += "?" + qs;
            }

            return await GetAsync<DndEffectiveResponse>(path, ct).ConfigureAwait(false);
        }

        // ── HTTP Helpers ────────────────────────────────────────────

        private async Task<T> GetAsync<T>(string path, CancellationToken ct)
        {
            var response = await _http.GetAsync(path, ct).ConfigureAwait(false);
            var body = await ReadResponseBodyAsync(response).ConfigureAwait(false);
            await EnsureSuccessAsync(response, body).ConfigureAwait(false);

            return JsonSerializer.Deserialize<T>(body, JsonOpts)
                ?? throw new AirlockGatewayException("Response deserialized to null");
        }

        private async Task PostAsync(string path, object? payload, CancellationToken ct)
        {
            HttpContent? content = null;
            if (payload != null)
            {
                var json = JsonSerializer.Serialize(payload, JsonOpts);
                content = new StringContent(json, Encoding.UTF8, "application/json");
            }

            var response = await _http.PostAsync(path, content, ct).ConfigureAwait(false);
            var body = await ReadResponseBodyAsync(response).ConfigureAwait(false);
            await EnsureSuccessAsync(response, body).ConfigureAwait(false);
        }

        private async Task<T> PostAsync<T>(string path, object payload, CancellationToken ct)
        {
            var json = JsonSerializer.Serialize(payload, JsonOpts);
            var content = new StringContent(json, Encoding.UTF8, "application/json");
            var response = await _http.PostAsync(path, content, ct).ConfigureAwait(false);
            var body = await ReadResponseBodyAsync(response).ConfigureAwait(false);
            await EnsureSuccessAsync(response, body).ConfigureAwait(false);

            return JsonSerializer.Deserialize<T>(body, JsonOpts)
                ?? throw new AirlockGatewayException("Response deserialized to null");
        }

        private static async Task<string> ReadResponseBodyAsync(HttpResponseMessage response)
        {
            return await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        }

        private static Task EnsureSuccessAsync(HttpResponseMessage response, string body)
        {
            if (response.IsSuccessStatusCode)
                return Task.CompletedTask;

            // Try to parse error envelope
            string? errorCode = null;
            string? errorMessage = null;
            string? requestId = null;

            try
            {
                using var doc = JsonDocument.Parse(body);
                var root = doc.RootElement;

                // HARP error envelope: { body: { code, message, requestId } }
                if (root.TryGetProperty("body", out var bodyEl))
                {
                    if (bodyEl.TryGetProperty("code", out var code))
                        errorCode = code.GetString();
                    if (bodyEl.TryGetProperty("message", out var msg))
                        errorMessage = msg.GetString();
                    if (bodyEl.TryGetProperty("requestId", out var rid))
                        requestId = rid.GetString();
                }
                // Direct error: { error: "...", message: "..." }
                else
                {
                    if (root.TryGetProperty("error", out var err))
                        errorCode = err.GetString();
                    if (root.TryGetProperty("message", out var msg))
                        errorMessage = msg.GetString();
                }
            }
            catch (JsonException)
            {
                // Not JSON — use raw body
            }

            var message = errorMessage ?? $"Gateway returned {(int)response.StatusCode}";
            throw new AirlockGatewayException(
                message, response.StatusCode, errorCode, body, requestId);
        }
    }
}
