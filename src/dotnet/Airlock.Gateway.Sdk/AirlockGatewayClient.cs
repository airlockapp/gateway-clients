using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Airlock.Gateway.Sdk.Crypto;
using Airlock.Gateway.Sdk.Models;

namespace Airlock.Gateway.Sdk
{
    /// <summary>
    /// HTTP client for the Airlock Integrations Gateway API.
    /// Supports PAT (recommended), Bearer token, and ClientId/ClientSecret authentication.
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
        /// Creates a new AirlockGatewayClient with a pre-configured HttpClient.
        /// The HttpClient should be configured with BaseAddress and auth headers.
        /// </summary>
        public AirlockGatewayClient(HttpClient httpClient)
        {
            _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        }

        /// <summary>
        /// Creates a new AirlockGatewayClient with Bearer token authentication.
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

        /// <summary>
        /// Creates a new AirlockGatewayClient with enforcer app (ClientId/ClientSecret) authentication.
        /// Used for third-party enforcer apps registered through the Developer Programme.
        /// </summary>
        /// <param name="baseUrl">Integrations Gateway URL (e.g., https://igw.airlocks.io)</param>
        /// <param name="clientId">The enforcer app's Client ID (X-Client-Id header)</param>
        /// <param name="clientSecret">The enforcer app's Client Secret (X-Client-Secret header)</param>
        public AirlockGatewayClient(string baseUrl, string clientId, string clientSecret)
        {
            if (string.IsNullOrWhiteSpace(clientId))
                throw new ArgumentException("Client ID is required.", nameof(clientId));
            if (string.IsNullOrWhiteSpace(clientSecret))
                throw new ArgumentException("Client Secret is required.", nameof(clientSecret));

            _http = new HttpClient
            {
                BaseAddress = new Uri(baseUrl.TrimEnd('/')),
                Timeout = TimeSpan.FromSeconds(90)
            };
            _http.DefaultRequestHeaders.Add("X-Client-Id", clientId);
            _http.DefaultRequestHeaders.Add("X-Client-Secret", clientSecret);
        }

        /// <summary>
        /// Sets (or clears) the user Bearer token on this client.
        /// This allows dual-auth scenarios where both client credentials and user bearer token
        /// are sent on every request (e.g., enforcer app acting on behalf of a logged-in user).
        /// </summary>
        public void SetBearerToken(string? bearerToken)
        {
            _http.DefaultRequestHeaders.Authorization = string.IsNullOrEmpty(bearerToken)
                ? null
                : new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", bearerToken);
        }

        /// <summary>
        /// Sets (or clears) the Personal Access Token (PAT) on this client.
        /// PAT is the recommended user identity mechanism — it replaces the Bearer token.
        /// Sends the X-PAT header on all requests.
        /// </summary>
        public void SetPat(string? pat)
        {
            // Remove existing X-PAT header if present
            _http.DefaultRequestHeaders.Remove("X-PAT");
            if (!string.IsNullOrEmpty(pat))
            {
                _http.DefaultRequestHeaders.Add("X-PAT", pat);
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

        // ── Pairing ─────────────────────────────────────────────────

        /// <inheritdoc />
        public async Task<PairingInitiateResponse> InitiatePairingAsync(
            PairingInitiateRequest request, CancellationToken ct = default)
        {
            return await PostAsync<PairingInitiateResponse>("/v1/pairing/initiate", request, ct)
                .ConfigureAwait(false);
        }

        /// <inheritdoc />
        public async Task<PairingStatusResponse> GetPairingStatusAsync(string nonce, CancellationToken ct = default)
        {
            return await GetAsync<PairingStatusResponse>($"/v1/pairing/{Uri.EscapeDataString(nonce)}/status", ct)
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
        public async Task<PairingClaimResponse> ClaimPairingAsync(
            PairingClaimRequest request, CancellationToken ct = default)
        {
            return await PostAsync<PairingClaimResponse>("/v1/pairing/claim", request, ct)
                .ConfigureAwait(false);
        }

        // ── Presence ────────────────────────────────────────────────

        /// <inheritdoc />
        public async Task SendHeartbeatAsync(PresenceHeartbeatRequest request, CancellationToken ct = default)
        {
            await PostAsync("/v1/presence/heartbeat", request, ct).ConfigureAwait(false);
        }

        // ── DND (Do Not Disturb) Policies ───────────────────────────

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

        /// <inheritdoc />
        public async Task<string> CheckConsentAsync(CancellationToken ct = default)
        {
            var response = await _http.GetAsync("/v1/consent/status", ct).ConfigureAwait(false);
            var body = await ReadResponseBodyAsync(response).ConfigureAwait(false);
            await EnsureSuccessAsync(response, body);

            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("status", out var s)
                ? s.GetString() ?? "unknown"
                : "unknown";
        }

        // ── Transparent Encryption ──────────────────────────────────

        /// <inheritdoc />
        public async Task<string> EncryptAndSubmitArtifactAsync(
            EncryptedArtifactRequest request, CancellationToken ct = default)
        {
            if (string.IsNullOrEmpty(request.PlaintextPayload))
                throw new ArgumentException("PlaintextPayload is required.", nameof(request));
            if (string.IsNullOrEmpty(request.EncryptionKeyBase64Url))
                throw new ArgumentException("EncryptionKeyBase64Url is required.", nameof(request));

            // 1. Canonicalize the plaintext JSON (RFC 8785 JCS)
            var canonical = CanonicalJson.Canonicalize(request.PlaintextPayload);

            // 2. Hash the canonical form (SHA-256)
            var artifactHash = CryptoHelpers.Sha256Hex(canonical);

            // 3. Encrypt with AES-256-GCM
            var ciphertext = CryptoHelpers.AesGcmEncrypt(request.EncryptionKeyBase64Url, canonical);

            // 4. Submit via the existing method
            var submitRequest = new ArtifactSubmitRequest
            {
                EnforcerId = request.EnforcerId,
                ArtifactType = request.ArtifactType,
                ArtifactHash = artifactHash,
                Ciphertext = ciphertext,
                ExpiresAt = request.ExpiresAt,
                Metadata = request.Metadata,
                RequestId = request.RequestId
            };

            return await SubmitArtifactAsync(submitRequest, ct).ConfigureAwait(false);
        }

        /// <inheritdoc />
        public DecisionVerificationResult VerifyDecision(
            DecisionDeliverEnvelope decision,
            string expectedArtifactHash,
            string signerPublicKeyBase64Url)
        {
            var body = decision.Body;
            if (body == null)
                return DecisionVerificationResult.Failure("Decision body is null.");

            // 1. Check artifact binding
            if (!string.Equals(body.ArtifactHash, expectedArtifactHash, StringComparison.OrdinalIgnoreCase))
                return DecisionVerificationResult.Failure(
                    $"Artifact hash mismatch: expected '{expectedArtifactHash}', got '{body.ArtifactHash}'.");

            // 2. Verify Ed25519 signature if present
            if (!string.IsNullOrEmpty(body.Signature) && !string.IsNullOrEmpty(body.DecisionHash))
            {
                // Build the signable payload: canonical JSON of the decision fields (excluding signature)
                var signable = new
                {
                    requestId = decision.RequestId,
                    artifactHash = body.ArtifactHash,
                    decision = body.Decision,
                    reason = body.Reason,
                    nonce = body.Nonce,
                    signerKeyId = body.SignerKeyId
                };

                var canonicalSignable = CanonicalJson.Serialize(signable);
                var signableBytes = Encoding.UTF8.GetBytes(canonicalSignable);

                var valid = CryptoHelpers.Ed25519Verify(
                    signerPublicKeyBase64Url, signableBytes, body.Signature);

                if (!valid)
                    return DecisionVerificationResult.Failure("Ed25519 signature verification failed.");
            }

            return DecisionVerificationResult.Success(body.Decision);
        }
    }
}
