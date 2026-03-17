using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;
using System.Threading.Tasks;

namespace Airlock.Gateway.Sdk
{
    /// <summary>
    /// Handles user authentication for enforcer apps.
    /// Supports two OAuth2 flows:
    /// <list type="bullet">
    ///   <item>Device Authorization Grant (RFC 8628) — for headless/CLI apps (Agent, Desktop, VS Code Extension)</item>
    ///   <item>Authorization Code + PKCE (RFC 7636) — for browser-capable apps (Web, Mobile)</item>
    /// </list>
    /// </summary>
    public class AirlockAuthClient : IDisposable
    {
        private readonly HttpClient _http;
        private readonly AirlockAuthOptions _options;
        private OidcDiscoveryResult? _oidcConfig;

        private string? _accessToken;
        private string? _refreshToken;
        private DateTimeOffset _tokenExpiresAt;

        private static readonly JsonSerializerOptions JsonOpts = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
        };

        /// <summary>
        /// Creates a new AirlockAuthClient for device authorization.
        /// </summary>
        public AirlockAuthClient(AirlockAuthOptions options, HttpClient? httpClient = null)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
            _http = httpClient ?? new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
        }

        /// <summary>Gets the current access token (may be null if not logged in).</summary>
        public string? AccessToken => _accessToken;

        /// <summary>True if the user is currently logged in with a valid token.</summary>
        public bool IsLoggedIn => _accessToken is not null;

        /// <summary>True if the access token has expired (refresh needed).</summary>
        public bool IsTokenExpired => _tokenExpiresAt <= DateTimeOffset.UtcNow;

        // ── OIDC Discovery ──────────────────────────────────────────

        /// <summary>
        /// Discovers OIDC endpoints from Keycloak's well-known configuration.
        /// Called automatically by <see cref="LoginAsync"/> if not already done.
        /// </summary>
        public async Task<OidcDiscoveryResult> DiscoverAsync(CancellationToken ct = default)
        {
            if (_oidcConfig is not null) return _oidcConfig;

            var wellKnownUrl = $"{_options.KeycloakRealmUrl.TrimEnd('/')}/.well-known/openid-configuration";
            var resp = await _http.GetAsync(wellKnownUrl, ct).ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();

            var json = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            _oidcConfig = JsonSerializer.Deserialize<OidcDiscoveryResult>(json, JsonOpts)
                ?? throw new InvalidOperationException("Failed to parse OIDC discovery document.");

            if (string.IsNullOrEmpty(_oidcConfig.TokenEndpoint))
                throw new InvalidOperationException("OIDC discovery: token_endpoint is missing.");

            return _oidcConfig;
        }

        // ── Device Authorization Grant ──────────────────────────────

        /// <summary>
        /// Start the Device Authorization Grant flow.
        /// Returns device code info (user_code, verification_uri) for the user to complete in their browser.
        /// Then polls the token endpoint until the user authorizes.
        /// </summary>
        /// <param name="onUserCode">
        /// Callback invoked when the user must open a URL and enter a code.
        /// Display the <see cref="DeviceCodeInfo.VerificationUriComplete"/> or
        /// <see cref="DeviceCodeInfo.VerificationUri"/> + <see cref="DeviceCodeInfo.UserCode"/> to the user.
        /// </param>
        /// <param name="ct">Cancellation token.</param>
        /// <returns>The token response with access_token and refresh_token.</returns>
        public async Task<TokenResponse> LoginAsync(
            Action<DeviceCodeInfo> onUserCode,
            CancellationToken ct = default)
        {
            var oidc = await DiscoverAsync(ct).ConfigureAwait(false);

            // Step 1: Request device code
            var deviceResp = await _http.PostAsync(
                oidc.DeviceAuthorizationEndpoint,
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["client_id"] = _options.OidcClientId,
                    ["scope"] = "openid profile email",
                }),
                ct).ConfigureAwait(false);

            deviceResp.EnsureSuccessStatusCode();
            var deviceJson = await deviceResp.Content.ReadAsStringAsync().ConfigureAwait(false);
            var deviceCode = JsonSerializer.Deserialize<DeviceCodeInfo>(deviceJson, JsonOpts)
                ?? throw new InvalidOperationException("Failed to parse device code response.");

            // Step 2: Notify caller to display the code
            onUserCode(deviceCode);

            // Step 3: Poll token endpoint
            var interval = Math.Max(deviceCode.Interval, 5);
            var deadline = DateTimeOffset.UtcNow.AddSeconds(deviceCode.ExpiresIn);

            while (DateTimeOffset.UtcNow < deadline)
            {
                ct.ThrowIfCancellationRequested();
                await Task.Delay(TimeSpan.FromSeconds(interval), ct).ConfigureAwait(false);

                var tokenResp = await _http.PostAsync(
                    oidc.TokenEndpoint,
                    new FormUrlEncodedContent(new Dictionary<string, string>
                    {
                        ["grant_type"] = "urn:ietf:params:oauth:grant-type:device_code",
                        ["client_id"] = _options.OidcClientId,
                        ["device_code"] = deviceCode.DeviceCode!,
                    }),
                    ct).ConfigureAwait(false);

                var tokenJson = await tokenResp.Content.ReadAsStringAsync().ConfigureAwait(false);

                if (tokenResp.IsSuccessStatusCode)
                {
                    var token = JsonSerializer.Deserialize<TokenResponse>(tokenJson, JsonOpts)
                        ?? throw new InvalidOperationException("Failed to parse token response.");

                    _accessToken = token.AccessToken;
                    _refreshToken = token.RefreshToken;
                    _tokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(token.ExpiresIn - 30);
                    return token;
                }

                // Check for expected polling errors
                var error = JsonSerializer.Deserialize<TokenErrorResponse>(tokenJson, JsonOpts);
                switch (error?.Error)
                {
                    case "authorization_pending":
                        continue; // User hasn't authorized yet, keep polling
                    case "slow_down":
                        interval += 5; // Back off
                        continue;
                    case "expired_token":
                        throw new AirlockAuthException("Device code expired. Please try logging in again.");
                    case "access_denied":
                        throw new AirlockAuthException("User denied the authorization request.");
                    default:
                        throw new AirlockAuthException(
                            $"Token request failed: {error?.Error} — {error?.ErrorDescription}");
                }
            }

            throw new AirlockAuthException("Device code expired before user completed authorization.");
        }

        // ── Authorization Code + PKCE ───────────────────────────────

        /// <summary>
        /// Start the Authorization Code + PKCE flow.
        /// Opens a browser for the user to authenticate, then receives the callback
        /// on a local HTTP listener. Best for Web and Mobile enforcer apps.
        /// </summary>
        /// <param name="redirectPort">Local port for the callback listener (default: 0 = auto-select).</param>
        /// <param name="onBrowserUrl">Callback invoked with the authorization URL for the user to open.</param>
        /// <param name="ct">Cancellation token.</param>
        /// <returns>The token response with access_token and refresh_token.</returns>
        public async Task<TokenResponse> LoginWithAuthCodeAsync(
            Action<string> onBrowserUrl,
            int redirectPort = 0,
            CancellationToken ct = default)
        {
            var oidc = await DiscoverAsync(ct).ConfigureAwait(false);
            if (string.IsNullOrEmpty(oidc.AuthorizationEndpoint))
                throw new InvalidOperationException("OIDC discovery: authorization_endpoint is missing.");

            // Step 1: Generate PKCE code_verifier + code_challenge
            var codeVerifier = GenerateCodeVerifier();
            var codeChallenge = ComputeCodeChallenge(codeVerifier);
            var state = Guid.NewGuid().ToString("N");

            // Step 2: Start local HTTP listener for the redirect callback
            if (redirectPort == 0) redirectPort = GetAvailablePort();
            var redirectUri = $"http://localhost:{redirectPort}/callback";
            var listener = new HttpListener();
            listener.Prefixes.Add($"http://localhost:{redirectPort}/");
            listener.Start();

            try
            {
                // Step 3: Build authorization URL
                var authUrl = $"{oidc.AuthorizationEndpoint}" +
                    $"?response_type=code" +
                    $"&client_id={Uri.EscapeDataString(_options.OidcClientId)}" +
                    $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                    $"&scope={Uri.EscapeDataString("openid profile email")}" +
                    $"&state={state}" +
                    $"&code_challenge={codeChallenge}" +
                    $"&code_challenge_method=S256";

                onBrowserUrl(authUrl);

                // Step 4: Wait for the callback
                var contextTask = listener.GetContextAsync();
                var completedTask = await Task.WhenAny(
                    contextTask,
                    Task.Delay(TimeSpan.FromMinutes(5), ct)
                ).ConfigureAwait(false);

                if (completedTask != contextTask)
                    throw new AirlockAuthException("Authorization timed out (5 minutes).");

                var httpContext = await contextTask.ConfigureAwait(false);
                var query = httpContext.Request.QueryString;

                // Check for errors
                var error = query["error"];
                if (!string.IsNullOrEmpty(error))
                {
                    var desc = query["error_description"] ?? "";
                    SendCallbackResponse(httpContext, false, $"Authorization failed: {error}");
                    throw new AirlockAuthException($"Authorization denied: {error} — {desc}");
                }

                // Validate state
                var returnedState = query["state"];
                if (returnedState != state)
                {
                    SendCallbackResponse(httpContext, false, "Invalid state parameter.");
                    throw new AirlockAuthException("CSRF state mismatch. Authorization may have been tampered with.");
                }

                var code = query["code"]
                    ?? throw new AirlockAuthException("No authorization code received in callback.");

                SendCallbackResponse(httpContext, true, "Authorization successful! You can close this tab.");

                // Step 5: Exchange code for tokens
                return await ExchangeCodeAsync(code, redirectUri, codeVerifier, ct).ConfigureAwait(false);
            }
            finally
            {
                listener.Stop();
                listener.Close();
            }
        }

        /// <summary>
        /// Builds the authorization URL for the Auth Code + PKCE flow.
        /// Use this when you manage the browser redirect yourself (e.g. in a web app).
        /// After the user authorizes, call <see cref="ExchangeCodeAsync"/> with the returned code.
        /// </summary>
        public async Task<AuthCodeRequest> GetAuthorizationUrlAsync(
            string redirectUri,
            CancellationToken ct = default)
        {
            var oidc = await DiscoverAsync(ct).ConfigureAwait(false);
            if (string.IsNullOrEmpty(oidc.AuthorizationEndpoint))
                throw new InvalidOperationException("OIDC discovery: authorization_endpoint is missing.");

            var codeVerifier = GenerateCodeVerifier();
            var codeChallenge = ComputeCodeChallenge(codeVerifier);
            var state = Guid.NewGuid().ToString("N");

            var authUrl = $"{oidc.AuthorizationEndpoint}" +
                $"?response_type=code" +
                $"&client_id={Uri.EscapeDataString(_options.OidcClientId)}" +
                $"&redirect_uri={Uri.EscapeDataString(redirectUri)}" +
                $"&scope={Uri.EscapeDataString("openid profile email")}" +
                $"&state={state}" +
                $"&code_challenge={codeChallenge}" +
                $"&code_challenge_method=S256";

            return new AuthCodeRequest
            {
                AuthorizationUrl = authUrl,
                State = state,
                CodeVerifier = codeVerifier,
                RedirectUri = redirectUri,
            };
        }

        /// <summary>
        /// Exchange an authorization code for tokens (used with Auth Code + PKCE flow).
        /// </summary>
        public async Task<TokenResponse> ExchangeCodeAsync(
            string code, string redirectUri, string codeVerifier,
            CancellationToken ct = default)
        {
            var oidc = await DiscoverAsync(ct).ConfigureAwait(false);

            var resp = await _http.PostAsync(
                oidc.TokenEndpoint,
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "authorization_code",
                    ["client_id"] = _options.OidcClientId,
                    ["code"] = code,
                    ["redirect_uri"] = redirectUri,
                    ["code_verifier"] = codeVerifier,
                }),
                ct).ConfigureAwait(false);

            var json = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (!resp.IsSuccessStatusCode)
            {
                var error = JsonSerializer.Deserialize<TokenErrorResponse>(json, JsonOpts);
                throw new AirlockAuthException(
                    $"Code exchange failed: {error?.Error} — {error?.ErrorDescription}");
            }

            var token = JsonSerializer.Deserialize<TokenResponse>(json, JsonOpts)
                ?? throw new InvalidOperationException("Failed to parse token response.");

            _accessToken = token.AccessToken;
            _refreshToken = token.RefreshToken;
            _tokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(token.ExpiresIn - 30);
            return token;
        }

        // ── PKCE Helpers ────────────────────────────────────────────

        private static string GenerateCodeVerifier()
        {
            var bytes = new byte[32];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(bytes);
            return Base64UrlEncode(bytes);
        }

        private static string ComputeCodeChallenge(string codeVerifier)
        {
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(Encoding.ASCII.GetBytes(codeVerifier));
            return Base64UrlEncode(hash);
        }

        private static string Base64UrlEncode(byte[] data)
            => Convert.ToBase64String(data)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');

        private static int GetAvailablePort()
        {
            var listener = new System.Net.Sockets.TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            var port = ((IPEndPoint)listener.LocalEndpoint).Port;
            listener.Stop();
            return port;
        }

        private static void SendCallbackResponse(HttpListenerContext ctx, bool success, string message)
        {
            var color = success ? "#22c55e" : "#ef4444";
            var icon = success ? "✓" : "✗";
            var html = $"""<!DOCTYPE html><html><body style="font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#0f172a;color:white"><div style="text-align:center"><div style="font-size:3em;color:{color}">{icon}</div><p>{message}</p></div></body></html>""";
            var buffer = Encoding.UTF8.GetBytes(html);
            ctx.Response.ContentType = "text/html; charset=utf-8";
            ctx.Response.StatusCode = success ? 200 : 400;
            ctx.Response.ContentLength64 = buffer.Length;
            ctx.Response.OutputStream.Write(buffer, 0, buffer.Length);
            ctx.Response.Close();
        }

        // ── Token Refresh ───────────────────────────────────────────

        /// <summary>
        /// Refresh the access token using the stored refresh token.
        /// </summary>
        public async Task<TokenResponse> RefreshTokenAsync(CancellationToken ct = default)
        {
            if (string.IsNullOrEmpty(_refreshToken))
                throw new AirlockAuthException("No refresh token available. Please login first.");

            var oidc = await DiscoverAsync(ct).ConfigureAwait(false);

            var resp = await _http.PostAsync(
                oidc.TokenEndpoint,
                new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["grant_type"] = "refresh_token",
                    ["client_id"] = _options.OidcClientId,
                    ["refresh_token"] = _refreshToken,
                }),
                ct).ConfigureAwait(false);

            var json = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);

            if (!resp.IsSuccessStatusCode)
            {
                var error = JsonSerializer.Deserialize<TokenErrorResponse>(json, JsonOpts);
                _accessToken = null;
                _refreshToken = null;
                throw new AirlockAuthException(
                    $"Token refresh failed: {error?.Error} — {error?.ErrorDescription}");
            }

            var token = JsonSerializer.Deserialize<TokenResponse>(json, JsonOpts)
                ?? throw new InvalidOperationException("Failed to parse token response.");

            _accessToken = token.AccessToken;
            _refreshToken = token.RefreshToken;
            _tokenExpiresAt = DateTimeOffset.UtcNow.AddSeconds(token.ExpiresIn - 30);
            return token;
        }

        // ── Get Valid Token ─────────────────────────────────────────

        /// <summary>
        /// Gets a valid access token, automatically refreshing if expired.
        /// Throws if not logged in.
        /// </summary>
        public async Task<string> GetAccessTokenAsync(CancellationToken ct = default)
        {
            if (_accessToken is null)
                throw new AirlockAuthException("Not logged in. Call LoginAsync first.");

            if (IsTokenExpired && _refreshToken is not null)
                await RefreshTokenAsync(ct).ConfigureAwait(false);

            return _accessToken
                ?? throw new AirlockAuthException("Token refresh failed and no valid token available.");
        }

        // ── Logout ──────────────────────────────────────────────────

        /// <summary>
        /// Revoke the refresh token at Keycloak and clear local state.
        /// </summary>
        public async Task LogoutAsync(CancellationToken ct = default)
        {
            if (_refreshToken is not null)
            {
                try
                {
                    var oidc = await DiscoverAsync(ct).ConfigureAwait(false);
                    if (!string.IsNullOrEmpty(oidc.RevocationEndpoint))
                    {
                        await _http.PostAsync(
                            oidc.RevocationEndpoint,
                            new FormUrlEncodedContent(new Dictionary<string, string>
                            {
                                ["client_id"] = _options.OidcClientId,
                                ["token"] = _refreshToken,
                                ["token_type_hint"] = "refresh_token",
                            }),
                            ct).ConfigureAwait(false);
                    }
                }
                catch
                {
                    // Best-effort revocation
                }
            }

            _accessToken = null;
            _refreshToken = null;
            _tokenExpiresAt = default;
        }

        // ── Consent Error Handling ──────────────────────────────────

        /// <summary>
        /// Parse a consent-related error from the gateway response.
        /// Returns null if the error is not consent-related.
        /// </summary>
        public static ConsentErrorInfo? ParseConsentError(
            int statusCode, string responseBody)
        {
            if (statusCode != 403) return null;

            try
            {
                using var doc = JsonDocument.Parse(responseBody);
                var root = doc.RootElement;
                if (!root.TryGetProperty("error", out var errorEl)) return null;

                var error = errorEl.GetString();
                if (error is not "app_consent_required" and not "app_consent_pending"
                    and not "app_consent_denied")
                    return null;

                return new ConsentErrorInfo
                {
                    Error = error,
                    Message = root.TryGetProperty("message", out var msg) ? msg.GetString() : null,
                    ConsentUrl = root.TryGetProperty("consentUrl", out var url) ? url.GetString() : null,
                    AppName = root.TryGetProperty("appName", out var name) ? name.GetString() : null,
                    AppId = root.TryGetProperty("appId", out var id) ? id.GetString() : null,
                };
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Restores tokens from previously saved state (e.g. loaded from disk).
        /// </summary>
        public void RestoreTokens(string accessToken, string refreshToken, DateTimeOffset expiresAt)
        {
            _accessToken = accessToken;
            _refreshToken = refreshToken;
            _tokenExpiresAt = expiresAt;
        }

        /// <summary>
        /// Gets the current token state for persistence.
        /// </summary>
        public (string? AccessToken, string? RefreshToken, DateTimeOffset ExpiresAt) GetTokenState()
            => (_accessToken, _refreshToken, _tokenExpiresAt);

        public void Dispose()
        {
            _http.Dispose();
            GC.SuppressFinalize(this);
        }
    }

    // ── Options ──────────────────────────────────────────────────

    /// <summary>Configuration for AirlockAuthClient.</summary>
    public class AirlockAuthOptions
    {
        /// <summary>
        /// The Keycloak realm URL, e.g. "https://auth.airlocks.io/realms/airlock".
        /// Used for OIDC discovery and Device Authorization Grant.
        /// </summary>
        public string KeycloakRealmUrl { get; set; } = string.Empty;

        /// <summary>
        /// The OIDC client ID for device authorization.
        /// Default: "airlock-integrations" (the public client configured in Keycloak).
        /// </summary>
        public string OidcClientId { get; set; } = "airlock-integrations";
    }

    // ── Models ───────────────────────────────────────────────────

    /// <summary>OIDC discovery document (subset).</summary>
    public class OidcDiscoveryResult
    {
        [JsonPropertyName("token_endpoint")]
        public string? TokenEndpoint { get; set; }

        [JsonPropertyName("device_authorization_endpoint")]
        public string? DeviceAuthorizationEndpoint { get; set; }

        [JsonPropertyName("revocation_endpoint")]
        public string? RevocationEndpoint { get; set; }

        [JsonPropertyName("authorization_endpoint")]
        public string? AuthorizationEndpoint { get; set; }
    }

    /// <summary>
    /// Returned by <see cref="AirlockAuthClient.GetAuthorizationUrlAsync"/> for apps
    /// that manage the browser redirect themselves (e.g. web apps).
    /// </summary>
    public class AuthCodeRequest
    {
        /// <summary>The full authorization URL to redirect the user to.</summary>
        public string AuthorizationUrl { get; set; } = string.Empty;

        /// <summary>CSRF protection state parameter (validate on callback).</summary>
        public string State { get; set; } = string.Empty;

        /// <summary>PKCE code_verifier — pass to <see cref="AirlockAuthClient.ExchangeCodeAsync"/>.</summary>
        public string CodeVerifier { get; set; } = string.Empty;

        /// <summary>The redirect URI used in the request.</summary>
        public string RedirectUri { get; set; } = string.Empty;
    }

    /// <summary>Device code response from the authorization server.</summary>
    public class DeviceCodeInfo
    {
        [JsonPropertyName("device_code")]
        public string? DeviceCode { get; set; }

        [JsonPropertyName("user_code")]
        public string? UserCode { get; set; }

        [JsonPropertyName("verification_uri")]
        public string? VerificationUri { get; set; }

        [JsonPropertyName("verification_uri_complete")]
        public string? VerificationUriComplete { get; set; }

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; } = 600;

        [JsonPropertyName("interval")]
        public int Interval { get; set; } = 5;
    }

    /// <summary>OAuth2 token response.</summary>
    public class TokenResponse
    {
        [JsonPropertyName("access_token")]
        public string? AccessToken { get; set; }

        [JsonPropertyName("refresh_token")]
        public string? RefreshToken { get; set; }

        [JsonPropertyName("token_type")]
        public string? TokenType { get; set; }

        [JsonPropertyName("expires_in")]
        public int ExpiresIn { get; set; }

        [JsonPropertyName("scope")]
        public string? Scope { get; set; }
    }

    /// <summary>OAuth2 token error response.</summary>
    public class TokenErrorResponse
    {
        [JsonPropertyName("error")]
        public string? Error { get; set; }

        [JsonPropertyName("error_description")]
        public string? ErrorDescription { get; set; }
    }

    /// <summary>Parsed consent error from the gateway.</summary>
    public class ConsentErrorInfo
    {
        /// <summary>Error code: app_consent_required, app_consent_pending, or app_consent_denied.</summary>
        public string? Error { get; set; }
        public string? Message { get; set; }
        public string? ConsentUrl { get; set; }
        public string? AppName { get; set; }
        public string? AppId { get; set; }
    }

    /// <summary>Exception thrown by AirlockAuthClient for authentication errors.</summary>
    public class AirlockAuthException : Exception
    {
        public AirlockAuthException(string message) : base(message) { }
        public AirlockAuthException(string message, Exception inner) : base(message, inner) { }
    }
}
