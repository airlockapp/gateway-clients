/**
 * Options for configuring the AirlockAuthClient.
 */
export interface AirlockAuthOptions {
  /**
   * The Keycloak realm URL (e.g., https://auth.airlocks.io/realms/airlock)
   * Used for OIDC discovery and Device Authorization Grant.
   */
  keycloakRealmUrl: string;

  /**
   * The OIDC client ID for device authorization.
   * Default: "airlock-integrations" (the public client configured in Keycloak).
   */
  oidcClientId?: string;

  /**
   * Custom fetch implementation (optional, used for testing or overriding globals).
   */
  fetch?: typeof fetch;
}

export interface OidcDiscoveryResult {
  token_endpoint?: string;
  device_authorization_endpoint?: string;
  revocation_endpoint?: string;
  authorization_endpoint?: string;
}

export interface AuthCodeRequest {
  /** The full authorization URL to redirect the user to. */
  authorizationUrl: string;
  /** CSRF protection state parameter (validate on callback). */
  state: string;
  /** PKCE code_verifier — pass to exchangeCode(). */
  codeVerifier: string;
  /** The redirect URI used in the request. */
  redirectUri: string;
}

export interface DeviceCodeInfo {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  expires_in: number;
  interval: number;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
}

export interface ConsentErrorInfo {
  error: string;
  message?: string;
  consentUrl?: string;
  appName?: string;
  appId?: string;
}

/**
 * Handles user authentication for enforcer apps.
 * Supports two OAuth2 flows:
 * - Device Authorization Grant (RFC 8628) — for headless/CLI apps (Agent, Desktop, VS Code Extension)
 * - Authorization Code + PKCE (RFC 7636) — for browser-capable apps (Web, Mobile)
 */
export class AirlockAuthClient {
  private readonly options: AirlockAuthOptions;
  private readonly fetchFn: typeof fetch;

  private oidcConfig: OidcDiscoveryResult | null = null;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private tokenExpiresAt: number = 0; // Epoch timestamp (ms)

  constructor(options: AirlockAuthOptions) {
    this.options = { ...options, oidcClientId: options.oidcClientId || 'airlock-integrations' };
    this.fetchFn = options.fetch || fetch;
  }

  /** Gets the current access token (may be null if not logged in). */
  get currentAccessToken(): string | null {
    return this.accessToken;
  }

  /** True if the user is currently logged in with a valid token. */
  get isLoggedIn(): boolean {
    return this.accessToken !== null;
  }

  /** True if the access token has expired (refresh needed). */
  get isTokenExpired(): boolean {
    return Date.now() >= this.tokenExpiresAt;
  }

  // ── OIDC Discovery ──────────────────────────────────────────

  /**
   * Discovers OIDC endpoints from Keycloak's well-known configuration.
   * Called automatically by login() if not already done.
   */
  async discover(): Promise<OidcDiscoveryResult> {
    if (this.oidcConfig) return this.oidcConfig;

    const realmUrl = this.options.keycloakRealmUrl.replace(/\/$/, '');
    const wellKnownUrl = `${realmUrl}/.well-known/openid-configuration`;

    const resp = await this.fetchFn(wellKnownUrl);
    if (!resp.ok) {
      throw new Error(`Failed to fetch OIDC discovery document: ${resp.status} ${resp.statusText}`);
    }

    this.oidcConfig = (await resp.json()) as OidcDiscoveryResult;

    if (!this.oidcConfig.token_endpoint) {
      throw new Error('OIDC discovery: token_endpoint is missing.');
    }

    return this.oidcConfig;
  }

  // ── Device Authorization Grant ──────────────────────────────

  /**
   * Start the Device Authorization Grant flow.
   * Returns device code info (user_code, verification_uri) for the user to complete in their browser.
   * Then polls the token endpoint until the user authorizes.
   *
   * @param onUserCode Callback invoked when the user must open a URL and enter a code.
   *                   Display the verification_uri_complete or verification_uri + user_code to the user.
   * @param abortSignal AbortSignal to cancel polling.
   * @returns The token response with access_token and refresh_token.
   */
  async login(
    onUserCode: (info: DeviceCodeInfo) => void,
    abortSignal?: AbortSignal
  ): Promise<TokenResponse> {
    const oidc = await this.discover();

    // Step 1: Request device code
    const deviceBody = new URLSearchParams({
      client_id: this.options.oidcClientId!,
      scope: 'openid profile email',
    });

    const deviceResp = await this.fetchFn(oidc.device_authorization_endpoint!, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: deviceBody.toString(),
      signal: abortSignal,
    });

    if (!deviceResp.ok) {
      throw new Error(`Device authorization request failed: ${deviceResp.status}`);
    }

    const deviceCode = (await deviceResp.json()) as DeviceCodeInfo;

    // Step 2: Notify caller to display the code
    onUserCode(deviceCode);

    // Step 3: Poll token endpoint
    let interval = Math.max(deviceCode.interval || 5, 5);
    const deadline = Date.now() + (deviceCode.expires_in * 1000);

    while (Date.now() < deadline) {
      if (abortSignal?.aborted) {
        throw new Error('Login cancelled by user.');
      }

      await new Promise(resolve => setTimeout(resolve, interval * 1000));

      const tokenBody = new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        client_id: this.options.oidcClientId!,
        device_code: deviceCode.device_code,
      });

      const tokenResp = await this.fetchFn(oidc.token_endpoint!, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: tokenBody.toString(),
        signal: abortSignal,
      });

      const tokenJson = await tokenResp.json();

      if (tokenResp.ok) {
        const token = tokenJson as TokenResponse;
        this.accessToken = token.access_token;
        this.refreshToken = token.refresh_token;
        this.tokenExpiresAt = Date.now() + ((token.expires_in - 30) * 1000);
        return token;
      }

      // Handle expected polling errors
      switch (tokenJson.error) {
        case 'authorization_pending':
          continue; // User hasn't authorized yet, keep polling
        case 'slow_down':
          interval += 5; // Back off
          continue;
        case 'expired_token':
          throw new Error('Device code expired. Please try logging in again.');
        case 'access_denied':
          throw new Error('User denied the authorization request.');
        default:
          throw new Error(`Token request failed: ${tokenJson.error} — ${tokenJson.error_description}`);
      }
    }

    throw new Error('Device code expired before user completed authorization.');
  }

  // ── Authorization Code + PKCE ──────────────────────────────

  /**
   * Start the Authorization Code + PKCE flow.
   * Opens a local HTTP server to receive the callback, then exchanges the code for tokens.
   * Best for Web and Mobile enforcer apps.
   *
   * @param onBrowserUrl Callback invoked with the authorization URL for the user to open.
   * @param redirectPort Local port for the callback listener (default: 0 = auto-select).
   * @param abortSignal AbortSignal to cancel the flow.
   */
  async loginWithAuthCode(
    onBrowserUrl: (url: string) => void,
    redirectPort: number = 0,
    abortSignal?: AbortSignal
  ): Promise<TokenResponse> {
    const oidc = await this.discover();
    if (!oidc.authorization_endpoint) {
      throw new Error('OIDC discovery: authorization_endpoint is missing.');
    }

    const { createServer } = await import('http');
    const { randomBytes, createHash } = await import('crypto');

    // Step 1: Generate PKCE code_verifier + code_challenge
    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
    const state = randomBytes(16).toString('hex');

    // Step 2: Start local HTTP server
    return new Promise<TokenResponse>((resolve, reject) => {
      const server = createServer(async (req, res) => {
        try {
          const url = new URL(req.url || '/', `http://localhost:${redirectPort}`);
          if (url.pathname !== '/callback') {
            res.writeHead(404);
            res.end();
            return;
          }

          const error = url.searchParams.get('error');
          if (error) {
            const desc = url.searchParams.get('error_description') || '';
            this.sendCallbackHtml(res, false, `Authorization failed: ${error}`);
            server.close();
            reject(new Error(`Authorization denied: ${error} — ${desc}`));
            return;
          }

          const returnedState = url.searchParams.get('state');
          if (returnedState !== state) {
            this.sendCallbackHtml(res, false, 'Invalid state parameter.');
            server.close();
            reject(new Error('CSRF state mismatch.'));
            return;
          }

          const code = url.searchParams.get('code');
          if (!code) {
            this.sendCallbackHtml(res, false, 'No authorization code received.');
            server.close();
            reject(new Error('No authorization code received in callback.'));
            return;
          }

          this.sendCallbackHtml(res, true, 'Authorization successful! You can close this tab.');

          const redirectUri = `http://localhost:${(server.address() as any).port}/callback`;
          const token = await this.exchangeCode(code, redirectUri, codeVerifier);
          server.close();
          resolve(token);
        } catch (e) {
          server.close();
          reject(e);
        }
      });

      server.listen(redirectPort, '127.0.0.1', () => {
        const port = (server.address() as any).port;
        const redirectUri = `http://localhost:${port}/callback`;

        const authUrl = `${oidc.authorization_endpoint}` +
          `?response_type=code` +
          `&client_id=${encodeURIComponent(this.options.oidcClientId!)}` +
          `&redirect_uri=${encodeURIComponent(redirectUri)}` +
          `&scope=${encodeURIComponent('openid profile email')}` +
          `&state=${state}` +
          `&code_challenge=${codeChallenge}` +
          `&code_challenge_method=S256`;

        onBrowserUrl(authUrl);
      });

      // Timeout after 5 minutes
      const timeout = setTimeout(() => {
        server.close();
        reject(new Error('Authorization timed out (5 minutes).'));
      }, 5 * 60 * 1000);

      server.on('close', () => clearTimeout(timeout));

      if (abortSignal) {
        abortSignal.addEventListener('abort', () => {
          server.close();
          reject(new Error('Login cancelled by user.'));
        });
      }
    });
  }

  /**
   * Builds the authorization URL for the Auth Code + PKCE flow.
   * Use this when you manage the browser redirect yourself (e.g. in a web app).
   * After the user authorizes, call exchangeCode() with the returned code.
   */
  async getAuthorizationUrl(redirectUri: string): Promise<AuthCodeRequest> {
    const oidc = await this.discover();
    if (!oidc.authorization_endpoint) {
      throw new Error('OIDC discovery: authorization_endpoint is missing.');
    }

    const { randomBytes, createHash } = await import('crypto');
    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
    const state = randomBytes(16).toString('hex');

    const authorizationUrl = `${oidc.authorization_endpoint}` +
      `?response_type=code` +
      `&client_id=${encodeURIComponent(this.options.oidcClientId!)}` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&scope=${encodeURIComponent('openid profile email')}` +
      `&state=${state}` +
      `&code_challenge=${codeChallenge}` +
      `&code_challenge_method=S256`;

    return { authorizationUrl, state, codeVerifier, redirectUri };
  }

  /**
   * Exchange an authorization code for tokens (used with Auth Code + PKCE flow).
   */
  async exchangeCode(code: string, redirectUri: string, codeVerifier: string): Promise<TokenResponse> {
    const oidc = await this.discover();

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.options.oidcClientId!,
      code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    });

    const resp = await this.fetchFn(oidc.token_endpoint!, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    const json = await resp.json();

    if (!resp.ok) {
      throw new Error(`Code exchange failed: ${json.error} — ${json.error_description}`);
    }

    const token = json as TokenResponse;
    this.accessToken = token.access_token;
    this.refreshToken = token.refresh_token;
    this.tokenExpiresAt = Date.now() + ((token.expires_in - 30) * 1000);
    return token;
  }

  private sendCallbackHtml(res: import('http').ServerResponse, success: boolean, message: string): void {
    const color = success ? '#22c55e' : '#ef4444';
    const icon = success ? '✓' : '✗';
    const html = `<!DOCTYPE html><html><body style="font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;background:#0f172a;color:white"><div style="text-align:center"><div style="font-size:3em;color:${color}">${icon}</div><p>${message}</p></div></body></html>`;
    res.writeHead(success ? 200 : 400, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
  }

  // ── Token Refresh ───────────────────────────────────────────

  /**
   * Refresh the access token using the stored refresh token.
   */
  async refreshTokenAsync(): Promise<TokenResponse> {
    if (!this.refreshToken) {
      throw new Error('No refresh token available. Please login first.');
    }

    const oidc = await this.discover();

    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: this.options.oidcClientId!,
      refresh_token: this.refreshToken,
    });

    const resp = await this.fetchFn(oidc.token_endpoint!, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    const json = await resp.json();

    if (!resp.ok) {
      this.accessToken = null;
      this.refreshToken = null;
      throw new Error(`Token refresh failed: ${json.error} — ${json.error_description}`);
    }

    const token = json as TokenResponse;
    this.accessToken = token.access_token;
    this.refreshToken = token.refresh_token;
    this.tokenExpiresAt = Date.now() + ((token.expires_in - 30) * 1000);
    return token;
  }

  // ── Get Valid Token ─────────────────────────────────────────

  /**
   * Gets a valid access token, automatically refreshing if expired.
   * Throws if not logged in.
   */
  async getAccessToken(): Promise<string> {
    if (!this.accessToken) {
      throw new Error('Not logged in. Call login() first.');
    }

    if (this.isTokenExpired && this.refreshToken) {
      await this.refreshTokenAsync();
    }

    if (!this.accessToken) {
      throw new Error('Token refresh failed and no valid token available.');
    }

    return this.accessToken;
  }

  // ── Logout ──────────────────────────────────────────────────

  /**
   * Revoke the refresh token at Keycloak and clear local state.
   */
  async logout(): Promise<void> {
    if (this.refreshToken) {
      try {
        const oidc = await this.discover();
        if (oidc.revocation_endpoint) {
          const body = new URLSearchParams({
            client_id: this.options.oidcClientId!,
            token: this.refreshToken,
            token_type_hint: 'refresh_token',
          });

          await this.fetchFn(oidc.revocation_endpoint, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body.toString(),
          });
        }
      } catch (e) {
        // Best-effort revocation
      }
    }

    this.accessToken = null;
    this.refreshToken = null;
    this.tokenExpiresAt = 0;
  }

  // ── Consent Error Handling ──────────────────────────────────

  /**
   * Parse a consent-related error from a response body or Error object.
   * Returns null if the error is not consent-related.
   */
  static parseConsentError(statusCode: number, responseBody: string): ConsentErrorInfo | null {
    if (statusCode !== 403) return null;

    try {
      const parsed = JSON.parse(responseBody);
      const errCode = parsed.error;
      
      if (
        errCode !== 'app_consent_required' &&
        errCode !== 'app_consent_pending' &&
        errCode !== 'app_consent_denied'
      ) {
        return null;
      }

      return {
        error: errCode,
        message: parsed.message,
        consentUrl: parsed.consentUrl,
        appName: parsed.appName,
        appId: parsed.appId,
      };
    } catch {
      return null;
    }
  }

  // ── State Persistence ───────────────────────────────────────

  /**
   * Restores tokens from previously saved state.
   */
  restoreTokens(accessToken: string, refreshToken: string, expiresAt: number): void {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.tokenExpiresAt = expiresAt;
  }

  /**
   * Gets the current token state for persistence.
   */
  getTokenState(): { accessToken: string | null; refreshToken: string | null; expiresAt: number } {
    return {
      accessToken: this.accessToken,
      refreshToken: this.refreshToken,
      expiresAt: this.tokenExpiresAt,
    };
  }
}
