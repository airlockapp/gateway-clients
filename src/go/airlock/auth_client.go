package airlock

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AirlockAuthOptions configures the AirlockAuthClient.
type AirlockAuthOptions struct {
	// KeycloakRealmURL is the base URL of the realm (e.g. "https://auth.airlocks.io/realms/airlock").
	KeycloakRealmURL string
	// OIDCClientID is the client ID for device authorization. Defaults to "airlock-integrations".
	OIDCClientID string
	// HTTPClient is an optional custom HTTP client.
	HTTPClient *http.Client
}

// AirlockAuthClient handles user authentication via Device Authorization Grant (RFC 8628)
// and Authorization Code + PKCE (RFC 7636).
type AirlockAuthClient struct {
	Options AirlockAuthOptions

	httpClient     *http.Client
	oidcConfig     *OidcDiscoveryResult
	accessToken    string
	refreshToken   string
	tokenExpiresAt time.Time
}

// NewAirlockAuthClient creates a new AirlockAuthClient.
func NewAirlockAuthClient(opts AirlockAuthOptions) *AirlockAuthClient {
	if opts.OIDCClientID == "" {
		opts.OIDCClientID = "airlock-integrations"
	}
	hc := opts.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &AirlockAuthClient{
		Options:    opts,
		httpClient: hc,
	}
}

// CurrentAccessToken returns the cached access token, or empty if none.
func (c *AirlockAuthClient) CurrentAccessToken() string {
	return c.accessToken
}

// IsLoggedIn returns true if we have a token.
func (c *AirlockAuthClient) IsLoggedIn() bool {
	return c.accessToken != ""
}

// IsTokenExpired returns true if the token is expired and needs refresh.
func (c *AirlockAuthClient) IsTokenExpired() bool {
	return time.Now().UTC().After(c.tokenExpiresAt)
}

// Discover fetches the OIDC discovery document from Keycloak.
func (c *AirlockAuthClient) Discover(ctx context.Context) (*OidcDiscoveryResult, error) {
	if c.oidcConfig != nil {
		return c.oidcConfig, nil
	}

	wellKnown := strings.TrimRight(c.Options.KeycloakRealmURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch OIDC discovery document: status %d", resp.StatusCode)
	}

	var res OidcDiscoveryResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}

	if res.TokenEndpoint == "" {
		return nil, errors.New("OIDC discovery: token_endpoint is missing")
	}

	c.oidcConfig = &res
	return &res, nil
}

// Login starts the Device Authorization Grant flow.
// It calls onUserCode so the user can be prompted to open the verification URI and enter code.
// It polls the token endpoint until the user grants access or it times out.
func (c *AirlockAuthClient) Login(ctx context.Context, onUserCode func(*DeviceCodeInfo)) (*TokenResponse, error) {
	oidc, err := c.Discover(ctx)
	if err != nil {
		return nil, err
	}

	// Step 1: Request device code
	data := url.Values{}
	data.Set("client_id", c.Options.OIDCClientID)
	data.Set("scope", "openid profile email")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oidc.DeviceAuthorizationEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("device authorization failed: status %d - %s", resp.StatusCode, string(body))
	}

	var deviceCode DeviceCodeInfo
	if err := json.NewDecoder(resp.Body).Decode(&deviceCode); err != nil {
		return nil, err
	}

	// Step 2: Notify caller
	onUserCode(&deviceCode)

	// Step 3: Poll token endpoint
	interval := deviceCode.Interval
	if interval < 5 {
		interval = 5
	}
	deadline := time.Now().UTC().Add(time.Duration(deviceCode.ExpiresIn) * time.Second)

	for time.Now().UTC().Before(deadline) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(time.Duration(interval) * time.Second):
		}

		tData := url.Values{}
		tData.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		tData.Set("client_id", c.Options.OIDCClientID)
		tData.Set("device_code", deviceCode.DeviceCode)

		tReq, err := http.NewRequestWithContext(ctx, http.MethodPost, oidc.TokenEndpoint, strings.NewReader(tData.Encode()))
		if err != nil {
			return nil, err
		}
		tReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		tResp, err := c.httpClient.Do(tReq)
		if err != nil {
			return nil, err
		}

		body, _ := io.ReadAll(tResp.Body)
		tResp.Body.Close()

		if tResp.StatusCode == http.StatusOK {
			var token TokenResponse
			if err := json.Unmarshal(body, &token); err != nil {
				return nil, err
			}
			c.accessToken = token.AccessToken
			c.refreshToken = token.RefreshToken
			c.tokenExpiresAt = time.Now().UTC().Add(time.Duration(token.ExpiresIn-30) * time.Second)
			return &token, nil
		}

		// Handle expected polling errors
		var tErr TokenErrorResponse
		if err := json.Unmarshal(body, &tErr); err != nil {
			return nil, fmt.Errorf("token request failed: status %d - %s", tResp.StatusCode, string(body))
		}

		switch tErr.Error {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += 5
			continue
		case "expired_token":
			return nil, errors.New("device code expired")
		case "access_denied":
			return nil, errors.New("user denied authorization request")
		default:
			return nil, fmt.Errorf("token request failed: %s - %s", tErr.Error, tErr.ErrorDescription)
		}
	}

	return nil, errors.New("device code expired before user completed authorization")
}

// AuthCodeRequest holds the authorization URL and PKCE verifier for apps
// that manage the browser redirect themselves.
type AuthCodeRequest struct {
	AuthorizationURL string
	State            string
	CodeVerifier     string
	RedirectURI      string
}

// LoginWithAuthCode starts the Authorization Code + PKCE flow.
// It starts a local HTTP server to receive the callback and exchanges the code for tokens.
// Best for Web and Mobile enforcer apps.
func (c *AirlockAuthClient) LoginWithAuthCode(ctx context.Context, onBrowserURL func(string), redirectPort int) (*TokenResponse, error) {
	oidc, err := c.Discover(ctx)
	if err != nil {
		return nil, err
	}

	if oidc.AuthorizationEndpoint == "" {
		return nil, errors.New("OIDC discovery: authorization_endpoint is missing")
	}

	// Step 1: Generate PKCE code_verifier + code_challenge
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("generate code verifier: %w", err)
	}
	codeChallenge := computeCodeChallenge(codeVerifier)
	state := generateState()

	// Step 2: Start local HTTP server
	var listener net.Listener
	if redirectPort == 0 {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
	} else {
		listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", redirectPort))
	}
	if err != nil {
		return nil, fmt.Errorf("start callback listener: %w", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://localhost:%d/callback", port)

	// Build authorization URL
	authURL := fmt.Sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s&code_challenge=%s&code_challenge_method=S256",
		oidc.AuthorizationEndpoint,
		url.QueryEscape(c.Options.OIDCClientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape("openid profile email"),
		state,
		codeChallenge,
	)

	onBrowserURL(authURL)

	// Step 3: Wait for callback
	type callbackResult struct {
		Code  string
		Error string
	}

	resultCh := make(chan callbackResult, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		if errCode := q.Get("error"); errCode != "" {
			w.WriteHeader(400)
			fmt.Fprintf(w, "Authorization failed: %s", errCode)
			resultCh <- callbackResult{Error: fmt.Sprintf("%s: %s", errCode, q.Get("error_description"))}
			return
		}

		if q.Get("state") != state {
			w.WriteHeader(400)
			fmt.Fprint(w, "Invalid state parameter.")
			resultCh <- callbackResult{Error: "CSRF state mismatch"}
			return
		}

		code := q.Get("code")
		if code == "" {
			w.WriteHeader(400)
			fmt.Fprint(w, "No authorization code received.")
			resultCh <- callbackResult{Error: "no authorization code"}
			return
		}

		w.WriteHeader(200)
		fmt.Fprint(w, "Authorization successful! You can close this tab.")
		resultCh <- callbackResult{Code: code}
	})

	server := &http.Server{Handler: mux}
	go server.Serve(listener)

	// Wait for callback or context cancellation or timeout
	timer := time.NewTimer(5 * time.Minute)
	defer timer.Stop()

	var res callbackResult
	select {
	case res = <-resultCh:
	case <-ctx.Done():
		server.Close()
		return nil, ctx.Err()
	case <-timer.C:
		server.Close()
		return nil, errors.New("authorization timed out (5 minutes)")
	}

	server.Close()

	if res.Error != "" {
		return nil, fmt.Errorf("authorization denied: %s", res.Error)
	}

	// Step 4: Exchange code for tokens
	return c.ExchangeCode(ctx, res.Code, redirectURI, codeVerifier)
}

// GetAuthorizationURL builds the authorization URL for the Auth Code + PKCE flow.
// Use this when you manage the browser redirect yourself.
func (c *AirlockAuthClient) GetAuthorizationURL(ctx context.Context, redirectURI string) (*AuthCodeRequest, error) {
	oidc, err := c.Discover(ctx)
	if err != nil {
		return nil, err
	}

	if oidc.AuthorizationEndpoint == "" {
		return nil, errors.New("OIDC discovery: authorization_endpoint is missing")
	}

	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return nil, err
	}
	codeChallenge := computeCodeChallenge(codeVerifier)
	state := generateState()

	authURL := fmt.Sprintf("%s?response_type=code&client_id=%s&redirect_uri=%s&scope=%s&state=%s&code_challenge=%s&code_challenge_method=S256",
		oidc.AuthorizationEndpoint,
		url.QueryEscape(c.Options.OIDCClientID),
		url.QueryEscape(redirectURI),
		url.QueryEscape("openid profile email"),
		state,
		codeChallenge,
	)

	return &AuthCodeRequest{
		AuthorizationURL: authURL,
		State:            state,
		CodeVerifier:     codeVerifier,
		RedirectURI:      redirectURI,
	}, nil
}

// ExchangeCode exchanges an authorization code for tokens (Auth Code + PKCE).
func (c *AirlockAuthClient) ExchangeCode(ctx context.Context, code, redirectURI, codeVerifier string) (*TokenResponse, error) {
	oidc, err := c.Discover(ctx)
	if err != nil {
		return nil, err
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", c.Options.OIDCClientID)
	data.Set("code", code)
	data.Set("redirect_uri", redirectURI)
	data.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oidc.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		var tErr TokenErrorResponse
		json.Unmarshal(body, &tErr)
		return nil, fmt.Errorf("code exchange failed: %s - %s", tErr.Error, tErr.ErrorDescription)
	}

	var token TokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, err
	}

	c.accessToken = token.AccessToken
	c.refreshToken = token.RefreshToken
	c.tokenExpiresAt = time.Now().UTC().Add(time.Duration(token.ExpiresIn-30) * time.Second)
	return &token, nil
}

// PKCE helpers

func generateCodeVerifier() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

func computeCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func generateState() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return fmt.Sprintf("%x", bytes)
}

// RefreshToken refreshes the access token.
func (c *AirlockAuthClient) RefreshToken(ctx context.Context) (*TokenResponse, error) {
	if c.refreshToken == "" {
		return nil, errors.New("no refresh token available")
	}

	oidc, err := c.Discover(ctx)
	if err != nil {
		return nil, err
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", c.Options.OIDCClientID)
	data.Set("refresh_token", c.refreshToken)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, oidc.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		c.accessToken = ""
		c.refreshToken = ""
		var tErr TokenErrorResponse
		json.Unmarshal(body, &tErr)
		return nil, fmt.Errorf("token refresh failed: %s - %s", tErr.Error, tErr.ErrorDescription)
	}

	var token TokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return nil, err
	}

	c.accessToken = token.AccessToken
	c.refreshToken = token.RefreshToken
	c.tokenExpiresAt = time.Now().UTC().Add(time.Duration(token.ExpiresIn-30) * time.Second)
	return &token, nil
}

// GetAccessToken returns a valid access token, auto-refreshing if needed.
func (c *AirlockAuthClient) GetAccessToken(ctx context.Context) (string, error) {
	if c.accessToken == "" {
		return "", errors.New("not logged in")
	}
	if c.IsTokenExpired() {
		if c.refreshToken != "" {
			if _, err := c.RefreshToken(ctx); err != nil {
				return "", err
			}
		} else {
			return "", errors.New("token expired and no refresh token")
		}
	}
	return c.accessToken, nil
}

// Logout revokes the refresh token and clears state.
func (c *AirlockAuthClient) Logout(ctx context.Context) error {
	if c.refreshToken != "" {
		oidc, err := c.Discover(ctx)
		if err == nil && oidc.RevocationEndpoint != "" {
			data := url.Values{}
			data.Set("client_id", c.Options.OIDCClientID)
			data.Set("token", c.refreshToken)
			data.Set("token_type_hint", "refresh_token")

			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, oidc.RevocationEndpoint, strings.NewReader(data.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			resp, err := c.httpClient.Do(req)
			if err == nil {
				resp.Body.Close()
			}
		}
	}

	c.accessToken = ""
	c.refreshToken = ""
	c.tokenExpiresAt = time.Time{}
	return nil
}

// ParseConsentError parses a consent error from an HTTP response payload.
func ParseConsentError(statusCode int, responseBody []byte) *ConsentErrorInfo {
	if statusCode != http.StatusForbidden {
		return nil
	}
	var res map[string]interface{}
	if err := json.Unmarshal(responseBody, &res); err != nil {
		return nil
	}

	errCode, ok := res["error"].(string)
	if !ok || (errCode != "app_consent_required" && errCode != "app_consent_pending" && errCode != "app_consent_denied") {
		return nil
	}

	msg, _ := res["message"].(string)
	url, _ := res["consentUrl"].(string)
	appName, _ := res["appName"].(string)
	appId, _ := res["appId"].(string)

	return &ConsentErrorInfo{
		Error:      errCode,
		Message:    msg,
		ConsentURL: url,
		AppName:    appName,
		AppID:      appId,
	}
}

// RestoreTokens restores tokens from persistent storage.
func (c *AirlockAuthClient) RestoreTokens(access, refresh string, expiresAt time.Time) {
	c.accessToken = access
	c.refreshToken = refresh
	c.tokenExpiresAt = expiresAt
}

// GetTokenState gets tokens for persistent storage.
func (c *AirlockAuthClient) GetTokenState() (string, string, time.Time) {
	return c.accessToken, c.refreshToken, c.tokenExpiresAt
}
