use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Sha256, Digest};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;
use std::time::{Duration, Instant, SystemTime};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::models::{AuthCodeRequest, DeviceCodeInfo, OidcDiscoveryResult, TokenResponse, ConsentErrorInfo};
use crate::errors::GatewayError;

// ── PKCE Helper Functions ──────────────────────────────────────────

/// Generate a random code_verifier for PKCE (43-128 url-safe chars).
fn generate_code_verifier() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    URL_SAFE_NO_PAD.encode(&bytes)
}

/// Compute the code_challenge from a code_verifier using SHA-256.
fn compute_code_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(digest)
}

/// Generate a random state parameter for CSRF protection (hex string).
fn generate_state() -> String {
    let mut rng = rand::thread_rng();
    let bytes: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Configuration for Airlock Auth Client.
#[derive(Debug, Clone)]
pub struct AirlockAuthOptions {
    pub keycloak_realm_url: String,
    pub oidc_client_id: String,
    pub reqwest_client: Option<Client>,
}

impl Default for AirlockAuthOptions {
    fn default() -> Self {
        Self {
            keycloak_realm_url: "".to_string(),
            oidc_client_id: "airlock-integrations".to_string(),
            reqwest_client: None,
        }
    }
}

/// Token state payload.
#[derive(Debug, Clone, Default)]
struct TokenState {
    access_token: String,
    refresh_token: String,
    expires_at: Option<std::time::SystemTime>,
}

/// AirlockAuthClient handles user authentication via Device Authorization Grant
/// and Authorization Code + PKCE.
#[derive(Clone)]
pub struct AirlockAuthClient {
    options: AirlockAuthOptions,
    client: Client,
    oidc_config: Arc<RwLock<Option<OidcDiscoveryResult>>>,
    token_state: Arc<RwLock<TokenState>>,
}

#[derive(Deserialize)]
struct TokenErrorResponse {
    error: String,
    error_description: Option<String>,
}

impl AirlockAuthClient {
    /// Create a new AirlockAuthClient with the given options.
    pub fn new(options: AirlockAuthOptions) -> Self {
        let client = options.reqwest_client.clone().unwrap_or_else(|| {
            Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .unwrap_or_default()
        });

        Self {
            options,
            client,
            oidc_config: Arc::new(RwLock::new(None)),
            token_state: Arc::new(RwLock::new(TokenState::default())),
        }
    }

    /// Restore tokens from persistent storage.
    pub async fn restore_tokens(&self, access: String, refresh: String, expires_at: Option<std::time::SystemTime>) {
        let mut state = self.token_state.write().await;
        state.access_token = access;
        state.refresh_token = refresh;
        state.expires_at = expires_at;
    }

    /// Get current token state for persistent storage.
    pub async fn token_state(&self) -> (String, String, Option<std::time::SystemTime>) {
        let state = self.token_state.read().await;
        (state.access_token.clone(), state.refresh_token.clone(), state.expires_at)
    }

    /// True if an access token exists.
    pub async fn is_logged_in(&self) -> bool {
        !self.token_state.read().await.access_token.is_empty()
    }

    /// True if the access token exists and is expired.
    pub async fn is_token_expired(&self) -> bool {
        let state = self.token_state.read().await;
        if state.access_token.is_empty() {
            return true;
        }
        if let Some(exp) = state.expires_at {
            SystemTime::now() >= exp
        } else {
            true
        }
    }

    /// Fetch OIDC Discovery document.
    pub async fn discover(&self) -> Result<OidcDiscoveryResult, GatewayError> {
        let cached: Option<OidcDiscoveryResult> = self.oidc_config.read().await.clone();
        if let Some(config) = cached {
            return Ok(config);
        }

        let url = format!("{}/.well-known/openid-configuration", self.options.keycloak_realm_url.trim_end_matches('/'));
        let config: OidcDiscoveryResult = self.client.get(&url).send().await?.error_for_status()?.json().await?;

        if config.token_endpoint.is_empty() {
            return Err(GatewayError::Api {
                status_code: 400,
                error_code: Some("missing_endpoint".into()),
                message: "OIDC discovery: token_endpoint is missing".into(),
                response_body: None,
                request_id: None,
            });
        }

        let mut write_cache = self.oidc_config.write().await;
        *write_cache = Some(config.clone());
        Ok(config)
    }

    /// Start Device Authorization Grant login.
    pub async fn login<F>(&self, on_user_code: F) -> Result<TokenResponse, GatewayError>
    where
        F: FnOnce(&DeviceCodeInfo),
    {
        let oidc = self.discover().await?;

        // Step 1: Request device code
        let params = [
            ("client_id", self.options.oidc_client_id.as_str()),
            ("scope", "openid profile email"),
        ];

        let req = self.client.post(&oidc.device_authorization_endpoint)
            .form(&params);

        let resp = req.send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body_text = resp.text().await.unwrap_or_default();
            return Err(GatewayError::Api {
                status_code: status,
                error_code: None,
                message: "Device authorization failed".into(),
                response_body: Some(body_text),
                request_id: None,
            });
        }

        let device_code: DeviceCodeInfo = resp.json().await?;

        // Step 2: Notify UX callback
        on_user_code(&device_code);

        // Step 3: Poll token endpoint
        let mut interval = device_code.interval.unwrap_or(5) as u64;
        if interval < 5 { interval = 5; }

        let start = Instant::now();
        let timeout = Duration::from_secs(device_code.expires_in as u64);

        while start.elapsed() < timeout {
            tokio::time::sleep(Duration::from_secs(interval)).await;

            let poll_params = [
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", self.options.oidc_client_id.as_str()),
                ("device_code", device_code.device_code.as_str()),
            ];

            let t_resp = self.client.post(&oidc.token_endpoint)
                .form(&poll_params)
                .send()
                .await?;

            let status = t_resp.status();
            let t_body = t_resp.bytes().await?;

            if status.is_success() {
                let token: TokenResponse = serde_json::from_slice(&t_body)?;
                let mut state = self.token_state.write().await;
                state.access_token = token.access_token.clone();
                state.refresh_token = token.refresh_token.clone();
                state.expires_at = Some(SystemTime::now() + Duration::from_secs(token.expires_in.saturating_sub(30) as u64));
                return Ok(token);
            }

            if let Ok(err_resp) = serde_json::from_slice::<TokenErrorResponse>(&t_body) {
                match err_resp.error.as_str() {
                    "authorization_pending" => continue,
                    "slow_down" => {
                        interval += 5;
                        continue;
                    }
                    "access_denied" => return Err(GatewayError::Api {
                        status_code: 403, error_code: Some("access_denied".into()), message: "User denied authorization".into(), response_body: None, request_id: None
                    }),
                    "expired_token" => return Err(GatewayError::Api {
                        status_code: 400, error_code: Some("expired_token".into()), message: "Device code expired".into(), response_body: None, request_id: None
                    }),
                    _ => return Err(GatewayError::Api {
                        status_code: status.as_u16(), error_code: Some(err_resp.error), message: err_resp.error_description.unwrap_or_default(), response_body: None, request_id: None
                    })
                }
            }
        }

        Err(GatewayError::Api {
            status_code: 408, error_code: Some("timeout".into()), message: "Device authorization timed out".into(), response_body: None, request_id: None
        })
    }

    // ── Authorization Code + PKCE ───────────────────────────────

    /// Start the Authorization Code + PKCE flow.
    /// Opens a local TCP listener to receive the callback.
    /// Best for Web and Mobile enforcer apps.
    pub async fn login_with_auth_code<F>(&self, on_browser_url: F, redirect_port: u16) -> Result<TokenResponse, GatewayError>
    where
        F: FnOnce(&str),
    {
        let oidc = self.discover().await?;
        if oidc.authorization_endpoint.is_empty() {
            return Err(GatewayError::Api {
                status_code: 400, error_code: Some("missing_endpoint".into()),
                message: "OIDC discovery: authorization_endpoint is missing".into(),
                response_body: None, request_id: None,
            });
        }

        // Step 1: Generate PKCE
        let code_verifier = generate_code_verifier();
        let code_challenge = compute_code_challenge(&code_verifier);
        let state = generate_state();

        // Step 2: Start local TCP listener
        let bind_addr = if redirect_port == 0 {
            "127.0.0.1:0".to_string()
        } else {
            format!("127.0.0.1:{}", redirect_port)
        };
        let listener = TcpListener::bind(&bind_addr).await.map_err(|e| GatewayError::Api {
            status_code: 500, error_code: None,
            message: format!("Failed to bind callback listener: {}", e),
            response_body: None, request_id: None,
        })?;
        let port = listener.local_addr().unwrap().port();
        let redirect_uri = format!("http://localhost:{}/callback", port);

        // Step 3: Build authorization URL
        let auth_url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            oidc.authorization_endpoint,
            urlencoding::encode(&self.options.oidc_client_id),
            urlencoding::encode(&redirect_uri),
            urlencoding::encode("openid profile email"),
            &state,
            &code_challenge,
        );

        on_browser_url(&auth_url);

        // Step 4: Wait for callback (simple HTTP/1.1 parsing)
        let timeout = tokio::time::timeout(Duration::from_secs(300), listener.accept()).await;
        let (mut stream, _) = match timeout {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(GatewayError::Api {
                status_code: 500, error_code: None,
                message: format!("Accept failed: {}", e),
                response_body: None, request_id: None,
            }),
            Err(_) => return Err(GatewayError::Api {
                status_code: 408, error_code: Some("timeout".into()),
                message: "Authorization timed out (5 minutes)".into(),
                response_body: None, request_id: None,
            }),
        };

        // Read the HTTP request
        let mut buf = vec![0u8; 4096];
        let n = stream.read(&mut buf).await.unwrap_or(0);
        let request = String::from_utf8_lossy(&buf[..n]).to_string();

        // Parse the GET request line for query params
        let query_string = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|path| path.split('?').nth(1))
            .unwrap_or("");

        let params: std::collections::HashMap<String, String> = query_string
            .split('&')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                Some((parts.next()?.to_string(), parts.next().unwrap_or("").to_string()))
            })
            .collect();

        // Check for errors
        if let Some(err) = params.get("error") {
            let desc = params.get("error_description").cloned().unwrap_or_default();
            let response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n\r\nAuthorization failed.";
            let _ = stream.write_all(response.as_bytes()).await;
            return Err(GatewayError::Api {
                status_code: 403, error_code: Some(err.clone()),
                message: format!("Authorization denied: {} - {}", err, desc),
                response_body: None, request_id: None,
            });
        }

        // Validate state
        if params.get("state").map(|s| s.as_str()) != Some(&state) {
            let response = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n\r\nInvalid state.";
            let _ = stream.write_all(response.as_bytes()).await;
            return Err(GatewayError::Api {
                status_code: 400, error_code: Some("state_mismatch".into()),
                message: "CSRF state mismatch".into(),
                response_body: None, request_id: None,
            });
        }

        let code = params.get("code").cloned().ok_or_else(|| GatewayError::Api {
            status_code: 400, error_code: None,
            message: "No authorization code received".into(),
            response_body: None, request_id: None,
        })?;

        let response = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nAuthorization successful! You can close this tab.";
        let _ = stream.write_all(response.as_bytes()).await;
        drop(stream);

        // Step 5: Exchange code for tokens
        self.exchange_code(&code, &redirect_uri, &code_verifier).await
    }

    /// Builds the authorization URL for the Auth Code + PKCE flow.
    pub async fn get_authorization_url(&self, redirect_uri: &str) -> Result<AuthCodeRequest, GatewayError> {
        let oidc = self.discover().await?;
        if oidc.authorization_endpoint.is_empty() {
            return Err(GatewayError::Api {
                status_code: 400, error_code: Some("missing_endpoint".into()),
                message: "OIDC discovery: authorization_endpoint is missing".into(),
                response_body: None, request_id: None,
            });
        }

        let code_verifier = generate_code_verifier();
        let code_challenge = compute_code_challenge(&code_verifier);
        let state = generate_state();

        let authorization_url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            oidc.authorization_endpoint,
            urlencoding::encode(&self.options.oidc_client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode("openid profile email"),
            &state,
            &code_challenge,
        );

        Ok(AuthCodeRequest {
            authorization_url,
            state,
            code_verifier,
            redirect_uri: redirect_uri.to_string(),
        })
    }

    /// Exchange an authorization code for tokens (Auth Code + PKCE).
    pub async fn exchange_code(&self, code: &str, redirect_uri: &str, code_verifier: &str) -> Result<TokenResponse, GatewayError> {
        let oidc = self.discover().await?;

        let params = [
            ("grant_type", "authorization_code"),
            ("client_id", self.options.oidc_client_id.as_str()),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", code_verifier),
        ];

        let resp = self.client.post(&oidc.token_endpoint)
            .form(&params)
            .send()
            .await?;

        let status = resp.status();
        let body = resp.bytes().await?;

        if !status.is_success() {
            let err: TokenErrorResponse = serde_json::from_slice(&body).unwrap_or(TokenErrorResponse {
                error: "unknown".into(),
                error_description: None,
            });
            return Err(GatewayError::Api {
                status_code: status.as_u16(),
                error_code: Some(err.error),
                message: err.error_description.unwrap_or_else(|| "Code exchange failed".into()),
                response_body: None,
                request_id: None,
            });
        }

        let token: TokenResponse = serde_json::from_slice(&body)?;
        let mut state = self.token_state.write().await;
        state.access_token = token.access_token.clone();
        state.refresh_token = token.refresh_token.clone();
        state.expires_at = Some(SystemTime::now() + Duration::from_secs(token.expires_in.saturating_sub(30) as u64));
        Ok(token)
    }

    /// Refresh the access token.
    pub async fn refresh_token(&self) -> Result<TokenResponse, GatewayError> {
        let refresh_token = self.token_state.read().await.refresh_token.clone();
        if refresh_token.is_empty() {
            return Err(GatewayError::Api { status_code: 401, error_code: Some("no_refresh_token".into()), message: "Not logged in".into(), response_body: None, request_id: None});
        }

        let oidc = self.discover().await?;

        let params = [
            ("grant_type", "refresh_token"),
            ("client_id", self.options.oidc_client_id.as_str()),
            ("refresh_token", refresh_token.as_str()),
        ];

        let req = self.client.post(&oidc.token_endpoint).form(&params);
        let resp = req.send().await?;
        let status = resp.status();
        let body = resp.bytes().await?;

        if !status.is_success() {
            let mut state = self.token_state.write().await;
            state.access_token.clear();
            state.refresh_token.clear();
            state.expires_at = None;
            return Err(GatewayError::Api { status_code: status.as_u16(), error_code: Some("refresh_failed".into()), message: "Token refresh failed".into(), response_body: Some(String::from_utf8_lossy(&body).into()), request_id: None});
        }

        let token: TokenResponse = serde_json::from_slice(&body)?;
        let mut state = self.token_state.write().await;
        state.access_token = token.access_token.clone();
        state.refresh_token = token.refresh_token.clone();
        state.expires_at = Some(SystemTime::now() + Duration::from_secs(token.expires_in.saturating_sub(30) as u64));
        Ok(token)
    }

    /// Get valid access token, auto-refreshing if needed.
    pub async fn get_access_token(&self) -> Result<String, GatewayError> {
        if self.is_token_expired().await {
            let state = self.token_state.read().await;
            if state.refresh_token.is_empty() {
                return Err(GatewayError::Api { status_code: 401, error_code: Some("not_logged_in".into()), message: "Token expired and no refresh token".into(), response_body: None, request_id: None});
            }
            drop(state);
            self.refresh_token().await?;
        }
        Ok(self.token_state.read().await.access_token.clone())
    }

    /// Fetch revocation endpoint and revoke refresh token.
    pub async fn logout(&self) -> Result<(), GatewayError> {
        let refresh_token = self.token_state.read().await.refresh_token.clone();
        if !refresh_token.is_empty() {
            if let Ok(oidc) = self.discover().await {
                if !oidc.revocation_endpoint.is_empty() {
                    let params = [
                        ("client_id", self.options.oidc_client_id.as_str()),
                        ("token", refresh_token.as_str()),
                        ("token_type_hint", "refresh_token"),
                    ];
                    let _ = self.client.post(&oidc.revocation_endpoint).form(&params).send().await;
                }
            }
        }

        let mut state = self.token_state.write().await;
        state.access_token.clear();
        state.refresh_token.clear();
        state.expires_at = None;
        Ok(())
    }

    /// Parses consent errors from a 403 API response.
    pub fn parse_consent_error(error: &GatewayError) -> Option<ConsentErrorInfo> {
        if let GatewayError::Api { status_code, response_body: Some(body), .. } = error {
            if *status_code == 403 {
                if let Ok(v) = serde_json::from_str::<Value>(body) {
                    let err = v.get("error").and_then(Value::as_str).unwrap_or_default();
                    if err == "app_consent_required" || err == "app_consent_pending" || err == "app_consent_denied" {
                        return Some(ConsentErrorInfo {
                            error: err.to_string(),
                            message: v.get("message").and_then(Value::as_str).unwrap_or_default().to_string(),
                            consent_url: v.get("consentUrl").and_then(Value::as_str).map(|s| s.to_string()),
                            app_name: v.get("appName").and_then(Value::as_str).map(|s| s.to_string()),
                            app_id: v.get("appId").and_then(Value::as_str).map(|s| s.to_string()),
                        });
                    }
                }
            }
        }
        None
    }
}
