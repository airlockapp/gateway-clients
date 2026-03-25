//! Interactive CLI for exercising the Airlock Gateway SDK (pairing, PAT, OAuth, encrypt+submit).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use airlock_gateway::{
    crypto::{derive_shared_key, generate_x25519_keypair, to_base64url},
    AirlockAuthClient, AirlockAuthOptions, AirlockGatewayClient, EncryptedArtifactRequest,
    GatewayError, PairingClaimRequest, PairingInitiateRequest, PresenceHeartbeatRequest,
};
use chrono::{DateTime, Utc};
use console::style;
use dialoguer::{Confirm, Input, Password, Select};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct Config {
    #[serde(default)]
    gateway_url: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    client_secret: String,
    #[serde(default)]
    enforcer_id: String,
    #[serde(default)]
    workspace_name: String,
    #[serde(default)]
    device_id: String,
    #[serde(default)]
    routing_token: String,
    #[serde(default)]
    encryption_key: String,
    #[serde(default)]
    pat: String,
    #[serde(default)]
    access_token: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default)]
    token_expires_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct DiscoveryResponse {
    idp: DiscoveryIdp,
}

#[derive(Deserialize)]
struct DiscoveryIdp {
    #[serde(rename = "baseUrl")]
    base_url: String,
}

struct Inner {
    cfg: Config,
    gw: Arc<Mutex<AirlockGatewayClient>>,
    auth: Option<AirlockAuthClient>,
    keycloak_url: String,
    last_req_id: String,
    heartbeat: Option<tokio::task::JoinHandle<()>>,
}

type Anyhow = Box<dyn std::error::Error + Send + Sync>;

fn de<E: std::error::Error + Send + Sync + 'static>(e: E) -> Anyhow {
    Box::new(e)
}

fn config_path() -> PathBuf {
    let base = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(base).join(".airlock").join("test-enforcer-rust.json")
}

fn load_config(path: &PathBuf) -> Config {
    let mut cfg: Config = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    if cfg.gateway_url.is_empty() {
        cfg.gateway_url = "https://igw.airlocks.io".into();
    }
    if cfg.enforcer_id.is_empty() {
        cfg.enforcer_id = "enf-test".into();
    }
    if cfg.workspace_name.is_empty() {
        cfg.workspace_name = "default".into();
    }
    cfg
}

fn save_config(path: &PathBuf, cfg: &Config) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(cfg).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
    })?;
    std::fs::write(path, data)
}

fn mask_secret(secret: &str) -> String {
    if secret.is_empty() {
        return "(not set)".into();
    }
    if secret.len() <= 8 {
        return "*".repeat(secret.len());
    }
    format!(
        "{}…{}",
        &secret[..4],
        &secret[secret.len().saturating_sub(4)..]
    )
}

fn http_client_debug() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(120))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

fn http_client_discovery() -> reqwest::Client {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
}

async fn discover_keycloak(cfg: &Config) -> String {
    let url = format!(
        "{}/v1/integrations/discovery",
        cfg.gateway_url.trim_end_matches('/')
    );
    let client = http_client_discovery();
    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(body) = resp.text().await {
                if let Ok(disc) = serde_json::from_str::<DiscoveryResponse>(&body) {
                    if !disc.idp.base_url.is_empty() {
                        dim(&format!("Keycloak: {}", disc.idp.base_url));
                        return disc.idp.base_url;
                    }
                }
            }
            warn("Discovery did not return a valid Keycloak URL. Sign In will be unavailable until reconfigured.");
        }
        Ok(resp) => {
            warn(&format!(
                "Gateway discovery returned status {} — Sign In may be unavailable.",
                resp.status()
            ));
        }
        Err(_) => {
            warn(&format!(
                "Could not reach gateway at {} — Sign In may be unavailable.",
                cfg.gateway_url
            ));
        }
    }
    String::new()
}

fn init_clients(cfg: &Config, keycloak_url: &str) -> (Option<AirlockAuthClient>, AirlockGatewayClient) {
    let http = http_client_debug();
    let auth = if !keycloak_url.is_empty() {
        Some(AirlockAuthClient::new(AirlockAuthOptions {
            keycloak_realm_url: keycloak_url.to_string(),
            oidc_client_id: "airlock-integrations".into(),
            reqwest_client: Some(http.clone()),
        }))
    } else {
        None
    };
    let gw = AirlockGatewayClient::with_credentials_and_http_client(
        cfg.gateway_url.trim_end_matches('/'),
        cfg.client_id.clone(),
        cfg.client_secret.clone(),
        http,
    );
    (auth, gw)
}

fn dim(msg: &str) {
    eprintln!("{}", style(msg).dim());
}

fn warn(msg: &str) {
    eprintln!("{}", style(msg).yellow());
}

fn ok(msg: &str) {
    eprintln!("{}", style(msg).green());
}

fn err(msg: &str) {
    eprintln!("{}", style(msg).red());
}

fn handle_gateway_error(e: &GatewayError) {
    err(&format!("Gateway error: {}", e));
    if let Some(info) = AirlockAuthClient::parse_consent_error(e) {
        warn("┌─ Consent Required ──────────────────────────────┐");
        warn(&format!("│ {}", info.message));
        warn("│ A consent request has been sent to your mobile device.");
        warn("│ Please approve it in the Airlock mobile app.");
        warn("└─────────────────────────────────────────────────┘");
    }
}

async fn run_setup_wizard(inner: &mut Inner, path: &PathBuf) -> Result<(), Anyhow> {
    stop_heartbeat(inner);
    let cfg = &mut inner.cfg;
    warn("─── Setup ──────────────────────────────────────");
    let gw_default = if cfg.gateway_url.is_empty() {
        "https://igw.airlocks.io"
    } else {
        cfg.gateway_url.as_str()
    };
    cfg.gateway_url = Input::<String>::new()
        .with_prompt("Gateway URL")
        .default(gw_default.to_string())
        .interact_text()
        .map_err(de)?;

    let cid_default = cfg.client_id.clone();
    cfg.client_id = Input::<String>::new()
        .with_prompt("Client ID")
        .default(cid_default)
        .interact_text()
        .map_err(de)?;

    let secret = Password::new()
        .with_prompt("Client Secret")
        .interact()
        .map_err(de)?;
    if !secret.is_empty() {
        cfg.client_secret = secret;
    }

    let eid_default = if cfg.enforcer_id.is_empty() {
        "enf-test"
    } else {
        cfg.enforcer_id.as_str()
    };
    cfg.enforcer_id = Input::<String>::new()
        .with_prompt("Enforcer ID")
        .default(eid_default.to_string())
        .interact_text()
        .map_err(de)?;

    let ws_default = if cfg.workspace_name.is_empty() {
        "default"
    } else {
        cfg.workspace_name.as_str()
    };
    cfg.workspace_name = Input::<String>::new()
        .with_prompt("Workspace Name")
        .default(ws_default.to_string())
        .interact_text()
        .map_err(de)?;

    save_config(path, cfg).map_err(de)?;
    ok("✓ Configuration saved");
    Ok(())
}

async fn apply_gw_auth_async(gw: &Mutex<AirlockGatewayClient>, cfg: &Config) {
    let mut g = gw.lock().await;
    if !cfg.pat.is_empty() {
        g.set_pat(Some(cfg.pat.clone()));
        g.set_bearer_token(None::<String>);
    } else if !cfg.access_token.is_empty() {
        g.set_pat(None::<String>);
        g.set_bearer_token(Some(cfg.access_token.clone()));
    } else {
        g.set_pat(None::<String>);
        g.set_bearer_token(None::<String>);
    }
}

fn stop_heartbeat(inner: &mut Inner) {
    if let Some(h) = inner.heartbeat.take() {
        h.abort();
        dim("❤ Heartbeat stopped");
    }
}

async fn start_heartbeat(inner: &mut Inner) {
    stop_heartbeat(inner);
    let gw = Arc::clone(&inner.gw);
    let enforcer_id = inner.cfg.enforcer_id.clone();
    let workspace = inner.cfg.workspace_name.clone();
    let h = tokio::spawn(async move {
        dim("❤ Heartbeat started (every 10s)");
        async fn beat(
            gw: &Mutex<AirlockGatewayClient>,
            enforcer_id: &str,
            workspace: &str,
        ) {
            let req = PresenceHeartbeatRequest {
                enforcer_id: enforcer_id.to_string(),
                workspace_name: Some(workspace.to_string()),
                enforcer_label: Some("Test Enforcer CLI".into()),
            };
            let g = gw.lock().await;
            if let Err(e) = g.send_heartbeat(&req).await {
                warn(&format!("❤ Heartbeat failed: {e}"));
            }
        }
        beat(&gw, &enforcer_id, &workspace).await;
        let mut ticker = tokio::time::interval(Duration::from_secs(10));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            beat(&gw, &enforcer_id, &workspace).await;
        }
    });
    inner.heartbeat = Some(h);
}

async fn check_consent(gw: &Mutex<AirlockGatewayClient>) {
    dim("Checking consent...");
    let g = gw.lock().await;
    match g.check_consent().await {
        Ok(status) => ok(&format!("✓ Consent status: {status}")),
        Err(e) => {
            if let Some(info) = AirlockAuthClient::parse_consent_error(&e) {
                warn("┌─ Consent Required ──────────────────────────────┐");
                warn(&format!("│ {}", info.message));
                warn("│ A consent request has been sent to your mobile device.");
                warn("│ Please approve it in the Airlock mobile app.");
                warn("└─────────────────────────────────────────────────┘");
            } else {
                warn(&format!("Consent check failed: {e}"));
            }
        }
    }
}

async fn try_restore_session(inner: &mut Inner, path: &PathBuf) {
    apply_gw_auth_async(&inner.gw, &inner.cfg).await;

    if !inner.cfg.pat.is_empty() {
        ok("✓ PAT restored");
        let consent_result = {
            let g = inner.gw.lock().await;
            g.check_consent().await
        };
        match consent_result {
            Ok(status) => ok(&format!("✓ Consent status: {status}")),
            Err(e) => {
                if e.status_code() == Some(401) {
                    err("✗ PAT is invalid or revoked.");
                    warn("Please set a new PAT or sign in with OAuth.");
                    inner.cfg.pat.clear();
                    apply_gw_auth_async(&inner.gw, &inner.cfg).await;
                    let _ = save_config(path, &inner.cfg);
                    return;
                }
                if let Some(info) = AirlockAuthClient::parse_consent_error(&e) {
                    warn("┌─ Consent Required ──────────────────────────────┐");
                    warn(&format!("│ {}", info.message));
                    warn("│ A consent request has been sent to your mobile device.");
                    warn("│ Please approve it in the Airlock mobile app.");
                    warn("└─────────────────────────────────────────────────┘");
                } else {
                    warn(&format!("⚠ PAT validation failed: {e}"));
                }
            }
        }
        if !inner.cfg.routing_token.is_empty() {
            start_heartbeat(inner).await;
        }
        return;
    }

    if inner.cfg.refresh_token.is_empty() {
        return;
    }

    let Some(ref auth) = inner.auth else {
        return;
    };

    let exp = inner
        .cfg
        .token_expires_at
        .map(|dt| std::time::SystemTime::from(dt));
    auth
        .restore_tokens(
            inner.cfg.access_token.clone(),
            inner.cfg.refresh_token.clone(),
            exp,
        )
        .await;

    dim("Refreshing session...");
    match auth.refresh_token().await {
        Ok(_) => {
            let (acc, refr, exp) = auth.token_state().await;
            inner.cfg.access_token = acc;
            inner.cfg.refresh_token = refr;
            inner.cfg.token_expires_at = exp.map(DateTime::<Utc>::from);
            let _ = save_config(path, &inner.cfg);
            apply_gw_auth_async(&inner.gw, &inner.cfg).await;
            ok("✓ Session restored");
            check_consent(&inner.gw).await;
            if !inner.cfg.routing_token.is_empty() {
                start_heartbeat(inner).await;
            }
        }
        Err(e) => {
            warn(&format!("Session expired: {e}"));
            inner.cfg.access_token.clear();
            inner.cfg.refresh_token.clear();
            inner.cfg.token_expires_at = None;
            let _ = save_config(path, &inner.cfg);
        }
    }
}

async fn ensure_fresh_token(inner: &mut Inner, path: &PathBuf) {
    let Some(ref auth) = inner.auth else {
        return;
    };
    if auth.is_token_expired().await && !inner.cfg.refresh_token.is_empty() {
        if auth.refresh_token().await.is_ok() {
            let (acc, refr, exp) = auth.token_state().await;
            inner.cfg.access_token = acc;
            inner.cfg.refresh_token = refr;
            inner.cfg.token_expires_at = exp.map(DateTime::<Utc>::from);
            let _ = save_config(path, &inner.cfg);
            apply_gw_auth_async(&inner.gw, &inner.cfg).await;
        }
    }
}

async fn do_set_pat(inner: &mut Inner, path: &PathBuf) -> Result<(), Anyhow> {
    let pat = Password::new()
        .with_prompt("Paste your Personal Access Token (airpat_…)")
        .interact()
        .map_err(de)?;
    if pat.is_empty() {
        return Ok(());
    }
    if !pat.starts_with("airpat_") {
        err("Invalid PAT. Tokens must start with 'airpat_'.");
        return Ok(());
    }
    inner.cfg.pat = pat;
    apply_gw_auth_async(&inner.gw, &inner.cfg).await;
    save_config(path, &inner.cfg)?;
    ok("✓ PAT set. You can now pair and submit artifacts without OAuth sign-in.");
    check_consent(&inner.gw).await;
    Ok(())
}

async fn do_sign_in(inner: &mut Inner, path: &PathBuf) -> Result<(), GatewayError> {
    let Some(ref auth) = inner.auth else {
        warn("Sign In unavailable: Keycloak URL not discovered.");
        return Ok(());
    };
    dim("Discovering OIDC endpoints...");
    auth.discover().await?;
    dim("Requesting device code...");
    auth
        .login(|info| {
            println!();
            warn("┌─ Device Authorization Required ─────────────────┐");
            let url = info
                .verification_uri_complete
                .as_deref()
                .unwrap_or(&info.verification_uri);
            warn(&format!("│ Open this URL: {url}"));
            println!(
                "{}",
                style(format!("│ Enter code:    {}", info.user_code)).cyan()
            );
            warn("└─────────────────────────────────────────────────┘");
            dim("Waiting for user authorization...");
        })
        .await?;

    ok("✓ Signed in successfully");
    let (acc, refr, exp) = auth.token_state().await;
    inner.cfg.access_token = acc;
    inner.cfg.refresh_token = refr;
    inner.cfg.token_expires_at = exp.map(DateTime::<Utc>::from);
    save_config(path, &inner.cfg).map_err(|e| GatewayError::Crypto(e.to_string()))?;
    apply_gw_auth_async(&inner.gw, &inner.cfg).await;
    check_consent(&inner.gw).await;
    Ok(())
}

async fn do_pair(inner: &mut Inner, path: &PathBuf) -> Result<(), GatewayError> {
    if inner.cfg.device_id.is_empty() {
        let host = std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "host".into());
        let default_id = format!("dev-{}", host.to_lowercase());
        let id = Input::<String>::new()
            .with_prompt("Device ID:")
            .default(default_id.clone())
            .interact_text()
            .map_err(|e| GatewayError::Crypto(e.to_string()))?;
        inner.cfg.device_id = if id.is_empty() {
            default_id
        } else {
            id
        };
    }

    let mode = Select::new()
        .with_prompt("How do you want to pair?")
        .items(&["New pairing (generate code)", "Claim a pre-generated code"])
        .default(0)
        .interact()
        .map_err(|e| GatewayError::Crypto(e.to_string()))?;

    let x25519 = generate_x25519_keypair();

    let pairing_nonce = if mode == 1 {
        let code = Input::<String>::new()
            .with_prompt("Enter the pre-generated pairing code:")
            .interact_text()
            .map_err(|e| GatewayError::Crypto(e.to_string()))?;
        let code = code.trim().to_string();
        if code.is_empty() {
            return Ok(());
        }
        let claim = PairingClaimRequest {
            pairing_code: code,
            device_id: inner.cfg.device_id.clone(),
            enforcer_id: inner.cfg.enforcer_id.clone(),
            enforcer_label: "Test Enforcer CLI".into(),
            workspace_name: inner.cfg.workspace_name.clone(),
            gateway_url: Some(inner.cfg.gateway_url.clone()),
            x25519_public_key: Some(x25519.public_key.clone()),
        };
        let claim_res = {
            let g = inner.gw.lock().await;
            g.claim_pairing(&claim).await?
        };
        let pairing_nonce = claim_res.pairing_nonce;
        ok(&format!("✓ Code claimed. Nonce: {pairing_nonce}"));
        dim("Waiting for the approver to complete pairing in the mobile app...");
        pairing_nonce
    } else {
        let req = PairingInitiateRequest {
            device_id: inner.cfg.device_id.clone(),
            enforcer_id: inner.cfg.enforcer_id.clone(),
            gateway_url: None,
            x25519_public_key: Some(x25519.public_key.clone()),
            enforcer_label: Some("Test Enforcer CLI".into()),
            workspace_name: Some(inner.cfg.workspace_name.clone()),
        };
        let res = {
            let g = inner.gw.lock().await;
            g.initiate_pairing(&req).await?
        };
        println!();
        warn("┌─ Pairing Initiated ─────────────────────────────┐");
        println!(
            "{}",
            style(format!("│ Pairing Code: {}", res.pairing_code)).cyan().bold()
        );
        println!("│ Nonce:        {}", res.pairing_nonce);
        warn("│ Enter this code in the Airlock mobile app to complete pairing.");
        warn("└─────────────────────────────────────────────────┘");
        res.pairing_nonce
    };

    if mode != 1 {
        dim("Waiting for the approver to complete pairing in the mobile app...");
    }
    for i in 0..60 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let status = {
            let g = inner.gw.lock().await;
            g.get_pairing_status(&pairing_nonce).await?
        };
        let state = status.state.to_lowercase();
        dim(&format!(
            "  Pairing status: {} ({}s)",
            state,
            (i + 1) * 5
        ));

        if state == "completed" {
            inner.cfg.routing_token = status.routing_token.unwrap_or_default();
            if let Some(ref rj) = status.response_json {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(rj) {
                    if let Some(pk) = v.get("x25519PublicKey").and_then(|x| x.as_str()) {
                        if !pk.is_empty() {
                            match derive_shared_key(&x25519.private_key, pk) {
                                Ok(k) => {
                                    inner.cfg.encryption_key = k;
                                    ok("✓ X25519 ECDH key agreement completed — E2E encryption enabled");
                                }
                                Err(e) => warn(&format!("⚠ Failed to derive encryption key: {e}")),
                            }
                        }
                    }
                }
            }
            if inner.cfg.encryption_key.is_empty() {
                warn("⚠ No approver X25519 key received — encryption will use random test keys");
            }
            save_config(path, &inner.cfg).map_err(|e| GatewayError::Crypto(e.to_string()))?;
            ok("✓ Paired! Routing token saved.");
            start_heartbeat(inner).await;
            return Ok(());
        }
        if state == "revoked" || state == "expired" {
            err(&format!("Pairing {state}"));
            return Ok(());
        }
    }
    err("Pairing timed out or was rejected.");
    Ok(())
}

async fn do_submit(inner: &mut Inner, path: &PathBuf) -> Result<(), GatewayError> {
    ensure_fresh_token(inner, path).await;

    let ts = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true);
    let plaintext = serde_json::json!({
        "requestLabel": "Test approval request from Rust enforcer",
        "command": "dotnet test --filter Category=Integration",
        "workspaceName": inner.cfg.workspace_name,
        "enforcerId": inner.cfg.enforcer_id,
        "timestamp": ts,
    })
    .to_string();

    let mut enc_key = inner.cfg.encryption_key.clone();
    if enc_key.is_empty() {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        enc_key = to_base64url(&key);
        warn("⚠ No encryption key from pairing — using random test key");
    }

    let mut meta = HashMap::new();
    meta.insert("routingToken".into(), inner.cfg.routing_token.clone());
    meta.insert("workspaceName".into(), inner.cfg.workspace_name.clone());
    meta.insert(
        "requestLabel".into(),
        "Test approval request from Rust enforcer".into(),
    );

    let enc_req = EncryptedArtifactRequest {
        enforcer_id: inner.cfg.enforcer_id.clone(),
        artifact_type: Some("command-approval".into()),
        plaintext_payload: plaintext,
        encryption_key_base64url: enc_key,
        expires_at: None,
        metadata: Some(meta),
        request_id: None,
    };

    dim("Submitting encrypted artifact...");
    let submitted_id = {
        let g = inner.gw.lock().await;
        g.encrypt_and_submit_artifact(enc_req).await?
    };
    inner.last_req_id = submitted_id;
    ok(&format!(
        "✓ Submitted: {} (AES-256-GCM encrypted)",
        inner.last_req_id
    ));

    dim("Waiting for decision...");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let mut poll = 0u32;
    while tokio::time::Instant::now() < deadline {
        poll += 1;
        dim(&format!(
            "  Waiting for decision... ({}s elapsed)",
            poll * 25
        ));
        let env = {
            let g = inner.gw.lock().await;
            g.wait_for_decision(&inner.last_req_id, 25).await?
        };
        if let Some(ref envelope) = env {
            if let Some(ref body) = envelope.body {
                if body.is_approved() {
                    ok("┌─ Decision ──────────────────────────────────────┐");
                    ok(&format!("│ ✓ {}", body.decision.to_uppercase()));
                } else {
                    err("┌─ Decision ──────────────────────────────────────┐");
                    err(&format!("│ ✗ {}", body.decision.to_uppercase()));
                }
                if let Some(ref r) = body.reason {
                    println!("│ Reason: {r}");
                }
                if let Some(ref s) = body.signer_key_id {
                    println!("│ Signer: {s}");
                }
                println!("└─────────────────────────────────────────────────┘");
                return Ok(());
            }
        }
    }
    warn("⏳ Timed out waiting for decision.");
    let _ = do_withdraw(inner).await;
    Ok(())
}

async fn do_withdraw(inner: &mut Inner) -> Result<(), GatewayError> {
    let mut id = inner.last_req_id.clone();
    if id.is_empty() {
        id = Input::<String>::new()
            .with_prompt("Request ID to withdraw:")
            .interact_text()
            .map_err(|e| GatewayError::Crypto(e.to_string()))?;
        if id.is_empty() {
            return Ok(());
        }
    }
    {
        let g = inner.gw.lock().await;
        g.withdraw_exchange(&id).await?;
    }
    ok(&format!("✓ Withdrawn: {id}"));
    inner.last_req_id.clear();
    Ok(())
}

async fn do_unpair(inner: &mut Inner, path: &PathBuf) -> Result<(), GatewayError> {
    if inner.cfg.routing_token.is_empty() {
        dim("Not paired.");
        return Ok(());
    }
    let ok_confirm = Confirm::new()
        .with_prompt("Revoke pairing?")
        .default(false)
        .interact()
        .map_err(|e| GatewayError::Crypto(e.to_string()))?;
    if !ok_confirm {
        return Ok(());
    }
    {
        let g = inner.gw.lock().await;
        let _ = g.revoke_pairing(&inner.cfg.routing_token).await;
    }
    inner.cfg.routing_token.clear();
    inner.cfg.device_id.clear();
    stop_heartbeat(inner);
    save_config(path, &inner.cfg).map_err(|e| GatewayError::Crypto(e.to_string()))?;
    ok("✓ Unpaired.");
    Ok(())
}

async fn do_sign_out(inner: &mut Inner, path: &PathBuf) -> Result<(), GatewayError> {
    if let Some(ref auth) = inner.auth {
        let _ = auth.logout().await;
    }
    inner.cfg.access_token.clear();
    inner.cfg.refresh_token.clear();
    inner.cfg.pat.clear();
    inner.cfg.token_expires_at = None;
    apply_gw_auth_async(&inner.gw, &inner.cfg).await;
    stop_heartbeat(inner);
    save_config(path, &inner.cfg).map_err(|e| GatewayError::Crypto(e.to_string()))?;
    ok("✓ Signed out.");
    Ok(())
}

fn print_status(inner: &Inner) {
    println!();
    println!("┌──────────────────────────────────────────────┐");
    println!(
        "{:<16} │ {:<28} │",
        "Gateway",
        truncate(&inner.cfg.gateway_url, 28)
    );
    println!(
        "{:<16} │ {:<28} │",
        "Client ID",
        truncate(&inner.cfg.client_id, 28)
    );
    println!(
        "{:<16} │ {:<28} │",
        "Client Secret",
        mask_secret(&inner.cfg.client_secret)
    );
    println!(
        "{:<16} │ {:<28} │",
        "Enforcer ID",
        truncate(&inner.cfg.enforcer_id, 28)
    );
    println!(
        "{:<16} │ {:<28} │",
        "Workspace",
        truncate(&inner.cfg.workspace_name, 28)
    );

    let oauth_in_memory = inner
        .auth
        .as_ref()
        .map(|a| {
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(a.is_logged_in())
            })
        })
        .unwrap_or(false);
    let auth_line = if !inner.cfg.pat.is_empty() {
        style("PAT (airpat_…)").green().to_string()
    } else if !inner.cfg.access_token.is_empty() || oauth_in_memory {
        style("OAuth signed in").green().to_string()
    } else {
        style("Not authenticated").dim().to_string()
    };
    println!("{:<16} │ {:<28} │", "Auth", auth_line);

    let paired = if !inner.cfg.routing_token.is_empty() {
        let t = &inner.cfg.routing_token;
        let trunc = if t.len() > 16 {
            format!("{}...", &t[..16])
        } else {
            t.clone()
        };
        style(trunc).green().to_string()
    } else {
        style("Not paired").dim().to_string()
    };
    println!("{:<16} │ {:<28} │", "Paired", paired);
    println!("└──────────────────────────────────────────────┘");
    println!();
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

#[tokio::main]
async fn main() -> Result<(), Anyhow> {
    let path = config_path();
    let cfg = load_config(&path);

    println!(
        "{}",
        style("╔═══════════════════════════════════════╗").cyan().bold()
    );
    println!(
        "{}",
        style("║     Airlock Test Enforcer (Rust)      ║")
            .cyan()
            .bold()
    );
    println!(
        "{}",
        style("╚═══════════════════════════════════════╝").cyan().bold()
    );
    println!();

    let mut keycloak_url = discover_keycloak(&cfg).await;
    let (auth, gw) = init_clients(&cfg, &keycloak_url);
    let mut inner = Inner {
        cfg,
        gw: Arc::new(Mutex::new(gw)),
        auth,
        keycloak_url: keycloak_url.clone(),
        last_req_id: String::new(),
        heartbeat: None,
    };

    if inner.cfg.client_id.is_empty() {
        run_setup_wizard(&mut inner, &path).await?;
        keycloak_url = discover_keycloak(&inner.cfg).await;
        let (a, g) = init_clients(&inner.cfg, &keycloak_url);
        inner.auth = a;
        inner.gw = Arc::new(Mutex::new(g));
        inner.keycloak_url = keycloak_url;
    }

    try_restore_session(&mut inner, &path).await;
    print_status(&inner);

    loop {
        let oauth_logged_in = match &inner.auth {
            Some(a) => a.is_logged_in().await,
            None => false,
        };
        let is_signed_in =
            !inner.cfg.pat.is_empty() || !inner.cfg.access_token.is_empty() || oauth_logged_in;

        let is_paired = !inner.cfg.routing_token.is_empty();

        let choices: Vec<&'static str> = if is_signed_in {
            if is_paired {
                vec![
                    "> Submit Artifact",
                    "> Withdraw",
                    "─────────",
                    "> Unpair",
                    "> Sign Out",
                    "> Reconfigure",
                    "x Exit",
                ]
            } else {
                vec![
                    "> Pair Device",
                    "─────────",
                    "> Sign Out",
                    "> Reconfigure",
                    "x Exit",
                ]
            }
        } else {
            vec![
                "> Set PAT (recommended)",
                "> Sign In (OAuth)",
                "> Reconfigure",
                "x Exit",
            ]
        };

        let idx = Select::new()
            .with_prompt("Choose action")
            .items(&choices)
            .default(0)
            .interact()
            .map_err(de)?;

        let choice = choices[idx];
        let res: Result<(), Anyhow> = match choice {
            "> Set PAT (recommended)" => do_set_pat(&mut inner, &path).await,
            "> Sign In (OAuth)" => do_sign_in(&mut inner, &path).await.map_err(de),
            "> Pair Device" => do_pair(&mut inner, &path).await.map_err(de),
            "> Submit Artifact" => do_submit(&mut inner, &path).await.map_err(de),
            "> Withdraw" => do_withdraw(&mut inner).await.map_err(de),
            "> Unpair" => do_unpair(&mut inner, &path).await.map_err(de),
            "> Sign Out" => do_sign_out(&mut inner, &path).await.map_err(de),
            "> Reconfigure" => {
                run_setup_wizard(&mut inner, &path).await?;
                let kc = discover_keycloak(&inner.cfg).await;
                let (a, g) = init_clients(&inner.cfg, &kc);
                inner.auth = a;
                inner.gw = Arc::new(Mutex::new(g));
                inner.keycloak_url = kc;
                apply_gw_auth_async(&inner.gw, &inner.cfg).await;
                if !inner.cfg.pat.is_empty() {
                    ok("✓ PAT re-applied");
                } else if !inner.cfg.access_token.is_empty() {
                    ok("✓ Bearer token re-applied");
                }
                Ok(())
            }
            "x Exit" => {
                stop_heartbeat(&mut inner);
                dim("Goodbye!");
                break;
            }
            "─────────" => Ok(()),
            _ => Ok(()),
        };

        if let Err(e) = res {
            if let Some(gw_err) = e.downcast_ref::<GatewayError>() {
                handle_gateway_error(gw_err);
            } else {
                err(&format!("[Error] {e}"));
            }
        }
    }

    Ok(())
}
