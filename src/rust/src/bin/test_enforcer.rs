use airlock_gateway::{
    AirlockAuthClient, AirlockAuthOptions, AirlockGatewayClient, GatewayError,
    ArtifactSubmitRequest, CiphertextRef, PairingInitiateRequest, PresenceHeartbeatRequest,
};
use console::style;
use dialoguer::{Confirm, Input, Password, Select};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

// ── Persistent Configuration ────────────────────────────────────────
#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
struct Config {
    gateway_url: String,
    client_id: String,
    client_secret: String,
    enforcer_id: String,
    workspace_name: String,
    device_id: String,
    routing_token: String,
    access_token: String,
    refresh_token: String,
    #[serde(default)]
    token_expires_at: Option<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            gateway_url: "https://localhost:7190".to_string(),
            client_id: String::new(),
            client_secret: String::new(),
            enforcer_id: "enf-test".to_string(),
            workspace_name: "default".to_string(),
            device_id: String::new(),
            routing_token: String::new(),
            access_token: String::new(),
            refresh_token: String::new(),
            token_expires_at: None,
        }
    }
}

fn mask_secret(s: &str) -> String {
    if s.is_empty() {
        return "(not set)".to_string();
    }
    if s.len() <= 8 {
        return "*".repeat(s.len());
    }
    format!("{}…{}", &s[..4], &s[s.len() - 4..])
}

fn config_path() -> PathBuf {
    let home = env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".airlock").join("test-enforcer-rust.json")
}

fn load_config() -> Config {
    let path = config_path();
    if path.exists() {
        if let Ok(data) = fs::read_to_string(&path) {
            if let Ok(c) = serde_json::from_str(&data) {
                return c;
            }
        }
    }
    Config::default()
}

fn save_config(cfg: &Config) {
    let path = config_path();
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    if let Ok(data) = serde_json::to_string_pretty(cfg) {
        let _ = fs::write(path, data);
    }
}

// ── Main ────────────────────────────────────────────────────────────
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", style("╔═══════════════════════════════════════════╗").cyan().bold());
    println!("{}", style("║       Airlock Test Enforcer (Rust)         ║").cyan().bold());
    println!("{}", style("╚═══════════════════════════════════════════╝").cyan().bold());
    println!();

    let mut cfg = load_config();

    // Discover gateway
    let keycloak_url = discover_gateway(&cfg.gateway_url).await;

    if cfg.client_id.is_empty() {
        run_setup_wizard(&mut cfg);
    }

    // Build insecure HTTP client
    let http = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(120))
        .build()?;

    let auth_client = AirlockAuthClient::new(AirlockAuthOptions {
        keycloak_realm_url: keycloak_url,
        oidc_client_id: "airlock-integrations".to_string(),
        reqwest_client: Some(http.clone()),
    });

    let mut gw_client = AirlockGatewayClient::with_credentials_and_http_client(
        &cfg.gateway_url,
        &cfg.client_id,
        &cfg.client_secret,
        http,
    );

    // Session restore
    try_restore_session(&auth_client, &mut gw_client, &mut cfg).await;
    print_status(&auth_client, &cfg).await;

    // Heartbeat handle
    let heartbeat_handle: Arc<Mutex<Option<JoinHandle<()>>>> = Arc::new(Mutex::new(None));
    let last_request_id: Arc<Mutex<String>> = Arc::new(Mutex::new(String::new()));

    // Auto-start heartbeat if already paired (session restore)
    if auth_client.is_logged_in().await && !cfg.routing_token.is_empty() {
        start_heartbeat(&gw_client, &cfg, &heartbeat_handle).await;
    }

    loop {
        let choices = build_menu_choices(&auth_client, &cfg).await;
        let selection = Select::new()
            .with_prompt(format!("{}", style("Choose action").cyan().bold()))
            .items(&choices)
            .default(0)
            .interact_opt();

        let idx = match selection {
            Ok(Some(i)) => i,
            _ => {
                stop_heartbeat(&heartbeat_handle).await;
                println!("{}", style("Goodbye!").dim());
                return Ok(());
            }
        };

        let choice = &choices[idx];
        let result = match choice.as_str() {
            "▸ Sign In" => do_sign_in(&auth_client, &mut gw_client, &mut cfg).await,
            "▸ Pair Device" => do_pair(&gw_client, &mut cfg, &heartbeat_handle).await,
            "▸ Submit Artifact" => {
                do_submit(&auth_client, &gw_client, &mut cfg, &last_request_id).await
            }
            "▸ Withdraw" => do_withdraw(&gw_client, &last_request_id).await,
            "▸ Unpair" => do_unpair(&gw_client, &mut cfg, &heartbeat_handle).await,
            "▸ Sign Out" => do_sign_out(&auth_client, &mut gw_client, &mut cfg, &heartbeat_handle).await,
            "▸ Reconfigure" => {
                run_setup_wizard(&mut cfg);
                // Reinit clients would need new client instances; for simplicity just inform user
                println!("{}", style("⚠ Restart the enforcer to apply new credentials.").yellow());
                Ok(())
            }
            "✕ Exit" => {
                stop_heartbeat(&heartbeat_handle).await;
                println!("{}", style("Goodbye!").dim());
                return Ok(());
            }
            _ => Ok(()),
        };

        if let Err(e) = result {
            handle_error(e);
        }
    }
}

// ── Menu ─────────────────────────────────────────────────────────────
async fn build_menu_choices(auth: &AirlockAuthClient, cfg: &Config) -> Vec<String> {
    let signed_in = auth.is_logged_in().await;
    let paired = !cfg.routing_token.is_empty();

    if signed_in {
        if paired {
            vec![
                "▸ Submit Artifact".into(), "▸ Withdraw".into(), "─────────".into(),
                "▸ Unpair".into(), "▸ Sign Out".into(), "▸ Reconfigure".into(), "✕ Exit".into(),
            ]
        } else {
            vec!["▸ Pair Device".into(), "─────────".into(), "▸ Sign Out".into(), "▸ Reconfigure".into(), "✕ Exit".into()]
        }
    } else {
        vec!["▸ Sign In".into(), "▸ Reconfigure".into(), "✕ Exit".into()]
    }
}

// ── Status Display ──────────────────────────────────────────────────
async fn print_status(auth: &AirlockAuthClient, cfg: &Config) {
    println!();
    println!("┌──────────────────────────────────────────────┐");
    println!("│ {:14} │ {:28} │", "Gateway", cfg.gateway_url);
    println!("│ {:14} │ {:28} │", "Client ID", cfg.client_id);
    println!("│ {:14} │ {:28} │", "Client Secret", mask_secret(&cfg.client_secret));
    println!("│ {:14} │ {:28} │", "Enforcer ID", cfg.enforcer_id);
    println!("│ {:14} │ {:28} │", "Workspace", cfg.workspace_name);

    if auth.is_logged_in().await {
        println!("│ {:14} │ {} │", "Auth", style("Signed in").green());
    } else {
        println!("│ {:14} │ {} │", "Auth", style("Not signed in").dim());
    }

    if !cfg.routing_token.is_empty() {
        let truncated = if cfg.routing_token.len() > 16 {
            format!("{}...", &cfg.routing_token[..16])
        } else {
            cfg.routing_token.clone()
        };
        println!("│ {:14} │ {} │", "Paired", style(truncated).green());
    } else {
        println!("│ {:14} │ {} │", "Paired", style("Not paired").dim());
    }
    println!("└──────────────────────────────────────────────┘");
    println!();
}

// ── Gateway Discovery ───────────────────────────────────────────────
async fn discover_gateway(gateway_url: &str) -> String {
    let default = "http://localhost:18080/realms/airlock".to_string();
    let url = format!("{}/v1/integrations/discovery", gateway_url.trim_end_matches('/'));

    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => {
            println!("{}", style(format!("Discovery failed — using default: {}", default)).dim().yellow());
            return default;
        }
    };

    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            if let Ok(data) = resp.json::<serde_json::Value>().await {
                if let Some(base) = data.get("idp").and_then(|i| i.get("baseUrl")).and_then(|v| v.as_str()) {
                    let result: String = base.to_string();
                    println!("{}", style(format!("Keycloak: {}", result)).dim());
                    return result;
                }
            }
            println!("{}", style(format!("Discovery failed — using default: {}", default)).dim().yellow());
            default
        }
        _ => {
            println!("{}", style(format!("Discovery failed — using default: {}", default)).dim().yellow());
            default
        }
    }
}

// ── Sign In ─────────────────────────────────────────────────────────
async fn do_sign_in(
    auth: &AirlockAuthClient,
    gw: &mut AirlockGatewayClient,
    cfg: &mut Config,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", style("Discovering OIDC endpoints...").dim());
    auth.discover().await?;

    println!("{}", style("Requesting device code...").dim());
    let _token = auth
        .login(|info| {
            let url = info.verification_uri_complete.as_deref().unwrap_or(&info.verification_uri);
            println!();
            println!("{}", style("┌─ Device Authorization Required ─────────────────┐").yellow());
            println!("│ Open this URL: {}", style(url).bold());
            println!("│ Enter code:    {}", style(&info.user_code).cyan().bold());
            println!("{}", style("└─────────────────────────────────────────────────┘").yellow());
            println!("{}", style("Waiting for user authorization...").dim());
        })
        .await?;

    println!("{}", style("✓ Signed in successfully").green());

    let (acc, ref_tok, exp) = auth.token_state().await;
    cfg.access_token = acc.clone();
    cfg.refresh_token = ref_tok;
    cfg.token_expires_at = exp
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs());
    save_config(cfg);

    gw.set_bearer_token(Some(acc));

    check_consent(gw).await;
    Ok(())
}

// ── Consent Check ───────────────────────────────────────────────────
async fn check_consent(gw: &AirlockGatewayClient) {
    println!("{}", style("Checking consent...").dim());
    match gw.check_consent().await {
        Ok(status) => {
            println!("{}", style(format!("✓ Consent status: {}", status)).green());
        }
        Err(GatewayError::Api { error_code, message, .. }) => {
            let code = error_code.as_deref().unwrap_or("");
            if code == "app_consent_required" || code == "app_consent_pending" {
                println!("{}", style("┌─ Consent Required ──────────────────────────────┐").yellow());
                println!("│ {}", style(&message).yellow());
                println!("│ A consent request has been sent to your mobile.");
                println!("│ Please approve it in the Airlock mobile app.");
                println!("{}", style("└─────────────────────────────────────────────────┘").yellow());
            } else {
                println!("{}", style(format!("Consent check failed: {} — {}", code, message)).yellow());
            }
        }
        Err(e) => {
            println!("{}", style(format!("Consent check failed: {}", e)).yellow());
        }
    }
}

// ── Pair Device ─────────────────────────────────────────────────────
async fn do_pair(
    gw: &AirlockGatewayClient,
    cfg: &mut Config,
    hb: &Arc<Mutex<Option<JoinHandle<()>>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    if cfg.device_id.is_empty() {
        let hostname = env::var("COMPUTERNAME")
            .or_else(|_| env::var("HOSTNAME"))
            .unwrap_or_else(|_| "test".to_string())
            .to_lowercase();
        let default_id = format!("dev-{}", hostname);
        cfg.device_id = Input::new()
            .with_prompt("Device ID")
            .default(default_id)
            .interact_text()?;
    }

    let req = PairingInitiateRequest {
        device_id: cfg.device_id.clone(),
        enforcer_id: cfg.enforcer_id.clone(),
        enforcer_label: Some("Test Enforcer Rust".to_string()),
        workspace_name: Some(cfg.workspace_name.clone()),
        gateway_url: None,
        x25519_public_key: None,
    };

    let res = gw.initiate_pairing(&req).await?;

    println!("{}", style("┌─ Pairing Initiated ─────────────────────────────┐").yellow());
    println!("│ Pairing Code: {}", style(&res.pairing_code).cyan().bold());
    println!("│ Nonce:        {}", res.pairing_nonce);
    println!("│ Enter this code in the Airlock mobile app.");
    println!("{}", style("└─────────────────────────────────────────────────┘").yellow());

    println!("{}", style("Waiting for pairing approval...").dim());
    for i in 0..60 {
        tokio::time::sleep(Duration::from_secs(5)).await;
        let status = gw.get_pairing_status(&res.pairing_nonce).await?;
        let state = status.state.to_lowercase();
        println!("  {} ({}s)", style(format!("Pairing status: {}", state)).dim(), (i + 1) * 5);

        if state == "completed" {
            cfg.routing_token = status.routing_token.unwrap_or_default();
            save_config(cfg);
            println!("{}", style("✓ Paired! Routing token saved.").green());
            start_heartbeat(gw, cfg, hb).await;
            return Ok(());
        }
        if state == "revoked" || state == "expired" {
            println!("{}", style(format!("Pairing {}", state)).red());
            return Ok(());
        }
    }

    println!("{}", style("Pairing timed out.").red());
    Ok(())
}

// ── Submit Artifact ─────────────────────────────────────────────────
async fn do_submit(
    auth: &AirlockAuthClient,
    gw: &AirlockGatewayClient,
    cfg: &mut Config,
    last_req: &Arc<Mutex<String>>,
) -> Result<(), Box<dyn std::error::Error>> {
    ensure_fresh_token(auth, gw, cfg).await;

    let req_id = format!("req-{}", uuid::Uuid::new_v4());
    let artifact_hash = format!("hash-{}", &uuid::Uuid::new_v4().to_string()[..12]);

    let mut rng = rand::thread_rng();
    let nonce_bytes: Vec<u8> = (0..24).map(|_| rng.gen::<u8>()).collect();
    let tag_bytes: Vec<u8> = (0..16).map(|_| rng.gen::<u8>()).collect();
    let data_bytes: Vec<u8> = (0..64).map(|_| rng.gen::<u8>()).collect();

    fn to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    let mut metadata = std::collections::HashMap::new();
    metadata.insert("routingToken".to_string(), cfg.routing_token.clone());
    metadata.insert("workspaceName".to_string(), cfg.workspace_name.clone());

    let req = ArtifactSubmitRequest {
        enforcer_id: cfg.enforcer_id.clone(),
        artifact_type: Some("command-approval".to_string()),
        artifact_hash,
        ciphertext: CiphertextRef {
            alg: "xchacha20-poly1305".to_string(),
            data: to_hex(&data_bytes),
            nonce: Some(to_hex(&nonce_bytes)),
            tag: Some(to_hex(&tag_bytes)),
            aad: None,
        },
        metadata: Some(metadata),
        request_id: Some(req_id.clone()),
        expires_at: None,
    };

    println!("{}", style(format!("Submitting artifact {}...", req_id)).dim());
    let submitted = gw.submit_artifact(req).await?;
    let rid = submitted;
    *last_req.lock().await = rid.clone();
    println!("{}", style(format!("✓ Submitted: {}", rid)).green());

    // Long-poll for decision
    println!("{}", style("Waiting for decision...").dim());
    let deadline = SystemTime::now() + Duration::from_secs(120);
    let mut poll = 0u64;

    while SystemTime::now() < deadline {
        poll += 1;
        println!("  {} ({}s elapsed)", style("Waiting for decision...").dim(), poll * 25);

        match gw.wait_for_decision(&rid, 25).await {
            Ok(Some(env)) => {
                if let Some(body) = env.body {
                    let is_approved = body.decision.to_lowercase() == "approve";
                    let icon = if is_approved { "✓" } else { "✗" };
                    let s = if is_approved { style(format!("{} {}", icon, body.decision.to_uppercase())).green() }
                            else { style(format!("{} {}", icon, body.decision.to_uppercase())).red() };

                    println!("┌─ Decision ──────────────────────────────────────┐");
                    println!("│ {}", s);
                    if let Some(r) = &body.reason {
                        println!("│ Reason: {}", r);
                    }
                    if let Some(k) = &body.signer_key_id {
                        println!("│ Signer: {}", k);
                    }
                    println!("└─────────────────────────────────────────────────┘");
                }
                return Ok(());
            }
            Ok(None) => continue,
            Err(GatewayError::Api { status_code: 404, .. }) => return Ok(()),
            Err(e) => return Err(e.into()),
        }
    }

    println!("{}", style("⏳ Timed out waiting for decision.").yellow());
    do_withdraw(gw, last_req).await?;
    Ok(())
}

// ── Withdraw ────────────────────────────────────────────────────────
async fn do_withdraw(
    gw: &AirlockGatewayClient,
    last_req: &Arc<Mutex<String>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut rid = last_req.lock().await.clone();
    if rid.is_empty() {
        rid = Input::new()
            .with_prompt("Request ID to withdraw")
            .interact_text()?;
        if rid.is_empty() {
            return Ok(());
        }
    }

    match gw.withdraw_exchange(&rid).await {
        Ok(()) => {
            println!("{}", style(format!("✓ Withdrawn: {}", rid)).green());
            *last_req.lock().await = String::new();
        }
        Err(e) => {
            println!("{}", style(format!("Withdraw failed (non-fatal): {}", e)).yellow());
        }
    }
    Ok(())
}

// ── Unpair ──────────────────────────────────────────────────────────
async fn do_unpair(
    gw: &AirlockGatewayClient,
    cfg: &mut Config,
    hb: &Arc<Mutex<Option<JoinHandle<()>>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    if cfg.routing_token.is_empty() {
        println!("{}", style("Not paired.").dim());
        return Ok(());
    }

    if !Confirm::new()
        .with_prompt("Revoke pairing?")
        .default(false)
        .interact()?
    {
        return Ok(());
    }

    match gw.revoke_pairing(&cfg.routing_token).await {
        Ok(_) => {}
        Err(e) => {
            println!(
                "{}",
                style(format!("Server revoke failed (token may be stale): {}", e)).dim()
            );
        }
    }

    cfg.routing_token.clear();
    cfg.device_id.clear();
    stop_heartbeat(hb).await;
    save_config(cfg);
    println!("{}", style("✓ Unpaired.").green());
    Ok(())
}

// ── Sign Out ────────────────────────────────────────────────────────
async fn do_sign_out(
    auth: &AirlockAuthClient,
    gw: &mut AirlockGatewayClient,
    cfg: &mut Config,
    hb: &Arc<Mutex<Option<JoinHandle<()>>>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let _ = auth.logout().await; // best effort
    cfg.access_token.clear();
    cfg.refresh_token.clear();
    cfg.token_expires_at = None;
    gw.set_bearer_token(None::<String>);
    stop_heartbeat(hb).await;
    save_config(cfg);
    println!("{}", style("✓ Signed out.").green());
    Ok(())
}

// ── Session Restore ─────────────────────────────────────────────────
async fn try_restore_session(
    auth: &AirlockAuthClient,
    gw: &mut AirlockGatewayClient,
    cfg: &mut Config,
) {
    if cfg.refresh_token.is_empty() {
        return;
    }

    let exp = cfg
        .token_expires_at
        .map(|s| UNIX_EPOCH + Duration::from_secs(s));

    auth.restore_tokens(cfg.access_token.clone(), cfg.refresh_token.clone(), exp)
        .await;

    println!("{}", style("Refreshing session...").dim());
    match auth.refresh_token().await {
        Ok(_) => {
            let (acc, ref_tok, new_exp) = auth.token_state().await;
            cfg.access_token = acc.clone();
            cfg.refresh_token = ref_tok;
            cfg.token_expires_at = new_exp
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs());
            save_config(cfg);
            gw.set_bearer_token(Some(acc));
            println!("{}", style("✓ Session restored").green());
            check_consent(gw).await;
        }
        Err(e) => {
            println!("{}", style(format!("Session expired: {}", e)).yellow());
            cfg.access_token.clear();
            cfg.refresh_token.clear();
            cfg.token_expires_at = None;
            save_config(cfg);
        }
    }
}

// ── Token Refresh ───────────────────────────────────────────────────
async fn ensure_fresh_token(
    auth: &AirlockAuthClient,
    _gw: &AirlockGatewayClient,
    cfg: &mut Config,
) {
    if auth.is_token_expired().await && !cfg.refresh_token.is_empty() {
        if let Ok(_) = auth.refresh_token().await {
            let (acc, ref_tok, exp) = auth.token_state().await;
            cfg.access_token = acc;
            cfg.refresh_token = ref_tok;
            cfg.token_expires_at = exp
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs());
            save_config(cfg);
        }
    }
}

// ── Background Heartbeat ────────────────────────────────────────────
async fn start_heartbeat(
    _gw: &AirlockGatewayClient,
    cfg: &Config,
    handle: &Arc<Mutex<Option<JoinHandle<()>>>>,
) {
    stop_heartbeat(handle).await;

    let enforcer_id = cfg.enforcer_id.clone();
    let workspace_name = cfg.workspace_name.clone();
    let gateway_url = cfg.gateway_url.clone();
    let client_id = cfg.client_id.clone();
    let client_secret = cfg.client_secret.clone();
    let access_token = cfg.access_token.clone();

    let task = tokio::spawn(async move {
        println!("{}", style("❤ Heartbeat started (every 10s)").dim());
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let mut hb_client = AirlockGatewayClient::with_credentials_and_http_client(
            &gateway_url, &client_id, &client_secret, http,
        );
        if !access_token.is_empty() {
            hb_client.set_bearer_token(Some(&access_token));
        }

        // Send an immediate heartbeat before starting the interval
        let req = PresenceHeartbeatRequest {
            enforcer_id: enforcer_id.clone(),
            enforcer_label: Some("Test Enforcer Rust".to_string()),
            workspace_name: Some(workspace_name.clone()),
        };
        if let Err(e) = hb_client.send_heartbeat(&req).await {
            println!("{}", style(format!("❤ Initial heartbeat failed: {}", e)).dim().yellow());
        }

        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            let req = PresenceHeartbeatRequest {
                enforcer_id: enforcer_id.clone(),
                enforcer_label: Some("Test Enforcer Rust".to_string()),
                workspace_name: Some(workspace_name.clone()),
            };
            if let Err(e) = hb_client.send_heartbeat(&req).await {
                println!("{}", style(format!("❤ Heartbeat failed: {}", e)).dim().yellow());
            }
        }
    });

    *handle.lock().await = Some(task);
}

async fn stop_heartbeat(handle: &Arc<Mutex<Option<JoinHandle<()>>>>) {
    let mut guard = handle.lock().await;
    if let Some(h) = guard.take() {
        h.abort();
        println!("{}", style("❤ Heartbeat stopped").dim());
    }
}

// ── Setup Wizard ────────────────────────────────────────────────────
fn run_setup_wizard(cfg: &mut Config) {
    println!("{}", style("─── Setup ──────────────────────────────────────").yellow());

    cfg.gateway_url = Input::new()
        .with_prompt("Gateway URL")
        .default(cfg.gateway_url.clone())
        .interact_text()
        .unwrap_or_else(|_| cfg.gateway_url.clone());

    cfg.client_id = Input::new()
        .with_prompt("Client ID")
        .default(cfg.client_id.clone())
        .interact_text()
        .unwrap_or_else(|_| cfg.client_id.clone());

    cfg.client_secret = Password::new()
        .with_prompt("Client Secret")
        .interact()
        .unwrap_or_else(|_| cfg.client_secret.clone());

    cfg.enforcer_id = Input::new()
        .with_prompt("Enforcer ID")
        .default(cfg.enforcer_id.clone())
        .interact_text()
        .unwrap_or_else(|_| cfg.enforcer_id.clone());

    cfg.workspace_name = Input::new()
        .with_prompt("Workspace Name")
        .default(cfg.workspace_name.clone())
        .interact_text()
        .unwrap_or_else(|_| cfg.workspace_name.clone());

    save_config(cfg);
    println!("{}", style("✓ Configuration saved").green());
}

// ── Error Handling ──────────────────────────────────────────────────
fn handle_error(e: Box<dyn std::error::Error>) {
    if let Some(gw_err) = e.downcast_ref::<GatewayError>() {
        match gw_err {
            GatewayError::Api { error_code, message, .. } => {
                println!("{}", style("┌─ Gateway Error ─────────────────────────────────┐").red());
                if let Some(c) = error_code {
                    println!("│ {}", style(c).red());
                }
                println!("│ {}", style(message).red());
                println!("{}", style("└─────────────────────────────────────────────────┘").red());

                if let Some(consent) = AirlockAuthClient::parse_consent_error(gw_err) {
                    println!("{}", style("┌─ Consent Required ──────────────────────────────┐").yellow());
                    println!("│ {}", style(&consent.message).yellow());
                    println!("│ Approve in the Airlock mobile app.");
                    println!("{}", style("└─────────────────────────────────────────────────┘").yellow());
                }
            }
            _ => {
                println!("{}", style(format!("[Error] {}", e)).red());
            }
        }
    } else {
        println!("{}", style(format!("[Error] {}", e)).red());
    }
}
