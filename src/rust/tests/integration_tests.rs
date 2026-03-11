//! Tests for the Airlock Gateway Rust SDK.
//!
//! Uses wiremock for HTTP mocking.

use airlock_gateway::*;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

async fn setup() -> (AirlockGatewayClient, MockServer) {
    let server = MockServer::start().await;
    let client =
        AirlockGatewayClient::new(server.uri(), Some("test-token"));
    (client, server)
}

// ── Echo ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_echo() {
    let (client, server) = setup().await;

    Mock::given(method("GET"))
        .and(path("/echo"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "utc": "2025-01-01T00:00:00Z",
            "local": "x",
            "timezone": "Europe/Istanbul",
            "offsetMinutes": 180
        })))
        .mount(&server)
        .await;

    let result = client.echo().await.unwrap();
    assert_eq!(result.timezone, "Europe/Istanbul");
    assert_eq!(result.offset_minutes, 180);
}

// ── Submit Artifact ──────────────────────────────────────────────

#[tokio::test]
async fn test_submit_artifact() {
    let (client, server) = setup().await;

    Mock::given(method("POST"))
        .and(path("/v1/artifacts"))
        .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({
            "msgType": "artifact.accepted"
        })))
        .mount(&server)
        .await;

    let result = client
        .submit_artifact(ArtifactSubmitRequest {
            enforcer_id: "e1".into(),
            artifact_hash: "abc123".into(),
            ciphertext: CiphertextRef {
                alg: "aes-256-gcm".into(),
                data: "encrypted".into(),
                nonce: None,
                tag: None,
                aad: None,
            },
            artifact_type: None,
            expires_at: None,
            metadata: None,
            request_id: Some("req-test123".into()),
        })
        .await
        .unwrap();

    assert_eq!(result, "req-test123");
}

#[tokio::test]
async fn test_submit_artifact_generates_request_id() {
    let (client, server) = setup().await;

    Mock::given(method("POST"))
        .and(path("/v1/artifacts"))
        .respond_with(ResponseTemplate::new(202).set_body_json(serde_json::json!({})))
        .mount(&server)
        .await;

    let result = client
        .submit_artifact(ArtifactSubmitRequest {
            enforcer_id: "e1".into(),
            artifact_hash: "h1".into(),
            ciphertext: CiphertextRef {
                alg: "aes-256-gcm".into(),
                data: "d".into(),
                nonce: None,
                tag: None,
                aad: None,
            },
            artifact_type: None,
            expires_at: None,
            metadata: None,
            request_id: None,
        })
        .await
        .unwrap();

    assert!(result.starts_with("req-"));
}

#[tokio::test]
async fn test_submit_artifact_quota_exceeded() {
    let (client, server) = setup().await;

    Mock::given(method("POST"))
        .and(path("/v1/artifacts"))
        .respond_with(ResponseTemplate::new(429).set_body_json(serde_json::json!({
            "body": {"code": "quota_exceeded", "message": "Monthly quota exceeded"}
        })))
        .mount(&server)
        .await;

    let err = client
        .submit_artifact(ArtifactSubmitRequest {
            enforcer_id: "e1".into(),
            artifact_hash: "h1".into(),
            ciphertext: CiphertextRef {
                alg: "aes-256-gcm".into(),
                data: "d".into(),
                nonce: None,
                tag: None,
                aad: None,
            },
            artifact_type: None,
            expires_at: None,
            metadata: None,
            request_id: None,
        })
        .await
        .unwrap_err();

    assert!(err.is_quota_exceeded());
}

#[tokio::test]
async fn test_submit_artifact_conflict() {
    let (client, server) = setup().await;

    Mock::given(method("POST"))
        .and(path("/v1/artifacts"))
        .respond_with(ResponseTemplate::new(409).set_body_json(serde_json::json!({
            "body": {"code": "AlreadyExistsConflict"}
        })))
        .mount(&server)
        .await;

    let err = client
        .submit_artifact(ArtifactSubmitRequest {
            enforcer_id: "e1".into(),
            artifact_hash: "h1".into(),
            ciphertext: CiphertextRef {
                alg: "aes-256-gcm".into(),
                data: "d".into(),
                nonce: None,
                tag: None,
                aad: None,
            },
            artifact_type: None,
            expires_at: None,
            metadata: None,
            request_id: None,
        })
        .await
        .unwrap_err();

    assert!(err.is_conflict());
}

// ── Exchange Status ──────────────────────────────────────────────

#[tokio::test]
async fn test_get_exchange_status() {
    let (client, server) = setup().await;

    Mock::given(method("GET"))
        .and(path("/v1/exchanges/req-1"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "msgType": "exchange.status",
            "requestId": "req-1",
            "body": {"requestId": "req-1", "state": "PendingApproval"}
        })))
        .mount(&server)
        .await;

    let result = client.get_exchange_status("req-1").await.unwrap();
    assert_eq!(result.body.unwrap().state, "PendingApproval");
}

// ── Wait for Decision ────────────────────────────────────────────

#[tokio::test]
async fn test_wait_for_decision_returns_decision() {
    let (client, server) = setup().await;

    Mock::given(method("GET"))
        .and(path("/v1/exchanges/req-1/wait"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "msgType": "decision.deliver",
            "requestId": "req-1",
            "body": {"artifactHash": "abc", "decision": "approve", "reason": "OK"}
        })))
        .mount(&server)
        .await;

    let result = client.wait_for_decision("req-1", 30).await.unwrap();
    assert!(result.is_some());
    let envelope = result.unwrap();
    assert!(envelope.body.unwrap().is_approved());
}

#[tokio::test]
async fn test_wait_for_decision_returns_none_on_204() {
    let (client, server) = setup().await;

    Mock::given(method("GET"))
        .and(path("/v1/exchanges/req-1/wait"))
        .respond_with(ResponseTemplate::new(204))
        .mount(&server)
        .await;

    let result = client.wait_for_decision("req-1", 5).await.unwrap();
    assert!(result.is_none());
}

// ── Pairing ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_initiate_pairing() {
    let (client, server) = setup().await;

    Mock::given(method("POST"))
        .and(path("/v1/pairing/initiate"))
        .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
            "pairingNonce": "n1",
            "pairingCode": "ABC123",
            "deviceId": "d1"
        })))
        .mount(&server)
        .await;

    let result = client
        .initiate_pairing(&PairingInitiateRequest {
            device_id: "d1".into(),
            enforcer_id: "e1".into(),
            gateway_url: None,
            x25519_public_key: None,
            enforcer_label: None,
            workspace_name: None,
        })
        .await
        .unwrap();

    assert_eq!(result.pairing_code, "ABC123");
}

#[tokio::test]
async fn test_resolve_pairing() {
    let (client, server) = setup().await;

    Mock::given(method("GET"))
        .and(path("/v1/pairing/resolve/ABC123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "pairingNonce": "n1",
            "deviceId": "d1",
            "enforcerLabel": "Cursor"
        })))
        .mount(&server)
        .await;

    let result = client.resolve_pairing("ABC123").await.unwrap();
    assert_eq!(result.enforcer_label, Some("Cursor".into()));
}

#[tokio::test]
async fn test_resolve_pairing_expired() {
    let (client, server) = setup().await;

    Mock::given(method("GET"))
        .and(path("/v1/pairing/resolve/OLD"))
        .respond_with(ResponseTemplate::new(410).set_body_json(serde_json::json!({
            "error": "expired"
        })))
        .mount(&server)
        .await;

    let err = client.resolve_pairing("OLD").await.unwrap_err();
    assert!(err.is_expired());
}

// ── Presence ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_list_enforcers() {
    let (client, server) = setup().await;

    Mock::given(method("GET"))
        .and(path("/v1/presence/enforcers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {"enforcerDeviceId": "e1", "status": "online"},
            {"enforcerDeviceId": "e2", "status": "online"}
        ])))
        .mount(&server)
        .await;

    let result = client.list_enforcers().await.unwrap();
    assert_eq!(result.len(), 2);
}

// ── Error Edge Cases ─────────────────────────────────────────────

#[tokio::test]
async fn test_unauthorized() {
    let (client, server) = setup().await;

    Mock::given(method("GET"))
        .and(path("/echo"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let err = client.echo().await.unwrap_err();
    assert_eq!(err.status_code(), Some(401));
}

// ── Model Tests ──────────────────────────────────────────────────

#[test]
fn test_decision_deliver_body_helpers() {
    let approve = DecisionDeliverBody {
        artifact_hash: "h".into(),
        decision: "approve".into(),
        reason: None,
        signer_key_id: None,
        nonce: None,
        signature: None,
        decision_hash: None,
    };
    assert!(approve.is_approved());
    assert!(!approve.is_rejected());

    let reject = DecisionDeliverBody {
        artifact_hash: "h".into(),
        decision: "reject".into(),
        reason: None,
        signer_key_id: None,
        nonce: None,
        signature: None,
        decision_hash: None,
    };
    assert!(!reject.is_approved());
    assert!(reject.is_rejected());
}

#[test]
fn test_ciphertext_ref_serialization() {
    let ct = CiphertextRef {
        alg: "aes-256-gcm".into(),
        data: "enc".into(),
        nonce: None,
        tag: None,
        aad: None,
    };

    let json = serde_json::to_string(&ct).unwrap();
    assert!(json.contains("aes-256-gcm"));
    assert!(!json.contains("nonce")); // Omitted when None
}

#[test]
fn test_echo_response_deserialization() {
    let json = r#"{"utc":"2025-01-01","local":"x","timezone":"UTC","offsetMinutes":0}"#;
    let resp: EchoResponse = serde_json::from_str(json).unwrap();
    assert_eq!(resp.timezone, "UTC");
    assert_eq!(resp.offset_minutes, 0);
}

#[test]
fn test_gateway_error_properties() {
    let err = GatewayError::Api {
        status_code: 429,
        error_code: Some("quota_exceeded".into()),
        message: "test".into(),
        response_body: None,
        request_id: None,
    };
    assert!(err.is_quota_exceeded());
    assert!(!err.is_conflict());

    let err2 = GatewayError::Api {
        status_code: 409,
        error_code: None,
        message: "conflict".into(),
        response_body: None,
        request_id: None,
    };
    assert!(err2.is_conflict());
    assert!(!err2.is_quota_exceeded());

    let err3 = GatewayError::Api {
        status_code: 403,
        error_code: Some("pairing_revoked".into()),
        message: "revoked".into(),
        response_body: None,
        request_id: None,
    };
    assert!(err3.is_pairing_revoked());
}
