package airlock

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// helper: create a test server + client pointing at it.
func setupTest(handler http.HandlerFunc) (*Client, *httptest.Server) {
	server := httptest.NewServer(handler)
	client := NewClient(server.URL, "test-token")
	client.WithHTTPClient(server.Client())
	return client, server
}

// ── Echo ─────────────────────────────────────────────────────────

func TestEcho(t *testing.T) {
	client, server := setupTest(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/echo" {
			t.Errorf("expected /echo, got %s", r.URL.Path)
		}
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"utc":"2025-01-01T00:00:00Z","local":"x","timezone":"Europe/Istanbul","offsetMinutes":180}`)
	})
	defer server.Close()

	resp, err := client.Echo()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Timezone != "Europe/Istanbul" {
		t.Errorf("expected Europe/Istanbul, got %s", resp.Timezone)
	}
	if resp.OffsetMinutes != 180 {
		t.Errorf("expected 180, got %d", resp.OffsetMinutes)
	}
}

// ── SubmitArtifact ───────────────────────────────────────────────

func TestSubmitArtifact(t *testing.T) {
	client, server := setupTest(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/artifacts" {
			t.Errorf("expected /v1/artifacts, got %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("expected Bearer test-token")
		}

		var envelope HarpEnvelope
		json.NewDecoder(r.Body).Decode(&envelope)
		if envelope.MsgType != "artifact.submit" {
			t.Errorf("expected artifact.submit, got %s", envelope.MsgType)
		}

		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, `{"msgType":"artifact.accepted"}`)
	})
	defer server.Close()

	reqID, err := client.SubmitArtifact(ArtifactSubmitRequest{
		EnforcerID:   "enforcer-1",
		ArtifactHash: "abc123",
		Ciphertext:   EncryptedPayload{Alg: "aes-256-gcm", Data: "encrypted"},
		RequestID:    "req-test123",
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqID != "req-test123" {
		t.Errorf("expected req-test123, got %s", reqID)
	}
}

func TestEncryptAndSubmitArtifact(t *testing.T) {
	keyB64 := ToBase64URL(bytes.Repeat([]byte{7}, 32))

	client, server := setupTest(func(w http.ResponseWriter, r *http.Request) {
		var envelope HarpEnvelope
		_ = json.NewDecoder(r.Body).Decode(&envelope)
		raw, _ := json.Marshal(envelope.Body)
		s := string(raw)
		if !strings.Contains(s, "d3c2d7effb479ffc5085aad2144df886a452a4863396060f4e0ea29a8409d0fd") {
			t.Errorf("expected canonical artifact hash in body, got %s", s)
		}
		if !strings.Contains(s, "AES-256-GCM") {
			t.Errorf("expected AES-256-GCM ciphertext, got %s", s)
		}
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, `{}`)
	})
	defer server.Close()

	reqID, err := client.EncryptAndSubmitArtifact(EncryptedArtifactRequest{
		EnforcerID:            "e1",
		PlaintextPayload:      `{"value":42,"action":"test"}`,
		EncryptionKeyBase64:   keyB64,
		RequestID:             "req-enc",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqID != "req-enc" {
		t.Errorf("expected req-enc, got %s", reqID)
	}
}

func TestSubmitArtifact_GeneratesRequestID(t *testing.T) {
	client, server := setupTest(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		fmt.Fprint(w, `{}`)
	})
	defer server.Close()

	reqID, err := client.SubmitArtifact(ArtifactSubmitRequest{
		EnforcerID:   "e1",
		ArtifactHash: "h1",
		Ciphertext:   EncryptedPayload{Alg: "aes-256-gcm", Data: "d"},
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(reqID, "req-") {
		t.Errorf("expected req- prefix, got %s", reqID)
	}
}

func TestSubmitArtifact_ReturnsGatewayErrorOnNoApprover(t *testing.T) {
	client, server := setupTest(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(422)
		fmt.Fprint(w, `{"msgType":"error","body":{"code":"no_approver","message":"No approver available."}}`)
	})
	defer server.Close()

	_, err := client.SubmitArtifact(ArtifactSubmitRequest{
		EnforcerID:   "e1",
		ArtifactHash: "h1",
		Ciphertext:   EncryptedPayload{Alg: "aes-256-gcm", Data: "d"},
	})

	gwErr, ok := err.(*GatewayError)
	if !ok {
		t.Fatalf("expected GatewayError, got %T", err)
	}
	if gwErr.ErrorCode != "no_approver" {
		t.Errorf("expected no_approver, got %s", gwErr.ErrorCode)
	}
}

func TestSubmitArtifact_QuotaExceeded(t *testing.T) {
	client, server := setupTest(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		fmt.Fprint(w, `{"body":{"code":"quota_exceeded"}}`)
	})
	defer server.Close()

	_, err := client.SubmitArtifact(ArtifactSubmitRequest{
		EnforcerID: "e1", ArtifactHash: "h1",
		Ciphertext: EncryptedPayload{Alg: "aes-256-gcm", Data: "d"},
	})

	gwErr := err.(*GatewayError)
	if !gwErr.IsQuotaExceeded() {
		t.Error("expected IsQuotaExceeded to be true")
	}
}

func TestSubmitArtifact_Conflict(t *testing.T) {
	client, server := setupTest(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		fmt.Fprint(w, `{"body":{"code":"AlreadyExistsConflict"}}`)
	})
	defer server.Close()

	_, err := client.SubmitArtifact(ArtifactSubmitRequest{
		EnforcerID: "e1", ArtifactHash: "h1",
		Ciphertext: EncryptedPayload{Alg: "aes-256-gcm", Data: "d"},
	})

	gwErr := err.(*GatewayError)
	if !gwErr.IsConflict() {
		t.Error("expected IsConflict to be true")
	}
}

// ── DND (Do Not Disturb) Policies ────────────────────────────────

func TestGetEffectiveDndPolicies(t *testing.T) {
	client, server := setupTest(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/policy/dnd/effective") {
			t.Errorf("expected /v1/policy/dnd/effective, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{
			"msgType": "dnd.policy.effective",
			"requestId": "dnd-effective-1",
			"body": [
				{
					"requestId": "p1",
					"objectType": "airlock.dnd.workspace",
					"workspaceId": "ws-1",
					"enforcerId": "enf-1",
					"policyMode": "approve_all",
					"expiresAt": "2099-01-01T00:00:00Z"
				}
			]
		}`)
	})
	defer server.Close()

	resp, err := client.GetEffectiveDndPolicies("enf-1", "ws-1", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.MsgType != "dnd.policy.effective" {
		t.Fatalf("unexpected msgType: %s", resp.MsgType)
	}
	if len(resp.Body) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(resp.Body))
	}
	if resp.Body[0].PolicyMode != "approve_all" {
		t.Fatalf("unexpected policyMode: %s", resp.Body[0].PolicyMode)
	}
}

// ── WaitForDecision ─────────────────────────────────────────────

func TestWaitForDecision_ReturnsDecision(t *testing.T) {
	client, server := setupTest(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"msgType":"decision.deliver","requestId":"req-1","body":{"decision":"approve","reason":"OK"}}`)
	})
	defer server.Close()

	result, err := client.WaitForDecision("req-1", 30)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Body.Decision != "approve" {
		t.Errorf("expected approve, got %s", result.Body.Decision)
	}
	if !result.Body.IsApproved() {
		t.Error("expected IsApproved to be true")
	}
}

func TestWaitForDecision_ReturnsNilOn204(t *testing.T) {
	client, server := setupTest(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	defer server.Close()

	result, err := client.WaitForDecision("req-1", 5)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != nil {
		t.Error("expected nil result on 204")
	}
}

func TestWaitForDecision_ClampsTimeout(t *testing.T) {
	client, server := setupTest(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.RawQuery, "timeout=60") {
			t.Errorf("expected timeout=60, got %s", r.URL.RawQuery)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	defer server.Close()

	client.WaitForDecision("req-1", 200)
}

// ── Withdraw ────────────────────────────────────────────────────

func TestWithdrawExchange(t *testing.T) {
	client, server := setupTest(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/exchanges/req-1/withdraw" {
			t.Errorf("expected /v1/exchanges/req-1/withdraw, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{}`)
	})
	defer server.Close()

	err := client.WithdrawExchange("req-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}



// ── Pairing ─────────────────────────────────────────────────────

func TestInitiatePairing(t *testing.T) {
	client, server := setupTest(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, `{"pairingNonce":"n1","pairingCode":"ABC123","deviceId":"d1"}`)
	})
	defer server.Close()

	resp, err := client.InitiatePairing(PairingInitiateRequest{
		DeviceID: "d1", EnforcerID: "e1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.PairingCode != "ABC123" {
		t.Errorf("expected ABC123, got %s", resp.PairingCode)
	}
}



func TestGetPairingStatus(t *testing.T) {
	client, server := setupTest(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"pairingNonce":"n1","state":"Completed","routingToken":"rt-1"}`)
	})
	defer server.Close()

	resp, err := client.GetPairingStatus("n1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.State != "Completed" {
		t.Errorf("expected Completed, got %s", resp.State)
	}
}



func TestRevokePairing(t *testing.T) {
	client, server := setupTest(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"revoked","enforcerId":"e-1"}`)
	})
	defer server.Close()

	resp, err := client.RevokePairing("rt-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Status != "revoked" {
		t.Errorf("expected revoked, got %s", resp.Status)
	}
}



// ── Presence ────────────────────────────────────────────────────

func TestSendHeartbeat(t *testing.T) {
	client, server := setupTest(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/presence/heartbeat" {
			t.Errorf("expected /v1/presence/heartbeat, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{}`)
	})
	defer server.Close()

	err := client.SendHeartbeat(PresenceHeartbeatRequest{EnforcerID: "e-1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}



// ── Error Edge Cases ────────────────────────────────────────────

func TestEcho_Unauthorized(t *testing.T) {
	client, server := setupTest(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	})
	defer server.Close()

	_, err := client.Echo()
	gwErr := err.(*GatewayError)
	if gwErr.StatusCode != 401 {
		t.Errorf("expected 401, got %d", gwErr.StatusCode)
	}
}

func TestEcho_NonJsonError(t *testing.T) {
	client, server := setupTest(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprint(w, "Internal Server Error")
	})
	defer server.Close()

	_, err := client.Echo()
	gwErr := err.(*GatewayError)
	if gwErr.StatusCode != 500 {
		t.Errorf("expected 500, got %d", gwErr.StatusCode)
	}
	if !strings.Contains(gwErr.ResponseBody, "Internal Server Error") {
		t.Error("expected response body to contain 'Internal Server Error'")
	}
}
