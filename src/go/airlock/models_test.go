package airlock

import (
	"encoding/json"
	"testing"
)

func TestHarpEnvelope_RoundTrips(t *testing.T) {
	envelope := HarpEnvelope{
		MsgID:     "msg-1",
		MsgType:   "artifact.submit",
		RequestID: "req-1",
		Sender:    &SenderInfo{EnforcerID: "e1"},
	}

	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var restored HarpEnvelope
	if err := json.Unmarshal(data, &restored); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if restored.MsgID != "msg-1" {
		t.Errorf("expected msg-1, got %s", restored.MsgID)
	}
	if restored.MsgType != "artifact.submit" {
		t.Errorf("expected artifact.submit, got %s", restored.MsgType)
	}
}

func TestEncryptedPayload_OmitsEmpty(t *testing.T) {
	ref := EncryptedPayload{Alg: "aes-256-gcm", Data: "enc"}

	data, _ := json.Marshal(ref)
	var m map[string]interface{}
	json.Unmarshal(data, &m)

	if _, ok := m["nonce"]; ok {
		t.Error("expected nonce to be omitted")
	}
	if _, ok := m["tag"]; ok {
		t.Error("expected tag to be omitted")
	}
}

func TestDecisionDeliverBody_Helpers(t *testing.T) {
	approve := DecisionDeliverBody{Decision: "approve"}
	if !approve.IsApproved() {
		t.Error("expected IsApproved to be true")
	}
	if approve.IsRejected() {
		t.Error("expected IsRejected to be false")
	}

	reject := DecisionDeliverBody{Decision: "reject"}
	if reject.IsApproved() {
		t.Error("expected IsApproved to be false")
	}
	if !reject.IsRejected() {
		t.Error("expected IsRejected to be true")
	}
}

func TestPairingInitiateRequest_Serializes(t *testing.T) {
	req := PairingInitiateRequest{
		DeviceID:      "dev-1",
		EnforcerID:    "e-1",
		EnforcerLabel: "Cursor",
	}

	data, _ := json.Marshal(req)
	var m map[string]interface{}
	json.Unmarshal(data, &m)

	if m["deviceId"] != "dev-1" {
		t.Errorf("expected dev-1, got %v", m["deviceId"])
	}
	if m["enforcerId"] != "e-1" {
		t.Errorf("expected e-1, got %v", m["enforcerId"])
	}
}



func TestEchoResponse_Deserializes(t *testing.T) {
	raw := `{"utc":"2025-01-01T00:00:00Z","local":"x","timezone":"Europe/Istanbul","offsetMinutes":180}`
	var resp EchoResponse
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if resp.Timezone != "Europe/Istanbul" {
		t.Errorf("expected Europe/Istanbul, got %s", resp.Timezone)
	}
	if resp.OffsetMinutes != 180 {
		t.Errorf("expected 180, got %d", resp.OffsetMinutes)
	}
}



func TestGatewayError_Properties(t *testing.T) {
	tests := []struct {
		name     string
		err      GatewayError
		quota    bool
		revoked  bool
		expired  bool
		conflict bool
	}{
		{"429", GatewayError{StatusCode: 429}, true, false, false, false},
		{"quota_exceeded", GatewayError{ErrorCode: "quota_exceeded"}, true, false, false, false},
		{"workspace_limit", GatewayError{ErrorCode: "workspace_limit_exceeded"}, true, false, false, false},
		{"pairing_revoked", GatewayError{ErrorCode: "pairing_revoked"}, false, true, false, false},
		{"410", GatewayError{StatusCode: 410}, false, false, true, false},
		{"expired", GatewayError{ErrorCode: "expired"}, false, false, true, false},
		{"409", GatewayError{StatusCode: 409}, false, false, false, true},
		{"other", GatewayError{StatusCode: 400, ErrorCode: "bad_request"}, false, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.IsQuotaExceeded() != tt.quota {
				t.Errorf("IsQuotaExceeded: expected %v", tt.quota)
			}
			if tt.err.IsPairingRevoked() != tt.revoked {
				t.Errorf("IsPairingRevoked: expected %v", tt.revoked)
			}
			if tt.err.IsExpired() != tt.expired {
				t.Errorf("IsExpired: expected %v", tt.expired)
			}
			if tt.err.IsConflict() != tt.conflict {
				t.Errorf("IsConflict: expected %v", tt.conflict)
			}
		})
	}
}
