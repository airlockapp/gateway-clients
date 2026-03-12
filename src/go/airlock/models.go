package airlock

import "time"

// HarpEnvelope is the HARP Gateway Wire Envelope.
type HarpEnvelope struct {
	MsgID     string      `json:"msgId,omitempty"`
	MsgType   string      `json:"msgType"`
	RequestID string      `json:"requestId"`
	CreatedAt string      `json:"createdAt,omitempty"`
	ExpiresAt string      `json:"expiresAt,omitempty"`
	Sender    *SenderInfo `json:"sender,omitempty"`
	Recipient *RecipInfo  `json:"recipient,omitempty"`
	Body      interface{} `json:"body,omitempty"`
}

// SenderInfo identifies the sender of a HARP message.
type SenderInfo struct {
	EnforcerID string `json:"enforcerId,omitempty"`
	ApproverID string `json:"approverId,omitempty"`
	GatewayID  string `json:"gatewayId,omitempty"`
}

// RecipInfo identifies the recipient of a HARP message.
type RecipInfo struct {
	EnforcerID string `json:"enforcerId,omitempty"`
	ApproverID string `json:"approverId,omitempty"`
}

// ── Artifact Submit ─────────────────────────────────────────────

// CiphertextRef is an encrypted payload reference.
type CiphertextRef struct {
	Alg   string `json:"alg"`
	Data  string `json:"data"`
	Nonce string `json:"nonce,omitempty"`
	Tag   string `json:"tag,omitempty"`
	Aad   string `json:"aad,omitempty"`
}

// ArtifactSubmitBody is the body of an artifact.submit envelope.
type ArtifactSubmitBody struct {
	ArtifactType string            `json:"artifactType"`
	ArtifactHash string            `json:"artifactHash"`
	Ciphertext   CiphertextRef     `json:"ciphertext"`
	ExpiresAt    string            `json:"expiresAt"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// ArtifactSubmitRequest holds options for building an artifact submission.
type ArtifactSubmitRequest struct {
	EnforcerID   string
	ArtifactType string
	ArtifactHash string
	Ciphertext   CiphertextRef
	ExpiresAt    *time.Time
	Metadata     map[string]string
	RequestID    string
}

// ── Decision ────────────────────────────────────────────────────

// DecisionDeliverBody is the body of a decision.deliver envelope.
type DecisionDeliverBody struct {
	ArtifactHash string `json:"artifactHash"`
	Decision     string `json:"decision"`
	Reason       string `json:"reason,omitempty"`
	SignerKeyID  string `json:"signerKeyId,omitempty"`
	Nonce        string `json:"nonce,omitempty"`
	Signature    string `json:"signature,omitempty"`
	DecisionHash string `json:"decisionHash,omitempty"`
}

// IsApproved returns true if the decision is "approve".
func (d *DecisionDeliverBody) IsApproved() bool {
	return d.Decision == "approve"
}

// IsRejected returns true if the decision is "reject".
func (d *DecisionDeliverBody) IsRejected() bool {
	return d.Decision == "reject"
}

// DecisionDeliverEnvelope wraps a decision.deliver response.
type DecisionDeliverEnvelope struct {
	MsgID     string               `json:"msgId,omitempty"`
	MsgType   string               `json:"msgType"`
	RequestID string               `json:"requestId"`
	Body      *DecisionDeliverBody `json:"body,omitempty"`
}

// ── Exchange Status ─────────────────────────────────────────────

// ExchangeStatusBody holds exchange state information.
type ExchangeStatusBody struct {
	RequestID    string      `json:"requestId"`
	State        string      `json:"state"`
	CreatedAt    string      `json:"createdAt,omitempty"`
	ExpiresAt    string      `json:"expiresAt,omitempty"`
	ArtifactHash string      `json:"artifactHash,omitempty"`
	Decision     interface{} `json:"decision,omitempty"`
}

// ExchangeStatusResponse wraps a GET /v1/exchanges/{id} response.
type ExchangeStatusResponse struct {
	MsgType   string              `json:"msgType"`
	RequestID string              `json:"requestId"`
	Body      *ExchangeStatusBody `json:"body,omitempty"`
}

// ── Ack ─────────────────────────────────────────────────────────

// AckSubmitBody is the body of an ack.submit envelope.
type AckSubmitBody struct {
	MsgID  string `json:"msgId"`
	Status string `json:"status"`
	AckAt  string `json:"ackAt"`
}

// ── Pairing ─────────────────────────────────────────────────────

// PairingInitiateRequest is the request body for POST /v1/pairing/initiate.
type PairingInitiateRequest struct {
	DeviceID       string `json:"deviceId"`
	EnforcerID     string `json:"enforcerId"`
	GatewayURL     string `json:"gatewayUrl,omitempty"`
	X25519PublicKey string `json:"x25519PublicKey,omitempty"`
	EnforcerLabel  string `json:"enforcerLabel,omitempty"`
	WorkspaceName  string `json:"workspaceName,omitempty"`
}

// PairingInitiateResponse is the response from POST /v1/pairing/initiate.
type PairingInitiateResponse struct {
	PairingNonce string `json:"pairingNonce"`
	PairingCode  string `json:"pairingCode"`
	DeviceID     string `json:"deviceId"`
	GatewayURL   string `json:"gatewayUrl,omitempty"`
	ExpiresAt    string `json:"expiresAt,omitempty"`
}

// PairingResolveResponse is the response from GET /v1/pairing/resolve/{code}.
type PairingResolveResponse struct {
	PairingNonce    string `json:"pairingNonce"`
	DeviceID        string `json:"deviceId"`
	GatewayURL      string `json:"gatewayUrl,omitempty"`
	ExpiresAt       string `json:"expiresAt,omitempty"`
	X25519PublicKey string `json:"x25519PublicKey,omitempty"`
	EnforcerLabel   string `json:"enforcerLabel,omitempty"`
	WorkspaceName   string `json:"workspaceName,omitempty"`
}

// PairingStatusResponse is the response from GET /v1/pairing/{nonce}/status.
type PairingStatusResponse struct {
	PairingNonce string `json:"pairingNonce"`
	State        string `json:"state"`
	ResponseJSON string `json:"responseJson,omitempty"`
	RoutingToken string `json:"routingToken,omitempty"`
	ExpiresAt    string `json:"expiresAt,omitempty"`
}

// PairingCompleteRequest is the request body for POST /v1/pairing/complete.
type PairingCompleteRequest struct {
	PairingNonce string `json:"pairingNonce"`
	ResponseJSON string `json:"responseJson,omitempty"`
}

// PairingCompleteResponse is the response from POST /v1/pairing/complete.
type PairingCompleteResponse struct {
	Status       string `json:"status"`
	PairingNonce string `json:"pairingNonce"`
	RoutingToken string `json:"routingToken,omitempty"`
}

// PairingRevokeResponse is the response from POST /v1/pairing/revoke.
type PairingRevokeResponse struct {
	Status     string `json:"status"`
	EnforcerID string `json:"enforcerId,omitempty"`
}

// PairingStatusBatchResponse is the response from POST /v1/pairing/status-batch.
type PairingStatusBatchResponse struct {
	Statuses map[string]string `json:"statuses"`
}

// ── Presence ────────────────────────────────────────────────────

// PresenceHeartbeatRequest is the request body for POST /v1/presence/heartbeat.
type PresenceHeartbeatRequest struct {
	EnforcerID    string `json:"enforcerId"`
	WorkspaceName string `json:"workspaceName,omitempty"`
	EnforcerLabel string `json:"enforcerLabel,omitempty"`
}

// EnforcerPresenceRecord represents a connected enforcer.
type EnforcerPresenceRecord struct {
	EnforcerDeviceID string            `json:"enforcerDeviceId"`
	Status           string            `json:"status"`
	LastSeenAt       string            `json:"lastSeenAt,omitempty"`
	Transport        string            `json:"transport,omitempty"`
	Capabilities     map[string]string `json:"capabilities,omitempty"`
	WorkspaceName    string            `json:"workspaceName,omitempty"`
	EnforcerLabel    string            `json:"enforcerLabel,omitempty"`
}

// ── Echo ────────────────────────────────────────────────────────

// EchoResponse is the response from GET /echo.
type EchoResponse struct {
	UTC           string `json:"utc"`
	Local         string `json:"local"`
	Timezone      string `json:"timezone"`
	OffsetMinutes int    `json:"offsetMinutes"`
}

// ── DND (Do Not Disturb) Policies ────────────────────────────────

// DndPolicy represents a DND policy object as returned by the gateway.
// This type intentionally mirrors the wire shape but keeps most fields generic
// so the SDK does not have to understand all possible extensions.
type DndPolicy struct {
	RequestID         string                 `json:"requestId"`
	ObjectType        string                 `json:"objectType"`
	WorkspaceID       string                 `json:"workspaceId"`
	SessionID         string                 `json:"sessionId,omitempty"`
	EnforcerID        string                 `json:"enforcerId"`
	PolicyMode        string                 `json:"policyMode"`
	TargetArtifactType string                `json:"targetArtifactType,omitempty"`
	ActionSelector    map[string]interface{} `json:"actionSelector,omitempty"`
	SelectorHash      string                 `json:"selectorHash,omitempty"`
	CreatedAt         string                 `json:"createdAt,omitempty"`
	ExpiresAt         string                 `json:"expiresAt"`
}

// DndEffectiveResponse is the response from GET /v1/policy/dnd/effective.
type DndEffectiveResponse struct {
	MsgType   string      `json:"msgType"`
	RequestID string      `json:"requestId"`
	Body      []DndPolicy `json:"body"`
}
