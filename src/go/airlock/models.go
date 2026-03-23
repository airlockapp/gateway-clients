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

// ArtifactSubmitBody is the body of an artifact.submit envelope.
type ArtifactSubmitBody struct {
	ArtifactType string            `json:"artifactType"`
	ArtifactHash string            `json:"artifactHash"`
	Ciphertext   EncryptedPayload  `json:"ciphertext"`
	ExpiresAt    string            `json:"expiresAt"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// ArtifactSubmitRequest holds options for building an artifact submission.
type ArtifactSubmitRequest struct {
	EnforcerID   string
	ArtifactType string
	ArtifactHash string
	Ciphertext   EncryptedPayload
	ExpiresAt    *time.Time
	Metadata     map[string]string
	RequestID    string
}

// EncryptedArtifactRequest holds options for transparent encrypted submission.
// The SDK handles canonicalization, hashing, and AES-256-GCM encryption.
type EncryptedArtifactRequest struct {
	EnforcerID          string
	ArtifactType        string
	PlaintextPayload    string
	EncryptionKeyBase64 string
	ExpiresAt           *time.Time
	Metadata            map[string]string
	RequestID           string
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

// ── Pairing ─────────────────────────────────────────────────────

// PairingInitiateRequest is the request body for POST /v1/pairing/initiate.
type PairingInitiateRequest struct {
	DeviceID        string `json:"deviceId"`
	EnforcerID      string `json:"enforcerId"`
	GatewayURL      string `json:"gatewayUrl,omitempty"`
	X25519PublicKey string `json:"x25519PublicKey,omitempty"`
	EnforcerLabel   string `json:"enforcerLabel,omitempty"`
	WorkspaceName   string `json:"workspaceName,omitempty"`
}

// PairingInitiateResponse is the response from POST /v1/pairing/initiate.
type PairingInitiateResponse struct {
	PairingNonce string `json:"pairingNonce"`
	PairingCode  string `json:"pairingCode"`
	DeviceID     string `json:"deviceId"`
	GatewayURL   string `json:"gatewayUrl,omitempty"`
	ExpiresAt    string `json:"expiresAt,omitempty"`
}

// PairingStatusResponse is the response from GET /v1/pairing/{nonce}/status.
type PairingStatusResponse struct {
	PairingNonce string `json:"pairingNonce"`
	State        string `json:"state"`
	ResponseJSON string `json:"responseJson,omitempty"`
	RoutingToken string `json:"routingToken,omitempty"`
	ExpiresAt    string `json:"expiresAt,omitempty"`
}

// PairingRevokeResponse is the response from POST /v1/pairing/revoke.
type PairingRevokeResponse struct {
	Status     string `json:"status"`
	EnforcerID string `json:"enforcerId,omitempty"`
}

// PairingClaimRequest is the request body for POST /v1/pairing/claim.
// Used to claim a pre-generated pairing code created by the approver.
type PairingClaimRequest struct {
	PairingCode   string `json:"pairingCode"`
	DeviceID      string `json:"deviceId"`
	EnforcerID    string `json:"enforcerId"`
	EnforcerLabel string `json:"enforcerLabel"`
	WorkspaceName string `json:"workspaceName"`
	GatewayURL    string `json:"gatewayUrl,omitempty"`
	X25519PubKey  string `json:"x25519PublicKey,omitempty"`
}

// PairingClaimResponse is the response from POST /v1/pairing/claim.
type PairingClaimResponse struct {
	PairingNonce string `json:"pairingNonce"`
	ExpiresAt    string `json:"expiresAt,omitempty"`
}

// ── Presence ────────────────────────────────────────────────────

// PresenceHeartbeatRequest is the request body for POST /v1/presence/heartbeat.
type PresenceHeartbeatRequest struct {
	EnforcerID    string `json:"enforcerId"`
	WorkspaceName string `json:"workspaceName,omitempty"`
	EnforcerLabel string `json:"enforcerLabel,omitempty"`
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
type DndPolicy struct {
	RequestID          string                 `json:"requestId"`
	ObjectType         string                 `json:"objectType"`
	WorkspaceID        string                 `json:"workspaceId"`
	SessionID          string                 `json:"sessionId,omitempty"`
	EnforcerID         string                 `json:"enforcerId"`
	PolicyMode         string                 `json:"policyMode"`
	TargetArtifactType string                 `json:"targetArtifactType,omitempty"`
	ActionSelector     map[string]interface{} `json:"actionSelector,omitempty"`
	SelectorHash       string                 `json:"selectorHash,omitempty"`
	CreatedAt          string                 `json:"createdAt,omitempty"`
	ExpiresAt          string                 `json:"expiresAt"`
}

// DndEffectiveResponse is the response from GET /v1/policy/dnd/effective.
type DndEffectiveResponse struct {
	MsgType   string      `json:"msgType"`
	RequestID string      `json:"requestId"`
	Body      []DndPolicy `json:"body"`
}

// ── Auth (Device Authorization Grant) ───────────────────────────

// OidcDiscoveryResult is the subset of OIDC config we need.
type OidcDiscoveryResult struct {
	TokenEndpoint               string `json:"token_endpoint"`
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	RevocationEndpoint          string `json:"revocation_endpoint"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
}

// DeviceCodeInfo is the response from the device_authorization endpoint.
type DeviceCodeInfo struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval,omitempty"`
}

// TokenResponse is the standard OAuth2 token response.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

// TokenErrorResponse is the standard OAuth2 error response.
type TokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// ConsentErrorInfo contains details about a required/pending consent.
type ConsentErrorInfo struct {
	Error      string
	Message    string
	ConsentURL string
	AppName    string
	AppID      string
}
