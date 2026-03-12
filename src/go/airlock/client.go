package airlock

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client is an HTTP client for the Airlock Gateway API.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// NewClient creates a new Airlock Gateway client.
// The baseURL should be the gateway's root URL (e.g., "https://gw.example.com").
func NewClient(baseURL, token string) *Client {
	return &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 90 * time.Second,
		},
	}
}

// WithHTTPClient sets a custom http.Client (useful for testing).
func (c *Client) WithHTTPClient(hc *http.Client) *Client {
	c.httpClient = hc
	return c
}

// ── Discovery ───────────────────────────────────────────────────

// Echo calls GET /echo for gateway discovery and health.
func (c *Client) Echo() (*EchoResponse, error) {
	var resp EchoResponse
	if err := c.doGet("/echo", &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ── Artifacts ───────────────────────────────────────────────────

// SubmitArtifact posts an artifact for approval. Returns the request ID.
func (c *Client) SubmitArtifact(req ArtifactSubmitRequest) (string, error) {
	requestID := req.RequestID
	if requestID == "" {
		requestID = fmt.Sprintf("req-%d", time.Now().UnixNano())
	}

	expiresAt := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339)
	if req.ExpiresAt != nil {
		expiresAt = req.ExpiresAt.Format(time.RFC3339)
	}

	artifactType := req.ArtifactType
	if artifactType == "" {
		artifactType = "command-approval"
	}

	envelope := HarpEnvelope{
		MsgID:     fmt.Sprintf("msg-%d", time.Now().UnixNano()),
		MsgType:   "artifact.submit",
		RequestID: requestID,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Sender:    &SenderInfo{EnforcerID: req.EnforcerID},
		Body: ArtifactSubmitBody{
			ArtifactType: artifactType,
			ArtifactHash: req.ArtifactHash,
			Ciphertext:   req.Ciphertext,
			ExpiresAt:    expiresAt,
			Metadata:     req.Metadata,
		},
	}

	return requestID, c.doPost("/v1/artifacts", envelope, nil)
}

// ── Exchanges ───────────────────────────────────────────────────

// GetExchangeStatus calls GET /v1/exchanges/{requestId}.
func (c *Client) GetExchangeStatus(requestID string) (*ExchangeStatusResponse, error) {
	var resp ExchangeStatusResponse
	path := fmt.Sprintf("/v1/exchanges/%s", url.PathEscape(requestID))
	if err := c.doGet(path, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// WaitForDecision calls GET /v1/exchanges/{requestId}/wait with long-poll.
// Returns nil, nil if the server returns 204 (no decision yet).
func (c *Client) WaitForDecision(requestID string, timeoutSec int) (*DecisionDeliverEnvelope, error) {
	if timeoutSec < 1 {
		timeoutSec = 1
	} else if timeoutSec > 60 {
		timeoutSec = 60
	}

	path := fmt.Sprintf("/v1/exchanges/%s/wait?timeout=%d", url.PathEscape(requestID), timeoutSec)

	resp, body, err := c.rawRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusNoContent {
		return nil, nil
	}

	if err := checkStatus(resp, body); err != nil {
		return nil, err
	}

	var envelope DecisionDeliverEnvelope
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return &envelope, nil
}

// WithdrawExchange calls POST /v1/exchanges/{requestId}/withdraw.
func (c *Client) WithdrawExchange(requestID string) error {
	path := fmt.Sprintf("/v1/exchanges/%s/withdraw", url.PathEscape(requestID))
	return c.doPost(path, nil, nil)
}

// ── Acknowledgements ────────────────────────────────────────────

// Acknowledge calls POST /v1/acks.
func (c *Client) Acknowledge(msgID, enforcerID string) error {
	envelope := HarpEnvelope{
		MsgID:     fmt.Sprintf("msg-%d", time.Now().UnixNano()),
		MsgType:   "ack.submit",
		RequestID: fmt.Sprintf("ack-%d", time.Now().UnixNano()),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Sender:    &SenderInfo{EnforcerID: enforcerID},
		Body: AckSubmitBody{
			MsgID:  msgID,
			Status: "acknowledged",
			AckAt:  time.Now().UTC().Format(time.RFC3339),
		},
	}
	return c.doPost("/v1/acks", envelope, nil)
}

// ── Pairing ─────────────────────────────────────────────────────

// InitiatePairing calls POST /v1/pairing/initiate.
func (c *Client) InitiatePairing(req PairingInitiateRequest) (*PairingInitiateResponse, error) {
	var resp PairingInitiateResponse
	if err := c.doPost("/v1/pairing/initiate", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ResolvePairing calls GET /v1/pairing/resolve/{code}.
func (c *Client) ResolvePairing(code string) (*PairingResolveResponse, error) {
	var resp PairingResolveResponse
	if err := c.doGet(fmt.Sprintf("/v1/pairing/resolve/%s", url.PathEscape(code)), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetPairingStatus calls GET /v1/pairing/{nonce}/status.
func (c *Client) GetPairingStatus(nonce string) (*PairingStatusResponse, error) {
	var resp PairingStatusResponse
	if err := c.doGet(fmt.Sprintf("/v1/pairing/%s/status", url.PathEscape(nonce)), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// CompletePairing calls POST /v1/pairing/complete.
func (c *Client) CompletePairing(req PairingCompleteRequest) (*PairingCompleteResponse, error) {
	var resp PairingCompleteResponse
	if err := c.doPost("/v1/pairing/complete", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// RevokePairing calls POST /v1/pairing/revoke.
func (c *Client) RevokePairing(routingToken string) (*PairingRevokeResponse, error) {
	var resp PairingRevokeResponse
	body := struct {
		RoutingToken string `json:"routingToken"`
	}{RoutingToken: routingToken}
	if err := c.doPost("/v1/pairing/revoke", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GetPairingStatusBatch calls POST /v1/pairing/status-batch.
func (c *Client) GetPairingStatusBatch(routingTokens []string) (*PairingStatusBatchResponse, error) {
	var resp PairingStatusBatchResponse
	body := struct {
		RoutingTokens []string `json:"routingTokens"`
	}{RoutingTokens: routingTokens}
	if err := c.doPost("/v1/pairing/status-batch", body, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ── Presence ────────────────────────────────────────────────────

// SendHeartbeat calls POST /v1/presence/heartbeat.
func (c *Client) SendHeartbeat(req PresenceHeartbeatRequest) error {
	return c.doPost("/v1/presence/heartbeat", req, nil)
}

// ListEnforcers calls GET /v1/presence/enforcers.
func (c *Client) ListEnforcers() ([]EnforcerPresenceRecord, error) {
	var resp []EnforcerPresenceRecord
	if err := c.doGet("/v1/presence/enforcers", &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// GetEnforcerPresence calls GET /v1/presence/enforcers/{id}.
func (c *Client) GetEnforcerPresence(enforcerDeviceID string) (*EnforcerPresenceRecord, error) {
	var resp EnforcerPresenceRecord
	if err := c.doGet(fmt.Sprintf("/v1/presence/enforcers/%s", url.PathEscape(enforcerDeviceID)), &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ── DND (Do Not Disturb) Policies ────────────────────────────────

// SubmitDndPolicy calls POST /v1/policy/dnd with a signed DND policy object.
// The payload should already be a canonical, signed policy JSON object.
func (c *Client) SubmitDndPolicy(policy interface{}) error {
	return c.doPost("/v1/policy/dnd", policy, nil)
}

// GetEffectiveDndPolicies calls GET /v1/policy/dnd/effective and returns the
// effective policies for the given enforcer/workspace/session.
func (c *Client) GetEffectiveDndPolicies(enforcerID, workspaceID, sessionID string) (*DndEffectiveResponse, error) {
	values := url.Values{}
	values.Set("enforcerId", enforcerID)
	values.Set("workspaceId", workspaceID)
	if sessionID != "" {
		values.Set("sessionId", sessionID)
	}
	path := "/v1/policy/dnd/effective?" + values.Encode()

	var resp DndEffectiveResponse
	if err := c.doGet(path, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// ── HTTP Helpers ────────────────────────────────────────────────

func (c *Client) doGet(path string, out interface{}) error {
	resp, body, err := c.rawRequest("GET", path, nil)
	if err != nil {
		return err
	}
	if err := checkStatus(resp, body); err != nil {
		return err
	}
	if out != nil {
		return json.Unmarshal(body, out)
	}
	return nil
}

func (c *Client) doPost(path string, payload interface{}, out interface{}) error {
	var bodyReader io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	resp, body, err := c.rawRequest("POST", path, bodyReader)
	if err != nil {
		return err
	}
	if err := checkStatus(resp, body); err != nil {
		return err
	}
	if out != nil && len(body) > 0 {
		return json.Unmarshal(body, out)
	}
	return nil
}

func (c *Client) rawRequest(method, path string, body io.Reader) (*http.Response, []byte, error) {
	reqURL := c.baseURL + path
	req, err := http.NewRequest(method, reqURL, body)
	if err != nil {
		return nil, nil, err
	}

	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}
	return resp, respBody, nil
}

func checkStatus(resp *http.Response, body []byte) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	gwErr := &GatewayError{
		StatusCode:   resp.StatusCode,
		ResponseBody: string(body),
	}

	// Try to parse HARP error envelope
	var envelope struct {
		Body *struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"requestId"`
		} `json:"body"`
		Error   string `json:"error"`
		Message string `json:"message"`
	}

	if json.Unmarshal(body, &envelope) == nil {
		if envelope.Body != nil {
			gwErr.ErrorCode = envelope.Body.Code
			gwErr.Message = envelope.Body.Message
			gwErr.RequestID = envelope.Body.RequestID
		} else {
			gwErr.ErrorCode = envelope.Error
			gwErr.Message = envelope.Message
		}
	}

	if gwErr.Message == "" {
		gwErr.Message = fmt.Sprintf("Gateway returned %d", resp.StatusCode)
	}

	return gwErr
}
