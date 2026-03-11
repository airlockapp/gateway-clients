// Package airlock provides a client SDK for the Airlock Gateway API.
//
// The client covers all enforcer-side endpoints: artifact submission,
// exchange polling, pairing management, presence tracking, and gateway discovery.
package airlock

import "fmt"

// GatewayError represents an error response from the Airlock Gateway.
type GatewayError struct {
	// HTTP status code.
	StatusCode int
	// Error code from the gateway (e.g., "no_approver", "quota_exceeded").
	ErrorCode string
	// Human-readable error message.
	Message string
	// Raw response body.
	ResponseBody string
	// Request ID associated with the failed operation.
	RequestID string
}

func (e *GatewayError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("gateway error %d (%s): %s", e.StatusCode, e.ErrorCode, e.Message)
	}
	return fmt.Sprintf("gateway error %d", e.StatusCode)
}

// IsQuotaExceeded returns true if the error is a rate-limit (429) or quota-exceeded response.
func (e *GatewayError) IsQuotaExceeded() bool {
	return e.StatusCode == 429 || e.ErrorCode == "quota_exceeded" || e.ErrorCode == "workspace_limit_exceeded"
}

// IsPairingRevoked returns true if the pairing was revoked.
func (e *GatewayError) IsPairingRevoked() bool {
	return e.ErrorCode == "pairing_revoked"
}

// IsExpired returns true if the error indicates an expired resource.
func (e *GatewayError) IsExpired() bool {
	return e.StatusCode == 410 || e.ErrorCode == "expired"
}

// IsConflict returns true if the error is an idempotency conflict (409).
func (e *GatewayError) IsConflict() bool {
	return e.StatusCode == 409
}
