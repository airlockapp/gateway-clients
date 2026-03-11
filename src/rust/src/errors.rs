//! Error types for the Airlock Gateway client.

use thiserror::Error;

/// Error returned when a Gateway API call fails.
#[derive(Debug, Error)]
pub enum GatewayError {
    /// HTTP-level error from the gateway.
    #[error("gateway error {status_code}: {message}")]
    Api {
        status_code: u16,
        error_code: Option<String>,
        message: String,
        response_body: Option<String>,
        request_id: Option<String>,
    },

    /// Network or transport error.
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    /// JSON serialization/deserialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

impl GatewayError {
    /// True if the error is a rate-limit (429) or quota-exceeded response.
    pub fn is_quota_exceeded(&self) -> bool {
        match self {
            GatewayError::Api {
                status_code,
                error_code,
                ..
            } => {
                *status_code == 429
                    || error_code.as_deref() == Some("quota_exceeded")
                    || error_code.as_deref() == Some("workspace_limit_exceeded")
            }
            _ => false,
        }
    }

    /// True if the pairing was revoked.
    pub fn is_pairing_revoked(&self) -> bool {
        matches!(self, GatewayError::Api { error_code, .. } if error_code.as_deref() == Some("pairing_revoked"))
    }

    /// True if the error indicates an expired resource (410 or "expired" code).
    pub fn is_expired(&self) -> bool {
        match self {
            GatewayError::Api {
                status_code,
                error_code,
                ..
            } => *status_code == 410 || error_code.as_deref() == Some("expired"),
            _ => false,
        }
    }

    /// True if the error is an idempotency conflict (409).
    pub fn is_conflict(&self) -> bool {
        matches!(self, GatewayError::Api { status_code, .. } if *status_code == 409)
    }

    /// HTTP status code, if available.
    pub fn status_code(&self) -> Option<u16> {
        match self {
            GatewayError::Api { status_code, .. } => Some(*status_code),
            _ => None,
        }
    }

    /// Error code from the gateway, if available.
    pub fn error_code(&self) -> Option<&str> {
        match self {
            GatewayError::Api { error_code, .. } => error_code.as_deref(),
            _ => None,
        }
    }
}
