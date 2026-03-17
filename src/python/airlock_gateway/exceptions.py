"""Typed exceptions for Airlock Gateway API errors."""

from __future__ import annotations


class AirlockGatewayError(Exception):
    """Raised when a Gateway API call returns an error response."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        error_code: str | None = None,
        response_body: str | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.response_body = response_body
        self.request_id = request_id

    @property
    def is_quota_exceeded(self) -> bool:
        """True if the error is a rate-limit (429) or quota-exceeded response."""
        return (
            self.status_code == 429
            or (self.error_code or "").lower() in ("quota_exceeded", "workspace_limit_exceeded")
        )

    @property
    def is_pairing_revoked(self) -> bool:
        """True if the pairing was revoked (403 pairing_revoked)."""
        return (self.error_code or "").lower() == "pairing_revoked"

    @property
    def is_expired(self) -> bool:
        """True if the error indicates an expired resource (410 or 422 expired)."""
        return self.status_code == 410 or (self.error_code or "").lower() == "expired"

    @property
    def is_conflict(self) -> bool:
        """True if the error is an idempotency conflict (409)."""
        return self.status_code == 409


class AirlockAuthException(Exception):
    """Raised for authentication errors in the AirlockAuthClient."""
    pass
