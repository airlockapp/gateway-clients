import time
import json
import hashlib
import os
import base64
import asyncio
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, urlparse, parse_qs
from datetime import datetime, timedelta, timezone
from typing import Optional, Callable, Dict, Any, Tuple
from dataclasses import dataclass
import httpx
import threading

from .models import DeviceCodeInfo, TokenResponse, ConsentErrorInfo
from .exceptions import AirlockAuthException

class AirlockAuthOptions:
    """Configuration for AirlockAuthClient."""
    def __init__(self, keycloak_realm_url: str, oidc_client_id: str = "airlock-integrations"):
        self.keycloak_realm_url = keycloak_realm_url
        self.oidc_client_id = oidc_client_id

class OidcDiscoveryResult:
    def __init__(self, data: Dict[str, Any]):
        self.token_endpoint = data.get("token_endpoint")
        self.device_authorization_endpoint = data.get("device_authorization_endpoint")
        self.revocation_endpoint = data.get("revocation_endpoint")
        self.authorization_endpoint = data.get("authorization_endpoint")

class AirlockAuthClient:
    """
    Handles user authentication for enforcer apps.
    Supports two OAuth2 flows:
      - Device Authorization Grant (RFC 8628) — for headless/CLI apps (Agent, Desktop, VS Code Extension)
      - Authorization Code + PKCE (RFC 7636) — for browser-capable apps (Web, Mobile)
    """
    def __init__(self, options: AirlockAuthOptions, httpx_client: Optional[httpx.AsyncClient] = None):
        self.options = options
        self._http = httpx_client or httpx.AsyncClient(timeout=30.0)
        
        self._oidc_config: Optional[OidcDiscoveryResult] = None
        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._token_expires_at: float = 0.0

    async def _close(self):
        await self._http.aclose()

    @property
    def current_access_token(self) -> Optional[str]:
        return self._access_token

    @property
    def is_logged_in(self) -> bool:
        return self._access_token is not None

    @property
    def is_token_expired(self) -> bool:
        return datetime.now(timezone.utc).timestamp() >= self._token_expires_at

    async def discover(self) -> OidcDiscoveryResult:
        if self._oidc_config:
            return self._oidc_config

        realm_url = self.options.keycloak_realm_url.rstrip("/")
        well_known_url = f"{realm_url}/.well-known/openid-configuration"

        resp = await self._http.get(well_known_url)
        resp.raise_for_status()

        data = resp.json()
        self._oidc_config = OidcDiscoveryResult(data)

        if not self._oidc_config.token_endpoint:
            raise RuntimeError("OIDC discovery: token_endpoint is missing.")

        return self._oidc_config

    async def login(self, on_user_code: Callable[[DeviceCodeInfo], None]) -> TokenResponse:
        """
        Start the Device Authorization Grant flow.
        Returns device code info (user_code, verification_uri) for the user to complete in their browser.
        Then polls the token endpoint until the user authorizes.
        """
        oidc = await self.discover()

        # Step 1: Request device code
        device_resp = await self._http.post(
            oidc.device_authorization_endpoint,
            data={
                "client_id": self.options.oidc_client_id,
                "scope": "openid profile email"
            }
        )
        device_resp.raise_for_status()
        device_data = device_resp.json()
        
        device_code = DeviceCodeInfo(device_data)

        # Step 2: Notify caller to display the code
        on_user_code(device_code)

        # Step 3: Poll token endpoint
        interval = max(device_code.interval, 5)
        deadline = datetime.now(timezone.utc).timestamp() + device_code.expires_in

        while datetime.now(timezone.utc).timestamp() < deadline:
            time.sleep(interval)

            token_resp = await self._http.post(
                oidc.token_endpoint,
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "client_id": self.options.oidc_client_id,
                    "device_code": device_code.device_code
                }
            )

            token_data = token_resp.json()

            if token_resp.is_success:
                token = TokenResponse(token_data)
                self._access_token = token.access_token
                self._refresh_token = token.refresh_token
                self._token_expires_at = datetime.now(timezone.utc).timestamp() + token.expires_in - 30
                return token

            error = token_data.get("error")
            if error == "authorization_pending":
                continue
            elif error == "slow_down":
                interval += 5
                continue
            elif error == "expired_token":
                raise AirlockAuthException("Device code expired. Please try logging in again.")
            elif error == "access_denied":
                raise AirlockAuthException("User denied the authorization request.")
            else:
                desc = token_data.get("error_description", "")
                raise AirlockAuthException(f"Token request failed: {error} — {desc}")

        raise AirlockAuthException("Device code expired before user completed authorization.")

    # ── Authorization Code + PKCE ───────────────────────────────

    async def login_with_auth_code(
        self,
        on_browser_url: Callable[[str], None],
        redirect_port: int = 0
    ) -> TokenResponse:
        """
        Start the Authorization Code + PKCE flow.
        Opens a local HTTP server to receive the callback, then exchanges the code for tokens.
        Best for Web and Mobile enforcer apps.
        """
        oidc = await self.discover()
        if not oidc.authorization_endpoint:
            raise RuntimeError("OIDC discovery: authorization_endpoint is missing.")

        # Step 1: Generate PKCE code_verifier + code_challenge
        code_verifier = self._generate_code_verifier()
        code_challenge = self._compute_code_challenge(code_verifier)
        state = os.urandom(16).hex()

        # Step 2: Find an available port if not specified
        if redirect_port == 0:
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', 0))
                redirect_port = s.getsockname()[1]

        redirect_uri = f"http://localhost:{redirect_port}/callback"

        # Step 3: Build authorization URL
        params = urlencode({
            "response_type": "code",
            "client_id": self.options.oidc_client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid profile email",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        })
        auth_url = f"{oidc.authorization_endpoint}?{params}"

        # Step 4: Start local HTTP server and wait for callback
        result: Dict[str, Any] = {}
        error_info: Dict[str, str] = {}

        class CallbackHandler(BaseHTTPRequestHandler):
            def do_GET(handler_self):
                parsed = urlparse(handler_self.path)
                if parsed.path != "/callback":
                    handler_self.send_response(404)
                    handler_self.end_headers()
                    return

                params = parse_qs(parsed.query)

                err = params.get("error", [None])[0]
                if err:
                    error_info["error"] = err
                    error_info["description"] = params.get("error_description", [""])[0]
                    handler_self.send_response(400)
                    handler_self.send_header("Content-Type", "text/html")
                    handler_self.end_headers()
                    handler_self.wfile.write(b"Authorization failed. You can close this tab.")
                    return

                returned_state = params.get("state", [None])[0]
                if returned_state != state:
                    error_info["error"] = "state_mismatch"
                    handler_self.send_response(400)
                    handler_self.send_header("Content-Type", "text/html")
                    handler_self.end_headers()
                    handler_self.wfile.write(b"Invalid state parameter.")
                    return

                code = params.get("code", [None])[0]
                if code:
                    result["code"] = code
                    handler_self.send_response(200)
                    handler_self.send_header("Content-Type", "text/html")
                    handler_self.end_headers()
                    handler_self.wfile.write(b"Authorization successful! You can close this tab.")

            def log_message(self, format, *args):
                pass  # Suppress logs

        server = HTTPServer(('127.0.0.1', redirect_port), CallbackHandler)
        server.timeout = 300  # 5 minute timeout

        on_browser_url(auth_url)

        # Handle one request in a thread to not block async
        server_thread = threading.Thread(target=server.handle_request)
        server_thread.start()
        server_thread.join(timeout=300)
        server.server_close()

        if error_info:
            raise AirlockAuthException(
                f"Authorization denied: {error_info.get('error')} — {error_info.get('description', '')}")

        if "code" not in result:
            raise AirlockAuthException("Authorization timed out or no code received.")

        # Step 5: Exchange code for tokens
        return await self.exchange_code(result["code"], redirect_uri, code_verifier)

    async def get_authorization_url(self, redirect_uri: str) -> Dict[str, str]:
        """
        Builds the authorization URL for the Auth Code + PKCE flow.
        Use this when you manage the browser redirect yourself.
        Returns dict with: authorization_url, state, code_verifier, redirect_uri.
        """
        oidc = await self.discover()
        if not oidc.authorization_endpoint:
            raise RuntimeError("OIDC discovery: authorization_endpoint is missing.")

        code_verifier = self._generate_code_verifier()
        code_challenge = self._compute_code_challenge(code_verifier)
        state = os.urandom(16).hex()

        params = urlencode({
            "response_type": "code",
            "client_id": self.options.oidc_client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid profile email",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        })

        return {
            "authorization_url": f"{oidc.authorization_endpoint}?{params}",
            "state": state,
            "code_verifier": code_verifier,
            "redirect_uri": redirect_uri,
        }

    async def exchange_code(self, code: str, redirect_uri: str, code_verifier: str) -> TokenResponse:
        """Exchange an authorization code for tokens (Auth Code + PKCE)."""
        oidc = await self.discover()

        resp = await self._http.post(
            oidc.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "client_id": self.options.oidc_client_id,
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            }
        )

        data = resp.json()
        if not resp.is_success:
            error = data.get("error", "")
            desc = data.get("error_description", "")
            raise AirlockAuthException(f"Code exchange failed: {error} — {desc}")

        token = TokenResponse(data)
        self._access_token = token.access_token
        self._refresh_token = token.refresh_token
        self._token_expires_at = datetime.now(timezone.utc).timestamp() + token.expires_in - 30
        return token

    @staticmethod
    def _generate_code_verifier() -> str:
        return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('ascii')

    @staticmethod
    def _compute_code_challenge(code_verifier: str) -> str:
        digest = hashlib.sha256(code_verifier.encode('ascii')).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')

    async def refresh_token(self) -> TokenResponse:
        if not self._refresh_token:
            raise AirlockAuthException("No refresh token available. Please login first.")

        oidc = await self.discover()

        resp = await self._http.post(
            oidc.token_endpoint,
            data={
                "grant_type": "refresh_token",
                "client_id": self.options.oidc_client_id,
                "refresh_token": self._refresh_token
            }
        )

        data = resp.json()

        if not resp.is_success:
            self._access_token = None
            self._refresh_token = None
            error = data.get("error")
            desc = data.get("error_description", "")
            raise AirlockAuthException(f"Token refresh failed: {error} — {desc}")

        token = TokenResponse(data)
        self._access_token = token.access_token
        self._refresh_token = token.refresh_token
        self._token_expires_at = datetime.now(timezone.utc).timestamp() + token.expires_in - 30
        return token

    async def get_access_token(self) -> str:
        if not self._access_token:
            raise AirlockAuthException("Not logged in. Call login() first.")

        if self.is_token_expired and self._refresh_token:
            await self.refresh_token()

        if not self._access_token:
            raise AirlockAuthException("Token refresh failed and no valid token available.")

        return self._access_token

    async def logout(self):
        if self._refresh_token:
            try:
                oidc = await self.discover()
                if oidc.revocation_endpoint:
                    await self._http.post(
                        oidc.revocation_endpoint,
                        data={
                            "client_id": self.options.oidc_client_id,
                            "token": self._refresh_token,
                            "token_type_hint": "refresh_token"
                        }
                    )
            except Exception:
                pass # Best-effort revocation

        self._access_token = None
        self._refresh_token = None
        self._token_expires_at = 0.0

    @staticmethod
    def parse_consent_error(status_code: int, response_body: str) -> Optional[ConsentErrorInfo]:
        if status_code != 403:
            return None

        try:
            data = json.loads(response_body)
            error = data.get("error")
            
            if error not in ("app_consent_required", "app_consent_pending", "app_consent_denied"):
                return None

            return ConsentErrorInfo(data)
        except Exception:
            return None

    def restore_tokens(self, access_token: str, refresh_token: str, expires_at: float):
        self._access_token = access_token
        self._refresh_token = refresh_token
        self._token_expires_at = expires_at

    def get_token_state(self) -> Tuple[Optional[str], Optional[str], float]:
        return (self._access_token, self._refresh_token, self._token_expires_at)
