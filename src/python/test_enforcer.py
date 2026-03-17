#!/usr/bin/env python3
"""Airlock Test Enforcer CLI (Python) — Full TUI with rich + questionary."""

import sys
import os
import json
import asyncio
import secrets
import base64
import socket
from pathlib import Path
from datetime import datetime, timezone

import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
import questionary

sys.path.insert(0, str(Path(__file__).parent))

from airlock_gateway.client import AirlockGatewayClient
from airlock_gateway.auth_client import AirlockAuthClient, AirlockAuthOptions, DeviceCodeInfo
from airlock_gateway.exceptions import AirlockGatewayError, AirlockAuthException

console = Console()

CONFIG_PATH = Path.home() / ".airlock" / "test-enforcer-python.json"

# ── Persistent Configuration ────────────────────────────────────────
class Config:
    def __init__(self):
        self.gateway_url = "https://localhost:7190"
        self.client_id = ""
        self.client_secret = ""
        self.enforcer_id = "enf-test"
        self.workspace_name = "default"
        self.device_id = ""
        self.routing_token = ""
        self.access_token = ""
        self.refresh_token = ""
        self.token_expires_at = 0.0

    def to_dict(self):
        return {
            "gatewayUrl": self.gateway_url,
            "clientId": self.client_id,
            "clientSecret": self.client_secret,
            "enforcerId": self.enforcer_id,
            "workspaceName": self.workspace_name,
            "deviceId": self.device_id,
            "routingToken": self.routing_token,
            "accessToken": self.access_token,
            "refreshToken": self.refresh_token,
            "tokenExpiresAt": self.token_expires_at,
        }

    @staticmethod
    def from_dict(data: dict) -> "Config":
        c = Config()
        c.gateway_url = data.get("gatewayUrl", c.gateway_url)
        c.client_id = data.get("clientId", c.client_id)
        c.client_secret = data.get("clientSecret", c.client_secret)
        c.enforcer_id = data.get("enforcerId", c.enforcer_id)
        c.workspace_name = data.get("workspaceName", c.workspace_name)
        c.device_id = data.get("deviceId", c.device_id)
        c.routing_token = data.get("routingToken", c.routing_token)
        c.access_token = data.get("accessToken", c.access_token)
        c.refresh_token = data.get("refreshToken", c.refresh_token)
        c.token_expires_at = data.get("tokenExpiresAt", c.token_expires_at)
        return c


cfg = Config()
auth_client: AirlockAuthClient = None
gw_client: AirlockGatewayClient = None
keycloak_url = "http://localhost:18080/realms/airlock"
last_request_id: str = ""
heartbeat_task: asyncio.Task = None


# ── Helpers ──────────────────────────────────────────────────────────
def mask_secret(secret: str) -> str:
    if not secret:
        return "(not set)"
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}…{secret[-4:]}"


def load_config():
    global cfg
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            cfg = Config.from_dict(json.load(f))


def save_config():
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg.to_dict(), f, indent=2)


# ── Debug HTTP Logging ──────────────────────────────────────────────
async def log_request(request):
    console.print(f"  [dim]{request.method} {request.url}[/dim]")

async def log_response(response):
    color = "green" if response.status_code < 400 else "red"
    console.print(f"  [{color}]=> {response.status_code} {response.reason_phrase}[/{color}]")


# ── Client Initialization ───────────────────────────────────────────
def discover_gateway():
    global keycloak_url
    try:
        with httpx.Client(verify=False, timeout=5.0) as http:
            url = f"{cfg.gateway_url.rstrip('/')}/v1/integrations/discovery"
            resp = http.get(url)
            if resp.status_code == 200:
                data = resp.json()
                base = data.get("idp", {}).get("baseUrl")
                if base:
                    keycloak_url = base
                    console.print(f"[dim]Keycloak: {keycloak_url}[/dim]")
                    return
    except Exception:
        pass
    console.print(f"[dim yellow]Discovery failed — using default: {keycloak_url}[/dim yellow]")


def init_clients():
    global auth_client, gw_client
    event_hooks = {"request": [log_request], "response": [log_response]}

    auth_http = httpx.AsyncClient(verify=False, timeout=30.0, event_hooks=event_hooks)
    auth_client = AirlockAuthClient(
        AirlockAuthOptions(keycloak_realm_url=keycloak_url, oidc_client_id="airlock-integrations"),
        httpx_client=auth_http,
    )

    gw_http = httpx.AsyncClient(
        base_url=cfg.gateway_url.rstrip("/"),
        verify=False,
        timeout=120.0,
        headers={"X-Client-Id": cfg.client_id, "X-Client-Secret": cfg.client_secret},
        event_hooks=event_hooks,
    )
    gw_client = AirlockGatewayClient(
        base_url=cfg.gateway_url,
        client_id=cfg.client_id,
        client_secret=cfg.client_secret,
        http_client=gw_http,
    )


# ── Status Display ──────────────────────────────────────────────────
def print_status():
    table = Table(border_style="grey50", show_edge=True)
    table.add_column("Property", style="bold")
    table.add_column("Value")

    table.add_row("Gateway", cfg.gateway_url)
    table.add_row("Client ID", cfg.client_id)
    table.add_row("Client Secret", mask_secret(cfg.client_secret))
    table.add_row("Enforcer ID", cfg.enforcer_id)
    table.add_row("Workspace", cfg.workspace_name)

    signed_in = auth_client and auth_client.is_logged_in
    table.add_row("Auth", "[green]Signed in[/green]" if signed_in else "[dim]Not signed in[/dim]")

    if cfg.routing_token:
        truncated = cfg.routing_token[:16] + "..." if len(cfg.routing_token) > 16 else cfg.routing_token
        table.add_row("Paired", f"[green]{truncated}[/green]")
    else:
        table.add_row("Paired", "[dim]Not paired[/dim]")

    console.print(table)


# ── Menu ─────────────────────────────────────────────────────────────
def build_menu_choices() -> list:
    signed_in = auth_client and auth_client.is_logged_in
    paired = bool(cfg.routing_token)

    if signed_in:
        if paired:
            return ["▸ Submit Artifact", "▸ Withdraw", "─────────", "▸ Unpair", "▸ Sign Out", "▸ Reconfigure", "✕ Exit"]
        return ["▸ Pair Device", "─────────", "▸ Sign Out", "▸ Reconfigure", "✕ Exit"]
    return ["▸ Sign In", "▸ Reconfigure", "✕ Exit"]


# ── Sign In (Device Auth Grant) ─────────────────────────────────────
async def do_sign_in():
    with console.status("Discovering OIDC endpoints..."):
        await auth_client.discover()

    with console.status("Requesting device code..."):
        token = await auth_client.login(lambda dc: _show_device_code(dc))

    console.print("[green]✓ Signed in successfully[/green]")

    acc, ref, exp = auth_client.get_token_state()
    cfg.access_token = acc or ""
    cfg.refresh_token = ref or ""
    cfg.token_expires_at = exp
    save_config()

    gw_client.set_bearer_token(acc)
    await check_consent()


def _show_device_code(dc: DeviceCodeInfo):
    url = dc.verification_uri_complete or dc.verification_uri
    console.print()
    console.print(Panel(
        f"[bold yellow]Open this URL:[/bold yellow]\n{url}\n\n"
        f"[bold]Enter code:[/bold] [cyan]{dc.user_code}[/cyan]",
        title="Device Authorization Required",
        border_style="yellow",
    ))
    console.print("[dim]Waiting for user authorization...[/dim]")


# ── Consent Check ───────────────────────────────────────────────────
async def check_consent():
    try:
        with console.status("Checking consent..."):
            status = await gw_client.check_consent()
        console.print(f"[green]✓ Consent status: {status}[/green]")
    except AirlockGatewayError as ex:
        if ex.error_code in ("app_consent_required", "app_consent_pending"):
            console.print(Panel(
                f"[yellow]{str(ex)}[/yellow]\n\n"
                "A consent request has been sent to your mobile device.\n"
                "Please approve it in the Airlock mobile app.",
                title=f"Consent: {ex.error_code}",
                border_style="yellow",
            ))
        else:
            raise


# ── Pair Device ─────────────────────────────────────────────────────
async def do_pair():
    if not cfg.device_id:
        default_id = f"dev-{socket.gethostname().lower()}"
        cfg.device_id = await questionary.text("Device ID:", default=default_id).ask_async() or default_id

    from airlock_gateway.models import PairingInitiateRequest
    req = PairingInitiateRequest(
        device_id=cfg.device_id,
        enforcer_id=cfg.enforcer_id,
        enforcer_label="Test Enforcer Python",
        workspace_name=cfg.workspace_name,
    )

    res = await gw_client.initiate_pairing(req)

    console.print(Panel(
        f"[bold]Pairing Code:[/bold] [cyan]{res.pairing_code}[/cyan]\n"
        f"[bold]Nonce:[/bold] {res.pairing_nonce}\n\n"
        "Enter this code in the Airlock mobile app to complete pairing.",
        title="Pairing Initiated",
        border_style="yellow",
    ))

    # Poll for completion
    with console.status("Waiting for pairing approval...") as status:
        for i in range(60):  # 5 min max
            await asyncio.sleep(5)
            ps = await gw_client.get_pairing_status(res.pairing_nonce)
            state = (ps.state or "").lower()
            status.update(f"Pairing status: [bold]{state}[/bold] ({(i + 1) * 5}s)")

            if state == "completed":
                cfg.routing_token = ps.routing_token
                save_config()
                console.print("[green]✓ Paired! Routing token saved.[/green]")
                start_heartbeat()
                return
            if state in ("revoked", "expired"):
                console.print(f"[red]Pairing {state}[/red]")
                return

    console.print("[red]Pairing timed out.[/red]")


# ── Submit Artifact ─────────────────────────────────────────────────
async def do_submit():
    global last_request_id
    await ensure_fresh_token()

    import uuid
    req_id = f"req-{uuid.uuid4().hex}"
    artifact_hash = f"hash-{uuid.uuid4().hex[:12]}"

    nonce = base64.b64encode(secrets.token_bytes(24)).decode()
    tag = base64.b64encode(secrets.token_bytes(16)).decode()
    data = base64.b64encode(secrets.token_bytes(64)).decode()

    from airlock_gateway.models import ArtifactSubmitRequest, CiphertextRef
    req = ArtifactSubmitRequest(
        enforcer_id=cfg.enforcer_id,
        artifact_type="command-approval",
        artifact_hash=artifact_hash,
        ciphertext=CiphertextRef(alg="xchacha20-poly1305", data=data, nonce=nonce, tag=tag),
        metadata={"routingToken": cfg.routing_token, "workspaceName": cfg.workspace_name},
        request_id=req_id,
    )

    console.print(f"[dim]Submitting artifact {req_id}...[/dim]")
    submitted_id = await gw_client.submit_artifact(req)
    last_request_id = submitted_id or req_id
    console.print(f"[green]✓ Submitted: {last_request_id}[/green]")

    # Long-poll for decision
    with console.status("Waiting for decision...") as status:
        deadline = datetime.now(timezone.utc).timestamp() + 120  # 2 min
        poll = 0
        while datetime.now(timezone.utc).timestamp() < deadline:
            poll += 1
            status.update(f"Waiting for decision... ({poll * 25}s elapsed)")
            try:
                env = await gw_client.wait_for_decision(last_request_id, timeout_seconds=25)
                if env and env.body:
                    is_approved = (env.body.decision or "").lower() == "approve"
                    color = "green" if is_approved else "red"
                    icon = "✓" if is_approved else "✗"
                    parts = [f"[bold]{icon} {(env.body.decision or 'UNKNOWN').upper()}[/bold]"]
                    if getattr(env.body, "reason", None):
                        parts.append(f"Reason: {env.body.reason}")
                    if getattr(env.body, "signer_key_id", None):
                        parts.append(f"Signer: {env.body.signer_key_id}")
                    console.print(Panel("\n".join(parts), title="Decision", border_style=color))
                    return
            except AirlockGatewayError as ex:
                if ex.status_code == 404:
                    return  # Exchange expired or withdrawn
                raise

    console.print("[yellow]⏳ Timed out waiting for decision.[/yellow]")
    await do_withdraw()


# ── Withdraw ─────────────────────────────────────────────────────────
async def do_withdraw():
    global last_request_id
    req_id = last_request_id
    if not req_id:
        req_id = await questionary.text("Request ID to withdraw:").ask_async()
        if not req_id:
            return

    try:
        await gw_client.withdraw_exchange(req_id)
        console.print(f"[green]✓ Withdrawn: {req_id}[/green]")
        last_request_id = ""
    except Exception as ex:
        console.print(f"[yellow]Withdraw failed (non-fatal): {ex}[/yellow]")


# ── Unpair ───────────────────────────────────────────────────────────
async def do_unpair():
    if not cfg.routing_token:
        console.print("[dim]Not paired.[/dim]")
        return

    if not await questionary.confirm("Revoke pairing?", default=False).ask_async():
        return

    try:
        await gw_client.revoke_pairing(cfg.routing_token)
    except Exception as ex:
        console.print(f"[dim]Server revoke failed (token may be stale): {ex}[/dim]")

    cfg.routing_token = ""
    cfg.device_id = ""
    stop_heartbeat()
    save_config()
    console.print("[green]✓ Unpaired.[/green]")


# ── Sign Out ─────────────────────────────────────────────────────────
async def do_sign_out():
    try:
        await auth_client.logout()
    except Exception:
        pass  # best effort

    cfg.access_token = ""
    cfg.refresh_token = ""
    cfg.token_expires_at = 0.0
    gw_client.set_bearer_token(None)
    stop_heartbeat()
    save_config()
    console.print("[green]✓ Signed out.[/green]")


# ── Session Restore ─────────────────────────────────────────────────
async def try_restore_session():
    if not cfg.refresh_token:
        return

    auth_client.restore_tokens(cfg.access_token, cfg.refresh_token, cfg.token_expires_at)

    try:
        with console.status("Refreshing session..."):
            await auth_client.refresh_token()

        acc, ref, exp = auth_client.get_token_state()
        cfg.access_token = acc or ""
        cfg.refresh_token = ref or ""
        cfg.token_expires_at = exp
        save_config()

        gw_client.set_bearer_token(acc)
        console.print("[green]✓ Session restored[/green]")

        await check_consent()

        if cfg.routing_token:
            start_heartbeat()

    except Exception as ex:
        console.print(f"[yellow]Session expired: {ex}[/yellow]")
        cfg.access_token = ""
        cfg.refresh_token = ""
        cfg.token_expires_at = 0.0
        save_config()


# ── Token Refresh ───────────────────────────────────────────────────
async def ensure_fresh_token():
    if auth_client and auth_client.is_token_expired and cfg.refresh_token:
        await auth_client.refresh_token()
        acc, ref, exp = auth_client.get_token_state()
        cfg.access_token = acc or ""
        cfg.refresh_token = ref or ""
        cfg.token_expires_at = exp
        gw_client.set_bearer_token(acc)
        save_config()


# ── Background Heartbeat ────────────────────────────────────────────
def start_heartbeat():
    global heartbeat_task
    stop_heartbeat()

    async def _heartbeat_loop():
        from airlock_gateway.models import PresenceHeartbeatRequest
        try:
            while True:
                try:
                    await gw_client.send_heartbeat(PresenceHeartbeatRequest(
                        enforcer_id=cfg.enforcer_id,
                        enforcer_label="Test Enforcer Python",
                        workspace_name=cfg.workspace_name,
                    ))
                except Exception:
                    pass  # Silent — don't interfere with TUI
                await asyncio.sleep(10)
        except asyncio.CancelledError:
            pass

    heartbeat_task = asyncio.create_task(_heartbeat_loop())


def stop_heartbeat():
    global heartbeat_task
    if heartbeat_task and not heartbeat_task.done():
        heartbeat_task.cancel()
        heartbeat_task = None


# ── Setup Wizard ────────────────────────────────────────────────────
async def run_setup_wizard():
    console.rule("[yellow]Setup[/yellow]")

    cfg.gateway_url = await questionary.text("Gateway URL:", default=cfg.gateway_url).ask_async() or cfg.gateway_url
    cfg.client_id = await questionary.text("Client ID:", default=cfg.client_id).ask_async() or cfg.client_id
    cfg.client_secret = await questionary.password("Client Secret:", default=cfg.client_secret).ask_async() or cfg.client_secret
    cfg.enforcer_id = await questionary.text("Enforcer ID:", default=cfg.enforcer_id).ask_async() or cfg.enforcer_id
    cfg.workspace_name = await questionary.text("Workspace Name:", default=cfg.workspace_name).ask_async() or cfg.workspace_name

    save_config()
    console.print("[green]✓ Configuration saved[/green]")


# ── Main ─────────────────────────────────────────────────────────────
async def main():
    console.print(Panel(
        "[bold cyan]Airlock Test Enforcer (Python)[/bold cyan]",
        border_style="cyan",
    ))

    load_config()
    discover_gateway()

    if not cfg.client_id:
        await run_setup_wizard()
        discover_gateway()

    init_clients()
    await try_restore_session()
    print_status()

    while True:
        choices = build_menu_choices()
        try:
            choice = await questionary.select(
                "Choose action:",
                choices=choices,
                qmark="",
            ).ask_async()
        except (EOFError, KeyboardInterrupt):
            stop_heartbeat()
            console.print("[dim]Goodbye![/dim]")
            return

        if choice is None:
            stop_heartbeat()
            console.print("[dim]Goodbye![/dim]")
            return

        try:
            if choice == "▸ Sign In":
                await do_sign_in()
            elif choice == "▸ Pair Device":
                await do_pair()
            elif choice == "▸ Submit Artifact":
                await do_submit()
            elif choice == "▸ Withdraw":
                await do_withdraw()
            elif choice == "▸ Unpair":
                await do_unpair()
            elif choice == "▸ Sign Out":
                await do_sign_out()
            elif choice == "▸ Reconfigure":
                await run_setup_wizard()
                init_clients()
            elif choice == "✕ Exit":
                stop_heartbeat()
                console.print("[dim]Goodbye![/dim]")
                return
        except AirlockGatewayError as ex:
            console.print(Panel(
                f"[red]{ex.error_code or 'error'}[/red]\n{str(ex)}",
                title="[red]Gateway Error[/red]",
                border_style="red",
            ))
        except AirlockAuthException as ex:
            console.print(Panel(
                f"[red]{ex}[/red]",
                title="[red]Auth Error[/red]",
                border_style="red",
            ))
        except Exception as ex:
            console.print_exception(show_locals=False)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
