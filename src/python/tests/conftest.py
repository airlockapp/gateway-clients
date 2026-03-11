"""Shared pytest fixtures for Airlock Gateway SDK tests."""

from __future__ import annotations

import httpx
import pytest
import respx

from airlock_gateway.client import AirlockGatewayClient


@pytest.fixture
def mock_api():
    """Provides a respx mock router scoped to https://gw.test."""
    with respx.mock(base_url="https://gw.test") as router:
        yield router


@pytest.fixture
async def client(mock_api):
    """Provides an AirlockGatewayClient configured for the mock API."""
    http_client = httpx.AsyncClient(base_url="https://gw.test")
    gw = AirlockGatewayClient("https://gw.test", http_client=http_client)
    yield gw
    await gw.close()
