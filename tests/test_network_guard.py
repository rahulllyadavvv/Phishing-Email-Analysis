"""The ``no_network`` fixture (conftest) must stop any real connection from a test."""

from __future__ import annotations

import socket

import httpx
import pytest


async def test_real_http_is_blocked() -> None:
    async with httpx.AsyncClient() as client:
        with pytest.raises(Exception, match="real network access"):
            await client.get("https://example.com/")


def test_real_socket_is_blocked() -> None:
    with pytest.raises(RuntimeError, match="real network access"):
        socket.create_connection(("192.0.2.1", 80), timeout=1)
