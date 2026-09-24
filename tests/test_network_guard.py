"""The ``no_network`` fixture (conftest) must stop any real connection from a test."""

from __future__ import annotations

import socket
from pathlib import Path

import httpx
import pytest


@pytest.mark.network_attempt_expected
async def test_real_http_is_blocked() -> None:
    async with httpx.AsyncClient() as client:
        with pytest.raises(Exception, match="real network access"):
            await client.get("https://example.com/")


@pytest.mark.network_attempt_expected
def test_real_socket_is_blocked() -> None:
    with pytest.raises(RuntimeError, match="real network access"):
        socket.create_connection(("192.0.2.1", 80), timeout=1)


def test_swallowed_attempts_still_fail_the_test(pytester: pytest.Pytester) -> None:
    """An analyzer that catches the error must not hide a network attempt."""
    pytester.makeini(
        "[pytest]\nasyncio_mode = auto\nasyncio_default_fixture_loop_scope = function\n"
    )
    pytester.makeconftest((Path(__file__).parent / "conftest.py").read_text())
    pytester.makepyfile(
        """
        import socket

        def test_swallowed():
            try:
                socket.create_connection(("192.0.2.1", 80), timeout=1)
            except Exception:
                pass
        """
    )
    result = pytester.runpytest("-p", "no:cacheprovider")
    result.assert_outcomes(passed=1, errors=1)
    result.stdout.fnmatch_lines(["*test tried real network access*"])
