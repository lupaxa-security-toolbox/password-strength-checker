"""HIBP range client."""

from __future__ import annotations

import urllib.error
import urllib.request
from email.message import Message
from io import BytesIO

import pytest

from lupaxa.password_strength.breach import BreachClient, parse_range_body
from lupaxa.password_strength.hashing import hibp_sha1


class FakeResponse:
    def __init__(self, body: bytes) -> None:
        self.body: bytes = body

    def read(self) -> bytes:
        return self.body

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        return None


def _digest(password: str) -> tuple[str, str]:
    digest = hibp_sha1(password).upper()
    return digest[:5], digest[5:]


def test_parse_requires_a_well_formed_body_before_not_found() -> None:
    suffix = "A" * 35

    missing = parse_range_body(f"{'B' * 35}:2\n", suffix)
    assert missing.status == "not_found"
    assert missing.breached is False
    assert missing.count == 0

    zero = parse_range_body(f"{suffix}:0\n", suffix)
    assert zero.status == "not_found"
    assert zero.count == 0

    found = parse_range_body(f"{suffix}:2\n{suffix}:9\n", suffix)
    assert found.status == "breached"
    assert found.breached is True
    assert found.count == 9

    malformed = parse_range_body(f"{suffix}:9\nNOT-A-HASH\n", suffix)
    assert malformed.status == "invalid_response"
    assert malformed.breached is None
    assert malformed.count is None

    assert parse_range_body("\n", suffix).status == "invalid_response"
    assert parse_range_body("", suffix).status == "invalid_response"


def test_lookup_sends_only_the_hash_prefix() -> None:
    password = "hunter2"
    prefix, suffix = _digest(password)
    seen: dict[str, object] = {}
    padding = "C" * 35 if suffix != "C" * 35 else "D" * 35

    def opener(request: urllib.request.Request, timeout: float) -> FakeResponse:
        seen["url"] = request.full_url
        seen["timeout"] = timeout
        seen["headers"] = {key.lower(): value for key, value in request.header_items()}
        return FakeResponse(f"{suffix}:4\n{padding}:0\n".encode())

    result = BreachClient(timeout=3, opener=opener).lookup(password)

    assert result.status == "breached"
    assert result.count == 4
    url = str(seen["url"])
    assert url.endswith("/" + prefix)
    assert suffix not in url
    assert password not in url
    headers = seen["headers"]
    assert isinstance(headers, dict)
    assert headers["add-padding"] == "true"
    assert headers["user-agent"] == "password-strength-checker"
    assert seen["timeout"] == 3


def test_malformed_success_is_not_a_clean_miss() -> None:
    password = "hunter2"
    _prefix, suffix = _digest(password)

    def opener(_request: urllib.request.Request, _timeout: float) -> FakeResponse:
        return FakeResponse(f"{suffix}:9\nBAD\n".encode())

    result = BreachClient(opener=opener).lookup(password)

    assert result.status == "invalid_response"
    assert result.breached is None


def test_http_and_network_failures_stay_unknown() -> None:
    def http_opener(request: urllib.request.Request, _timeout: float) -> FakeResponse:
        raise urllib.error.HTTPError(request.full_url, 503, "unavailable", Message(), BytesIO(b"down"))

    def network_opener(_request: urllib.request.Request, _timeout: float) -> FakeResponse:
        raise urllib.error.URLError("timed out")

    http_result = BreachClient(opener=http_opener).lookup("hunter2")
    network_result = BreachClient(opener=network_opener).lookup("hunter2")

    assert http_result.status == "http_error"
    assert http_result.error == "HTTP 503"
    assert http_result.breached is None
    assert "hunter2" not in (http_result.error or "")
    assert network_result.status == "network_error"
    assert network_result.breached is None
    assert network_result.error == "The HIBP request failed."


def test_timeout_must_be_positive() -> None:
    with pytest.raises(ValueError, match="timeout"):
        _ = BreachClient(timeout=0)
