"""Have I Been Pwned range lookup.

Only a five-character SHA-1 prefix leaves the machine. A failed or malformed
response is never reported as "not found".
"""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, cast

from lupaxa.password_strength.hashing import hibp_sha1

HIBP_URL = "https://api.pwnedpasswords.com/range/{}"
USER_AGENT = "password-strength-checker"
_RANGE_LINE = re.compile(r"^[0-9A-F]{35}:[0-9]+$")
_PREFIX = re.compile(r"^[0-9A-F]{5}$")


class RangeResponse(Protocol):
    """Minimum response surface used to read a range body."""

    def read(self) -> bytes:
        """Return the raw response body."""
        raise NotImplementedError

    def __enter__(self) -> RangeResponse:
        """Enter the response context."""
        raise NotImplementedError

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> object:
        """Leave the response context."""
        raise NotImplementedError


Opener = Callable[[urllib.request.Request, float], RangeResponse]


@dataclass(frozen=True)
class BreachLookup:
    """Outcome of one k-anonymity lookup.

    Attributes
    ----------
    status : str
        ``breached``, ``not_found``, ``http_error``, ``network_error``, or
        ``invalid_response``.
    count : int or None
        Recorded occurrences when the suffix was found. Zero when the hash
        was absent from a valid body. ``None`` when the check did not succeed.
    error : str or None
        Short reason for a failed check. It never contains the password.
    """

    status: str
    count: int | None = None
    error: str | None = None

    @property
    def breached(self) -> bool | None:
        """Return whether the password was found, or ``None`` if that is unknown."""
        if self.status == "breached":
            return True
        if self.status == "not_found":
            return False
        return None


class PasswordChecker(Protocol):
    """A breach lookup the analyser can call."""

    def lookup(self, password: str) -> BreachLookup:
        """Return the lookup for one password."""
        raise NotImplementedError


def parse_range_body(body: str, suffix: str) -> BreachLookup:
    """Interpret a HIBP range body.

    Parameters
    ----------
    body : str
        Response body. Every non-empty line must be ``SUFFIX:COUNT``.
    suffix : str
        The 35-character hash suffix to compare locally.

    Returns
    -------
    BreachLookup
        ``not_found`` only when every line is well formed and the suffix is
        absent or has a count of zero.
    """
    matched: int | None = None
    saw_line = False
    for line in body.splitlines():
        if line == "":
            continue
        saw_line = True
        if _RANGE_LINE.fullmatch(line) is None:
            return BreachLookup(status="invalid_response", error="HIBP returned a malformed range body.")
        hash_suffix, count_text = line.split(":", 1)
        count = int(count_text)
        if hash_suffix == suffix:
            matched = count if matched is None else max(matched, count)
    if not saw_line:
        return BreachLookup(status="invalid_response", error="HIBP returned an empty body.")
    if matched is None or matched == 0:
        return BreachLookup(status="not_found", count=0)
    return BreachLookup(status="breached", count=matched)


def _open_range(request: urllib.request.Request, timeout: float) -> RangeResponse:
    # The URL is the fixed HIBP range host plus a 5-character hash prefix.
    # urlopen's declared result is Any, so the cast is the typed boundary.
    opened: object = urllib.request.urlopen(request, timeout=timeout)  # noqa: S310  # pyright: ignore[reportAny]
    return cast(RangeResponse, opened)


class BreachClient:
    """Client for the HIBP password-range API."""

    def __init__(self, *, timeout: float = 10.0, opener: Opener | None = None) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be greater than zero.")
        self.timeout: float = timeout
        self._open: Opener = opener or _open_range

    def lookup(self, password: str) -> BreachLookup:
        """Check one password without sending it or its full hash.

        Parameters
        ----------
        password : str
            Password to hash locally. It is not included in the request or the result.

        Returns
        -------
        BreachLookup
            Breach count, or a distinct failure status when the response cannot be trusted.
        """
        digest = hibp_sha1(password).upper()
        prefix, suffix = digest[:5], digest[5:]
        if _PREFIX.fullmatch(prefix) is None:
            return BreachLookup(status="invalid_response", error="Could not hash the password.")
        # Prefix is five hex characters. The password and the rest of the hash stay local.
        request = urllib.request.Request(  # noqa: S310
            HIBP_URL.format(prefix),
            headers={
                "Add-Padding": "true",
                "User-Agent": USER_AGENT,
            },
            method="GET",
        )
        try:
            with self._open(request, self.timeout) as response:
                payload = response.read()
        except urllib.error.HTTPError as exc:
            return BreachLookup(status="http_error", error=f"HTTP {exc.code}")
        except (urllib.error.URLError, TimeoutError, OSError):
            return BreachLookup(status="network_error", error="The HIBP request failed.")
        try:
            text = payload.decode("utf-8")
        except UnicodeDecodeError:
            return BreachLookup(status="invalid_response", error="HIBP returned a body that is not UTF-8.")
        return parse_range_body(text, suffix)
