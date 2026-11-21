"""Offline SHA-1 list of banned passwords.

A hit is a confirmed exposure. A missing, unreadable, or malformed list is
unknown. It is never treated as a clean result.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

_HASH_LINE = re.compile(r"^([0-9a-fA-F]{40})(?::[0-9]+)?$")


@dataclass(frozen=True)
class BannedLookup:
    """Outcome of one local hash-list check.

    Attributes
    ----------
    status : str
        ``breached``, ``not_found``, ``unreadable``, or ``invalid_list``.
    error : str or None
        Short reason for a failed check. It never contains the password.
    """

    status: str
    error: str | None = None

    @property
    def found(self) -> bool | None:
        """Return whether the hash was in the list, or ``None`` if that is unknown."""
        if self.status == "breached":
            return True
        if self.status == "not_found":
            return False
        return None


@dataclass(frozen=True)
class BannedList:
    """SHA-1 hashes loaded from a file, or the reason that load failed."""

    hashes: frozenset[str]
    status: str
    error: str | None = None

    @classmethod
    def read(cls, path: Path) -> BannedList:
        """Load a banned-hash file without raising.

        Parameters
        ----------
        path : Path
            Text file of 40-character SHA-1 hashes, one per line. ``#`` starts a
            comment. A HIBP-style ``HASH:COUNT`` line is accepted.

        Returns
        -------
        BannedList
            A usable list, or an unreadable or invalid list that must not be
            treated as a clean miss.
        """
        try:
            text = path.read_text(encoding="utf-8-sig")
        except (OSError, UnicodeError):
            return cls(frozenset(), "unreadable", "The banned list could not be read.")
        hashes: set[str] = set()
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            matched = _HASH_LINE.fullmatch(line)
            if matched is None:
                return cls(frozenset(), "invalid_list", "The banned list is not a list of SHA-1 hashes.")
            hashes.add(matched.group(1).lower())
        return cls(frozenset(hashes), "ready")

    def lookup(self, password: str) -> BannedLookup:
        """Check one password against the loaded hashes.

        Parameters
        ----------
        password : str
            Password to hash locally. It is not stored.

        Returns
        -------
        BannedLookup
            Whether the hash was present, or why the list cannot be trusted.
        """
        if self.status != "ready":
            return BannedLookup(status=self.status, error=self.error)
        digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().lower()
        if digest in self.hashes:
            return BannedLookup(status="breached")
        return BannedLookup(status="not_found")
