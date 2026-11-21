"""Offline banned-hash list."""

from __future__ import annotations

from pathlib import Path

from lupaxa.password_strength.banned import BannedList
from lupaxa.password_strength.hashing import hibp_sha1


def test_hit_miss_and_hibp_style_line(tmp_path: Path) -> None:
    path = tmp_path / "banned.txt"
    _ = path.write_text(f"# comment\n\n{hibp_sha1('secret').upper()}:4\n", encoding="utf-8")
    banned = BannedList.read(path)

    assert banned.lookup("secret").found is True
    assert banned.lookup("other").found is False
    assert banned.lookup("other").status == "not_found"


def test_missing_file_is_unknown(tmp_path: Path) -> None:
    banned = BannedList.read(tmp_path / "missing.txt")
    result = banned.lookup("secret")

    assert result.found is None
    assert result.status == "unreadable"
    assert result.error == "The banned list could not be read."


def test_malformed_list_is_unknown(tmp_path: Path) -> None:
    path = tmp_path / "banned.txt"
    _ = path.write_text("not-a-hash\n", encoding="utf-8")
    result = BannedList.read(path).lookup("secret")

    assert result.found is None
    assert result.status == "invalid_list"
    assert result.error == "The banned list is not a list of SHA-1 hashes."
