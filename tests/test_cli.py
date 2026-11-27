"""Command-line behaviour."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from lupaxa.password_strength.breach import BreachLookup
from lupaxa.password_strength.cli import NoPasswordError, main, read_password
from lupaxa.password_strength.version import get_version


def _object_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise AssertionError("expected a JSON object")
    mapped: dict[str, object] = {}
    for key, item in cast(Mapping[object, object], value).items():
        mapped[str(key)] = item
    return mapped


def _payload(text: str) -> dict[str, object]:
    return _object_dict(cast(object, json.loads(text)))


def _nested(value: object) -> dict[str, object]:
    return _object_dict(value)


class Stream:
    def __init__(self, line: str, *, tty: bool) -> None:
        self.line: str = line
        self.tty: bool = tty

    def isatty(self) -> bool:
        return self.tty

    def readline(self) -> str:
        return self.line


def test_hidden_prompt_and_piped_stdin() -> None:
    prompted: list[str] = []

    def prompt(text: str) -> str:
        prompted.append(text)
        return "secret"

    assert read_password(input_stream=Stream("", tty=True), prompt=prompt) == "secret"
    assert prompted == ["Password: "]
    assert read_password(input_stream=Stream("piped\n", tty=False), prompt=prompt) == "piped"

    def closed(_text: str) -> str:
        raise EOFError

    with pytest.raises(NoPasswordError):
        _ = read_password(input_stream=Stream("", tty=True), prompt=closed)


def test_empty_password_prints_a_report(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("lupaxa.password_strength.cli.read_password", lambda: "")
    assert main([]) == 0
    output = capsys.readouterr().out
    assert "Password Strength" in output
    assert "Very weak" in output


def test_password_is_not_a_command_argument() -> None:
    with pytest.raises(SystemExit) as caught:
        _ = main(["hunter2"])
    assert caught.value.code == 2


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        _ = main(["--version"])
    assert caught.value.code == 0
    assert capsys.readouterr().out.strip() == get_version()


def test_timeout_is_rejected_before_prompting(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    def fail() -> str:
        raise AssertionError("password prompt")

    monkeypatch.setattr("lupaxa.password_strength.cli.read_password", fail)
    assert main(["--timeout", "0"]) == 2
    assert "Timeout" in capsys.readouterr().err


def test_json_report_has_no_password_field(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("lupaxa.password_strength.cli.read_password", lambda: "correct horse battery staple")
    assert main(["--json", "--user-input", "exampleuser"]) == 0
    payload = _payload(capsys.readouterr().out)
    assert "password" not in payload
    assert payload["length"] == len("correct horse battery staple")
    assert payload["breach_status"] == "not_checked"
    assert payload["breached"] is None


def test_policy_exit_status_is_separate_from_failure(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    monkeypatch.setattr("lupaxa.password_strength.cli.read_password", lambda: "password")

    def fail() -> str:
        raise AssertionError("password prompt")

    assert main(["--reject-breached"]) == 2
    assert "needs --check-breach" in capsys.readouterr().err
    monkeypatch.setattr("lupaxa.password_strength.cli.read_password", fail)
    assert main(["--min-score", "101"]) == 2
    monkeypatch.setattr("lupaxa.password_strength.cli.read_password", lambda: "password")

    assert main(["--json", "--min-score", "75"]) == 3
    payload = _payload(capsys.readouterr().out)
    policy = _nested(payload["policy"])
    assert policy["accepted"] is False
    assert policy["failures"] == [f"score {payload['score']} is below 75"]
    assert "password" not in payload

    path = tmp_path / "banned.txt"
    _ = path.write_text("zzzz\n", encoding="utf-8")
    assert main(["--json", "--banned-hashes", str(path), "--reject-breached"]) == 3
    rejected = _payload(capsys.readouterr().out)
    assert rejected["banned"] is None
    assert rejected["banned_status"] == "invalid_list"
    failures = _nested(rejected["policy"])["failures"]
    assert isinstance(failures, list)
    assert "banned list could not be checked" in failures


def test_breach_error_is_reported_as_unknown(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    monkeypatch.setattr("lupaxa.password_strength.cli.read_password", lambda: "secret")

    class FakeClient:
        def __init__(self, timeout: float) -> None:
            self.timeout: float = timeout

        def lookup(self, _password: str) -> BreachLookup:
            return BreachLookup(status="http_error", error="HTTP 503")

    monkeypatch.setattr("lupaxa.password_strength.cli.BreachClient", FakeClient)
    assert main(["--json", "--check-breach", "--timeout", "2"]) == 0
    payload = _payload(capsys.readouterr().out)
    assert "password" not in payload
    assert payload["breached"] is None
    assert payload["breach_status"] == "http_error"
    assert payload["breach_error"] == "HTTP 503"
