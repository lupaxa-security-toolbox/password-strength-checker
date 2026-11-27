"""Strength reports."""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from lupaxa.password_strength.analyser import Policy, analyse
from lupaxa.password_strength.banned import BannedList
from lupaxa.password_strength.breach import BreachLookup
from lupaxa.password_strength.card import MIN_INNER
from lupaxa.password_strength.hashing import hibp_sha1


class FakeClient:
    def __init__(self, result: BreachLookup) -> None:
        self.result: BreachLookup = result
        self.seen: str | None = None

    def lookup(self, password: str) -> BreachLookup:
        self.seen = password
        return self.result


def _zxcvbn_result(score: int = 3, guesses: float = 1_000_000.0) -> dict[str, object]:
    return {
        "score": score,
        "guesses": guesses,
        "crack_times_seconds": {
            "online_throttling_100_per_hour": 10.0,
            "online_no_throttling_10_per_second": 20.0,
            "offline_slow_hashing_1e4_per_second": 30.0,
            "offline_fast_hashing_1e10_per_second": 40.0,
        },
        "crack_times_display": {
            "online_throttling_100_per_hour": "10 seconds",
            "online_no_throttling_10_per_second": "20 seconds",
            "offline_slow_hashing_1e4_per_second": "30 seconds",
            "offline_fast_hashing_1e10_per_second": "40 seconds",
        },
        "sequence": [
            {
                "pattern": "bruteforce",
                "token": "ab",
                "i": 0,
                "j": 1,
                "guesses": 11,
                "password": "do-not-copy",
            }
        ],
        "feedback": {"warning": "Short pattern", "suggestions": ["Add another word"]},
    }


def _fake_zxcvbn(password: str, user_inputs: list[str] | None = None, *, score: int = 3, guesses: float = 1_000_000.0) -> dict[str, object]:
    del password, user_inputs
    return _zxcvbn_result(score=score, guesses=guesses)


def test_score_follows_zxcvbn_until_a_breach(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("lupaxa.password_strength.analyser.zxcvbn", _fake_zxcvbn)
    password = "not-the-report"
    offline = analyse(password)

    assert offline.zxcvbn_score == 3
    assert offline.score == 75
    assert offline.rating == "Strong"
    assert offline.breach_status == "not_checked"
    assert offline.breached is None
    assert offline.entropy_bits == round(math.log2(1_000_000.0), 2)
    assert offline.crack_times_display["online_throttled"] == "10 seconds"
    assert offline.patterns[0]["token"] == "ab"
    assert "password" not in offline.patterns[0]
    assert "password" not in offline.to_dict()
    card = offline.to_text().splitlines()
    title = next(line for line in card if "Password Strength" in line)
    inner = title[1:-1]
    heading = "Password Strength"
    before = inner.index(heading)
    after = len(inner) - before - len(heading)
    assert abs(before - after) <= 1
    assert card[0].startswith("╭")
    assert card[-1].startswith("╰")
    assert len({len(line) for line in card}) == 1
    assert "Password:" not in offline.to_text()
    assert "Not run" in offline.to_text()
    composition = next(line for line in card if "Lowercase" in line)
    length_line = next(line for line in card if "Length" in line)
    guesses_line = next(line for line in card if "Guesses" in line)
    assert length_line.index("14") == guesses_line.index("1,000,000")
    assert "Character classes" in composition
    assert "Uppercase" in next(line for line in card if "Digits" in line)
    breach_rule = next(line for line in card if "Breach" in line)
    inner = breach_rule[1:-1]
    before = inner.index("Breach")
    after = len(inner) - before - len("Breach")
    assert abs(before - after) <= 1
    coloured = offline.to_text(colour=True)
    assert "\033[1;4;36mPassword Strength\033[0m" in coloured
    assert "\033[1;36mBreach\033[0m" in coloured
    assert "\033[1;32mGuesses:\033[0m" in coloured
    assert "\033[1;32mLength:\033[0m" in coloured
    assert "\033[1;32mUnique characters:\033[0m" in coloured
    assert "\033[33mShort pattern\033[0m" in coloured
    assert "\033[1;32mStrong\033[0m" in coloured
    assert "\033[1;32m75 / 100\033[0m" in coloured
    assert coloured.splitlines()[0].startswith("\033[2;90m╭")

    client = FakeClient(BreachLookup(status="breached", count=12))
    breached = analyse(password, breach_client=client)

    assert client.seen == password
    assert breached.zxcvbn_score == 3
    assert breached.score == 0
    assert breached.rating == "Compromised"
    assert breached.breached is True
    assert breached.breach_count == 12
    assert "12 occurrences" in breached.to_text()
    assert "\033[1;31mBreached. 12 occurrences.\033[0m" in breached.to_text(colour=True)
    assert "Compromised" in breached.to_text()


def test_failed_breach_check_does_not_call_the_password_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_zxcvbn(password: str, user_inputs: list[str] | None = None) -> dict[str, object]:
        del password, user_inputs
        return _zxcvbn_result(score=4, guesses=2**40)

    monkeypatch.setattr("lupaxa.password_strength.analyser.zxcvbn", fake_zxcvbn)
    client = FakeClient(BreachLookup(status="network_error", error="The HIBP request failed."))
    report = analyse("offline-score-remains", breach_client=client)

    assert report.score == 100
    assert report.rating == "Very strong"
    assert report.breached is None
    assert report.breach_status == "network_error"
    text = report.to_text()
    assert "does not call the password safe" in text
    assert "not found" not in text


def test_not_found_is_explicitly_not_a_guarantee(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("lupaxa.password_strength.analyser.zxcvbn", _fake_zxcvbn)
    report = analyse("example", breach_client=FakeClient(BreachLookup(status="not_found", count=0)))

    assert report.breached is False
    assert "does not mean the password is safe" in report.to_text()


def test_user_inputs_are_passed_to_zxcvbn(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def fake(password: str, user_inputs: list[str] | None = None) -> dict[str, object]:
        seen["password"] = password
        seen["user_inputs"] = user_inputs
        return _zxcvbn_result(score=1)

    monkeypatch.setattr("lupaxa.password_strength.analyser.zxcvbn", fake)
    report = analyse("example", user_inputs=["exampleuser", "examplecompany"])

    assert seen["user_inputs"] == ["exampleuser", "examplecompany"]
    assert report.score == 25
    assert report.rating == "Weak"


def test_card_omits_the_pattern_section() -> None:
    report = analyse("correct horse battery staple")
    text = report.to_text()

    assert report.guesses is not None
    assert report.guesses > 1_000_000_000
    assert report.entropy_bits is not None
    assert report.entropy_bits > 0
    assert report.patterns
    assert "Patterns" not in text
    assert "common word" not in text
    assert "horse" not in text
    assert len({len(line) for line in text.splitlines()}) == 1


def test_card_grows_only_when_a_tip_needs_the_room() -> None:
    short = analyse("password123")
    short_width = len(short.to_text(max_columns=120).splitlines()[0])
    assert short_width == MIN_INNER + 2

    tip = "Predictable substitutions like '@' instead of 'a' don't help very much."
    wide = replace(short, suggestions=[tip]).to_text(max_columns=120)
    lines = wide.splitlines()
    assert MIN_INNER + 2 < len(lines[0]) <= 120 - 10
    assert len({len(line) for line in lines}) == 1
    assert any(tip in line for line in lines)

    capped = replace(short, suggestions=[tip]).to_text(max_columns=80)
    capped_lines = capped.splitlines()
    assert len(capped_lines[0]) == 80 - 10
    assert not any(tip in line for line in capped_lines)


def test_each_suggestion_sentence_keeps_its_bullet() -> None:
    text = analyse("password123").to_text()
    first = next(line for line in text.splitlines() if "Add another word" in line)
    second = next(line for line in text.splitlines() if "Uncommon words" in line)

    assert "• Add another word or two." in first
    assert "• Uncommon words are better." in second
    assert len({len(line) for line in text.splitlines()}) == 1


def test_real_dictionary_word_stays_weak() -> None:
    report = analyse("password")

    assert report.length == 8
    assert report.zxcvbn_score is not None
    assert report.zxcvbn_score <= 1
    assert report.score == report.zxcvbn_score * 25
    assert report.character_counts["lowercase"] == 8
    assert "password" not in report.to_dict()
    assert report.guesses is not None
    if report.guesses > 0:
        assert report.entropy_bits == round(math.log2(report.guesses), 2)


def test_empty_password_is_a_report() -> None:
    report = analyse("")

    assert report.length == 0
    assert report.zxcvbn_score == 0
    assert report.score == 0
    assert report.rating == "Very weak"
    assert report.guesses == 1
    assert report.entropy_bits == 0
    assert report.patterns == []
    assert report.unique_characters == 0
    assert report.classes_used == 0
    assert report.crack_times_display["online_throttled"] == "36 seconds"
    assert "Use a few words, avoid common phrases." in report.suggestions
    card = report.to_text().splitlines()
    assert len({len(line) for line in card}) == 1
    assert "Very weak" in report.to_text()


def test_empty_password_can_still_be_checked() -> None:
    client = FakeClient(BreachLookup(status="not_found", count=0))
    report = analyse("", breach_client=client)

    assert client.seen == ""
    assert report.breach_status == "not_found"
    assert report.score == 0


def test_long_password_keeps_composition_without_a_guess_estimate() -> None:
    password = "a" * 73
    report = analyse(password)

    assert report.scored is False
    assert report.length == 73
    assert report.character_counts["lowercase"] == 73
    assert report.score is None
    assert report.rating == "Not scored"
    assert report.zxcvbn_score is None
    assert report.guesses is None
    assert report.entropy_bits is None
    assert report.estimate_note == "Longer than 72 characters, so guesses were not estimated."
    text = report.to_text()
    assert "not estimated" in text
    assert report.estimate_note in text
    assert len({len(line) for line in text.splitlines()}) == 1
    assert "password" not in report.to_dict()


def test_lookalikes_do_not_change_the_score() -> None:
    password = "p\u0430ssword"
    report = analyse(password)

    assert report.lookalikes == [{"character": "\u0430", "looks_like": "a"}]
    assert report.zxcvbn_score is not None
    assert report.score == report.zxcvbn_score * 25
    assert "looks like a" in report.to_text()
    assert len({len(line) for line in report.to_text().splitlines()}) == 1


def test_banned_hit_forces_compromised_without_hiding_an_unscored_password(tmp_path: Path) -> None:
    digest = hibp_sha1("a" * 73)
    path = tmp_path / "banned.txt"
    _ = path.write_text(digest + "\n", encoding="utf-8")
    report = analyse("a" * 73, banned_hashes=BannedList.read(path))

    assert report.banned is True
    assert report.score == 0
    assert report.rating == "Compromised"
    assert report.zxcvbn_score is None
    assert "Found in the banned list." in report.to_text()


def test_unreadable_banned_list_is_not_a_miss(tmp_path: Path) -> None:
    report = analyse("example", banned_hashes=BannedList.read(tmp_path / "missing.txt"))

    assert report.banned is None
    assert report.banned_status == "unreadable"
    assert report.rating != "Compromised"
    text = report.to_text()
    assert "The banned list could not be read." in text
    assert "does not call the password safe" in text


def test_policy_rejects_a_low_score_and_an_unknown_breach() -> None:
    weak = analyse("password", policy=Policy(min_score=75))
    assert weak.policy is not None
    assert weak.policy.accepted is False
    assert weak.policy.failures == (f"score {weak.score} is below 75",)
    assert "Rejected" in weak.to_text()

    unknown = analyse("example", breach_client=FakeClient(BreachLookup(status="network_error", error="The HIBP request failed.")), policy=Policy(min_score=0, reject_breached=True))
    assert unknown.policy is not None
    assert unknown.policy.accepted is False
    assert unknown.policy.failures == ("breach check did not complete",)
    assert unknown.breached is None
    assert unknown.score == (unknown.zxcvbn_score or 0) * 25

    missed = analyse("example", breach_client=FakeClient(BreachLookup(status="not_found", count=0)), policy=Policy(reject_breached=True))
    assert missed.policy is not None
    assert missed.policy.accepted is True
    assert missed.policy.failures == ()
    assert "\033[1;32mAccepted\033[0m" in missed.to_text(colour=True)


def test_policy_without_a_rule_is_rejected() -> None:
    with pytest.raises(ValueError, match="minimum score"):
        _ = Policy()


def test_user_inputs_must_be_strings() -> None:
    with pytest.raises(TypeError, match="strings"):
        _ = analyse("example", user_inputs=cast(Sequence[str], ["ok", 3]))
