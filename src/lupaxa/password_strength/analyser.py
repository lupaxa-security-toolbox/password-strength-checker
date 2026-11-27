"""Combine zxcvbn, composition, and an optional breach lookup."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from decimal import Decimal
from typing import cast

from zxcvbn import zxcvbn  # pyright: ignore[reportMissingModuleSource]
from zxcvbn.feedback import get_feedback  # pyright: ignore[reportMissingModuleSource]
from zxcvbn.time_estimates import estimate_attack_times  # pyright: ignore[reportMissingModuleSource]

from lupaxa.password_strength.banned import BannedList
from lupaxa.password_strength.breach import PasswordChecker
from lupaxa.password_strength.card import render_report
from lupaxa.password_strength.composition import character_counts
from lupaxa.password_strength.lookalikes import find_lookalikes

ZXCVBN_MAX_LENGTH = 72
_TOO_LONG = "Longer than 72 characters, so guesses were not estimated."

_RATINGS = {
    0: "Very weak",
    1: "Weak",
    2: "Fair",
    3: "Strong",
    4: "Very strong",
}
_CRACK_TIME_FIELDS = (
    ("online_throttling_100_per_hour", "online_throttled"),
    ("online_no_throttling_10_per_second", "online_unthrottled"),
    ("offline_slow_hashing_1e4_per_second", "offline_slow_hash"),
    ("offline_fast_hashing_1e10_per_second", "offline_fast_hash"),
)
_PATTERN_FIELDS = (
    "pattern",
    "token",
    "i",
    "j",
    "guesses",
    "dictionary_name",
    "matched_word",
    "rank",
    "l33t",
    "reversed",
    "sub_display",
    "repeat_count",
    "base_token",
    "sequence_name",
    "sequence_space",
    "year",
    "month",
    "day",
    "regex_name",
    "graph",
    "turns",
)

JsonValue = str | int | float | bool | None


@dataclass(frozen=True)
class Policy:
    """Acceptance rules. They do not change the strength score.

    Attributes
    ----------
    min_score : int or None
        Reject a report whose overall score is below this value, from 0 to 100.
        A password zxcvbn did not score is rejected.
    reject_breached : bool
        Reject a confirmed breach or banned-list hit. An incomplete check is
        rejected as well.
    """

    min_score: int | None = None
    reject_breached: bool = False

    def __post_init__(self) -> None:
        """Reject a policy that has no rule or a score outside 0 to 100."""
        if self.min_score is None and not self.reject_breached:
            raise ValueError("A policy needs a minimum score or breach rejection.")
        if self.min_score is None:
            return
        # bool is an int subclass, so the type has to be checked exactly.
        if type(self.min_score) is not int:
            raise TypeError("min_score must be an integer.")
        if not 0 <= self.min_score <= 100:
            raise ValueError("min_score must be from 0 to 100.")


@dataclass(frozen=True)
class PolicyResult:
    """Whether a report met a policy.

    Attributes
    ----------
    accepted : bool
        True when every requested rule passed.
    failures : tuple of str
        Reasons for a rejection, in rule order. Empty when accepted.
    """

    accepted: bool
    failures: tuple[str, ...]


@dataclass(frozen=True)
class Analysis:
    """Strength report.

    The complete password is not stored. Pattern tokens can still be
    substrings of it, so the report itself is sensitive.

    Attributes
    ----------
    score : int or None
        Overall score from 0 to 100. A confirmed breach or banned hash forces
        this to 0. None when zxcvbn did not score the password.
    rating : str
        Descriptive rating. A confirmed exposure is ``Compromised``. An
        unscored password is ``Not scored``.
    zxcvbn_score : int or None
        Unmodified zxcvbn score from 0 to 4, or None when it was not produced.
    """

    score: int | None
    rating: str
    zxcvbn_score: int | None
    length: int
    character_counts: dict[str, int]
    unique_characters: int
    classes_used: int
    guesses: int | float | None
    entropy_bits: float | None
    crack_times_seconds: dict[str, int | float | None]
    crack_times_display: dict[str, str]
    patterns: list[dict[str, JsonValue]]
    warning: str
    suggestions: list[str]
    lookalikes: list[dict[str, str]]
    estimate_note: str | None
    scored: bool
    breached: bool | None
    breach_count: int | None
    breach_status: str
    breach_error: str | None
    banned: bool | None
    banned_status: str
    banned_error: str | None
    policy: PolicyResult | None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-ready mapping with no password field."""
        return asdict(self)

    def to_json(self) -> str:
        """Return the report as indented JSON."""
        return json.dumps(self.to_dict(), indent=2, allow_nan=False)

    def to_text(self, *, colour: bool = False, max_columns: int | None = None) -> str:
        """Return the report as a text card.

        Parameters
        ----------
        colour : bool, optional
            Colour the rating and the score meter when true.
        max_columns : int, optional
            Terminal width. The card stops 10 columns short of this. When omitted,
            the current terminal is measured.

        Returns
        -------
        str
            The card, without a trailing newline.
        """
        return render_report(self, colour=colour, max_columns=max_columns)


def analyse(
    password: str, *, user_inputs: Sequence[str] | None = None, breach_client: PasswordChecker | None = None, banned_hashes: BannedList | None = None, policy: Policy | None = None
) -> Analysis:
    """Score a password and optionally check breaches, a banned list, and a policy.

    Parameters
    ----------
    password : str
        Password to assess. It is not copied into the report.
    user_inputs : sequence of str, optional
        Words zxcvbn should treat as predictable, such as a username.
    breach_client : PasswordChecker, optional
        When omitted, the report stays offline and does not claim the password is safe.
    banned_hashes : BannedList, optional
        Local SHA-1 list. A hit forces the rating to Compromised. A list that
        cannot be read stays unknown.
    policy : Policy, optional
        When omitted, the report is an assessment and ``policy`` is None.

    Returns
    -------
    Analysis
        Structured strength report.
    """
    words = _user_inputs(user_inputs)
    counts = character_counts(password)
    similar = find_lookalikes(password)
    scored, raw = _zxcvbn_result(password, words)
    crack_seconds: dict[str, int | float | None]
    if scored:
        zxcvbn_score = _bounded_score(raw.get("score"))
        guesses = _guesses(raw.get("guesses"))
        entropy = 0.0 if guesses <= 0 else round(math.log2(guesses), 2)
        crack_seconds = _crack_seconds(_mapping(raw.get("crack_times_seconds")))
        crack_display = _crack_display(_mapping(raw.get("crack_times_display")))
        patterns = _patterns(raw.get("sequence"))
        feedback = _mapping(raw.get("feedback"))
        warning = feedback.get("warning")
        warning_text = warning if isinstance(warning, str) else ""
        suggestions = _suggestions(feedback.get("suggestions"))
        estimate_note = None
    else:
        zxcvbn_score = None
        guesses = None
        entropy = None
        crack_seconds = {}
        for _, name in _CRACK_TIME_FIELDS:
            crack_seconds[name] = None
        crack_display = dict.fromkeys((name for _, name in _CRACK_TIME_FIELDS), "not estimated")
        patterns = []
        warning_text = ""
        suggestions = []
        estimate_note = _TOO_LONG
    lookup = breach_client.lookup(password) if breach_client is not None else None
    banned_lookup = banned_hashes.lookup(password) if banned_hashes is not None else None
    breached = None if lookup is None else lookup.breached
    banned = None if banned_lookup is None else banned_lookup.found
    score, rating = _overall(zxcvbn_score, exposed=breached is True or banned is True)
    breach_status = "not_checked" if lookup is None else lookup.status
    banned_status = "not_checked" if banned_lookup is None else banned_lookup.status
    return Analysis(
        score=score,
        rating=rating,
        zxcvbn_score=zxcvbn_score,
        length=len(password),
        character_counts=counts,
        unique_characters=len(set(password)),
        classes_used=sum(1 for value in counts.values() if value),
        guesses=guesses,
        entropy_bits=entropy,
        crack_times_seconds=crack_seconds,
        crack_times_display=crack_display,
        patterns=patterns,
        warning=warning_text,
        suggestions=suggestions,
        lookalikes=similar,
        estimate_note=estimate_note,
        scored=scored,
        breached=breached,
        breach_count=None if lookup is None else lookup.count,
        breach_status=breach_status,
        breach_error=None if lookup is None else lookup.error,
        banned=banned,
        banned_status=banned_status,
        banned_error=None if banned_lookup is None else banned_lookup.error,
        policy=_apply_policy(policy, score=score, breach_status=breach_status, banned_status=banned_status),
    )


def _zxcvbn_result(password: str, words: list[str]) -> tuple[bool, dict[str, object]]:
    if len(password) > ZXCVBN_MAX_LENGTH:
        return False, {}
    # zxcvbn unwinds a match sequence before its empty-password case, and that unwind crashes.
    if password == "":
        return True, _empty_password_result()
    return True, _mapping(zxcvbn(password, user_inputs=words))


def _apply_policy(policy: Policy | None, *, score: int | None, breach_status: str, banned_status: str) -> PolicyResult | None:
    if policy is None:
        return None
    failures: list[str] = []
    if policy.min_score is not None:
        if score is None:
            failures.append("password was not scored")
        elif score < policy.min_score:
            failures.append(f"score {score} is below {policy.min_score}")
    if policy.reject_breached:
        failures.extend(_exposure_failures(breach_status, banned_status))
    return PolicyResult(accepted=not failures, failures=tuple(failures))


def _exposure_failures(breach_status: str, banned_status: str) -> list[str]:
    failures: list[str] = []
    if breach_status == "breached":
        failures.append("found in a breach")
    elif breach_status not in {"not_checked", "not_found"}:
        failures.append("breach check did not complete")
    if banned_status == "breached":
        failures.append("found in the banned list")
    elif banned_status not in {"not_checked", "not_found"}:
        failures.append("banned list could not be checked")
    if breach_status == "not_checked" and banned_status == "not_checked":
        failures.append("breach check was not run")
    return failures


def _overall(zxcvbn_score: int | None, *, exposed: bool) -> tuple[int | None, str]:
    if exposed:
        return 0, "Compromised"
    if zxcvbn_score is None:
        return None, "Not scored"
    return zxcvbn_score * 25, _RATINGS[zxcvbn_score]


def _empty_password_result() -> dict[str, object]:
    """Return the report zxcvbn means to build for an empty password."""
    guesses = 1
    times = estimate_attack_times(guesses)
    seconds = times["crack_times_seconds"]
    return {
        "score": times["score"],
        "guesses": guesses,
        "crack_times_seconds": {str(key): _finite_float(value) for key, value in _mapping(seconds).items()},
        "crack_times_display": dict(times["crack_times_display"]),
        "sequence": [],
        "feedback": get_feedback(times["score"], []),
    }


def _user_inputs(user_inputs: Sequence[object] | None) -> list[str]:
    words: list[str] = []
    for word in user_inputs or []:
        if not isinstance(word, str):
            raise TypeError("user_inputs must contain strings.")
        words.append(word)
    return words


def _bounded_score(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return min(4, max(0, value))


def _guesses(value: object) -> int | float:
    if isinstance(value, bool) or not isinstance(value, int | float | Decimal):
        return 0
    if isinstance(value, Decimal):
        if not value.is_finite() or value < 0:
            return 0
        if value == value.to_integral_value():
            return int(value)
        return float(value)
    if isinstance(value, int):
        return value if value >= 0 else 0
    if not math.isfinite(value) or value < 0:
        return 0
    return value


def _finite_float(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return 0.0
    return float(value)


def _mapping(value: object) -> dict[str, object]:
    if not isinstance(value, Mapping):
        return {}
    mapped: dict[str, object] = {}
    for key, item in cast(Mapping[object, object], value).items():
        mapped[str(key)] = item
    return mapped


def _objects(value: object) -> list[object]:
    if not isinstance(value, list):
        return []
    return cast(list[object], value)


def _json_value(value: object) -> JsonValue:
    if value is None or isinstance(value, str | bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            return None
        return value
    return str(value)


def _patterns(value: object) -> list[dict[str, JsonValue]]:
    patterns: list[dict[str, JsonValue]] = []
    for item in _objects(value):
        if not isinstance(item, Mapping):
            continue
        pattern: dict[str, JsonValue] = {}
        for key in _PATTERN_FIELDS:
            if key not in item or item[key] is None:
                continue
            pattern[key] = _json_value(item[key])
        if pattern:
            patterns.append(pattern)
    return patterns


def _crack_seconds(values: Mapping[str, object]) -> dict[str, int | float | None]:
    seconds: dict[str, int | float | None] = {}
    for source, name in _CRACK_TIME_FIELDS:
        number = _guesses(values.get(source))
        seconds[name] = number if source in values else None
    return seconds


def _crack_display(values: Mapping[str, object]) -> dict[str, str]:
    display: dict[str, str] = {}
    for source, name in _CRACK_TIME_FIELDS:
        text = values.get(source)
        display[name] = text if isinstance(text, str) and text else "unknown"
    return display


def _suggestions(value: object) -> list[str]:
    return [item for item in _objects(value) if isinstance(item, str)]
