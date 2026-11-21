"""Text card for a strength report."""

from __future__ import annotations

import re
import shutil
import textwrap
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Protocol


class _PolicyView(Protocol):
    """The policy fields the card prints."""

    @property
    def accepted(self) -> bool:
        """Whether the password met the policy."""
        raise NotImplementedError

    @property
    def failures(self) -> tuple[str, ...]:
        """Reasons the policy rejected the password."""
        raise NotImplementedError


class _Report(Protocol):
    """The report fields the card prints. The password is not one of them."""

    @property
    def score(self) -> int | None:
        """Overall score from 0 to 100, or None when it was not scored."""
        raise NotImplementedError

    @property
    def rating(self) -> str:
        """Descriptive rating."""
        raise NotImplementedError

    @property
    def zxcvbn_score(self) -> int | None:
        """Unmodified zxcvbn score from 0 to 4."""
        raise NotImplementedError

    @property
    def length(self) -> int:
        """Number of characters."""
        raise NotImplementedError

    @property
    def character_counts(self) -> Mapping[str, int]:
        """Counts for each character class."""
        raise NotImplementedError

    @property
    def unique_characters(self) -> int:
        """Number of distinct characters."""
        raise NotImplementedError

    @property
    def classes_used(self) -> int:
        """Number of character classes present."""
        raise NotImplementedError

    @property
    def guesses(self) -> int | float | None:
        """Estimated guesses, or None when they were not estimated."""
        raise NotImplementedError

    @property
    def entropy_bits(self) -> float | None:
        """Log2 of the guess count."""
        raise NotImplementedError

    @property
    def crack_times_display(self) -> Mapping[str, str]:
        """Display strings for the four crack-time scenarios."""
        raise NotImplementedError

    @property
    def warning(self) -> str:
        """Zxcvbn warning, or an empty string."""
        raise NotImplementedError

    @property
    def suggestions(self) -> Sequence[str]:
        """Zxcvbn suggestions."""
        raise NotImplementedError

    @property
    def lookalikes(self) -> Sequence[Mapping[str, str]]:
        """Characters that resemble a different letter or digit."""
        raise NotImplementedError

    @property
    def estimate_note(self) -> str | None:
        """Why guesses were left empty, when they were."""
        raise NotImplementedError

    @property
    def breach_count(self) -> int | None:
        """Recorded breach occurrences."""
        raise NotImplementedError

    @property
    def breach_status(self) -> str:
        """Breach lookup status."""
        raise NotImplementedError

    @property
    def breach_error(self) -> str | None:
        """Why the breach lookup could not be trusted."""
        raise NotImplementedError

    @property
    def banned_status(self) -> str:
        """Banned-list lookup status."""
        raise NotImplementedError

    @property
    def banned_error(self) -> str | None:
        """Why the banned list could not be trusted."""
        raise NotImplementedError

    @property
    def policy(self) -> _PolicyView | None:
        """Policy result, or None when no policy was set."""
        raise NotImplementedError


MIN_INNER = 62
_TERMINAL_MARGIN = 10
_LABEL_WIDTH = 24
_PAIR_VALUE_WIDTH = 6
_SECOND_LABEL_WIDTH = 19

_COUNTS = (
    ("lowercase", "Lowercase"),
    ("uppercase", "Uppercase"),
    ("digits", "Digits"),
    ("symbols", "Symbols"),
    ("spaces", "Spaces"),
    ("other_unicode", "Other Unicode"),
)
_CRACKS = (
    ("online_throttled", "Online (Throttled)"),
    ("online_unthrottled", "Online (Unthrottled)"),
    ("offline_slow_hash", "Offline (Slow Hash)"),
    ("offline_fast_hash", "Offline (Fast Hash)"),
)
_RATING_COLOUR = {
    "Compromised": "31",
    "Very weak": "31",
    "Weak": "33",
    "Fair": "33",
    "Strong": "32",
    "Very strong": "92",
}


def render_report(report: _Report, *, colour: bool = False, max_columns: int | None = None) -> str:
    """Render a strength report as a text card.

    The card stays at its usual width unless a warning or suggestion is longer
    than that. It then grows to fit the tip, but never wider than the terminal
    width minus 10 columns. A longer tip wraps.

    Parameters
    ----------
    report : _Report
        Strength report to display. The password itself is not a field on it.
    colour : bool, optional
        Colour the frame, title, section titles, field labels, rating, meter, warnings, and breaches.
        Defaults to plain text.
    max_columns : int, optional
        Terminal width. The card stops 10 columns short of this. When omitted,
        the current terminal is measured.

    Returns
    -------
    str
        The card, without a trailing newline.
    """
    inner = _card_inner(report, max_columns=max_columns if max_columns is not None else _terminal_columns())
    rows = [
        _center("Password Strength", inner),
        "",
        *_header(report, inner),
    ]
    if report.lookalikes:
        rows.extend([_band("Lookalikes", inner), *_lookalikes(report, inner)])
    rows.extend(
        [
            _band("Composition", inner),
            *_composition(report),
            _band("Guessing", inner),
            *_guessing(report, inner),
            _band("Advice", inner),
            *_advice(report, inner),
            _band("Breach", inner),
            *_breach(report, inner),
        ]
    )
    if report.banned_status != "not_checked":
        rows.extend([_band("Banned", inner), *_banned(report, inner)])
    if report.policy is not None:
        rows.extend([_band("Policy", inner), *_policy(report, inner)])
    framed = [
        _edge("╭", "╮", inner),
        *[_rule(row, inner) if row.startswith("├") else _box(row, inner) for row in rows],
        _edge("╰", "╯", inner),
    ]
    if colour:
        framed = _colourise(framed, report)
    return "\n".join(framed)


def _terminal_columns() -> int:
    return shutil.get_terminal_size(fallback=(80, 24)).columns


def _card_inner(report: _Report, *, max_columns: int) -> int:
    """Return a card width that fits the longest tip, within the terminal cap."""
    width = MIN_INNER
    prefix = 2 + _LABEL_WIDTH
    warning = report.warning.strip()
    if warning:
        width = max(width, prefix + _width(warning) + 2)
    for tip in _tips(report.suggestions):
        width = max(width, prefix + _width(f"• {tip}") + 2)
    # The drawn line includes both borders, and stays 10 columns inside the terminal.
    limit = max(1, max_columns - _TERMINAL_MARGIN - 2)
    return min(width, limit)


def _header(report: _Report, inner: int) -> list[str]:
    usable = inner - 2
    score = "not scored" if report.score is None else f"{report.score} / 100"
    left = f"  {report.rating}"
    gap = usable - _width(left) - _width(score)
    rating_line = left if gap < 1 else left + " " * gap + score
    bar_width = usable - 2
    filled = 0 if report.score is None else round(report.score / 100 * bar_width)
    filled = min(bar_width, max(0, filled))
    bar = "█" * filled + "░" * (bar_width - filled)
    zxcvbn = "— / 4" if report.zxcvbn_score is None else f"{report.zxcvbn_score} / 4"
    zx_left = "  zxcvbn:"
    zx_gap = usable - _width(zx_left) - _width(zxcvbn)
    return [rating_line, "  " + bar, zx_left + " " * max(zx_gap, 1) + zxcvbn]


def _composition(report: _Report) -> list[str]:
    items = [
        ("Length", str(report.length)),
        ("Unique characters", str(report.unique_characters)),
        ("Character classes", str(report.classes_used)),
    ]
    items.extend((label, str(report.character_counts.get(key, 0))) for key, label in _COUNTS)
    rows: list[str] = []
    for start in range(0, len(items), 2):
        right = items[start + 1] if start + 1 < len(items) else None
        rows.append(_composition_row(items[start], right))
    return rows


def _lookalikes(report: _Report, inner: int) -> list[str]:
    rows: list[str] = []
    for item in report.lookalikes:
        rows.extend(_field(item["character"], f"looks like {item['looks_like']}", inner))
    return rows


def _guessing(report: _Report, inner: int) -> list[str]:
    if report.estimate_note is not None or report.guesses is None or report.entropy_bits is None:
        rows = _field("Guesses", "not estimated", inner)
        rows.extend(_field("Entropy", "not estimated", inner))
        if report.estimate_note:
            rows.append("")
            rows.extend(_note(report.estimate_note, inner))
        return rows
    rows = _field("Guesses", _format_guesses(report.guesses), inner)
    rows.extend(_field("Entropy", f"{report.entropy_bits:.2f} bits", inner))
    rows.append("")
    for key, label in _CRACKS:
        rows.extend(_field(label, report.crack_times_display.get(key) or "unknown", inner))
    return rows


def _advice(report: _Report, inner: int) -> list[str]:
    warning = report.warning.strip()
    rows = _field("Warning", warning or "None", inner)
    tips = _tips(report.suggestions)
    if not tips:
        rows.extend(_field("Suggestions", "None", inner))
        return rows
    for index, tip in enumerate(tips):
        label = "Suggestions" if index == 0 else ""
        rows.extend(_bullet_field(label, tip, inner))
    return rows


def _tips(suggestions: Sequence[str]) -> list[str]:
    tips: list[str] = []
    for suggestion in suggestions:
        parts = re.split(r"(?<=[.!?])\s+", suggestion.strip())
        tips.extend(part for part in parts if part)
    return tips


def _bullet_field(label: str, text: str, inner: int) -> list[str]:
    prefix = f"  {_label(label):<{_LABEL_WIDTH}}"
    marker = "• "
    room = inner - 2 - _width(prefix) - _width(marker)
    parts = textwrap.wrap(text, width=max(room, 8), break_long_words=True, break_on_hyphens=False) or [""]
    rows = [prefix + marker + parts[0]]
    hang = " " * (_width(prefix) + _width(marker))
    rows.extend(hang + part for part in parts[1:])
    return rows


def _breach(report: _Report, inner: int) -> list[str]:
    if report.breach_status == "not_checked":
        return _note("Not run. The check stayed on this machine.", inner)
    if report.breach_status == "not_found":
        return [
            *_note("Not found in this dataset.", inner),
            *_note("This does not mean the password is safe.", inner),
        ]
    if report.breach_status == "breached":
        count = 0 if report.breach_count is None else report.breach_count
        return _note(f"Breached. {count:,} occurrences.", inner)
    detail = (report.breach_error or report.breach_status).rstrip(".")
    return [
        *_note(f"{detail}.", inner),
        *_note("This report does not call the password safe.", inner),
    ]


def _banned(report: _Report, inner: int) -> list[str]:
    if report.banned_status == "breached":
        return _note("Found in the banned list.", inner)
    if report.banned_status == "not_found":
        return [
            *_note("Not in this banned list.", inner),
            *_note("This does not mean the password is safe.", inner),
        ]
    detail = (report.banned_error or "The banned list could not be checked.").rstrip(".")
    return [
        *_note(f"{detail}.", inner),
        *_note("This report does not call the password safe.", inner),
    ]


def _policy(report: _Report, inner: int) -> list[str]:
    if report.policy is None:
        return []
    if report.policy.accepted:
        return ["  Accepted"]
    rows = ["  Rejected"]
    for failure in report.policy.failures:
        rows.extend(_note(f"• {failure}", inner))
    return rows


def _label(text: str) -> str:
    if not text or text.endswith(":"):
        return text
    return f"{text}:"


def _composition_row(left: tuple[str, str], right: tuple[str, str] | None) -> str:
    label, value = left
    line = f"  {_label(label):<{_LABEL_WIDTH}}{_pad(value, _PAIR_VALUE_WIDTH)}"
    if right is None:
        return line
    second_label, second_value = right
    return f"{line}  {_label(second_label):<{_SECOND_LABEL_WIDTH}}{second_value}"


def _field(label: str, value: str, inner: int) -> list[str]:
    label = _label(label)
    prefix = f"  {label:<{_LABEL_WIDTH}}"
    room = inner - 2 - _width(prefix)
    if room < 8:
        return _note(f"{label} {value}" if label else value, inner)
    parts = textwrap.wrap(value, width=room, break_long_words=True, break_on_hyphens=False) or [""]
    rows = [prefix + parts[0]]
    pad = " " * _width(prefix)
    rows.extend(pad + part for part in parts[1:])
    return rows


def _note(text: str, inner: int) -> list[str]:
    parts = textwrap.wrap(text, width=inner - 4, break_long_words=True, break_on_hyphens=False) or [""]
    return [f"  {part}" for part in parts]


def _band(title: str, inner: int) -> str:
    label = f" {title} "
    if _width(label) > inner:
        label = _clip(label, inner)
    gap = inner - _width(label)
    left = gap // 2
    return "├" + "─" * left + label + "─" * (gap - left) + "┤"


def _box(content: str, inner: int) -> str:
    return "│" + _fit(content, inner) + "│"


def _rule(content: str, inner: int) -> str:
    return content if _width(content) == inner + 2 else _fit(content, inner + 2)


def _center(text: str, inner: int) -> str:
    gap = inner - _width(text)
    return " " * (gap // 2) + text


def _edge(left: str, right: str, inner: int) -> str:
    return left + "─" * inner + right


def _colourise(lines: list[str], report: _Report) -> list[str]:
    rating = "2" if report.rating == "Not scored" else "1;" + _RATING_COLOUR.get(report.rating, "37")
    meter = "2" if report.score is None else rating
    score = None if report.score is None else f"{report.score} / 100"
    painted: list[str] = []
    warning_follows = False
    for line in lines:
        spans, warning_follows = _line_spans(
            line,
            report,
            rating=rating,
            meter=meter,
            score=score,
            warning_follows=warning_follows,
        )
        painted.append(_paint_spans(line, spans))
    return painted


def _line_spans(
    line: str,
    report: _Report,
    *,
    rating: str,
    meter: str,
    score: str | None,
    warning_follows: bool,
) -> tuple[list[tuple[int, int, str]], bool]:
    if line.startswith(("╭", "╰")):
        return [(0, len(line), "2;90")], False
    if line.startswith("├"):
        return _band_spans(line), False
    if not line.startswith("│"):
        return [], False
    spans = [(0, 1, "2;90"), (len(line) - 1, len(line), "2;90")]
    if "█" in line or "░" in line:
        start = next(index for index, char in enumerate(line) if char in "█░")
        end = start
        while end < len(line) and line[end] in "█░":
            end += 1
        spans.append((start, end, meter))
        return spans, False
    if "Password Strength" in line:
        start = line.find("Password Strength")
        spans.append((start, start + len("Password Strength"), "1;4;36"))
        return spans, False
    body = line[3:-1].strip()
    if body == report.rating or body.startswith(f"{report.rating} "):
        start = line.find(report.rating)
        spans.append((start, start + len(report.rating), rating))
        if score is not None:
            score_at = line.rfind(score)
            if score_at != -1:
                spans.append((score_at, score_at + len(score), rating))
        return spans, False
    if body in {"Accepted", "Rejected"}:
        bounds = _text_bounds(line, 3)
        if bounds is not None:
            spans.append((*bounds, "1;32" if body == "Accepted" else "1;31"))
        return spans, False
    if body.startswith("Breached.") or body.startswith("Found in the banned list."):
        bounds = _text_bounds(line, 3)
        if bounds is not None:
            spans.append((*bounds, "1;31"))
        return spans, False
    if body.startswith("Not run.") or "does not " in body:
        bounds = _text_bounds(line, 3)
        if bounds is not None:
            spans.append((*bounds, "2"))
        return spans, False
    if warning_follows and not line[3:27].strip():
        bounds = _text_bounds(line, 27)
        if bounds is not None:
            spans.append((*bounds, "33"))
            return spans, True
        return spans, False
    warning_follows = False
    for start, width in ((3, _LABEL_WIDTH), (35, _SECOND_LABEL_WIDTH)):
        label = _column_label(line, start, width)
        if label is not None:
            spans.append((*label, "1;32"))
            if line[label[0] : label[1]] == "Warning:":
                bounds = _text_bounds(line, start + width)
                if bounds is not None and line[bounds[0] : bounds[1]] != "None":
                    spans.append((*bounds, "33"))
                    warning_follows = True
    return spans, warning_follows


def _band_spans(line: str) -> list[tuple[int, int, str]]:
    for title in ("Lookalikes", "Composition", "Guessing", "Advice", "Breach", "Banned", "Policy"):
        start = line.find(f" {title} ")
        if start == -1:
            continue
        word = start + 1
        end = word + len(title)
        return [(0, word, "2;90"), (word, end, "1;36"), (end, len(line), "2;90")]
    return [(0, len(line), "2;90")]


def _column_label(line: str, start: int, width: int) -> tuple[int, int] | None:
    if start + width >= len(line):
        return None
    column = line[start : start + width]
    if not column.endswith(" ") or not column.strip() or not line[start + width : -1].strip():
        return None
    text = column.rstrip(" ")
    return start, start + len(text)


def _text_bounds(line: str, start: int) -> tuple[int, int] | None:
    end = len(line) - 1
    while end > start and line[end - 1] == " ":
        end -= 1
    if end <= start:
        return None
    return start, end


def _paint_spans(line: str, spans: list[tuple[int, int, str]]) -> str:
    for start, end, code in sorted(spans, reverse=True):
        line = _paint(line, start, end, code)
    return line


def _paint(line: str, start: int, end: int, code: str) -> str:
    return f"{line[:start]}\033[{code}m{line[start:end]}\033[0m{line[end:]}"


def _format_guesses(guesses: int | float) -> str:
    if isinstance(guesses, int):
        return f"{guesses:,}"
    if guesses.is_integer():
        return f"{int(guesses):,}"
    return f"{guesses:,.2f}"


def _width(text: str) -> int:
    total = 0
    for character in text:
        if unicodedata.category(character) in {"Mn", "Me"}:
            continue
        total += 2 if unicodedata.east_asian_width(character) in {"W", "F"} else 1
    return total


def _pad(text: str, width: int) -> str:
    if _width(text) >= width:
        return text
    return text + " " * (width - _width(text))


def _fit(text: str, width: int) -> str:
    if _width(text) > width:
        text = _clip(text, width)
    return text + " " * (width - _width(text))


def _clip(text: str, width: int) -> str:
    kept: list[str] = []
    used = 0
    for character in text:
        if unicodedata.category(character) in {"Mn", "Me"}:
            kept.append(character)
            continue
        size = 2 if unicodedata.east_asian_width(character) in {"W", "F"} else 1
        if used + size > width:
            break
        kept.append(character)
        used += size
    return "".join(kept)
