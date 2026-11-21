"""Unicode lookalikes stay beside the score."""

from __future__ import annotations

from lupaxa.password_strength.lookalikes import find_lookalikes


def test_cyrillic_and_fullwidth_are_reported_once() -> None:
    cyrillic_a = "\u0430"
    cyrillic_capital = "\u0410"
    fullwidth_a = "\uff21"
    found = find_lookalikes(f"p{cyrillic_a}ss{cyrillic_capital}{fullwidth_a}p{cyrillic_a}")

    assert found == [
        {"character": cyrillic_a, "looks_like": "a"},
        {"character": cyrillic_capital, "looks_like": "A"},
        {"character": fullwidth_a, "looks_like": "A"},
    ]


def test_accents_and_ascii_are_not_lookalikes() -> None:
    assert find_lookalikes("café password") == []
