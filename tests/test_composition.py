"""Character composition."""

from lupaxa.password_strength.composition import character_counts


def test_counts_ascii_classes_and_other_unicode() -> None:
    counts = character_counts("Aa1! ü")

    assert counts == {
        "lowercase": 1,
        "uppercase": 1,
        "digits": 1,
        "symbols": 1,
        "spaces": 1,
        "other_unicode": 1,
    }


def test_tabs_and_newlines_count_as_spaces() -> None:
    counts = character_counts("a\tb\n")

    assert counts["lowercase"] == 2
    assert counts["spaces"] == 2
    assert counts["other_unicode"] == 0
