"""Thin command-line interface.

The password is read from a hidden prompt, or from stdin when stdin is not a
terminal. It is never accepted as an argument.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

from lupaxa.password_strength.analyser import Policy, analyse
from lupaxa.password_strength.banned import BannedList
from lupaxa.password_strength.breach import BreachClient
from lupaxa.password_strength.version import __version__


class NoPasswordError(Exception):
    """The terminal closed before a password was entered."""


class _LineStream(Protocol):
    """A stream that can say whether it is a terminal and yield one line."""

    def isatty(self) -> bool:
        """Return whether the stream is a terminal."""
        raise NotImplementedError

    def readline(self) -> str:
        """Return the next line, including its newline when one was present."""
        raise NotImplementedError


class _Args(argparse.Namespace):
    """Typed view of the parsed command line."""

    def __init__(self) -> None:
        super().__init__()
        self.check_breach: bool = False
        self.json: bool = False
        self.user_input: list[str] = []
        self.timeout: float = 10.0
        self.min_score: int | None = None
        self.reject_breached: bool = False
        self.banned_hashes: Path | None = None


def build_parser() -> argparse.ArgumentParser:
    """Return the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="password-strength-checker",
        description="Score a password and optionally check Have I Been Pwned.",
    )
    _ = parser.add_argument(
        "--check-breach",
        action="store_true",
        help="Check Have I Been Pwned using k-anonymity. Off by default.",
    )
    _ = parser.add_argument("--json", action="store_true", help="Print a JSON report.")
    _ = parser.add_argument(
        "--user-input",
        action="append",
        default=[],
        metavar="WORD",
        help="Word zxcvbn should treat as predictable. Repeat to add more than one.",
    )
    _ = parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Seconds to wait for Have I Been Pwned. Default: 10.",
    )
    _ = parser.add_argument(
        "--min-score",
        type=int,
        help="Reject a password whose overall score is below this, from 0 to 100.",
    )
    _ = parser.add_argument(
        "--reject-breached",
        action="store_true",
        help="Reject a breach or banned-list hit. An incomplete check is rejected too.",
    )
    _ = parser.add_argument(
        "--banned-hashes",
        type=Path,
        metavar="FILE",
        help="File of SHA-1 hashes, one per line. A hit marks the password compromised.",
    )
    _ = parser.add_argument("--version", action="version", version=__version__)
    return parser


def read_password(
    *,
    input_stream: _LineStream | None = None,
    prompt: Callable[[str], str] = getpass.getpass,
) -> str:
    """Read a password without accepting it on the command line.

    Parameters
    ----------
    input_stream : _LineStream, optional
        Stream to read when it is not a terminal. Defaults to stdin.
    prompt : callable, optional
        Hidden prompt used when the stream is a terminal.

    Returns
    -------
    str
        The entered password, which may be empty.

    Raises
    ------
    NoPasswordError
        The terminal closed before a password was entered.
    """
    stream = sys.stdin if input_stream is None else input_stream
    is_tty = getattr(stream, "isatty", lambda: False)
    if is_tty():
        try:
            return prompt("Password: ")
        except EOFError as exc:
            raise NoPasswordError("No password was entered.") from exc
    line = stream.readline()
    if line.endswith("\n"):
        line = line[:-1]
    if line.endswith("\r"):
        line = line[:-1]
    return line


def main(argv: list[str] | None = None) -> int:
    """Run the checker and return a process status.

    Parameters
    ----------
    argv : list of str, optional
        Arguments, excluding the program name. Defaults to the process arguments.

    Returns
    -------
    int
        ``0`` when a report was produced and any policy passed, ``3`` when a policy
        rejected it, ``2`` for usage errors, ``1`` when analysis failed.
    """
    parser = build_parser()
    args = parser.parse_args(argv, namespace=_Args())
    if args.timeout <= 0:
        print("Timeout must be greater than zero.", file=sys.stderr)
        return 2
    if args.min_score is not None and not 0 <= args.min_score <= 100:
        print("Minimum score must be from 0 to 100.", file=sys.stderr)
        return 2
    if args.reject_breached and not args.check_breach and args.banned_hashes is None:
        print("Rejecting breaches needs --check-breach or --banned-hashes.", file=sys.stderr)
        return 2
    try:
        password = read_password()
    except NoPasswordError:
        print("No password was entered.", file=sys.stderr)
        return 2
    client = BreachClient(timeout=args.timeout) if args.check_breach else None
    banned = BannedList.read(args.banned_hashes) if args.banned_hashes is not None else None
    policy = None
    if args.min_score is not None or args.reject_breached:
        policy = Policy(min_score=args.min_score, reject_breached=args.reject_breached)
    try:
        report = analyse(
            password,
            user_inputs=args.user_input,
            breach_client=client,
            banned_hashes=banned,
            policy=policy,
        )
    except (OSError, TypeError, ValueError):
        print("Password analysis failed.", file=sys.stderr)
        return 1
    colour = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    text = report.to_json() if args.json else report.to_text(colour=colour)
    _ = sys.stdout.write(text)
    if not text.endswith("\n"):
        _ = sys.stdout.write("\n")
    if report.policy is not None and not report.policy.accepted:
        return 3
    return 0
