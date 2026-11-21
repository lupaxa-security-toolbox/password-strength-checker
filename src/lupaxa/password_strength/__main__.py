"""Allow ``python -m lupaxa.password_strength``."""

from lupaxa.password_strength.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
