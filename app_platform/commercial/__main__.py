"""Entrypoint for ``python -m app_platform.commercial``."""

from __future__ import annotations

import bootstrap_env

bootstrap_env.bootstrap(required=[])

from .cli import main  # noqa: E402


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
