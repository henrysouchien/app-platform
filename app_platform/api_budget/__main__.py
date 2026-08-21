"""Package entrypoint for ``python -m app_platform.api_budget``."""

# --- bootstrap_env path discovery (auto-injected for `python3 path/to/file.py` invocations) ---
import sys as _bootstrap_sys
from pathlib import Path as _BootstrapPath
_p = _BootstrapPath(__file__).resolve()
while _p.parent != _p:
    if (_p / "bootstrap_env.py").exists():
        if str(_p) not in _bootstrap_sys.path:
            _bootstrap_sys.path.insert(0, str(_p))
        break
    _p = _p.parent
del _p, _bootstrap_sys, _BootstrapPath
# --- end auto-injected ---

import bootstrap_env

bootstrap_env.bootstrap(required=[])

from .cli import main


if __name__ == "__main__":  # pragma: no cover - module entrypoint
    raise SystemExit(main())
