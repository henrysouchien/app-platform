from __future__ import annotations

import sys
from pathlib import Path


_PACKAGE_ROOT = Path(__file__).resolve().parent
_REPO_ROOT = _PACKAGE_ROOT.parent


def _normalize_nested_package_test_path() -> None:
    """Keep nested app_platform tests on the repo package, not an installed wheel."""

    package_root = str(_PACKAGE_ROOT)
    repo_root = str(_REPO_ROOT)
    sys.path[:] = [
        entry
        for entry in sys.path
        if Path(entry or ".").resolve() != _PACKAGE_ROOT
    ]
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)
    elif sys.path[0] != repo_root:
        sys.path.remove(repo_root)
        sys.path.insert(0, repo_root)
    if package_root in sys.path:
        sys.path.remove(package_root)


_normalize_nested_package_test_path()
