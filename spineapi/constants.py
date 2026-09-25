"""Constants and path helpers used across SpineAPI."""

from __future__ import annotations

from pathlib import Path
from typing import FrozenSet, Optional, Tuple

SKIP_PATH_HINTS = (
    "/admin/doc",
    "/__debug__",
    "/static/",
    "/media/",
    "/healthz",
    "/readyz",
)

HTTP_METHODS = frozenset({"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"})

NOISE_DIR_NAMES = frozenset({
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".tox",
    "site-packages",
    "dist",
    "build",
})

SOURCE_RANK = {"swagger": 3, "source_code": 2, "catalog": 1}


def is_noise_path(path: Path) -> bool:
    return bool({part.lower() for part in path.parts} & NOISE_DIR_NAMES)


def should_skip_path(path: str) -> bool:
    lower = path.lower()
    return any(hint in lower for hint in SKIP_PATH_HINTS)


def read_text(path: Path) -> Tuple[Optional[str], Optional[OSError]]:
    try:
        return path.read_text(encoding="utf-8"), None
    except OSError as exc:
        return None, exc
