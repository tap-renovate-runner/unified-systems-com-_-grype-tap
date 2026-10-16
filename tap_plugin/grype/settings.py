"""The operator-only settings file, ``<home>/settings.json`` (req-grype-binary, req-grype-database).

These settings decide what runs and which database is trusted, so they live on the operator's
filesystem and are never read from the grid: a value on a user-editable node would let anyone who
can edit that node redirect the collector. Stdlib only.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SETTINGS_NAME = "settings.json"
DEFAULT_MAX_AGE_DAYS = 3  # George's ruling, 2026-10-15
_KNOWN = {"database_max_age_days", "database_mirror"}


class SettingsError(ValueError):
    """``settings.json`` is unreadable or holds a value it must not."""


@dataclass(frozen=True)
class Settings:
    """What the operator decided."""

    database_max_age_days: int = DEFAULT_MAX_AGE_DAYS
    database_mirror: str | None = None


def parse_settings(data: Any) -> Settings:
    """Validate decoded settings; raise ``SettingsError`` on any unknown or malformed value."""
    if not isinstance(data, dict):
        raise SettingsError("settings.json must be a JSON object")
    if set(data) - _KNOWN:
        raise SettingsError(f"settings.json has unknown keys: {sorted(set(data) - _KNOWN)}")
    days = data.get("database_max_age_days", DEFAULT_MAX_AGE_DAYS)
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= 365:
        raise SettingsError("database_max_age_days must be an integer from 1 to 365")
    mirror = data.get("database_mirror")
    if mirror is not None and (not isinstance(mirror, str) or not os.path.isabs(mirror)):
        raise SettingsError("database_mirror must be an absolute directory path or null")
    return Settings(database_max_age_days=days, database_mirror=mirror)


def load_settings(home: Path) -> Settings:
    """The operator's settings; defaults when the file does not exist yet."""
    path = home / SETTINGS_NAME
    if not path.exists():
        return Settings()
    try:
        return parse_settings(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError) as exc:
        raise SettingsError(f"cannot read {path}: {exc}") from exc


def write_default_settings(home: Path) -> bool:
    """Write the default file when none exists; never overwrite an operator's choices.

    Returns True when a file was written.
    """
    path = home / SETTINGS_NAME
    if path.exists():
        return False
    home.mkdir(parents=True, exist_ok=True)
    body = {"database_max_age_days": DEFAULT_MAX_AGE_DAYS, "database_mirror": None}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(body, indent=2) + "\n")
    return True
