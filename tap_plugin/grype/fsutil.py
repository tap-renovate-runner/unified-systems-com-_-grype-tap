"""Small filesystem helpers shared by the installer and the database refresh. Stdlib only."""

from __future__ import annotations

import os
from pathlib import Path


def repoint(link: Path, target_name: str) -> None:
    """Atomically make ``link`` a relative symlink to ``target_name`` in its own directory."""
    temporary = link.with_name(f".{link.name}.{os.getpid()}.tmp")
    try:
        if temporary.is_symlink() or temporary.exists():
            temporary.unlink()
        temporary.symlink_to(target_name)
        os.replace(temporary, link)
    finally:
        if temporary.is_symlink() or temporary.exists():
            temporary.unlink()
