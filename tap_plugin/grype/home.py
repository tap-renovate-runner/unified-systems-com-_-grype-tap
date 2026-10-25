"""Where the pinned binary, the advisory database and the scratch trees live (req-grype-binary, req-grype-database).

Stdlib only. The default sits under the runtime user's ``HOME``, in the container's own filesystem, the way
vuln_mosaic places its stores: tap core offers a plugin no data volume, and a path under ``/app`` is the git
checkout. The cost is accepted (George, 2026-10-25, Q24): a recreated container starts empty, and the refresh
collector places the binary and downloads the database again. A volume is an optimization for later; an operator
who has one sets ``GRYPE_TAP_HOME`` to a directory on it.
"""

from __future__ import annotations

import os
from pathlib import Path

HOME_ENV = "GRYPE_TAP_HOME"
DEFAULT_SUBPATH = ".local/share/tap/grype"


def resolve_home(home: str | os.PathLike[str] | None = None) -> Path:
    """The directory this plugin owns: the argument, else ``GRYPE_TAP_HOME``, else ``~/.local/share/tap/grype``."""
    if home is not None:
        return Path(home)
    configured = os.environ.get(HOME_ENV)
    if configured:
        return Path(configured)
    return Path.home() / DEFAULT_SUBPATH
