"""The operator mirror for the Grype database (req-grype-database, req-grype-database-6).

Where the TAP container cannot reach Anchore, an operator fills a directory with database archives, each
beside a manifest the operator's fetch step wrote (``<archive>.manifest.json``: ``archive``, ``sha256``,
``built``, taken from Anchore's ``latest.json`` over TLS). This module only chooses and verifies; it never
imports. Whether ``grype db import`` itself authenticates an archive is NOT verified, so nothing relies on it.

Trust boundary, stated plainly: anyone who can write this directory (archive and manifest together) can
substitute a database. The digest check catches accident and half-substitution, not a deliberate swap.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

MANIFEST_SUFFIX = ".manifest.json"
FUTURE_TOLERANCE = timedelta(minutes=5)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ARCHIVE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*\.tar\.(zst|gz)$")


class MirrorError(RuntimeError):
    """The mirror holds nothing usable, or something that must not be imported."""


@dataclass(frozen=True)
class MirrorArchive:
    """A verified archive in the mirror."""

    path: Path
    built: datetime
    sha256: str


def parse_time(value: Any) -> datetime:
    """An RFC 3339 UTC timestamp as Grype and Anchore write it (``2026-10-15T06:30:36Z``)."""
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value):
        raise MirrorError(f"not an RFC 3339 UTC time: {value!r}")
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)


def _parse_manifest(path: Path) -> tuple[str, str, datetime]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MirrorError(f"cannot read manifest {path.name}: {exc}") from exc
    if not isinstance(data, dict) or set(data) != {"archive", "sha256", "built"}:
        raise MirrorError(f"manifest {path.name} must hold exactly archive, sha256 and built")
    archive, digest = data["archive"], data["sha256"]
    if not isinstance(archive, str) or not _ARCHIVE.match(archive):
        raise MirrorError(f"manifest {path.name}: archive must be a plain file name ending .tar.zst or .tar.gz")
    if not isinstance(digest, str) or not _SHA256.match(digest):
        raise MirrorError(f"manifest {path.name}: sha256 must be 64 lowercase hex characters")
    return archive, digest, parse_time(data["built"])


def select_archive(directory: Path, *, now: datetime) -> MirrorArchive:
    """The newest verified archive, newest by its manifest's ``built`` and never by file modification time.

    Refuses: a malformed manifest, an archive that is missing, is a symlink, or is not a regular file, a
    digest that differs from the manifest, and a ``built`` stamped in the future.
    """
    if not directory.is_dir():
        raise MirrorError(f"the mirror {directory} is not a directory")
    manifests = sorted(p for p in directory.iterdir() if p.name.endswith(MANIFEST_SUFFIX) and p.is_file())
    if not manifests:
        raise MirrorError(f"the mirror {directory} holds no manifests")
    parsed = [(built, name, digest) for name, digest, built in (_parse_manifest(p) for p in manifests)]
    built, name, digest = max(parsed)  # newest built; ties break on the archive name, deterministically
    if built > now + FUTURE_TOLERANCE:
        raise MirrorError(f"{name} claims to be built {built.isoformat()}, in the future; refusing it")
    archive = directory / name
    if archive.is_symlink() or not archive.is_file():
        raise MirrorError(f"{name} is missing or is not a regular file; refusing it")
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if actual != digest:
        raise MirrorError(f"{name} hashes to {actual}, its manifest says {digest}; refusing it")
    return MirrorArchive(path=archive, built=built, sha256=digest)
