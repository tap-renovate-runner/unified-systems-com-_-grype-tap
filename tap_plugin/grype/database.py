"""The Grype advisory database: layout, age rule, locking and the atomic refresh (req-grype-database).

Stdlib only; every subprocess call goes through an injected ``Runner`` so the logic is testable without
Grype. Layout, under the operator's ``<home>``::

    db/<build id>/        one complete database cache per build (Grype writes ``6/vulnerability.db`` inside)
    db/current            symlink to the build scans use; moved atomically, only after a build validated
    db/.lock              flock file: scans hold it shared, a refresh holds it exclusive

A scan resolves ``current`` to its real path once and uses that one directory for every document, so a
refresh that swaps ``current`` cannot give one run two builds. A refresh and a scan never overlap: the
refresh takes the lock exclusively and non-blocking, so while a scan holds it the refresh does not start.
Observed (ran, Grype v0.120.1): a database is about 3 GB on disk, so two kept builds plus a staging copy is
about 9 GB at the peak.
"""

from __future__ import annotations

import fcntl
import json
import os
import shutil
import subprocess
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from tap_plugin.grype.fsutil import repoint
from tap_plugin.grype.mirror import FUTURE_TOLERANCE, MirrorError, parse_time, select_archive
from tap_plugin.grype.settings import Settings

OK = "ok"
STALE = "db-stale"
UNAVAILABLE = "db-unavailable"

KEEP_BUILDS = 2
COMMAND_TIMEOUT_SECONDS = 1800
_STATUS_KEYS = {"schemaVersion", "from", "built", "path", "valid", "error"}


class DatabaseError(RuntimeError):
    """The database could not be read, refreshed or swapped; the installed one is untouched."""


class Busy(DatabaseError):
    """The lock is held by the other kind of job (a scan holds it shared, a refresh exclusive)."""


@dataclass(frozen=True)
class DbStatus:
    """What ``grype db status -o json`` says about a database."""

    schema_version: str
    built: datetime
    source: str | None

    @property
    def data_version(self) -> str:
        """The identifier recorded on a run: the schema and the build time Grype reports."""
        return f"{self.schema_version}@{self.built.strftime('%Y-%m-%dT%H:%M:%SZ')}"

    @property
    def build_id(self) -> str:
        """A directory name for this build."""
        return f"{self.schema_version.lstrip('v')}-{self.built.strftime('%Y%m%dT%H%M%SZ')}"


def parse_status(text: str) -> DbStatus | None:
    """A valid database's status, or None when Grype reports no usable database.

    ``valid`` false (observed: ``{"schemaVersion": "", "path": ..., "valid": false, "error": "database does
    not exist"}``) is None, not an error: it is the ordinary state of a first install. Anything that is not
    that shape is a ``DatabaseError``: an unreadable status is never read as a healthy one.
    """
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise DatabaseError(f"db status is not JSON: {exc}") from exc
    if not isinstance(data, dict) or set(data) - _STATUS_KEYS or not {"schemaVersion", "path", "valid"} <= set(data):
        raise DatabaseError("db status has an unexpected shape")
    if data["valid"] is not True:
        if data["valid"] is not False:
            raise DatabaseError("db status `valid` must be a boolean")
        return None
    schema, source = data["schemaVersion"], data.get("from")
    if not isinstance(schema, str) or not schema.startswith("v"):
        raise DatabaseError(f"db status schemaVersion {schema!r} is not a version")
    try:
        built = parse_time(data.get("built"))
    except MirrorError as exc:
        raise DatabaseError(f"db status built: {exc}") from exc
    return DbStatus(schema_version=schema, built=built, source=source if isinstance(source, str) else None)


def age_outcome(status: DbStatus | None, now: datetime, max_age_days: int) -> str:
    """``ok``, ``db-stale`` (older than the limit) or ``db-unavailable`` (none).

    Age is ``now - built``: Anchore's own build time, never the time of installation, so a late install does
    not make an old build look fresh. A build exactly at the limit is still ok.
    """
    if status is None:
        return UNAVAILABLE
    return STALE if now - status.built > timedelta(days=max_age_days) else OK


@contextmanager
def lock(home: Path, *, exclusive: bool) -> Iterator[None]:
    """Hold the database lock: shared for a scan, exclusive for a refresh; never waits, raises ``Busy``."""
    db_dir = home / "db"
    db_dir.mkdir(parents=True, exist_ok=True)
    fd = os.open(db_dir / ".lock", os.O_RDWR | os.O_CREAT, 0o644)
    try:
        try:
            fcntl.flock(fd, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Busy("a scan holds the database" if exclusive else "a refresh holds the database") from exc
        yield
    finally:
        os.close(fd)  # closing releases the flock


def resolve_current(home: Path) -> Path:
    """The real directory ``current`` points at now. A scan calls this once and keeps the result."""
    current = home / "db" / "current"
    if not current.is_symlink():
        raise DatabaseError("no database is installed (db/current does not exist)")
    resolved = current.resolve(strict=True)
    if not resolved.is_dir():
        raise DatabaseError(f"db/current points at {resolved}, which is not a directory")
    return resolved


@dataclass(frozen=True)
class RunResult:
    """What a subprocess said."""

    returncode: int
    stdout: str
    stderr: str


Runner = Callable[[Sequence[str], Mapping[str, str]], RunResult]


def run_command(argv: Sequence[str], env: Mapping[str, str]) -> RunResult:
    """Run Grype: an argument list, no shell, the given environment only, a timeout."""
    completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, env is built here, not inherited
        list(argv), env=dict(env), capture_output=True, text=True, timeout=COMMAND_TIMEOUT_SECONDS, check=False
    )
    return RunResult(completed.returncode, completed.stdout, completed.stderr)


def grype_env(cache_dir: Path, *, auto_update: bool) -> dict[str, str]:
    """A scrubbed environment: nothing inherited, the cache directory named, update behaviour explicit."""
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(cache_dir),
        "GRYPE_DB_CACHE_DIR": str(cache_dir),
        "GRYPE_DB_AUTO_UPDATE": "true" if auto_update else "false",
        "GRYPE_CHECK_FOR_APP_UPDATE": "false",
    }


def read_status(binary: Path, cache_dir: Path, run: Runner = run_command) -> DbStatus | None:
    """``grype db status -o json`` against a cache directory, with auto-update off."""
    result = run([str(binary), "db", "status", "-o", "json"], grype_env(cache_dir, auto_update=False))
    return parse_status(result.stdout)


@dataclass(frozen=True)
class RefreshResult:
    """The outcome of one refresh: ``installed`` a newer build, or the installed one is ``current``."""

    outcome: str
    status: DbStatus


def _prune(home: Path, keep: int) -> None:
    """Remove builds beyond the ``keep`` newest, never the one ``current`` points at. Exclusive lock held."""
    db_dir = home / "db"
    protected = resolve_current(home)
    builds = sorted(
        (p for p in db_dir.iterdir() if p.is_dir() and not p.is_symlink() and not p.name.startswith(".")),
        key=lambda p: p.name.rsplit("-", 1)[-1],  # the build time, oldest first
    )
    for old in builds[: max(len(builds) - keep, 0)]:
        if old.resolve() != protected:
            shutil.rmtree(old)


def refresh(
    home: Path,
    settings: Settings,
    binary: Path,
    *,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    run: Runner = run_command,
) -> RefreshResult:
    """Install a newer database build, or report that the installed one is current.

    Stages into a fresh directory next to the live one, validates it with ``grype db status``, and only then
    moves it into place and repoints ``current``. Any failure removes the staging copy and leaves the
    installed database serving scans. With ``settings.database_mirror`` set the build comes from the mirror
    (``grype db import``) and the network is not used; otherwise from Anchore (``grype db update``).
    """
    with lock(home, exclusive=True):
        db_dir = home / "db"
        installed: DbStatus | None = None
        if (db_dir / "current").is_symlink():
            installed = read_status(binary, resolve_current(home), run)
        stage = db_dir / f".staging-{os.getpid()}"
        shutil.rmtree(stage, ignore_errors=True)
        stage.mkdir(parents=True, mode=0o700)
        try:
            if settings.database_mirror:
                try:
                    archive = select_archive(Path(settings.database_mirror), now=now())
                except MirrorError as exc:
                    raise DatabaseError(f"mirror: {exc}") from exc
                argv = [str(binary), "db", "import", str(archive.path)]
                env = grype_env(stage, auto_update=False)
            else:
                argv = [str(binary), "db", "update"]
                env = grype_env(stage, auto_update=True)
            result = run(argv, env)
            if result.returncode != 0:
                raise DatabaseError(f"`{' '.join(argv[1:3])}` exited {result.returncode}: {result.stderr.strip()[:300]}")
            staged = read_status(binary, stage, run)
            if staged is None:
                raise DatabaseError("the refreshed database does not validate")
            if staged.built > now() + FUTURE_TOLERANCE:
                raise DatabaseError(f"the refreshed database claims to be built {staged.built.isoformat()}, in the future")
            if installed is not None and staged.built < installed.built:
                raise DatabaseError(
                    f"the refreshed database ({staged.built.isoformat()}) is older than the installed one "
                    f"({installed.built.isoformat()}); refusing a rollback"
                )
            if installed is not None and staged.built == installed.built:
                return RefreshResult(outcome="current", status=installed)
            target = db_dir / staged.build_id
            if target.exists():
                shutil.rmtree(target)
            os.replace(stage, target)
            repoint(db_dir / "current", target.name)
            _prune(home, KEEP_BUILDS)
            return RefreshResult(outcome="installed", status=staged)
        finally:
            shutil.rmtree(stage, ignore_errors=True)

