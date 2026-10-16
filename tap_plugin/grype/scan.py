"""Running Grype over one SBOM document (req-grype-collector-3, -4, -6). Stdlib only, no Django.

One invocation per document, with the controls the spec names: an argument list and no shell, a scrubbed
environment with the database pinned to one directory and every update switch off (a scan never opens a
connection), a timeout, and the output written to a file the scan owns so its size is checked before it is
read instead of after it is in memory (observed 2026-10-16: ``-o json=<file>`` writes the file and prints
nothing). Grid data never reaches a command line: the only variable argument is a path this module builds.
Every failure is one ``ScanError``; the caller records the document's targets as not scanned.
"""

from __future__ import annotations

import os
import re
import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from tap_plugin.grype.database import Runner, grype_env, run_command
from tap_plugin.grype.output import MAX_DOCUMENT_BYTES, Document, GrypeOutputError, parse_document

_RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{7,63}$")
MAX_SBOM_BYTES = 256 * 1024 * 1024


class ScanError(RuntimeError):
    """A document could not be scanned or its output could not be trusted."""


@contextmanager
def scratch_dir(home: Path, run_id: str) -> Iterator[Path]:
    """``<home>/scratch/<run_id>/``: per run, mode 0700, never fixed or cwd-relative, removed on exit.

    The run id is checked against a plain pattern, so it cannot name another directory. Two concurrent runs
    have different ids and so never share a path; the directory is removed whether the run ended or failed.
    """
    if not _RUN_ID.match(run_id):
        raise ScanError(f"run id {run_id!r} is not a plain identifier")
    root = home / "scratch"
    root.mkdir(parents=True, exist_ok=True)
    path = root / run_id
    path.mkdir(mode=0o700)  # an existing directory is a collision, never silently reused
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def scan_document(
    binary: Path,
    db_dir: Path,
    sbom: bytes,
    scratch: Path,
    *,
    expected_version: str,
    index: int = 0,
    run: Runner = run_command,
) -> Document:
    """Scan one SBOM and return the parsed document, or raise ``ScanError``.

    ``db_dir`` is the one database directory this whole run uses (``database.resolve_current``, resolved once).
    File names inside ``scratch`` are fixed (``doc-<n>.cdx.json``, ``out-<n>.json``) and never derived from data.
    """
    if len(sbom) > MAX_SBOM_BYTES:
        raise ScanError("the SBOM is implausibly large; refusing to write it")
    sbom_path = scratch / f"doc-{int(index)}.cdx.json"
    out_path = scratch / f"out-{int(index)}.json"
    fd = os.open(sbom_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(sbom)
    argv = [str(binary), f"sbom:{sbom_path}", "-o", f"json={out_path}"]
    try:
        result = run(argv, grype_env(db_dir, auto_update=False))
    except OSError as exc:
        raise ScanError(f"could not run grype: {exc}") from exc
    if result.returncode != 0:
        raise ScanError(f"grype exited {result.returncode}: {result.stderr.strip()[:300]}")
    if out_path.is_symlink() or not out_path.is_file():
        raise ScanError("grype wrote no output file")
    if out_path.stat().st_size > MAX_DOCUMENT_BYTES:
        raise ScanError("grype's output is implausibly large; refusing to read it")
    try:
        return parse_document(out_path.read_text(encoding="utf-8"), expected_version=expected_version)
    except (GrypeOutputError, UnicodeDecodeError) as exc:
        raise ScanError(f"grype's output cannot be trusted: {exc}") from exc
