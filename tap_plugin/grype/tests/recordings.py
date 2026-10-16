"""Loads the recorded native Grype outputs (tests/fixtures, plain JSON) for the recorded tier of req-grype-corpus."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

FIXTURES = Path(__file__).with_name("fixtures")
VERSION = "0.120.1"


class FixtureError(AssertionError):
    """A recording does not match what recorded.json says it is."""


def manifest() -> dict:
    """What recorded.json claims about each recording."""
    return json.loads((FIXTURES / "recorded.json").read_text(encoding="utf-8"))


def text(name: str, *, directory: Path = FIXTURES) -> str:
    """The recording's JSON text, e.g. ``tap-web.grype-0.120.1.trimmed.json``.

    The recordings are plain JSON a reviewer can read in the diff. They are still checked against
    recorded.json before any test sees them, so an edit that changes a recording without updating the manifest
    (and so without being noticed in review) fails here.
    """
    claimed = manifest()["files"][name]
    raw = (directory / name).read_bytes()
    if len(raw) != claimed["bytes"] or hashlib.sha256(raw).hexdigest() != claimed["sha256"]:
        raise FixtureError(f"{name} does not match the size and sha256 in recorded.json")
    return raw.decode("utf-8")


def data(name: str) -> dict:
    """The recording decoded."""
    return json.loads(text(name))


TAP_WEB = "tap-web.grype-0.120.1.trimmed.json"
LOG4J = "log4j.grype-0.120.1.trimmed.json"
