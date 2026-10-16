"""Loads the recorded native Grype outputs (tests/fixtures) for the recorded tier of req-grype-corpus."""

from __future__ import annotations

import hashlib
import json
import zlib
from pathlib import Path

FIXTURES = Path(__file__).with_name("fixtures")
VERSION = "0.120.1"


class FixtureError(AssertionError):
    """A recording does not match what recorded.json says it is."""


def manifest() -> dict:
    """What recorded.json claims about each recording."""
    return json.loads((FIXTURES / "recorded.json").read_text(encoding="utf-8"))


def text(name: str, *, directory: Path = FIXTURES) -> str:
    """The recording's JSON text, e.g. ``tap-web.grype-0.120.1.json.gz``.

    The recording is opaque to a reader of the diff, so it is never trusted blind: decompression is bounded
    by the size the manifest declares (a gzip bomb cannot allocate more), and the result must equal the
    manifest's byte count and sha256 before any test sees it. Bytes after the gzip stream (a hidden second
    member, a trailer) are refused too: the file holds exactly the recording and nothing else.
    """
    claimed = manifest()["files"][name]
    limit = claimed["bytes"]
    inflater = zlib.decompressobj(wbits=31)  # gzip framing
    raw = inflater.decompress((directory / name).read_bytes(), limit + 1)
    if len(raw) > limit or inflater.unconsumed_tail or not inflater.eof or inflater.unused_data:
        raise FixtureError(f"{name} decompresses to more than the {limit} bytes recorded.json declares")
    if len(raw) != limit or hashlib.sha256(raw).hexdigest() != claimed["uncompressed_sha256"]:
        raise FixtureError(f"{name} does not match the size and sha256 in recorded.json")
    return raw.decode("utf-8")


def data(name: str) -> dict:
    """The recording decoded."""
    return json.loads(text(name))


TAP_WEB = "tap-web.grype-0.120.1.json.gz"
LOG4J = "log4j.grype-0.120.1.json.gz"
