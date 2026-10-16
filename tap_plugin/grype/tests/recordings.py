"""Loads the recorded native Grype outputs (tests/fixtures) for the recorded tier of req-grype-corpus."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

FIXTURES = Path(__file__).with_name("fixtures")
VERSION = "0.120.1"


def text(name: str) -> str:
    """The recording's JSON text, e.g. ``tap-web.grype-0.120.1.json.gz``."""
    return gzip.decompress((FIXTURES / name).read_bytes()).decode("utf-8")


def data(name: str) -> dict:
    """The recording decoded."""
    return json.loads(text(name))


TAP_WEB = "tap-web.grype-0.120.1.json.gz"
LOG4J = "log4j.grype-0.120.1.json.gz"
