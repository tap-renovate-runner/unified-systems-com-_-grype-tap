"""The pinned Grype release: load and validate ``binary.json`` (req-grype-binary).

Stdlib only, so the installer and the pin tool run in an image build or at provisioning with no
Django. ``binary.json`` is the one place the version appears; the URLs are checked against it
rather than trusted beside it, so a version and a URL cannot drift apart. ``binary.schema.json``
is the published contract for outside tooling; this module enforces the same constraints.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

PIN_PATH = Path(__file__).with_name("binary.json")
PLATFORMS = ("linux/amd64", "linux/arm64")

_VERSION = re.compile(r"^v(\d+\.\d+\.\d+)$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RELEASE = "https://github.com/anchore/grype/releases/download"


class PinError(ValueError):
    """``binary.json`` is missing, malformed, or inconsistent with itself."""


@dataclass(frozen=True)
class Asset:
    """One platform's release archive and the binary inside it."""

    url: str
    sha256: str
    binary_sha256: str


@dataclass(frozen=True)
class Pin:
    """The pinned Grype release."""

    version: str
    checksums_url: str
    assets: dict[str, Asset]

    @property
    def bare_version(self) -> str:
        """The version without its ``v`` (what ``grype --version`` reports)."""
        return self.version[1:]


def archive_name(version: str, platform: str) -> str:
    """The release archive's file name for a platform, e.g. ``grype_0.120.1_linux_amd64.tar.gz``."""
    os_name, arch = platform.split("/")
    return f"grype_{version.removeprefix('v')}_{os_name}_{arch}.tar.gz"


def expected_asset_url(version: str, platform: str) -> str:
    """The release URL a platform's archive must have for this version."""
    return f"{_RELEASE}/{version}/{archive_name(version, platform)}"


def expected_checksums_url(version: str) -> str:
    """The URL of the release's own published checksums file."""
    return f"{_RELEASE}/{version}/grype_{version.removeprefix('v')}_checksums.txt"


def parse_pin(data: Any) -> Pin:
    """Validate a decoded ``binary.json`` and return the pin; raise ``PinError`` on anything else."""
    if not isinstance(data, dict):
        raise PinError("binary.json must be a JSON object")
    allowed = {"description", "version", "checksums_url", "platforms"}
    if set(data) - allowed:
        raise PinError(f"binary.json has unknown keys: {sorted(set(data) - allowed)}")
    if not isinstance(data.get("description"), str) or not data["description"].strip():
        raise PinError("binary.json needs a non-empty top-level description")
    version = data.get("version")
    if not isinstance(version, str) or not _VERSION.match(version):
        raise PinError(f"version must look like v1.2.3, got {version!r}")
    if data.get("checksums_url") != expected_checksums_url(version):
        raise PinError("checksums_url is not the release's published checksums file for this version")
    platforms = data.get("platforms")
    if not isinstance(platforms, dict) or not platforms:
        raise PinError("platforms must name at least one platform")
    assets: dict[str, Asset] = {}
    for name, entry in platforms.items():
        if name not in PLATFORMS:
            raise PinError(f"unsupported platform {name!r}; supported: {list(PLATFORMS)}")
        if not isinstance(entry, dict) or set(entry) != {"description", "url", "sha256", "binary_sha256"}:
            raise PinError(f"platform {name}: expected exactly description, url, sha256, binary_sha256")
        if not isinstance(entry["description"], str) or not entry["description"].strip():
            raise PinError(f"platform {name}: description must be non-empty text")
        if entry["url"] != expected_asset_url(version, name):
            raise PinError(f"platform {name}: url is not the release archive for {version}")
        if not isinstance(entry["sha256"], str) or not _SHA256.match(entry["sha256"]):
            raise PinError(f"platform {name}: sha256 must be 64 lowercase hex characters")
        if not isinstance(entry["binary_sha256"], str) or not _SHA256.match(entry["binary_sha256"]):
            raise PinError(f"platform {name}: binary_sha256 must be 64 lowercase hex characters")
        assets[name] = Asset(url=entry["url"], sha256=entry["sha256"], binary_sha256=entry["binary_sha256"])
    return Pin(version=version, checksums_url=data["checksums_url"], assets=assets)


def load_pin(path: Path = PIN_PATH) -> Pin:
    """Read and validate the pin file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PinError(f"cannot read {path}: {exc}") from exc
    return parse_pin(data)
