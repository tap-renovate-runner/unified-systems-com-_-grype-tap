"""Rewrite ``binary.json`` for a Grype release from the release's own published checksums (req-grype-binary-5).

    python -m tap_plugin.grype.pin_tool v0.120.1 --write

Renovate moves only the version in ``binary.json``; it cannot compute the archive digests, so a bump
PR fails the checks until this runs (req-grype-binary-8). The tool reads the release's published
``checksums.txt``, downloads each archive, and refuses unless the archive's digest equals that file's
line for it, so a checksum is never copied by hand. It does NOT verify the checksums file's
signature (the release publishes a sigstore bundle; checking it needs cosign or an X.509 parser, which
this stdlib-only tool does not carry). Stdlib only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from tap_plugin.grype.binary_pin import (
    PIN_PATH,
    PLATFORMS,
    PinError,
    archive_name,
    expected_asset_url,
    expected_checksums_url,
    parse_pin,
)
from tap_plugin.grype.installer import Fetcher, InstallError, fetch_url


def parse_checksums(text: str) -> dict[str, str]:
    """``sha256sum``-format lines to ``{file name: digest}``; refuse a malformed line."""
    result: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2 or len(parts[0]) != 64:
            raise PinError(f"malformed checksums line: {line!r}")
        result[parts[1].lstrip("*")] = parts[0].lower()
    return result


def build_pin(version: str, *, fetch: Fetcher = fetch_url) -> dict:
    """The ``binary.json`` content for a release, every digest taken from the release and re-checked."""
    published = parse_checksums(fetch(expected_checksums_url(version)).decode("utf-8"))
    platforms: dict[str, dict[str, str]] = {}
    for platform in PLATFORMS:
        name = archive_name(version, platform)
        if name not in published:
            raise PinError(f"the release's checksums file has no line for {name}")
        archive = fetch(expected_asset_url(version, platform))
        actual = hashlib.sha256(archive).hexdigest()
        if actual != published[name]:
            raise PinError(f"{name}: the archive hashes to {actual} but the release publishes {published[name]}")
        platforms[platform] = {
            "description": f"The Grype {version} release archive for {platform}.",
            "url": expected_asset_url(version, platform),
            "sha256": published[name],
        }
    data = {
        "description": (
            "The pinned Grype release binary (req-grype-binary). The version is the only place it appears; "
            "every sha256 is the release's own published digest, re-checked against the downloaded archive by "
            "tap_plugin.grype.pin_tool. Renovate bumps `version`; run the pin tool to refresh the digests."
        ),
        "version": version,
        "checksums_url": expected_checksums_url(version),
        "platforms": platforms,
    }
    parse_pin(data)  # the file we are about to write must satisfy our own contract
    return data


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pin Grype to a release from its published checksums.")
    parser.add_argument("version", help="a release tag such as v0.120.1")
    parser.add_argument("--write", action="store_true", help="write binary.json (default: print it)")
    parser.add_argument("--path", type=Path, default=PIN_PATH)
    args = parser.parse_args(argv)
    try:
        data = build_pin(args.version)
    except (PinError, InstallError, OSError) as exc:
        print(f"pin tool: {exc}", file=sys.stderr)
        return 1
    text = json.dumps(data, indent=2) + "\n"
    if args.write:
        args.path.write_text(text, encoding="utf-8")
        print(f"wrote {args.path}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    print(
        "note: the checksums file's sigstore signature was NOT verified (needs cosign); record the "
        "signing identity by hand on the first pin.",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
