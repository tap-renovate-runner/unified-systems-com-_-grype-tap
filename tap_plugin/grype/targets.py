"""Mapping a Grype match back to the grid node it concerns (req-grype-collector-5). Stdlib only, no Django.

The collector scans packages and libraries the grid already holds, so every match must land on one of them
or be counted as unmapped; a match is never dropped silently and never guessed onto the wrong node. Two
tiers, strictest first: the artifact's canonical purl equals the target's canonical purl, then the purl type,
name and version equal the target's ecosystem, name and version. A tier that finds more than one target
refuses to choose and reports the match as ``ambiguous``. The second tier exists for packages only: a library
carries no ecosystem, so a library is found by its canonical purl alone.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import parse_qsl, quote, unquote

from tap_plugin.grype.output import Match

NO_TARGET = "no-target"
AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class Target:
    """A package or library node as the collector read it from the grid."""

    id: str
    kind: str  # "package" or "library"
    name: str
    version: str
    ecosystem: str | None = None
    purl: str | None = None


def canonical_purl(purl: str) -> str | None:
    """A purl in one spelling: lowercase type, decoded then re-encoded parts, qualifiers sorted by key.

    Returns None for anything that is not a ``pkg:`` purl with a type and a name, so a malformed purl can
    never equal another by accident. Grype regenerates purls, so the same package arrives spelled differently
    (qualifier order, percent-encoding); both sides go through this one function.
    """
    if not purl.startswith("pkg:"):
        return None
    rest = purl[4:]
    if rest.startswith("/"):
        return None  # a leading slash is not part of a purl; never normalised away into a valid one
    rest, _, subpath = rest.partition("#")
    rest, _, query = rest.partition("?")
    path, at, version = rest.rpartition("@") if "@" in rest.split("/")[-1] else (rest, "", "")
    raw_segments = path.split("/")
    if len(raw_segments) < 2 or not all(raw_segments):
        return None  # an empty segment (``a//b``) is malformed, not a shorter path
    segments = [unquote(part) for part in raw_segments]
    ptype, name = segments[0].lower(), segments[-1]
    namespace = "/".join(segments[1:-1])
    qualifiers = sorted((key.lower(), value) for key, value in parse_qsl(query, keep_blank_values=False))
    out = f"pkg:{quote(ptype, safe='')}/"
    if namespace:
        out += "/".join(quote(part, safe="") for part in namespace.split("/")) + "/"
    out += quote(name, safe="")
    if at:
        out += "@" + quote(unquote(version), safe="")
    if qualifiers:
        out += "?" + "&".join(f"{quote(key, safe='')}={quote(value, safe='')}" for key, value in qualifiers)
    if subpath:
        # Part of a purl's identity: two purls that differ only in subpath are different, never one target.
        out += "#" + "/".join(quote(unquote(part), safe="") for part in subpath.split("/") if part)
    return out


def purl_type(purl: str) -> str | None:
    """The purl's type (``apk``, ``pypi``, ``generic``), lowercased."""
    canonical = canonical_purl(purl)
    return canonical[4:].split("/", 1)[0] if canonical else None


@dataclass(frozen=True)
class Mapping:
    """Where each match went."""

    mapped: dict[str, list[Match]]
    unmapped: list[tuple[Match, str]]


def map_matches(matches: list[Match] | tuple[Match, ...], targets: list[Target]) -> Mapping:
    """Place every match on exactly one target, or on the unmapped list with the reason."""
    by_purl: dict[str, list[Target]] = defaultdict(list)
    by_key: dict[tuple[str, str, str], list[Target]] = defaultdict(list)
    for target in targets:
        canonical = canonical_purl(target.purl) if target.purl else None
        if canonical:
            by_purl[canonical].append(target)
        if target.kind == "package" and target.ecosystem:
            by_key[(target.ecosystem.lower(), target.name, target.version)].append(target)
    mapped: dict[str, list[Match]] = defaultdict(list)
    unmapped: list[tuple[Match, str]] = []
    for match in matches:
        canonical = canonical_purl(match.artifact.purl)
        candidates = by_purl.get(canonical, []) if canonical else []
        if not candidates and canonical:
            candidates = by_key.get((purl_type(match.artifact.purl) or "", match.artifact.name, match.artifact.version), [])
        if len(candidates) == 1:
            mapped[candidates[0].id].append(match)
        else:
            unmapped.append((match, AMBIGUOUS if candidates else NO_TARGET))
    return Mapping(mapped=dict(mapped), unmapped=unmapped)
