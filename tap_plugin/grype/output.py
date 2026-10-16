"""Grype's native JSON, strictly parsed (req-grype-collector, req-grype-collector-4).

Stdlib only. The parser reads exactly the fields the plugin uses and refuses anything else it cannot
trust: it never repairs, defaults or guesses, because a finding written from a half-read document is worse
than none. Failure is one exception, ``GrypeOutputError``, and the caller turns it into "these targets were
not scanned"; nothing is inferred from a partial parse.

Shapes below were observed (ran 2026-10-15/16, Grype v0.120.1, tap-web and log4j-core SBOMs), not assumed:
``epss``, ``cwes`` and ``description`` are absent on many matches, ``knownExploited`` is absent unless the
vulnerability is on the CISA catalog, ``fix.state`` is ``fixed`` or ``unknown`` (``not-fixed`` and
``wont-fix`` are documented and handled), and ``descriptor.db.status`` reports the database the scan used.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Any

MAX_DOCUMENT_BYTES = 128 * 1024 * 1024
FIX_STATES = ("fixed", "not-fixed", "wont-fix", "unknown")
_VULN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_SCHEMA_VERSION = re.compile(r"^v\d{1,3}(\.\d{1,3}){0,2}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


class GrypeOutputError(ValueError):
    """The document is not one this plugin can read safely."""


@dataclass(frozen=True)
class DbInfo:
    """The database a document says it was matched against (``descriptor.db.status``)."""

    schema_version: str
    built: datetime
    source: str | None

    @property
    def data_version(self) -> str:
        """The identifier recorded on a run; identical to ``database.DbStatus.data_version``."""
        return f"{self.schema_version}@{self.built.strftime('%Y-%m-%dT%H:%M:%SZ')}"


@dataclass(frozen=True)
class KevEntry:
    """One CISA Known Exploited Vulnerabilities entry as Grype carries it."""

    cve: str
    date_added: date | None
    due_date: date | None
    required_action: str | None
    ransomware_use: str | None


@dataclass(frozen=True)
class EpssEntry:
    """One EPSS reading."""

    cve: str
    score: float
    percentile: float
    on: date


@dataclass(frozen=True)
class Artifact:
    """The package Grype matched."""

    name: str
    version: str
    type: str
    purl: str


@dataclass(frozen=True)
class Match:
    """One vulnerability matched against one artifact."""

    vuln_id: str
    related_ids: tuple[str, ...]
    severity: str
    description: str | None
    data_source: str | None
    fix_state: str
    fixed_versions: tuple[str, ...]
    kev: tuple[KevEntry, ...]
    epss: tuple[EpssEntry, ...]
    artifact: Artifact


@dataclass(frozen=True)
class Document:
    """A parsed Grype document."""

    grype_version: str
    db: DbInfo | None
    matches: tuple[Match, ...]


def _fail(where: str, why: str) -> GrypeOutputError:
    return GrypeOutputError(f"{where}: {why}")


def _obj(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _fail(where, "expected an object")
    return value


def _str(container: dict[str, Any], key: str, where: str, *, required: bool = True) -> str | None:
    value = container.get(key)
    if value is None:
        if required:
            raise _fail(where, f"missing required `{key}`")
        return None
    if not isinstance(value, str) or (required and not value):
        raise _fail(where, f"`{key}` must be a {'non-empty ' if required else ''}string")
    return value


def _day(value: Any, where: str) -> date:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise _fail(where, f"not a YYYY-MM-DD date: {value!r}")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise _fail(where, f"not a real date: {value!r}") from exc


def _unit(value: Any, where: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1:
        raise _fail(where, f"must be a number from 0 to 1, got {value!r}")
    return float(value)


def _vuln_id(value: Any, where: str) -> str:
    if not isinstance(value, str) or not _VULN_ID.match(value):
        raise _fail(where, f"not a usable vulnerability id: {value!r}")
    return value


def _parse_db(descriptor: dict[str, Any]) -> DbInfo | None:
    """The database block. Absent is None (the document cannot say which database it used); present must be sound."""
    db = descriptor.get("db")
    if db is None:
        return None
    status = _obj(_obj(db, "descriptor.db").get("status"), "descriptor.db.status")
    if status.get("valid") is not True:
        raise _fail("descriptor.db.status", "the scan reports its database as not valid")
    schema = status.get("schemaVersion")
    if not isinstance(schema, str) or not _SCHEMA_VERSION.match(schema):
        raise _fail("descriptor.db.status", f"schemaVersion {schema!r} is not a version")
    built = status.get("built")
    if not isinstance(built, str) or not _TIME.match(built):
        raise _fail("descriptor.db.status", f"built {built!r} is not an RFC 3339 UTC time")
    source = status.get("from")
    return DbInfo(
        schema_version=schema,
        built=datetime.strptime(built, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC),
        source=source if isinstance(source, str) else None,
    )


def _parse_kev(entries: Any, where: str) -> tuple[KevEntry, ...]:
    if entries is None:
        return ()
    if not isinstance(entries, list):
        raise _fail(where, "knownExploited must be a list")
    parsed = []
    for index, raw in enumerate(entries):
        entry = _obj(raw, f"{where}[{index}]")
        cve = entry.get("cve")
        if not isinstance(cve, str) or not _CVE.match(cve):
            raise _fail(f"{where}[{index}]", f"cve {cve!r} is not a CVE id")
        added = entry.get("dateAdded")
        due = entry.get("dueDate")
        parsed.append(
            KevEntry(
                cve=cve,
                date_added=_day(added, f"{where}[{index}].dateAdded") if added else None,
                due_date=_day(due, f"{where}[{index}].dueDate") if due else None,
                required_action=_str(entry, "requiredAction", f"{where}[{index}]", required=False),
                ransomware_use=_str(entry, "knownRansomwareCampaignUse", f"{where}[{index}]", required=False),
            )
        )
    return tuple(parsed)


def _parse_epss(entries: Any, where: str) -> tuple[EpssEntry, ...]:
    if entries is None:
        return ()
    if not isinstance(entries, list):
        raise _fail(where, "epss must be a list")
    parsed = []
    for index, raw in enumerate(entries):
        entry = _obj(raw, f"{where}[{index}]")
        cve = entry.get("cve")
        if not isinstance(cve, str) or not _CVE.match(cve):
            raise _fail(f"{where}[{index}]", f"cve {cve!r} is not a CVE id")
        parsed.append(
            EpssEntry(
                cve=cve,
                score=_unit(entry.get("epss"), f"{where}[{index}].epss"),
                percentile=_unit(entry.get("percentile"), f"{where}[{index}].percentile"),
                on=_day(entry.get("date"), f"{where}[{index}].date"),
            )
        )
    return tuple(parsed)


def _parse_match(raw: Any, index: int) -> Match:
    where = f"matches[{index}]"
    match = _obj(raw, where)
    vulnerability = _obj(match.get("vulnerability"), f"{where}.vulnerability")
    artifact = _obj(match.get("artifact"), f"{where}.artifact")
    vwhere = f"{where}.vulnerability"
    fix = _obj(vulnerability.get("fix"), f"{vwhere}.fix")
    state = fix.get("state")
    if state not in FIX_STATES:
        raise _fail(f"{vwhere}.fix", f"state {state!r} is not one of {list(FIX_STATES)}")
    versions = fix.get("versions", [])
    if not isinstance(versions, list) or not all(isinstance(v, str) and v for v in versions):
        raise _fail(f"{vwhere}.fix", "versions must be a list of strings")
    related_raw = match.get("relatedVulnerabilities", [])
    if related_raw is None:
        related_raw = []
    if not isinstance(related_raw, list):
        raise _fail(where, "relatedVulnerabilities must be a list")
    related = tuple(
        _vuln_id(_obj(item, f"{where}.relatedVulnerabilities[{i}]").get("id"), f"{where}.relatedVulnerabilities[{i}].id")
        for i, item in enumerate(related_raw)
    )
    awhere = f"{where}.artifact"
    return Match(
        vuln_id=_vuln_id(vulnerability.get("id"), f"{vwhere}.id"),
        related_ids=related,
        severity=_str(vulnerability, "severity", vwhere) or "Unknown",
        description=_str(vulnerability, "description", vwhere, required=False),
        data_source=_str(vulnerability, "dataSource", vwhere, required=False),
        fix_state=state,
        fixed_versions=tuple(versions),
        kev=_parse_kev(vulnerability.get("knownExploited"), f"{vwhere}.knownExploited"),
        epss=_parse_epss(vulnerability.get("epss"), f"{vwhere}.epss"),
        artifact=Artifact(
            name=_str(artifact, "name", awhere) or "",
            version=_str(artifact, "version", awhere) or "",
            type=_str(artifact, "type", awhere) or "",
            purl=_str(artifact, "purl", awhere) or "",
        ),
    )


def parse_document(text: str, *, expected_version: str) -> Document:
    """Parse one native Grype JSON document, or raise ``GrypeOutputError``.

    ``expected_version`` is the pinned Grype version without its ``v`` (``0.120.1``); a document from any other
    version is refused, because the shapes above were observed for one version only.
    """
    if len(text) > MAX_DOCUMENT_BYTES:
        raise _fail("document", "implausibly large")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise _fail("document", f"not JSON ({exc.msg} at char {exc.pos})") from exc
    root = _obj(data, "document")
    descriptor = _obj(root.get("descriptor"), "descriptor")
    if descriptor.get("name") != "grype":
        raise _fail("descriptor", f"name {descriptor.get('name')!r} is not grype")
    version = descriptor.get("version")
    if version != expected_version:
        raise _fail("descriptor", f"version {version!r} is not the pinned {expected_version!r}")
    raw_matches = root.get("matches")
    if not isinstance(raw_matches, list):
        raise _fail("document", "`matches` must be a list")
    return Document(
        grype_version=version,
        db=_parse_db(descriptor),
        matches=tuple(_parse_match(raw, index) for index, raw in enumerate(raw_matches)),
    )
