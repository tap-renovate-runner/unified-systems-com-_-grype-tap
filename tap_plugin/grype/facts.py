"""What the matches say, derived once (req-grype-vulnerability, req-grype-finding). Stdlib only, no Django.

Pure functions from parsed matches to the facts the plugin writes. They decide nothing about the grid:
the writer applies them, with ``patch_node`` for existing vulnerabilities, so a field another source wrote
is never blanked here or there.

Three states, never two. ``kev`` is True when the catalog lists the vulnerability, False only when the scan
reported the database it used and the catalog does not list it, and None when the scan could not say (a
document with no ``descriptor.db.status``). An absent ``epss`` is None, never 0.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date

from tap_plugin.grype.output import Document, EpssEntry, KevEntry, Match
from tap_plugin.grype.targets import canonical_purl

_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_SEVERITY_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Negligible": 1, "Unknown": 0}


def vuln_key(match: Match) -> tuple[str, tuple[str, ...]]:
    """The vulnerability's identity and its aliases.

    The key is the CVE id: the match's own id when it is a CVE, else the first CVE among the related
    vulnerabilities, else the match id (a GHSA with no CVE). Every other id Grype names is an alias.
    Observed: 24 of the 26 GHSA matches in the tap-web output have no related CVE, so a GHSA key is ordinary.
    """
    if _CVE.match(match.vuln_id):
        key = match.vuln_id
    else:
        key = next((related for related in match.related_ids if _CVE.match(related)), match.vuln_id)
    aliases = sorted({match.vuln_id, *match.related_ids} - {key})
    return key, tuple(aliases)


@dataclass(frozen=True)
class KevFact:
    """The catalog's answer for one vulnerability."""

    kev: bool | None
    date_added: date | None = None
    due_date: date | None = None
    required_action: str | None = None
    ransomware_use: str | None = None


@dataclass(frozen=True)
class EpssFact:
    """EPSS for one vulnerability, or nothing."""

    score: float
    percentile: float
    on: date


@dataclass(frozen=True)
class VulnerabilityFacts:
    """Everything this plugin may write about one vulnerability."""

    key: str
    aliases: tuple[str, ...]
    description: str | None
    record_url: str | None
    kev: KevFact
    epss: EpssFact | None


def _kev_fact(key: str, aliases: tuple[str, ...], matches: list[Match], db_reported: bool) -> KevFact:
    ours = {key, *aliases}
    entries: list[KevEntry] = sorted(
        (e for m in matches for e in m.kev if e.cve in ours),
        key=lambda e: (e.cve, str(e.date_added), str(e.due_date), e.required_action or "", e.ransomware_use or ""),
    )
    if entries:
        first = entries[0]
        return KevFact(True, first.date_added, first.due_date, first.required_action, first.ransomware_use)
    # No entry. That is the catalog's answer only if the scan reported the database it read.
    return KevFact(False) if db_reported else KevFact(None)


def _epss_fact(key: str, matches: list[Match]) -> EpssFact | None:
    """The newest reading whose ``cve`` is the vulnerability's own key; none for a key that is not a CVE."""
    readings: list[EpssEntry] = [e for m in matches for e in m.epss if e.cve == key]
    if not readings:
        return None
    best = max(readings, key=lambda e: (e.on, e.score, e.percentile))
    return EpssFact(best.score, best.percentile, best.on)


def vulnerability_facts(document: Document) -> dict[str, VulnerabilityFacts]:
    """Group a document's matches by vulnerability key and derive each one's facts, in key order."""
    groups: dict[str, list[Match]] = {}
    alias_sets: dict[str, set[str]] = {}
    for match in document.matches:
        key, aliases = vuln_key(match)
        groups.setdefault(key, []).append(match)
        alias_sets.setdefault(key, set()).update(aliases)
    db_reported = document.db is not None
    result: dict[str, VulnerabilityFacts] = {}
    for key in sorted(groups):
        matches = groups[key]
        aliases = tuple(sorted(alias_sets[key]))
        own = next((m for m in matches if m.vuln_id == key), matches[0])
        description = next((m.description for m in sorted(matches, key=lambda m: m.vuln_id) if m.description), None)
        result[key] = VulnerabilityFacts(
            key=key,
            aliases=aliases,
            description=description,
            record_url=own.data_source,
            kev=_kev_fact(key, aliases, matches, db_reported),
            epss=_epss_fact(key, matches),
        )
    return result


@dataclass(frozen=True)
class FindingFact:
    """One vulnerability asserted against one artifact, duplicates collapsed."""

    key: str
    purl: str
    name: str
    version: str
    type: str
    severity: str
    fix_state: str
    fixed_versions: tuple[str, ...] | None


def _fixed_versions(matches: list[Match]) -> tuple[str, ...] | None:
    """A list when fixed, an empty list when looked at and not fixable, None when unknown."""
    if any(m.fix_state == "fixed" for m in matches):
        return tuple(sorted({v for m in matches if m.fix_state == "fixed" for v in m.fixed_versions}))
    if any(m.fix_state in ("not-fixed", "wont-fix") for m in matches):
        return ()
    return None


def finding_facts(document: Document) -> list[FindingFact]:
    """One fact per (vulnerability key, artifact purl); several matches of one pair collapse to one.

    The pair is keyed on the canonical purl, the same spelling ``targets.map_matches`` compares, so two matches
    whose purls differ only in qualifier order or percent-encoding are one finding, as they are one target.
    """
    groups: dict[tuple[str, str], list[Match]] = {}
    for match in document.matches:
        key, _ = vuln_key(match)
        groups.setdefault((key, canonical_purl(match.artifact.purl) or match.artifact.purl), []).append(match)
    facts = []
    for (key, _canonical), matches in sorted(groups.items()):
        artifact = matches[0].artifact
        purl = artifact.purl
        severity = max((m.severity for m in matches), key=lambda s: _SEVERITY_RANK.get(s, 0))
        states = {m.fix_state for m in matches}
        state = "fixed" if "fixed" in states else next((s for s in ("not-fixed", "wont-fix") if s in states), "unknown")
        facts.append(
            FindingFact(
                key=key,
                purl=purl,
                name=artifact.name,
                version=artifact.version,
                type=artifact.type,
                severity=severity,
                fix_state=state,
                fixed_versions=_fixed_versions(matches),
            )
        )
    return facts
