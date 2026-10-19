"""What one run should write to the grid, as plain data (req-grype-run, -finding, -lifecycle, -vulnerability).

Stdlib only, no Django and no I/O. The collector reads the grid into the inputs below, calls ``plan_scan`` and
hands the result to the writers; because this module only decides, every rule the spec states about findings,
coverage, resolution and vulnerability patches can be tested on the real recordings without a database.

The rules, in the order the plan applies them:

* A target is ``scanned`` only when every document it appears in parsed. Any failed document makes it
  ``not-scanned`` (``document-failed``), and a not-scanned target resolves nothing: a finding absent from the
  documents that did parse may simply have been in the one that failed.
* A finding's key is a JSON array of the vulnerability id, the target's entity type and each field of its natural
  key, so no two tuples can share a key. A key over 512 characters is refused, never truncated, and the target it
  belongs to is recorded ``failed`` (``finding-key-too-long``) rather than half tracked.
* A document with a match that maps to no single target makes every target in it ``not-scanned`` (``unmapped``): the
  match may belong to one of them, so none of them can be said to have lost a finding. Findings are still created
  and reopened from the matches that did map.
* A finding keeps the key it was minted with. When a vulnerability node already exists the key uses that node's
  ``vuln_id``, which never changes, so a CVE that Grype's database later attaches to a GHSA-only advisory does not
  turn the same finding into a new one.
* An existing finding of a ``scanned`` target that no longer matches is resolved; a resolved one that matches again is
  reopened; matches from parsed documents create or reopen findings even for a not-scanned target.
* A vulnerability is written (minted or patched) only from the matches of accepted targets: a refused or unmapped
  match contributes no node, no patch and no field value, even to a vulnerability another target also names.
* A vulnerability is found under any of its ids (as ``vuln_id`` or as an alias) before one is minted. Two different
  existing nodes for one vulnerability are refused, not guessed between.
* The plugin writes only the vulnerability fields it owns, and only values that differ; it never writes ``null`` over
  a value, ``0`` for an unread score, or ``false`` for a catalog it did not read.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from tap_plugin.grype.facts import VulnerabilityFacts, finding_facts, vuln_key, vulnerability_facts
from tap_plugin.grype.output import DbInfo, Document, Match
from tap_plugin.grype.targets import Target, map_matches

SOURCE = "grype"
CATEGORY = "grype-grid"
KEY_LIMIT = 512
NAME_LIMIT = 255
SUMMARY_LIMIT = 500

SCANNED = "scanned"
NOT_SCANNED = "not-scanned"
FAILED = "failed"
DOCUMENT_FAILED = "document-failed"
UNMAPPED = "unmapped"
KEY_TOO_LONG = "finding-key-too-long"
VULNERABILITY_AMBIGUOUS = "vulnerability-ambiguous"

OPEN = "open"
RESOLVED = "resolved"


class PlanError(ValueError):
    """The inputs contradict each other; nothing is planned from them."""


@dataclass(frozen=True)
class Ref:
    """A node the plan writes or points at: one already on the grid, or one this plan creates."""

    kind: str  # "existing" or "new"
    value: str  # the node id, or the key the new node will carry

    @classmethod
    def existing(cls, node_id: str) -> Ref:
        return cls("existing", node_id)

    @classmethod
    def new(cls, key: str) -> Ref:
        return cls("new", key)


@dataclass(frozen=True)
class GridTarget:
    """A scan target as read from the grid: the mapping view plus what a finding key needs."""

    target: Target
    entity_type: str
    natural_key: tuple[str, ...]


@dataclass(frozen=True)
class DocumentResult:
    """One document the collector ran: the targets it carried, and its parsed output, or ``None`` if it failed."""

    label: str
    target_ids: tuple[str, ...]
    document: Document | None


@dataclass(frozen=True)
class ExistingFinding:
    """A finding of source ``grype`` already on the grid."""

    key: str
    node_id: str
    target_id: str
    status: str
    summary: str
    reporting_edge_id: str | None


@dataclass(frozen=True)
class ExistingVulnerability:
    """A vulnerability node already on the grid, with the fields this plugin may patch as it last read them."""

    node_id: str
    version: int
    vuln_id: str
    aliases: tuple[str, ...]
    fields: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MintVulnerability:
    key: str
    fields: dict[str, Any]


@dataclass(frozen=True)
class PatchVulnerability:
    node_id: str
    expected_version: int
    fields: dict[str, Any]


@dataclass(frozen=True)
class MintFinding:
    key: str
    target_id: str
    vulnerability: Ref
    name: str
    summary: str
    fixed_versions: tuple[str, ...] | None  # None: Grype's fix state is unknown, so the edge carries no list


@dataclass(frozen=True)
class PatchFinding:
    node_id: str
    fields: dict[str, Any]


@dataclass(frozen=True)
class Report:
    """The run reports this finding (``REPORTS_COMPLIANCE_FINDING``); the earlier edge, if any, is deleted."""

    finding: Ref


@dataclass(frozen=True)
class Coverage:
    target_id: str
    outcome: str
    reason: str | None


@dataclass(frozen=True)
class Unmapped:
    vuln_id: str
    purl: str
    reason: str


@dataclass(frozen=True)
class Plan:
    run: dict[str, Any]
    coverage: list[Coverage] = field(default_factory=list)
    mint_vulnerabilities: list[MintVulnerability] = field(default_factory=list)
    patch_vulnerabilities: list[PatchVulnerability] = field(default_factory=list)
    mint_findings: list[MintFinding] = field(default_factory=list)
    patch_findings: list[PatchFinding] = field(default_factory=list)
    reports: list[Report] = field(default_factory=list)
    delete_edges: list[str] = field(default_factory=list)
    unmapped: list[Unmapped] = field(default_factory=list)


def finding_key(vuln_id: str, grid_target: GridTarget) -> str:
    """The finding's ``source_key``: a compact JSON array, so two different tuples can never share one."""
    key = json.dumps([vuln_id, grid_target.entity_type, *grid_target.natural_key], separators=(",", ":"), ensure_ascii=True)
    if len(key) > KEY_LIMIT:
        raise PlanError(f"finding key is {len(key)} characters, over the {KEY_LIMIT} the grid keeps")
    return key


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _combined(parsed: Sequence[Document]) -> Document | None:
    """All parsed documents as one, or ``None`` when there are none.

    The database is the same for every document of a run, so two builds is a contradiction and refused. If any
    parsed document did not report its database the combined one reports none, which makes every KEV answer
    ``null`` and never ``false``.
    """
    if not parsed:
        return None
    dbs = [d.db for d in parsed]
    versions = {db.data_version for db in dbs if db is not None}
    if len(versions) > 1:
        raise PlanError(f"the documents of one run report different database builds: {sorted(versions)}")
    db: DbInfo | None = dbs[0] if all(db is not None for db in dbs) else None
    return Document(grype_version=parsed[0].grype_version, db=db, matches=tuple(m for d in parsed for m in d.matches))


def _desired_vulnerability_fields(facts: VulnerabilityFacts, data_version: str | None) -> dict[str, Any]:
    """The fields Grype supplies for one vulnerability, as the grid stores them (dates as ISO strings)."""
    fields: dict[str, Any] = {}
    if facts.description is not None:
        fields["description"] = facts.description
    if facts.record_url is not None:
        fields["record_url"] = facts.record_url
    kev = facts.kev
    if kev.kev is not None:
        fields["kev"] = kev.kev
        if kev.kev:  # a detail the catalog did not give is left alone, never written as null
            for name, value in (
                ("kev_added", kev.date_added.isoformat() if kev.date_added else None),
                ("kev_due_date", kev.due_date.isoformat() if kev.due_date else None),
                ("kev_required_action", kev.required_action),
                ("kev_ransomware_use", kev.ransomware_use),
            ):
                if value is not None:
                    fields[name] = value
        if data_version is not None:
            fields["kev_catalog_version"] = f"grype-db:{data_version}"
    if facts.epss is not None:
        fields["epss_score"] = facts.epss.score
        fields["epss_percentile"] = facts.epss.percentile
        fields["epss_date"] = facts.epss.on.isoformat()
    return fields


def _patch_for(facts: VulnerabilityFacts, desired: dict[str, Any], existing: ExistingVulnerability) -> dict[str, Any]:
    """Only what changes. Aliases are a union, a description is written once, nothing is blanked."""
    patch: dict[str, Any] = {}
    wanted_aliases = {*facts.aliases, *(() if existing.vuln_id == facts.key else (facts.key,))} - {existing.vuln_id}
    held = set(existing.aliases)
    if wanted_aliases - held:
        patch["aliases"] = sorted(held | wanted_aliases)
    for name, value in desired.items():
        current = existing.fields.get(name)
        if name == "description":
            if current is None:
                patch[name] = value
        elif name == "kev_catalog_version":
            continue  # follows the KEV answer below, and never causes a patch on its own
        elif current != value:
            patch[name] = value
    if any(name.startswith("kev") and name != "kev_catalog_version" for name in patch) and "kev_catalog_version" in desired:
        patch["kev_catalog_version"] = desired["kev_catalog_version"]
    return patch


def _resolve_vulnerabilities(
    facts: Mapping[str, VulnerabilityFacts],
    existing: Sequence[ExistingVulnerability],
    data_version: str | None,
) -> tuple[dict[str, Ref | None], dict[str, str], list[MintVulnerability], list[PatchVulnerability]]:
    """For each vulnerability key, the node it is (``None``: ambiguous, refused), the id its findings are keyed
    under (the node's own ``vuln_id``), and the writes that follow."""
    index: dict[str, set[str]] = defaultdict(set)
    by_id: dict[str, ExistingVulnerability] = {}
    for node in existing:
        by_id[node.node_id] = node
        for name in (node.vuln_id, *node.aliases):
            index[name].add(node.node_id)
    refs: dict[str, Ref | None] = {}
    canonical: dict[str, str] = {}
    mints: list[MintVulnerability] = []
    patches: list[PatchVulnerability] = []
    for key, fact in sorted(facts.items()):
        names = (key, *fact.aliases)
        found = {node_id for name in names for node_id in index.get(name, ())}
        if len(found) > 1:  # however it came to be, two nodes for one vulnerability is not for this plugin to settle
            refs[key] = None
            continue
        desired = _desired_vulnerability_fields(fact, data_version)
        if found:
            node = by_id[next(iter(found))]
            refs[key] = Ref.existing(node.node_id)
            canonical[key] = node.vuln_id
            patch = _patch_for(fact, desired, node)
            if patch:
                patches.append(PatchVulnerability(node.node_id, node.version, patch))
        else:
            refs[key] = Ref.new(key)
            canonical[key] = key
            mints.append(MintVulnerability(key, {"vuln_id": key, "aliases": list(fact.aliases), **desired}))
    return refs, canonical, mints, patches


def plan_unscanned(*, outcome: str, run_key: str, observed_at: datetime, tool_version: str) -> Plan:
    """A run that scanned nothing (``db-stale``, ``db-unavailable``): the run alone, and no coverage, so the previous coverage stands."""
    if outcome not in ("db-stale", "db-unavailable"):
        raise PlanError(f"{outcome!r} is not an outcome of a run that scanned nothing")
    return Plan(run=_run_fields(outcome, run_key, observed_at, tool_version, 0, None))


def _run_fields(
    outcome: str, run_key: str, observed_at: datetime, tool_version: str, results_count: int, db: DbInfo | None
) -> dict[str, Any]:
    return {
        "source": SOURCE,
        "run_key": run_key,
        "category": CATEGORY,
        "tool_version": tool_version,
        "observed_at": observed_at.isoformat(),
        "outcome": outcome,
        "results_count": results_count,
        "data_version": db.data_version if db else None,
        "data_built_at": db.built.isoformat() if db else None,
    }


def plan_scan(
    *,
    targets: Sequence[GridTarget],
    results: Sequence[DocumentResult],
    existing_findings: Sequence[ExistingFinding],
    existing_vulnerabilities: Sequence[ExistingVulnerability],
    existing_coverage: Mapping[str, str],
    run_key: str,
    observed_at: datetime,
    tool_version: str,
) -> Plan:
    """Decide every write of one scan. ``existing_coverage`` maps a target id to this scanner's current coverage edge."""
    grid = {gt.target.id: gt for gt in targets}
    if len(grid) != len(targets):
        raise PlanError("two targets share an id")
    labels = [r.label for r in results]
    if len(set(labels)) != len(labels):
        raise PlanError("two documents share a label; a document is identified by it")
    documents: dict[str, list[DocumentResult]] = defaultdict(list)
    for result in results:
        for target_id in result.target_ids:
            if target_id not in grid:
                raise PlanError(f"document {result.label!r} names target {target_id!r}, which is not a target of this run")
            documents[target_id].append(result)
    missing = sorted(set(grid) - set(documents))
    if missing:
        raise PlanError(f"{len(missing)} target(s) are in no document, so none could be scanned or recorded: {missing[:3]}")

    parsed = [r.document for r in results if r.document is not None]
    combined = _combined(parsed)
    db = combined.db if combined else None
    data_version = db.data_version if db else None

    # Matches per target, from the documents that parsed.
    per_target: dict[str, list[Match]] = defaultdict(list)
    unmapped: list[Unmapped] = []
    has_unmapped: set[str] = set()
    for result in results:
        if result.document is None:
            continue
        mapping = map_matches(result.document.matches, [grid[t].target for t in result.target_ids])
        for target_id, matches in mapping.mapped.items():
            per_target[target_id].extend(matches)
        for match, reason in mapping.unmapped:
            has_unmapped.add(result.label)
            unmapped.append(Unmapped(vuln_key(match)[0], match.artifact.purl, reason))

    outcomes: dict[str, tuple[str, str | None]] = {}
    for target_id in grid:
        if any(r.document is None for r in documents[target_id]):
            outcomes[target_id] = (NOT_SCANNED, DOCUMENT_FAILED)
        elif any(r.label in has_unmapped for r in documents[target_id]):
            outcomes[target_id] = (NOT_SCANNED, UNMAPPED)
        else:
            outcomes[target_id] = (SCANNED, None)

    existing_by_target: dict[str, dict[str, ExistingFinding]] = defaultdict(dict)
    for finding in existing_findings:
        existing_by_target[finding.target_id][finding.key] = finding

    # Which targets are accepted, and what the vulnerabilities are, depend on each other: a target is refused for an
    # ambiguous vulnerability or an over-long key, and a vulnerability is derived from the matches of accepted targets
    # alone. So resolve, refuse, and resolve again over what is left until no further target is refused. A refused
    # target stays refused (the set only grows), so this ends, and it never lets a refused match shape a node.
    refused: dict[str, str] = {}
    while True:
        live = [t for t in sorted(grid) if t not in refused]
        accepted = [m for t in live for m in per_target.get(t, ())]
        accepted_doc = Document(grype_version=combined.grype_version, db=db, matches=tuple(accepted)) if combined and accepted else None
        facts = vulnerability_facts(accepted_doc) if accepted_doc else {}
        refs, canonical, mint_vulns, patch_vulns = _resolve_vulnerabilities(facts, existing_vulnerabilities, data_version)
        planned: dict[str, list[tuple[str, Any, Ref]]] = {}
        newly: dict[str, str] = {}
        for target_id in live:
            gt = grid[target_id]
            sub = Document(grype_version=combined.grype_version, db=db, matches=tuple(per_target.get(target_id, ()))) if combined else None
            rows: list[tuple[str, Any, Ref]] = []
            for fact in finding_facts(sub) if sub else []:
                ref = refs.get(fact.key)
                if ref is None:
                    newly[target_id] = VULNERABILITY_AMBIGUOUS
                    break
                try:
                    key = finding_key(canonical[fact.key], gt)
                except PlanError:
                    newly[target_id] = KEY_TOO_LONG
                    break
                rows.append((key, fact, ref))
            planned[target_id] = rows
        if not newly:
            break
        refused.update(newly)
    for target_id, reason in refused.items():
        outcomes[target_id] = (FAILED, reason)  # nothing about it is written, and nothing is resolved

    mint_findings: list[MintFinding] = []
    patch_findings: list[PatchFinding] = []
    reports: list[Report] = []
    delete_edges: list[str] = []
    for target_id in live:
        gt = grid[target_id]
        matched: set[str] = set()
        for key, fact, ref in planned[target_id]:
            matched.add(key)
            summary = _clip(f"Grype severity {fact.severity}; fix {fact.fix_state}", SUMMARY_LIMIT)
            current = existing_by_target[target_id].get(key)
            if current is None:
                # A finding minted before the node existed, or under another of the vulnerability's ids, is the same finding.
                for other in (fact.key, *facts[fact.key].aliases):
                    try:
                        older = finding_key(other, gt)
                    except PlanError:
                        continue
                    if older in existing_by_target[target_id]:
                        key, current = older, existing_by_target[target_id][older]
                        matched.add(older)
                        break
            if current is None:
                name = _clip(f"{fact.key} in {gt.target.name} {gt.target.version}", NAME_LIMIT)
                mint_findings.append(MintFinding(key, target_id, ref, name, summary, fact.fixed_versions))
                reports.append(Report(Ref.new(key)))
                continue
            patch: dict[str, Any] = {}
            if current.status != OPEN:
                patch["status"] = OPEN
            if current.summary != summary:
                patch["summary"] = summary
            if patch:
                patch_findings.append(PatchFinding(current.node_id, patch))
            reports.append(Report(Ref.existing(current.node_id)))
            if current.reporting_edge_id:
                delete_edges.append(current.reporting_edge_id)
        if outcomes[target_id][0] == SCANNED:
            for key, current in sorted(existing_by_target[target_id].items()):
                if key not in matched and current.status == OPEN:
                    patch_findings.append(PatchFinding(current.node_id, {"status": RESOLVED}))

    coverage = [Coverage(t, *outcomes[t]) for t in sorted(grid)]
    delete_edges.extend(existing_coverage[t] for t in sorted(grid) if t in existing_coverage)

    scanned_all = all(o == SCANNED for o, _ in outcomes.values())
    if not parsed:
        outcome = "failed"
    elif scanned_all and not unmapped:
        outcome = "ok"
    else:
        outcome = "partial"
    results_count = sum(len(d.matches) for d in parsed)
    return Plan(
        run=_run_fields(outcome, run_key, observed_at, tool_version, results_count, db),
        coverage=coverage,
        mint_vulnerabilities=mint_vulns,
        patch_vulnerabilities=patch_vulns,
        mint_findings=mint_findings,
        patch_findings=patch_findings,
        reports=reports,
        delete_edges=delete_edges,
        unmapped=unmapped,
    )
