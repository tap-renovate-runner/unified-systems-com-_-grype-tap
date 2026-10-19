"""The GRIFT document of one run (req-grype-collector, "Landing"). Stdlib only, no Django and no I/O.

``build_document`` turns a ``plan.Plan`` into one single-batch GRIFT v0 document: the run node and its scanner
edge, the findings the plan creates, the vulnerabilities it mints, the coverage and reporting edges, and a
``deletes`` section for the edges the run replaces. The collector hands the result to ``submit_grift``, the one
write path a collector is given, so the whole run lands in one all-or-nothing batch.

A GRIFT upsert of a node that already exists REPLACES it, so a shared node can never be sent as only the fields this
plugin owns. Every update to an existing node is therefore a read-modify-write: the caller supplies the node as it
was read (properties, dimensions and version), this module overlays the planned fields on those properties, and the
envelope declares the version it read as ``entity_expected_version``. If anyone wrote the node in between, GRIFT
refuses the batch and the collector re-reads and re-plans; nothing is forced.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid7

from tap_plugin.grype import plan as planning

COLLECTION_FORMAT = "tap.grype.collection-v0"
BATCH_SOURCE = "tap_plugin.grype.collectors.grype_collector"
_GRIFT_VERSION = "0"

FINDING = "compliance_core__compliance_finding"
RUN = "compliance_core__compliance_scan_run"
VULNERABILITY = "compliance_core__compliance_vulnerability"

PERFORMS = "PERFORMS_COMPLIANCE_SCAN_RUN__compliance_core"
SCANNED = "SCANNED_COMPLIANCE_TARGET__compliance_core"
REPORTS = "REPORTS_COMPLIANCE_FINDING__compliance_core"
CARRIES = "CARRIES_COMPLIANCE_FINDING__compliance_core"
CONCERNS = "CONCERNS_COMPLIANCE_VULNERABILITY__compliance_core"

_NODE_DIMENSIONS = {FINDING: {"compliance": "finding"}, RUN: {"compliance": "scan-run"}, VULNERABILITY: {"compliance": "vulnerability"}}
_EDGE_DIMENSIONS = {
    PERFORMS: {"compliance": "scan-run"},
    SCANNED: {"compliance": "scan-run"},
    REPORTS: {"compliance": "finding"},
    CARRIES: {"compliance": "finding"},
    CONCERNS: {"compliance": "vulnerability"},
}


class DocumentError(ValueError):
    """The plan names something the document cannot be built from."""


@dataclass(frozen=True)
class ExistingNode:
    """A node as the grid last held it: everything needed to send it back with only some fields changed."""

    version: int
    properties: Mapping[str, Any]
    dimensions: Mapping[str, str]
    name: str


@dataclass(frozen=True)
class Context:
    scanner_id: str
    #: The nodes the plan patches, by id. A patch of a node not in here is refused, never sent blind.
    existing_nodes: Mapping[str, ExistingNode] = field(default_factory=dict)
    new_id: Callable[[], str] = lambda: str(uuid7())
    now: Callable[[], datetime] = lambda: datetime.now(UTC)


def _node(entity_id: str, entity_type: str, name: str, dimensions: Mapping[str, str], fields: Mapping[str, Any], version: int | None = None) -> dict[str, Any]:
    entity: dict[str, Any] = {"entity_id": entity_id, "entity_type": entity_type, "name": name, "dimensions": dict(dimensions)}
    if version is not None:
        entity["entity_expected_version"] = version
    return {"entity": entity, "node": dict(fields)}


def _edge(entity_id: str, edge_type: str, source: str, target: str, properties: Mapping[str, Any] | None = None) -> dict[str, Any]:
    # `entity.entity_type` is the literal "edge"; the slug rides in `entity.name` and `edge.edge_type`.
    return {
        "entity": {"entity_id": entity_id, "entity_type": "edge", "name": edge_type, "dimensions": dict(_EDGE_DIMENSIONS[edge_type])},
        "edge": {"from_entity_id": source, "to_entity_id": target, "edge_type": edge_type, "properties": dict(properties or {})},
    }


def _overlay(ctx: Context, node_id: str, fields: Mapping[str, Any]) -> tuple[ExistingNode, dict[str, Any]]:
    existing = ctx.existing_nodes.get(node_id)
    if existing is None:
        raise DocumentError(f"the plan patches node {node_id!r}, which was not read; it will not be sent from memory")
    return existing, {**existing.properties, **fields}


def build_document(plan: planning.Plan, ctx: Context, *, batch_name: str | None = None) -> dict[str, Any]:
    """The single-batch GRIFT v0 document that carries out ``plan``."""
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    ids: dict[tuple[str, str], str] = {}

    def minted(kind: str, key: str) -> str:
        ids.setdefault((kind, key), ctx.new_id())
        return ids[(kind, key)]

    def resolve(kind: str, ref: planning.Ref) -> str:
        return ref.value if ref.kind == "existing" else minted(kind, ref.value)

    run = plan.run
    run_id = ctx.new_id()
    nodes.append(_node(run_id, RUN, f"Grype run {run['run_key']}", _NODE_DIMENSIONS[RUN], {k: v for k, v in run.items() if v is not None}))
    edges.append(_edge(ctx.new_id(), PERFORMS, ctx.scanner_id, run_id))

    for mint in plan.mint_vulnerabilities:
        nodes.append(_node(minted("vulnerability", mint.key), VULNERABILITY, mint.key, _NODE_DIMENSIONS[VULNERABILITY], mint.fields))
    for patch in plan.patch_vulnerabilities:
        existing, fields = _overlay(ctx, patch.node_id, patch.fields)
        if existing.version != patch.expected_version:
            raise DocumentError(f"vulnerability {patch.node_id!r} was planned at version {patch.expected_version} but read at {existing.version}")
        nodes.append(_node(patch.node_id, VULNERABILITY, existing.name, existing.dimensions, fields, existing.version))

    for finding in plan.mint_findings:
        finding_id = minted("finding", finding.key)
        fields = {"source": planning.SOURCE, "source_key": finding.key, "name": finding.name, "summary": finding.summary, "status": planning.OPEN}
        nodes.append(_node(finding_id, FINDING, finding.name, _NODE_DIMENSIONS[FINDING], fields))
        props = {} if finding.fixed_versions is None else {"fixed_versions": list(finding.fixed_versions)}
        edges.append(_edge(ctx.new_id(), CONCERNS, finding_id, resolve("vulnerability", finding.vulnerability), props))
        edges.append(_edge(ctx.new_id(), CARRIES, finding.target_id, finding_id))
    for patch in plan.patch_findings:
        existing, fields = _overlay(ctx, patch.node_id, patch.fields)
        nodes.append(_node(patch.node_id, FINDING, existing.name, existing.dimensions, fields, existing.version))

    for report in plan.reports:
        edges.append(_edge(ctx.new_id(), REPORTS, run_id, resolve("finding", report.finding)))
    for cover in plan.coverage:
        props = {"outcome": cover.outcome, **({"reason": cover.reason} if cover.reason else {})}
        edges.append(_edge(ctx.new_id(), SCANNED, run_id, cover.target_id, props))

    external = {ctx.scanner_id, *(c.target_id for c in plan.coverage), *(f.target_id for f in plan.mint_findings)}
    external |= {f.vulnerability.value for f in plan.mint_findings if f.vulnerability.kind == "existing"}
    external |= {r.finding.value for r in plan.reports if r.finding.kind == "existing"}
    defined = {n["entity"]["entity_id"] for n in nodes}
    for edge in edges:
        for end in (edge["edge"]["from_entity_id"], edge["edge"]["to_entity_id"]):
            if end not in defined and end not in external:
                raise DocumentError(f"edge {edge['edge']['edge_type']} names {end!r}, which is neither in this batch nor a node the plan was given")

    name = batch_name or f"Grype scan {run['run_key']}"
    batch: dict[str, Any] = {
        "batch_entity": {"entity_id": ctx.new_id(), "entity_type": "batch", "name": name, "dimensions": {"compliance": "scan-run"}},
        "batch_node": {
            "source": BATCH_SOURCE,
            "name": name,
            "description": f"One Grype scan of the grid: outcome {run['outcome']}, {run['results_count']} match(es).",
            "description_json": {
                "format": COLLECTION_FORMAT,
                "collected_at": ctx.now().isoformat().replace("+00:00", "Z"),
                "counts": {"nodes": len(nodes), "edges": len(edges)},
                "run": {
                    "run_key": run["run_key"],
                    "outcome": run["outcome"],
                    "results_count": run["results_count"],
                    "unmapped": len(plan.unmapped),
                    "targets": len(plan.coverage),
                },
            },
        },
        "nodes": nodes,
        "edges": edges,
    }
    if plan.delete_edges:
        batch["deletes"] = {
            "on_missing": "warn",
            "on_tombstoned": "warn",
            "edges": [{"entity_id": edge_id, "entity_type": "edge", "reason": "replaced by a later Grype run"} for edge_id in plan.delete_edges],
            "nodes": [],
        }
    return {"metadata": {"grift_version": _GRIFT_VERSION}, "_reserved": {}, "batches": [batch]}
