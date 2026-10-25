"""Reading the grid into what the planner and the document builder take (req-grype-collector, "Scope").

The only module of the orchestration that touches the database, and it only reads. Everything it returns is plain
data (``plan.GridTarget``, ``plan.ExistingFinding``, ``plan.ExistingVulnerability``, ``document.ExistingNode``), so
the planner and the document stay testable without one. Models are reached through their default manager, which
excludes tombstoned rows, so a retired package is not a scan target and a retired finding is not an existing one.

A node that will be sent back whole is read through ``read_node``: every field the model declares, serialised the
way GRIFT takes it, with the entity's own name, dimensions and version, so the document layer can send it unchanged
apart from the fields this plugin owns.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from typing import Any

from tap_grid.models import Edge, Entity
from tap_plugin.compliance_core.models.compliance_finding import ComplianceFinding
from tap_plugin.compliance_core.models.compliance_scanner import ComplianceScanner
from tap_plugin.compliance_core.models.compliance_vulnerability import ComplianceVulnerability
from tap_plugin.computing_core.models.library import Library
from tap_plugin.computing_core.models.operating_system import OperatingSystem
from tap_plugin.computing_core.models.package import Package
from tap_plugin.grype import document, plan
from tap_plugin.grype.targets import Target

INSTALLS = "INSTALLS_PACKAGE__computing_core"
SHIPS = "SHIPS_LIBRARY__computing_core"
RUNS_OS = "RUNS_OPERATING_SYSTEM__computing_core"
CARRIES = document.CARRIES

SCANNER_KEY = "grype-tap"
PACKAGE_TYPE = "computing_core__package"
LIBRARY_TYPE = "computing_core__library"

#: Every vulnerability field this plugin compares against Grype's facts, as the plan expects to find it.
_VULNERABILITY_COMPARED = (
    "description", "record_url", "kev", "kev_added", "kev_due_date", "kev_required_action", "kev_ransomware_use",
    "kev_catalog_version", "epss_score", "epss_percentile", "epss_date",
)

MODELS = {
    document.VULNERABILITY: ComplianceVulnerability,
    document.FINDING: ComplianceFinding,
}


def field_names() -> dict[str, frozenset[str]]:
    """The fields of each node type the document layer updates, as the model declares them."""
    return {entity_type: frozenset(model.FIELD_CRUD_SCHEMA) for entity_type, model in MODELS.items()}


def _json(value: Any) -> Any:
    """A model value as GRIFT takes it: dates and datetimes as ISO strings, the rest as it is."""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return value


def read_node(entity_type: str, node_id: str) -> document.ExistingNode:
    """One node whole: every declared field, plus the entity's name, dimensions and version."""
    model = MODELS[entity_type]
    entity = Entity.objects.get(id=node_id)
    obj = model.objects.get(entity_id=node_id)
    properties = {name: _json(getattr(obj, name)) for name in model.FIELD_CRUD_SCHEMA}
    return document.ExistingNode(entity.version, properties, dict(entity.dimensions), entity.name)


def known_ids(
    targets: Iterable[plan.GridTarget],
    findings: Iterable[plan.ExistingFinding],
    vulnerabilities: Iterable[plan.ExistingVulnerability],
) -> frozenset[str]:
    """The ids of every node this run read, for ``document.Context``: the only existing nodes an edge may name."""
    return frozenset([t.target.id for t in targets] + [f.node_id for f in findings] + [v.node_id for v in vulnerabilities])


def read_nodes(patches: plan.Plan) -> dict[str, document.ExistingNode]:
    """The nodes a plan patches, read whole, for ``document.Context``."""
    nodes: dict[str, document.ExistingNode] = {}
    for patch in patches.patch_vulnerabilities:
        nodes[patch.node_id] = read_node(document.VULNERABILITY, patch.node_id)
    for patch in patches.patch_findings:
        nodes[patch.node_id] = read_node(document.FINDING, patch.node_id)
    return nodes


def read_targets() -> list[tuple[plan.GridTarget, dict[str, Any]]]:
    """Every live package and library as a planner target, with the properties the document builder takes."""
    rows: list[tuple[plan.GridTarget, dict[str, Any]]] = []
    for kind, entity_type, model, extra in (
        ("package", PACKAGE_TYPE, Package, ()),
        ("library", LIBRARY_TYPE, Library, ("source_kind", "source_url", "path")),
    ):
        for obj in model.objects.all().order_by("ecosystem", "name", "version", "id"):
            node_id = str(obj.entity_id)
            target = Target(
                id=node_id, kind=kind, name=obj.name, version=obj.version, ecosystem=obj.ecosystem or None, purl=obj.purl or None
            )
            grid_target = plan.GridTarget(target, entity_type, (obj.ecosystem, obj.name, obj.version))
            props: dict[str, Any] = {
                "ecosystem": obj.ecosystem, "name": obj.name, "version": obj.version, "purl": obj.purl,
                "cpe": obj.cpe, "license": obj.license, **{f: getattr(obj, f) for f in extra},
            }
            if kind == "package":
                props["cpe_candidates"] = list(obj.cpe_candidates or [])
            rows.append((grid_target, props))
    return rows


def read_operating_systems() -> dict[str, list[str | None]]:
    """For each target, the operating systems of the hosts that install or ship it; ``[None]`` when no host does.

    Derived by traversal, never stored: a host ``RUNS_OPERATING_SYSTEM`` and ``INSTALLS_PACKAGE`` or
    ``SHIPS_LIBRARY``, so a target under two operating systems is returned under both, and one no host installs
    has none and is scanned in a document with no operating-system component.
    """
    os_of_host: dict[str, set[str]] = defaultdict(set)
    for host, os_id in Edge.objects.filter(edge_type=RUNS_OS).values_list("from_entity_id", "to_entity_id"):
        os_of_host[str(host)].add(str(os_id))
    result: dict[str, set[str]] = defaultdict(set)
    for host, target in Edge.objects.filter(edge_type__in=(INSTALLS, SHIPS)).values_list("from_entity_id", "to_entity_id"):
        result[str(target)] |= os_of_host.get(str(host), set())
    return {target: sorted(systems) or [None] for target, systems in result.items()}


def read_operating_system(os_id: str) -> dict[str, Any]:
    """One operating system's properties, as the SBOM builder takes them."""
    obj = OperatingSystem.objects.get(entity_id=os_id)
    return {name: getattr(obj, name) for name in OperatingSystem.FIELD_CRUD_SCHEMA}


def read_scanner_id() -> str | None:
    """The id of this plugin's scanner node (``source`` ``grype``, ``scanner_key`` ``grype-tap``), or ``None`` when it is not seeded."""
    scanner = ComplianceScanner.objects.filter(source=plan.SOURCE, scanner_key=SCANNER_KEY).first()
    return str(scanner.entity_id) if scanner else None


def read_existing_findings() -> list[plan.ExistingFinding]:
    """Every live finding of source ``grype`` with its target and its status."""
    findings = {str(f.entity_id): f for f in ComplianceFinding.objects.filter(source=plan.SOURCE)}
    if not findings:
        return []
    versions = dict(Entity.objects.filter(id__in=list(findings)).values_list("id", "version"))
    target_of: dict[str, str] = {}
    for target, finding in Edge.objects.filter(edge_type=CARRIES, to_entity_id__in=list(findings)).values_list("from_entity_id", "to_entity_id"):
        target_of[str(finding)] = str(target)
    existing = []
    for node_id, finding_row in findings.items():
        target_id = target_of.get(node_id)
        if target_id is None:
            continue  # no carrying edge: nothing to resolve it against, so it is not this run's to touch
        existing.append(
            plan.ExistingFinding(
                key=finding_row.source_key,
                node_id=node_id,
                target_id=target_id,
                status=finding_row.status,
                summary=finding_row.summary,
                version=versions[finding_row.entity_id],
            )
        )
    return existing


def read_existing_vulnerabilities() -> list[plan.ExistingVulnerability]:
    """Every live vulnerability, with the fields the plan compares as they are stored."""
    rows = list(ComplianceVulnerability.objects.all())
    versions = dict(Entity.objects.filter(id__in=[r.entity_id for r in rows]).values_list("id", "version")) if rows else {}
    return [
        plan.ExistingVulnerability(
            node_id=str(row.entity_id),
            version=versions[row.entity_id],
            vuln_id=row.vuln_id,
            aliases=tuple(row.aliases or ()),
            fields={name: _json(getattr(row, name)) for name in _VULNERABILITY_COMPARED},
        )
        for row in rows
    ]


def documents_by_operating_system(
    rows: list[tuple[plan.GridTarget, dict[str, Any]]], systems: Mapping[str, list[str | None]]
) -> dict[str | None, list[tuple[plan.GridTarget, dict[str, Any]]]]:
    """Group targets by operating system: one document each; a target under two is in both; none is under ``None``."""
    grouped: dict[str | None, list[tuple[plan.GridTarget, dict[str, Any]]]] = defaultdict(list)
    for grid_target, props in rows:
        for os_id in systems.get(grid_target.target.id, [None]):
            grouped[os_id].append((grid_target, props))
    return dict(grouped)
