"""The grid reader, and the whole write path against a real database (req-grype-collector, req-grype-vulnerability).

pytest with the grid's database, so it runs in a TAP stack (the plugin's ``ci`` record) and not on a bare host. Nodes
are seeded through the service layer inside the test's own transaction; nothing here ships in or seeds a live grid.

The last class is the one that matters: it runs the planner and the document builder over rows read back from the
database, submits the document through ``grift_import``, and checks what the grid then holds. That is where the claim
"an existing vulnerability can be updated through GRIFT without blanking another source's fields" is proved or not.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
import tap_plugin.compliance_core.models  # noqa: F401 - trigger model registration
import tap_plugin.computing_core.models  # noqa: F401

from tap_grid.grift import grift_import
from tap_grid.models import Edge, Entity
from tap_grid.registry import get_model_class
from tap_grid.services import create_edge, create_node, delete_node, patch_node
from tap_plugin.grype import document, plan, reader
from tap_plugin.grype.tests import recordings
from tap_plugin.grype.tests.test_plan import parsed

NOW = datetime(2026, 10, 19, 4, 43, tzinfo=UTC)
VERSION = recordings.VERSION


def make(type_slug: str, payload: dict[str, Any]) -> Entity:
    result = create_node(type_slug, payload)
    assert result.success, f"create_node failed: {result.errors}"
    return Entity.objects.get(pk=result.entity_id)


def link(source: Entity, target: Entity, edge_type: str, **properties: Any) -> Edge:
    return create_edge(source, target, edge_type, properties=properties or None)


def package(name: str, version: str = "1.0", ecosystem: str = "apk", purl: str | None = None) -> Entity:
    payload = {"ecosystem": ecosystem, "name": name, "version": version}
    if purl:
        payload["purl"] = purl
    return make("computing_core__package", payload)


@pytest.mark.django_db
class TestReadTargets:
    def test_packages_and_libraries_are_targets_with_the_natural_key_a_finding_key_uses(self) -> None:
        pkg = package("libssl3", "3.5.4-r0", purl="pkg:apk/wolfi/libssl3@3.5.4-r0")
        lib = make("computing_core__library", {"ecosystem": "generic", "name": "vendored", "version": "2", "purl": "pkg:generic/vendored@2"})
        rows = {gt.target.id: (gt, props) for gt, props in reader.read_targets()}
        grid_target, props = rows[str(pkg.id)]
        assert (grid_target.entity_type, grid_target.natural_key) == ("computing_core__package", ("apk", "libssl3", "3.5.4-r0"))
        assert (grid_target.target.kind, grid_target.target.ecosystem, grid_target.target.purl) == ("package", "apk", "pkg:apk/wolfi/libssl3@3.5.4-r0")
        assert props["ecosystem"] == "apk" and props["cpe_candidates"] == []
        library, _ = rows[str(lib.id)]
        assert (library.entity_type, library.natural_key, library.target.kind, library.target.ecosystem) == (
            "computing_core__library", ("generic", "vendored", "2"), "library", "generic",
        )

    def test_a_package_without_a_purl_has_none_on_the_target(self) -> None:
        pkg = package("bare")
        grid_target = {gt.target.id: gt for gt, _ in reader.read_targets()}[str(pkg.id)]
        assert grid_target.target.purl is None

    def test_a_retired_package_is_not_a_target(self) -> None:
        pkg = package("gone")
        assert str(pkg.id) in {gt.target.id for gt, _ in reader.read_targets()}
        result = delete_node(pkg.id, reason="operator")
        assert result.success, result.errors
        assert str(pkg.id) not in {gt.target.id for gt, _ in reader.read_targets()}


@pytest.mark.django_db
class TestOperatingSystems:
    def seed(self) -> dict[str, Entity]:
        n = {
            "alpine": make("computing_core__operating_system", {"os_id": "alpine", "version_id": "3.20", "build_id": ""}),
            "wolfi": make("computing_core__operating_system", {"os_id": "wolfi", "version_id": "", "build_id": "rolling"}),
            "h1": make("computing_core__host", {"realm": "test", "stable_id": "h1"}),
            "h2": make("computing_core__host", {"realm": "test", "stable_id": "h2"}),
            "shared": package("shared"),
            "only_h1": package("only-h1"),
            "orphan": package("orphan"),
        }
        link(n["h1"], n["alpine"], "RUNS_OPERATING_SYSTEM__computing_core")
        link(n["h2"], n["wolfi"], "RUNS_OPERATING_SYSTEM__computing_core")
        link(n["h1"], n["shared"], "INSTALLS_PACKAGE__computing_core")
        link(n["h2"], n["shared"], "INSTALLS_PACKAGE__computing_core")
        link(n["h1"], n["only_h1"], "INSTALLS_PACKAGE__computing_core")
        return n

    def test_a_target_is_under_the_operating_system_of_every_host_that_installs_it(self) -> None:
        n = self.seed()
        systems = reader.read_operating_systems()
        assert systems[str(n["shared"].id)] == sorted([str(n["alpine"].id), str(n["wolfi"].id)])
        assert systems[str(n["only_h1"].id)] == [str(n["alpine"].id)]
        assert str(n["orphan"].id) not in systems  # no host installs it: the caller scans it under None

    def test_documents_group_by_operating_system_and_an_uninstalled_target_goes_under_none(self) -> None:
        n = self.seed()
        grouped = reader.documents_by_operating_system(reader.read_targets(), reader.read_operating_systems())
        members = {os_id: {gt.target.id for gt, _ in rows} for os_id, rows in grouped.items()}
        assert str(n["shared"].id) in members[str(n["alpine"].id)] and str(n["shared"].id) in members[str(n["wolfi"].id)]
        assert members[None] == {str(n["orphan"].id)}
        assert str(n["only_h1"].id) not in members.get(str(n["wolfi"].id), set())


@pytest.mark.django_db
class TestEndToEnd:
    """Plan, document, submit, read back: with another source's data on a shared vulnerability node."""

    @pytest.fixture(autouse=True)
    def _grid(self) -> None:
        self.doc = parsed(recordings.LOG4J)
        seen: dict[str, Entity] = {}
        for match in self.doc.matches:
            art = match.artifact
            if art.purl in seen:
                continue
            ptype = art.purl[4:].split("/", 1)[0]
            seen[art.purl] = package(art.name, art.version, ptype, art.purl)
        self.packages = seen
        self.scanner = make(
            "compliance_core__compliance_scanner", {"source": "grype", "scanner_key": "grype-tap", "name": "Grype", "locator": "test"}
        )
        # Another source already wrote this vulnerability, with its CVSS, CWE and SSVC.
        self.theirs = make(
            "compliance_core__compliance_vulnerability",
            {
                "vuln_id": "CVE-2021-44228", "aliases": ["GHSA-jfh8-c2jp-5v3q"], "description": "their description",
                "cvss_score": 10.0, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "cvss_version": "3.1",
                "cvss_source": "GitHub", "cwes": ["CWE-917", "CWE-20"], "ssvc_exploitation": "active", "kev": False,
            },
        )

    def targets(self) -> list[tuple[plan.GridTarget, dict[str, Any]]]:
        return reader.read_targets()

    def run_once(self, run_key: str) -> tuple[plan.Plan, Any]:
        the_plan, built = self.prepare(run_key)
        return the_plan, grift_import(built)

    def prepare(self, run_key: str) -> tuple[plan.Plan, dict[str, Any]]:
        rows = self.targets()
        grid_targets = [gt for gt, _ in rows]
        result = plan.DocumentResult("doc-0", tuple(gt.target.id for gt in grid_targets), self.doc)
        findings, vulnerabilities = reader.read_existing_findings(), reader.read_existing_vulnerabilities()
        the_plan = plan.plan_scan(
            targets=grid_targets,
            results=[result],
            existing_findings=findings,
            existing_vulnerabilities=vulnerabilities,
            run_key=run_key,
            observed_at=NOW,
            tool_version=VERSION,
        )
        ctx = document.Context(
            scanner_id=str(self.scanner.id),
            field_names=reader.field_names(),
            known_ids=reader.known_ids(grid_targets, findings, vulnerabilities),
            existing_nodes=reader.read_nodes(the_plan),
        )
        return the_plan, document.build_document(the_plan, ctx)

    def vuln(self, vuln_id: str) -> Any:
        return get_model_class(document.VULNERABILITY).objects.get(vuln_id=vuln_id)

    def test_the_first_run_writes_findings_coverage_and_a_run_and_leaves_the_other_sources_fields_alone(self) -> None:
        the_plan, result = self.run_once("run-1")
        assert not result.errors, result.errors
        node = self.vuln("CVE-2021-44228")
        assert node.entity_id == self.theirs.id  # the same node, updated in place, not a second one
        # Another source's facts survived the whole-node replace.
        assert (node.cvss_score, node.cvss_version, node.cvss_source, node.cwes) == (10.0, "3.1", "GitHub", ["CWE-917", "CWE-20"])
        assert node.ssvc_exploitation == "active" and node.description == "their description"
        # Ours were written.
        assert node.kev is True and node.kev_catalog_version.startswith("grype-db:") and node.epss_score is not None
        assert get_model_class(document.VULNERABILITY).objects.filter(vuln_id="CVE-2021-44228").count() == 1
        findings = get_model_class(document.FINDING).objects.filter(source="grype")
        assert findings.count() == len(the_plan.mint_findings)
        assert get_model_class(document.RUN).objects.filter(source="grype").count() == 1

    def test_the_replace_bumped_the_version_so_a_stale_read_would_have_been_refused(self) -> None:
        before = Entity.objects.get(pk=self.theirs.id).version
        self.run_once("run-1")
        assert Entity.objects.get(pk=self.theirs.id).version > before

    def test_a_second_run_over_unchanged_rows_creates_no_node_reports_nothing_again_and_adds_one_coverage_edge_per_target(self) -> None:
        self.run_once("run-1")
        finding_model, vulnerability_model = get_model_class(document.FINDING), get_model_class(document.VULNERABILITY)
        findings_before = set(finding_model.objects.values_list("entity_id", flat=True))
        vulnerabilities_before = set(vulnerability_model.objects.values_list("entity_id", flat=True))
        the_plan, result = self.run_once("run-2")
        assert not result.errors, result.errors
        assert (the_plan.mint_findings, the_plan.mint_vulnerabilities, the_plan.patch_findings, the_plan.reports) == ([], [], [], [])
        assert get_model_class(document.RUN).objects.filter(source="grype").count() == 2  # one node per execution
        # The same finding and vulnerability nodes, not copies: a run does not remint what it saw before.
        assert set(finding_model.objects.values_list("entity_id", flat=True)) == findings_before
        assert set(vulnerability_model.objects.values_list("entity_id", flat=True)) == vulnerabilities_before
        for finding in finding_model.objects.filter(source="grype"):
            reporting = Edge.objects.filter(edge_type=document.REPORTS, to_entity_id=finding.entity_id)
            assert reporting.count() == 1  # reported by the run that opened it; staying open writes nothing more
        runs = {str(r.entity_id): r.run_key for r in get_model_class(document.RUN).objects.filter(source="grype")}
        for package_entity in self.packages.values():
            coverage = Edge.objects.filter(edge_type=document.SCANNED, to_entity_id=package_entity.id)
            assert sorted(runs[str(c.from_entity_id)] for c in coverage) == ["run-1", "run-2"]  # history stays; the latest is read by the run's time
            assert all(c.properties == {"outcome": "scanned"} for c in coverage)

    def test_the_current_coverage_of_a_target_is_the_latest_run_of_this_scanner_and_nobody_elses(self) -> None:
        self.run_once("run-1")
        later = datetime(2026, 10, 19, 5, 43, tzinfo=UTC)
        target = next(iter(self.packages.values()))
        first = reader.read_latest_coverage([target.id])[str(target.id)]
        assert first.outcome == "scanned" and first.observed_at == NOW
        # A later run of ours, and a still later run of ANOTHER scanner's source that also examined the target.
        mine = make("compliance_core__compliance_scan_run", {"source": "grype", "run_key": "run-2", "category": "grype-grid", "outcome": "ok", "observed_at": later.isoformat()})
        link(mine, target, document.SCANNED, outcome="not-scanned", reason="document-failed")
        older = make("compliance_core__compliance_scan_run", {"source": "grype", "run_key": "run-0", "category": "grype-grid", "outcome": "ok", "observed_at": datetime(2026, 10, 18, tzinfo=UTC).isoformat()})
        link(older, target, document.SCANNED, outcome="failed", reason="finding-key-too-long")  # inserted last but observed first: order of arrival must not matter
        theirs = make("compliance_core__compliance_scan_run", {"source": "trivy", "run_key": "t-1", "category": "x", "outcome": "ok", "observed_at": datetime(2026, 10, 20, tzinfo=UTC).isoformat()})
        link(theirs, target, document.SCANNED, outcome="scanned")
        current = reader.read_latest_coverage([target.id])[str(target.id)]
        assert (current.run_id, current.outcome, current.reason, current.observed_at) == (str(mine.id), "not-scanned", "document-failed", later)
        assert reader.read_latest_coverage([]) == {}

    def test_two_first_runs_planned_from_the_same_empty_snapshot_cannot_leave_two_nodes_for_one_finding(self) -> None:
        _, first = self.prepare("run-a")
        _, second = self.prepare("run-b")  # planned before run-a was written, so it mints the same findings again
        assert not grift_import(first).errors
        refused = grift_import(second)
        assert refused.errors, "the second run would mint a second node for each finding; the grid's natural key refuses it"
        assert {r.run_key for r in get_model_class(document.RUN).objects.filter(source="grype")} == {"run-a"}  # run-b wrote nothing
        finding_model = get_model_class(document.FINDING)
        assert finding_model.objects.filter(source="grype").count() == len({f.source_key for f in finding_model.objects.filter(source="grype")})
        _, again = self.run_once("run-b2")  # a fresh read and plan, as the collector does after a refusal, succeeds
        assert not again.errors

    def test_two_runs_planned_from_the_same_populated_snapshot_both_land_and_only_add_history(self) -> None:
        self.run_once("run-1")
        _, first = self.prepare("run-a")
        _, second = self.prepare("run-b")
        assert not grift_import(first).errors and not grift_import(second).errors
        finding_model = get_model_class(document.FINDING)
        assert finding_model.objects.filter(source="grype").count() == len({f.source_key for f in finding_model.objects.filter(source="grype")})
        for package_entity in self.packages.values():
            assert Edge.objects.filter(edge_type=document.SCANNED, to_entity_id=package_entity.id).count() == 3  # run-1, run-a, run-b

    def test_a_node_that_moved_between_planning_and_reading_it_whole_is_refused_before_anything_is_sent(self) -> None:
        rows = self.targets()
        grid_targets = [gt for gt, _ in rows]
        vulnerabilities = reader.read_existing_vulnerabilities()
        the_plan = plan.plan_scan(
            targets=grid_targets,
            results=[plan.DocumentResult("doc-0", tuple(gt.target.id for gt in grid_targets), self.doc)],
            existing_findings=[], existing_vulnerabilities=vulnerabilities,
            run_key="run-moved", observed_at=NOW, tool_version=VERSION,
        )
        assert the_plan.patch_vulnerabilities, "the plan must patch the shared vulnerability for this to mean anything"
        changed = patch_node(self.theirs.id, {"cvss_score": 9.0})  # after the plan was made, before the node is read whole
        assert changed.success, changed.errors
        ctx = document.Context(
            scanner_id=str(self.scanner.id),
            field_names=reader.field_names(),
            known_ids=reader.known_ids(grid_targets, [], vulnerabilities),
            existing_nodes=reader.read_nodes(the_plan),  # reads the NEWER version
        )
        with pytest.raises(document.DocumentError):
            document.build_document(the_plan, ctx)  # the plan was made at the older one

    def test_a_writer_that_changed_the_node_between_the_read_and_the_submit_is_detected_and_nothing_lands(self) -> None:
        rows = self.targets()
        grid_targets = [gt for gt, _ in rows]
        the_plan = plan.plan_scan(
            targets=grid_targets,
            results=[plan.DocumentResult("doc-0", tuple(gt.target.id for gt in grid_targets), self.doc)],
            existing_findings=[], existing_vulnerabilities=reader.read_existing_vulnerabilities(),
            run_key="run-conflict", observed_at=NOW, tool_version=VERSION,
        )
        vulnerabilities = reader.read_existing_vulnerabilities()
        ctx = document.Context(
            scanner_id=str(self.scanner.id),
            field_names=reader.field_names(),
            known_ids=reader.known_ids(grid_targets, [], vulnerabilities),
            existing_nodes=reader.read_nodes(the_plan),
        )
        built = document.build_document(the_plan, ctx)
        changed = patch_node(self.theirs.id, {"cvss_score": 9.0})  # someone else writes in between
        assert changed.success, changed.errors
        result = grift_import(built)
        assert result.errors, "the stale version should have been refused"
        assert get_model_class(document.RUN).objects.filter(source="grype").count() == 0
        assert get_model_class(document.FINDING).objects.filter(source="grype").count() == 0
        assert self.vuln("CVE-2021-44228").cvss_score == 9.0  # their write stands; ours did not clobber it
        assert self.vuln("CVE-2021-44228").kev is False
