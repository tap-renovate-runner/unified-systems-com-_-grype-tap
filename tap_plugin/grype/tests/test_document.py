"""The GRIFT document of one run, built from real plans (req-grype-collector "Landing").

Stdlib ``unittest`` only. Plans come from the recordings through ``plan.plan_scan``; the document is checked
structurally here, and against tap's GRIFT schema when ``jsonschema`` and the schema file are importable (the
container), skipped otherwise.
"""

import dataclasses
import itertools
import json
import unittest
from pathlib import Path

from tap_plugin.grype import document, plan
from tap_plugin.grype.tests import recordings
from tap_plugin.grype.tests.test_plan import NOW, as_existing, grid_targets, one_document, parsed, run


VULN_FIELDS = frozenset(
    "vuln_id aliases title description published_at cvss_score cvss_vector cvss_version cvss_source cwes ssvc_exploitation "
    "ssvc_automatable ssvc_technical_impact ssvc_assessed_at kev kev_added kev_catalog_version kev_due_date kev_required_action "
    "kev_ransomware_use epss_score epss_percentile epss_date record_url record_updated_at".split()
)
FINDING_FIELDS = frozenset("source source_key name summary description status".split())
FIELDS = {document.VULNERABILITY: VULN_FIELDS, document.FINDING: FINDING_FIELDS}


def whole(fields: frozenset[str], given: dict) -> dict:
    """A node read the way the reader reads it: every field of the type, null where unset."""
    return {name: given.get(name) for name in fields}


def counter():
    n = itertools.count(1)
    return lambda: f"00000000-0000-7000-8000-{next(n):012d}"


def known_for(plan_: plan.Plan) -> frozenset[str]:
    """What a reader would have read for this plan: its targets and the existing nodes it points at."""
    ids = {c.target_id for c in plan_.coverage} | {f.target_id for f in plan_.mint_findings}
    ids |= {f.vulnerability.value for f in plan_.mint_findings if f.vulnerability.kind == "existing"}
    ids |= {r.finding.value for r in plan_.reports if r.finding.kind == "existing"}
    ids |= {p.node_id for p in plan_.patch_vulnerabilities} | {p.node_id for p in plan_.patch_findings}
    return frozenset(ids)


def context(plan_: plan.Plan, **kw) -> document.Context:
    known = kw.pop("known_ids", known_for(plan_))
    return document.Context(scanner_id="scanner-0", field_names=FIELDS, known_ids=known, new_id=counter(), now=lambda: NOW, **kw)


def targets_ctx(grid) -> dict[str, str]:
    return {g.target.id: g.target.id for g in grid}


class TestFirstRunDocument(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.doc = parsed(recordings.LOG4J)
        cls.grid = grid_targets(cls.doc)
        cls.plan = run(cls.grid, one_document(cls.doc, cls.grid))
        cls.out = document.build_document(cls.plan, context(cls.plan))
        cls.batch = cls.out["batches"][0]

    def kinds(self, key: str, field: str) -> list[str]:
        return [item["entity"][field] for item in self.batch[key]]

    def test_it_is_one_batch_of_grift_v0(self) -> None:
        self.assertEqual(self.out["metadata"], {"grift_version": "0"})
        self.assertEqual(len(self.out["batches"]), 1)
        self.assertNotIn("deletes", self.batch)  # nothing replaced on a first run

    def test_the_run_the_findings_and_the_vulnerabilities_are_nodes_of_the_right_types(self) -> None:
        types = self.kinds("nodes", "entity_type")
        self.assertEqual(types.count(document.RUN), 1)
        self.assertEqual(types.count(document.FINDING), len(self.plan.mint_findings))
        self.assertEqual(types.count(document.VULNERABILITY), len(self.plan.mint_vulnerabilities))
        self.assertEqual(set(types), {document.RUN, document.FINDING, document.VULNERABILITY})  # no other types

    def test_every_entity_id_is_unique(self) -> None:
        ids = self.kinds("nodes", "entity_id") + self.kinds("edges", "entity_id")
        self.assertEqual(len(ids), len(set(ids)))

    def test_a_finding_carries_source_key_name_summary_and_open_status_and_nothing_it_does_not_own(self) -> None:
        finding = next(n for n in self.batch["nodes"] if n["entity"]["entity_type"] == document.FINDING)
        self.assertEqual(set(finding["node"]), {"source", "source_key", "name", "summary", "status"})
        self.assertEqual((finding["node"]["source"], finding["node"]["status"]), ("grype", "open"))
        self.assertEqual(finding["entity"]["dimensions"], {"compliance": "finding"})

    def test_the_run_node_holds_the_runs_facts_and_no_null(self) -> None:
        node = next(n for n in self.batch["nodes"] if n["entity"]["entity_type"] == document.RUN)["node"]
        self.assertEqual(node["outcome"], "ok")
        self.assertEqual(node["data_version"], "v6.1.10@2026-10-15T06:30:36Z")
        self.assertNotIn(None, node.values())

    def test_edges_come_in_the_five_kinds_with_the_properties_the_edge_types_declare(self) -> None:
        by_type: dict[str, list[dict]] = {}
        for edge in self.batch["edges"]:
            by_type.setdefault(edge["edge"]["edge_type"], []).append(edge["edge"])
        self.assertEqual(set(by_type), {document.PERFORMS, document.SCANNED, document.REPORTS, document.CARRIES, document.CONCERNS})
        self.assertEqual({tuple(sorted(e["properties"])) for e in by_type[document.SCANNED]}, {("outcome",)})
        for concerns in by_type[document.CONCERNS]:
            self.assertLessEqual(set(concerns["properties"]), {"fixed_versions"})
        self.assertEqual(len(by_type[document.SCANNED]), len(self.grid))
        self.assertEqual(len(by_type[document.REPORTS]), len(self.plan.mint_findings))

    def test_fixed_versions_is_absent_for_unknown_and_a_list_otherwise(self) -> None:
        by_finding = {f.key: f.fixed_versions for f in self.plan.mint_findings}
        node_ids = {n["entity"]["entity_id"]: n["node"]["source_key"] for n in self.batch["nodes"] if n["entity"]["entity_type"] == document.FINDING}
        for edge in self.batch["edges"]:
            e = edge["edge"]
            if e["edge_type"] != document.CONCERNS:
                continue
            expected = by_finding[node_ids[e["from_entity_id"]]]
            self.assertEqual(e["properties"].get("fixed_versions"), None if expected is None else list(expected))
            self.assertEqual("fixed_versions" in e["properties"], expected is not None)

    def test_an_unknown_fix_state_writes_no_fixed_versions_and_a_not_fixed_one_writes_an_empty_list(self) -> None:
        def with_state(state: str):
            matches = tuple(dataclasses.replace(m, fix_state=state, fixed_versions=()) for m in self.doc.matches)
            doc = dataclasses.replace(self.doc, matches=matches)
            built_plan = run(self.grid, one_document(doc, self.grid))
            batch = document.build_document(built_plan, context(built_plan))["batches"][0]
            return [e["edge"]["properties"] for e in batch["edges"] if e["edge"]["edge_type"] == document.CONCERNS]
        self.assertTrue(all("fixed_versions" not in p for p in with_state("unknown")))
        self.assertTrue(all(p.get("fixed_versions") == [] for p in with_state("not-fixed")))

    def test_a_plan_that_points_at_a_node_it_does_not_create_is_refused(self) -> None:
        broken = dataclasses.replace(self.plan, mint_vulnerabilities=[])
        with self.assertRaises(document.DocumentError):
            document.build_document(broken, context(broken))

    def test_every_edge_endpoint_is_in_the_batch_or_a_node_the_plan_was_given(self) -> None:
        defined = set(self.kinds("nodes", "entity_id"))
        given = {"scanner-0", *(g.target.id for g in self.grid)}
        for edge in self.batch["edges"]:
            for end in (edge["edge"]["from_entity_id"], edge["edge"]["to_entity_id"]):
                self.assertIn(end, defined | given)

    def test_the_batch_names_what_ran_without_secrets_or_free_text_from_the_grid(self) -> None:
        described = self.batch["batch_node"]["description_json"]
        self.assertEqual(described["format"], document.COLLECTION_FORMAT)
        self.assertEqual(described["counts"], {"nodes": len(self.batch["nodes"]), "edges": len(self.batch["edges"])})
        self.assertEqual(described["run"]["outcome"], "ok")


class TestSecondRunDocument(unittest.TestCase):
    def setUp(self) -> None:
        self.doc = parsed(recordings.LOG4J)
        self.grid = grid_targets(self.doc)
        first = run(self.grid, one_document(self.doc, self.grid))
        self.findings, self.vulns = as_existing(first, self.grid)

    def second(self, plan_: plan.Plan, ctx: document.Context) -> dict:
        return document.build_document(plan_, ctx)["batches"][0]

    def test_the_second_run_sends_no_deletes_a_collector_holds_no_delete_capability(self) -> None:
        plan_ = run(self.grid, one_document(self.doc, self.grid), findings=self.findings, vulnerabilities=self.vulns)
        batch = self.second(plan_, context(plan_))
        self.assertNotIn("deletes", batch)  # core ruling: collectors never retire; earlier runs' edges stay as history
        self.assertEqual([e["edge"]["edge_type"] for e in batch["edges"]].count(document.SCANNED), len(self.grid))  # a fresh coverage edge per target

    def test_an_existing_vulnerability_is_sent_whole_with_the_version_it_was_read_at(self) -> None:
        theirs = plan.ExistingVulnerability("v-cve", 4, "CVE-2021-44228", ("GHSA-jfh8-c2jp-5v3q",), {"cvss_score": 10.0, "kev": False})
        plan_ = run(self.grid, one_document(self.doc, self.grid), vulnerabilities=[theirs])
        read = document.ExistingNode(
            4,
            whole(VULN_FIELDS, {"vuln_id": "CVE-2021-44228", "aliases": ["GHSA-jfh8-c2jp-5v3q"], "cvss_score": 10.0, "cvss_vector": "AV:N", "cwes": ["CWE-917"], "ssvc_exploitation": "active", "kev": False}),
            {"compliance": "vulnerability", "x.other": "kept"},
            "CVE-2021-44228",
        )
        batch = self.second(plan_, context(plan_, existing_nodes={"v-cve": read}))
        sent = next(n for n in batch["nodes"] if n["entity"]["entity_id"] == "v-cve")
        self.assertEqual(sent["entity"]["entity_expected_version"], 4)
        self.assertEqual(sent["entity"]["dimensions"], {"compliance": "vulnerability", "x.other": "kept"})
        for kept in ("cvss_score", "cvss_vector", "cwes", "ssvc_exploitation", "vuln_id"):
            self.assertEqual(sent["node"][kept], read.properties[kept], kept)  # another source's fields survive the replace
        self.assertIs(sent["node"]["kev"], True)  # ours changed
        self.assertIn("kev_catalog_version", sent["node"])

    def test_a_node_the_plan_patches_but_nobody_read_is_refused_not_sent_blind(self) -> None:
        theirs = plan.ExistingVulnerability("v-cve", 4, "CVE-2021-44228", ("GHSA-jfh8-c2jp-5v3q",), {"kev": False})
        plan_ = run(self.grid, one_document(self.doc, self.grid), vulnerabilities=[theirs])
        with self.assertRaises(document.DocumentError):
            document.build_document(plan_, context(plan_))

    def test_a_version_that_moved_between_planning_and_reading_is_refused(self) -> None:
        theirs = plan.ExistingVulnerability("v-cve", 4, "CVE-2021-44228", ("GHSA-jfh8-c2jp-5v3q",), {"kev": False})
        plan_ = run(self.grid, one_document(self.doc, self.grid), vulnerabilities=[theirs])
        read = document.ExistingNode(5, whole(VULN_FIELDS, {"vuln_id": "CVE-2021-44228"}), {"compliance": "vulnerability"}, "CVE-2021-44228")
        with self.assertRaises(document.DocumentError):
            document.build_document(plan_, context(plan_, existing_nodes={"v-cve": read}))

    def test_a_resolved_finding_is_sent_as_the_whole_finding_with_its_version(self) -> None:
        gone = plan.ExistingFinding('["CVE-0000-0001","computing_core__library","x","1"]', "f-gone", self.grid[0].target.id, plan.OPEN, "x", 2)
        plan_ = run(self.grid, one_document(self.doc, self.grid), findings=[*self.findings, gone], vulnerabilities=self.vulns)
        read = document.ExistingNode(2, whole(FINDING_FIELDS, {"source": "grype", "source_key": gone.key, "name": "n", "summary": "x", "status": "open", "description": "kept"}), {"compliance": "finding"}, "n")
        batch = self.second(plan_, context(plan_, existing_nodes={"f-gone": read}))
        sent = next(n for n in batch["nodes"] if n["entity"]["entity_id"] == "f-gone")
        self.assertEqual((sent["node"]["status"], sent["node"]["description"], sent["entity"]["entity_expected_version"]), ("resolved", "kept", 2))


class TestGuardsOnWhatIsSentWhole(unittest.TestCase):
    """An existing node is replaced by what is sent, so what is sent is checked before it leaves."""

    def setUp(self) -> None:
        self.doc = parsed(recordings.LOG4J)
        self.grid = grid_targets(self.doc)
        first = run(self.grid, one_document(self.doc, self.grid))
        self.first_plan = first
        self.findings, self.vulns = as_existing(first, self.grid)
        self.gone = plan.ExistingFinding('["CVE-0000-0001","computing_core__library","x","1"]', "f-gone", self.grid[0].target.id, plan.OPEN, "x", 3)
        self.resolving = run(self.grid, one_document(self.doc, self.grid), findings=[*self.findings, self.gone], vulnerabilities=self.vulns)
        self.read = document.ExistingNode(3, whole(FINDING_FIELDS, {"source": "grype", "source_key": self.gone.key, "name": "n", "status": "open"}), {"compliance": "finding"}, "n")

    def test_a_finding_read_at_a_newer_version_than_planned_is_refused(self) -> None:
        newer = dataclasses.replace(self.read, version=4)
        with self.assertRaises(document.DocumentError):
            document.build_document(self.resolving, context(self.resolving, existing_nodes={"f-gone": newer}))
        document.build_document(self.resolving, context(self.resolving, existing_nodes={"f-gone": self.read}))  # at the planned version it is sent

    def test_a_node_read_without_a_field_of_its_type_is_refused_rather_than_sent_thin(self) -> None:
        thin = dataclasses.replace(self.read, properties={k: v for k, v in self.read.properties.items() if k != "description"})
        with self.assertRaises(document.DocumentError):
            document.build_document(self.resolving, context(self.resolving, existing_nodes={"f-gone": thin}))

    def test_a_node_read_with_a_field_its_type_does_not_declare_is_refused_not_written_back(self) -> None:
        extra = dataclasses.replace(self.read, properties={**self.read.properties, "unexpected_field": "value"})
        with self.assertRaises(document.DocumentError):
            document.build_document(self.resolving, context(self.resolving, existing_nodes={"f-gone": extra}))

    def test_an_edge_to_an_id_this_run_never_read_is_refused(self) -> None:
        stranger = "00000000-0000-7000-8000-00000000ffff"
        for label, bad in (
            ("coverage", dataclasses.replace(self.resolving, coverage=[plan.Coverage(stranger, "scanned", None), *self.resolving.coverage])),
            ("carries", dataclasses.replace(self.first_plan, mint_findings=[dataclasses.replace(f, target_id=stranger) for f in self.first_plan.mint_findings[:1]])),
            ("reports", dataclasses.replace(self.resolving, reports=[plan.Report(plan.Ref.existing(stranger))])),
        ):
            base = self.first_plan if label == "carries" else self.resolving
            known = known_for(base)  # what a reader would have read: the legitimate plan's nodes, not the stranger
            with self.subTest(label), self.assertRaises(document.DocumentError):
                document.build_document(bad, context(bad, known_ids=known, existing_nodes={"f-gone": self.read}))

    def test_a_plan_that_patches_a_field_this_plugin_does_not_own_is_refused(self) -> None:
        foreign = dataclasses.replace(self.resolving, patch_findings=[plan.PatchFinding("f-gone", {"status": "resolved", "description": "mine now"}, 3)])
        with self.assertRaises(document.DocumentError):
            document.build_document(foreign, context(foreign, existing_nodes={"f-gone": self.read}))
        vuln = plan.PatchVulnerability("v-cve", 1, {"cvss_score": 1.0})
        node = document.ExistingNode(1, whole(VULN_FIELDS, {"vuln_id": "CVE-2021-44228"}), {"compliance": "vulnerability"}, "CVE-2021-44228")
        with self.assertRaises(document.DocumentError):
            patched = dataclasses.replace(self.resolving, patch_vulnerabilities=[vuln])
            document.build_document(patched, context(patched, existing_nodes={"v-cve": node, "f-gone": self.read}))

    def test_a_context_that_does_not_say_what_the_fields_of_a_type_are_cannot_send_a_whole_node(self) -> None:
        ctx = document.Context(scanner_id="s", field_names={}, known_ids=known_for(self.resolving), new_id=counter(), now=lambda: NOW, existing_nodes={"f-gone": self.read})
        with self.assertRaises(document.DocumentError):
            document.build_document(self.resolving, ctx)


class TestRunThatScannedNothing(unittest.TestCase):
    def test_the_document_is_the_run_and_its_scanner_edge_only(self) -> None:
        empty = plan.plan_unscanned(outcome="db-stale", run_key="k", observed_at=NOW, tool_version="0.120.1")
        batch = document.build_document(empty, context(empty))["batches"][0]
        self.assertEqual([n["entity"]["entity_type"] for n in batch["nodes"]], [document.RUN])
        self.assertEqual([e["edge"]["edge_type"] for e in batch["edges"]], [document.PERFORMS])
        self.assertNotIn("deletes", batch)


class TestAgainstTheGriftSchema(unittest.TestCase):
    def test_the_document_validates_against_taps_schema(self) -> None:
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not importable here; the container run covers this")
        schema_path = next((p / "tap_grid" / "schemas" / "grift-document.schema.json" for p in [Path("/app"), *Path(__file__).parents] if (p / "tap_grid" / "schemas" / "grift-document.schema.json").exists()), None)
        if schema_path is None:
            self.skipTest("tap's GRIFT schema is not on this machine")
        schema = json.loads(schema_path.read_text())
        doc = parsed(recordings.LOG4J)
        grid = grid_targets(doc)
        first = run(grid, one_document(doc, grid))
        findings, vulns = as_existing(first, grid)
        second = run(grid, one_document(doc, grid), findings=findings, vulnerabilities=vulns, coverage={g.target.id: f"00000000-0000-7000-8000-{n:012d}" for n, g in enumerate(grid, 100)})
        # A run that patches existing nodes whole: a vulnerability another source wrote, and a finding that stopped matching.
        theirs = plan.ExistingVulnerability("00000000-0000-7000-8000-0000000000b1", 4, "CVE-2021-44228", ("GHSA-jfh8-c2jp-5v3q",), {"kev": False})
        gone = plan.ExistingFinding('["CVE-0000-0001","computing_core__library","x","1"]', "00000000-0000-7000-8000-0000000000b2", grid[0].target.id, plan.OPEN, "x", 2)
        patching = run(grid, one_document(doc, grid), findings=[*findings, gone], vulnerabilities=[theirs])
        nodes = {
            theirs.node_id: document.ExistingNode(4, whole(VULN_FIELDS, {"vuln_id": "CVE-2021-44228", "aliases": ["GHSA-jfh8-c2jp-5v3q"], "cvss_score": 10.0, "kev": False}), {"compliance": "vulnerability"}, "CVE-2021-44228"),
            gone.node_id: document.ExistingNode(2, whole(FINDING_FIELDS, {"source": "grype", "source_key": gone.key, "name": "n", "summary": "x", "status": "open"}), {"compliance": "finding"}, "n"),
        }
        scanner = "00000000-0000-7000-8000-0000000000aa"
        cases = (
            ("first run", first, {}),
            ("second run", second, {}),
            ("a run that patches existing nodes", patching, nodes),
            ("nothing scanned", plan.plan_unscanned(outcome="db-stale", run_key="k", observed_at=NOW, tool_version="0.120.1"), {}),
        )
        for label, plan_, existing in cases:
            with self.subTest(label):
                out = document.build_document(plan_, document.Context(scanner_id=scanner, field_names=FIELDS, known_ids=known_for(plan_), existing_nodes=existing, new_id=counter(), now=lambda: NOW))
                jsonschema.validate(out, schema)


if __name__ == "__main__":
    unittest.main()
