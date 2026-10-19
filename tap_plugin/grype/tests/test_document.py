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


def counter():
    n = itertools.count(1)
    return lambda: f"00000000-0000-7000-8000-{next(n):012d}"


def context(**kw) -> document.Context:
    return document.Context(scanner_id="scanner-0", new_id=counter(), now=lambda: NOW, **kw)


def targets_ctx(grid) -> dict[str, str]:
    return {g.target.id: g.target.id for g in grid}


class TestFirstRunDocument(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.doc = parsed(recordings.LOG4J)
        cls.grid = grid_targets(cls.doc)
        cls.plan = run(cls.grid, one_document(cls.doc, cls.grid))
        cls.out = document.build_document(cls.plan, context())
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
            batch = document.build_document(run(self.grid, one_document(doc, self.grid)), context())["batches"][0]
            return [e["edge"]["properties"] for e in batch["edges"] if e["edge"]["edge_type"] == document.CONCERNS]
        self.assertTrue(all("fixed_versions" not in p for p in with_state("unknown")))
        self.assertTrue(all(p.get("fixed_versions") == [] for p in with_state("not-fixed")))

    def test_a_plan_that_points_at_a_node_it_does_not_create_is_refused(self) -> None:
        broken = dataclasses.replace(self.plan, mint_vulnerabilities=[])
        with self.assertRaises(document.DocumentError):
            document.build_document(broken, context())

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

    def test_replaced_edges_go_into_deletes_by_id(self) -> None:
        plan_ = run(self.grid, one_document(self.doc, self.grid), findings=self.findings, vulnerabilities=self.vulns, coverage={g.target.id: f"cov-{g.target.id}" for g in self.grid})
        batch = self.second(plan_, context())
        deletes = batch["deletes"]
        self.assertEqual((deletes["on_missing"], deletes["nodes"]), ("warn", []))
        self.assertEqual({d["entity_id"] for d in deletes["edges"]}, {f.reporting_edge_id for f in self.findings} | {f"cov-{g.target.id}" for g in self.grid})
        self.assertEqual({d["entity_type"] for d in deletes["edges"]}, {"edge"})
        self.assertTrue(all(d["reason"] for d in deletes["edges"]))

    def test_an_existing_vulnerability_is_sent_whole_with_the_version_it_was_read_at(self) -> None:
        theirs = plan.ExistingVulnerability("v-cve", 4, "CVE-2021-44228", ("GHSA-jfh8-c2jp-5v3q",), {"cvss_score": 10.0, "kev": False})
        plan_ = run(self.grid, one_document(self.doc, self.grid), vulnerabilities=[theirs])
        read = document.ExistingNode(
            4,
            {"vuln_id": "CVE-2021-44228", "aliases": ["GHSA-jfh8-c2jp-5v3q"], "cvss_score": 10.0, "cvss_vector": "AV:N", "cwes": ["CWE-917"], "ssvc_exploitation": "active", "kev": False},
            {"compliance": "vulnerability", "x.other": "kept"},
            "CVE-2021-44228",
        )
        batch = self.second(plan_, context(existing_nodes={"v-cve": read}))
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
            document.build_document(plan_, context())

    def test_a_version_that_moved_between_planning_and_reading_is_refused(self) -> None:
        theirs = plan.ExistingVulnerability("v-cve", 4, "CVE-2021-44228", ("GHSA-jfh8-c2jp-5v3q",), {"kev": False})
        plan_ = run(self.grid, one_document(self.doc, self.grid), vulnerabilities=[theirs])
        read = document.ExistingNode(5, {"vuln_id": "CVE-2021-44228"}, {"compliance": "vulnerability"}, "CVE-2021-44228")
        with self.assertRaises(document.DocumentError):
            document.build_document(plan_, context(existing_nodes={"v-cve": read}))

    def test_a_resolved_finding_is_sent_as_the_whole_finding_with_its_version(self) -> None:
        gone = plan.ExistingFinding('["CVE-0000-0001","computing_core__library","x","1"]', "f-gone", self.grid[0].target.id, plan.OPEN, "x", None)
        plan_ = run(self.grid, one_document(self.doc, self.grid), findings=[*self.findings, gone], vulnerabilities=self.vulns)
        read = document.ExistingNode(2, {"source": "grype", "source_key": gone.key, "name": "n", "summary": "x", "status": "open", "description": "kept"}, {"compliance": "finding"}, "n")
        batch = self.second(plan_, context(existing_nodes={"f-gone": read}))
        sent = next(n for n in batch["nodes"] if n["entity"]["entity_id"] == "f-gone")
        self.assertEqual((sent["node"]["status"], sent["node"]["description"], sent["entity"]["entity_expected_version"]), ("resolved", "kept", 2))


class TestRunThatScannedNothing(unittest.TestCase):
    def test_the_document_is_the_run_and_its_scanner_edge_only(self) -> None:
        empty = plan.plan_unscanned(outcome="db-stale", run_key="k", observed_at=NOW, tool_version="0.120.1")
        batch = document.build_document(empty, context())["batches"][0]
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
        for label, plan_ in (("first run", first), ("second run", second), ("nothing scanned", plan.plan_unscanned(outcome="db-stale", run_key="k", observed_at=NOW, tool_version="0.120.1"))):
            with self.subTest(label):
                out = document.build_document(plan_, document.Context(scanner_id="00000000-0000-7000-8000-0000000000aa", new_id=counter(), now=lambda: NOW))
                jsonschema.validate(out, schema)


if __name__ == "__main__":
    unittest.main()
