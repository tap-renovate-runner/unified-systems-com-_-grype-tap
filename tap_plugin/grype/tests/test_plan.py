"""The plan of one run: findings, coverage, resolution and vulnerability patches, on the real recordings.

Stdlib ``unittest`` only. The plan is pure, so each case feeds it parsed recordings and a description of what the
grid already holds, and reads back what would be written. A second run is simulated by turning the first plan's
mints into the "existing" rows the grid would then hold.
"""

import dataclasses
import json
import unittest
from datetime import UTC, datetime

from tap_plugin.grype import output, plan, targets
from tap_plugin.grype.tests import recordings

VERSION = recordings.VERSION
NOW = datetime(2026, 10, 16, 4, 43, tzinfo=UTC)


def parsed(name: str) -> output.Document:
    return output.parse_document(recordings.text(name), expected_version=VERSION)


def grid_targets(document: output.Document) -> list[plan.GridTarget]:
    seen: dict[str, plan.GridTarget] = {}
    for match in document.matches:
        art = match.artifact
        if art.purl in seen:
            continue
        ptype = targets.purl_type(art.purl) or ""
        library = ptype == "generic"
        target = targets.Target(
            id=f"t{len(seen)}",
            kind="library" if library else "package",
            name=art.name,
            version=art.version,
            ecosystem=None if library else ptype,
            purl=art.purl,
        )
        seen[art.purl] = plan.GridTarget(
            target,
            "computing_core__library" if library else "computing_core__package",
            (art.name, art.version) if library else (ptype, art.name, art.version),
        )
    return list(seen.values())


def run(
    grid: list[plan.GridTarget],
    results: list[plan.DocumentResult],
    *,
    findings: list[plan.ExistingFinding] | None = None,
    vulnerabilities: list[plan.ExistingVulnerability] | None = None,
    coverage: dict[str, str] | None = None,
) -> plan.Plan:
    return plan.plan_scan(
        targets=grid,
        results=results,
        existing_findings=findings or [],
        existing_vulnerabilities=vulnerabilities or [],
        existing_coverage=coverage or {},
        run_key="0194-run",
        observed_at=NOW,
        tool_version=VERSION,
    )


def one_document(document: output.Document, grid: list[plan.GridTarget]) -> list[plan.DocumentResult]:
    return [plan.DocumentResult("doc-0", tuple(g.target.id for g in grid), document)]


def as_existing(first: plan.Plan, grid: list[plan.GridTarget]) -> tuple[list[plan.ExistingFinding], list[plan.ExistingVulnerability]]:
    """The rows the grid would hold after ``first`` was written."""
    findings = [
        plan.ExistingFinding(f.key, f"f-{n}", f.target_id, plan.OPEN, f.summary, f"re-{n}") for n, f in enumerate(first.mint_findings)
    ]
    vulns = [
        plan.ExistingVulnerability(f"v-{n}", 1, v.key, tuple(v.fields["aliases"]), {k: x for k, x in v.fields.items() if k not in ("vuln_id", "aliases")})
        for n, v in enumerate(first.mint_vulnerabilities)
    ]
    return findings, vulns


class TestFirstRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.doc = parsed(recordings.TAP_WEB)
        cls.grid = grid_targets(cls.doc)
        cls.plan = run(cls.grid, one_document(cls.doc, cls.grid))

    def test_the_tap_web_run_is_ok_and_names_what_it_read(self) -> None:
        run_fields = self.plan.run
        self.assertEqual(run_fields["outcome"], "ok")
        self.assertEqual(run_fields["results_count"], 91)
        self.assertEqual(run_fields["data_version"], "v6.1.10@2026-10-15T06:30:36Z")
        self.assertEqual(run_fields["data_built_at"], "2026-10-15T06:30:36+00:00")
        self.assertEqual((run_fields["source"], run_fields["category"], run_fields["tool_version"]), ("grype", "grype-grid", VERSION))

    def test_every_target_is_scanned_and_every_match_becomes_one_new_finding(self) -> None:
        self.assertEqual({(c.outcome, c.reason) for c in self.plan.coverage}, {("scanned", None)})
        self.assertEqual(len(self.plan.coverage), len(self.grid))
        self.assertEqual(len(self.plan.mint_findings), 91)
        self.assertEqual(len({f.key for f in self.plan.mint_findings}), 91)
        self.assertEqual(len(self.plan.reports), 91)
        self.assertEqual(len(self.plan.mint_vulnerabilities), 27)
        self.assertEqual((self.plan.patch_vulnerabilities, self.plan.patch_findings, self.plan.delete_edges, self.plan.unmapped), ([], [], [], []))
        minted = {m.key for m in self.plan.mint_vulnerabilities}
        self.assertEqual({f.vulnerability.value for f in self.plan.mint_findings}, minted)  # every reference is to a node the plan creates

    def test_a_finding_key_is_a_json_array_of_the_vulnerability_and_the_targets_natural_key(self) -> None:
        by_id = {g.target.id: g for g in self.grid}
        for finding in self.plan.mint_findings:
            decoded = json.loads(finding.key)
            target = by_id[finding.target_id]
            self.assertEqual(decoded[0], finding.vulnerability.value)  # a new vulnerability's ref is its key
            self.assertEqual(decoded[1:], [target.entity_type, *target.natural_key])
            self.assertNotIn(" ", finding.key)
        self.assertEqual({json.loads(f.key)[1] for f in self.plan.mint_findings}, {"computing_core__package", "computing_core__library"})

    def test_a_finding_names_its_vulnerability_target_and_the_scanners_statement(self) -> None:
        finding = self.plan.mint_findings[0]
        self.assertIn(" in ", finding.name)
        self.assertTrue(finding.summary.startswith("Grype severity "))
        self.assertEqual(finding.vulnerability.kind, "new")


class TestLog4j(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.doc = parsed(recordings.LOG4J)
        cls.grid = grid_targets(cls.doc)
        cls.plan = run(cls.grid, one_document(cls.doc, cls.grid))
        cls.vulns = {v.key: v for v in cls.plan.mint_vulnerabilities}

    def test_a_ghsa_match_yields_one_cve_node_with_the_ghsa_as_alias(self) -> None:
        node = self.vulns["CVE-2021-44228"]
        self.assertEqual(node.fields["vuln_id"], "CVE-2021-44228")
        self.assertEqual(node.fields["aliases"], ["GHSA-jfh8-c2jp-5v3q"])
        self.assertFalse(any(key.startswith("GHSA-") and any(key in v.fields["aliases"] for v in self.vulns.values()) for key in self.vulns))

    def test_kev_and_epss_are_carried_as_grype_supplies_them(self) -> None:
        fields = self.vulns["CVE-2021-44228"].fields
        self.assertIs(fields["kev"], True)
        self.assertEqual(fields["kev_ransomware_use"], "known")  # as given, not re-cased
        self.assertEqual(fields["kev_catalog_version"], "grype-db:v6.1.10@2026-10-15T06:30:36Z")
        self.assertIn("kev_added", fields)
        self.assertEqual({"epss_score", "epss_percentile", "epss_date"} - set(fields), set())

    def test_a_vulnerability_grype_does_not_list_is_false_and_carries_no_kev_details(self) -> None:
        fields = self.vulns["CVE-2021-45105"].fields
        self.assertIs(fields["kev"], False)
        self.assertEqual([k for k in fields if k.startswith("kev_") and k != "kev_catalog_version"], [])

    def test_a_vulnerability_without_an_epss_reading_gets_no_epss_field_never_zero(self) -> None:
        no_epss = dataclasses.replace(self.doc, matches=tuple(dataclasses.replace(m, epss=()) for m in self.doc.matches))
        fields = {v.key: v for v in run(self.grid, one_document(no_epss, self.grid)).mint_vulnerabilities}["CVE-2021-44228"].fields
        self.assertEqual([k for k in fields if k.startswith("epss")], [])

    def test_a_document_that_did_not_report_its_database_never_writes_kev_false(self) -> None:
        blind = dataclasses.replace(self.doc, db=None)
        plan_ = run(self.grid, one_document(blind, self.grid))
        nodes = {n.key: n.fields for n in plan_.mint_vulnerabilities}
        self.assertIs(nodes["CVE-2021-44228"]["kev"], True)  # a listing is an answer whether or not the database was reported
        self.assertNotIn("CVE-2021-45105", {k for k, f in nodes.items() if "kev" in f})  # an omission is not, so null and never false
        self.assertEqual([k for k, f in nodes.items() if f.get("kev") is False], [])
        self.assertEqual([k for k, f in nodes.items() if "kev_catalog_version" in f], [])
        self.assertIsNone(plan_.run["data_version"])


class TestSecondRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.doc = parsed(recordings.TAP_WEB)
        cls.grid = grid_targets(cls.doc)
        cls.first = run(cls.grid, one_document(cls.doc, cls.grid))
        cls.findings, cls.vulns = as_existing(cls.first, cls.grid)

    def second(self, **kw) -> plan.Plan:
        return run(self.grid, one_document(self.doc, self.grid), findings=self.findings, vulnerabilities=self.vulns, **kw)

    def test_an_unchanged_rerun_creates_and_patches_nothing(self) -> None:
        again = self.second()
        self.assertEqual((again.mint_findings, again.patch_findings, again.mint_vulnerabilities, again.patch_vulnerabilities), ([], [], [], []))

    def test_the_finding_is_the_same_node_across_runs_and_only_its_reporting_edge_moves(self) -> None:
        again = self.second()
        self.assertEqual({r.finding for r in again.reports}, {plan.Ref.existing(f.node_id) for f in self.findings})
        self.assertEqual(sorted(again.delete_edges), sorted(f.reporting_edge_id for f in self.findings))

    def test_the_previous_coverage_edge_of_each_touched_target_is_deleted(self) -> None:
        old = {g.target.id: f"cov-{g.target.id}" for g in self.grid}
        again = self.second(coverage=old)
        self.assertEqual(set(old.values()) - set(again.delete_edges), set())
        self.assertEqual(len(again.coverage), len(self.grid))

    def test_a_finding_no_longer_matched_on_a_scanned_target_is_resolved(self) -> None:
        stale = plan.ExistingFinding('["CVE-0000-0001","computing_core__package","apk","gone","1"]', "f-gone", self.grid[0].target.id, plan.OPEN, "x", "re-gone")
        again = run(self.grid, one_document(self.doc, self.grid), findings=[*self.findings, stale], vulnerabilities=self.vulns)
        self.assertEqual([(p.node_id, p.fields) for p in again.patch_findings], [("f-gone", {"status": "resolved"})])
        self.assertNotIn("re-gone", again.delete_edges)  # a resolved finding keeps its edge to the last run that saw it

    def test_a_resolved_finding_that_matches_again_is_reopened(self) -> None:
        resolved = [dataclasses.replace(self.findings[0], status=plan.RESOLVED), *self.findings[1:]]
        again = run(self.grid, one_document(self.doc, self.grid), findings=resolved, vulnerabilities=self.vulns)
        self.assertEqual([(p.node_id, p.fields) for p in again.patch_findings], [(self.findings[0].node_id, {"status": "open"})])

    def test_a_changed_severity_or_fix_state_updates_the_summary_only(self) -> None:
        changed = [dataclasses.replace(self.findings[0], summary="Grype severity Low; fix unknown"), *self.findings[1:]]
        again = run(self.grid, one_document(self.doc, self.grid), findings=changed, vulnerabilities=self.vulns)
        self.assertEqual([set(p.fields) for p in again.patch_findings], [{"summary"}])


class TestResolveOnlyWhatWasScanned(unittest.TestCase):
    def setUp(self) -> None:
        self.doc = parsed(recordings.LOG4J)
        self.grid = grid_targets(self.doc)
        self.first = run(self.grid, one_document(self.doc, self.grid))
        self.findings, self.vulns = as_existing(self.first, self.grid)
        self.ids = tuple(g.target.id for g in self.grid)
        self.gone = plan.ExistingFinding('["CVE-0000-0001","computing_core__library","x","1"]', "f-gone", self.grid[0].target.id, plan.OPEN, "x", None)

    def test_when_every_document_failed_nothing_is_written_but_the_record_of_it(self) -> None:
        failed = run(self.grid, [plan.DocumentResult("doc-0", self.ids, None)], findings=[*self.findings, self.gone], vulnerabilities=self.vulns)
        self.assertEqual(failed.run["outcome"], "failed")
        self.assertEqual({(c.outcome, c.reason) for c in failed.coverage}, {("not-scanned", "document-failed")})
        self.assertEqual((failed.mint_findings, failed.patch_findings, failed.reports, failed.mint_vulnerabilities), ([], [], [], []))
        self.assertIsNone(failed.run["data_version"])

    def test_a_target_in_one_parsed_and_one_failed_document_is_not_scanned_and_resolves_nothing(self) -> None:
        results = [plan.DocumentResult("doc-0", self.ids, self.doc), plan.DocumentResult("doc-1", self.ids, None)]
        mixed = run(self.grid, results, findings=[*self.findings, self.gone], vulnerabilities=self.vulns)
        self.assertEqual({(c.outcome, c.reason) for c in mixed.coverage}, {("not-scanned", "document-failed")})
        self.assertEqual(mixed.run["outcome"], "partial")
        self.assertNotIn("f-gone", [p.node_id for p in mixed.patch_findings])  # still open
        self.assertEqual({r.finding for r in mixed.reports}, {plan.Ref.existing(f.node_id) for f in self.findings})  # matches still count

    def test_a_target_only_in_the_failed_document_is_untouched_while_another_is_resolved(self) -> None:
        second = dataclasses.replace(self.grid[0], target=dataclasses.replace(self.grid[0].target, id="other", name="other-lib", purl="pkg:generic/other@1"), natural_key=("other-lib", "1"))
        grid = [*self.grid, second]
        stranded = plan.ExistingFinding('["CVE-0000-0002","computing_core__library","other-lib","1"]', "f-other", "other", plan.OPEN, "x", None)
        results = [plan.DocumentResult("good", tuple(g.target.id for g in self.grid), self.doc), plan.DocumentResult("bad", ("other",), None)]
        mixed = run(grid, results, findings=[*self.findings, self.gone, stranded], vulnerabilities=self.vulns)
        outcomes = {c.target_id: c.outcome for c in mixed.coverage}
        self.assertEqual(outcomes["other"], "not-scanned")
        resolved = {p.node_id for p in mixed.patch_findings}
        self.assertIn("f-gone", resolved)
        self.assertNotIn("f-other", resolved)

    def test_a_match_that_maps_to_no_target_is_counted_and_the_run_is_partial(self) -> None:
        fewer = self.grid[:0]
        extra = plan.GridTarget(targets.Target("lonely", "library", "lonely", "1", None, "pkg:generic/lonely@1"), "computing_core__library", ("lonely", "1"))
        partial = run([extra], [plan.DocumentResult("doc-0", ("lonely",), self.doc)])
        self.assertEqual(fewer, [])
        self.assertEqual(partial.run["outcome"], "partial")
        self.assertEqual(len(partial.unmapped), len(self.doc.matches))
        self.assertEqual({u.reason for u in partial.unmapped}, {targets.NO_TARGET})
        self.assertEqual(partial.mint_findings, [])
        self.assertEqual([(c.outcome, c.reason) for c in partial.coverage], [("not-scanned", "unmapped")])

    def test_a_document_with_an_unmapped_match_resolves_nothing_for_any_target_in_it(self) -> None:
        extra = plan.GridTarget(targets.Target("lonely", "library", "lonely", "1", None, "pkg:generic/lonely@1"), "computing_core__library", ("lonely", "1"))
        stale = plan.ExistingFinding('["CVE-0000-0003","computing_core__library","lonely","1"]', "f-lonely", "lonely", plan.OPEN, "x", None)
        # One document, several targets, one match that maps to none of them: no target in it can be said to have lost a finding.
        stray = dataclasses.replace(self.doc.matches[0], artifact=dataclasses.replace(self.doc.matches[0].artifact, purl="pkg:maven/not/in-the-grid@9", name="in-the-grid", version="9"))
        doc = dataclasses.replace(self.doc, matches=(*self.doc.matches, stray))
        ids = tuple(g.target.id for g in self.grid)
        result = run([*self.grid, extra], [plan.DocumentResult("doc-0", (*ids, "lonely"), doc)], findings=[*self.findings, stale], vulnerabilities=self.vulns)
        self.assertEqual({(c.outcome, c.reason) for c in result.coverage}, {("not-scanned", "unmapped")})
        self.assertEqual([p for p in result.patch_findings if p.fields.get("status") == "resolved"], [])
        self.assertEqual({r.finding for r in result.reports}, {plan.Ref.existing(f.node_id) for f in self.findings})  # what did map still counts
        self.assertEqual(result.run["outcome"], "partial")
        self.assertEqual(len(result.unmapped), 1)

    def test_matches_from_a_document_that_carries_no_target_are_unmapped_and_the_run_is_partial(self) -> None:
        ids = tuple(g.target.id for g in self.grid)
        result = run(self.grid, [plan.DocumentResult("doc-0", ids, self.doc), plan.DocumentResult("orphan", (), self.doc)])
        self.assertEqual({(c.outcome, c.reason) for c in result.coverage}, {("scanned", None)})
        self.assertEqual(len(result.unmapped), len(self.doc.matches))
        self.assertEqual(result.run["outcome"], "partial")

    def test_a_vulnerability_only_an_unmapped_match_names_is_not_minted(self) -> None:
        extra = plan.GridTarget(targets.Target("lonely", "library", "lonely", "1", None, "pkg:generic/lonely@1"), "computing_core__library", ("lonely", "1"))
        result = run([extra], [plan.DocumentResult("doc-0", ("lonely",), self.doc)])
        self.assertEqual((result.mint_vulnerabilities, result.patch_vulnerabilities), ([], []))

    def test_an_existing_vulnerability_only_a_refused_target_names_is_not_patched(self) -> None:
        doc = parsed(recordings.LOG4J)
        grid = grid_targets(doc)
        long_key = [dataclasses.replace(grid[0], natural_key=("x" * 600,))]
        held = plan.ExistingVulnerability("v-cve", 1, "CVE-2021-44228", ("GHSA-jfh8-c2jp-5v3q",), {"kev": False})
        result = run(long_key, one_document(doc, long_key), vulnerabilities=[held])
        self.assertEqual(result.patch_vulnerabilities, [])

    def test_a_refused_target_contributes_no_field_value_to_a_vulnerability_an_accepted_target_also_names(self) -> None:
        base = self.doc.matches[0]
        def at(purl: str, source: str):
            art = dataclasses.replace(base.artifact, purl=purl, name=purl.split("/")[-1].split("@")[0], version="1")
            return dataclasses.replace(base, artifact=art, data_source=source)
        refused_first = at("pkg:maven/b/refused@1", "https://example.test/from-the-refused-target")
        accepted = at("pkg:maven/a/accepted@1", "https://example.test/from-the-accepted-target")
        def gt(purl: str, natural: tuple[str, ...]) -> plan.GridTarget:
            return plan.GridTarget(targets.Target(natural[0], "package", natural[0], "1", "maven", purl), "computing_core__package", natural)
        grid = [gt("pkg:maven/b/refused@1", ("x" * 600,)), gt("pkg:maven/a/accepted@1", ("accepted", "1"))]
        grid[0] = dataclasses.replace(grid[0], target=dataclasses.replace(grid[0].target, id="refused"))
        doc = dataclasses.replace(self.doc, matches=(refused_first, accepted))
        held = plan.ExistingVulnerability("v-cve", 1, "CVE-2021-44228", (base.vuln_id,), {})
        result = run(grid, one_document(doc, grid), vulnerabilities=[held])
        patch = next(p for p in result.patch_vulnerabilities if p.node_id == "v-cve")
        self.assertEqual(patch.fields["record_url"], "https://example.test/from-the-accepted-target")

    def test_a_finding_points_at_the_node_the_vulnerability_writes_make_even_when_a_refused_match_names_an_alias(self) -> None:
        base = self.doc.matches[0]  # GHSA-jfh8-c2jp-5v3q with CVE-2021-44228 in relatedVulnerabilities
        def at(purl: str, vuln_id: str, related: tuple[str, ...]):
            art = dataclasses.replace(base.artifact, purl=purl, name=purl.split("/")[-1].split("@")[0], version="1")
            return dataclasses.replace(base, artifact=art, vuln_id=vuln_id, related_ids=related)
        def gt(purl: str, natural: tuple[str, ...], ident: str) -> plan.GridTarget:
            return plan.GridTarget(targets.Target(ident, "package", natural[0], "1", "maven", purl), "computing_core__package", natural)
        accepted = at("pkg:maven/a/accepted@1", "CVE-2021-44228", ())  # names the CVE alone
        refused = at("pkg:maven/b/refused@1", "GHSA-jfh8-c2jp-5v3q", ("CVE-2021-44228",))  # would add the GHSA alias
        grid = [gt("pkg:maven/a/accepted@1", ("accepted", "1"), "ok"), gt("pkg:maven/b/refused@1", ("x" * 600,), "refused")]
        doc = dataclasses.replace(self.doc, matches=(accepted, refused))
        only_ghsa = plan.ExistingVulnerability("v-ghsa", 1, "GHSA-jfh8-c2jp-5v3q", (), {})
        result = run(grid, one_document(doc, grid), vulnerabilities=[only_ghsa])
        minted = {m.key for m in result.mint_vulnerabilities}
        for finding in result.mint_findings:
            if finding.vulnerability.kind == "new":
                self.assertIn(finding.vulnerability.value, minted)  # a reference to a node nothing creates would dangle
            else:
                self.assertEqual(finding.vulnerability.value, "v-ghsa")
        self.assertEqual([p for p in result.patch_vulnerabilities if p.node_id == "v-ghsa"], [])  # the refused match's alias did not reach it

    def test_two_documents_sharing_a_label_are_refused(self) -> None:
        ids = tuple(g.target.id for g in self.grid)
        with self.assertRaises(plan.PlanError):
            run(self.grid, [plan.DocumentResult("same", ids[:1], self.doc), plan.DocumentResult("same", ids[1:], self.doc)])

    def test_a_failed_document_outranks_an_unmapped_match_as_the_reason(self) -> None:
        stray = dataclasses.replace(self.doc.matches[0], artifact=dataclasses.replace(self.doc.matches[0].artifact, purl="pkg:maven/not/in-the-grid@9", name="in-the-grid", version="9"))
        doc = dataclasses.replace(self.doc, matches=(*self.doc.matches, stray))
        ids = tuple(g.target.id for g in self.grid)
        result = run(self.grid, [plan.DocumentResult("a", ids, doc), plan.DocumentResult("b", ids, None)])
        self.assertEqual({(c.outcome, c.reason) for c in result.coverage}, {("not-scanned", "document-failed")})


class TestAFindingKeepsItsKey(unittest.TestCase):
    """The same finding must stay the same node when a database build later gives its advisory a CVE."""

    def setUp(self) -> None:
        self.full = parsed(recordings.LOG4J)
        self.grid = grid_targets(self.full)
        # The first sighting: Grype named only the GHSA, with no CVE in relatedVulnerabilities.
        self.ghsa_only = dataclasses.replace(self.full, matches=tuple(dataclasses.replace(m, related_ids=()) for m in self.full.matches))

    def test_a_cve_attached_later_does_not_turn_the_finding_into_a_new_one(self) -> None:
        first = run(self.grid, one_document(self.ghsa_only, self.grid))
        findings, vulns = as_existing(first, self.grid)
        self.assertTrue(all(json.loads(f.key)[0].startswith("GHSA-") for f in findings))
        again = run(self.grid, one_document(self.full, self.grid), findings=findings, vulnerabilities=vulns)
        self.assertEqual((again.mint_findings, again.mint_vulnerabilities), ([], []))
        self.assertEqual([p for p in again.patch_findings if p.fields.get("status") == "resolved"], [])
        self.assertEqual({r.finding for r in again.reports}, {plan.Ref.existing(f.node_id) for f in findings})
        added = {a for p in again.patch_vulnerabilities for a in p.fields.get("aliases", [])}
        self.assertIn("CVE-2021-44228", added)  # the CVE becomes an alias of the node that already exists

    def test_a_new_finding_on_a_reused_node_is_keyed_by_the_nodes_own_id(self) -> None:
        theirs = plan.ExistingVulnerability("v-ghsa", 1, "GHSA-jfh8-c2jp-5v3q", (), {})
        result = run(self.grid, one_document(self.full, self.grid), vulnerabilities=[theirs])
        keys = [json.loads(f.key)[0] for f in result.mint_findings if f.vulnerability == plan.Ref.existing("v-ghsa")]
        self.assertEqual(keys, ["GHSA-jfh8-c2jp-5v3q"])

    def test_a_finding_minted_under_the_cve_is_still_found_after_the_node_turns_out_to_be_keyed_by_the_ghsa(self) -> None:
        first = run(self.grid, one_document(self.full, self.grid))
        findings, _ = as_existing(first, self.grid)
        theirs = plan.ExistingVulnerability("v-ghsa", 1, "GHSA-jfh8-c2jp-5v3q", ("CVE-2021-44228",), {})
        again = run(self.grid, one_document(self.full, self.grid), findings=findings, vulnerabilities=[theirs])
        old_keys = {json.loads(f.key)[0]: f for f in findings}
        self.assertIn("CVE-2021-44228", old_keys)
        minted = {json.loads(f.key)[0] for f in again.mint_findings}
        self.assertNotIn("CVE-2021-44228", minted)  # not minted a second time under another spelling
        self.assertEqual([p for p in again.patch_findings if p.fields.get("status") == "resolved" and p.node_id == old_keys["CVE-2021-44228"].node_id], [])


class TestFindingKeys(unittest.TestCase):
    def target(self, *natural: str) -> plan.GridTarget:
        return plan.GridTarget(targets.Target("t", "package", "n", "1", "apk", None), "computing_core__package", tuple(natural))

    def test_two_targets_that_differ_only_where_a_pipe_falls_get_different_keys(self) -> None:
        a = plan.finding_key("CVE-2026-1", self.target("a|b", "c"))
        b = plan.finding_key("CVE-2026-1", self.target("a", "b|c"))
        self.assertNotEqual(a, b)
        self.assertEqual(json.loads(a), ["CVE-2026-1", "computing_core__package", "a|b", "c"])

    def test_a_key_over_512_characters_is_refused_not_truncated(self) -> None:
        with self.assertRaises(plan.PlanError):
            plan.finding_key("CVE-2026-1", self.target("x" * 600))
        self.assertLessEqual(len(plan.finding_key("CVE-2026-1", self.target("x" * 400))), plan.KEY_LIMIT)

    def test_a_target_whose_key_is_refused_is_recorded_failed_and_writes_and_resolves_nothing(self) -> None:
        doc = parsed(recordings.LOG4J)
        grid = grid_targets(doc)
        long_key = dataclasses.replace(grid[0], natural_key=("x" * 600,))
        old = plan.ExistingFinding("old", "f-old", grid[0].target.id, plan.OPEN, "x", None)
        refused = run([long_key], one_document(doc, [long_key]), findings=[old])
        self.assertEqual([(c.outcome, c.reason) for c in refused.coverage], [("failed", "finding-key-too-long")])
        self.assertEqual((refused.mint_findings, refused.patch_findings, refused.reports), ([], [], []))
        self.assertEqual((refused.mint_vulnerabilities, refused.patch_vulnerabilities), ([], []))  # no orphan vulnerability either
        self.assertEqual(refused.run["outcome"], "partial")


class TestVulnerabilityPatch(unittest.TestCase):
    def setUp(self) -> None:
        self.doc = parsed(recordings.LOG4J)
        self.grid = grid_targets(self.doc)

    def planned(self, existing: list[plan.ExistingVulnerability]) -> plan.Plan:
        return run(self.grid, one_document(self.doc, self.grid), vulnerabilities=existing)

    def test_a_node_another_producer_made_under_the_ghsa_is_reused_and_given_the_cve_as_alias(self) -> None:
        theirs = plan.ExistingVulnerability("v-ghsa", 7, "GHSA-jfh8-c2jp-5v3q", (), {"cvss_score": 10.0})
        result = self.planned([theirs])
        self.assertNotIn("CVE-2021-44228", {m.key for m in result.mint_vulnerabilities})
        patch = next(p for p in result.patch_vulnerabilities if p.node_id == "v-ghsa")
        self.assertEqual(patch.expected_version, 7)
        self.assertEqual(patch.fields["aliases"], ["CVE-2021-44228"])
        self.assertTrue(all(f.vulnerability == plan.Ref.existing("v-ghsa") for f in result.mint_findings if f.vulnerability.kind == "existing"))

    def test_a_patch_never_touches_another_sources_fields_or_replaces_a_description(self) -> None:
        theirs = plan.ExistingVulnerability(
            "v-cve", 3, "CVE-2021-44228", ("GHSA-jfh8-c2jp-5v3q",),
            {"description": "their words", "cvss_score": 10.0, "cwes": ["CWE-917"], "ssvc_exploitation": "active", "kev": False},
        )
        patch = next(p for p in self.planned([theirs]).patch_vulnerabilities if p.node_id == "v-cve")
        self.assertNotIn("description", patch.fields)
        self.assertEqual({k for k in patch.fields if k.startswith(("cvss", "cwe", "ssvc"))}, set())
        self.assertIs(patch.fields["kev"], True)  # a listing turns the answer on, with its details
        self.assertEqual(patch.fields["kev_catalog_version"], "grype-db:v6.1.10@2026-10-15T06:30:36Z")

    def test_a_null_description_is_filled_once(self) -> None:
        theirs = plan.ExistingVulnerability("v-cve", 1, "CVE-2021-44228", ("GHSA-jfh8-c2jp-5v3q",), {"description": None})
        patch = next(p for p in self.planned([theirs]).patch_vulnerabilities if p.node_id == "v-cve")
        self.assertIsInstance(patch.fields["description"], str)

    def test_a_delisted_vulnerability_is_set_false_and_an_unchanged_one_is_not_patched(self) -> None:
        listed = plan.ExistingVulnerability("v", 1, "CVE-2021-45105", ("GHSA-p6xc-xr62-6r2g",), {"kev": True, "kev_added": "2021-12-01"})
        patch = next(p for p in self.planned([listed]).patch_vulnerabilities if p.node_id == "v")
        self.assertIs(patch.fields["kev"], False)
        self.assertNotIn("kev_added", patch.fields)  # the old details are not blanked
        first = self.planned([])
        _, vulns = as_existing(first, self.grid)
        self.assertEqual(self.planned(vulns).patch_vulnerabilities, [])

    def test_a_new_database_build_alone_does_not_patch_an_unchanged_answer(self) -> None:
        _, vulns = as_existing(self.planned([]), self.grid)
        newer = dataclasses.replace(self.doc, db=dataclasses.replace(self.doc.db, built=datetime(2026, 10, 16, 6, 0, tzinfo=UTC)))
        again = run(self.grid, one_document(newer, self.grid), vulnerabilities=vulns)
        self.assertEqual(again.patch_vulnerabilities, [])
        self.assertEqual(again.run["data_version"], "v6.1.10@2026-10-16T06:00:00Z")

    def test_two_different_nodes_for_one_vulnerability_are_refused_and_the_target_records_and_writes_nothing(self) -> None:
        # CVE-2021-45105 sorts after other vulnerabilities of the same target, so the refusal comes mid-target.
        one = plan.ExistingVulnerability("v1", 1, "GHSA-p6xc-xr62-6r2g", (), {})
        two = plan.ExistingVulnerability("v2", 1, "GHSA-other", ("CVE-2021-45105",), {})
        old = plan.ExistingFinding('["CVE-0000-0001","computing_core__library","x","1"]', "f-old", self.grid[0].target.id, plan.OPEN, "x", None)
        result = run(self.grid, one_document(self.doc, self.grid), vulnerabilities=[one, two], findings=[old])
        self.assertNotIn("CVE-2021-45105", {m.key for m in result.mint_vulnerabilities})
        self.assertIn(("failed", "vulnerability-ambiguous"), {(c.outcome, c.reason) for c in result.coverage})
        blocked = {c.target_id for c in result.coverage if c.outcome == "failed"}
        self.assertEqual(len(blocked), 1)
        self.assertEqual([f for f in result.mint_findings if f.target_id in blocked], [])  # not a partial set of its findings
        self.assertNotIn("f-old", [p.node_id for p in result.patch_findings])  # and not a resolve
        self.assertEqual(result.run["outcome"], "partial")

    def test_an_exact_id_node_does_not_hide_a_second_node_that_claims_the_same_vulnerability(self) -> None:
        canonical = plan.ExistingVulnerability("v-cve", 1, "CVE-2021-45105", (), {})
        claimant = plan.ExistingVulnerability("v-dup", 1, "GHSA-elsewhere", ("CVE-2021-45105",), {})
        result = self.planned([canonical, claimant])
        self.assertEqual([p for p in result.patch_vulnerabilities if p.node_id in ("v-cve", "v-dup")], [])
        self.assertIn(("failed", "vulnerability-ambiguous"), {(c.outcome, c.reason) for c in result.coverage})

    def test_a_kev_detail_the_catalog_did_not_give_is_left_alone_not_blanked(self) -> None:
        bare = tuple(
            dataclasses.replace(m, kev=tuple(dataclasses.replace(k, required_action=None) for k in m.kev)) for m in self.doc.matches
        )
        doc = dataclasses.replace(self.doc, matches=bare)
        held = plan.ExistingVulnerability("v", 1, "CVE-2021-44228", ("GHSA-jfh8-c2jp-5v3q",), {"kev": True, "kev_required_action": "their text"})
        patch = [p for p in run(self.grid, one_document(doc, self.grid), vulnerabilities=[held]).patch_vulnerabilities if p.node_id == "v"]
        self.assertTrue(all("kev_required_action" not in p.fields for p in patch))


class TestInputsThatContradict(unittest.TestCase):
    def test_two_database_builds_in_one_run_are_refused(self) -> None:
        doc = parsed(recordings.LOG4J)
        grid = grid_targets(doc)
        other = dataclasses.replace(doc, db=dataclasses.replace(doc.db, built=datetime(2026, 10, 16, tzinfo=UTC)))
        ids = tuple(g.target.id for g in grid)
        with self.assertRaises(plan.PlanError):
            run(grid, [plan.DocumentResult("a", ids, doc), plan.DocumentResult("b", ids, other)])

    def test_a_target_in_no_document_is_refused_not_left_unrecorded(self) -> None:
        doc = parsed(recordings.LOG4J)
        grid = grid_targets(doc)
        with self.assertRaises(plan.PlanError):
            run(grid, [plan.DocumentResult("a", (), doc)])

    def test_a_document_naming_an_unknown_target_is_refused(self) -> None:
        doc = parsed(recordings.LOG4J)
        grid = grid_targets(doc)
        with self.assertRaises(plan.PlanError):
            run(grid, [plan.DocumentResult("a", ("ghost",), doc)])


class TestRunsThatScannedNothing(unittest.TestCase):
    def test_db_stale_and_db_unavailable_write_the_run_alone_so_coverage_ages(self) -> None:
        for outcome in ("db-stale", "db-unavailable"):
            with self.subTest(outcome):
                empty = plan.plan_unscanned(outcome=outcome, run_key="k", observed_at=NOW, tool_version=VERSION)
                self.assertEqual(empty.run["outcome"], outcome)
                self.assertEqual((empty.coverage, empty.delete_edges, empty.mint_findings, empty.patch_findings), ([], [], [], []))
                self.assertIsNone(empty.run["data_version"])

    def test_any_other_outcome_is_refused(self) -> None:
        with self.assertRaises(plan.PlanError):
            plan.plan_unscanned(outcome="ok", run_key="k", observed_at=NOW, tool_version=VERSION)


if __name__ == "__main__":
    unittest.main()
