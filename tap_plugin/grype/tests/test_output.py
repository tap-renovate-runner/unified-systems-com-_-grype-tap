"""The native-JSON parser and the facts derived from it, against the recorded Grype outputs.

Stdlib ``unittest`` only. The two recordings are real Grype v0.120.1 output (see tests/fixtures/recorded.json);
every defect case is made by damaging a copy of one of them, so a case fails for the reason it names.
"""

import copy
import gzip
import json
import tempfile
import unittest
from pathlib import Path
from datetime import date

from tap_plugin.grype import facts, output
from tap_plugin.grype.tests import recordings

VERSION = recordings.VERSION


def parse(data: dict) -> output.Document:
    return output.parse_document(json.dumps(data), expected_version=VERSION)


class TestRecordingsAreChecked(unittest.TestCase):
    """The gzip recordings are opaque in a diff, so the loader enforces what recorded.json claims."""

    def test_the_committed_recordings_match_their_manifest(self) -> None:
        for name, claimed in recordings.manifest()["files"].items():
            raw = recordings.text(name).encode("utf-8")
            self.assertEqual(len(raw), claimed["bytes"], name)

    def _replacement(self, payload: bytes) -> Path:
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: [p.unlink() for p in directory.iterdir()] and directory.rmdir())
        (directory / recordings.LOG4J).write_bytes(gzip.compress(payload))
        return directory

    def test_a_substituted_recording_of_the_right_size_is_refused(self) -> None:
        size = recordings.manifest()["files"][recordings.LOG4J]["bytes"]
        with self.assertRaises(recordings.FixtureError):
            recordings.text(recordings.LOG4J, directory=self._replacement(b" " * size))

    def test_a_recording_that_decompresses_larger_than_declared_is_refused(self) -> None:
        size = recordings.manifest()["files"][recordings.LOG4J]["bytes"]
        with self.assertRaises(recordings.FixtureError):
            recordings.text(recordings.LOG4J, directory=self._replacement(b"0" * (size * 50)))

    def test_a_truncated_recording_is_refused(self) -> None:
        directory = self._replacement(b"{}")
        with self.assertRaises(recordings.FixtureError):
            recordings.text(recordings.LOG4J, directory=directory)


class TestRecordedDocuments(unittest.TestCase):
    def test_the_tap_web_recording_parses_to_the_counts_the_spec_names(self) -> None:
        doc = output.parse_document(recordings.text(recordings.TAP_WEB), expected_version=VERSION)
        self.assertEqual(len(doc.matches), 91)
        self.assertEqual(len({m.vuln_id for m in doc.matches}), 27)
        self.assertEqual(doc.db.data_version, "v6.1.10@2026-10-15T06:30:36Z")
        self.assertEqual(sum(1 for m in doc.matches if m.epss), 67)
        self.assertEqual(sum(1 for m in doc.matches if m.kev), 0)

    def test_the_log4j_recording_carries_kev_and_a_ghsa_named_match(self) -> None:
        doc = output.parse_document(recordings.text(recordings.LOG4J), expected_version=VERSION)
        known = [m for m in doc.matches if m.kev]
        self.assertEqual(len(known), 2)
        self.assertTrue(all(m.vuln_id.startswith("GHSA-") for m in known))
        self.assertIn("CVE-2021-44228", {e.cve for m in known for e in m.kev})

    def test_unknown_extra_keys_are_tolerated_because_grype_adds_them(self) -> None:
        data = recordings.data(recordings.LOG4J)
        data["somethingNew"] = {"a": 1}
        data["matches"][0]["vulnerability"]["alsoNew"] = [1]
        self.assertEqual(len(parse(data).matches), len(data["matches"]))

    def test_no_matches_and_no_database_block_are_both_ordinary(self) -> None:
        doc = parse({"descriptor": {"name": "grype", "version": VERSION}, "matches": []})
        self.assertEqual((doc.matches, doc.db), ((), None))


class TestFailsClosed(unittest.TestCase):
    """req-grype-collector-4: nothing is read from a document that cannot be trusted whole."""

    def damaged(self, change) -> dict:
        data = copy.deepcopy(recordings.data(recordings.LOG4J))
        change(data)
        return data

    def test_truncated_and_non_json_text_is_refused(self) -> None:
        text = recordings.text(recordings.TAP_WEB)
        for label, damaged in {"truncated": text[: len(text) // 2], "empty": "", "prose": "grype: error", "array": "[]"}.items():
            with self.subTest(label), self.assertRaises(output.GrypeOutputError):
                output.parse_document(damaged, expected_version=VERSION)

    def test_a_document_from_another_version_or_tool_is_refused(self) -> None:
        for label, change in {
            "other version": lambda d: d["descriptor"].update(version="0.119.0"),
            "other tool": lambda d: d["descriptor"].update(name="syft"),
            "no descriptor": lambda d: d.pop("descriptor"),
        }.items():
            with self.subTest(label), self.assertRaises(output.GrypeOutputError):
                parse(self.damaged(change))

    def test_each_missing_or_malformed_required_field_is_refused(self) -> None:
        cases = {
            "matches missing": lambda d: d.pop("matches"),
            "matches null": lambda d: d.update(matches=None),
            "matches not a list": lambda d: d.update(matches={}),
            "match not an object": lambda d: d["matches"].__setitem__(0, 5),
            "vulnerability missing": lambda d: d["matches"][0].pop("vulnerability"),
            "vulnerability id missing": lambda d: d["matches"][0]["vulnerability"].pop("id"),
            "vulnerability id path-like": lambda d: d["matches"][0]["vulnerability"].update(id="../etc/passwd"),
            "vulnerability id empty": lambda d: d["matches"][0]["vulnerability"].update(id=""),
            "severity missing": lambda d: d["matches"][0]["vulnerability"].pop("severity"),
            "fix missing": lambda d: d["matches"][0]["vulnerability"].pop("fix"),
            "fix state unknown word": lambda d: d["matches"][0]["vulnerability"]["fix"].update(state="maybe"),
            "fix versions not strings": lambda d: d["matches"][0]["vulnerability"]["fix"].update(versions=[1]),
            "artifact missing": lambda d: d["matches"][0].pop("artifact"),
            "artifact purl missing": lambda d: d["matches"][0]["artifact"].pop("purl"),
            "artifact name empty": lambda d: d["matches"][0]["artifact"].update(name=""),
            "related id bad": lambda d: d["matches"][0].update(relatedVulnerabilities=[{"id": "a b"}]),
            "kev cve bad": lambda d: d["matches"][0]["vulnerability"].update(knownExploited=[{"cve": "nope"}]),
            "kev date bad": lambda d: d["matches"][0]["vulnerability"].update(knownExploited=[{"cve": "CVE-2021-44228", "dateAdded": "10 Dec"}]),
            "epss out of range": lambda d: d["matches"][0]["vulnerability"].update(epss=[{"cve": "CVE-2021-44228", "epss": 1.5, "percentile": 0.1, "date": "2026-10-14"}]),
            "epss not a list": lambda d: d["matches"][0]["vulnerability"].update(epss={"epss": 0.1}),
            "db not valid": lambda d: d["descriptor"]["db"]["status"].update(valid=False),
            "db built garbage": lambda d: d["descriptor"]["db"]["status"].update(built="yesterday"),
            "db schema path-like": lambda d: d["descriptor"]["db"]["status"].update(schemaVersion="v6/../x"),
        }
        for label, change in cases.items():
            with self.subTest(label), self.assertRaises(output.GrypeOutputError):
                parse(self.damaged(change))


class TestVulnerabilityFacts(unittest.TestCase):
    def test_a_ghsa_named_match_is_keyed_by_its_cve_with_the_ghsa_as_alias(self) -> None:
        """req-grype-vulnerability-1 and req-grype-corpus-1, on the real log4j recording."""
        doc = output.parse_document(recordings.text(recordings.LOG4J), expected_version=VERSION)
        vulns = facts.vulnerability_facts(doc)
        log4shell = vulns["CVE-2021-44228"]
        self.assertIn("GHSA-jfh8-c2jp-5v3q", log4shell.aliases)
        self.assertTrue(log4shell.kev.kev)
        self.assertEqual(log4shell.kev.date_added, date(2021, 12, 10))
        self.assertIsNotNone(log4shell.kev.due_date)
        self.assertTrue(log4shell.kev.required_action)
        self.assertEqual(log4shell.kev.ransomware_use, "known", "Grype carries the catalog value lowercased (observed)")
        self.assertEqual((log4shell.epss.score, log4shell.epss.percentile, log4shell.epss.on), (0.99999, 1.0, date(2026, 10, 14)))
        self.assertTrue(log4shell.record_url)

    def test_a_ghsa_with_no_cve_keeps_the_ghsa_as_its_key(self) -> None:
        doc = output.parse_document(recordings.text(recordings.TAP_WEB), expected_version=VERSION)
        vulns = facts.vulnerability_facts(doc)
        ghsa_keys = [k for k in vulns if k.startswith("GHSA-")]
        self.assertEqual(len(vulns), 27, "the spec's 27 vulnerabilities, as keys")
        self.assertEqual((len(ghsa_keys), len(vulns) - len(ghsa_keys)), (5, 22))
        rekeyed = {m.vuln_id: facts.vuln_key(m)[0] for m in doc.matches if m.vuln_id != facts.vuln_key(m)[0]}
        self.assertEqual(rekeyed, {"GHSA-hj66-6f7g-4r5v": "CVE-2026-49264", "GHSA-xpv3-w29h-x7cv": "CVE-2026-49265"})
        self.assertTrue(ghsa_keys, "the recording holds GHSA-keyed vulnerabilities with no CVE")
        for key in ghsa_keys:
            self.assertIsNone(vulns[key].epss, "EPSS is CVE-keyed, so a GHSA key has none")

    def test_kev_is_false_only_when_the_scan_reported_its_database(self) -> None:
        data = recordings.data(recordings.TAP_WEB)
        with_db = facts.vulnerability_facts(parse(data))
        self.assertTrue(all(v.kev.kev is False for v in with_db.values()))
        del data["descriptor"]["db"]
        without_db = facts.vulnerability_facts(parse(data))
        self.assertTrue(all(v.kev.kev is None for v in without_db.values()), "unread is null, never false")

    def test_an_absent_epss_is_none_never_zero(self) -> None:
        doc = output.parse_document(recordings.text(recordings.TAP_WEB), expected_version=VERSION)
        vulns = facts.vulnerability_facts(doc)
        absent = {facts.vuln_key(m)[0] for m in doc.matches if not m.epss}
        self.assertTrue(absent)
        for key in absent - {facts.vuln_key(m)[0] for m in doc.matches if m.epss}:
            self.assertIsNone(vulns[key].epss)

    def test_a_cve_named_match_keeps_its_own_id_even_when_other_cves_are_related(self) -> None:
        data = recordings.data(recordings.LOG4J)
        data["matches"] = data["matches"][:1]
        data["matches"][0]["vulnerability"]["id"] = "CVE-2024-0001"
        data["matches"][0]["relatedVulnerabilities"] = [{"id": "CVE-2024-0002"}, {"id": "GHSA-aaaa-bbbb-cccc"}]
        (match,) = parse(data).matches
        self.assertEqual(facts.vuln_key(match), ("CVE-2024-0001", ("CVE-2024-0002", "GHSA-aaaa-bbbb-cccc")))

    def test_an_epss_reading_for_a_different_cve_is_not_this_vulnerabilitys(self) -> None:
        data = recordings.data(recordings.LOG4J)
        for m in data["matches"]:
            for reading in m["vulnerability"].get("epss", []):
                reading["cve"] = "CVE-1999-0001"
        vulns = facts.vulnerability_facts(parse(data))
        self.assertTrue(all(v.epss is None for v in vulns.values()))

    def test_kev_entries_for_another_cve_do_not_make_a_vulnerability_known_exploited(self) -> None:
        data = recordings.data(recordings.LOG4J)
        for m in data["matches"]:
            for entry in m["vulnerability"].get("knownExploited", []):
                entry["cve"] = "CVE-1999-0001"
        vulns = facts.vulnerability_facts(parse(data))
        self.assertTrue(all(v.kev.kev is False for v in vulns.values()))


class TestFindingFacts(unittest.TestCase):
    def test_every_recorded_match_is_one_finding(self) -> None:
        doc = output.parse_document(recordings.text(recordings.TAP_WEB), expected_version=VERSION)
        self.assertEqual(len(facts.finding_facts(doc)), 91)

    def test_fixed_versions_are_a_list_when_fixed_and_none_when_unknown(self) -> None:
        doc = output.parse_document(recordings.text(recordings.TAP_WEB), expected_version=VERSION)
        by_state = {}
        for fact in facts.finding_facts(doc):
            by_state.setdefault(fact.fix_state, []).append(fact)
        self.assertTrue(all(f.fixed_versions for f in by_state["fixed"]))
        self.assertTrue(all(f.fixed_versions is None for f in by_state["unknown"]))

    def test_not_fixed_and_wont_fix_are_an_empty_list_not_unknown(self) -> None:
        for state in ("not-fixed", "wont-fix"):
            data = recordings.data(recordings.LOG4J)
            data["matches"] = data["matches"][:1]
            data["matches"][0]["vulnerability"]["fix"] = {"state": state, "versions": []}
            (fact,) = facts.finding_facts(parse(data))
            self.assertEqual(fact.fixed_versions, (), state)

    def test_several_matches_of_one_vulnerability_on_one_artifact_collapse(self) -> None:
        data = recordings.data(recordings.LOG4J)
        first = copy.deepcopy(data["matches"][0])
        second = copy.deepcopy(first)
        second["vulnerability"]["severity"] = "Critical"
        first["vulnerability"]["severity"] = "Low"
        data["matches"] = [first, second]
        (fact,) = facts.finding_facts(parse(data))
        self.assertEqual(fact.severity, "Critical")


if __name__ == "__main__":
    unittest.main()
