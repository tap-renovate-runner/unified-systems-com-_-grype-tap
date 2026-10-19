"""Mapping matches to targets, and running Grype over a document with a fake binary.

Stdlib ``unittest`` only; no Grype and no network. The fake runner plays Grype's ``sbom:<file> -o json=<file>``
by writing a recorded real document to the output path it is given, so the file handling, the size and
version checks and the controls on the invocation are exercised for real.
"""

import json
import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path

from tap_plugin.grype import output, scan, targets
from tap_plugin.grype.database import RunResult, grype_env
from tap_plugin.grype.tests import recordings

BINARY = Path("/opt/grype/bin/grype")
DB_DIR = Path("/opt/grype/db/6.1.10-20261015T063036Z")
VERSION = recordings.VERSION


class TestPurl(unittest.TestCase):
    def test_spellings_of_one_purl_are_equal_and_different_packages_are_not(self) -> None:
        a = "pkg:apk/wolfi/libcrypto3@3.6.4-r8?arch=aarch64&distro=wolfi-20230201&upstream=openssl"
        b = "pkg:apk/wolfi/libcrypto3@3.6.4-r8?upstream=openssl&distro=wolfi-20230201&arch=aarch64"
        c = "PKG:apk/wolfi/libcrypto3@3.6.4-r8?arch=aarch64&distro=wolfi-20230201&upstream=openssl"
        self.assertEqual(targets.canonical_purl(a), targets.canonical_purl(b))
        self.assertIsNotNone(targets.canonical_purl(a))
        self.assertIsNone(targets.canonical_purl(c), "not a pkg: purl")
        self.assertNotEqual(targets.canonical_purl(a), targets.canonical_purl(a.replace("r8", "r9")))
        self.assertNotEqual(targets.canonical_purl(a), targets.canonical_purl(a.replace("libcrypto3", "libssl3")))

    def test_a_malformed_purl_never_normalises_into_a_valid_one(self) -> None:
        valid = "pkg:apk/wolfi/name@1"
        self.assertIsNotNone(targets.canonical_purl(valid))
        for malformed in ("pkg:/apk/wolfi/name@1", "pkg:apk//wolfi/name@1", "pkg:apk/wolfi//name@1", "pkg:apk/wolfi/name/", "pkg://apk/wolfi/name@1"):
            with self.subTest(malformed):
                self.assertIsNone(targets.canonical_purl(malformed))
                self.assertNotEqual(targets.canonical_purl(malformed), targets.canonical_purl(valid))

    def test_purls_that_differ_only_in_subpath_are_different(self) -> None:
        one = targets.canonical_purl("pkg:generic/a@1#one")
        two = targets.canonical_purl("pkg:generic/a@1#two")
        self.assertIsNotNone(one)
        self.assertNotEqual(one, two)
        self.assertNotEqual(one, targets.canonical_purl("pkg:generic/a@1"))

    def test_malformed_parts_are_refused_not_repaired(self) -> None:
        valid = targets.canonical_purl("pkg:generic/a%25ZZ@1")
        self.assertIsNotNone(valid)
        for malformed in (
            "pkg:generic/a%ZZ@1",  # an invalid escape must not equal the valid encoded text above
            "pkg:generic/a@1?arch=x&bad",  # a qualifier with no =
            "pkg:generic/a@1?=x",  # an empty key
            "pkg:generic/a@1?arch=x&arch=y",  # a key given twice
            "pkg:generic/a@1?ar ch=x",  # an odd key
            "pkg:generic/a@1#x//y",  # an empty subpath segment
            "pkg:generic/a@1#x/../y",  # a dot segment
            "pkg:generic/a@1#/x",
            "pkg:generic/a@1#x#y",  # a second raw delimiter must not be absorbed by the encoder
            "pkg:generic/a@1?a=1?b=2",
            "pkg:generic/a@1@2",
            "pkg:generic/a@1?a=1#x?y",
            "pkg:generic/a@",  # an empty version
            "pkg:generic/a#x@y",  # a version marker after the subpath
            "pkg:generic/a%FF@1",  # an escape that is not valid UTF-8 is not replaced by U+FFFD
            "pkg:generic/a@1#%FF",
            "pkg:generic/a@1?arch=%FF",
            "pkg:generic/a@1?",  # a delimiter with nothing after it
            "pkg:generic/a@1#",
            "pkg:generic/a@1?#",
            "pkg:generic/a@1?arch=x#",
        ):
            with self.subTest(malformed):
                self.assertIsNone(targets.canonical_purl(malformed))
        self.assertNotEqual(targets.canonical_purl("pkg:generic/a%ZZ@1"), valid)
        self.assertEqual(
            targets.canonical_purl("pkg:generic/a@1?arch=x&empty="), targets.canonical_purl("pkg:generic/a@1?arch=x"),
            "an empty qualifier value carries no information and is left out, as the purl specification says",
        )

    def test_a_raw_delimiter_is_not_the_same_purl_as_its_encoded_spelling(self) -> None:
        for raw, encoded in (
            ("pkg:generic/a@1#x#y", "pkg:generic/a@1#x%23y"),
            ("pkg:generic/a@1?a=1?b=2", "pkg:generic/a@1?a=1%3Fb=2"),
            ("pkg:generic/a@1@2", "pkg:generic/a@1%402"),
        ):
            with self.subTest(raw):
                self.assertIsNotNone(targets.canonical_purl(encoded), "the encoded spelling is a valid purl")
                self.assertIsNone(targets.canonical_purl(raw))

    def test_a_string_that_cannot_be_encoded_is_refused_not_raised(self) -> None:
        for purl in ("pkg:generic/a" + chr(0xD800) + "@1", "pkg:generic/a@1#" + chr(0xDC00), "pkg:generic/a@1?k=" + chr(0xD800)):
            with self.subTest(repr(purl)):
                self.assertIsNone(targets.canonical_purl(purl))

    def test_percent_encoding_is_normalised_and_junk_is_none(self) -> None:
        plain = "pkg:generic/openssl-fips-provider@3.5.8?download_url=https://github.com/x/y.tar.gz"
        encoded = "pkg:generic/openssl-fips-provider@3.5.8?download_url=https%3A%2F%2Fgithub.com%2Fx%2Fy.tar.gz"
        self.assertEqual(targets.canonical_purl(plain), targets.canonical_purl(encoded))
        for junk in ("", "pkg:", "pkg:apk", "apk/x@1", "pkg:/@"):
            self.assertIsNone(targets.canonical_purl(junk), junk)
        self.assertEqual(targets.purl_type("pkg:PyPI/requests@2.0"), "pypi")


def real_targets(*, drop: str | None = None) -> list[targets.Target]:
    doc = output.parse_document(recordings.text(recordings.TAP_WEB), expected_version=VERSION)
    seen: dict[str, targets.Target] = {}
    for match in doc.matches:
        art = match.artifact
        ptype = targets.purl_type(art.purl) or ""
        kind = "library" if ptype == "generic" else "package"
        key = art.purl
        if key not in seen and art.name != drop:
            seen[key] = targets.Target(
                id=f"t{len(seen)}", kind=kind, name=art.name, version=art.version, ecosystem=None if kind == "library" else ptype, purl=art.purl
            )
    return list(seen.values())


class TestMapping(unittest.TestCase):
    def test_every_recorded_match_lands_on_exactly_one_target(self) -> None:
        doc = output.parse_document(recordings.text(recordings.TAP_WEB), expected_version=VERSION)
        mapping = targets.map_matches(doc.matches, real_targets())
        self.assertEqual(mapping.unmapped, [])
        self.assertEqual(sum(len(v) for v in mapping.mapped.values()), 91)

    def test_a_malformed_scanner_purl_is_unmapped_not_attached_to_a_real_target(self) -> None:
        doc = output.parse_document(recordings.text(recordings.TAP_WEB), expected_version=VERSION)
        real = real_targets()
        victim = next(t for t in real if t.kind == "package")
        match = next(m for m in doc.matches if m.artifact.purl == victim.purl)
        broken = match.__class__(**{**match.__dict__, "artifact": match.artifact.__class__(match.artifact.name, match.artifact.version, match.artifact.type, "pkg:/" + victim.purl[4:])})
        mapping = targets.map_matches([broken], real)
        self.assertEqual(mapping.mapped, {})
        self.assertEqual([r for _, r in mapping.unmapped], [targets.NO_TARGET])

    def test_a_match_with_no_target_is_counted_not_dropped(self) -> None:
        doc = output.parse_document(recordings.text(recordings.TAP_WEB), expected_version=VERSION)
        mapping = targets.map_matches(doc.matches, real_targets(drop="libcrypto3"))
        self.assertTrue(mapping.unmapped)
        self.assertTrue(all(reason == targets.NO_TARGET for _, reason in mapping.unmapped))
        self.assertEqual(sum(len(v) for v in mapping.mapped.values()) + len(mapping.unmapped), 91)

    def test_the_natural_key_tier_catches_a_purl_spelled_differently(self) -> None:
        doc = output.parse_document(recordings.text(recordings.TAP_WEB), expected_version=VERSION)
        packages = [t for t in real_targets() if t.kind == "package"]
        # Same package, purl spelled so it cannot equal Grype's: only (type, name, version) can still find it.
        respelled = [targets.Target(t.id, t.kind, t.name, t.version, t.ecosystem, f"pkg:{t.ecosystem}/x/{t.name}@{t.version}") for t in packages]
        libraries = [t for t in real_targets() if t.kind == "library"]
        mapping = targets.map_matches(doc.matches, respelled + libraries)
        self.assertEqual(mapping.unmapped, [])
        package_matches = [m for m in doc.matches if targets.purl_type(m.artifact.purl) != "generic"]
        self.assertEqual(sum(len(mapping.mapped.get(t.id, [])) for t in packages), len(package_matches))

    def test_two_candidates_are_ambiguous_and_never_guessed(self) -> None:
        doc = output.parse_document(recordings.text(recordings.TAP_WEB), expected_version=VERSION)
        match = doc.matches[0]
        one = targets.Target("a", "package", match.artifact.name, match.artifact.version, "apk", match.artifact.purl)
        two = targets.Target("b", "package", match.artifact.name, match.artifact.version, "apk", match.artifact.purl)
        mapping = targets.map_matches([match], [one, two])
        self.assertEqual(mapping.mapped, {})
        self.assertEqual([r for _, r in mapping.unmapped], [targets.AMBIGUOUS])


class FakeGrype:
    """Writes a recorded document where the real binary would, and records how it was called."""

    def __init__(self, document: str | None, returncode: int = 0, stderr: str = "") -> None:
        self.document, self.returncode, self.stderr = document, returncode, stderr
        self.calls: list[tuple[list[str], dict[str, str]]] = []

    def __call__(self, argv, env) -> RunResult:
        self.calls.append((list(argv), dict(env)))
        out = next(a for a in argv if a.startswith("json=")).removeprefix("json=")
        if self.document is not None:
            Path(out).write_text(self.document, encoding="utf-8")
        return RunResult(self.returncode, "", self.stderr)


class TestScratch(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.home = Path(self._tmp.name)

    def test_the_directory_is_per_run_private_and_removed_even_on_failure(self) -> None:
        with scan.scratch_dir(self.home, "run-0000000a") as one, scan.scratch_dir(self.home, "run-0000000b") as two:
            self.assertNotEqual(one, two)
            self.assertEqual(stat.S_IMODE(one.stat().st_mode), 0o700)
            (one / "x").write_text("x")
        self.assertEqual(list((self.home / "scratch").iterdir()), [])
        with self.assertRaises(RuntimeError), scan.scratch_dir(self.home, "run-0000000c") as three:
            (three / "left-behind").write_text("x")
            raise RuntimeError("the run failed")
        self.assertEqual(list((self.home / "scratch").iterdir()), [])

    def test_a_directory_the_caller_already_removed_is_not_a_cleanup_failure(self) -> None:
        with scan.scratch_dir(self.home, "run-00000010") as path:
            shutil.rmtree(path)
        with self.assertRaises(RuntimeError) as caught, scan.scratch_dir(self.home, "run-00000011") as path:
            shutil.rmtree(path)
            raise RuntimeError("the run failed")
        self.assertEqual(getattr(caught.exception, "__notes__", []), [])

    def test_a_cleanup_failure_is_reported_never_swallowed(self) -> None:
        original = scan.shutil.rmtree

        def failing(path, *args, **kwargs):
            raise PermissionError("read-only volume")

        scan.shutil.rmtree = failing
        try:
            with self.assertRaises(scan.ScanError), scan.scratch_dir(self.home, "run-0000000e"):
                pass
            with self.assertRaises(RuntimeError) as caught, scan.scratch_dir(self.home, "run-0000000f"):
                raise RuntimeError("the run failed")
        finally:
            scan.shutil.rmtree = original
        self.assertEqual(str(caught.exception), "the run failed", "the real error is not masked")
        self.assertTrue(any("was not removed" in note for note in caught.exception.__notes__))

    def test_a_run_id_cannot_name_another_directory_and_a_collision_is_refused(self) -> None:
        for bad in ("../escape", "a/b", "", "short", "run id with spaces", "..", "x" * 80):
            with self.subTest(bad), self.assertRaises(scan.ScanError), scan.scratch_dir(self.home, bad):
                pass
        with scan.scratch_dir(self.home, "run-0000000d"), self.assertRaises(FileExistsError), scan.scratch_dir(self.home, "run-0000000d"):
            pass


class TestScanDocument(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.scratch = Path(self._tmp.name)
        self.good = recordings.text(recordings.LOG4J)

    def scan(self, fake: FakeGrype, **kwargs):
        return scan.scan_document(BINARY, DB_DIR, b'{"bomFormat":"CycloneDX"}', self.scratch, expected_version=VERSION, run=fake, **kwargs)

    def test_a_good_run_returns_the_parsed_document(self) -> None:
        document = self.scan(FakeGrype(self.good))
        self.assertEqual(len(document.matches), 21)

    def test_the_invocation_has_the_controls_the_spec_names(self) -> None:
        os.environ["AWS_SECRET_ACCESS_KEY"] = "must-not-leak"
        self.addCleanup(os.environ.pop, "AWS_SECRET_ACCESS_KEY", None)
        fake = FakeGrype(self.good)
        self.scan(fake, index=3)
        (argv, env), = fake.calls
        self.assertIsInstance(argv, list)
        self.assertEqual(argv[0], str(BINARY))
        self.assertEqual(argv[1:3], [f"sbom:{self.scratch / 'doc-3.cdx.json'}", "-o"])
        self.assertEqual(argv[3], f"json={self.scratch / 'out-3.json'}")
        self.assertEqual(env, grype_env(DB_DIR, auto_update=False))
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)
        self.assertEqual(env["GRYPE_DB_AUTO_UPDATE"], "false")
        self.assertEqual(env["GRYPE_CHECK_FOR_APP_UPDATE"], "false")
        self.assertEqual(env["GRYPE_DB_CACHE_DIR"], str(DB_DIR))
        self.assertEqual(stat.S_IMODE((self.scratch / "doc-3.cdx.json").stat().st_mode), 0o600)

    def test_each_failure_is_one_scan_error(self) -> None:
        big = scan.MAX_SBOM_BYTES + 1
        cases = {
            "non-zero exit": FakeGrype(self.good, returncode=2, stderr="boom"),
            "no output file": FakeGrype(None),
            "garbage output": FakeGrype("not json at all"),
            "truncated output": FakeGrype(self.good[: len(self.good) // 2]),
            "wrong version": FakeGrype(json.dumps(json.loads(self.good) | {"descriptor": {"name": "grype", "version": "0.1.0"}})),
        }
        for number, (label, fake) in enumerate(cases.items()):
            with self.subTest(label), self.assertRaises(scan.ScanError):
                self.scan(fake, index=number)  # a fixed index per case: string hashes are randomised per process
        with self.assertRaises(scan.ScanError):
            scan.scan_document(BINARY, DB_DIR, b"x" * big, self.scratch, expected_version=VERSION, run=FakeGrype(self.good))

    def test_oversized_output_is_refused_before_it_is_read(self) -> None:
        original = scan.MAX_DOCUMENT_BYTES
        scan.MAX_DOCUMENT_BYTES = 10
        try:
            with self.assertRaises(scan.ScanError):
                self.scan(FakeGrype(self.good), index=77)
        finally:
            scan.MAX_DOCUMENT_BYTES = original

    def test_an_unrunnable_binary_is_a_scan_error(self) -> None:
        def missing(argv, env):
            raise FileNotFoundError("no such binary")

        with self.assertRaises(scan.ScanError):
            self.scan(missing, index=5)


if __name__ == "__main__":
    unittest.main()
