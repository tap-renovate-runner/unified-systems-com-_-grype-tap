"""The Grype database: status parsing, the age rule, the lock, the mirror and the atomic refresh.

Plain ``unittest`` and stdlib only; no Grype, no network. A ``FakeGrype`` plays the binary's three
commands (``db update``, ``db import``, ``db status -o json``) over a real directory, so the swap, prune
and rollback logic runs against real files. The two JSON status fixtures are copied from a real Grype
v0.120.1 run (2026-10-15).
"""

import hashlib
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from tap_plugin.grype import database, mirror
from tap_plugin.grype.database import Busy, DatabaseError, RunResult
from tap_plugin.grype.settings import Settings

OBSERVED_VALID = """{
 "schemaVersion": "v6.1.10",
 "from": "https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.10_2026-10-15T00:29:08Z_1792045836.tar.zst?checksum=sha256%3A2f1597f2",
 "built": "2026-10-15T06:30:36Z",
 "path": "/cache/6/vulnerability.db",
 "valid": true
}"""
OBSERVED_EMPTY = """{
 "schemaVersion": "",
 "path": "/cache/6/vulnerability.db",
 "valid": false,
 "error": "database does not exist"
}"""
NOW = datetime(2026, 10, 16, 12, 0, 0, tzinfo=UTC)
BINARY = Path("/opt/grype/bin/grype")


def stamp(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeGrype:
    """Plays ``grype db update|import|status`` over real directories."""

    def __init__(self, build: datetime, *, fail: str | None = None, status_text: str | None = None) -> None:
        self.build = build
        self.fail = fail
        self.status_text = status_text
        self.calls: list[list[str]] = []

    def __call__(self, argv, env) -> RunResult:
        argv = list(argv)
        self.calls.append(argv)
        cache = Path(env["GRYPE_DB_CACHE_DIR"])
        verb = argv[2]
        if verb in ("update", "import"):
            if self.fail == verb:
                return RunResult(1, "", f"{verb} failed")
            (cache / "6").mkdir(parents=True, exist_ok=True)
            (cache / "6" / "vulnerability.db").write_text(stamp(self.build), encoding="utf-8")
            return RunResult(0, "", "")
        if verb == "status":
            if self.status_text is not None and self.fail == "status":
                return RunResult(0, self.status_text, "")
            db = cache / "6" / "vulnerability.db"
            if not db.exists():
                return RunResult(1, OBSERVED_EMPTY, "database does not exist")
            built = db.read_text(encoding="utf-8")
            return RunResult(0, json.dumps({"schemaVersion": "v6.1.10", "from": "x", "built": built, "path": str(db), "valid": True}), "")
        raise AssertionError(f"unexpected grype call {argv}")


class TempHome(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.home = self.root / "home"

    def refresh(self, build: datetime, settings: Settings | None = None, **kwargs):
        fake = FakeGrype(build, **kwargs)
        result = database.refresh(self.home, settings or Settings(), BINARY, now=lambda: NOW, run=fake)
        return result, fake

    def builds(self) -> list[str]:
        return sorted(
            p.name for p in (self.home / "db").iterdir() if p.is_dir() and not p.is_symlink() and not p.name.startswith(".")
        )

    def current_build(self) -> str:
        return os.readlink(self.home / "db" / "current")


class TestStatus(unittest.TestCase):
    def test_the_observed_valid_status_parses(self) -> None:
        status = database.parse_status(OBSERVED_VALID)
        assert status is not None
        self.assertEqual(status.schema_version, "v6.1.10")
        self.assertEqual(status.built, datetime(2026, 10, 15, 6, 30, 36, tzinfo=UTC))
        self.assertEqual(status.data_version, "v6.1.10@2026-10-15T06:30:36Z")
        self.assertEqual(status.build_id, "6.1.10-20261015T063036Z")

    def test_the_observed_empty_cache_is_no_database_not_an_error(self) -> None:
        self.assertIsNone(database.parse_status(OBSERVED_EMPTY))

    def test_anything_else_is_refused_not_read_as_healthy(self) -> None:
        for label, text in {
            "not json": "Vulnerability database...",
            "not an object": "[]",
            "unknown key": json.dumps({"schemaVersion": "v6", "path": "p", "valid": False, "surprise": 1}),
            "missing valid": json.dumps({"schemaVersion": "v6", "path": "p"}),
            "valid is a string": json.dumps({"schemaVersion": "v6", "path": "p", "valid": "yes"}),
            "valid with no built": json.dumps({"schemaVersion": "v6.1.10", "path": "p", "valid": True}),
            "valid with a bad built": json.dumps({"schemaVersion": "v6.1.10", "path": "p", "valid": True, "built": "yesterday"}),
            "valid with a bad schema": json.dumps({"schemaVersion": "6", "path": "p", "valid": True, "built": "2026-10-15T06:30:36Z"}),
        }.items():
            with self.subTest(label), self.assertRaises(DatabaseError):
                database.parse_status(text)


class TestAgeRule(unittest.TestCase):
    def status(self, age: timedelta):
        return database.DbStatus("v6.1.10", NOW - age, None)

    def test_the_rule(self) -> None:
        self.assertEqual(database.age_outcome(self.status(timedelta(hours=5)), NOW, 3), database.OK)
        self.assertEqual(database.age_outcome(self.status(timedelta(days=3)), NOW, 3), database.OK, "exactly at the limit is ok")
        self.assertEqual(database.age_outcome(self.status(timedelta(days=3, seconds=1)), NOW, 3), database.STALE)
        self.assertEqual(database.age_outcome(None, NOW, 3), database.UNAVAILABLE)

    def test_age_is_the_build_time_not_the_install_time(self) -> None:
        # A build Anchore made five days ago, installed a minute ago, is still stale.
        self.assertEqual(database.age_outcome(self.status(timedelta(days=5)), NOW, 3), database.STALE)


class TestRefresh(TempHome):
    def test_a_first_install_stages_validates_and_swaps_in(self) -> None:
        build = NOW - timedelta(hours=6)
        result, fake = self.refresh(build)
        self.assertEqual(result.outcome, "installed")
        self.assertEqual(self.current_build(), "6.1.10-20261016T060000Z")
        self.assertEqual(self.builds(), ["6.1.10-20261016T060000Z"])
        self.assertTrue((self.home / "db" / "current" / "6" / "vulnerability.db").is_file())
        self.assertEqual(fake.calls[0][2], "update")
        self.assertEqual([p.name for p in (self.home / "db").iterdir() if p.name.startswith(".staging")], [])

    def test_a_newer_build_replaces_current_and_the_two_newest_are_kept(self) -> None:
        for hours in (72, 48, 24):
            self.refresh(NOW - timedelta(hours=hours))
        self.assertEqual(self.builds(), ["6.1.10-20261014T120000Z", "6.1.10-20261015T120000Z"])
        self.assertEqual(self.current_build(), "6.1.10-20261015T120000Z")

    def test_the_same_build_leaves_the_installed_one_current(self) -> None:
        self.refresh(NOW - timedelta(hours=6))
        result, _ = self.refresh(NOW - timedelta(hours=6))
        self.assertEqual(result.outcome, "current")
        self.assertEqual(len(self.builds()), 1)

    def test_an_older_build_is_refused_as_a_rollback(self) -> None:
        self.refresh(NOW - timedelta(hours=6))
        with self.assertRaises(DatabaseError):
            self.refresh(NOW - timedelta(hours=30))
        self.assertEqual(self.current_build(), "6.1.10-20261016T060000Z")

    def test_a_build_stamped_in_the_future_is_refused(self) -> None:
        with self.assertRaises(DatabaseError):
            self.refresh(NOW + timedelta(days=1))
        self.assertFalse((self.home / "db" / "current").exists())

    def test_a_failure_at_any_step_leaves_the_installed_database_serving(self) -> None:
        self.refresh(NOW - timedelta(hours=48))
        before = self.current_build()
        for fail in ("update", "status"):
            with self.subTest(fail), self.assertRaises(DatabaseError):
                self.refresh(NOW - timedelta(hours=6), fail=fail, status_text="not json" if fail == "status" else None)
            self.assertEqual(self.current_build(), before)
            self.assertEqual(self.builds(), [before])
            self.assertEqual([p.name for p in (self.home / "db").iterdir() if p.name.startswith(".staging")], [])

    def test_a_refresh_that_does_not_validate_is_refused(self) -> None:
        class NoDb(FakeGrype):
            def __call__(self, argv, env):
                if list(argv)[2] == "update":
                    return RunResult(0, "", "")  # succeeds but writes nothing
                return super().__call__(argv, env)

        with self.assertRaises(DatabaseError):
            database.refresh(self.home, Settings(), BINARY, now=lambda: NOW, run=NoDb(NOW))
        self.assertFalse((self.home / "db" / "current").exists())


class TestLock(TempHome):
    def test_a_scan_blocks_a_refresh_and_a_refresh_blocks_a_scan(self) -> None:
        with database.lock(self.home, exclusive=False), self.assertRaises(Busy):
            self.refresh(NOW - timedelta(hours=6))
        with database.lock(self.home, exclusive=True), self.assertRaises(Busy), database.lock(self.home, exclusive=False):
            pass

    def test_two_scans_may_overlap(self) -> None:
        with database.lock(self.home, exclusive=False), database.lock(self.home, exclusive=False):
            pass

    def test_a_scan_keeps_the_build_it_resolved_across_a_swap(self) -> None:
        self.refresh(NOW - timedelta(hours=48))
        resolved = database.resolve_current(self.home)
        with database.lock(self.home, exclusive=False):
            pass  # the scan finished; a refresh may now swap
        self.refresh(NOW - timedelta(hours=6))
        self.assertTrue(resolved.is_dir(), "the older build is kept, so a path resolved earlier is not pulled away")
        self.assertNotEqual(database.resolve_current(self.home), resolved)

    def test_no_database_installed_is_an_error_not_a_guess(self) -> None:
        with self.assertRaises(DatabaseError):
            database.resolve_current(self.home)


class TestMirror(TempHome):
    def make_mirror(self, name: str, payload: bytes, built: datetime, *, digest: str | None = None) -> Path:
        directory = self.root / "mirror"
        directory.mkdir(exist_ok=True)
        (directory / name).write_bytes(payload)
        manifest = {"archive": name, "sha256": digest or hashlib.sha256(payload).hexdigest(), "built": stamp(built)}
        (directory / f"{name}.manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        return directory

    def test_the_newest_by_manifest_is_chosen_not_by_modification_time(self) -> None:
        directory = self.make_mirror("old.tar.zst", b"old", NOW - timedelta(days=2))
        self.make_mirror("new.tar.zst", b"new", NOW - timedelta(hours=3))
        os.utime(directory / "new.tar.zst", (1, 1))  # make the genuinely newer file look ancient
        self.assertEqual(mirror.select_archive(directory, now=NOW).path.name, "new.tar.zst")

    def test_each_defect_is_refused(self) -> None:
        cases = {
            "digest differs": lambda: self.make_mirror("a.tar.zst", b"data", NOW - timedelta(hours=1), digest="0" * 64),
            "built in the future": lambda: self.make_mirror("a.tar.zst", b"data", NOW + timedelta(days=1)),
            "no manifests": lambda: (self.root / "mirror").mkdir(),
        }
        for label, build in cases.items():
            with self.subTest(label):
                import shutil

                shutil.rmtree(self.root / "mirror", ignore_errors=True)
                build()
                with self.assertRaises(mirror.MirrorError):
                    mirror.select_archive(self.root / "mirror", now=NOW)

    def test_a_symlinked_archive_and_a_malformed_manifest_are_refused(self) -> None:
        directory = self.make_mirror("real.tar.zst", b"data", NOW - timedelta(hours=1))
        (directory / "real.tar.zst").rename(directory / "elsewhere.bin")
        (directory / "real.tar.zst").symlink_to("elsewhere.bin")
        with self.assertRaises(mirror.MirrorError):
            mirror.select_archive(directory, now=NOW)
        for bad in (
            {"archive": "../x.tar.zst", "sha256": "0" * 64, "built": stamp(NOW)},
            {"archive": "x.tar.zst", "sha256": "abc", "built": stamp(NOW)},
            {"archive": "x.tar.zst", "sha256": "0" * 64, "built": "yesterday"},
            {"archive": "x.tar.zst", "sha256": "0" * 64, "built": stamp(NOW), "extra": 1},
        ):
            with self.subTest(bad):
                folder = self.root / f"m{abs(hash(str(bad)))}"
                folder.mkdir()
                (folder / "x.tar.zst.manifest.json").write_text(json.dumps(bad), encoding="utf-8")
                with self.assertRaises(mirror.MirrorError):
                    mirror.select_archive(folder, now=NOW)

    def test_a_mirror_refresh_imports_and_never_runs_an_update(self) -> None:
        directory = self.make_mirror("db.tar.zst", b"archive", NOW - timedelta(hours=6))
        result, fake = self.refresh(NOW - timedelta(hours=6), Settings(database_mirror=str(directory)))
        self.assertEqual(result.outcome, "installed")
        verbs = [call[2] for call in fake.calls]
        self.assertIn("import", verbs)
        self.assertNotIn("update", verbs)
        self.assertEqual(fake.calls[0][3], str(directory / "db.tar.zst"))

    def test_a_tampered_mirror_archive_is_refused_and_the_installed_database_stays(self) -> None:
        self.refresh(NOW - timedelta(hours=48))
        before = self.current_build()
        directory = self.make_mirror("db.tar.zst", b"archive", NOW - timedelta(hours=6), digest="1" * 64)
        with self.assertRaises(DatabaseError):
            self.refresh(NOW - timedelta(hours=6), Settings(database_mirror=str(directory)))
        self.assertEqual(self.current_build(), before)

    def test_a_mirror_older_than_the_installed_database_is_refused_as_a_rollback(self) -> None:
        self.refresh(NOW - timedelta(hours=6))
        directory = self.make_mirror("db.tar.zst", b"archive", NOW - timedelta(days=2))
        with self.assertRaises(DatabaseError):
            self.refresh(NOW - timedelta(days=2), Settings(database_mirror=str(directory)))


if __name__ == "__main__":
    unittest.main()
