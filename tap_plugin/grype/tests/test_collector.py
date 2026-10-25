"""The scan collector, run for real through ``run_collection`` against a database (req-grype-collector, req-grype-run).

pytest with the grid's database, so it runs in a TAP stack and not on a bare host. The collector class is the registered
one (``grype:grype``), run as the collector role by the same ``run_collection`` a schedule uses; the only thing replaced
is the Grype binary, by a fake that answers its three commands (``--version``, ``db status``, ``sbom:`` scan) and writes
a real recorded Grype output for a scan. So what is proved is the orchestration end to end: the guards, the read, the
scan, the plan, the write through GRIFT as the collector role, and what the grid then holds.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import tap_plugin.compliance_core.models  # noqa: F401 - trigger model registration
import tap_plugin.computing_core.models  # noqa: F401

from tap_cares.collectors.base import CollectorBase
from tap_cares.models import CollectionJob, CollectionJobStatus, Collector
from tap_cares.registry import reconcile_collector_nodes
from tap_cares.services import run_collection
from tap_grid.grift import grift_import
from tap_grid.models import Edge, Entity
from tap_grid.registry import get_model_class
from tap_plugin.grype import database, document, reader
from tap_plugin.grype.collectors import grype_collector as mod
from tap_plugin.grype.database import RunResult
from tap_plugin.grype.home import HOME_ENV
from tap_plugin.grype.tests import recordings
from tap_plugin.grype.tests.test_plan import parsed
from tap_plugin.grype.tests.test_reader import make, package

PACKAGE_DIR = Path(mod.__file__).parent.parent
VERSION = recordings.VERSION


def stamp(when: datetime) -> str:
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


class FakeGrype:
    """Plays ``grype --version``, ``db status -o json`` and ``sbom:<file> -o json=<out>``."""

    def __init__(self, recording: str, *, built: datetime | None = None, version: str = VERSION, scan_exit: int = 0) -> None:
        self.recording = recording
        self.built = built or datetime.now(UTC) - timedelta(hours=6)
        self.version = version
        self.scan_exit = scan_exit
        self.calls: list[list[str]] = []

    def scans(self) -> list[list[str]]:
        return [call for call in self.calls if call[1].startswith("sbom:")]

    def __call__(self, argv: Any, env: Any) -> RunResult:
        argv = list(argv)
        self.calls.append(argv)
        if argv[1:] == ["--version"]:
            return RunResult(0, f"grype {self.version}\n", "")
        if argv[1:3] == ["db", "status"]:
            body = {"schemaVersion": "v6.1.10", "from": "https://grype.anchore.io/x", "built": stamp(self.built), "path": "/c/6/vulnerability.db", "valid": True}
            return RunResult(0, json.dumps(body), "")
        if argv[1].startswith("sbom:"):
            if self.scan_exit:
                return RunResult(self.scan_exit, "", "boom")
            Path(argv[3].removeprefix("json=")).write_text(self.recording, encoding="utf-8")
            return RunResult(0, "", "")
        raise AssertionError(f"unexpected command {argv}")


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    path = tmp_path / "grype"
    (path / "db" / "build-1").mkdir(parents=True)
    database.repoint(path / "db" / "current", "build-1")
    monkeypatch.setenv(HOME_ENV, str(path))
    return path


def use(monkeypatch: pytest.MonkeyPatch, fake: FakeGrype) -> FakeGrype:
    monkeypatch.setattr(mod.GrypeCollector, "runner", staticmethod(fake))
    return fake


def seed_scanner() -> None:
    seeded = grift_import(json.loads((PACKAGE_DIR / "grift" / "scanner.grift.json").read_text(encoding="utf-8")))
    assert seeded.success, seeded.errors


def seed_packages(recording: str) -> dict[str, Entity]:
    seen: dict[str, Entity] = {}
    for match in parsed(recording).matches:
        art = match.artifact
        if art.purl not in seen:
            seen[art.purl] = package(art.name, art.version, art.purl[4:].split("/", 1)[0], art.purl)
    return seen


def collect() -> CollectionJob:
    reconcile_collector_nodes()
    job = run_collection(Collector.objects.get(collector_registry="grype:grype"))
    job.refresh_from_db()
    return job


def codes(job: CollectionJob, level: str) -> list[str]:
    return [entry["message_code"] for entry in job.results[level]]


def runs() -> Any:
    return get_model_class(document.RUN).objects.filter(source="grype").order_by("observed_at")


def findings() -> Any:
    return get_model_class(document.FINDING).objects.filter(source="grype")


@pytest.mark.django_db(transaction=True)
class TestAFullRun:
    @pytest.fixture(autouse=True)
    def _grid(self, home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.recording = recordings.text(recordings.LOG4J)
        seed_scanner()
        self.packages = seed_packages(recordings.LOG4J)
        self.fake = use(monkeypatch, FakeGrype(self.recording))
        self.home = home

    def test_it_lands_the_run_findings_and_one_coverage_edge_per_target_and_the_job_succeeds(self) -> None:
        job = collect()
        assert job.status == CollectionJobStatus.SUCCESSFUL.value, (job.summary, job.results["error"])
        (run,) = runs()
        assert (run.outcome, run.tool_version, run.category) == ("ok", VERSION, "grype-grid")
        assert run.data_version and run.data_built_at and run.results_count == len(parsed(recordings.LOG4J).matches)
        assert findings().count() > 0 and all(f.status == "open" for f in findings())
        for entity in self.packages.values():
            coverage = Edge.objects.filter(edge_type=document.SCANNED, to_entity_id=entity.id)
            assert coverage.count() == 1  # exactly one, to this run
            assert str(coverage.get().from_entity_id) == str(run.entity_id)
        assert codes(job, "info") == ["RUN_STARTED", "RUN_FINISHED"] and job.summary.startswith("Run ok:")

    def test_the_scan_never_fetches_and_runs_with_the_installed_database_and_leaves_no_scratch(self) -> None:
        collect()
        (scan,) = self.fake.scans()
        assert scan[0] == str(self.home / "bin" / "grype") and scan[2] == "-o" and scan[3].startswith("json=")
        assert not list((self.home / "scratch").iterdir())  # removed on exit

    def test_a_second_run_over_the_unchanged_grid_adds_a_run_but_no_finding(self) -> None:
        collect()
        before = set(findings().values_list("entity_id", flat=True))
        job = collect()
        assert job.status == CollectionJobStatus.SUCCESSFUL.value, job.summary
        assert runs().count() == 2 and set(findings().values_list("entity_id", flat=True)) == before
        for entity in self.packages.values():
            assert Edge.objects.filter(edge_type=document.SCANNED, to_entity_id=entity.id).count() == 2  # one per run: history, not replacement
        for finding in findings():
            assert Edge.objects.filter(edge_type=document.REPORTS, to_entity_id=finding.entity_id).count() == 1  # the run that opened it

    def test_a_finding_that_stops_matching_is_resolved_and_one_that_returns_is_reopened(self, monkeypatch: pytest.MonkeyPatch) -> None:
        collect()
        use(monkeypatch, FakeGrype(json.dumps({**json.loads(self.recording), "matches": []})))
        collect()
        assert findings().count() > 0 and all(f.status == "resolved" for f in findings())
        use(monkeypatch, FakeGrype(self.recording))
        collect()
        assert all(f.status == "open" for f in findings())

    def test_a_document_that_fails_fails_the_run_and_writes_no_finding_but_the_run_exists(self, monkeypatch: pytest.MonkeyPatch) -> None:
        use(monkeypatch, FakeGrype(self.recording, scan_exit=2))
        job = collect()
        assert job.status == CollectionJobStatus.FAILED.value
        (run,) = runs()
        assert run.outcome == "failed" and findings().count() == 0
        assert "DOCUMENT_FAILED" in codes(job, "warn")
        for entity in self.packages.values():
            (edge,) = Edge.objects.filter(edge_type=document.SCANNED, to_entity_id=entity.id)
            assert edge.properties["outcome"] == "not-scanned" and edge.properties["reason"] == "document-failed"


@pytest.mark.django_db(transaction=True)
class TestGuards:
    @pytest.fixture(autouse=True)
    def _grid(self, home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.recording = recordings.text(recordings.LOG4J)
        seed_scanner()
        self.packages = seed_packages(recordings.LOG4J)
        self.fake = use(monkeypatch, FakeGrype(self.recording))
        self.home = home

    def test_a_binary_that_is_not_the_pinned_version_stops_before_any_scan_and_writes_no_run(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = use(monkeypatch, FakeGrype(self.recording, version="0.0.1"))
        job = collect()
        assert job.status == CollectionJobStatus.FAILED.value and "BINARY_VERSION_MISMATCH" in json.dumps(job.self_test)  # the readiness phase stops it
        assert fake.scans() == [] and runs().count() == 0 and findings().count() == 0

    def test_the_in_run_version_gate_holds_if_the_binary_changes_after_the_readiness_phase(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(mod.GrypeCollector, "self_test", classmethod(lambda cls: mod.CollectorSelfTestResult.from_checks([mod.check_pass("X", "ok")], summary="x")))
        fake = use(monkeypatch, FakeGrype(self.recording, version="0.0.1"))
        job = collect()
        assert job.status == CollectionJobStatus.FAILED.value and codes(job, "error") == ["BINARY_VERSION_MISMATCH"]
        assert "0.0.1" in job.summary and VERSION in job.summary
        assert fake.scans() == [] and runs().count() == 0 and findings().count() == 0

    def test_a_stale_database_writes_a_db_stale_run_moves_no_finding_and_fails_the_job(self, monkeypatch: pytest.MonkeyPatch) -> None:
        collect()  # a good run first, so there is something a stale run must not touch
        opened = {str(f.entity_id): (f.status, Entity.objects.get(pk=f.entity_id).version) for f in findings()}
        use(monkeypatch, FakeGrype(self.recording, built=datetime.now(UTC) - timedelta(days=9)))
        job = collect()
        assert job.status == CollectionJobStatus.FAILED.value and "db-stale" in job.summary
        latest = runs().last()
        assert latest.outcome == "db-stale" and runs().count() == 2
        assert {str(f.entity_id): (f.status, Entity.objects.get(pk=f.entity_id).version) for f in findings()} == opened
        for entity in self.packages.values():  # the earlier coverage stands and ages
            (edge,) = Edge.objects.filter(edge_type=document.SCANNED, to_entity_id=entity.id)
            assert str(edge.from_entity_id) != str(latest.entity_id) and edge.properties["outcome"] == "scanned"

    def test_a_missing_database_writes_a_db_unavailable_run(self, monkeypatch: pytest.MonkeyPatch) -> None:
        (self.home / "db" / "current").unlink()
        job = collect()
        assert job.status == CollectionJobStatus.FAILED.value
        (run,) = runs()
        assert run.outcome == "db-unavailable" and findings().count() == 0

    def test_a_missing_scanner_node_stops_before_any_scan_and_writes_no_run(self) -> None:
        get_model_class("compliance_core__compliance_scanner").objects.all().delete()
        job = collect()
        assert job.status == CollectionJobStatus.FAILED.value and "SCANNER_MISSING" in json.dumps(job.self_test)
        assert runs().count() == 0 and self.fake.scans() == []

    def test_a_stale_or_missing_database_is_a_readiness_warning_not_a_block(self, monkeypatch: pytest.MonkeyPatch) -> None:
        use(monkeypatch, FakeGrype(self.recording, built=datetime.now(UTC) - timedelta(days=9)))
        checks = {c.code: c for c in mod.GrypeCollector.self_test().checks}
        assert checks["DATABASE_DB_STALE"].status.value == "warn" and not checks["DATABASE_DB_STALE"].is_failure

    def test_a_refresh_holding_the_database_stops_the_scan(self) -> None:
        with database.lock(self.home, exclusive=True):
            job = collect()
        assert job.status == CollectionJobStatus.FAILED.value and codes(job, "error") == ["REFRESH_RUNNING"]
        assert runs().count() == 0

    def test_another_running_collection_job_skips_the_fire_and_writes_nothing(self) -> None:
        other = CollectionJob.objects.create(name="other", description="x", status=CollectionJobStatus.RUNNING.value)
        job = collect()
        assert job.status == CollectionJobStatus.SUCCESSFUL.value and job.summary.startswith("Skipped:")
        assert str(other.entity_id) in job.summary and "SKIPPED_OTHER_JOB_RUNNING" in codes(job, "warn")
        assert self.fake.scans() == [] and runs().count() == 0

    def test_the_job_itself_is_not_the_other_job(self) -> None:
        job = CollectionJob.objects.create(name="me", description="x", status=CollectionJobStatus.RUNNING.value)
        assert mod.other_running_job(job.entity_id) is None


@pytest.mark.django_db(transaction=True)
class TestTheGridMoving:
    @pytest.fixture(autouse=True)
    def _grid(self, home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        self.recording = recordings.text(recordings.LOG4J)
        seed_scanner()
        self.packages = seed_packages(recordings.LOG4J)
        self.fake = use(monkeypatch, FakeGrype(self.recording))

    def refuse(self, monkeypatch: pytest.MonkeyPatch, code: str, times: int) -> list[int]:
        """Make the first ``times`` submissions come back refused with ``code``; later ones go through."""
        real = CollectorBase.submit_grift
        attempts: list[int] = []

        def submit(self: Any, doc: Any, **kwargs: Any) -> Any:
            attempts.append(1)
            if len(attempts) <= times:
                return SimpleNamespace(errors=[SimpleNamespace(code=code, message=f"{code} (test)")])
            return real(self, doc, **kwargs)

        monkeypatch.setattr(CollectorBase, "submit_grift", submit)
        return attempts

    def test_a_refusal_because_the_grid_moved_is_read_and_planned_again_and_then_lands(self, monkeypatch: pytest.MonkeyPatch) -> None:
        attempts = self.refuse(monkeypatch, "entity_version_conflict", 1)
        job = collect()
        assert job.status == CollectionJobStatus.SUCCESSFUL.value, (job.summary, job.results["error"])
        assert len(attempts) == 2 and "GRID_MOVED_RETRYING" in codes(job, "warn")
        assert runs().count() == 1  # the first, refused attempt wrote nothing

    def test_it_gives_up_after_the_bounded_number_of_attempts_and_writes_nothing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        attempts = self.refuse(monkeypatch, "entity_version_conflict", 99)
        job = collect()
        assert job.status == CollectionJobStatus.FAILED.value and codes(job, "error") == ["GRID_KEPT_MOVING"]
        assert len(attempts) == mod.MAX_ATTEMPTS and runs().count() == 0 and findings().count() == 0

    def test_any_other_refusal_fails_at_once_without_a_second_scan(self, monkeypatch: pytest.MonkeyPatch) -> None:
        attempts = self.refuse(monkeypatch, "schema_validation_failed", 99)
        job = collect()
        assert job.status == CollectionJobStatus.FAILED.value and "GRIFT_BATCH_REJECTED" in codes(job, "error")
        assert len(attempts) == 1 and len(self.fake.scans()) == 1

    def test_which_refusals_are_worth_a_retry(self) -> None:
        assert mod.retryable(["entity_version_conflict"]) and mod.retryable(["entity_version_conflict", "entity_version_conflict"])
        assert not mod.retryable(["removal_target_missing"])  # a collector deletes nothing, so this is a defect, not a race
        assert not mod.retryable([]) and not mod.retryable(["entity_version_conflict", "schema_validation_failed"])


@pytest.mark.django_db(transaction=True)
class TestSeedsAndRegistration:
    def test_the_scanner_seed_imports_and_is_found_by_the_reader(self) -> None:
        assert reader.read_scanner_id() is None
        seed_scanner()
        scanner = get_model_class("compliance_core__compliance_scanner").objects.get(source="grype", scanner_key="grype-tap")
        assert reader.read_scanner_id() == str(scanner.entity_id)
        assert scanner.name == "Grype" and scanner.configuration == {"staleness_hours": 48}
        assert Entity.objects.get(pk=scanner.entity_id).dimensions == {"compliance": "scanner"}

    def test_the_scan_schedule_targets_the_registered_collector_and_runs_after_the_refresh(self) -> None:
        from tap_cares.registry import NAMESPACE_COLLECTOR

        batch = json.loads((PACKAGE_DIR / "grift" / "scan_schedule.grift.json").read_text(encoding="utf-8"))["batches"][0]
        (edge,) = batch["edges"]
        assert edge["edge"]["to_entity_id"] == str(uuid.uuid5(NAMESPACE_COLLECTOR, "grype:grype"))
        (schedule,) = batch["nodes"]
        assert schedule["node"]["cron_expression"] == "43 4 * * *" and schedule["node"]["max_active_runs"] == 1
        refresh = json.loads((PACKAGE_DIR / "grift" / "schedule.grift.json").read_text(encoding="utf-8"))["batches"][0]["nodes"][0]
        assert refresh["node"]["cron_expression"] == "17 2 * * *"  # 02:17 refresh, 04:43 scan

    def test_the_self_test_names_what_is_missing(self, home: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        use(monkeypatch, FakeGrype("{}", version="0.0.1"))
        failed = {c.code for c in mod.GrypeCollector.self_test().checks if c.is_failure}
        assert {"BINARY_VERSION_MISMATCH", "SCANNER_MISSING"} <= failed
        seed_scanner()
        use(monkeypatch, FakeGrype("{}"))
        assert not [c for c in mod.GrypeCollector.self_test().checks if c.is_failure]

    def test_the_collector_is_registered_with_a_literal_scope_and_key(self) -> None:
        source = (PACKAGE_DIR / "apps.py").read_text(encoding="utf-8")
        assert 'key="grype"' in source and source.count('scope="grype"') == 2
        assert os.path.exists(PACKAGE_DIR / "collectors" / "grype_collector.py")
