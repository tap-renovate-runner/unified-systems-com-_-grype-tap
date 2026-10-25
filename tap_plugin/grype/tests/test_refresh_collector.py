"""The database refresh collector and its schedule (req-grype-database-1, req-grype-database-5 in part).

``install`` and ``database.refresh`` are replaced, so no network, no Grype binary and no database are involved: what
is under test is the collector's own orchestration, the order it does things in, and what it records.
"""

from __future__ import annotations

import json
import tomllib
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tap_plugin.grype import database
from tap_plugin.grype.binary_pin import PinError
from tap_plugin.grype.collectors import refresh as mod
from tap_plugin.grype.home import HOME_ENV
from tap_plugin.grype.installer import InstallError

PACKAGE = Path(mod.__file__).parent.parent
BINARY = Path("/home/nonroot/.local/share/tap/grype/bin/grype-v0.120.1")


def status(built: datetime) -> database.DbStatus:
    return database.DbStatus(schema_version="v6.1.10", built=built, source="https://grype.anchore.io/")


def make() -> mod.GrypeDatabaseRefreshCollector:
    instance = mod.GrypeDatabaseRefreshCollector.__new__(mod.GrypeDatabaseRefreshCollector)
    instance.results = {"info": [], "warn": [], "error": []}
    instance._produced_batches, instance._surfaces, instance._surfaces_declared, instance.summary = [], [], False, ""
    return instance


@pytest.fixture
def home(monkeypatch, tmp_path) -> Path:
    monkeypatch.setenv(HOME_ENV, str(tmp_path / "grype"))
    return tmp_path / "grype"


@pytest.fixture
def calls(monkeypatch) -> list[str]:
    """Replace the two outside effects; record the order they were reached in."""
    seen: list[str] = []
    fresh = datetime.now(UTC) - timedelta(hours=6)

    def fake_install(home, pin, *, platform):
        seen.append("install")
        return BINARY

    def fake_refresh(home, settings, binary):
        seen.append("refresh")
        return database.RefreshResult(outcome="installed", status=status(fresh))

    monkeypatch.setattr(mod, "install", fake_install)
    monkeypatch.setattr(mod.database, "refresh", fake_refresh)
    return seen


def codes(instance: mod.GrypeDatabaseRefreshCollector, level: str) -> list[str]:
    return [entry["message_code"] for entry in instance.results[level]]


class TestRun:
    def test_it_places_the_binary_then_refreshes_and_lands_no_batch(self, home, calls) -> None:
        instance = make()
        instance.run()
        assert calls == ["install", "refresh"]
        assert instance._produced_batches == [] and instance._surfaces_declared is True
        assert codes(instance, "info") == ["RUN_STARTED", "RUN_FINISHED"]
        assert instance.summary.startswith("Database installed: v6.1.10@")
        assert (home / "settings.json").exists()  # the operator's defaults are written once, never over a choice

    def test_an_existing_settings_file_is_not_overwritten(self, home, calls) -> None:
        home.mkdir(parents=True)
        (home / "settings.json").write_text('{"database_max_age_days": 7, "database_mirror": null}')
        make().run()
        assert json.loads((home / "settings.json").read_text())["database_max_age_days"] == 7

    def test_a_current_database_older_than_the_limit_is_a_warning_not_a_failure(self, home, monkeypatch, calls) -> None:
        old = datetime.now(UTC) - timedelta(days=9)
        monkeypatch.setattr(
            mod.database, "refresh", lambda *a, **k: database.RefreshResult(outcome="current", status=status(old))
        )
        instance = make()
        instance.run()
        assert "DATABASE_STALE" in codes(instance, "warn") and codes(instance, "error") == []
        assert "db-stale" in instance.summary

    def test_a_refresh_warning_is_carried_to_the_job(self, home, monkeypatch, calls) -> None:
        fresh = datetime.now(UTC)
        monkeypatch.setattr(
            mod.database,
            "refresh",
            lambda *a, **k: database.RefreshResult("installed", status(fresh), warnings=("could not prune old builds: x",)),
        )
        instance = make()
        instance.run()
        assert codes(instance, "warn") == ["REFRESH_WARNING"]


class TestFailures:
    def test_invalid_settings_fetch_nothing(self, home, calls) -> None:
        home.mkdir(parents=True)
        (home / "settings.json").write_text('{"nope": 1}')
        instance = make()
        with pytest.raises(mod.GrypeRefreshError):
            instance.run()
        assert calls == [] and codes(instance, "error") == ["SETTINGS_INVALID"]
        assert instance.summary.startswith("settings.json is not usable")

    def test_an_unwritable_home_fetches_nothing(self, monkeypatch, tmp_path, calls) -> None:
        blocker = tmp_path / "file"
        blocker.write_text("not a directory")
        monkeypatch.setenv(HOME_ENV, str(blocker / "grype"))
        instance = make()
        with pytest.raises(mod.GrypeRefreshError):
            instance.run()
        assert calls == [] and codes(instance, "error") == ["HOME_UNWRITABLE"]

    @pytest.mark.parametrize("error", [InstallError("sha256 differs"), PinError("bad pin"), OSError("disk full")])
    def test_a_binary_that_cannot_be_placed_stops_before_the_database(self, home, monkeypatch, calls, error) -> None:
        def broken(*a, **k):
            raise error

        monkeypatch.setattr(mod, "install", broken)
        instance = make()
        with pytest.raises(mod.GrypeRefreshError):
            instance.run()
        assert calls == [] and codes(instance, "error") == ["BINARY_INSTALL_FAILED"]
        assert str(error) in instance.summary

    def test_a_scan_holding_the_database_is_reported_as_blocked(self, home, monkeypatch, calls) -> None:
        def busy(*a, **k):
            raise database.Busy("a scan holds the database")

        monkeypatch.setattr(mod.database, "refresh", busy)
        instance = make()
        with pytest.raises(mod.GrypeRefreshError):
            instance.run()
        assert codes(instance, "error") == ["REFRESH_BLOCKED"]

    def test_a_failed_refresh_says_the_installed_database_is_untouched(self, home, monkeypatch, calls) -> None:
        def failed(*a, **k):
            raise database.DatabaseError("`db update` exited 1")

        monkeypatch.setattr(mod.database, "refresh", failed)
        instance = make()
        with pytest.raises(mod.GrypeRefreshError) as exc:
            instance.run()
        assert codes(instance, "error") == ["DATABASE_REFRESH_FAILED"]
        assert "untouched" in str(exc.value) and "db update" in instance.summary


class TestSelfTest:
    def test_a_healthy_home_passes(self, home) -> None:
        result = mod.GrypeDatabaseRefreshCollector.self_test()
        assert not [c for c in result.checks if c.is_failure], result
        assert {c.code for c in result.checks} >= {"HOME_WRITABLE", "SETTINGS_VALID", "BINARY_PIN_VALID", "EGRESS_HOSTS"}

    def test_the_probe_never_touches_a_file_an_operator_keeps_in_the_home(self, home, tmp_path) -> None:
        home.mkdir(parents=True)
        (home / ".self-test").write_text("an operator's file")
        victim = tmp_path / "victim"
        victim.write_text("keep me")
        (home / ".self-test-link").symlink_to(victim)
        result = mod.GrypeDatabaseRefreshCollector.self_test()
        assert "HOME_WRITABLE" in {c.code for c in result.checks}
        assert (home / ".self-test").read_text() == "an operator's file" and victim.read_text() == "keep me"
        assert sorted(p.name for p in home.iterdir()) == [".self-test", ".self-test-link"]  # and it left nothing behind

    def test_the_named_egress_hosts_are_the_ones_the_downloads_use(self) -> None:
        from urllib.parse import urlparse

        from tap_plugin.grype.binary_pin import load_pin

        assert urlparse(load_pin().assets["linux/amd64"].url).hostname in mod.EGRESS_HOSTS  # the first hop
        # GitHub sends the archive to release-assets.githubusercontent.com (traced 2026-10-25), and the database is served by Anchore.
        assert set(mod.EGRESS_HOSTS) == {"github.com", "release-assets.githubusercontent.com", "grype.anchore.io"}

    def test_bad_settings_are_named(self, home) -> None:
        home.mkdir(parents=True)
        (home / "settings.json").write_text('{"nope": 1}')
        failed = {c.code for c in mod.GrypeDatabaseRefreshCollector.self_test().checks if c.is_failure}
        assert "SETTINGS_INVALID" in failed

    def test_a_mirror_means_no_database_egress(self, home) -> None:
        home.mkdir(parents=True)
        (home / "settings.json").write_text(json.dumps({"database_mirror": "/srv/grype-mirror"}))
        codes_ = {c.code for c in mod.GrypeDatabaseRefreshCollector.self_test().checks}
        assert "DATABASE_MIRROR" in codes_ and "EGRESS_HOSTS" not in codes_


class TestRegistrationAndSchedule:
    def test_registered_with_literal_scope_and_key(self) -> None:
        source = (PACKAGE / "apps.py").read_text()
        assert 'scope="grype"' in source and 'key="database_refresh"' in source

    def test_the_manifest_ships_the_schedule(self) -> None:
        manifest = tomllib.loads((PACKAGE / "tap-plugin.toml").read_text())
        assert manifest["grift"]["schedule"] == "grift/schedule.grift.json"

    def test_the_schedule_targets_the_registered_collector_daily_and_off_the_hour(self) -> None:
        from tap_cares.registry import NAMESPACE_COLLECTOR

        document = json.loads((PACKAGE / "grift" / "schedule.grift.json").read_text())
        batch = document["batches"][0]
        (schedule,) = batch["nodes"]
        (edge,) = batch["edges"]
        assert edge["edge"]["edge_type"] == "SCHEDULED_TARGET"
        assert edge["edge"]["from_entity_id"] == schedule["entity"]["entity_id"]
        assert edge["edge"]["to_entity_id"] == str(uuid.uuid5(NAMESPACE_COLLECTOR, "grype:database_refresh"))
        assert schedule["node"]["cron_expression"] == "17 2 * * *" and schedule["node"]["max_active_runs"] == 1
        assert batch["batch_node"]["description_json"]["data"]["collector"] == "grype:database_refresh"
