"""GrypeDatabaseRefreshCollector: place the pinned Grype binary and keep its advisory database current (req-grype-database).

Registered as ``grype:database_refresh``. It lands NO GRIFT batch: its only grid footprint is the collection job
record. It first makes sure the pinned binary is in place (a recreated container starts with an empty home, so the
refresh is also what restores it), then installs a newer database build or reports that the installed one is
current. A refresh that cannot finish ends as a failed job naming why, and the previously installed database keeps
serving scans (``database.refresh`` stages and swaps).
"""

from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime
from typing import NoReturn

from tap_plugin.grype import database
from tap_plugin.grype.binary_pin import PinError, load_pin
from tap_plugin.grype.home import resolve_home
from tap_plugin.grype.installer import InstallError, host_platform, install
from tap_plugin.grype.settings import SettingsError, load_settings, write_default_settings

from tap_cares.collectors.base import CollectorBase
from tap_cares.collectors.readiness import (
    CollectorReadinessStatus,
    CollectorSelfTestResult,
    check_fail,
    check_pass,
)

# record_* call-site tokens (minted via scripts/log-site-id; unique within this file).
_SITE_STARTED = "1308"
_SITE_HOME = "a827"
_SITE_SETTINGS = "3a4d"
_SITE_BINARY = "d45e"
_SITE_BUSY = "ee3e"
_SITE_DATABASE = "7879"
_SITE_WARNING = "db10"
_SITE_STALE = "bcc1"
_SITE_FINISHED = "a1a8"

#: The hosts a refresh without a mirror reaches, named in the self-test so an operator can open egress for them.
#: Traced 2026-10-25 with `curl -I`: the pinned archive URL on github.com answers 302 to
#: release-assets.githubusercontent.com; the database listing (`/databases/v6/latest.json`) and the database archive are
#: both served by grype.anchore.io with no redirect (200).
EGRESS_HOSTS = ("github.com", "release-assets.githubusercontent.com", "grype.anchore.io")


class GrypeRefreshError(RuntimeError):
    """The refresh could not finish; ``str(exc)`` says why."""


class GrypeDatabaseRefreshCollector(CollectorBase):
    def run(self) -> None:
        self.declare_no_surfaces()
        self.record_info(_SITE_STARTED, "RUN_STARTED", "Refreshing the pinned Grype binary and its advisory database.")
        home = resolve_home()
        try:
            write_default_settings(home)
            settings = load_settings(home)
        except SettingsError as exc:
            self._fail(_SITE_SETTINGS, "SETTINGS_INVALID", f"settings.json is not usable; nothing was fetched: {exc}")
        except OSError as exc:
            self._fail(_SITE_HOME, "HOME_UNWRITABLE", f"{home} cannot be written; nothing was fetched: {exc}")
        try:
            binary = install(home, load_pin(), platform=host_platform())
        except (PinError, InstallError, OSError) as exc:
            self._fail(_SITE_BINARY, "BINARY_INSTALL_FAILED", f"the pinned Grype binary could not be placed: {exc}")
        try:
            result = database.refresh(home, settings, binary)
        except database.Busy as exc:
            self._fail(_SITE_BUSY, "REFRESH_BLOCKED", f"the database is in use, so it was not refreshed: {exc}")
        except (database.DatabaseError, OSError) as exc:
            self._fail(_SITE_DATABASE, "DATABASE_REFRESH_FAILED", f"the database was not refreshed; the installed one is untouched: {exc}")
        for warning in result.warnings:
            self.record_warn(_SITE_WARNING, "REFRESH_WARNING", warning)
        age = database.age_outcome(result.status, datetime.now(UTC), settings.database_max_age_days)
        built = result.status.built.isoformat()
        self.summary = f"Database {result.outcome}: {result.status.data_version}, built {built}."[:400]
        if age != database.OK:
            self.summary = f"{self.summary[:300]} It is older than {settings.database_max_age_days} days, so scans will end db-stale."
            self.record_warn(
                _SITE_STALE,
                "DATABASE_STALE",
                self.summary,
                message_data={"data_version": result.status.data_version, "built": built, "max_age_days": settings.database_max_age_days},
            )
        self.record_info(
            _SITE_FINISHED,
            "RUN_FINISHED",
            self.summary,
            message_data={"outcome": result.outcome, "data_version": result.status.data_version, "built": built},
        )

    def _fail(self, site: str, code: str, message: str) -> NoReturn:
        """Record the error, set the summary, and end the run as failed."""
        self.summary = message[:400]
        self.record_error(site, code, message)
        raise GrypeRefreshError(message)

    @classmethod
    def self_test(cls) -> CollectorSelfTestResult:
        checks = []
        home = resolve_home()
        try:
            home.mkdir(parents=True, exist_ok=True)
            # A randomly named file created exclusively, never a fixed name: a fixed one would overwrite and delete a
            # file an operator keeps there, or write through a symlink planted at that name.
            handle, probe = tempfile.mkstemp(prefix=".self-test-", dir=home)
            os.close(handle)
            os.unlink(probe)
            checks.append(check_pass("HOME_WRITABLE", f"{home} is writable."))
        except OSError as exc:
            checks.append(check_fail("HOME_UNWRITABLE", f"{home} is not writable: {exc}", readiness_status=CollectorReadinessStatus.MISCONFIGURED))
        settings = None
        try:
            settings = load_settings(home)
            checks.append(check_pass("SETTINGS_VALID", "settings.json is valid (or absent: defaults apply)."))
        except SettingsError as exc:
            checks.append(check_fail("SETTINGS_INVALID", str(exc), readiness_status=CollectorReadinessStatus.MISCONFIGURED))
        try:
            pin = load_pin()
            platform = host_platform()
            if platform in pin.assets:
                checks.append(check_pass("BINARY_PIN_VALID", f"Grype {pin.version} is pinned for {platform}."))
            else:
                checks.append(check_fail("BINARY_PIN_PLATFORM", f"the pin has no archive for {platform}.", readiness_status=CollectorReadinessStatus.MISCONFIGURED))
        except (PinError, InstallError) as exc:
            checks.append(check_fail("BINARY_PIN_INVALID", str(exc), readiness_status=CollectorReadinessStatus.MISCONFIGURED))
        if settings is not None and settings.database_mirror:
            checks.append(check_pass("DATABASE_MIRROR", f"the database imports from {settings.database_mirror}; no database egress."))
        else:
            checks.append(check_pass("EGRESS_HOSTS", f"egress hosts for the binary and the database: {', '.join(EGRESS_HOSTS)}."))
        return CollectorSelfTestResult.from_checks(checks, summary="grype database refresh self-test")
