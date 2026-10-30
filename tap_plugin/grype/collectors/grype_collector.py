"""GrypeCollector: scan the packages and libraries on the grid and land the findings (req-grype-collector).

Registered as ``grype:grype``. It reads every live package and library, builds one CycloneDX document per operating
system, runs the pinned Grype over each against the installed database (a scan never fetches), plans every write as
plain data (``plan``), builds one GRIFT document (``document``) and submits it as the collector role. The run, its
findings, vulnerabilities and per-target coverage land in one batch or not at all.

The collector is the orchestration only; every decision lives in a pure module so it can be tested without a database:
``plan.plan_scan`` decides, ``document.build_document`` shapes, ``reader`` reads. What is here is the order of things,
the guards around them (another collection job running, the binary's version, the database's age, the lock) and the
retry when the grid moved between the read and the write.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, NoReturn
from uuid import uuid7

from tap_plugin.computing_core.sbom.builder import build_cyclonedx
from tap_plugin.grype import database, document, plan, reader
from tap_plugin.grype.binary_pin import PinError, load_pin
from tap_plugin.grype.database import Runner, run_command
from tap_plugin.grype.home import resolve_home
from tap_plugin.grype.scan import ScanError, scan_document, scratch_dir
from tap_plugin.grype.settings import Settings, SettingsError, load_settings

from tap_cares.collectors.base import CollectorBase
from tap_cares.collectors.readiness import (
    CollectorReadinessStatus,
    CollectorSelfTestResult,
    check_fail,
    check_pass,
    check_warn,
)
from tap_cares.exceptions import GriftRejectedError
from tap_cares.models import CollectionJob, CollectionJobStatus

# record_* call-site tokens (minted via scripts/log-site-id; unique within this file).
_SITE_STARTED = "483e"
_SITE_SKIPPED = "4287"
_SITE_SETTINGS = "4fa6"
_SITE_BINARY = "5967"
_SITE_SCANNER = "6d75"
_SITE_BUSY = "c82c"
_SITE_DOCUMENT = "0c72"
_SITE_REJECTED = "c523"
_SITE_RETRY = "55ce"
_SITE_UNMAPPED = "6e24"
_SITE_NOT_CLEAN = "3e5d"
_SITE_FINISHED = "3833"
_SITE_KEPT_MOVING = "bc1a"

#: How many times a run re-reads the grid and starts over when another writer got there first.
MAX_ATTEMPTS = 3
#: GRIFT error codes that mean the grid moved between this run's read and its write; anything else is a defect and fails
#: at once, so a deterministic refusal is not scanned three times.
RETRYABLE_CODES = frozenset({"entity_version_conflict"})
#: Run outcomes that leave the collection job failed: the run node exists (the evidence a scan was attempted) but the
#: job must not read as a success.
FAILED_OUTCOMES = frozenset({"failed", "db-stale", "db-unavailable"})

_VERSION = re.compile(r"(\d+\.\d+\.\d+)")


class GrypeScanError(RuntimeError):
    """The run could not finish; ``str(exc)`` says why."""


@dataclass(frozen=True)
class Landed:
    """What one attempt wrote."""

    outcome: str
    plan: plan.Plan


def reported_version(binary: Path, run: Runner = run_command) -> str | None:
    """The version ``grype --version`` prints (``grype 0.120.1`` gives ``0.120.1``), or ``None`` if it cannot be read."""
    try:
        result = run([str(binary), "--version"], {})
    except OSError:
        return None
    if result.returncode != 0:
        return None
    found = _VERSION.search(result.stdout)
    return found.group(1) if found else None


def retryable(codes: Sequence[str]) -> bool:
    """True when every refusal means the grid moved, so reading again and planning again can succeed."""
    return bool(codes) and all(code in RETRYABLE_CODES for code in codes)


def other_running_job(own_job_id: Any) -> CollectionJob | None:
    """Another collection job that is running now (Q25a, 2026-10-25), or ``None``.

    Status alone decides, however long the row has been running. A row left `RUNNING` by a dead worker is core's to
    finalize (`tap_cares.services.reaper` reaps a `RUNNING` job with no live claim); this plugin does not second-guess it
    with an age of its own, because an age would let a scan run beside a genuinely long inventory collection.
    """
    return CollectionJob.objects.filter(status=CollectionJobStatus.RUNNING.value).exclude(entity_id=own_job_id).first()


def target_signature(
    rows: Sequence[tuple[plan.GridTarget, dict[str, Any]]],
    systems: dict[str, list[str | None]],
    operating_systems: dict[str, dict[str, Any]],
) -> frozenset[tuple[Any, ...]]:
    """What a scan was made from: each target's identity and facts, the operating systems it is under, and their properties."""
    return frozenset(
        [
            ("operating_system", os_id, repr(sorted((key, repr(value)) for key, value in props.items())))
            for os_id, props in operating_systems.items()
        ]
        + [
            (
            grid_target.target.id,
            grid_target.entity_type,
            grid_target.natural_key,
            grid_target.target.purl,
            tuple(sorted(str(os_id) for os_id in systems.get(grid_target.target.id, [None]))),
            repr(sorted((key, repr(value)) for key, value in props.items())),
        )
        for grid_target, props in rows
        ]
    )


class GrypeCollector(CollectorBase):
    #: The seam tests replace with a fake Grype; production runs the real binary.
    runner: Runner = staticmethod(run_command)  # type: ignore[assignment]

    def run(self) -> None:
        self.declare_no_surfaces()
        self.record_info(_SITE_STARTED, "RUN_STARTED", "Scanning the packages and libraries on the grid with the pinned Grype.")
        blocker = other_running_job(self.config.collection_job_entity_id)
        if blocker is not None:
            self.summary = f"Skipped: collection job {blocker.entity_id} is running; no scan was made and no run was written."
            self.record_warn(_SITE_SKIPPED, "SKIPPED_OTHER_JOB_RUNNING", self.summary, message_data={"job": str(blocker.entity_id)})
            return
        home = resolve_home()
        try:
            settings = load_settings(home)
            pin = load_pin()
        except (SettingsError, PinError) as exc:
            self._fail(_SITE_SETTINGS, "SETTINGS_INVALID", f"the settings or the pin are not usable; nothing was scanned: {exc}")
        binary = home / "bin" / "grype"
        version = reported_version(binary, self.runner)
        wanted = pin.version.lstrip("v")
        if version != wanted:
            self._fail(
                _SITE_BINARY,
                "BINARY_VERSION_MISMATCH",
                f"the installed Grype reports {version or 'nothing'}, the pin is {wanted}; nothing was scanned and no run was written.",
            )
        scanner_id = reader.read_scanner_id()
        if scanner_id is None:
            self._fail(_SITE_SCANNER, "SCANNER_MISSING", "the grype scanner node is not on the grid (its seed was not applied); nothing was scanned.")

        last = ""
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                with database.lock(home, exclusive=False):
                    landed = self._attempt(home, binary, settings, version, scanner_id)
            except database.Busy as exc:
                self._fail(_SITE_BUSY, "REFRESH_RUNNING", f"the database is being refreshed, so nothing was scanned: {exc}")
            if isinstance(landed, str):  # the grid moved: read it again
                last = landed
                self.record_warn(_SITE_RETRY, "GRID_MOVED_RETRYING", f"attempt {attempt} of {MAX_ATTEMPTS}: {landed}")
                continue
            self._finish(landed)
            return
        self._fail(_SITE_KEPT_MOVING, "GRID_KEPT_MOVING", f"the grid changed under {MAX_ATTEMPTS} attempts in a row; nothing was written. Last: {last}")

    def _attempt(self, home: Path, binary: Path, settings: Settings, version: str, scanner_id: str) -> Landed | str:
        """One read, scan, plan and write. Returns what landed, or (as text) why the grid moved and it must be redone."""
        run_key = str(uuid7())
        observed_at = datetime.now(UTC)
        db_dir: Path | None = None
        try:
            db_dir = database.resolve_current(home)
            status = database.read_status(binary, db_dir, self.runner)
        except database.DatabaseError:
            status = None
        verdict = database.age_outcome(status, observed_at, settings.database_max_age_days)
        if verdict != database.OK or db_dir is None:
            return self._submit(plan.plan_unscanned(outcome=verdict, run_key=run_key, observed_at=observed_at, tool_version=version), scanner_id)

        rows = reader.read_targets()
        systems = reader.read_operating_systems()
        grouped = reader.documents_by_operating_system(rows, systems)
        # Read once, used to build the documents and compared after the scan: an operating system's properties go into
        # the SBOM, so a change to one is a change to what was scanned.
        os_props = {os_id: reader.read_operating_system(os_id) for os_id in grouped if os_id}
        scanned_from = target_signature(rows, systems, os_props)
        results: list[plan.DocumentResult] = []
        with scratch_dir(home, run_key) as scratch:
            for index, (os_id, members) in enumerate(sorted(grouped.items(), key=lambda item: item[0] or "")):
                label = f"os:{os_id or 'none'}"
                target_ids = tuple(grid_target.target.id for grid_target, _ in members)
                sbom = build_cyclonedx(
                    [props for grid_target, props in members if grid_target.target.kind == "package"],
                    [props for grid_target, props in members if grid_target.target.kind == "library"],
                    os_props[os_id] if os_id else None,
                )
                try:
                    parsed = scan_document(binary, db_dir, sbom, scratch, expected_version=version, index=index, run=self.runner)
                except ScanError as exc:
                    self.record_warn(_SITE_DOCUMENT, "DOCUMENT_FAILED", f"{label}: {exc}", message_data={"document": label, "targets": len(target_ids)})
                    parsed = None
                results.append(plan.DocumentResult(label, target_ids, parsed))

        # The grid is read again after the scan, not before it, so the window in which it can move is as short as it can be.
        # An inventory collector that started after the guard at the top of the run could have changed what was scanned: if
        # the targets are not the ones the documents were made from, the results are not trusted and the run starts again.
        after = target_signature(reader.read_targets(), reader.read_operating_systems(), {os_id: reader.read_operating_system(os_id) for os_id in os_props})
        if after != scanned_from:
            return f"the packages or libraries on the grid changed while Grype was scanning ({len(after ^ scanned_from)} differ)"
        targets = [grid_target for grid_target, _ in rows]
        findings = reader.read_existing_findings()
        vulnerabilities = reader.read_existing_vulnerabilities()
        planned = plan.plan_scan(
            targets=targets,
            results=results,
            existing_findings=findings,
            existing_vulnerabilities=vulnerabilities,
            run_key=run_key,
            observed_at=observed_at,
            tool_version=version,
        )
        return self._submit(planned, scanner_id, targets, findings, vulnerabilities)

    def _submit(
        self,
        planned: plan.Plan,
        scanner_id: str,
        targets: Sequence[plan.GridTarget] = (),
        findings: Sequence[plan.ExistingFinding] = (),
        vulnerabilities: Sequence[plan.ExistingVulnerability] = (),
    ) -> Landed | str:
        try:
            ctx = document.Context(
                scanner_id=scanner_id,
                field_names=reader.field_names(),
                known_ids=reader.known_ids(targets, findings, vulnerabilities),
                existing_nodes=reader.read_nodes(planned),
            )
            batch = document.build_document(planned, ctx)
        except document.StaleNodeError as exc:  # a node moved between the plan and reading it whole: read and plan again
            return str(exc)
        result = self.submit_grift(batch, on_rejection="return")
        if result.errors:
            codes = [str(getattr(issue, "code", "?")) for issue in result.errors]
            detail = "; ".join(f"{getattr(issue, 'code', '?')}: {getattr(issue, 'message', '')}" for issue in result.errors[:5])
            if retryable(codes):
                return detail
            self.record_error(_SITE_REJECTED, "GRIFT_BATCH_REJECTED", detail)
            raise GriftRejectedError(detail)
        return Landed(planned.run["outcome"], planned)

    def _finish(self, landed: Landed) -> None:
        planned = landed.plan
        coverage = Counter(item.outcome for item in planned.coverage)
        resolved = sum(1 for patch in planned.patch_findings if patch.fields.get("status") == "resolved")
        self.summary = (
            f"Run {landed.outcome}: {coverage.get('scanned', 0)} scanned, {coverage.get('not-scanned', 0)} not scanned, "
            f"{coverage.get('failed', 0)} failed; {len(planned.mint_findings)} findings opened, {resolved} resolved, "
            f"{len(planned.mint_vulnerabilities)} vulnerabilities minted, {len(planned.unmapped)} unmapped matches."
        )[:400]
        for unmapped in planned.unmapped[:20]:
            self.record_warn(_SITE_UNMAPPED, "MATCH_UNMAPPED", f"{unmapped.vuln_id} on {unmapped.purl}: {unmapped.reason}")
        if landed.outcome != "ok":
            self.record_warn(_SITE_NOT_CLEAN, "RUN_NOT_CLEAN", self.summary, message_data={"outcome": landed.outcome, "unmapped": len(planned.unmapped)})
        self.record_info(
            _SITE_FINISHED,
            "RUN_FINISHED",
            self.summary,
            message_data={"outcome": landed.outcome, "run_key": planned.run["run_key"], "data_version": planned.run.get("data_version")},
        )
        if landed.outcome in FAILED_OUTCOMES:
            raise GrypeScanError(self.summary)

    def _fail(self, site: str, code: str, message: str) -> NoReturn:
        """Record the error, set the summary, and end the run as failed."""
        self.summary = message[:400]
        self.record_error(site, code, message)
        raise GrypeScanError(message)

    @classmethod
    def self_test(cls) -> CollectorSelfTestResult:
        checks = []
        home = resolve_home()
        settings: Settings | None = None
        try:
            settings = load_settings(home)
            checks.append(check_pass("SETTINGS_VALID", "settings.json is valid (or absent: defaults apply)."))
        except SettingsError as exc:
            checks.append(check_fail("SETTINGS_INVALID", str(exc), readiness_status=CollectorReadinessStatus.MISCONFIGURED))
        binary = home / "bin" / "grype"
        try:
            wanted = load_pin().version.lstrip("v")
            version = reported_version(binary, cls.runner)
            if version == wanted:
                checks.append(check_pass("BINARY_VERSION", f"Grype {version} is installed, as pinned."))
            else:
                checks.append(
                    check_fail(
                        "BINARY_VERSION_MISMATCH",
                        f"the installed Grype reports {version or 'nothing'}, the pin is {wanted}; the database refresh places the pinned binary.",
                        readiness_status=CollectorReadinessStatus.MISCONFIGURED,
                    )
                )
        except PinError as exc:
            checks.append(check_fail("BINARY_PIN_INVALID", str(exc), readiness_status=CollectorReadinessStatus.MISCONFIGURED))
        if settings is not None:
            try:
                status = database.read_status(binary, database.resolve_current(home), cls.runner)
            except (database.DatabaseError, OSError):
                status = None
            verdict = database.age_outcome(status, datetime.now(UTC), settings.database_max_age_days)
            if verdict == database.OK and status is not None:
                checks.append(check_pass("DATABASE_CURRENT", f"the installed database ({status.data_version}) is within {settings.database_max_age_days} days."))
            else:
                # A warning, not a failure: a run on a stale or missing database is still made and recorded as
                # `db-stale` or `db-unavailable` (the evidence a scan was attempted), which a failed self-test would prevent.
                checks.append(
                    check_warn(
                        "DATABASE_" + verdict.upper().replace("-", "_"),
                        f"a scan now would end {verdict}: the database refresh installs a current build.",
                    )
                )
        if reader.read_scanner_id():
            checks.append(check_pass("SCANNER_SEEDED", "the grype scanner node is on the grid."))
        else:
            checks.append(
                check_fail("SCANNER_MISSING", "the grype scanner node is not on the grid; its seed has not been applied.", readiness_status=CollectorReadinessStatus.MISCONFIGURED)
            )
        return CollectorSelfTestResult.from_checks(checks, summary="grype scan self-test")
