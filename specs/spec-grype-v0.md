# Grype Plugin Specification

**A grid-native implementation of Grype: on a schedule it builds an SBOM from the packages and libraries already on the grid, matches it against Grype's advisory database with a pinned local binary, and writes the results back to the grid as scan runs, findings, vulnerabilities (with their KEV and EPSS facts) and per-target coverage. It makes no pages and holds no credential.**

## Plugin Identity

| Field | Value |
| --- | --- |
| Slug | `grype` |
| Display name | TAP Grype |
| Description | A grid-native Grype scan: builds an SBOM from the packages on the grid, matches it against Grype's advisory database on a schedule, and writes findings, KEV and EPSS back to the grid. |
| Kind | Leaf plugin: consumes computing_core (packages, libraries, operating systems, and the SBOM builder) and compliance_core (vulnerability, scanner, scan run and finding types); consumed by nothing in v0. |

**Default dimensions.** This plugin ships no TAP-managed node or edge types of its own: every node and edge it writes is compliance_core's, so it stamps no dimension vocabulary.

## Philosophy

Software deployed in the field, above all long-running containers, does not pass through a CI deploy, so new CVEs accumulate against it unseen. Rescanning deployed assets independent of new versions is a FedRAMP requirement. Grype is the matcher (Trivy stays in CI as the image scan and release gate), and TAP already holds the inventory, so the missing piece is a scheduled loop that turns the grid's packages into a throwaway SBOM, matches it, and puts the answer back beside the packages it concerns.

Five consequences shape v0:

1. **Consume, do not rebuild.** The SBOM comes from computing_core's builder, the node types are compliance_core's, and the matching is Grype's. This plugin authors none of the three. It is the loop and the lifecycle between them.
2. **Everything on the grid is scanned.** A package on the grid is presumed to matter to someone. Deciding what is deployed is not this plugin's job, so it scans every package and library and says nothing about deployment.
3. **Three states, never two.** A target Grype did not scan, because its document failed, or because the database was too old, is recorded as *not scanned*, never as clean. A fact nothing read is `null`, never `false` or `0`. A package nobody has scanned yet reads as *never scanned*.
4. **A run is a function of grid state, a pinned binary and a database build.** Scans never touch the network. The database is refreshed by its own scheduled collector, so a scan's result can be replayed and its inputs are all named on the run.
5. **One identity per fact.** A vulnerability is one node named by its CVE (the GHSA is an alias). A finding is keyed by what it asserts, never by the run. Findings from different producers are not merged by sharing a key: the same vulnerability on the same package is found by traversing the shared vulnerability and package nodes.

**Prior art, and what it changed.** Surveyed 2026-10-15 (documented from each project's own docs, not run): Clair separates indexing, matching and notifying and re-matches stored indexes whenever its data updates, which is this plugin's rescan-without-a-build requirement, so the grid inventory plays the stored index and Grype the matcher; Dependency-Track re-analyses its portfolio when data changes and keeps a finding as a component and vulnerability pair with triage apart from detection, hence findings keyed by pair and exceptions left to compliance_core's own edge; Trivy Operator expires a per-workload report on a time to live and rescans, hence coverage that ages into *stale*, rejecting its one-blob report as the corner-jam this repository's rules forbid; DefectDojo's reimport closes findings absent from a new report and reopens ones that return, but its tracker shows wrong closures when the closing logic ignores what was actually scanned and when a key recipe changes under stored findings, hence *resolve only what was scanned* and a key that does not depend on the scanner or database build; GUAC's discipline of origin and collector on every assertion is carried by the scanner and run nodes.

**Provenance markers.** *Observed* (ran, 2026-10-15, by the rampart-pg session, Grype v0.120.1): the tap-web SBOM (image `sha256:a9149a88…`, 192 components) yields 91 matches over 27 vulnerability ids with the full purl, CPE and CPE candidates, 89 without the candidates, 50 without the CPE and 12 without the upstream and CPE (Wolfi advisories are filed against the origin package); a log4j-core 2.14.1 SBOM yields KEV (`knownExploited`: cve, dateAdded, requiredAction, dueDate, knownRansomwareCampaignUse) and EPSS (`epss`: cve, epss, percentile, date) in native JSON, where the match id is the GHSA and the CVE sits in `relatedVulnerabilities`; Grype's CycloneDX output carries KEV on the GHSA entry only. *Observed* (read, cache on disk): the v6 database is delivered as `https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.10_2026-10-15T00:29:08Z_<id>.tar.zst?checksum=sha256:…` and was 3.25 GB on disk. *Observed* (ran): Grype is not on PyPI (three package names, all 404). *Documented* (Anchore's v6 schema post, not re-measured): databases are built daily, about 65 MB compressed at the v6 launch; nothing read documents an incremental update, so each refresh is a full archive. *Documented, not run by this plugin's author*: Grype's `db update`, `db import`, `db status` and the auto-update switch. *Designed*: everything else, including the unverified items named in each requirement.

## Goals

| # | Name | Description |
| --- | --- | --- |
| 1 | Rescan Without A Deploy | Every package and library on the grid is matched against current advisories on a schedule, independent of any new build. |
| 2 | Grid In, Grid Out | The inventory is read from the grid, the answer is written to the grid, and no page, credential or side channel stands between. |
| 3 | Never Clean By Omission | Not scanned, stale and never scanned are recorded as such; a fact nothing observed is `null`. |
| 4 | Pinned And Reproducible | The binary is pinned and checksummed, the database build is recorded, scans never fetch, and a run names every input. |
| 5 | One Identity Per Fact | A vulnerability is one node, a finding is keyed by its assertion, and cross-producer correlation is by graph, not by a shared key. |
| 6 | Backend Only | No page or panel ships; the outputs are nodes, edges and patches other surfaces can read. |

## Requirements

| RID | Name | Status | Notes |
| --- | --- | --- | --- |
| req-grype-binary | [The Pinned Release Binary](#the-pinned-release-binary) | In Development | Pinned release binary and sha256 placed by an operator step; version gate; honest `[fips]` with its unverifiable caveat |
| req-grype-database | [The Advisory Database](#the-advisory-database) | Proposed | Own daily refresh collector with an operator mirror fallback; scans never fetch; the age rule ends a run `db-stale` or `db-unavailable` |
| req-grype-collector | [The Whole-Grid Collector](#the-whole-grid-collector) | Proposed | `grype:grype`: per-operating-system SBOMs from computing_core's builder, native JSON, fail closed, per-run scratch |
| req-grype-trigger | [Own Schedule And Its Guards](#own-schedule-and-its-guards) | Proposed | Seeded daily schedule; skips with no run node while upstream writes; names the upstream jobs it read; the actor and its write permission |
| req-grype-vulnerability | [Vulnerabilities, Minted And Patched](#vulnerabilities-minted-and-patched) | Proposed | CVE-keyed with the GHSA as alias, alias-aware lookup, partial patches only, null never false |
| req-grype-finding | [The Finding](#the-finding) | Proposed | Keyed by vulnerability and target, under source `grype`; fixed versions on the edge; correlation by graph |
| req-grype-lifecycle | [Findings Resolve Only What Was Scanned](#findings-resolve-only-what-was-scanned) | Proposed | Resolve, reopen, latest-run-only reporting edge, net-new derived |
| req-grype-run | [Scanner, Run And Coverage](#scanner-run-and-coverage) | Proposed | One scanner node, one scan run per execution, one coverage edge per target |
| req-grype-staleness | [Staleness Is Derived](#staleness-is-derived) | Proposed | Four coverage states read by query; nothing stored on package nodes |
| req-grype-corpus | [The Corpus Proof](#the-corpus-proof) | Proposed | Recorded native outputs always; the live tier reproduces 91 matches over 27 ids when the binary and database are present |
| req-grype-first-light | [First Light](#first-light) | Proposed | A scheduled run observed on the live grid, with its counts and a clean second run |
| req-grype-sidecar | [Delivery By Sidecar](#delivery-by-sidecar) | Backlog | Replaces the release binary when docker sidecars are available |
| req-grype-sandbox | [Binary Sandbox](#binary-sandbox) | Backlog | Landlock plus seccomp around every Grype invocation, once tap_plugins ships the shared wrapper (tap#858); fail closed when the kernel cannot apply it |
| req-grype-nongoals | [v0 Non-Goals](#v0-non-goals) | Proposed | What this plugin deliberately does not do, and who owns it |

### The Pinned Release Binary
----
RID: `req-grype-binary`

Status: `In Development`

Grype is a Go binary published by Anchore as release archives and container images; it is not on PyPI, and the plugin architecture ships no non-Python runtime packaging, so zizmor's pin-by-wheel does not carry over. The first cut pins an exact release binary with a checksum, placed on a persistent volume by an explicit operator step and never fetched during a scan. The collector reads `grype --version` and refuses to scan when it differs from the pin. The manifest `[fips]` table declares the posture honestly (see the implementation note on what verifies it).

#### Implementation

A declarative data file `tap_plugin/grype/binary.json`, with a JSON Schema authored beside it and a `description` on the top level and on every entry, names the pin: `version` (for example `v0.120.1`) and, per platform (`linux/amd64`, `linux/arm64`), the release archive URL, its `sha256`, and the `binary_sha256` of the `grype` executable inside it. It is the only place the version appears; the collector and the installer both read it.

The operator step is a stdlib-only script shipped with the plugin (no Django import, so it can run in an image build or at provisioning). It downloads the archive named for the host platform, refuses on a `sha256` mismatch, extracts only the single member named `grype` (refusing absolute paths, `..`, symlinks and hard links, and special files, and never writing outside the target directory) to `<home>/bin/grype-<version>`, and atomically repoints `<home>/bin/grype`. It is idempotent, and idempotence is not trust: a binary already installed is accepted only when its sha256 equals the pin's `binary_sha256`, otherwise it is replaced from a fresh verified download. `<home>` is an operator-controlled directory on a persistent volume, fixed by the operator step and never read from the grid. A path or setting on a user-editable node would let anyone who can edit that node point the collector at a different binary, which would pass the version gate by printing the right version. The scanner node's `locator` records `<home>` for readers and is never used to execute or locate anything. The operator-only settings (`database_mirror`, `database_max_age_days`) live in `<home>/settings.json`, written by the operator step, for the same reason.

**Named weakness.** The `sha256` in `binary.json` is a checksum the plugin's authors copy from the release's published checksums at pin time. This is the shape zizmor's spec rejected for a hand-authored checksum: presence, not correctness, unless the copy is checked. The bump procedure therefore verifies the release's published checksums file against the archive and records the upstream signing identity if Anchore publishes one (NOT verified at authoring; recorded as a verify-once step on the first pin).

**How a bump is noticed (Renovate).** The version lives in `binary.json` precisely so a dependency bot can see it. The repository carries a `renovate.json5` with a regex custom manager over `tap_plugin/grype/binary.json` that reads `version` and looks it up as a `github-releases` dependency on `anchore/grype` (semver, `v`-prefixed tags), so a new Grype release becomes a Renovate PR. Renovate moves only the version. The per-platform `sha256` values are digests of release archives that Renovate cannot compute, and the fleet's Renovate allows exactly one post-upgrade command (the boot-record refresh), so the PR arrives with a stale checksum and fails the bump check (`req-grype-binary-5`) until `scripts/pin-grype <version>` is run. That script, shipped with the plugin and stdlib-only, rewrites `binary.json` from the release's published checksums file and refuses unless the downloaded archive matches it. A red bump PR is the intended fail-closed state, not a defect. Read, not run: Renovate's own option table (`lib/config/options/index.ts` on its main branch) marks `customManagers` as `mergeable: true`, as it does `packageRules`, so a repository's managers are added to the inherited ones and do not replace them; no Renovate run has shown it here. Not verified: whether `osvVulnerabilityAlerts` resolves advisories for a binary tracked only as a GitHub release, so a Grype security advisory may not raise its own PR; the Dependabot alert channel does not cover `binary.json` either.

**FIPS.** Grype is a Go program; its TLS and hashing run on Go's standard crypto and ignore `OPENSSL_CONF`. The manifest declares `[fips] status = "uses-nonvalidated"` with that reason. The crypto-BOM check scans a plugin's shipped files and declared dependencies, and an out-of-band binary is neither, so nothing mechanical verifies this declaration; the spec states that plainly so no reader assumes it is checked. The scan itself never opens a network connection (`req-grype-database-4`); only the refresh collector does.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-grype-binary-1 | Pin Validates | Implemented | `binary.json` validates against its schema, names one version and a `sha256` per supported platform, and the installer refuses any archive whose digest differs. | A tampered-archive test. `tests/test_binary.py` `TestPinFile`, `TestInstaller::test_a_digest_mismatch_is_refused_and_writes_nothing`; the schema half of the agreement test runs only where `jsonschema` is importable and is skipped loudly elsewhere. |
| req-grype-binary-2 | Version Gate | Proposed | A fire whose `grype --version` differs from the pin ends before any SBOM is built, as a failed collection job naming both versions, and writes no run, finding or edge. | The binary that ran is the one that was pinned. |
| req-grype-binary-3 | Honest FIPS Declaration | Proposed | The manifest carries `[fips]` with `uses-nonvalidated` and a non-empty reason, `validate_plugin --strict` passes, and this spec states that the declaration is unverified by the crypto-BOM check. | |
| req-grype-binary-4 | Installer Is Idempotent | Implemented | Running the installer twice leaves one binary and a correct link; a failed download leaves the previous binary in place. | `tests/test_binary.py` `TestInstaller` (idempotent re-run, failed download keeps the previous binary). |
| req-grype-binary-5 | Bump Is Checked | Proposed | A change to the pin is accepted only when the archive's digest equals the digest in the release's own published checksums file, checked by a script run at the bump, and the bump records the upstream signing identity where Anchore publishes one. | The check that turns a copied checksum into a verified one. Built: the digest-equality half (`pin_tool`, `TestPinTool`). Not built: the upstream signing identity (the release publishes a sigstore bundle; checking it needs cosign), so this stays Proposed. |
| req-grype-binary-6 | Extraction Is Contained | Implemented | An archive carrying an absolute path, a `..` member, a symlink or hard link that escapes, or a device file is refused even when its digest matches the pin, and nothing is written outside `<home>/bin`. | A malicious-archive fixture. `tests/test_binary.py` `test_a_matching_digest_does_not_excuse_a_dangerous_archive` (7 cases); the real v0.120.1 archive passes the member check. |
| req-grype-binary-7 | Nothing Executable From The Grid | Proposed | Editing the scanner node's `locator` or `configuration` changes neither which binary runs nor which database or mirror is used. | A test that edits both and re-runs. |
| req-grype-binary-8 | Pin Is Visible To Renovate | Proposed | A new Grype release produces a Renovate PR that changes only `binary.json`'s `version`; that PR fails the bump check until `scripts/pin-grype <version>` rewrites the checksums from the release's published checksums file, and the script refuses on a mismatch. | Shown with a fixture release. The fleet-preset merge and OSV coverage are named unverified above. Built: the Renovate manager and a test that it matches `binary.json`. Not shown: a real Renovate PR. |

### The Advisory Database
----
RID: `req-grype-database`

Status: `Proposed`

Grype matches against a vulnerability database that Anchore builds daily. The plugin refreshes it with its own collector on its own schedule, and a scan only reads the database already installed, so a scan never depends on a download and a failed refresh costs nothing but age. Where the TAP container cannot reach Anchore, an operator mirror directory is the fallback. A run whose database is missing or older than the limit ends without touching any finding.

#### Implementation

**Refresh collector** `grype:database_refresh`, with a plugin-seeded schedule node (default cron `17 2 * * *`, off the hour and ahead of the scan, user-editable, one active run). It runs the pinned binary's own update (`grype db update`) with the database directory pointed at a staging directory next to the live one, so Anchore's client does the download, the checksum and the validation; the plugin writes none of that. It then reads `grype db status` on the staging copy and, only if that succeeds, moves it to `<home>/db/<build id>/`, atomically repoints `<home>/db/current` to it, and keeps the two newest builds, removing an older one only when no scan is active. A failed refresh leaves `current` untouched and ends as a failed collection job naming why.

**Mirror fallback.** `database_mirror` in `<home>/settings.json` names a directory; when set, the refresh imports from it (`grype db import`) instead of reaching Anchore, with the same staging, validation and swap. An operator fills the directory. "Newest" means the archive with the latest build time in its manifest, never a file's modification time. Each archive sits beside a manifest the operator's fetch step writes (`archive` name, `sha256`, `built`, taken from Anchore's `latest.json` over TLS); the refresh refuses an archive whose digest does not match its manifest, one built earlier than the installed database (no rollback), and one stamped in the future, and keeps the installed database. Whether `grype db import` itself authenticates an archive is NOT verified, so the plugin does not rely on it. **Trust boundary, stated plainly:** anyone who can write the mirror directory (archive and manifest together) or edit `<home>/settings.json` can substitute a database, and the checksum only catches accident and half-substitution. The mirror directory and `settings.json` are therefore operator-writable only, and neither is on the grid. Whether the TAP container can reach `grype.anchore.io` in a given deployment is NOT observed; the mirror is how that question stops blocking.

**Scans never fetch.** Every scan invocation sets the auto-update and application-update-check switches off, so a scan makes no connection, and the test for it blocks egress. A scan resolves `<home>/db/current` to its real path once, at the start, and passes that one directory to every invocation, so a refresh that swaps `current` mid-run cannot give one run two builds or remove files from beneath an invocation. Each document's own output reports the database it used (`descriptor.db.status`: schema version, build time, source); the run records those values (`data_built_at`, `data_version`, `req-grype-run`) and ends `failed` if two documents report different builds. A refresh does not start while a scan is active, and a scan does not start while a refresh is active.

**Age rule.** The limit is `database_max_age_days` in `<home>/settings.json`, default 3 (George's ruling). Age is `now − data_built_at`, Anchore's own build time and not the time of installation, so a late install does not make an old build look fresh; three days covers one missed daily refresh plus publishing lag. Whether Anchore publishes every day, weekends included, is NOT verified. A database older than that ends the run with outcome `db-stale`; a missing or unreadable one, `db-unavailable`. Both create a scan run (the evidence that a scan was attempted), write no finding, patch no vulnerability, write no coverage edge, and mark no target clean.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-grype-database-1 | Scheduled Refresh | Proposed | The seeded refresh schedule fires `grype:database_refresh`, which installs a newer database build and records the job's outcome; the schedule is verified by the `schedule-grift-targets` guard. | |
| req-grype-database-2 | Atomic Swap, Keep The Last | Proposed | A refresh that fails at download, import or validation leaves the previously installed database serving scans. | Failure injected at each step. |
| req-grype-database-3 | Mirror Fallback | Proposed | With `database_mirror` set, the refresh imports from the directory and makes no network connection. | Asserted with egress blocked. |
| req-grype-database-4 | Scans Never Fetch | Proposed | A scan with egress blocked completes against the installed database and makes no connection attempt. | |
| req-grype-database-5 | Age Rule | Proposed | A database older than `database_max_age_days`, or missing, ends the run `db-stale` or `db-unavailable`, changes no finding or vulnerability, and writes no coverage edge. | The run exists; the findings do not move. |
| req-grype-database-6 | Mirror Is Verified | Proposed | An archive whose digest differs from its manifest, one built earlier than the installed database, and one stamped in the future are each refused, and the installed database keeps serving scans. | A negative substitution test. |
| req-grype-database-7 | One Build Per Run | Proposed | A refresh that swaps `current` while a scan is running does not change the database any of that scan's documents use, and a run whose documents report different builds ends `failed`. | A concurrency test; neither job starts while the other is active. |

### The Whole-Grid Collector
----
RID: `req-grype-collector`

Status: `Proposed`

`GrypeCollector` (`CollectorBase`, registry key `grype:grype`) is derived: it reads package, library and operating-system rows already on the grid, builds throwaway CycloneDX documents with computing_core's `build_cyclonedx`, runs the pinned Grype over each, parses Grype's native JSON (`-o json`), and lands the results. It needs no credential and, at scan time, no network.

#### Implementation

**Scope: the whole grid.** Every live `package` and `library` node is a scan target. The grid, not this plugin, decides what matters; deployment is out of scope (`req-grype-nongoals`).

**One document per operating system.** The builder takes a single operating system. A target's operating system is found by traversal: the hosts that `INSTALLS_PACKAGE` (or `SHIPS_LIBRARY`) the target, and their `RUNS_OPERATING_SYSTEM`. One document is built per distinct `operating_system` node; a target under several is included in each and its matches are collapsed to one finding per target. A target no host installs has no operating system, and the builder (computing_core v0.8.0, read 2026-10-16: `build_cyclonedx(packages, libraries, operating_system=None, *, requires=())`) accepts none, so such targets go into a document of their own with no operating-system component and are scanned. Matches then rest on the purl and CPE alone; the recorded ablation found the operating-system component made no difference to the 91 matches, because the distro rides the purl's `distro=` qualifier, but that was observed on a document that had one, so a package whose purl lacks the qualifier is the case the corpus must cover. The builder takes plain mappings of node properties (`ecosystem`, `name`, `version`, `purl`, `cpe`, `cpe_candidates`, `license`; for libraries also `source_kind`, `source_url`, `path`), collapses two rows with one natural key into one component, gives a package with no purl a minimal one in the document only, writes ASCII CycloneDX 1.6, and takes optional `requires` pairs for dependencies, which this plugin does not need.

**Several documents, one outcome.** A target in more than one document is `scanned` only when every document it appears in parsed successfully. Matches from the successful documents still create or reopen findings, but if any one of its documents failed the target is `not-scanned` with reason `document-failed` and none of its findings is resolved: a finding absent from the successful document may simply have been in the failed one.

**Scratch.** Each run uses `<home>/scratch/<run_id>/`, created `0700`, never a fixed or cwd-relative path, removed on exit including on failure. File names inside are fixed (`doc-<n>.cdx.json`), never derived from grid data.

**Invocation.** One invocation per document: `<home>/bin/grype sbom:<file> -o json` with `GRYPE_DB_CACHE_DIR=<home>/db/current`, auto-update and update-check off, a scrubbed environment, an argument list (no shell), a timeout, and a cap on output size. A non-zero exit or a timeout fails that document.

**Native JSON, strictly parsed.** The output is validated against a JSON Schema this plugin authors for exactly the fields it reads (`matches[].vulnerability` id, severity, `knownExploited`, `epss`, `fix`, `dataSource`; `relatedVulnerabilities`; `matches[].artifact` name, version, type, purl; `descriptor.version`). The descriptor version must equal the pin. Unparseable output, a missing required field, or an unexpected shape fails that document closed: its targets are `not-scanned`, nothing is inferred from a partial parse.

**Mapping back.** A match maps to its grid target by the artifact's purl against the node's kept purl (computing_core keeps the whole purl), falling back to the node's natural key. A match that maps to no target is counted on the run as `unmapped` and the run ends `partial`; it is never dropped silently.

**Landing.** The run, scanner link, findings, edges and coverage land as one batch. Vulnerability creation rides the same batch; vulnerability patches use the partial-patch path (`req-grype-vulnerability`). Whether the service layer carries both in one atomic batch is settled against the code at build; if it cannot, findings land first and a failed patch step ends the run `partial`, never silently complete.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-grype-collector-1 | Pure Function Of Grid State | Proposed | Two runs over unchanged rows, the same binary and the same database build produce identical finding sets, with egress blocked. | |
| req-grype-collector-2 | Whole Grid, Per Operating System | Proposed | Every live package and library is a target; one document is built per operating system; a target under two is scanned in both and yields one finding per vulnerability. | |
| req-grype-collector-3 | Scratch Is Ephemeral And Isolated | Proposed | The scratch tree is per run; two concurrent runs never share a path; none remains after a run or a failed run. | |
| req-grype-collector-4 | Fails Closed | Proposed | Truncated JSON, a wrong descriptor version, a missing required field and a non-zero exit each leave that document's targets `not-scanned` and write no finding for it. | Fixtures for each. |
| req-grype-collector-5 | Mapping, With Unmapped Counted | Proposed | Matches map by purl then natural key; an unmappable match increments the run's unmapped count and the run ends `partial`. | |
| req-grype-collector-6 | Subprocess Hygiene | Proposed | Grype is run with an argument list and no shell, a scrubbed environment, a timeout and an output cap. | Grid data never enters a command line. |
| req-grype-collector-7 | Mixed Documents Never Resolve | Proposed | A target in two operating-system documents, one parsed and one failed, is `not-scanned` with reason `document-failed`; a prior finding absent from the parsed document stays `open`. | |

### Own Schedule And Its Guards
----
RID: `req-grype-trigger`

Status: `Proposed`

The collector runs on its own seeded schedule rather than a consumer's, because the finding set is a property of the pinned scanner and the database, not of any product's page: a database refresh changes what is true when no package changed. A fire that finds its inputs mid-write finalizes as skipped.

#### Implementation

This plugin's GRIFT (`grift/schedule.grift.json`, declared under `[grift]`) seeds two tap_cares `schedule` nodes: one targeting `grype:grype` (default cron `43 4 * * *`, off the hour, after the refresh) and the refresh schedule of `req-grype-database`. Both are user-editable and `max_active_runs` 1, and the `schedule-grift-targets` guard verifies their targets.

**Skip while upstream writes.** A fire that finds an upstream collection job active is finalized as skipped naming that job, and creates no run node. Upstream means the refresh job and any active job of a collector that writes the computing_core rows this scan reads. The set is derived, never authored: every collector whose declared outputs include computing_core node types. Whether tap_cares exposes a collector's declared outputs is NOT verified. If it does not, the build adds that derivation to tap_cares (the owning plugin) before this requirement is Implemented, and until then the fire fails closed, with the collection job failing and naming that the upstream set cannot be derived, rather than scanning on an authored list that can go stale. A torn read of computing_core must never mint findings or mark targets current.

**Source recorded.** The collection job's `results` (tap_cares-owned, lossless) names the upstream collection jobs whose rows were read, and joins to the run through the shared batch id; the run node itself carries no such field.

**The actor.** The collector runs as the collection job's actor, which must hold write capability on the compliance_core types it writes (vulnerability, scanner, scan run, finding and their edges, and, for edges, the target nodes only as endpoints) and read on computing_core. Which actor that is, and whether it holds those capabilities today, is NOT observed; first light (`req-grype-first-light`) is the proof, and the name of the actor is recorded in its notes.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-grype-trigger-1 | Seeded Schedules Fire | Proposed | After seeding, both schedule nodes exist with their default crons and a tick at a matching slot creates a `ScheduleFire` that runs the target collector. | |
| req-grype-trigger-2 | Skips While Upstream Writes | Proposed | With an upstream job active, a fire finalizes as skipped naming it and creates no run node. | |
| req-grype-trigger-3 | Source Recorded | Proposed | Every run's collection job names the upstream jobs whose rows it read. | Provenance, not only timing. |
| req-grype-trigger-4 | Actor Can Write | Proposed | The collector's actor is named and demonstrably writes the compliance_core types and reads the computing_core rows. | Proved at first light. |
| req-grype-trigger-5 | One Active Run | Proposed | A second fire while a run is active does not start a second run. | |
| req-grype-trigger-6 | Upstream Set Is Derived Or The Fire Fails | Proposed | The upstream set comes from collectors' declared outputs; if it cannot be derived the fire fails naming why and scans nothing. | No authored list exists to go stale. |

### Vulnerabilities, Minted And Patched
----
RID: `req-grype-vulnerability`

Status: `Proposed`

The plugin mints a vulnerability node when a match names one the grid does not hold, and patches the facts Grype supplies on existing ones as they change. The node is compliance_core's and is written by several sources, so the plugin writes only the fields it owns by contract and never overwrites another source's.

#### Implementation

**Identity.** `vuln_id` is the CVE id: the match's own id if it is a CVE, else the first CVE in `relatedVulnerabilities`, else the match id (a GHSA with no CVE). Every other id is an `aliases` entry (observed: a match id that is the GHSA with the CVE in `relatedVulnerabilities`).

**Alias-aware lookup.** Before minting, the collector looks for an existing node under any of the ids as `vuln_id` and any as an alias. A node found under one id is used and given the others as aliases; a vulnerability seen first by another producer under its GHSA must not become a second node when Grype names the CVE.

**Owned fields, written by partial patch.** `aliases` (union, never removed), `description` (only when `null`; once any source has written it, it is not replaced), `record_url` (Grype's `dataSource`), the KEV fields and the EPSS fields. The patch path is `patch_node`, whose omitted fields are unchanged; GRIFT's node lane is full-object and could blank CVSS or SSVC another source wrote, so it is not used on an existing vulnerability. Writes carry `entity_expected_version` so a concurrent writer is detected and re-read, never overwritten. CVSS, CWE and SSVC are other sources' facts (the CI-side enrichment, tap#1044) and this plugin does not write them.

**KEV.** A match carrying `knownExploited` sets `kev` true with `kev_added`, `kev_due_date`, `kev_required_action` and `kev_ransomware_use`. Grype omits the `knownExploited` key when the catalog does not list a vulnerability (observed 2026-10-15 in the recorded outputs: absent on all 91 matches of the tap-web output and on 19 of 21 of the log4j output, present on the two known-exploited GHSA-keyed matches). When the database loaded, meaning the document's `descriptor.db.status` is present, that omission is the catalog's answer, so the plugin sets `kev` false for a matched vulnerability with no block. That is an inference from the omission pattern, not a documented guarantee, so the corpus pins it on the recorded outputs, and a document without `descriptor.db.status` writes `null`, never `false`. A node previously true that Grype no longer lists is set false explicitly, so a delisting is visible. `kev_catalog_version` is the database build as `grype-db:<data_version>`; that is a proxy, since Grype exposes no catalog release, and the spec names it so (presence is not correctness).

**EPSS.** An `epss` entry whose `cve` equals `vuln_id` sets `epss_score`, `epss_percentile` and `epss_date` from it. No entry leaves the three `null`; the plugin never writes `0` for an unread score.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-grype-vulnerability-1 | CVE Key, GHSA Alias | Proposed | A GHSA-named match with a CVE in `relatedVulnerabilities` yields one node keyed by the CVE with the GHSA as an alias. | The log4j fixture. |
| req-grype-vulnerability-2 | No Duplicate By Alias | Proposed | A vulnerability already on the grid under its GHSA, or as an alias, is reused, never minted again. | |
| req-grype-vulnerability-3 | Partial Patch Only | Proposed | Patching KEV and EPSS leaves another source's CVSS, CWE and SSVC fields unchanged. | Node pre-seeded with those fields. |
| req-grype-vulnerability-4 | Null Is Never False | Proposed | A vulnerability with no `epss` entry keeps `epss_*` `null`; none is written as `0`. | |
| req-grype-vulnerability-5 | KEV True, False, Delisted | Proposed | `knownExploited` sets true with its details; a matched id with none sets false only when the document reported its database; a document without `descriptor.db.status` writes `null`; a node true that is no longer listed is set false. | Pinned on the recorded outputs. |
| req-grype-vulnerability-6 | Concurrent Writers Detected | Proposed | A patch whose node changed since it was read fails with the version conflict, is re-read and re-planned, and is never forced. | |

### The Finding
----
RID: `req-grype-finding`

Status: `Proposed`

A finding is one vulnerability asserted against one scan target, keyed by that assertion. It is written under the source `grype` only: other producers keep their own findings, and the same vulnerability on the same package is correlated by traversing the shared vulnerability and target nodes, not by sharing a key.

#### Implementation

A `compliance_finding` with `source` `grype` and `source_key` a compact JSON array of the vulnerability id, the target's entity type and each field of the target's natural key, in order, for example `["CVE-2026-1234","computing_core__package","apk","libssl3","3.5.4-r0"]`. The array form is the canonical encoding: a delimiter-joined string would let two different tuples (`a|b`, `c` and `a`, `b|c`) share one key and resolve or reopen each other's findings. The run is never in the key, and neither are the Grype version or the database build, so a finding is the same node across reruns and across scanner updates. Its `name` is `<vuln_id> in <target name> <version>`, its `summary` carries Grype's severity and fix state as the scanner's statement and not a verdict, and `status` is `open` or `resolved`.

Edges: `CONCERNS_COMPLIANCE_VULNERABILITY` to the vulnerability, with `fixed_versions` as the match's fix versions when Grype says fixed, `[]` when it says not fixed or won't fix (looked, none), and absent when the fix state is unknown; `CARRIES_COMPLIANCE_FINDING` from the target to the finding; `REPORTS_COMPLIANCE_FINDING` from the run (`req-grype-lifecycle`). Several matches of one vulnerability on one target (different match details) collapse to one finding.

**Correlation.** Findings from the CI SBOM pipeline or an alert source are separate nodes under their own `source`. That the same CVE, component version and image coincide is read by traversal from the one vulnerability node and the one package node, and the acceptance test shows it with a CI-shaped finding beside this one. No second finding identity is minted, and none is merged.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-grype-finding-1 | Not Run-Scoped | Proposed | Two runs over the same unchanged match produce the same finding node, with the same key. | |
| req-grype-finding-2 | Source-Namespaced | Proposed | Every finding has `source` `grype`; a finding of another source with the same vulnerability and package is a separate node. | |
| req-grype-finding-3 | Fixed Versions Tri-State | Proposed | `fixed_versions` is the list for a fixed match, `[]` for not-fixed or won't-fix, and absent for unknown. | |
| req-grype-finding-4 | Duplicate Matches Collapse | Proposed | Several matches of one vulnerability on one target yield one finding. | |
| req-grype-finding-5 | Correlated By Graph | Proposed | A query from the vulnerability and package nodes returns this finding and a CI-shaped finding together, with no shared key. | Fixture of a second producer. |
| req-grype-finding-6 | Key Cannot Collide | Proposed | Two targets whose natural-key fields differ only in where a `|` falls produce different `source_key` values, because the key is a JSON array; a key over 512 characters is refused, not truncated. | |

### Findings Resolve Only What Was Scanned
----
RID: `req-grype-lifecycle`

Status: `Proposed`

A finding closes only when its target was scanned successfully and no longer matches. A target that could not be scanned keeps whatever it had and is recorded as not scanned. Nothing is deleted: a fixed finding is `resolved`, a returning one is reopened.

#### Implementation

After a run of outcome `ok` or `partial`, for each target whose coverage outcome is `scanned`: its `open` findings from this plugin that were not matched this run become `resolved`; a `resolved` finding that matched again becomes `open`; a match with no existing finding mints one `open`. A target whose outcome is `not-scanned` or `failed` is untouched.

compliance_core keeps only the latest run's `REPORTS_COMPLIANCE_FINDING` per finding, and its edge definitions cannot refuse a second. The collector therefore deletes the earlier reporting edge for each re-matched finding in the same batch, through the batch's `deletes` section and not a hand-rolled delete. A resolved finding keeps the edge to the last run that saw it.

**Net-new and first-seen** are derived: a finding is net-new in a run when that run's batch created it, and its first-seen is its creation in the grid's history. No field is stored for either.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-grype-lifecycle-1 | Resolve Only When Scanned | Proposed | A finding whose target was `scanned` and no longer matches becomes `resolved`. | |
| req-grype-lifecycle-2 | Not-Scanned Is Untouched | Proposed | A target `not-scanned` or `failed` keeps its findings' status unchanged. | The guard against closing what was never looked at. |
| req-grype-lifecycle-3 | Reopen | Proposed | A `resolved` finding that matches again becomes `open`. | |
| req-grype-lifecycle-4 | Latest Run Only | Proposed | After two runs, a re-matched finding has one `REPORTS_COMPLIANCE_FINDING` edge, to the latest run, the old one removed through `deletes`. | |
| req-grype-lifecycle-5 | Net-New Is Derived | Proposed | The findings created by a run's batch are exactly its net-new set, readable with no stored field. | |

### Scanner, Run And Coverage
----
RID: `req-grype-run`

Status: `Proposed`

One scanner node says which installed Grype this is; every execution is a scan run node; and every target gets exactly one coverage edge to the latest run that examined it, carrying that run's outcome for it. Coverage is what lets "not scanned" be a recorded fact and never an absence.

#### Implementation

**Scanner.** One `compliance_scanner` with `source` `grype`, `scanner_key` `grype-tap`, `name` `Grype`, seeded by this plugin's GRIFT. It never carries a version. `locator` records `<home>` for readers and is never used to execute or locate anything. `configuration` holds only `staleness_hours` (48), which changes how the derived staleness reads and nothing about what runs; the operator-only settings are in `<home>/settings.json` (`req-grype-binary`). `PERFORMS_COMPLIANCE_SCAN_RUN` links it to each run.

**Run.** One `compliance_scan_run` per execution: `source` `grype`, `run_key` a UUIDv7 minted for the run, `category` `grype-grid`, `tool_version` from `grype --version`, `observed_at`, `outcome` (`ok`: every target scanned; `partial`: some not scanned or unmapped; `failed`: no document parsed; `db-stale`; `db-unavailable`), `results_count` (matches), and `data_version` and `data_built_at` from the documents' own `descriptor.db.status`. `commit_sha` and `ref` stay `null`. These two fields and the coverage edge are compliance_core's additions for this plugin (PR# 39 - compliance-core-tap, not yet released at authoring).

**Coverage.** `SCANNED_COMPLIANCE_TARGET` from the run to each target, with `outcome` (`scanned`, `not-scanned`, `failed`) and, when not scanned, a `reason` (`document-failed`, `unmapped`). A target has exactly one such edge per scanner: the batch deletes only the previous coverage edge whose run belongs to this plugin's scanner (source `grype`), for each target it touches, and never another scanner's edge to the same target. A run that ended `db-stale` or `db-unavailable` writes none, so the previous coverage stands and ages.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-grype-run-1 | One Run Per Execution | Proposed | An executed scan creates one run node under the scanner, with the outcome vocabulary above. | A skipped fire creates none. |
| req-grype-run-2 | Versions Recorded | Proposed | The run's `tool_version` equals the binary's reported version and its `data_version` and `data_built_at` equal the database the documents reported in `descriptor.db.status`. | |
| req-grype-run-3 | Per-Target Outcome | Proposed | Every target of a completed run has a coverage edge with `scanned`, `not-scanned` or `failed`, and `not-scanned` carries a reason. | |
| req-grype-run-4 | One Coverage Edge Per Scanner | Proposed | After two runs a target has one coverage edge from this scanner's runs, to the later run, and a coverage edge from another scanner's run to the same target is left untouched. | |
| req-grype-run-5 | Scanner Carries No Version | Proposed | The scanner node has no version field value and its settings are read from `configuration`. | |

### Staleness Is Derived
----
RID: `req-grype-staleness`

Status: `Proposed`

A package or library that has not been scanned within the cadence reads as stale, never clean. The state is derived by query from the latest coverage edge from this scanner's runs and that run; nothing is stored on the package or library nodes, which computing_core owns.

#### Implementation

Four coverage states per target: `scanned-current` (latest coverage outcome `scanned`, its run `ok` or `partial`, `observed_at` within `staleness_hours`), `stale` (the same but older), `not-scanned` (latest outcome `not-scanned` or `failed`), and `never-scanned` (no coverage edge). A target with open findings and a `stale` state shows both: findings are not hidden by age. The query is written in Gryphon and lives in the tests as the executable definition; the plugin seeds no page or search for it.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-grype-staleness-1 | Four States | Proposed | On a fixture with one target in each state, the query returns exactly those four. | |
| req-grype-staleness-2 | Never-Scanned Is Not Clean | Proposed | A package added after the last run reads `never-scanned` and is absent from any "clean" result. | |
| req-grype-staleness-3 | Derived, Not Stored | Proposed | A run patches no package or library node and adds no `last_scanned` field to either. | A write-trace test. |

### The Corpus Proof
----
RID: `req-grype-corpus`

Status: `Proposed`

Two tiers. The recorded tier feeds Grype's real native JSON, recorded once, through the parser and the lifecycle and always runs. The live tier runs the real binary and database and reproduces the recorded counts, and when either is absent it is skipped loudly on ordinary CI, and in the nightly job a skipped live tier is a failure: the job asserts after the run that the live tests executed, so the proof cannot be lost by a skip reported as success. Fixtures never ship in or seed a live grid; the suite seeds nodes in its own transaction.

#### Implementation

Fixtures in `tap_plugin/grype/tests/`: Grype v0.120.1 native JSON recorded from the tap-web SBOM (91 matches over 27 vulnerability ids) and from the log4j-core 2.14.1 SBOM (KEV, EPSS, GHSA with the CVE in `relatedVulnerabilities`), each with the recording's date and database build in a header. The recorded tier maps them onto package nodes seeded from the SBOM through computing_core's parser. The live tier is a nightly job in the repository's CI where the binary and database are installed, and a marker that skips with a named reason elsewhere.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-grype-corpus-1 | Log4j Round Trip | Proposed | The recorded log4j output yields one CVE-keyed vulnerability with KEV details, EPSS and the GHSA alias, and a finding on its package. | |
| req-grype-corpus-2 | tap-web Recorded Output | Proposed | The recorded tap-web output yields 27 vulnerabilities and the expected findings, with every match mapped or counted unmapped. | |
| req-grype-corpus-3 | Live Tier Reproduces | Proposed | With the binary and database present the live tier reproduces 91 matches over 27 ids on the same SBOM, within the tolerance the database build allows, and reports skipped with a reason otherwise on ordinary CI; the nightly job fails if the live tier did not execute. | The database moves daily; the tolerance is stated with the recorded build. |
| req-grype-corpus-4 | Fail-Closed Fixtures | Proposed | A truncated JSON, a wrong descriptor version and an empty output each leave targets not-scanned. | |

### First Light
----
RID: `req-grype-first-light`

Status: `Proposed`

The plugin has executed against the live grid once, unattended, and the counts it produced are recorded. A schedule that exists but has not been seen firing is a declaration that is false until proven. This waits on the builder and compliance_core releases, the binary and a database being installed, and an SBOM-built package inventory on the grid.

#### Implementation

After the prerequisites, a scheduler tick at the scan's slot produces a `ScheduleFire`, a collection job that reaches `SUCCESSFUL`, and a run node with its counts. A second run afterwards creates no duplicate finding and moves no unchanged finding. The notes record the observed date, counts, database build and the actor.

#### Acceptance Criteria

| ACID | Title | Status | Description | Notes |
| --- | --- | :---: | --- | --- |
| req-grype-first-light-1 | Fires Unattended | Proposed | A scheduler tick produces a `ScheduleFire`, a `CollectionJob` that reaches `SUCCESSFUL`, and a run node carrying its counts. | Observed date and counts recorded here when seen. |
| req-grype-first-light-2 | Second Run Is Idempotent | Proposed | A second run creates no duplicate finding and leaves an unchanged finding unchanged. | |

### Delivery By Sidecar
----
RID: `req-grype-sidecar`

Status: `Backlog`

When docker sidecars are available, Grype is delivered as a pinned sidecar image by digest and the release-binary installer is retired. The same version gate, the same recorded database build and the same scan contract apply. Not designed here; the first cut is the release binary because no packaging channel for a Go binary exists yet.

### Binary Sandbox
----
RID: `req-grype-sandbox`

Status: `Backlog`

Every Grype invocation, the scan and the database refresh alike, runs inside the standard plugin-binary sandbox once it exists: Landlock for the filesystem and a self-applied seccomp filter for syscalls, as tap#858 settled and `req-tap-plugin-manifest-capability-declaration` would declare. The wrapper is a shared tap_plugins deliverable, not something this plugin builds privately, so this row is Backlog until that lands. The interim controls are the ones in `req-grype-collector-6` and `req-grype-database-4`.

**Fail closed (ruled by George, 2026-10-15).** Once the sandbox is adopted, a run on a kernel that cannot apply it refuses to scan: the collection job fails naming the missing capability, no run node is created that claims a result, and no finding, vulnerability or coverage edge is written. There is no unsandboxed fallback and no "ran without it" mode.

**Intended profile, to be verified at adoption.** The scan: no `socket` or `connect` (so "scans never fetch" is enforced and no longer only tested); read the binary, the installed database directory and its own scratch tree; write only the scratch tree. Whether Grype writes anything into the database directory with auto-update off is NOT verified and is tested first. The refresh: network only, with TCP connect limited to port 443 by Landlock where the kernel supports it; hostname-level control of `grype.anchore.io` belongs to the operator's egress proxy or firewall, driven by the capability declaration. The launcher is a separate process that restricts itself and then execs Grype, because restrictions are inherited across exec and must not be applied to the collector's own threaded worker.

### v0 Non-Goals
----
RID: `req-grype-nongoals`

Status: `Proposed`

This plugin does not: ship pages or panels; build or parse SBOMs (computing_core); define the vulnerability, finding, scanner or scan-run types or their fields (compliance_core); poll the CISA catalog on its own (the standalone KEV updater is cancelled, Grype's database carries KEV); write CVSS, CWE or SSVC (CI-side enrichment, tap#1044); decide what is deployed; replace Trivy as the CI image scan and release gate; or hold any credential. Each belongs to the system named.

## Reference data

| Document | Contents | Seeded by |
| --- | --- | --- |
| `grift/schedule.grift.json` | The two schedule nodes of `req-grype-database` and `req-grype-trigger` | Plugin GRIFT (`[grift]`) |
| `grift/scanner.grift.json` | The scanner node and its `configuration` of `req-grype-run` | Plugin GRIFT (`[grift]`) |
