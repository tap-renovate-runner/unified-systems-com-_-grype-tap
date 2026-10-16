# grype-tap

A TAP plugin that runs Grype against the packages and libraries already on the grid, on a schedule,
and writes the answer back: scan runs, findings, vulnerabilities with their KEV and EPSS facts, and
per-target coverage so that "not scanned" never reads as "clean". Software deployed in the field does
not pass through a CI deploy, so new CVEs accumulate against it; this is the loop that rescans it.

**What it owns.** The collector, its schedules, its pinned Grype binary and database refresh, and the
lifecycle of the findings it writes. **What lives elsewhere.** The package, library and operating-system
types and the SBOM builder are computing_core's; the vulnerability, scanner, scan-run and finding types
are compliance_core's. It ships no pages and no types of its own.

**Read first.** `specs/spec-grype-v0.md` is the canon; the code is checked against it. Status of each
requirement is in its table; nothing is built until it is marked.

**Stand it up.** Develop it in a TAP session. Everything below was run on 2026-10-16 (Docker Desktop, macOS).

```sh
scripts/spawn-session.sh <label> cli --from 'git+https://github.com/unified-systems-com/grype-tap@main#ci' --dev-plugins grype
```

Two things the spawn will not tell you until it fails:

- `--from` clones a **branch or tag name**. A commit sha fails at the stage-0 fetch (`Remote branch <sha> not found`). This repository has no release tag yet, so use `main`.
- The `ci` record pins this plugin at a commit, and the spawn clones `_dev-plugins/grype` at **that** commit, which can predate the package. Pre-boot then aborts with `/app/_dev-plugins/grype does not appear to be a Python project`. Move the clone to the code under test and bring the stack up again:

  ```sh
  git -C _dev-plugins/grype checkout main        # or your branch
  scripts/dc up -d
  ```

Then run the whole suite in the `web` container, one pytest at a time per stack:

```sh
scripts/dc exec -T web uv run pytest -p no:cacheprovider --pyargs tap_plugin.grype
```

The modules that import no Django (binary, database, mirror, output, facts, targets, scan) also run on the host with the standard library only:
`PYTHONPATH=. python3 -m unittest tap_plugin.grype.tests.test_output tap_plugin.grype.tests.test_scan tap_plugin.grype.tests.test_database tap_plugin.grype.tests.test_binary`.

Grype is not a Python dependency; see `req-grype-binary` for how the pinned release binary is placed.
