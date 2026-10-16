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

**Stand it up.** Develop it in a TAP session with
`spawn-session.sh <label> --from 'git+https://github.com/unified-systems-com/grype-tap@<rev>#ci' --dev-plugins grype`,
then `pytest --pyargs tap_plugin.grype` in the `web` container. Grype is not a Python dependency; see
`req-grype-binary` for how the pinned release binary is placed.
