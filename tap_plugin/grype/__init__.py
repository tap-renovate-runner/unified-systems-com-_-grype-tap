"""TAP grype plugin: a grid-native Grype scan of the packages on the grid.

Spec: specs/spec-grype-v0.md. A scheduled, derived collector builds throwaway SBOMs from the
packages and libraries already on the grid, runs a pinned Grype binary over them with no network,
and writes runs, findings, vulnerabilities and per-target coverage back. No pages, no credential.
"""
