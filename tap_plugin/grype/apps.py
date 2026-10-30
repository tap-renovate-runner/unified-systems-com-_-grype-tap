"""TAP grype plugin AppConfig.

``name`` is derived from this module's package path and ``label`` / ``verbose_name`` come
from tap-plugin.toml (slug / name); nothing is authored here
(req-tap-plugin-manifest-v0-scaffold). The collectors register in ``ready()`` as they are built
(req-grype-collector, req-grype-database).
"""

from tap_plugins.base import TapPluginConfig


class GrypeConfig(TapPluginConfig):
    def ready(self) -> None:
        # Base ready() loads tap-plugin.toml and registers the plugin's models/edges.
        super().ready()

        # Imported inside ready(), not at module top, so the app-loading graph stays light.
        from tap_plugin.grype.collectors.grype_collector import GrypeCollector
        from tap_plugin.grype.collectors.refresh import GrypeDatabaseRefreshCollector

        from tap_cares.registry import register_collector

        register_collector(
            key="database_refresh",
            # Stable scope (the plugin slug), never inferred from the module path: the derived entity id is a
            # durable grid key and the schedule bundle's hardcoded target (req-grype-database-1).
            scope="grype",
            cls=GrypeDatabaseRefreshCollector,
            name="Grype Database Refresh Collector",
            description=(
                "Places the pinned Grype binary and installs a newer Grype advisory database build, or reports the "
                "installed one current. Lands no GRIFT batch; the collection job record carries the outcome."
            ),
        )

        register_collector(
            key="grype",
            scope="grype",
            cls=GrypeCollector,
            name="Grype Collector",
            description=(
                "Scans every package and library on the grid with the pinned Grype against the installed advisory "
                "database and writes the scan run, findings, vulnerabilities (with KEV and EPSS) and per-target "
                "coverage as one batch. Reads the grid; makes no network connection."
            ),
        )
