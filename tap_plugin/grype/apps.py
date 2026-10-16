"""TAP grype plugin AppConfig.

``name`` is derived from this module's package path and ``label`` / ``verbose_name`` come
from tap-plugin.toml (slug / name); nothing is authored here
(req-tap-plugin-manifest-v0-scaffold). The collectors register in ``ready()`` as they are built
(req-grype-collector, req-grype-database); this scaffold registers none.
"""

from tap_plugins.base import TapPluginConfig


class GrypeConfig(TapPluginConfig):
    pass
