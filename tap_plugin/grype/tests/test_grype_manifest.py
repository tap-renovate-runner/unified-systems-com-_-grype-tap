"""Plugin validation-system tests (new-plugin skill, Step 9): structure and strict levels.

`loads` / `runs` levels need an installed, booted plugin; structure-level works standalone.
"""

from pathlib import Path

from tap_plugins.validate.service import validate_plugin

# The plugin PACKAGE directory (tap_plugin/grype), which validate_plugin accepts and which
# resolves the same way from an editable checkout and from an installed wheel
# (`pytest --pyargs tap_plugin.grype` in CI). The package-identity chain (slug / dist /
# entry point / namespace) needs the project root and is checked by CI's conformance job
# against the checkout, not here.
PLUGIN_ROOT = Path(__file__).resolve().parents[1]


class TestStructure:
    def test_structure_passes(self) -> None:
        result = validate_plugin(PLUGIN_ROOT, level="structure")
        if not result.ok:
            raise AssertionError(result.to_human())

    def test_strict_passes(self) -> None:
        result = validate_plugin(PLUGIN_ROOT, level="structure", strict=True)
        if not result.ok:
            raise AssertionError(result.to_human())
