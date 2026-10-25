"""Where the plugin's home is (req-grype-binary): the argument, then the environment, then HOME."""

from pathlib import Path

from tap_plugin.grype.home import DEFAULT_SUBPATH, HOME_ENV, resolve_home


class TestResolveHome:
    def test_an_argument_wins(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv(HOME_ENV, str(tmp_path / "env"))
        assert resolve_home(tmp_path / "arg") == tmp_path / "arg"

    def test_the_environment_is_next(self, monkeypatch, tmp_path) -> None:
        monkeypatch.setenv(HOME_ENV, str(tmp_path / "env"))
        assert resolve_home() == tmp_path / "env"

    def test_the_default_is_under_the_runtime_users_home(self, monkeypatch) -> None:
        monkeypatch.delenv(HOME_ENV, raising=False)
        assert resolve_home() == Path.home() / DEFAULT_SUBPATH

    def test_an_empty_variable_is_the_default(self, monkeypatch) -> None:
        monkeypatch.setenv(HOME_ENV, "")
        assert resolve_home() == Path.home() / DEFAULT_SUBPATH
