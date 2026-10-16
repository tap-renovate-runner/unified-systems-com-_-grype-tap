"""The pinned Grype binary: pin file, installer, settings and pin tool (req-grype-binary).

Plain ``unittest`` and stdlib only on purpose: these modules need no Django, so the same file runs
under pytest in CI and under ``python3 -m unittest`` on any machine. Every archive is built in memory
and every download is a fake; nothing here touches the network.
"""

import hashlib
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path

from tap_plugin.grype import binary_pin, installer, pin_tool, settings
from tap_plugin.grype.binary_pin import Asset, Pin, PinError

try:
    import jsonschema
except ImportError:  # the schema half of the agreement test is skipped, loudly, where this is absent
    jsonschema = None

VERSION = "v9.9.9"
PLATFORM = "linux/amd64"
GOOD_BINARY = b"#!/bin/sh\necho grype 9.9.9\n"


def make_archive(members: list[tuple[tarfile.TarInfo, bytes | None]]) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for info, payload in members:
            archive.addfile(info, io.BytesIO(payload) if payload is not None else None)
    return buffer.getvalue()


def file_member(name: str, payload: bytes) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    info.mode = 0o755
    return info, payload


def special_member(name: str, kind: bytes, linkname: str = "") -> tuple[tarfile.TarInfo, None]:
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = linkname
    return info, None


def pin_for(archive: bytes, version: str = VERSION, binary: bytes = GOOD_BINARY) -> Pin:
    url = binary_pin.expected_asset_url(version, PLATFORM)
    return Pin(
        version=version,
        checksums_url=binary_pin.expected_checksums_url(version),
        assets={
            PLATFORM: Asset(
                url=url, sha256=hashlib.sha256(archive).hexdigest(), binary_sha256=hashlib.sha256(binary).hexdigest()
            )
        },
    )


class FakeFetch:
    def __init__(self, payload: bytes | Exception) -> None:
        self.payload = payload
        self.calls = 0

    def __call__(self, url: str) -> bytes:
        self.calls += 1
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


class TempHome(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        self.home = self.root / "home"


class TestPinFile(unittest.TestCase):
    def test_the_shipped_pin_loads_and_names_both_platforms(self) -> None:
        pin = binary_pin.load_pin()
        self.assertRegex(pin.version, r"^v\d+\.\d+\.\d+$")
        self.assertEqual(set(pin.assets), set(binary_pin.PLATFORMS))
        for platform, asset in pin.assets.items():
            self.assertEqual(asset.url, binary_pin.expected_asset_url(pin.version, platform))

    def _valid(self) -> dict:
        return json.loads(binary_pin.PIN_PATH.read_text(encoding="utf-8"))

    def test_each_inconsistency_is_refused(self) -> None:
        def broken(change) -> dict:
            data = self._valid()
            change(data)
            return data

        cases = {
            "unknown key": lambda d: d.update(extra=1),
            "no description": lambda d: d.update(description=""),
            "bad version": lambda d: d.update(version="0.120.1"),
            "checksums url for another version": lambda d: d.update(checksums_url=d["checksums_url"].replace("0.", "1.")),
            "unsupported platform": lambda d: d["platforms"].update({"windows/amd64": d["platforms"]["linux/amd64"]}),
            "url for another version": lambda d: d["platforms"]["linux/amd64"].update(
                url=d["platforms"]["linux/amd64"]["url"].replace("0.120", "0.119")
            ),
            "short sha": lambda d: d["platforms"]["linux/amd64"].update(sha256="abc"),
            "short binary sha": lambda d: d["platforms"]["linux/amd64"].update(binary_sha256="abc"),
            "no binary sha": lambda d: d["platforms"]["linux/amd64"].pop("binary_sha256"),
            "uppercase sha": lambda d: d["platforms"]["linux/amd64"].update(
                sha256=d["platforms"]["linux/amd64"]["sha256"].upper()
            ),
            "extra platform key": lambda d: d["platforms"]["linux/amd64"].update(extra="x"),
        }
        for label, change in cases.items():
            with self.subTest(label), self.assertRaises(PinError):
                binary_pin.parse_pin(broken(change))

    @unittest.skipUnless(jsonschema, "jsonschema is not importable here, so the schema half is NOT checked")
    def test_the_schema_and_the_validator_agree_on_the_shipped_pin(self) -> None:
        schema = json.loads(Path(binary_pin.__file__).with_name("binary.schema.json").read_text(encoding="utf-8"))
        data = self._valid()
        jsonschema.validate(data, schema)
        data["platforms"]["linux/amd64"]["sha256"] = "nope"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(data, schema)


class TestInstaller(TempHome):
    def test_a_good_archive_installs_and_links(self) -> None:
        archive = make_archive([file_member("LICENSE", b"mit"), file_member("grype", GOOD_BINARY)])
        pin = pin_for(archive)
        path = installer.install(self.home, pin, platform=PLATFORM, fetch=FakeFetch(archive))
        self.assertEqual(path, self.home / "bin" / f"grype-{VERSION}")
        self.assertEqual(path.read_bytes(), GOOD_BINARY)
        self.assertTrue(os.access(path, os.X_OK))
        link = self.home / "bin" / "grype"
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), path.name)
        self.assertEqual(sorted(p.name for p in (self.home / "bin").iterdir()), sorted([path.name, "grype"]))

    def test_a_second_run_is_idempotent_and_does_not_download(self) -> None:
        archive = make_archive([file_member("grype", GOOD_BINARY)])
        pin = pin_for(archive)
        installer.install(self.home, pin, platform=PLATFORM, fetch=FakeFetch(archive))
        again = FakeFetch(archive)
        installer.install(self.home, pin, platform=PLATFORM, fetch=again)
        self.assertEqual(again.calls, 0)
        self.assertEqual(len(list((self.home / "bin").iterdir())), 2)

    def test_a_replaced_binary_does_not_survive_a_reinstall(self) -> None:
        archive = make_archive([file_member("grype", GOOD_BINARY)])
        pin = pin_for(archive)
        path = installer.install(self.home, pin, platform=PLATFORM, fetch=FakeFetch(archive))
        path.write_bytes(b"#!/bin/sh\necho owned\n")
        again = FakeFetch(archive)
        installer.install(self.home, pin, platform=PLATFORM, fetch=again)
        self.assertEqual(again.calls, 1, "a file that differs from the pin must be replaced from a fresh download")
        self.assertEqual(path.read_bytes(), GOOD_BINARY)
        self.assertEqual(os.readlink(self.home / "bin" / "grype"), path.name)

    def test_a_replaced_binary_with_no_reachable_download_is_not_trusted(self) -> None:
        archive = make_archive([file_member("grype", GOOD_BINARY)])
        pin = pin_for(archive)
        path = installer.install(self.home, pin, platform=PLATFORM, fetch=FakeFetch(archive))
        path.write_bytes(b"tampered")
        with self.assertRaises(OSError):
            installer.install(self.home, pin, platform=PLATFORM, fetch=FakeFetch(OSError("network down")))

    def test_an_archive_whose_binary_differs_from_the_pinned_binary_digest_is_refused(self) -> None:
        archive = make_archive([file_member("grype", GOOD_BINARY)])
        pin = pin_for(archive, binary=b"a different binary")
        with self.assertRaises(installer.InstallError):
            installer.install(self.home, pin, platform=PLATFORM, fetch=FakeFetch(archive))
        self.assertFalse((self.home / "bin").exists())

    def test_a_digest_mismatch_is_refused_and_writes_nothing(self) -> None:
        archive = make_archive([file_member("grype", GOOD_BINARY)])
        pin = pin_for(archive)
        tampered = make_archive([file_member("grype", GOOD_BINARY + b"x")])
        with self.assertRaises(installer.InstallError):
            installer.install(self.home, pin, platform=PLATFORM, fetch=FakeFetch(tampered))
        self.assertFalse((self.home / "bin").exists())

    def test_a_matching_digest_does_not_excuse_a_dangerous_archive(self) -> None:
        dangerous = {
            "absolute path": [file_member("/etc/grype-owned", b"x"), file_member("grype", GOOD_BINARY)],
            "dot-dot member": [file_member("../escape", b"x"), file_member("grype", GOOD_BINARY)],
            "dot-dot inside a path": [file_member("a/../../escape", b"x"), file_member("grype", GOOD_BINARY)],
            "symlink": [special_member("lnk", tarfile.SYMTYPE, "/etc/passwd"), file_member("grype", GOOD_BINARY)],
            "hard link": [special_member("hl", tarfile.LNKTYPE, "grype"), file_member("grype", GOOD_BINARY)],
            "device file": [special_member("dev", tarfile.CHRTYPE), file_member("grype", GOOD_BINARY)],
            "fifo": [special_member("pipe", tarfile.FIFOTYPE), file_member("grype", GOOD_BINARY)],
        }
        for label, members in dangerous.items():
            with self.subTest(label):
                archive = make_archive(members)
                pin = pin_for(archive)
                with self.assertRaises(installer.InstallError):
                    installer.install(self.home, pin, platform=PLATFORM, fetch=FakeFetch(archive))
                self.assertFalse((self.home / "bin").exists())
                self.assertEqual([p.name for p in self.root.iterdir()], [])  # nothing escaped beside `home`

    def test_an_archive_with_no_top_level_grype_is_refused(self) -> None:
        archive = make_archive([file_member("sub/grype", GOOD_BINARY), file_member("LICENSE", b"mit")])
        with self.assertRaises(installer.InstallError):
            installer.install(self.home, pin_for(archive), platform=PLATFORM, fetch=FakeFetch(archive))

    def test_a_failed_download_leaves_the_previous_binary_in_place(self) -> None:
        old = make_archive([file_member("grype", GOOD_BINARY)])
        installer.install(self.home, pin_for(old, "v9.9.8"), platform=PLATFORM, fetch=FakeFetch(old))
        new = make_archive([file_member("grype", GOOD_BINARY + b"2")])
        with self.assertRaises(OSError):
            installer.install(
                self.home, pin_for(new, binary=GOOD_BINARY + b"2"), platform=PLATFORM, fetch=FakeFetch(OSError("network down"))
            )
        link = self.home / "bin" / "grype"
        self.assertEqual(os.readlink(link), "grype-v9.9.8")
        self.assertEqual(link.read_bytes(), GOOD_BINARY)

    def test_an_unpinned_platform_is_refused(self) -> None:
        archive = make_archive([file_member("grype", GOOD_BINARY)])
        with self.assertRaises(installer.InstallError):
            installer.install(self.home, pin_for(archive), platform="linux/arm64", fetch=FakeFetch(archive))

    def test_a_non_https_url_is_refused_before_any_connection(self) -> None:
        with self.assertRaises(installer.InstallError):
            installer.fetch_url("http://example.invalid/grype.tar.gz")


class TestSettings(TempHome):
    def test_defaults_when_no_file_exists(self) -> None:
        loaded = settings.load_settings(self.home)
        self.assertEqual((loaded.database_max_age_days, loaded.database_mirror), (3, None))

    def test_the_default_file_is_written_once_and_never_overwrites_a_choice(self) -> None:
        self.assertTrue(settings.write_default_settings(self.home))
        (self.home / settings.SETTINGS_NAME).write_text(json.dumps({"database_max_age_days": 7}), encoding="utf-8")
        self.assertFalse(settings.write_default_settings(self.home))
        self.assertEqual(settings.load_settings(self.home).database_max_age_days, 7)

    def test_bad_values_are_refused(self) -> None:
        for label, data in {
            "unknown key": {"surprise": 1},
            "zero days": {"database_max_age_days": 0},
            "too many days": {"database_max_age_days": 366},
            "boolean days": {"database_max_age_days": True},
            "string days": {"database_max_age_days": "3"},
            "relative mirror": {"database_mirror": "mirror"},
            "numeric mirror": {"database_mirror": 5},
            "not an object": [],
        }.items():
            with self.subTest(label), self.assertRaises(settings.SettingsError):
                settings.parse_settings(data)

    def test_a_mirror_directory_is_accepted_when_absolute(self) -> None:
        self.assertEqual(settings.parse_settings({"database_mirror": "/srv/grype-mirror"}).database_mirror, "/srv/grype-mirror")


class TestPinTool(unittest.TestCase):
    def _release(self, version: str, tamper: str | None = None, drop: str | None = None) -> "dict[str, bytes]":
        files: dict[str, bytes] = {}
        lines = []
        for platform in binary_pin.PLATFORMS:
            archive = make_archive([file_member("grype", GOOD_BINARY + platform.encode())])
            name = binary_pin.archive_name(version, platform)
            files[binary_pin.expected_asset_url(version, platform)] = (archive + b"!") if tamper == platform else archive
            if name != drop:
                lines.append(f"{hashlib.sha256(archive).hexdigest()}  {name}")
        files[binary_pin.expected_checksums_url(version)] = ("\n".join(lines) + "\n").encode()
        return files

    def _fetch(self, files: "dict[str, bytes]"):
        return lambda url: files[url]

    def test_a_pin_is_built_from_the_published_checksums_and_satisfies_the_contract(self) -> None:
        data = pin_tool.build_pin(VERSION, fetch=self._fetch(self._release(VERSION)))
        pin = binary_pin.parse_pin(data)
        self.assertEqual(pin.version, VERSION)
        self.assertEqual(set(pin.assets), set(binary_pin.PLATFORMS))
        for platform, asset in pin.assets.items():
            self.assertEqual(asset.binary_sha256, hashlib.sha256(GOOD_BINARY + platform.encode()).hexdigest())

    def test_an_archive_that_differs_from_the_published_digest_is_refused(self) -> None:
        with self.assertRaises(PinError):
            pin_tool.build_pin(VERSION, fetch=self._fetch(self._release(VERSION, tamper="linux/arm64")))

    def test_a_missing_checksum_line_is_refused(self) -> None:
        name = binary_pin.archive_name(VERSION, "linux/amd64")
        with self.assertRaises(PinError):
            pin_tool.build_pin(VERSION, fetch=self._fetch(self._release(VERSION, drop=name)))

    def test_a_malformed_checksums_line_is_refused(self) -> None:
        with self.assertRaises(PinError):
            pin_tool.parse_checksums("not-a-digest grype.tar.gz\n")

    def test_the_renovate_manager_matches_the_shipped_pin(self) -> None:
        import re

        text = (Path(binary_pin.__file__).resolve().parents[2] / "renovate.json5").read_text(encoding="utf-8")
        pattern = re.search(r'matchStrings: \["(.+)"\],', text)
        self.assertIsNotNone(pattern)
        regex = pattern.group(1).replace('\\"', '"').replace("\\\\", "\\")
        regex = regex.replace("(?<", "(?P<")  # Renovate's JavaScript named groups, spelled the Python way
        match = re.search(regex, binary_pin.PIN_PATH.read_text(encoding="utf-8"))
        self.assertIsNotNone(match)
        self.assertEqual(match.group("currentValue"), binary_pin.load_pin().version)


if __name__ == "__main__":
    unittest.main()
