"""The operator step that places the pinned Grype binary (req-grype-binary).

    python -m tap_plugin.grype.installer --home /var/lib/tap/grype

Stdlib only (no Django), so it runs in an image build or at provisioning, never during a scan. It
downloads the archive the pin names for this platform, refuses on a sha256 mismatch, refuses an
archive carrying anything that could write outside its target even when the digest matches, extracts
only the single member named ``grype``, and atomically repoints ``<home>/bin/grype``. It is idempotent
and a failed run leaves the previously installed binary in place.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import platform as platform_module
import sys
import tarfile
import urllib.request
from collections.abc import Callable
from pathlib import Path, PurePosixPath

from tap_plugin.grype.binary_pin import PLATFORMS, Pin, PinError, load_pin
from tap_plugin.grype.settings import write_default_settings

MAX_ARCHIVE_BYTES = 200 * 1024 * 1024
FETCH_TIMEOUT_SECONDS = 120

Fetcher = Callable[[str], bytes]


class InstallError(RuntimeError):
    """The install was refused or failed; nothing was changed."""


def fetch_url(url: str) -> bytes:
    """Download a URL over https, capped in size. The only network call in this module."""
    if not url.startswith("https://"):
        raise InstallError(f"refusing a non-https URL: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "grype-tap-installer"})  # noqa: S310 - https only, checked above
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT_SECONDS) as response:  # noqa: S310
        data = response.read(MAX_ARCHIVE_BYTES + 1)
    if len(data) > MAX_ARCHIVE_BYTES:
        raise InstallError(f"{url} is larger than {MAX_ARCHIVE_BYTES} bytes; refusing it")
    return data


def host_platform() -> str:
    """The pin's platform key for this machine, e.g. ``linux/amd64``."""
    system = platform_module.system().lower()
    machine = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(
        platform_module.machine().lower(), platform_module.machine().lower()
    )
    key = f"{system}/{machine}"
    if key not in PLATFORMS:
        raise InstallError(f"no pinned Grype archive for {key}; supported: {list(PLATFORMS)}")
    return key


def check_members(archive: tarfile.TarFile) -> tarfile.TarInfo:
    """Refuse any archive that could write outside its target; return the single ``grype`` member.

    Every member is inspected, not only the one extracted: an archive carrying an absolute path, a
    ``..`` segment, a link of either kind, or a device or FIFO is refused outright, because a
    digest that matches the pin says the archive is the one pinned, not that it is safe.
    """
    binary: tarfile.TarInfo | None = None
    for member in archive.getmembers():
        path = PurePosixPath(member.name)
        if path.is_absolute() or member.name.startswith(("/", "\\")) or ".." in path.parts:
            raise InstallError(f"archive member {member.name!r} would escape the target; refusing the archive")
        if member.issym() or member.islnk():
            raise InstallError(f"archive member {member.name!r} is a link; refusing the archive")
        if member.ischr() or member.isblk() or member.isfifo():
            raise InstallError(f"archive member {member.name!r} is a special file; refusing the archive")
        if member.isfile() and path.name == "grype" and len(path.parts) == 1:
            if member.size > MAX_ARCHIVE_BYTES:
                raise InstallError("the grype member is implausibly large; refusing the archive")
            if binary is not None:
                raise InstallError("archive holds more than one top-level `grype`; refusing it")
            binary = member
    if binary is None:
        raise InstallError("archive holds no top-level `grype` file")
    return binary


def _repoint(link: Path, target_name: str) -> None:
    """Atomically make ``link`` a relative symlink to ``target_name`` in its own directory."""
    temporary = link.with_name(f".{link.name}.{os.getpid()}.tmp")
    try:
        if temporary.is_symlink() or temporary.exists():
            temporary.unlink()
        temporary.symlink_to(target_name)
        os.replace(temporary, link)
    finally:
        if temporary.is_symlink() or temporary.exists():
            temporary.unlink()


def install(home: Path, pin: Pin, *, platform: str, fetch: Fetcher = fetch_url) -> Path:
    """Place the pinned binary under ``<home>/bin`` and return its path.

    Idempotent: when ``bin/grype-<version>`` exists, ``bin/grype`` points at it and the file's sha256
    equals the pin's ``binary_sha256``, nothing is downloaded. A file that exists but differs from the
    pin is not trusted: it is replaced from a fresh, verified download. Any failure leaves the previous
    binary and link untouched.
    """
    if platform not in pin.assets:
        raise InstallError(f"the pin has no archive for {platform}")
    asset = pin.assets[platform]
    bin_dir = home / "bin"
    versioned = bin_dir / f"grype-{pin.version}"
    link = bin_dir / "grype"
    if (
        versioned.is_file()
        and link.is_symlink()
        and os.readlink(link) == versioned.name
        and hashlib.sha256(versioned.read_bytes()).hexdigest() == asset.binary_sha256
    ):
        return versioned

    data = fetch(asset.url)
    digest = hashlib.sha256(data).hexdigest()
    if digest != asset.sha256:
        raise InstallError(f"sha256 of {asset.url} is {digest}, the pin says {asset.sha256}; refusing it")
    try:
        archive = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")  # noqa: SIM115 - closed in the with below
    except tarfile.TarError as exc:
        raise InstallError(f"cannot read the archive: {exc}") from exc
    with archive:
        member = check_members(archive)
        stream = archive.extractfile(member)
        if stream is None:
            raise InstallError("the grype member cannot be read")
        binary = stream.read()
    binary_digest = hashlib.sha256(binary).hexdigest()
    if binary_digest != asset.binary_sha256:
        raise InstallError(f"the extracted grype hashes to {binary_digest}, the pin says {asset.binary_sha256}; refusing it")

    bin_dir.mkdir(parents=True, exist_ok=True)
    temporary = bin_dir / f".grype-{pin.version}.{os.getpid()}.tmp"
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o755)
        with os.fdopen(fd, "wb") as handle:
            handle.write(binary)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, versioned)
    finally:
        if temporary.exists():
            temporary.unlink()
    _repoint(link, versioned.name)
    return versioned


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Place the pinned Grype release binary (req-grype-binary).")
    parser.add_argument("--home", required=True, type=Path, help="operator-controlled directory on a persistent volume")
    args = parser.parse_args(argv)
    try:
        pin = load_pin()
        path = install(args.home, pin, platform=host_platform())
        wrote = write_default_settings(args.home)
    except (PinError, InstallError) as exc:
        print(f"grype installer: {exc}", file=sys.stderr)
        return 1
    print(f"installed {path}" + ("; wrote default settings.json" if wrote else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
