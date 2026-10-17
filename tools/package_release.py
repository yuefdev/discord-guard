"""Produce an explicitly experimental, unsigned preview plus complete application source."""

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIRS = ("src", "tests", "native", "tools", "docs", ".github")
SOURCE_FILES = ("README.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "THIRD_PARTY_NOTICES.md",
                "requirements-build.txt", "pyproject.toml", "build.ps1", ".gitignore")


def source_files(root=ROOT):
    for name in SOURCE_FILES:
        path = root / name
        if path.is_file():
            yield path
    for directory in SOURCE_DIRS:
        for path in (root / directory).rglob("*"):
            if path.is_file() and not path.is_symlink() and not any(
                    piece in ("__pycache__", "build", "dist", ".pytest_cache") for piece in path.parts) \
                    and path.suffix not in (".pyc", ".pfx", ".key", ".pem", ".sys", ".exe", ".nupkg"):
                yield path


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def build_setup(staging: Path, output: Path, version: str) -> Path:
    manifest = {path.relative_to(staging).as_posix(): sha256(path)
                for path in sorted(staging.rglob("*")) if path.is_file()}
    (staging / "payload-sha256.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    name = f"DiscordGuard-{version}-Setup"
    work = output / "setup-build"
    subprocess.run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile", "--windowed",
                    "--name", name, "--distpath", str(output), "--workpath", str(work / "build"),
                    "--specpath", str(work / "spec"), "--exclude-module", "PySide6",
                    "--add-data", f"{staging};payload", str(ROOT / "tools/setup_bootstrap.py")], check=True)
    installer = output / f"{name}.exe"
    subprocess.run([str(installer), "--smoke-test"], check=True, timeout=180)
    return installer


def package(app: Path, native: Path, output: Path):
    version_text = (ROOT / "src/discord_guard/__init__.py").read_text(encoding="utf-8")
    version = re.search(r'__version__ = "([0-9.]+)"', version_text)[1]
    if not app.is_dir() or not (app / "DiscordGuard.exe").is_file() or not (app / "_internal").is_dir():
        raise ValueError("Release previews require the onedir app layout, with replaceable Qt libraries")
    for path in app.rglob("*"):
        if path.is_symlink():
            raise ValueError("No symlinks are accepted in release input")
    native_manifest = json.loads((native / "manifest.json").read_text(encoding="utf-8"))
    if native_manifest.get("runtime_driver_tested") is not False or native_manifest.get("driver_signed") is not False:
        raise ValueError("This packager only accepts transparent unsigned previews; signed releases use the reviewed signing route")
    for name, expected in native_manifest["sha256"].items():
        if Path(name).name != name or sha256(native / name) != expected:
            raise ValueError("Native artifact hash mismatch")
    output.mkdir(parents=True, exist_ok=True)
    staging = output / "DiscordGuard-preview"
    if staging.exists():
        raise ValueError("Output staging already exists; choose a fresh release directory")
    staging.mkdir()
    shutil.copytree(app, staging / "app")
    for name in ("LICENSE", "THIRD_PARTY_NOTICES.md", "SECURITY.md"):
        shutil.copy2(ROOT / name, staging / name)
        shutil.copy2(ROOT / name, staging / "app" / name)
    licences = staging / "app" / "licences"
    licences.mkdir()
    # Verbatim GNU texts from the exact Qt release; no downloaded code is run.
    qt_licences = "https://raw.githubusercontent.com/qt/qtbase/v6.11.2/LICENSES/"
    for filename, url in (("GPL-3.0.txt", qt_licences + "GPL-3.0-only.txt"),
                          ("LGPL-3.0.txt", qt_licences + "LGPL-3.0-only.txt")):
        with urllib.request.urlopen(url, timeout=30) as response:
            text = response.read(100_000)
            if b"GNU" not in text or len(text) < 5000:
                raise ValueError("GNU licence text could not be validated")
            (licences / filename).write_bytes(text)
    dependencies = {}
    for name in ("PySide6", "shiboken6", "PyInstaller"):
        distribution = importlib.metadata.distribution(name)
        dependencies[name] = distribution.version
        for file in distribution.files or []:
            if "licenses" in file.parts and distribution.locate_file(file).is_file():
                target = licences / name / file.name
                target.parent.mkdir(exist_ok=True)
                shutil.copy2(distribution.locate_file(file), target)
    python_licence = Path(sys.base_prefix) / "LICENSE.txt"
    if python_licence.is_file():
        shutil.copy2(python_licence, licences / "Python.txt")
    notice = ("DiscordGuard " + version + " experimental preview\n\n"
              "Run app\\DiscordGuard.exe, or download the Setup.exe asset for guided installation.\n"
              "Setup creates a separate standard Windows account. UAC, a new account password, "
              "Windows sign-in and Discord sign-in remain interactive.\n"
              "Discord launches only after the account, interactive session and private ACL checks pass.\n"
              "GuardCore is separate, unsigned and VM-only; no driver is installed by this app.\n"
              "See SECURITY.md, source docs/RELEASING.md and native/README.md.\n")
    (staging / "READ-ME-FIRST.txt").write_text(notice, encoding="utf-8")
    source_zip = output / f"DiscordGuard-{version}-source.zip"
    with zipfile.ZipFile(source_zip, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source_files()):
            archive.write(path, path.relative_to(ROOT).as_posix())
    shutil.copy2(source_zip, staging / "app" / "source.zip")
    installer = build_setup(staging, output, version)
    app_zip = output / f"DiscordGuard-{version}-preview-windows-x64.zip"
    with zipfile.ZipFile(app_zip, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(staging.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(staging).as_posix())
    native_zip = output / f"GuardCore-{version}-UNSIGNED-VM-ONLY.zip"
    shutil.copy2(native / "GuardCore-lab.zip", native_zip)
    artifacts = [source_zip, app_zip, native_zip, installer]
    (output / "SHA256SUMS.txt").write_text("".join(f"{sha256(path)}  {path.name}\n" for path in artifacts), encoding="ascii")
    manifest = {"version": version, "channel": "experimental-preview", "app_signed": False,
                 "driver_signed": False, "driver_runtime_validated": False, "active_rat_protection_claimed": False,
                 "requires_isolated_session": True, "installer_smoke_tested": True,
                "dependencies": dependencies, "artifacts": {path.name: sha256(path) for path in artifacts}}
    (output / "release-manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(json.dumps({"preview": str(app_zip), "installer": str(installer), "source": str(source_zip), "driver_runtime_validated": False}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    package(args.app.resolve(), args.native.resolve(), args.output.resolve())
