"""Self-extracting setup: retain the onedir payload until UAC setup has finished."""

import ctypes
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys


def verified_payload(root: Path) -> Path:
    manifest = json.loads((root / "payload-sha256.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or not manifest or "app/DiscordGuard.exe" not in manifest:
        raise ValueError("Installer payload manifest is invalid")
    for name, expected in manifest.items():
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or "\\" in name or ":" in name:
            raise ValueError("Installer payload path is invalid")
        path = root.joinpath(*relative.parts)
        for item in (path, *path.parents):
            if item == root.parent:
                break
            if item.is_symlink() or getattr(item.lstat(), "st_file_attributes", 0) & 0x400:
                raise ValueError("Installer payload contains a redirected path")
        digest = hashlib.sha256()
        with path.open("rb") as source:
            while chunk := source.read(1024 * 1024):
                digest.update(chunk)
        if digest.hexdigest() != expected:
            raise ValueError("Installer payload is damaged")
    # Every payload file must be covered; unexpected DLLs must not be loaded.
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
    if actual != set(manifest) | {"payload-sha256.json"}:
        raise ValueError("Installer payload contains unexpected files")
    return root / "app" / "DiscordGuard.exe"


def main(argv=None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments not in ([], ["--smoke-test"]):
        return 2
    try:
        if not getattr(sys, "frozen", False):
            raise ValueError("Use the packaged setup executable")
        executable = verified_payload(Path(sys._MEIPASS) / "payload")
        # subprocess.call waits. The app also waits for its elevated setup child,
        # so PyInstaller cannot remove DLLs while the installer still uses them.
        return subprocess.call([str(executable), "--smoke-test" if arguments else "--onboard"],
                               cwd=str(executable.parent), close_fds=True)
    except (OSError, ValueError):
        if sys.platform == "win32" and not arguments:
            ctypes.windll.user32.MessageBoxW(None,
                "Kurulum paketi doğrulanamadı. GitHub sürüm sayfasından yeniden indir.", "DiscordGuard kurulumu", 0x10)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
