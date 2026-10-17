import importlib.util
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseToolsTests(unittest.TestCase):
    def test_source_archive_uses_allowlist_and_excludes_signing_credentials(self):
        package = load("package_release")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src" / "app.py").write_text("fixture", encoding="ascii")
            (root / "src" / "secret.pfx").write_text("fixture", encoding="ascii")
            (root / "personal.txt").write_text("fixture", encoding="ascii")
            names = [path.relative_to(root).as_posix() for path in package.source_files(root)]
            self.assertEqual(names, ["src/app.py"])

    def test_submission_rejects_lab_altitude_and_inf_control_characters(self):
        submission = load("prepare_submission")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for provider, altitude in (("Publisher", "385201.4242"), ('Bad"\nName', "385999"),
                                       ("Publisher", "MICROSOFT_ASSIGNED")):
                with self.subTest(provider=provider, altitude=altitude), self.assertRaises(ValueError):
                    submission.prepare(root, root / "output", provider=provider, altitude=altitude)
            self.assertFalse((root / "output").exists())

    def test_submission_requires_debug_symbols_not_just_a_driver(self):
        submission = load("prepare_submission")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "GuardCore.sys").write_bytes(b"synthetic")
            with self.assertRaisesRegex(ValueError, "GuardCore.pdb"):
                submission.prepare(root, root / "output", provider="Publisher", altitude="385999")

    def test_preview_packager_refuses_single_file_distribution(self):
        package = load("package_release")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "DiscordGuard.exe").write_bytes(b"synthetic")
            with self.assertRaisesRegex(ValueError, "onedir"):
                package.package(root, root, root / "release")

    def test_installer_rejects_modified_missing_and_extra_payload_files(self):
        bootstrap = load("setup_bootstrap")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app").mkdir()
            binary = root / "app" / "DiscordGuard.exe"
            binary.write_bytes(b"fixture")
            manifest = {"app/DiscordGuard.exe": hashlib.sha256(b"fixture").hexdigest()}
            (root / "payload-sha256.json").write_text(json.dumps(manifest), encoding="utf-8")
            self.assertEqual(bootstrap.verified_payload(root), binary)
            binary.write_bytes(b"changed")
            with self.assertRaises(ValueError):
                bootstrap.verified_payload(root)
            binary.write_bytes(b"fixture")
            extra = root / "app" / "unlisted.dll"
            extra.write_bytes(b"fixture")
            with self.assertRaises(ValueError):
                bootstrap.verified_payload(root)
            extra.unlink()
            binary.unlink()
            with self.assertRaises(OSError):
                bootstrap.verified_payload(root)

    def test_installer_manifest_cannot_escape_the_payload(self):
        bootstrap = load("setup_bootstrap")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("../outside.exe", "C:/outside.exe", "/outside.exe", "app\\bad.exe"):
                manifest = {name: "unused", "app/DiscordGuard.exe": "unused"}
                (root / "payload-sha256.json").write_text(json.dumps(manifest), encoding="utf-8")
                with self.subTest(name=name), self.assertRaises(ValueError):
                    bootstrap.verified_payload(root)


if __name__ == "__main__":
    unittest.main()
