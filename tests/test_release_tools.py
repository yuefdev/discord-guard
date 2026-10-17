import importlib.util
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


if __name__ == "__main__":
    unittest.main()
