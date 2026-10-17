import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

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
            (root / "src" / "secret.P12").write_text("fixture", encoding="ascii")
            (root / "src" / ".env").write_text("fixture", encoding="ascii")
            (root / "src" / ".env.signing").write_text("fixture", encoding="ascii")
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

    def test_signing_options_must_be_complete_before_packaging_creates_output(self):
        package = load("package_release")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for thumbprint, signtool in (("placeholder", root / "signtool.exe"),
                                        ("a" * 40, None), (None, root / "signtool.exe")):
                with self.subTest(thumbprint=thumbprint), self.assertRaisesRegex(ValueError, "certificate"):
                    package.package(root, root, root / "release", certificate_thumbprint=thumbprint, signtool=signtool)
            self.assertFalse((root / "release").exists())

    def test_signature_evidence_cannot_refer_to_different_file_bytes(self):
        package = load("package_release")
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "DiscordGuard.exe"
            binary.write_bytes(b"fixture")
            evidence = {"valid": True, "timestamped": True, "certificate_thumbprint": "a" * 40,
                        "product": "DiscordGuard", "version": "0.8.0", "sha256": "0" * 64}
            with patch.object(package, "powershell_path", return_value=Path("powershell.exe")), \
                    patch.object(package.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(evidence))), \
                    self.assertRaisesRegex(ValueError, "final artifact"):
                package.verify_publisher_artifact(binary, "a" * 40, "0.8.0")

    def test_signed_candidate_hashes_final_bytes_and_still_reports_experimental_driver_status(self):
        package = load("package_release")
        version = load("version_info").project_version()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app, native, output = root / "app", root / "native", root / "release"
            (app / "_internal").mkdir(parents=True)
            native.mkdir()
            (app / "DiscordGuard.exe").write_bytes(b"unsigned app fixture")
            (app / "_internal" / "upstream.dll").write_bytes(b"upstream library fixture")
            (native / "DiscordGuardSession.exe").write_bytes(b"unsigned helper fixture")
            (native / "GuardCore-lab.zip").write_bytes(b"unsigned laboratory archive fixture")
            (native / "manifest.json").write_text(json.dumps({"runtime_driver_tested": False, "driver_signed": False,
                "sha256": {"DiscordGuardSession.exe": package.sha256(native / "DiscordGuardSession.exe")}}), encoding="utf-8")
            signtool = root / "signtool.exe"
            signtool.write_bytes(b"inert fixture; the signer is mocked")
            thumbprint = "a" * 40
            signed = []

            def run(args, **kwargs):
                if "PyInstaller" in args:
                    staging = output / "DiscordGuard-preview"
                    manifest = json.loads((staging / "payload-sha256.json").read_text(encoding="utf-8"))
                    for name in ("DiscordGuard.exe", "DiscordGuardSession.exe"):
                        path = staging / "app" / name
                        self.assertTrue(path.read_bytes().endswith(b" signed fixture"))
                        self.assertEqual(manifest[f"app/{name}"], package.sha256(path))
                    (output / f"DiscordGuard-{version}-Setup.exe").write_bytes(b"unsigned setup fixture")
                elif "-File" in args:
                    script = Path(args[args.index("-File") + 1]).name
                    path = Path(args[args.index("-Artifact") + 1])
                    if script == "sign-app.ps1":
                        signed.append(path.name)
                        path.write_bytes(path.read_bytes() + b" signed fixture")
                    elif script == "verify-app.ps1":
                        return subprocess.CompletedProcess(args, 0, json.dumps({"valid": True, "timestamped": True,
                            "certificate_thumbprint": thumbprint, "product": "DiscordGuard", "version": version,
                            "sha256": package.sha256(path)}))
                    else:
                        self.fail(f"Unexpected signing script: {script}")
                else:
                    self.assertIn("--smoke-test", args)
                    self.assertTrue(Path(args[0]).read_bytes().endswith(b" signed fixture"))
                return subprocess.CompletedProcess(args, 0, "")

            response = Mock()
            response.__enter__ = Mock(return_value=response)
            response.__exit__ = Mock(return_value=False)
            response.read.return_value = b"GNU" + b"x" * 6000
            distribution = Mock(version="fixture", files=[])
            with patch.object(package, "powershell_path", return_value=Path("powershell.exe")), \
                    patch.object(package.subprocess, "run", side_effect=run), \
                    patch.object(package, "defender_scan"), \
                    patch.object(package, "source_files", return_value=[]), \
                    patch.object(package.urllib.request, "urlopen", return_value=response), \
                    patch.object(package.importlib.metadata, "distribution", return_value=distribution):
                package.package(app, native, output, certificate_thumbprint=thumbprint, signtool=signtool)
            self.assertEqual(signed, ["DiscordGuard.exe", "DiscordGuardSession.exe", f"DiscordGuard-{version}-Setup.exe"])
            manifest = json.loads((output / "release-manifest.json").read_text(encoding="utf-8"))
            self.assertTrue(manifest["app_signed"] and manifest["installer_signed"])
            self.assertFalse(manifest["driver_signed"] or manifest["driver_runtime_validated"] or manifest["active_rat_protection_claimed"])
            self.assertEqual(manifest["channel"], "experimental-preview")
            for name, expected in manifest["artifacts"].items():
                self.assertEqual(expected, package.sha256(output / name))
            self.assertEqual((app / "DiscordGuard.exe").read_bytes(), b"unsigned app fixture")

    def test_executable_version_metadata_is_valid_pyinstaller_input(self):
        from PyInstaller.utils.win32 import versioninfo
        metadata = load("version_info")
        namespace = {name: getattr(versioninfo, name) for name in
                     ("VSVersionInfo", "FixedFileInfo", "StringFileInfo", "StringTable", "StringStruct", "VarFileInfo", "VarStruct")}
        version = metadata.project_version()
        for filename in ("DiscordGuard.exe", "DiscordGuardSession.exe", f"DiscordGuard-{version}-Setup.exe"):
            with self.subTest(filename=filename):
                parsed = eval(metadata.render(filename, "pyinstaller"), namespace)
                self.assertIsInstance(parsed, versioninfo.VSVersionInfo)
                self.assertEqual(parsed.ffi.fileVersionMS, (int(version.split('.')[0]) << 16) | int(version.split('.')[1]))
        with self.assertRaises(ValueError):
            metadata.render("third-party.exe", "pyinstaller")

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
