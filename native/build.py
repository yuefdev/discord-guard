"""Build unsigned research artifacts. Never installs drivers or changes Windows settings."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import urllib.request
import zipfile

WDK_VERSION = "10.0.26100.6584"
WDK_PACKAGE = "microsoft.windows.wdk.x64"
WDK_SHA512 = "jhddaBnhMDqt3GVr32RVTtaR0KHmZDjY0JCTMn10OQpk4+AShXCK9QA09vBazp8ni1Mju84qM5SGXfIfnyOJ+g=="
ROOT = Path(__file__).resolve().parent


def acquire_wdk(output):
    destination = output / "wdk"
    marker = destination / ".complete"
    if marker.is_file():
        return destination
    package = output / "wdk.nupkg"
    base = f"https://api.nuget.org/v3-flatcontainer/{WDK_PACKAGE}/{WDK_VERSION}/{WDK_PACKAGE}.{WDK_VERSION}.nupkg"
    # Pinned to NuGet's catalog metadata for the selected Microsoft WDK package.
    expected = base64.b64decode(WDK_SHA512, validate=True)
    digest = hashlib.sha512()
    with urllib.request.urlopen(base, timeout=60) as response, package.open("wb") as target:
        while chunk := response.read(1024 * 1024):
            digest.update(chunk)
            target.write(chunk)
    if digest.digest() != expected:
        package.unlink(missing_ok=True)
        raise RuntimeError("WDK package hash did not match NuGet metadata")
    destination.mkdir(exist_ok=True)
    with zipfile.ZipFile(package) as archive:
        for member in archive.infolist():
            resolved = (destination / member.filename).resolve()
            if not resolved.is_relative_to(destination.resolve()):
                raise RuntimeError("Unsafe WDK archive path")
        archive.extractall(destination)
    marker.write_text(WDK_VERSION, encoding="ascii")
    return destination


def run(args, *, cwd, env):
    subprocess.run([str(arg) for arg in args], cwd=cwd, env=env, check=True)


def build(output, wdk_root=None):
    output.mkdir(parents=True, exist_ok=True)
    wdk = wdk_root or acquire_wdk(output)
    pf86 = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    roots = [pf86 / "Microsoft Visual Studio" / "2022" / "BuildTools"]
    vswhere = pf86 / "Microsoft Visual Studio" / "Installer" / "vswhere.exe"
    if vswhere.is_file():
        found = subprocess.run([str(vswhere), "-latest", "-products", "*", "-requires",
            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"],
            capture_output=True, text=True, check=True).stdout.strip()
        if found:
            roots.insert(0, Path(found))
    msvc_versions = sorted(path for root in roots for path in (root / "VC" / "Tools" / "MSVC").glob("*"))
    if not msvc_versions:
        raise RuntimeError("Visual Studio 2022 C++ Build Tools not found")
    msvc = msvc_versions[-1]
    tools = msvc / "bin" / "Hostx64" / "x64"
    sdk = pf86 / "Windows Kits" / "10"
    sdk_version = "10.0.26100.0"
    if not (sdk / "Include" / sdk_version).is_dir():
        raise RuntimeError("Matching Windows SDK 10.0.26100.0 is required")
    headers = list(wdk.rglob("fltKernel.h"))
    if len(headers) != 1:
        raise RuntimeError("Exactly one x64 WDK fltKernel.h directory is required")
    km = headers[0].parent
    libs = list(wdk.rglob("ntoskrnl.lib"))
    kernel_lib = next((lib.parent for lib in libs if "x64" in str(lib).lower()), None)
    if not kernel_lib:
        raise RuntimeError("x64 WDK kernel libraries missing")
    env = os.environ.copy()
    env["PATH"] = str(tools) + os.pathsep + env.get("PATH", "")
    includes = [ROOT / "include", msvc / "include", sdk / "Include" / sdk_version / "ucrt",
                sdk / "Include" / sdk_version / "shared", sdk / "Include" / sdk_version / "um"]
    inc = [f"/I{path}" for path in includes]
    userlibs = [msvc / "lib" / "x64", sdk / "Lib" / sdk_version / "ucrt" / "x64",
                sdk / "Lib" / sdk_version / "um" / "x64"]
    libflags = [f"/LIBPATH:{path}" for path in userlibs]
    cl, link = tools / "cl.exe", tools / "link.exe"
    run([cl, "/nologo", "/EHsc", "/W4", "/WX", "/std:c++17", *inc,
         ROOT / "tests" / "policy_tests.cpp", f"/Fe:{output / 'policy_tests.exe'}",
         f"/Fo:{output / 'policy_tests.obj'}", "/link", *libflags], cwd=output, env=env)
    run([output / "policy_tests.exe"], cwd=output, env=env)
    run([cl, "/nologo", "/c", "/W4", "/WX", "/kernel", "/GS", "/Zl", "/D_AMD64_",
         "/D_WIN64", "/D_WIN32_WINNT=0x0A00", "/DNTDDI_VERSION=0x0A00000C",
         "/Z7", f"/I{km}", f"/I{km / 'crt'}", *inc, ROOT / "driver" / "guardcore.c",
         f"/Fo:{output / 'GuardCore.obj'}"], cwd=output, env=env)
    run([link, "/nologo", "/DRIVER", "/SUBSYSTEM:NATIVE", "/ENTRY:GsDriverEntry", "/MACHINE:X64",
         "/DEBUG", f"/PDB:{output / 'GuardCore.pdb'}", "/INTEGRITYCHECK", "/DYNAMICBASE", "/NXCOMPAT", f"/OUT:{output / 'GuardCore.sys'}",
         output / "GuardCore.obj", f"/LIBPATH:{kernel_lib}", "ntoskrnl.lib", "fltmgr.lib", "BufferOverflowFastFailK.lib"], cwd=output, env=env)
    run([cl, "/nologo", "/EHsc", "/W4", "/WX", "/std:c++17", "/DUNICODE", "/D_UNICODE", *inc,
         ROOT / "broker" / "broker.cpp", f"/Fo:{output / 'GuardCoreCtl.obj'}",
         f"/Fe:{output / 'GuardCoreCtl.exe'}", "/link", *libflags,
         "advapi32.lib", "fltlib.lib", "wtsapi32.lib", "userenv.lib", "wintrust.lib", "crypt32.lib"],
        cwd=output, env=env)
    run([cl, "/nologo", "/EHsc", "/W4", "/WX", "/std:c++17", "/DUNICODE", "/D_UNICODE", *inc,
         ROOT / "desktop" / "session.cpp", f"/Fo:{output / 'DiscordGuardSession.obj'}",
         f"/Fe:{output / 'DiscordGuardSession.exe'}", "/link", *libflags,
         "advapi32.lib", "wtsapi32.lib", "userenv.lib", "wintrust.lib", "crypt32.lib", "winhttp.lib",
         "user32.lib", "shell32.lib", "ole32.lib"], cwd=output, env=env)
    artifacts = [output / "GuardCore.sys", output / "GuardCoreCtl.exe", output / "GuardCore.pdb", output / "policy_tests.exe",
                 output / "DiscordGuardSession.exe"]
    manifest = {"version": "0.6.0-lab", "runtime_driver_tested": False, "driver_signed": False,
                "sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in artifacts}}
    manifest_path = output / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    with zipfile.ZipFile(output / "GuardCore-lab.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in [*artifacts, manifest_path, ROOT / "README.md", ROOT / "install-vm.ps1", ROOT / "remove-vm.ps1"]:
            archive.write(path, arcname=path.name)
    print(f"Unsigned research artifacts: {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--wdk", type=Path)
    args = parser.parse_args()
    build(args.output.resolve(), args.wdk.resolve() if args.wdk else None)
