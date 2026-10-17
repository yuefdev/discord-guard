"""Generate matching Windows metadata for DiscordGuard's own executable files."""

import argparse
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def project_version() -> str:
    source = (ROOT / "src/discord_guard/__init__.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__ = "(\d+\.\d+\.\d+)"$', source, re.MULTILINE)
    if not match or any(int(part) > 65535 for part in match[1].split(".")):
        raise ValueError("Project version must fit Windows version metadata")
    return match[1]


def attributes(filename: str, version: str) -> dict:
    descriptions = {"DiscordGuard.exe": "DiscordGuard desktop launcher",
                    "DiscordGuardSession.exe": "DiscordGuard private desktop service",
                    f"DiscordGuard-{version}-Setup.exe": "DiscordGuard setup"}
    if filename not in descriptions:
        raise ValueError("Version metadata is restricted to DiscordGuard's own release executables")
    return {"CompanyName": "DiscordGuard contributors", "FileDescription": descriptions[filename],
            "FileVersion": version, "InternalName": Path(filename).stem,
            "LegalCopyright": "DiscordGuard contributors; MIT licence",
            "OriginalFilename": filename, "ProductName": "DiscordGuard", "ProductVersion": version}


def render(filename: str, format: str) -> str:
    version = project_version()
    values = attributes(filename, version)
    numbers = tuple(int(part) for part in version.split(".")) + (0,)
    if format == "pyinstaller":
        strings = ",\n".join(f"                StringStruct({key!r}, {value!r})" for key, value in values.items())
        return ("VSVersionInfo(\n"
                f"    ffi=FixedFileInfo(filevers={numbers!r}, prodvers={numbers!r},\n"
                "        mask=0x3f, flags=0, OS=0x40004, fileType=1, subtype=0, date=(0, 0)),\n"
                "    kids=[StringFileInfo([StringTable('040904B0', [\n" + strings +
                "\n            ])]), VarFileInfo([VarStruct('Translation', [1033, 1200])])])\n")
    if format == "rc":
        strings = "\n".join(f'            VALUE "{key}", "{value}\\0"' for key, value in values.items())
        numeric = ",".join(str(part) for part in numbers)
        return (f"1 VERSIONINFO\nFILEVERSION {numeric}\nPRODUCTVERSION {numeric}\n"
                "FILEFLAGSMASK 0x3fL\nFILEFLAGS 0x0L\nFILEOS 0x40004L\nFILETYPE 0x1L\nFILESUBTYPE 0x0L\n"
                'BEGIN\n    BLOCK "StringFileInfo"\n    BEGIN\n        BLOCK "040904B0"\n        BEGIN\n' +
                strings + '\n        END\n    END\n    BLOCK "VarFileInfo"\n    BEGIN\n'
                '        VALUE "Translation", 0x409, 1200\n    END\nEND\n')
    raise ValueError("Unsupported Windows metadata format")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--filename", required=True)
    parser.add_argument("--format", choices=("pyinstaller", "rc"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    text = render(args.filename, args.format)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(text, encoding="ascii")
