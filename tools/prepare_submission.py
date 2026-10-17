"""Prepare driver submission input only; no signing, uploading or installation."""

import argparse
from datetime import datetime, timezone
from pathlib import Path
import re
import shutil

ROOT = Path(__file__).resolve().parents[1]


def prepare(native, output, *, provider, altitude):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._-]{1,79}", provider):
        raise ValueError("Use the real verified publisher name, with no INF control characters")
    if not re.fullmatch(r"[0-9]{5,6}(?:\.[0-9]{1,8})?", altitude) or altitude == "385201.4242":
        raise ValueError("A Microsoft-assigned production minifilter altitude is required")
    if output.exists():
        raise ValueError("Choose a new submission directory; existing files are never overwritten")
    for name in ("GuardCore.sys", "GuardCore.pdb"):
        if not (native / name).is_file():
            raise ValueError(f"Missing {name}; build with native/build.py")
    template = (ROOT / "native/driver/GuardCore.inf.in").read_text(encoding="utf-8")
    inf = template.replace("@PROVIDER@", provider).replace("@ALTITUDE@", altitude).replace(
        "@DATE@", datetime.now(timezone.utc).strftime("%m/%d/%Y"))
    output.mkdir(parents=True)
    for name in ("GuardCore.sys", "GuardCore.pdb"):
        shutil.copy2(native / name, output / name)
    (output / "GuardCore.inf").write_text(inf, encoding="utf-16")
    (output / "SUBMISSION-NOT-READY.txt").write_text(
        "Candidate only. Run InfVerif and Inf2Cat, generate the catalog, complete HLK/runtime/update/recovery tests, "
        "sign the submission with a registered publisher certificate and use the Hardware dashboard.\n"
        "No Microsoft signature, certification, production compatibility or deployment is implied.\n"
        "The current broker pins one Discord version; production updates remain unresolved.\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--native", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--altitude", required=True)
    args = parser.parse_args()
    prepare(args.native.resolve(), args.output.resolve(), provider=args.provider, altitude=args.altitude)
