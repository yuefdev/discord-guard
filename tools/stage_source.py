"""Copy the explicit public-source allowlist into a fresh staging directory."""

import argparse
from pathlib import Path
import shutil

from package_release import ROOT, source_files


def stage(destination):
    if destination.exists():
        raise ValueError("Choose a fresh source staging directory; existing files are never overwritten")
    if not destination.parent.is_dir():
        raise ValueError("Source staging parent must already exist")
    destination.mkdir()
    count = 0
    for source in source_files():
        target = destination / source.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        count += 1
    print(f"Staged {count} source files in {destination}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", required=True, type=Path)
    stage(parser.parse_args().destination.resolve())
