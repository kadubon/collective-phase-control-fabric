# SPDX-License-Identifier: Apache-2.0
"""Validate the one-wheel/one-sdist release contract and write checksums."""

from __future__ import annotations

import argparse
import hashlib
import re
import tomllib
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--metadata-out", type=Path)
    parser.add_argument("--tag")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    name = str(project["name"])
    version = str(project["version"])
    if name != "collective-phase-control-fabric":
        raise SystemExit("release project name mismatch")
    if args.tag and args.tag != f"v{version}":
        raise SystemExit("release tag does not match package metadata")
    public_files = sorted(
        path for path in args.dist.iterdir() if path.is_file() and not path.name.startswith(".")
    )
    wheels = [path for path in public_files if path.suffix == ".whl"]
    sdists = [path for path in public_files if path.name.endswith(".tar.gz")]
    if len(wheels) != 1 or len(sdists) != 1 or len(public_files) != 2:
        raise SystemExit("dist must contain exactly one wheel and one source distribution")
    normalized = name.replace("-", "_")
    expected_wheel = re.compile(
        rf"^{re.escape(normalized)}-{re.escape(version)}-py3-none-any\.whl$"
    )
    expected_sdist = f"{normalized}-{version}.tar.gz"
    if expected_wheel.fullmatch(wheels[0].name) is None or sdists[0].name != expected_sdist:
        raise SystemExit("distribution filename does not match project metadata")
    lines = [
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"
        for path in [*wheels, *sdists]
    ]
    if args.metadata_out is not None:
        args.metadata_out.mkdir(parents=True, exist_ok=True)
        (args.metadata_out / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"validated release artifacts for {name} {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
