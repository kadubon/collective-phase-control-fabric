# SPDX-License-Identifier: Apache-2.0
"""Copy unchanged source into Mutmut's supported single-src import layout.

Only the isolated copy's mutation configuration and source placement change.
Every selected source file is hash-checked, and the frozen dependency lock,
test selection, mutation operators, timeouts and score threshold are preserved.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tomllib
from pathlib import Path
from typing import Any

from scripts.check_publication_hygiene import _blocked_path, _manifest_patterns


def prepare(root: Path, output: Path) -> dict[str, Any]:
    root = root.resolve()
    output = output.resolve()
    if output.exists():
        raise ValueError("mutation_workspace_already_exists")
    original_text = (root / "pyproject.toml").read_text(encoding="utf-8")
    original = tomllib.loads(original_text)
    config = original["tool"]["mutmut"]
    source_roots = [Path(p) for p in config["source_paths"]]
    if Path("src") not in source_roots:
        raise ValueError("mutation_primary_source_missing")
    paths = set()
    for pattern in _manifest_patterns(root):
        for path in root.glob(pattern + "/*" if pattern.endswith("/**") else pattern):
            if path.is_symlink():
                raise ValueError("mutation_source_symlink")
            if path.is_file() and _blocked_path(path.relative_to(root).as_posix()) is None:
                paths.add(path)
    output.mkdir(parents=True)
    for path in sorted(paths):
        destination = output / path.relative_to(root)
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, destination)
    manifest = {}
    for source in source_roots:
        for path in sorted(p for p in paths if p.is_relative_to(root / source)):
            relative = path.relative_to(root / source)
            destination = output / "src" / relative
            if source != Path("src"):
                if destination.exists():
                    raise ValueError("mutation_source_collision")
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, destination)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            if hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
                raise ValueError("mutation_source_bytes_changed")
            manifest[path.relative_to(root).as_posix()] = {
                "path": destination.relative_to(output).as_posix(),
                "sha256": digest,
            }
    rewritten = dict(config)
    rewritten["source_paths"] = ["src"]
    rewritten["only_mutate"] = [manifest[p]["path"] for p in config["only_mutate"]]
    rewritten["pytest_add_cli_args"] = [
        "pythonpath=src" if arg.startswith("pythonpath=") else arg
        for arg in config["pytest_add_cli_args"]
    ]
    prefix, separator, tail = original_text.partition("[tool.mutmut]")
    if not separator or "\n[" in tail:
        raise ValueError("mutation_configuration_layout_unsupported")
    text = (
        prefix
        + separator
        + "\n"
        + "\n".join(f"{key} = {json.dumps(value)}" for key, value in rewritten.items())
        + "\n"
    )
    parsed = tomllib.loads(text)
    parsed["tool"]["mutmut"] = config
    if parsed != original:
        raise ValueError("mutation_unrelated_configuration_changed")
    (output / "pyproject.toml").write_text(text, encoding="utf-8", newline="\n")
    (output / "mutation-source-manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    manifest = prepare(Path.cwd(), args.output)
    print(f"mutation workspace prepared: {len(manifest)} unchanged source files")


if __name__ == "__main__":
    main()
