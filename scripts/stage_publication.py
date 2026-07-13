# SPDX-License-Identifier: Apache-2.0
"""Stage exactly the explicit publication manifest; never approximate `git add .`."""

from __future__ import annotations

import argparse
import fnmatch
import os
import subprocess
from pathlib import Path

BLOCKED_PARTS = {
    ".git",
    ".hypothesis",
    ".idea",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    ".vscode",
    "__pycache__",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    root = args.root.resolve()
    manifest = root / "publication-files.txt"
    patterns = [
        line.strip()
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    paths: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if any(part.lower() in BLOCKED_PARTS for part in path.relative_to(root).parts):
            continue
        if not any(fnmatch.fnmatchcase(relative, pattern) for pattern in patterns):
            continue
        relative_parents = []
        current = path.parent
        while current != root:
            relative_parents.append(current)
            current = current.parent
        is_junction = getattr(os.path, "isjunction", lambda _: False)
        if (
            path.is_symlink()
            or os.path.islink(path)
            or is_junction(path)
            or any(parent.is_symlink() or is_junction(parent) for parent in relative_parents)
        ):
            raise SystemExit(f"refusing linked publication path: {relative}")
        paths.append(relative)
    paths.sort()
    if not paths:
        raise SystemExit("publication manifest selected no files")
    if args.apply:
        subprocess.run(
            ["git", "add", "--pathspec-from-file=-", "--pathspec-file-nul"],
            cwd=root,
            input=b"\x00".join(path.encode("utf-8") for path in paths) + b"\x00",
            check=True,
        )
        print(f"staged {len(paths)} explicitly allowlisted files")
    else:
        print(f"publication manifest selects {len(paths)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
