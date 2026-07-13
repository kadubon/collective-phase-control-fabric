# SPDX-License-Identifier: Apache-2.0
"""Reject local paths, credentials, and non-source artifacts before publication.

The checker reports only rule names and locations. It never prints matched values.
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import tarfile
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

MAX_SOURCE_BYTES = 5 * 1024 * 1024
MAX_ARCHIVE_MEMBER_BYTES = 16 * 1024 * 1024
BLOCKED_SUFFIXES = {
    ".7z",
    ".cer",
    ".crt",
    ".db",
    ".dll",
    ".dylib",
    ".env",
    ".exe",
    ".jks",
    ".key",
    ".keystore",
    ".p12",
    ".pem",
    ".pfx",
    ".pyc",
    ".pyo",
    ".so",
    ".sqlite",
    ".sqlite3",
    ".zip",
}
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
BLOCKED_NAMES = {
    ".coverage",
    "build-production-requirements.txt",
    "coverage-v5.json",
    "coverage.xml",
    "sbom.cdx.json",
}
TEXT_RULES = {
    "windows_home_path": re.compile(
        rb"(?i)(?:[a-z]:[\\/](?:users|documents and settings)[\\/][^\\/\s]+)"
    ),
    "macos_home_path": re.compile(b"/" + b"Users/" + rb"[^/\s]+/"),
    "linux_home_path": re.compile(b"/" + b"home/" + rb"[^/\s]+/"),
    "file_url": re.compile(b"(?i)" + b"file" + b"://"),
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github_token": re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    "pypi_token": re.compile(rb"\bpypi-[A-Za-z0-9_-]{20,}\b"),
    "aws_access_key": re.compile(rb"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "google_api_key": re.compile(rb"\bAIza[0-9A-Za-z_-]{30,}\b"),
    "slack_token": re.compile(rb"\bxox[baprs]-[0-9A-Za-z-]{20,}\b"),
    "bearer_credential": re.compile(rb"(?i)\bBearer[ \t]+[A-Za-z0-9._~+/-]{12,}\b"),
    "credentialed_connection_string": re.compile(
        rb"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis)://[^\s/:]+:[^\s/@]+@"
    ),
}


@dataclass(frozen=True)
class Finding:
    rule: str
    location: str
    line: int | None = None


def _manifest_patterns(root: Path) -> list[str]:
    return [
        line.strip()
        for line in (root / "publication-files.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def _allowed(path: str, patterns: Iterable[str]) -> bool:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return any(fnmatch.fnmatchcase(normalized, pattern) for pattern in patterns)


def _blocked_path(path: str) -> str | None:
    pure = PurePosixPath(path.replace("\\", "/"))
    if pure.is_absolute() or ".." in pure.parts:
        return "unsafe_archive_path"
    if any(part.lower() in BLOCKED_PARTS for part in pure.parts):
        return "generated_or_local_directory"
    name = pure.name.lower()
    if name in BLOCKED_NAMES or name.startswith(".env") or name.startswith("coverage-"):
        return "generated_or_sensitive_file"
    if any(name.startswith(prefix) for prefix in ("dist-", "dist_")):
        return "nested_build_output"
    if pure.suffix.lower() in BLOCKED_SUFFIXES:
        return "blocked_file_type"
    return None


def _allowed_disposable_test_value(path: str, line: bytes) -> bool:
    normalized = path.replace("\\", "/")
    if normalized == ".gitleaks.toml" or normalized.endswith("/.gitleaks.toml"):
        return b"Bearer " + b"ephemeral-token" in line
    if normalized == ".github/workflows/ci.yml" or normalized.endswith("/.github/workflows/ci.yml"):
        return any(
            value in line
            for value in (
                b"postgresql+psycopg://cpcf_owner:cpcf-test@localhost:5432/cpcf",
                b"postgresql+psycopg://cpcf_app_test:cpcf-app-test@localhost:5432/cpcf",
            )
        )
    disposable_bearer = b"Bearer " + b"ephemeral-token"
    return (
        normalized == "tests/test_v6_package_interfaces.py"
        or normalized.endswith("/tests/test_v6_package_interfaces.py")
    ) and disposable_bearer in line


def _scan_bytes(path: str, data: bytes, *, size_limit: int) -> list[Finding]:
    findings: list[Finding] = []
    if len(data) > size_limit:
        findings.append(Finding("oversized_file", path))
        return findings
    if b"\x00" in data:
        findings.append(Finding("unapproved_binary", path))
        return findings
    if path.lower().endswith(".py") and b"SPDX-License-Identifier: Apache-2.0" not in b"\n".join(
        data.splitlines()[:3]
    ):
        findings.append(Finding("missing_spdx_license", path))
    for number, line in enumerate(data.splitlines(), start=1):
        for name, pattern in TEXT_RULES.items():
            if pattern.search(line) and not _allowed_disposable_test_value(path, line):
                findings.append(Finding(name, path, number))
    return findings


def _source_files(root: Path) -> Iterable[tuple[str, bytes]]:
    patterns = _manifest_patterns(root)
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        if _blocked_path(relative) is not None:
            continue
        if _allowed(relative, patterns):
            yield relative, path.read_bytes()


def _staged_files(root: Path) -> Iterable[tuple[str, bytes]]:
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    for raw in result.stdout.split(b"\x00"):
        if not raw:
            continue
        relative = raw.decode("utf-8", errors="strict").replace("\\", "/")
        content = subprocess.run(
            ["git", "show", f":{relative}"], cwd=root, check=True, capture_output=True
        ).stdout
        yield relative, content


def _archive_files(path: Path) -> Iterable[tuple[str, bytes]]:
    if path.suffix == ".whl" or path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if not info.is_dir():
                    yield info.filename, archive.read(info)
        return
    if path.name.endswith((".tar.gz", ".tgz", ".tar")):
        with tarfile.open(path, "r:*") as archive:
            for info in archive.getmembers():
                if info.isfile():
                    source = archive.extractfile(info)
                    if source is not None:
                        yield info.name, source.read()
        return
    raise ValueError(f"unsupported archive type: {path.name}")


def _scan_collection(
    files: Iterable[tuple[str, bytes]], *, patterns: list[str] | None, archive: bool
) -> list[Finding]:
    findings: list[Finding] = []
    for relative, data in files:
        blocked = _blocked_path(relative)
        if blocked is not None:
            findings.append(Finding(blocked, relative))
            continue
        if patterns is not None and not _allowed(relative, patterns):
            findings.append(Finding("outside_publication_manifest", relative))
            continue
        findings.extend(
            _scan_bytes(
                relative,
                data,
                size_limit=MAX_ARCHIVE_MEMBER_BYTES if archive else MAX_SOURCE_BYTES,
            )
        )
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--source-tree", action="store_true")
    mode.add_argument("--staged", action="store_true")
    mode.add_argument("--archive", type=Path, action="append")
    args = parser.parse_args()
    root = args.root.resolve()
    patterns = _manifest_patterns(root)
    if args.source_tree:
        findings = _scan_collection(_source_files(root), patterns=patterns, archive=False)
    elif args.staged:
        findings = _scan_collection(_staged_files(root), patterns=patterns, archive=False)
    else:
        findings = []
        for archive in args.archive or []:
            findings.extend(_scan_collection(_archive_files(archive), patterns=None, archive=True))
    for finding in findings:
        suffix = f":{finding.line}" if finding.line is not None else ""
        print(f"FAIL {finding.rule} {finding.location}{suffix}")
    if findings:
        print(f"Publication hygiene failed with {len(findings)} finding(s).")
        return 1
    print("Publication hygiene passed; no matched values were printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
