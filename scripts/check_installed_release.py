# SPDX-License-Identifier: Apache-2.0
"""Run with an isolated installed Python, outside the checkout, using `python -I`."""

from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    args = parser.parse_args()
    root = args.source_root.resolve()
    if Path.cwd().resolve().is_relative_to(root):
        raise RuntimeError("installed_check_requires_external_working_directory")
    if any(Path(p).resolve().is_relative_to(root) for p in sys.path):
        raise RuntimeError("checkout_present_on_import_path")
    if importlib.metadata.version("collective-phase-control-fabric") != args.version:
        raise RuntimeError("installed_distribution_version_mismatch")
    paths = {}
    for name in (
        "collective_phase_control_fabric",
        "cpcf_api",
        "cpcf_cli",
        "cpcf_worker",
        "cpcf_runner_protocol",
    ):
        module = importlib.import_module(name)
        if module.__file__ is None:
            raise RuntimeError("installed_import_origin_missing")
        path = Path(module.__file__).resolve()
        if module.__version__ != args.version or path.is_relative_to(root):
            raise RuntimeError("installed_import_version_or_origin_mismatch")
        paths[name] = str(path)
    from cpcf_cli.main import main as cli

    scenarios = ("preparation", "frontier-chain", "epistemic-probe", "epistemic-integrated")
    for command in (
        ["self-check", "--json"],
        *(["growth", "example", "--scenario", scenario, "--json"] for scenario in scenarios),
    ):
        output = io.StringIO()
        with (
            patch("socket.socket", side_effect=RuntimeError("offline_network_attempt")),
            redirect_stdout(output),
        ):
            status = cli(command)
        result = json.loads(output.getvalue())
        if status != 0 or not isinstance(result, dict):
            raise RuntimeError("installed_cli_check_failed")
        if "epistemic-integrated" in command:
            if result.get("code") != "epistemic_composition_example":
                raise RuntimeError("installed_integrated_example_incomplete")
            checked = result["replanned"]["policy_check"]
            if not checked["policy_feasible"] or checked["execution_authorized"]:
                raise RuntimeError("installed_continuation_not_checked")
    print(
        json.dumps(
            {
                "version": args.version,
                "imports": paths,
                "scenarios": scenarios,
                "network_disabled": True,
                "status": "installed_base_wheel_checked",
            }
        )
    )


if __name__ == "__main__":
    main()
