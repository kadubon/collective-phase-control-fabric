# SPDX-License-Identifier: Apache-2.0
"""CPCF runner protocol package."""

from importlib.metadata import PackageNotFoundError, version

from cpcf_runner_protocol.protocol import RunnerConformance, validate_receipt

try:
    __version__ = version("collective-phase-control-fabric")
except PackageNotFoundError:  # Source-tree execution before installation.
    __version__ = "0.6.0"
__all__ = ["RunnerConformance", "__version__", "validate_receipt"]
