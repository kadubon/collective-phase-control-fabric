# SPDX-License-Identifier: Apache-2.0
"""Collective Phase Control Fabric public package."""

from importlib.metadata import PackageNotFoundError, version

from collective_phase_control_fabric.engine import analyze

__all__ = ["__version__", "analyze"]
try:
    __version__ = version("collective-phase-control-fabric")
except PackageNotFoundError:  # Source-tree execution before installation.
    __version__ = "0.6.0"
