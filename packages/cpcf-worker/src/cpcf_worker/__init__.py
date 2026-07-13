# SPDX-License-Identifier: Apache-2.0
"""CPCF trusted analysis worker."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("collective-phase-control-fabric")
except PackageNotFoundError:  # Source-tree execution before installation.
    __version__ = "0.6.0"
