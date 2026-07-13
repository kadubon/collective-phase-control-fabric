# SPDX-License-Identifier: Apache-2.0
"""CPCF v0.6 evidence-control kernel.

The v0.6 namespace is intentionally isolated from legacy execution paths. Legacy documents can be
inspected and copied into quarantine, but cannot establish v0.6 authority.
"""

from collective_phase_control_fabric.v6.models import API_VERSION, DOCUMENT_MODELS

__all__ = ["API_VERSION", "DOCUMENT_MODELS"]
