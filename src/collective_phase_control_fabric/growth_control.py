# SPDX-License-Identifier: Apache-2.0
"""Maintained CPCF 1.x finite growth-control facade.

All results are conditional on explicitly declared finite models. This facade
does not admit capabilities, dispatch runners, sign records or establish causality.
See docs/public-api.md for formats, bounded failures and compatibility policy.
"""

from collective_phase_control_fabric.v6.catalogue_revision import (
    propose_catalogue,
    replan_catalogue,
)
from collective_phase_control_fabric.v6.composition import check_composition
from collective_phase_control_fabric.v6.epistemic import Domain, canonical_support, support_digest
from collective_phase_control_fabric.v6.epistemic_checking import check_epistemic_plan
from collective_phase_control_fabric.v6.epistemic_evidence import (
    export_epistemic,
    reassess_epistemic,
    replan_epistemic,
)
from collective_phase_control_fabric.v6.epistemic_planning import compare_epistemic, plan_epistemic
from collective_phase_control_fabric.v6.growth import GrowthError
from collective_phase_control_fabric.v6.information_value import information_value
from collective_phase_control_fabric.v6.registry import (
    DocumentValidationError,
    parse_document,
    parse_document_bytes,
)
from collective_phase_control_fabric.v6.synthesis import synthesize

__all__ = [
    "DocumentValidationError",
    "Domain",
    "GrowthError",
    "canonical_support",
    "check_composition",
    "check_epistemic_plan",
    "compare_epistemic",
    "export_epistemic",
    "information_value",
    "parse_document",
    "parse_document_bytes",
    "plan_epistemic",
    "propose_catalogue",
    "reassess_epistemic",
    "replan_catalogue",
    "replan_epistemic",
    "support_digest",
    "synthesize",
]
