# Concept-to-Code-to-Test-to-Nonclaim Mapping

This table prevents a citation or analogy from being promoted beyond executable behavior. “Partial”
means the release gate remains open.

| Concept | Executable location | Representative tests | Status | Explicit nonclaim |
|---|---|---|---|---|
| RFC 8785-style float-free canonicalization and bounded JSON | `v6/canonical.py`, `v6/registry.py` | `test_v6_adversarial.py`, `test_v6_branches.py` | implemented | not a general JSON security proof |
| DSSE protected subject and role quorum | `v6/trust.py` | `test_v6_adversarial.py`, `test_v6_advanced.py` | implemented kernel; API admission incomplete | not threshold cryptography or TUF equivalence |
| directed-hypergraph reachability | `v6/science.py` | `test_v6_science.py` | implemented | reachability is not causal formation |
| strictly prior causal formation | `v6/science.py` | `test_v6_science.py` | implemented bounded kernel | no elapsed-time or kinetics claim |
| chemical-organization closure and exact maintenance balance | `v6/science.py` | `test_v6_science.py` | partial | no equilibrium, stability, or thermodynamic feasibility claim |
| generalized/generative RAF distinctions | `v6/science.py` | `test_v6_science.py` | partial; exhaustive differential gate open | no chemical equivalence or universal catalysis claim |
| exact finite resource trajectory | `v6/science.py` | `test_v6_science.py`, `test_v6_advanced.py` | implemented bounded kernel | mass balance is not kinetic or thermodynamic feasibility |
| minimal and fed siphons | `v6/structural_analysis.py`, `v6/science.py` | `test_v6_structural_analysis.py` | exact up to the declared 20-coordinate bound; larger inputs unknown | no persistence conclusion from an incomplete search |
| verifier interval feasibility | `v6/science.py` | `test_v6_science.py` | implemented interval check | no stationarity or queue identity claim |
| deterministic arrival/service curves | `v6/structural_analysis.py`, `v6/science.py` | `test_v6_structural_analysis.py` | exact for validated piecewise-rational finite curves | no backlog or delay bound without signed complete curves |
| steady-state flux blocking and full coupling | `v6/structural_analysis.py` | `test_v6_structural_analysis.py` | bounded Z3 models with exact rational recheck | no kinetic or thermodynamic feasibility claim |
| minimal transformation cuts and enablement sets | `v6/structural_analysis.py` | `test_v6_structural_analysis.py` | exhaustive up to the declared 20-transformation bound | no general network controllability claim |
| bounded 1-safe occurrence prefix | `v6/structural_analysis.py` | `test_v6_structural_analysis.py` | bounded unit-stoichiometry profile | no unbounded Petri-net reachability claim |
| effective independence | `v6/science.py`, `v6/coordination.py` | `test_v6_science.py`, `test_v6_advanced.py` | implemented bounded kernel | labels, roles, or model names do not prove independence |
| reduced-snapshot perturbation replay | `v6/science.py` | `test_v6_advanced.py` | object-removal partial | no robustness claim for unsupported modification classes |
| bounded strong nondeterministic planning | `v6/planning.py` | `test_v6_advanced.py`, `test_v6_branches.py` | abstract-state partial | no fairness, eventual success, or general controllability claim |
| target-trial binding | `v6/trials.py` | `test_v6_advanced.py`, `test_v6_branches.py` | kernel implemented; authoritative API admission incomplete | no causality or statistical-method certification |
| immutable bundle integrity | `bundle.py`, `v6/storage.py` | `test_v6_advanced.py` | implemented content check | unsigned content consistency is not distribution authenticity |

The stable release remains blocked while any required row is partial or incomplete, or while its
coverage, mutation, integration, or operational evidence gate is unmet.
