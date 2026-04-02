# mech-interp

This repository contains two related bodies of work on mechanistic interpretability for PowerShell malware classification in Foundation-Sec-8B-Instruct.

## Repository Structure

### Root-level materials

The root directory contains the original small-scale circuit analysis and its supporting notebooks, guides, and validation notes. These files are useful context for the current work because they define the original claim we are now trying to stress-test:

- early layer-0 heads `H11`, `H8`, `H23`, and `H9` act as the originally proposed malicious-indicator detector circuit
- later layers refine and harden the final `ALLOW` vs `BLOCK` decision

Important root-level files:

- [`00_START_HERE.md`](./00_START_HERE.md)
- [`README_CIRCUIT_ANALYSIS.md`](./README_CIRCUIT_ANALYSIS.md)
- [`CIRCUIT_FINDINGS.md`](./CIRCUIT_FINDINGS.md)
- [`foundation_sec_mi_powershell_circuit_analysis.py`](./foundation_sec_mi_powershell_circuit_analysis.py)
- [`circuit_validation_experiments.ipynb`](./circuit_validation_experiments.ipynb)
- [`circuit_validation_results/`](./circuit_validation_results)

These root files should be treated as prior context and initial claims, not as the final large-scale validated result.

### `mech-interp-circuit/`

This subdirectory contains the new scaled validation pipeline and all new paper-oriented work.

Key files:

- [`mech-interp-circuit/PLAN.md`](./mech-interp-circuit/PLAN.md)
- [`mech-interp-circuit/FINDINGS.md`](./mech-interp-circuit/FINDINGS.md)
- [`mech-interp-circuit/EVASION_BENCHMARK_SCHEMA.md`](./mech-interp-circuit/EVASION_BENCHMARK_SCHEMA.md)
- [`mech-interp-circuit/RESUME_2026-03-27.md`](./mech-interp-circuit/RESUME_2026-03-27.md)
- [`mech-interp-circuit/scaled_validation.py`](./mech-interp-circuit/scaled_validation.py)
- [`mech-interp-circuit/circuit_val_set.csv`](./mech-interp-circuit/circuit_val_set.csv)

## Plan

The current plan is:

1. Start from the original root-level circuit claim.
2. Build a broader validation dataset where suspicious indicator strings appear in both benign and malicious samples.
3. Filter to examples that the full model actually classifies correctly.
4. Run reduced-layer mechanistic experiments that are tractable locally.
5. Re-run the decisive circuit validation work on CUDA hardware for deeper late-stage tests.
6. Build a runnable evasion benchmark with semantics-preserving obfuscations.
7. Record only measured, reproducible findings in [`mech-interp-circuit/FINDINGS.md`](./mech-interp-circuit/FINDINGS.md).

## Progress So Far

Current status:

- Built an overlap-controlled validation set with balanced benign and malicious classes.
- Constructed explicit benign/malicious indicator-matched pair manifests.
- Ran full-model baseline filtering to keep only correctly classified pairs.
- Implemented a reproducible scaled validation CLI for:
  - dataset prep
  - baseline eval
  - head recurrence
  - activation patching
  - head ablation
  - family-level overlap summaries
- Added an evasion benchmark pipeline for:
  - generating conservative runnable obfuscations
  - manifesting seeds and variants
  - syntax and invariant review
  - paired seed/variant evaluation
- Fixed the local MPSGraph failure by moving causal interventions from `hook_result` to `hook_z`.
- Preserved the original 18-pair overlap-controlled run as a discovery-stage pilot and artifact record.
- Extended the late-stage validation on an H100 host, using a 96-pair within-family matched cohort as the current basis for repo-facing circuit claims, plus evasion follow-up probes.

Best current result:

- The current repo-facing claim is grounded in the 96-pair within-family matched cohort rather than the older 18-pair pilot.
- On that 96-pair cohort, the cleanest currently supported direct branch is `L0H11 -> L12H15/L12H5/L12H4` (`mean Δ = -3.156`, `flip_rate = 0.5625`).
- The stronger sufficiency-oriented late carrier on the same cohort is `L12H15/L12H5/L12H4/L12H28` (`mean Δ = -3.293`, `flip_rate = 0.625`), while `L12H2` behaves more like an auxiliary ablation-sensitive helper than a stable core writer.
- The runnable evasion benchmark now has two explicit tiers: a strict candidate screen and a provisional `IEX` extension. The strict screen covers `DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `Invoke-Expression`, and `-EncodedCommand`. A separate provisional tier adds the pure `IEX` scriptblock-creation slice without weakening the strict benchmark. Two techniques produce real misses, with `invoke_webrequest_alias` as the strongest current one. Current probes suggest a necessity-versus-sufficiency split in the late-stage circuit rather than simple route deletion.

## Current Limitations

- The 96-pair cohort is useful but not a fully independent holdout because source scripts are reused across multiple pairings.
- The late-stage decision process is only partially decomposed: the route is validated at the head-group level, but the redistributed computation under evasion is not yet isolated.
- The evasion benchmark is broader than the first pass, but it is still not comprehensive. Current strict candidate results include `DownloadFile` and `-EncodedCommand` without new misses, and the separate provisional `IEX` tier likewise shows `0/4` misses. The remaining limitation is that pure `IEX` still lacks runtime-side parse validation in this environment.
- Linux-side syntax review uses `tree-sitter` as a fallback when real PowerShell runtimes are unavailable, so runnable validity is still strongest when later rechecked on Windows PowerShell or `pwsh`.

The repo now contains a complete reduced-layer validation pipeline, CUDA-backed late-stage follow-up, and a first artifact-backed evasion benchmark. We treat stronger independent holdout construction and broader family coverage as future expansion, not as blockers on the current study.
