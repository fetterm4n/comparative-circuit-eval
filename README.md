# mech-interp

This repository contains two related bodies of work on mechanistic interpretability for PowerShell malware classification in Foundation-Sec-8B-Instruct.

## Repository Structure

### Root-level materials

The root directory contains the original small-scale circuit analysis and its supporting notebooks, guides, and validation notes. These files are useful context for the current work because they define the original claim we are now trying to stress-test:

- early layer-0 heads `H11`, `H8`, `H23`, and `H9` act as the main malicious-indicator detector circuit
- later layers refine and harden the final `ALLOW` vs `BLOCK` decision

Important root-level files:

- [`00_START_HERE.md`](/Users/rfetterman/DEV/mech-interp/00_START_HERE.md)
- [`README_CIRCUIT_ANALYSIS.md`](/Users/rfetterman/DEV/mech-interp/README_CIRCUIT_ANALYSIS.md)
- [`CIRCUIT_FINDINGS.md`](/Users/rfetterman/DEV/mech-interp/CIRCUIT_FINDINGS.md)
- [`foundation_sec_mi_powershell_circuit_analysis.py`](/Users/rfetterman/DEV/mech-interp/foundation_sec_mi_powershell_circuit_analysis.py)
- [`circuit_validation_experiments.ipynb`](/Users/rfetterman/DEV/mech-interp/circuit_validation_experiments.ipynb)
- [`circuit_validation_results/`](/Users/rfetterman/DEV/mech-interp/circuit_validation_results)

These root files should be treated as prior context and initial claims, not as the final large-scale validated result.

### `mech-interp-circuit/`

This subdirectory contains the new scaled validation pipeline and all new paper-oriented work.

Key files:

- [`mech-interp-circuit/PLAN.md`](/Users/rfetterman/DEV/mech-interp/mech-interp-circuit/PLAN.md)
- [`mech-interp-circuit/FINDINGS.md`](/Users/rfetterman/DEV/mech-interp/mech-interp-circuit/FINDINGS.md)
- [`mech-interp-circuit/scaled_validation.py`](/Users/rfetterman/DEV/mech-interp/mech-interp-circuit/scaled_validation.py)
- [`mech-interp-circuit/circuit_val_set.csv`](/Users/rfetterman/DEV/mech-interp/mech-interp-circuit/circuit_val_set.csv)

## Plan

The current plan is:

1. Start from the original root-level circuit claim.
2. Build a broader validation dataset where suspicious indicator strings appear in both benign and malicious samples.
3. Filter to examples that the full model actually classifies correctly.
4. Run reduced-layer mechanistic experiments that are tractable locally.
5. Check whether the originally claimed heads still recur and still have causal effect.
6. Record only measured, reproducible findings in [`mech-interp-circuit/FINDINGS.md`](/Users/rfetterman/DEV/mech-interp/mech-interp-circuit/FINDINGS.md).

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
- Fixed the local MPSGraph failure by moving causal interventions from `hook_result` to `hook_z`.
- Scaled the overlap-controlled 4-layer causal run to the full 18-pair validated cohort.

Best current result:

- The original root claim is only partially validated.
- Early layer-0 recurrence generalizes well.
- The strongest portable causal signal is concentrated in `L0H11` and `L0H9`.
- `H8` and `H23` recur, but do not behave like equally stable cross-family causal heads on the broader overlap-controlled dataset.

## Current Limitation

The main remaining limitation is hardware depth, not workflow completeness:

- the full 18-pair overlap-controlled causal run succeeds at 4 layers on the local Apple Silicon machine
- the same experiment at 8 layers still runs out of MPS memory locally

That means the current repo contains a complete reduced-layer validation pipeline, but deeper/fuller causal confirmation should be rerun on a larger CUDA machine.
