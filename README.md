# mech-interp-circuit

This repository contains the code, datasets, notebooks, and generated artifacts supporting _From Detection to Evasion: Mechanistic Circuit Evaluation of Malicious Code Classification in LLMs_, by Ryan Fetterman.

## Summary

This work studies malicious PowerShell classification through a mechanistic interpretability lens. The repository centers on two linked questions:

- which compact internal route explains the model's malicious classification behavior
- how conservative evasion rewrites affect both classification and the internal route

The current repo-facing results support a validated late route built around:

- upstream entry: `L0H11`
- minimal late route: `L12H15`, `L12H5`, `L12H4`
- stronger sufficiency-oriented add-on: `L12H28`
- auxiliary ablation-sensitive helper: `L12H2`

On the 96-pair matched cohort, grouped path patching shows that:

- the minimal direct branch removes about 90% of the model's average malicious decision margin and flips `54/96` predictions
- the stronger late carrier removes about 93% of that average margin and flips `60/96` predictions

The repository also includes an evasion benchmark built from conservative syntax-preserving rewrites. The strongest current failure mode is `Invoke-WebRequest` alias substitution, and the benchmark follow-up supports a downstream-redistribution interpretation: the late malicious-evidence carrier can remain detectable upstream while later computation still produces misclassification.

## Repository Structure

- `scaled_validation.py`
  Primary pipeline for dataset filtering, validation experiments, evasion generation, review, and paired follow-up analysis.

- `FINDINGS.md`
  Current measured findings, claim boundaries, and interpretation notes.

- `EVASION_BENCHMARK_SCHEMA.md`
  Schema and definitions for the evasion benchmark outputs and review fields.

- `PLAN.md`
  Project plan and execution notes for the scaled validation and evasion work.

- `IMPROVEMENT_CHECKLIST.md`
  Focused checklist of open quality and workflow improvements.

- `circuit_val_set.csv`
  Validation dataset used to build the matched-pair analysis cohorts.

- `artifacts/`
  Generated experiment outputs, manifests, summaries, and paper figures.

- `notebooks/`
  Exploratory and supporting notebooks for circuit discovery, validation, and evasion analysis.

- `generate_demo_notebooks.py`
  Helper script for generating notebook assets used in the analysis workflow.

## What To Read First

- Start with `FINDINGS.md` for the current mechanistic claim.
- Use `EVASION_BENCHMARK_SCHEMA.md` to understand the benchmark fields and success criteria.
- Use `scaled_validation.py` for the implementation of the validation and evasion methodology.
- Inspect `artifacts/` for the actual experiment outputs and exported figures.
