# mech-interp-circuit

This repository contains the working code, artifacts, and benchmark materials supporting the publication _From Detection to Evasion: Mechanistic Circuit Evaluation of Malicious Code Classification in LLMs_, by Ryan Fetterman.

## Scope

The focus of this repository is a mechanistic interpretability study of malicious PowerShell classification. The codebase centers on:

- dataset construction and matched validation cohorts
- circuit discovery and validation experiments
- intervention analysis for sufficiency and necessity
- conservative evasion transforms and paired follow-up probes
- artifact generation for figures and supporting analysis

Paper drafting materials are intentionally excluded from version control here. This repository is meant to contain the reproducible analysis assets, not the manuscript workspace.

## Main Files

- `scaled_validation.py`: primary validation and evasion pipeline
- `FINDINGS.md`: current measured findings and claim boundaries
- `EVASION_BENCHMARK_SCHEMA.md`: benchmark schema and field definitions
- `PLAN.md`: project execution plan and milestone tracking
- `artifacts/`: generated figures, manifests, and exported analysis views
- `notebooks/`: exploratory and supporting notebooks
- `circuit_val_set.csv`: validation dataset backing the matched-pair work

## Notes

- `paper/` is kept out of GitHub for this repository.
- local `RESUME_*` files are also excluded from version control.
- commit only reproducible research code, datasets, and analysis artifacts relevant to the circuit and evasion work.
