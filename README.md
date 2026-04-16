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

The repository also includes a two-tier evasion benchmark built from syntax-preserving PowerShell rewrites.

- `baseline_v1`
  Conservative rewrites that stay close to the original benchmark style, such as alias substitution, simple token splitting, call-operator indirection, and quoted-literal reconstruction. This tier is intended as the stable benchmark baseline.

- `realistic_v2`
  A more realistic defensive-evasion robustness tier that adds stronger string and command reconstruction patterns, including backticks, format strings, ASCII or Base64 recovery, invisible Unicode normalization, and alternate quoting or subexpressions. This tier is intended to stress whether the same internal route survives more deployment-plausible obfuscation.

The strongest current baseline failure mode is `Invoke-WebRequest` alias substitution. In the newer realistic tier, `invoke_expression_format_string` adds a second concrete failure mode. Across both tiers, the follow-up evidence supports the same broad interpretation: the validated late malicious-evidence carrier can remain present while later computation still produces misclassification.

## Comparative Circuit Study: Foundation-Sec-8B vs. Llama-3.1-8B-Instruct

A comparative mechanistic interpretability study is now underway to determine whether the identified circuit is a product of cybersecurity-domain fine-tuning or a general property of the underlying Llama-3.1-8B architecture.

**Central question**: Is the circuit `L0H11 → L12H15/L12H5/L12H4/L12H28` specific to Foundation-Sec-8B's security training, or does it reflect a general inductive bias present in the base Llama-3.1-8B-Instruct model?

Foundation-Sec-8B was created by continued pretraining of `meta-llama/Llama-3.1-8B` on a cybersecurity corpus, then instruction-tuned. Both models share identical architecture (32 layers, 32 heads, 4096 hidden dim), making this a clean architectural control.

### Predicted outcomes

- **Fine-tuning hypothesis** (expected): Llama-3.1-8B-Instruct has no stable Layer 0 detector for PowerShell indicators. Its circuit, if it classifies at all, is distributed differently — perhaps more Layer 0-absent or later-dominated — and evasion rates are higher.
- **Architecture hypothesis** (would be surprising): Llama-3.1-8B-Instruct has a similar early detector family, suggesting the circuit reflects a general inductive bias in Llama toward early keyword detection, not cybersecurity training specifically.
- **Null outcome**: Llama-3.1-8B-Instruct cannot reliably classify PowerShell as malicious/benign, making mechanistic comparison impossible without prompt engineering.

### Study phases

| Phase | Description | Status |
|---|---|---|
| 0 | Classification task setup — prompt design and baseline accuracy check | Pending |
| 1 | Circuit discovery — attention head ranking, layer ablation, residual direction tracing | Pending |
| 2 | Causal validation — grouped path patching and head ablation on 96-pair cohort | Pending |
| 3 | Evasion benchmark — run identical two-tier benchmark on Llama, compare miss rates | Pending |

### Baseline comparison targets (Foundation-Sec-8B)

| Metric | Foundation-Sec-8B | Llama-3.1-8B |
|---|---|---|
| Baseline accuracy on 96-pair cohort | 100% | TBD |
| Early detector layer | Layer 0 (`L0H11`) | TBD |
| Late writer layer | Layer 12 | TBD |
| Minimal branch mean Δ logit diff | -3.156 | TBD |
| Minimal branch flip rate | 54/96 (56.25%) | TBD |
| Stronger carrier mean Δ | -3.293 | TBD |
| Stronger carrier flip rate | 60/96 (62.5%) | TBD |
| `baseline_v1` evasion misses | 6/44 | TBD |
| `realistic_v2` evasion misses | 4/46 | TBD |
| Circuit survives evasion? | Yes (redistribution pattern) | TBD |

See `llama3_comparison_plan.md` for the full pickup guide, CLI commands, go/no-go criteria, and interpretation framework.

## Repository Structure

- `scaled_validation.py`
  Primary pipeline for dataset filtering, validation experiments, evasion generation, review, and paired follow-up analysis.

- `FINDINGS.md`
  Current measured findings, claim boundaries, and interpretation notes.

- `EVASION_BENCHMARK_SCHEMA.md`
  Schema and definitions for the two-tier evasion benchmark outputs, presets, and review fields.

- `llama3_comparison_plan.md`
  Self-contained pickup guide for the Llama-3.1-8B-Instruct comparative circuit study, including CLI commands, phase definitions, and interpretation criteria.

- `circuit_val_set.csv`
  Validation dataset used to build the matched-pair analysis cohorts.

- `artifacts/`
  Generated experiment outputs, manifests, summaries, and paper figures. Llama comparison artifacts will be written with the `llama3_` prefix.

- `notebooks/`
  Exploratory and supporting notebooks for circuit discovery, validation, and evasion analysis.

- `generate_demo_notebooks.py`
  Helper script for generating notebook assets used in the analysis workflow.

## What To Read First

- Start with `FINDINGS.md` for the current Foundation-Sec mechanistic claim.
- Read `llama3_comparison_plan.md` to pick up the comparative study.
- Use `EVASION_BENCHMARK_SCHEMA.md` to understand the benchmark fields and success criteria.
- Use `scaled_validation.py` for the implementation of the validation and evasion methodology.
- Inspect `artifacts/` for the actual experiment outputs and exported figures.
