# Mechanistic Circuit Validation – Experiment Plan

## Objective

Identify and causally validate circuits responsible for malicious PowerShell detection in an LLM, and evaluate robustness under adversarial obfuscation.

## Current Repo State

- Early detector is partially localized and causally supported: strongest portable heads are `L0H11` and `L0H9`
- Best current minimal direct branch is `L0H11 -> L12H15/L12H5/L12H4`
- Best current cleaner sufficiency-oriented late carrier is `L12H15/L12H5/L12H4/L12H28`
- `L12H2` now looks like a family-sensitive auxiliary late head: it weakens the 96-pair path-patching result when included, but improves grouped ablation on several families
- Main mechanistic cohort remains the 18-pair overlap-controlled set
- A larger interim cohort now exists with 96 valid within-family matched pairs, but it reuses source scripts and should not be treated as a fully independent holdout
- A first runnable evasion benchmark now exists and has produced real misses under conservative, syntax-preserving obfuscation
- The clearest evasion finding so far is a necessity/sufficiency split: `downloadstring_psobject_invoke` weakens or reroutes the usual late bundle under ablation while leaving a still-usable sufficient route under path patching
- Remaining gaps are stronger independent generalization, broader evasion coverage beyond the first `DownloadString` slice, and a clearer decomposition of the redistributed late-stage computation

---

## Repo Structure

/mech-interp/
/notebooks/
    01_circuit_discovery.ipynb
    02_circuit_validation.ipynb
    03_evasion_analysis.ipynb
/artifacts/
/data/

---

## Notebook 1: Circuit Discovery

### Goals
- Identify candidate heads
- Localize attention
- Analyze residual stream

### Tasks
- Load model + dataset
- Map indicator tokens
- Compute attention scores
- Generate heatmaps
- Run logit lens

---

## Notebook 2: Circuit Validation

### Goals
- Prove causal role
- Quantify effects

### Tasks
- Activation patching
- Head ablation
- Batch evaluation

---

## Notebook 3: Evasion Analysis

### Goals
- Test robustness
- Identify failures
- Compare how the validated circuit behaves before and after obfuscation

### Tasks
- Generate obfuscations
- Review variants for syntax and conservative invariants
- Evaluate model
- Compare circuit behavior with:
  - grouped ablation
  - path patching
  - seed vs obfuscated paired analysis

---

## Success Criteria

- Circuit identified
- Causal validation proven
- Generalization shown
- Evasion benchmark established
- At least one real evasion mechanism characterized mechanistically

## Practical Next Steps

- Consolidate the final claim around:
  - minimal direct branch: `L0H11 -> L12H15/L12H5/L12H4`
  - cleaner late sufficiency carrier: `L12H15/L12H5/L12H4/L12H28`
  - auxiliary ablation-sensitive helper: `L12H2`
- Build a more independent holdout with more distinct scripts rather than only recombined within-family pairings
- Expand the evasion benchmark beyond the current `DownloadString`-focused candidate slice
- Add more runnable obfuscation families for `DownloadFile`, `Invoke-WebRequest`, `IEX`, and `-EncodedCommand`
- Push the new necessity-vs-sufficiency evasion read into the final writeup so the robustness claim is mechanistically precise
- Probe the redistributed late-stage computation on missed variants rather than assuming the original late writer bundle is simply absent

---

## Codex Instructions

Implement functions:
- get_indicator_tokens
- compute_attention_scores
- run_activation_patching
- run_head_ablation
- generate_obfuscations

Save outputs to /artifacts
