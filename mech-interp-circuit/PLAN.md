# Mechanistic Circuit Validation – Experiment Plan

## Objective

Identify and causally validate circuits responsible for malicious PowerShell detection in an LLM, and evaluate robustness under adversarial obfuscation.

## Current Repo State

- Early detector is localized and causally supported: strongest portable heads are `L0H11` and `L0H9`
- Best current minimal direct branch is `L0H11 -> L12H15/L12H5/L12H4`
- Best current cleaner sufficiency-oriented late carrier is `L12H15/L12H5/L12H4/L12H28`
- `L12H2` now looks like a family-sensitive auxiliary late head: it weakens the 96-pair path-patching result when included, but improves grouped ablation on several families
- Main mechanistic cohort remains the 18-pair overlap-controlled set
- A larger interim cohort now exists with 96 valid within-family matched pairs, but it reuses source scripts and should not be treated as a fully independent holdout
- A runnable evasion benchmark now exists with two artifact-backed failure modes under conservative, syntax-preserving obfuscation:
  - `downloadstring_psobject_invoke`
  - `invoke_webrequest_alias`
- The evasion story is now mechanistically specific:
  - on evaded variants, the validated late writer family remains present and still writes the familiar malicious-evidence direction at `resid_pre13`
  - the dependence on that evidence is redistributed downstream between `resid_pre13` and `resid_pre31`
  - by `resid_pre31`, the anti-causal split is already present in the late residual stream
- Remaining gaps are stronger independent generalization, broader evasion coverage across more families, and final writeup consolidation rather than another major mechanistic search

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

- Circuit identified: substantially complete
- Causal validation proven on the main overlap-controlled cohort: substantially complete
- Generalization shown on the interim expanded 96-pair cohort: partial, with known dependence caveat
- Evasion benchmark established: complete
- At least one real evasion mechanism characterized mechanistically: complete

## Practical Next Steps

- Consolidate the final claim around:
  - minimal direct branch: `L0H11 -> L12H15/L12H5/L12H4`
  - cleaner late sufficiency carrier: `L12H15/L12H5/L12H4/L12H28`
  - auxiliary ablation-sensitive helper: `L12H2`
  - final evasion read: the late carrier survives, but downstream late blocks redistribute how the final decision depends on it under obfuscation
- Merge the March 31 evasion follow-ups into the main writeup and artifact narrative
- Build a more independent holdout with more distinct scripts rather than only recombined within-family pairings
- Expand the evasion benchmark beyond the current `DownloadString` and `Invoke-WebRequest` slices
- Add more runnable obfuscation families for `DownloadFile`, `IEX`, and `-EncodedCommand`
- Prepare the final figure and artifact shortlist around:
  - 18-pair mechanistic core
  - 96-pair late-carrier refinement
  - `downloadstring_psobject_invoke` necessity/sufficiency split
  - `invoke_webrequest_alias` downstream redistribution result
- Keep all H100 jobs strictly serial on this host; parallel TransformerLens model loads still OOM the GPU

---

## Codex Instructions

Current code path is `mech-interp-circuit/scaled_validation.py`.

Operational notes:
- Save outputs to `/artifacts`
- Prefer reusing existing manifests and artifact naming conventions
- Run H100 jobs serially, not in parallel
