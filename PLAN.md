# Mechanistic Circuit Validation – Experiment Plan

## Objective

Identify and causally validate circuits responsible for malicious PowerShell detection in an LLM, and evaluate robustness under adversarial obfuscation.

## Current Repo State

- The active repo claim is anchored to the 96-pair within-family matched cohort, not the earlier 18-pair pilot
- Best current minimal direct branch on that 96-pair cohort is `L0H11 -> L12H15/L12H5/L12H4`
- Best current cleaner sufficiency-oriented late carrier on that 96-pair cohort is `L12H15/L12H5/L12H4/L12H28`
- `L12H2` now looks like a family-sensitive auxiliary late head: removing it improves 96-pair path patching, but including it improves grouped ablation on several families
- The 18-pair overlap-controlled set remains useful as discovery-stage history, but it is no longer the basis for repo-facing validation claims
- The 96-pair cohort materially improves matched-control coverage, but it reuses source scripts and should not be treated as a fully independent holdout
- A runnable evasion benchmark now exists with a strict candidate tier plus a separate provisional `IEX` extension
- The strict candidate tier covers `DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `Invoke-Expression`, and `-EncodedCommand`
- Two artifact-backed failure modes remain the substantive misses under conservative, syntax-preserving obfuscation:
  - `downloadstring_psobject_invoke`
  - `invoke_webrequest_alias`
- `DownloadFile` and `-EncodedCommand` now have benchmarked strict candidate slices with no observed misses in the current run
- The pure `IEX` slice is now included as a provisional candidate tier: invariant-checked, benchmarked, and still `0/4` on the current run, but not part of the strict benchmark because the current environment lacks a PowerShell runtime and the fallback parse screen does not accept those variants
- The evasion story is now mechanistically specific:
  - on evaded variants, the validated late writer family remains present and still writes the familiar malicious-evidence direction at `resid_pre13`
  - the dependence on that evidence is redistributed downstream between `resid_pre13` and `resid_pre31`
  - by `resid_pre31`, the anti-causal split is already present in the late residual stream
- The core study is complete at the current 96-pair validation bar; future expansion should target stronger independent generalization and broader evasion coverage rather than another major mechanistic search

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
- Prove causal role on the 96-pair cohort
- Quantify late-route effects

### Tasks
- Grouped path patching
- Grouped head ablation
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
- Causal validation proven on the 96-pair within-family cohort: substantially complete
- Current study complete at the 96-pair within-family validation bar: complete
- Evasion benchmark established: complete
- At least one real evasion mechanism characterized mechanistically: complete

## Future Expansion

- Consolidate the final claim around:
  - minimal direct branch: `L0H11 -> L12H15/L12H5/L12H4`
  - cleaner late sufficiency carrier: `L12H15/L12H5/L12H4/L12H28`
  - auxiliary ablation-sensitive helper: `L12H2`
  - final evasion read: the late carrier survives, but downstream late blocks redistribute how the final decision depends on it under obfuscation
- Merge the March 31 evasion follow-ups into the main writeup and artifact narrative
- Build a more independent holdout with more distinct scripts rather than only recombined within-family pairings
- Finish runtime-side validation for the pure `IEX` evasion slice so it can move from the provisional tier into the strict candidate benchmark
- Prepare the final figure and artifact shortlist around:
  - 96-pair minimal direct branch
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
