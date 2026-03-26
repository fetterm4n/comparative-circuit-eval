# Mechanistic Circuit Validation – Experiment Plan

## Objective

Identify and causally validate circuits responsible for malicious PowerShell detection in an LLM, and evaluate robustness under adversarial obfuscation.

## Current Repo State

- Early detector is partially localized and causally supported: strongest portable heads are `L0H11` and `L0H9`
- Best current minimal direct branch is `L0H11 -> L12H15/L12H5/L12H4`
- Best current fuller late carrier is `L12H15/L12H5/L12H4/L12H2/L12H28`
- Main mechanistic cohort remains the 18-pair overlap-controlled set
- A larger interim cohort now exists with 96 valid within-family matched pairs, but it reuses source scripts and should not be treated as a fully independent holdout
- Remaining gaps are end-to-end sufficiency/necessity clarity, stronger generalization with more distinct scripts, and artifact-backed evasion evaluation

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

### Tasks
- Generate obfuscations
- Evaluate model
- Compare circuit behavior

---

## Success Criteria

- Circuit identified
- Causal validation proven
- Generalization shown
- Evasion demonstrated

## Practical Next Steps

- Re-run the key branch and late-carrier summaries on the 96-pair interim cohort
- Build a more independent holdout with more distinct scripts rather than only recombined pairings
- Add a real evasion benchmark beyond formatting-preserving rewrites
- Consolidate the final claim around the minimal direct branch versus the fuller late carrier

---

## Codex Instructions

Implement functions:
- get_indicator_tokens
- compute_attention_scores
- run_activation_patching
- run_head_ablation
- generate_obfuscations

Save outputs to /artifacts
