# Mechanistic Circuit Validation – Experiment Plan

## Objective

Identify and causally validate circuits responsible for malicious PowerShell detection in an LLM, and evaluate robustness under adversarial obfuscation.

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

---

## Codex Instructions

Implement functions:
- get_indicator_tokens
- compute_attention_scores
- run_activation_patching
- run_head_ablation
- generate_obfuscations

Save outputs to /artifacts
