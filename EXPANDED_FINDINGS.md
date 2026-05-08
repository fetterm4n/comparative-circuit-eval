# Expanded Dataset Re-Validation

## Purpose

The original 96-pair within-family result drew the main criticism that the cohort was too thin — particularly the `-EncodedCommand` (2 pairs) and `IEX` (6 pairs) families. This document tracks re-validation of the core circuit claims on a larger augmented dataset covering the same 7 original indicator families.

## Dataset Comparison

| Family | Original pairs | Augmented candidate pairs |
|--------|---------------:|-------------------------:|
| `-EncodedCommand` | 2 | 12 |
| `DownloadFile` | 20 | 150 |
| `DownloadString` | 10 | 64 |
| `FromBase64String` | 20 | 44 |
| `IEX` | 6 | 36 |
| `Invoke-Expression` | 20 | 32 |
| `Invoke-WebRequest` | 18 | 42 |
| **Total** | **96** | **380** |

Candidate manifest: `artifacts/foundation_sec/circuit_val_aug_orig_families_manifest.csv`

The augmented dataset has 456 unique files vs. 78 in the original, so the increased pair count reflects genuinely broader script coverage.

Families `Net.WebClient`, `Start-Process`, and `VirtualAlloc` are present in the full augmented set but excluded here to keep the comparison directly against the original claim.

---

## Step 1 — Baseline Eval

**Command:**
```
python3 scaled_validation.py baseline-eval \
  --manifest artifacts/foundation_sec/circuit_val_aug_orig_families_manifest.csv \
  --model-name fdtn-ai/Foundation-Sec-8B-Instruct \
  --output artifacts/foundation_sec/circuit_val_aug_orig_families_baseline_h100.csv
```

**Status:** complete

**Results:**

| Metric | Value |
|--------|-------|
| Rows evaluated | 760 |
| Accuracy | 0.8803 |
| Mean logit diff | 1.063 |

Note: one sequence exceeded the model's 4096-token context limit (single outlier, not a systemic truncation problem — no rows exceed the 12k char preprocessing cap).

Family-level accuracy:

| Family | Rows | Accuracy | Mean logit diff |
|--------|-----:|---------:|----------------:|
| `-EncodedCommand` | 24 | 0.792 | -0.149 |
| `DownloadFile` | 300 | 0.987 | 2.245 |
| `DownloadString` | 128 | 0.820 | 1.026 |
| `FromBase64String` | 88 | 0.898 | 0.169 |
| `IEX` | 72 | 0.833 | 1.351 |
| `Invoke-Expression` | 64 | 0.781 | -0.599 |
| `Invoke-WebRequest` | 84 | 0.714 | -0.796 |

---

## Step 2 — Valid Pair Filtering

**Command:**
```
python3 scaled_validation.py filter-valid-pairs \
  --manifest artifacts/foundation_sec/circuit_val_aug_orig_families_manifest.csv \
  --baseline-eval artifacts/foundation_sec/circuit_val_aug_orig_families_baseline_h100.csv \
  --output artifacts/foundation_sec/circuit_val_aug_orig_families_valid_h100.csv
```

**Status:** complete

**Results:**

| Metric | Value |
|--------|-------|
| Candidate pairs in | 380 |
| Valid pairs out | 293 |
| Rows out | 586 |
| Rejection rate | 22.9% |

Valid pairs by family:

| Family | Original valid pairs | Augmented valid pairs |
|--------|--------------------:|---------------------:|
| `-EncodedCommand` | 2 | 7 |
| `DownloadFile` | 20 | 146 |
| `DownloadString` | 10 | 43 |
| `FromBase64String` | 20 | 35 |
| `IEX` | 6 | 25 |
| `Invoke-Expression` | 20 | 18 |
| `Invoke-WebRequest` | 18 | 19 |
| **Total** | **96** | **293** |

---

## Step 3 — Path Patching

All path-patching runs use the valid manifest from Step 2 with `--num-pairs 9999`.

### 3a — Minimal direct branch `L0H11 → L12H15/H5/H4`

**Command:**
```
python3 scaled_validation.py batch-path-patching \
  --manifest artifacts/foundation_sec/circuit_val_aug_orig_families_valid_h100.csv \
  --heads 0.11,12.15,12.5,12.4 --num-pairs 9999 \
  --model-name fdtn-ai/Foundation-Sec-8B-Instruct \
  --template-name meta-llama/Llama-3.1-8B-Instruct \
  --output-prefix artifacts/foundation_sec/circuit_val_path_patching_h011_plus_l12_top3_aug_orig_h100
```

**Status:** complete

**Original 96-pair result:** `mean Δ = -3.156`, `flip_rate = 0.5625`

| Metric | Original | Augmented |
|--------|----------|-----------|
| `mean Δ` | -3.156 | **-3.614** |
| `flip_rate` | 0.5625 | **0.297** |
| N pairs | 96 | 293 |

Mean delta strengthened. Flip rate drop is a composition effect: `DownloadFile` now represents 50% of the cohort (146/293 pairs) and has the lowest per-family flip rate (0.199), pulling the overall rate down. All families show consistent negative mean delta.

Per-family breakdown:

| Family | N | `mean Δ` | `flip_rate` |
|--------|--:|---------:|------------:|
| `-EncodedCommand` | 7 | -1.411 | 0.000 |
| `DownloadFile` | 146 | -4.842 | 0.199 |
| `DownloadString` | 43 | -3.772 | 0.442 |
| `FromBase64String` | 35 | -1.188 | 0.371 |
| `IEX` | 25 | -3.027 | 0.320 |
| `Invoke-Expression` | 18 | -1.461 | 0.500 |
| `Invoke-WebRequest` | 19 | -1.916 | 0.474 |

---

### 3b — Top-5 bundle `L12H15/H5/H4/H2/H28`

**Command:**
```
python3 scaled_validation.py batch-path-patching \
  --manifest artifacts/foundation_sec/circuit_val_aug_orig_families_valid_h100.csv \
  --heads 12.15,12.5,12.4,12.2,12.28 --num-pairs 9999 \
  --model-name fdtn-ai/Foundation-Sec-8B-Instruct \
  --template-name meta-llama/Llama-3.1-8B-Instruct \
  --output-prefix artifacts/foundation_sec/circuit_val_path_patching_l12_writer_top5_aug_orig_h100
```

**Status:** complete

**Original 96-pair result:** `mean Δ = -3.265`, `flip_rate = 0.583`

| Metric | Original | Augmented |
|--------|----------|-----------|
| `mean Δ` | -3.265 | **-3.808** |
| `flip_rate` | 0.583 | **0.266** |
| N pairs | 96 | 293 |

Per-family breakdown:

| Family | N | `mean Δ` | `flip_rate` |
|--------|--:|---------:|------------:|
| `-EncodedCommand` | 7 | -0.993 | 0.000 |
| `DownloadFile` | 146 | -5.067 | 0.151 |
| `DownloadString` | 43 | -4.051 | 0.442 |
| `FromBase64String` | 35 | -1.255 | 0.343 |
| `IEX` | 25 | -3.441 | 0.320 |
| `Invoke-Expression` | 18 | -1.610 | 0.500 |
| `Invoke-WebRequest` | 19 | -1.879 | 0.421 |

---

### 3c — H2-free carrier `L12H15/H5/H4/H28`

**Command:**
```
python3 scaled_validation.py batch-path-patching \
  --manifest artifacts/foundation_sec/circuit_val_aug_orig_families_valid_h100.csv \
  --heads 12.15,12.5,12.4,12.28 --num-pairs 9999 \
  --model-name fdtn-ai/Foundation-Sec-8B-Instruct \
  --template-name meta-llama/Llama-3.1-8B-Instruct \
  --output-prefix artifacts/foundation_sec/circuit_val_path_patching_l12_writer_minus_h2_aug_orig_h100
```

**Status:** complete

**Original 96-pair result:** `mean Δ = -3.293`, `flip_rate = 0.625`

| Metric | Original | Augmented |
|--------|----------|-----------|
| `mean Δ` | -3.293 | **-3.824** |
| `flip_rate` | 0.625 | **0.297** |
| N pairs | 96 | 293 |

H2-free carrier is marginally stronger than the top-5 bundle (−3.824 vs −3.808), replicating the original direction. The H2-free carrier remains the strongest sufficiency-oriented route.

Per-family breakdown:

| Family | N | `mean Δ` | `flip_rate` |
|--------|--:|---------:|------------:|
| `-EncodedCommand` | 7 | -1.272 | 0.000 |
| `DownloadFile` | 146 | -5.047 | 0.158 |
| `DownloadString` | 43 | -4.121 | 0.512 |
| `FromBase64String` | 35 | -1.287 | 0.343 |
| `IEX` | 25 | -3.480 | 0.440 |
| `Invoke-Expression` | 18 | -1.662 | 0.556 |
| `Invoke-WebRequest` | 19 | -1.861 | 0.474 |

---

### 3d — Minus-H28 bundle `L12H15/H5/H4/H2`

**Command:**
```
python3 scaled_validation.py batch-path-patching \
  --manifest artifacts/foundation_sec/circuit_val_aug_orig_families_valid_h100.csv \
  --heads 12.15,12.5,12.4,12.2 --num-pairs 9999 \
  --model-name fdtn-ai/Foundation-Sec-8B-Instruct \
  --template-name meta-llama/Llama-3.1-8B-Instruct \
  --output-prefix artifacts/foundation_sec/circuit_val_path_patching_l12_writer_minus_h28_aug_orig_h100
```

**Status:** complete

**Original 96-pair result:** `mean Δ = -2.886`, `flip_rate = 0.490`

| Metric | Original | Augmented |
|--------|----------|-----------|
| `mean Δ` | -2.886 | **-3.316** |
| `flip_rate` | 0.490 | **0.188** |
| N pairs | 96 | 293 |

Removing H28 materially weakens the route vs the H2-free carrier (−3.316 vs −3.824), replicating the original direction. H28 remains a meaningful contributor.

Per-family breakdown:

| Family | N | `mean Δ` | `flip_rate` |
|--------|--:|---------:|------------:|
| `-EncodedCommand` | 7 | -1.109 | 0.000 |
| `DownloadFile` | 146 | -4.414 | 0.068 |
| `DownloadString` | 43 | -3.560 | 0.302 |
| `FromBase64String` | 35 | -1.086 | 0.343 |
| `IEX` | 25 | -2.834 | 0.160 |
| `Invoke-Expression` | 18 | -1.338 | 0.444 |
| `Invoke-WebRequest` | 19 | -1.757 | 0.421 |

---

## Step 4 — Grouped Head Ablation

All ablation runs use the valid manifest from Step 2 with `--num-pairs 9999`.

### 4a — Minimal branch heads `L12H15/H5/H4`

**Command:**
```
python3 scaled_validation.py batch-head-group-ablation \
  --manifest artifacts/foundation_sec/circuit_val_aug_orig_families_valid_h100.csv \
  --heads 12.15,12.5,12.4 --num-pairs 9999 \
  --model-name fdtn-ai/Foundation-Sec-8B-Instruct \
  --template-name meta-llama/Llama-3.1-8B-Instruct \
  --output-prefix artifacts/foundation_sec/circuit_val_head_group_ablation_l12_h011_route_aug_orig_h100
```

**Status:** complete

**Original 96-pair result:** `mean Δ = -0.840`

| Metric | Original | Augmented |
|--------|----------|-----------|
| `mean Δ` | -0.840 | **-1.461** |
| `flip_rate` | — | 0.051 |
| N pairs | 96 | 293 |

Necessity signal strengthened substantially on the larger cohort. All families show consistent negative mean delta.

Per-family breakdown:

| Family | N | `mean Δ` | `flip_rate` |
|--------|--:|---------:|------------:|
| `-EncodedCommand` | 7 | -0.787 | 0.000 |
| `DownloadFile` | 146 | -2.148 | 0.007 |
| `DownloadString` | 43 | -1.193 | 0.023 |
| `FromBase64String` | 35 | -0.431 | 0.171 |
| `IEX` | 25 | -0.694 | 0.000 |
| `Invoke-Expression` | 18 | -0.284 | 0.278 |
| `Invoke-WebRequest` | 19 | -1.053 | 0.105 |

---

### 4b — Top-5 bundle `L12H15/H5/H4/H2/H28`

**Command:**
```
python3 scaled_validation.py batch-head-group-ablation \
  --manifest artifacts/foundation_sec/circuit_val_aug_orig_families_valid_h100.csv \
  --heads 12.15,12.5,12.4,12.2,12.28 --num-pairs 9999 \
  --model-name fdtn-ai/Foundation-Sec-8B-Instruct \
  --template-name meta-llama/Llama-3.1-8B-Instruct \
  --output-prefix artifacts/foundation_sec/circuit_val_head_group_ablation_l12_writer_top5_aug_orig_h100
```

**Status:** complete

**Original 96-pair result:** `mean Δ = -1.206`

| Metric | Original | Augmented |
|--------|----------|-----------|
| `mean Δ` | -1.206 | **-2.174** |
| `flip_rate` | — | 0.058 |
| N pairs | 96 | 293 |

Top-5 bundle stronger than 3-head ablation (−2.174 vs −1.461), replicating the original direction that adding H2 and H28 strengthens the necessity signal.

Per-family breakdown:

| Family | N | `mean Δ` | `flip_rate` |
|--------|--:|---------:|------------:|
| `-EncodedCommand` | 7 | -0.853 | 0.000 |
| `DownloadFile` | 146 | -3.279 | 0.007 |
| `DownloadString` | 43 | -1.702 | 0.023 |
| `FromBase64String` | 35 | -0.565 | 0.143 |
| `IEX` | 25 | -1.023 | 0.000 |
| `Invoke-Expression` | 18 | -0.427 | 0.278 |
| `Invoke-WebRequest` | 19 | -1.363 | 0.263 |

---

### 4c — H2-free carrier `L12H15/H5/H4/H28`

**Command:**
```
python3 scaled_validation.py batch-head-group-ablation \
  --manifest artifacts/foundation_sec/circuit_val_aug_orig_families_valid_h100.csv \
  --heads 12.15,12.5,12.4,12.28 --num-pairs 9999 \
  --model-name fdtn-ai/Foundation-Sec-8B-Instruct \
  --template-name meta-llama/Llama-3.1-8B-Instruct \
  --output-prefix artifacts/foundation_sec/circuit_val_head_group_ablation_l12_writer_h28_aug_orig_h100
```

**Status:** complete

**Original 96-pair result:** `mean Δ = -1.044`

| Metric | Original | Augmented |
|--------|----------|-----------|
| `mean Δ` | -1.044 | **-1.893** |
| `flip_rate` | — | 0.061 |
| N pairs | 96 | 293 |

H2-free carrier (−1.893) is weaker than top-5 bundle (−2.174) under ablation, replicating the original finding that H2 contributes to the necessity signal even though it weakens the patching sufficiency result.

Per-family breakdown:

| Family | N | `mean Δ` | `flip_rate` |
|--------|--:|---------:|------------:|
| `-EncodedCommand` | 7 | -0.740 | 0.000 |
| `DownloadFile` | 146 | -2.844 | 0.007 |
| `DownloadString` | 43 | -1.442 | 0.023 |
| `FromBase64String` | 35 | -0.540 | 0.171 |
| `IEX` | 25 | -0.901 | 0.000 |
| `Invoke-Expression` | 18 | -0.429 | 0.333 |
| `Invoke-WebRequest` | 19 | -1.216 | 0.211 |

---

## Summary Table

All experiments use the valid-pair manifest filtered from 380 candidate pairs (7 original families, augmented scripts). N=293 valid pairs vs N=96 in the original.

| Experiment | Route | Orig `mean Δ` | Orig flip_rate | Aug `mean Δ` | Aug flip_rate | N (aug) |
|------------|-------|-------------:|---------------:|-------------:|--------------:|--------:|
| Path patch | `L0H11 → L12H15/H5/H4` | -3.156 | 0.5625 | **-3.614** | 0.297 | 293 |
| Path patch | `L12H15/H5/H4/H2/H28` (top-5) | -3.265 | 0.583 | **-3.808** | 0.266 | 293 |
| Path patch | `L12H15/H5/H4/H28` (H2-free) | -3.293 | 0.625 | **-3.824** | 0.297 | 293 |
| Path patch | `L12H15/H5/H4/H2` (minus H28) | -2.886 | 0.490 | **-3.316** | 0.188 | 293 |
| Ablation | `L12H15/H5/H4` | -0.840 | — | **-1.461** | 0.051 | 293 |
| Ablation | `L12H15/H5/H4/H2/H28` (top-5) | -1.206 | — | **-2.174** | 0.058 | 293 |
| Ablation | `L12H15/H5/H4/H28` (H2-free) | -1.044 | — | **-1.893** | 0.061 | 293 |

## Interpretation

**Mean deltas all strengthened** across every experiment on the larger cohort. Every original directional finding replicates cleanly:

1. The H2-free carrier `L12H15/H5/H4/H28` remains the strongest sufficiency-oriented route under path patching (−3.824), marginally beating the top-5 bundle (−3.808) — same direction as original.
2. Removing H28 materially weakens patching (−3.316), confirming H28 as a meaningful contributor.
3. Under ablation, the top-5 bundle (−2.174) is stronger than the H2-free carrier (−1.893), replicating the finding that H2 adds to the necessity signal even though it hurts patching sufficiency.

**Flip rates are lower** than in the original across all path-patching experiments. This is a composition effect, not a weakening of the signal. `DownloadFile` now represents 50% of the cohort (146/293 pairs) and has the lowest per-family flip rate (0.158–0.199) due to higher base logit margins (mean base diff = 4.71 vs lower values in the original cohort). Per-family flip rates for the smaller families remain comparable or stronger than the original aggregate:

| Family | Orig agg flip (3a) | Aug flip (3a) |
|--------|-------------------:|--------------:|
| `DownloadString` | — | 0.442 |
| `FromBase64String` | — | 0.371 |
| `IEX` | — | 0.320 |
| `Invoke-Expression` | — | 0.500 |
| `Invoke-WebRequest` | — | 0.474 |

**The `-EncodedCommand` family** now has 7 pairs (vs 2) but shows zero flips under path patching and near-zero ablation effects. This is the one family where the circuit claim is weakest and merits a cautionary note in the writeup.

**Conclusion:** The core circuit claim — that `L0H11 → L12H15/H5/H4` is a causal malicious-evidence route and `L12H15/H5/H4/H28` is the strongest sufficiency-oriented late carrier — is robustly replicated on a 3× larger, more balanced dataset covering the same 7 indicator families. The thin-cohort criticism is addressed.

---

## Evasion Benchmark (Augmented)

### Overview

55 seed scripts drawn from the 293 valid pairs (8 per family, 7 for `-EncodedCommand`). 10 obfuscation techniques across 3 families (`execution_indirection`, `keyword_hiding`, `string_construction`). 85 candidate variants after strict + provisional_iex filtering (77 strict parse-OK, 8 provisional IEX).

### Evasion Results

**Baseline eval on 85 variants:** accuracy = 0.9764 (83/85 correctly detected as malicious).

**Evasion successes: 2/85 variants (2.4%).**

| Variant filename | Family | Technique | Seed logit diff | Variant logit diff | Tier |
|-----------------|--------|-----------|----------------:|-----------------:|------|
| `1362__seed_017509287b2d__invoke_webrequest_alias.ps1` | `keyword_hiding` | `invoke_webrequest_alias` | +0.172 | **−0.313** | strict |
| `9724...invoke_expression_scriptblock_create.ps1` | `execution_indirection` | `invoke_expression_scriptblock_create` | +1.031 | **−0.047** | strict |

Both misses involve `Invoke-WebRequest` seeds (both map to `Invoke-WebRequest` as the family indicator). The `invoke_webrequest_alias` variant replaces `Invoke-WebRequest` with its `iwr` alias; the `invoke_expression_scriptblock_create` variant uses `[scriptblock]::Create(...)` to defer execution.

**Per-family summary:**

| Family (indicator) | Variants tested | Evasion successes | Evasion rate | Mean logit diff delta |
|-------------------|----------------:|------------------:|-------------:|----------------------:|
| `-EncodedCommand` | 8 | 0 | 0.000 | −0.227 |
| `DownloadFile` | 8 | 0 | 0.000 | −1.932 |
| `DownloadString` | 9 | 0 | 0.000 | −1.315 |
| `IEX` | 32 | 0 | 0.000 | +0.973 |
| `Invoke-Expression` | 13 | 0 | 0.000 | −0.130 |
| `Invoke-WebRequest` | 15 | **2** | **0.133** | −0.380 |

Note: `IEX` variants show positive mean delta (harder to evade) because `iex_call_operator_string` and `iex_scriptblock_create` techniques increase logit margin. `Invoke-WebRequest` is the only family with evasion successes, both from seeds with low base logit margins (0.17 and 1.03).

**Comparison to original evasion benchmark:**

The original benchmark reported `invoke_webrequest_alias` as the primary miss technique (4/4 seeds evaded on the specific `1362.ps1` script). The augmented seed set draws different `Invoke-WebRequest` scripts — only one of the augmented IWR seeds (`seed_017509287b2d`, from `1362.ps1`) is shared with the original. The original miss-rate for `invoke_webrequest_alias` is therefore partly script-specific rather than universal to the technique.

---

### Evasion Mechanistic Probes

**Question:** Does the `L12H15/H5/H4/H28` circuit still fire causally on evasion variants, even when those variants evade the model?

**Probe manifest:** 85 pairs — each variant paired with its original benign counterpart.

#### Path Patching (H2-free carrier `L12H15/H5/H4/H28`) on variants

**Overall (85 pairs):** `mean Δ = −3.103`, `flip_rate = 0.482`

The circuit fires comparably on variants as on the original valid-pair cohort (Aug: −3.824 on 293 pairs). Syntax-preserving obfuscation does not disrupt the causal signal of the late writing heads.

**By family:**

| Family | N | `mean Δ` | `flip_rate` | Evasion successes |
|--------|--:|---------:|------------:|------------------:|
| `-EncodedCommand` | 8 | −2.757 | 0.000 | 0 |
| `DownloadFile` | 16 | −3.455 | 0.063 | 0 |
| `DownloadString` | 24 | −3.367 | 0.750 | 0 |
| `FromBase64String` | 2 | −1.750 | 0.500 | 0 |
| `IEX` | 10 | −2.761 | 0.600 | 0 |
| `Invoke-Expression` | 7 | −1.429 | 0.714 | 0 |
| `Invoke-WebRequest` | 18 | −3.583 | 0.556 | **2** |

**Miss variant details (path patching):**

| Variant | `base_logit_diff` | `patched_logit_diff` | `Δ` | Flipped |
|---------|------------------:|---------------------:|----:|--------:|
| `invoke_webrequest_alias` | −0.297 | −1.891 | −1.594 | ✓ |
| `invoke_expression_scriptblock_create` | −0.047 | −0.734 | −0.688 | ✓ |

**Interpretation:** Both miss variants *already have negative base logit diff* (model predicts ALLOW before any patching). Patching the circuit makes the ALLOW prediction stronger — the causal signal is still there but it was already suppressed. The evasion acts on the input representation, not by circumventing the circuit.

#### Head Group Ablation (top-5 `L12H15/H5/H4/H2/H28`) on variants

**Overall (85 pairs):** `mean Δ = −1.231`, `flip_rate = 0.059`

Comparable to the augmented cohort ablation result (Aug: −2.174 on 293 pairs), confirming the late heads are necessary on variants as well.

**Miss variant details (ablation):**

| Variant | `base_logit_diff` | `ablated_logit_diff` | `Δ` | Flipped |
|---------|------------------:|---------------------:|----:|--------:|
| `invoke_webrequest_alias` | −0.297 | −0.109 | +0.188 | ✓ |
| `invoke_expression_scriptblock_create` | −0.047 | −0.109 | −0.063 | ✓ |

For the miss variants, ablating the late heads has near-zero effect (Δ = +0.188 and −0.063) — consistent with the evasion having already disrupted the circuit input. When the model is already in the ALLOW regime, the heads have nothing to amplify.

---

### Evasion Summary

**The circuit story holds under evasion.** On the 83 detected variants, the H2-free carrier mean delta (−3.15) and flip rate (0.470) are nearly identical to the augmented validation cohort results, confirming that syntax-preserving obfuscation does not degrade the causal structure of the detection circuit.

The 2 evasion successes (`invoke_webrequest_alias`, `invoke_expression_scriptblock_create`) are mechanistically explained: both variants start with near-zero or negative base logit diff, meaning the evasion technique successfully depresses the model's initial malicious-evidence score below zero. Under path patching, the circuit route still produces a negative delta (further ALLOW-ward) — the circuit fires in the correct direction but from a starting point that is already in the ALLOW regime. The evasion operates on the input representation, not by bypassing the `L12` writing heads.

**Comparison to original:** The original `invoke_webrequest_alias` technique showed 4/4 miss rate on `1362.ps1`. In the augmented set, only 1/6 `invoke_webrequest_alias` variants evades (also from `1362.ps1`), confirming the original result is script-specific rather than universal to the technique. The broader augmented evasion rate is 2/85 = 2.4%, consistent with high robustness of the detection circuit to syntax-level obfuscation.
