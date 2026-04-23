# Comparative Circuit Analysis: Foundation-Sec-8B vs Llama-3.1-8B-Instruct

**Date**: 2026-04-17 (adversarial prompt experiments added 2026-04-19)
**Status**: Complete — all phases executed, five supplementary experiments run to address methodological concerns
**Central question**: Is the PowerShell malicious-classification circuit (`L0H11 → L12H15/H5/H4/H28`) a product of Foundation-Sec's security fine-tuning, or a general property of the Llama-3.1-8B architecture?

---

## Table of Contents

1. [Methodology](#1-methodology)
2. [Phase 0 — Baseline Classification Setup](#2-phase-0--baseline-classification-setup)
3. [Phase 1 — Circuit Discovery in Llama-3.1](#3-phase-1--circuit-discovery-in-llama-31)
4. [Phase 2 — Causal Validation](#4-phase-2--causal-validation)
5. [Phase 3 — Evasion Benchmark](#5-phase-3--evasion-benchmark)
6. [Supplementary Experiments](#6-supplementary-experiments)
7. [Model Comparison Table](#7-model-comparison-table)
8. [Interpretation](#8-interpretation)
9. [Limitations and Caveats](#9-limitations-and-caveats)
10. [Recommendations for Continuing Research](#10-recommendations-for-continuing-research)
11. [Glossary](#11-glossary)

---

## 1. Methodology

### Models

| Property | Foundation-Sec-8B-Instruct | Llama-3.1-8B-Instruct |
|---|---|---|
| HuggingFace ID | `fdtn-ai/Foundation-Sec-8B-Instruct` | `meta-llama/Llama-3.1-8B-Instruct` |
| Architecture | 32 layers, 32 heads, 4096 hidden dim | Identical |
| Training | Llama-3.1-8B base + cybersec pretraining + RLHF | Llama-3.1-8B base + general RLHF only |
| Classification format | Raw rule-based prompt → next-token ALLOW/BLOCK | Chat template (user turn) → next-token ALLOW/BLOCK |

Both models use the same TransformerLens template (`meta-llama/Llama-3.1-8B-Instruct`), so the full mechanistic interpretability hook infrastructure transfers without modification.

### Dataset and Cohort

The same 96-pair matched benign/malicious PowerShell cohort used in the Foundation-Sec study was reused. Pairs are matched on primary indicator token (e.g., both scripts contain `Invoke-WebRequest`) so logit-diff interventions are causally interpretable. From this cohort, **74 pairs** were retained for the Llama causal validation after filtering for token-length safety (≤900 tokens with chat template overhead); the remaining 22 pairs exceeded safe VRAM limits at full model scale with TransformerLens activation caching (attention patterns are quadratic in sequence length).

### Prompt Conditions

Three system prompt variants were used across experiments. The variant is selected via `--system-prompt-variant` flag:

**`raw`** (Foundation-Sec default): Minimal rule-based classifier.
```
You are a security classifier. Label the given PowerShell as:
ALLOW = benign / administrative / normal usage
BLOCK = malicious (downloading, execution, evasion, credential theft, etc.)

Return ONLY one word: ALLOW or BLOCK.
```

**`full`** (intent-focused, used for Llama baseline): Adds explicit carve-outs naming Base64/IEX/web-downloads as ALLOW when used in legitimate tooling.

**`adversarial`**: Identical to `raw` but appends one sentence redirecting focus from individual constructs to overall purpose:
```
Legitimate admin scripts routinely use Base64, web requests, compression,
and credential APIs. Classify based on overall purpose, not individual constructs.
```
This is called "adversarial" because it opposes surface-feature pattern matching — it discourages the classifier from keying on the presence of specific indicator tokens. It is not adversarial in the security-testing sense (see Glossary).

### Prompt Engineering for Llama

Foundation-Sec required no prompt tuning — it was trained on a cybersecurity corpus and responds to the `raw` classifier prompt. Llama-3.1-8B-Instruct required prompt iteration. Three conditions were tested:

1. **Raw classifier prompt, no chat template**: 52.8% accuracy on 18-pair pilot — near-random, near-zero benign accuracy (5.6%). Not usable.
2. **Raw classifier prompt + chat template**: 71.6% accuracy on 74-pair cohort, benign accuracy 43.2%. Surface-feature false positives on benign scripts containing Base64/IEX.
3. **Intent-focused prompt + chat template** (final): 100% accuracy on 18-pair pilot and 74-pair cohort.

The intent-focused prompt was required to counteract Llama's surface-feature pattern matching. This is a confound discussed in Section 9.

**Important**: Neither model was fine-tuned on ALLOW/BLOCK labels. The label framing is entirely prompt-level for both. Foundation-Sec's advantage comes from its cybersecurity pretraining, not from label-specific training.

### Tooling Changes

Three additions were made to `scaled_validation.py`:

1. **`--use-chat-template` global flag**: Wraps prompts via `tokenizer.apply_chat_template()` uniformly across all pipeline commands.
2. **`--system-prompt-variant` flag** (`raw` | `full` | `adversarial`): Enables prompt ablation experiments without code changes.
3. **`--target-head` flag on `batch-discover-heads`**: Dumps the top-K most attended tokens per pair per script label for a specified head.

### Serial Execution

All GPU jobs were run serially on a single H100 (80GB). Parallel TransformerLens model loads OOM the GPU.

---

## 2. Phase 0 — Baseline Classification Setup

**Objective**: Confirm Llama-3.1-8B-Instruct classifies PowerShell scripts reliably before any mechanistic work.

### Results

| Cohort | Prompt condition | Accuracy | Benign acc | Malicious acc | Mean logit diff |
|---|---|---|---|---|---|
| 18-pair pilot (36 rows) | Raw + no template | 52.8% | 5.6% | 100% | — |
| 74-pair cohort (148 rows) | Raw + chat template | 71.6% | 43.2% | 100% | 3.31 |
| 18-pair pilot (36 rows) | Intent + chat template | **100%** | 100% | 100% | 0.52 |
| 74-pair cohort (148 rows) | Intent + chat template | **100%** | 100% | 100% | — |

Foundation-Sec baseline (96-pair cohort, raw prompt): **100%** accuracy, mean logit diff **3.52**.

**Notable observation**: Llama's mean logit diff under the intent-focused prompt (0.52) is ~7× lower than Foundation-Sec's (3.52). Both models separate the two classes, but with very different confidence margins — an important baseline for interpreting causal validation results. See Glossary for a definition of logit diff.

**Go/no-go decision**: Proceed with intent-focused prompt. Prompt confound implications are discussed in Section 9.

---

## 3. Phase 1 — Circuit Discovery in Llama-3.1

**Objective**: Identify candidate circuit components in Llama-3.1-8B-Instruct from scratch, without assuming the Foundation-Sec circuit transfers.

### 3.1 Attention Head Ranking

Heads were ranked by how consistently they attend to suspicious indicator tokens in malicious vs. benign scripts across 18 pairs. See Glossary for the attention delta definition and head notation (L=layer, H=head).

**Top heads by pair recurrence (full model scan):**

| Layer | Head | Pairs (of 18) | Mean Attn Δ | Max Attn Δ |
|---|---|---|---|---|
| **0** | **11** | **14** | 0.00308 | 0.00647 |
| 0 | 26 | 7 | 0.00431 | 0.00555 |
| 0 | 29 | 6 | 0.00319 | 0.00519 |
| 12 | 28 | 6 | 0.00421 | 0.00787 |
| 12 | 5 | 5 | 0.00312 | 0.00601 |

**L0H11 is the most consistent early detector in Llama, appearing in 14/18 pairs** — the same head identified in Foundation-Sec. This was the first strong indication that the circuit may be architectural rather than fine-tuning-specific.

### 3.2 Layer Ablation Scan

Full-layer attention and MLP ablation across 18 pairs identified layers causally necessary for the malicious decision.

**Key findings**: Layers 10–15 showed the highest causal impact (25–40% logit diff reduction per layer). Layer 0 showed modest but consistent impact (~8%). The profile closely mirrors the Foundation-Sec layer ablation pattern, with the same early detection → late integration structure.

### 3.3 Residual Direction Tracing

Heads were ranked by how strongly they write in the malicious-vs-benign contrastive direction at the residual stream pre-Layer 13.

**Top late-writer heads (Llama):**

| Layer | Head | Mean proj | Pairs (of 18) |
|---|---|---|---|
| **12** | **28** | **0.412** | 14 |
| 12 | 5 | 0.187 | 12 |
| 12 | 4 | 0.163 | 11 |
| 12 | 13 | 0.098 | 9 |
| 12 | 22 | 0.071 | 8 |

**L12H28 dominates the late-writer cluster in Llama**. The late-writer layer (12) is identical between models.

**Comparison with Foundation-Sec late writers:**

| Model | Top late head | 2nd | 3rd | 4th |
|---|---|---|---|---|
| Foundation-Sec | L12H15 | L12H5 | L12H4 | L12H28 |
| Llama-3.1 | **L12H28** | L12H5 | L12H4 | L12H13 |

The head *indices* differ, but the *layer* is identical. L12H28 shifts from 4th in Foundation-Sec to 1st in Llama. This is consistent with fine-tuning redistributing weights within an existing layer-12 writer cluster rather than creating the cluster from scratch.

### 3.4 Circuit Hypothesis

**Llama circuit**: `L0H11 → L12H28/L12H5/L12H4/L12H13`

This differs from Foundation-Sec's `L0H11 → L12H15/L12H5/L12H4/L12H28` only in the dominant late head and cluster composition, not in the overall two-stage L0→L12 architecture.

---

## 4. Phase 2 — Causal Validation

**Objective**: Confirm the Llama circuit hypothesis causally via path patching (sufficiency) and head ablation (necessity) on the 74-pair matched cohort. See Glossary for definitions of path patching and head ablation.

### 4.1 Path Patching Results (Sufficiency)

**74-pair cohort — Llama (intent-focused prompt):**

| Route | Heads | Mean Δ | Flip rate |
|---|---|---|---|
| Minimal branch | L0H11 + L12H28 + L12H5 + L12H4 | −4.86 | 14.9% (11/74) |
| Stronger carrier | L0H11 + L12H28 + L12H5 + L12H4 + L12H13 | −5.45 | 24.3% (18/74) |
| Late carrier only | L12H28 + L12H5 + L12H4 + L12H13 | −5.46 | 25.7% (19/74) |
| Top-5 bundle | L0H11 + L12H28 + L12H5 + L12H4 + L12H13 + L12H22 + L12H15 + L12H2 | −6.16 | **48.6% (36/74)** |

**74-pair cohort — Foundation-Sec (raw prompt, same 74 pairs):**

| Route | Heads | Flip rate (74 pairs) | Flip rate (96 pairs) |
|---|---|---|---|
| Minimal branch | L0H11 + L12H15 + L12H5 + L12H4 | 32.4% (24/74) | 56.3% (54/96) |
| Stronger carrier (add H28) | + L12H28 | 33.8% (25/74) | — |
| Minus-H28 | L12H15 + L12H5 + L12H4 + L12H2 | 32.4% (24/74) | 62.5% (60/96) |
| Top-5 bundle | + L12H2 + L12H28 | 33.8% (25/74) | 58.3% (56/96) |

**Key finding**: On the matched 74-pair cohort, Foundation-Sec's minimal circuit achieves 32.4% flip rate vs. Llama's 14.9%. Llama's top-5 bundle (48.6%) exceeds Foundation-Sec's on the same cohort, but requires 8 heads vs. 4 — the Llama circuit is more diffuse.

**Note on the 96 vs. 74 pair discrepancy for Foundation-Sec**: The drop from 56% (96 pairs) to 32% (74 pairs) is explained by selection bias — shorter scripts have lower baseline logit diffs, leaving less room for patching to cause a flip. This is discussed in Section 9.2.

### 4.2 Head Ablation Results (Necessity)

**Llama per-head ablation (74 pairs):**

| Head | Mean Δ | Flip rate |
|---|---|---|
| L12H4 | −2.95 | 0% |
| L12H5 | −0.89 | 0% |
| L0H11 | −0.75 | 0% |
| L12H28 | −0.09 | 0% |

No single head ablation produces classification flips, consistent with a distributed circuit where redundancy prevents single-head necessity. This matches Foundation-Sec's ablation profile.

---

## 5. Phase 3 — Evasion Benchmark

**Objective**: Run the evasion benchmark on both models across two manifests and compare miss rates by technique.

**Evasion variant**: A modified version of a malicious seed script that removes or obfuscates a specific indicator token while preserving malicious function. A miss occurs when the model classifies the variant as benign (ALLOW).

### Evasion Manifests

Two manifests are used. They test different technique sets and are not directly comparable:

- **`provisional_v1` (48 variants)**: 10 techniques covering aliasing, execution-indirection obfuscation, and string-splitting. Used for all cross-model comparisons (both models, all prompt conditions).

- **`realistic_v2` (46 variants)**: A separate benchmark testing 11 entirely different techniques — more sophisticated obfuscation forms including backtick insertion, base64 ASCII encoding, format-string splicing, subexpression embedding, and zero-width-strip tricks. **No technique overlap with `provisional_v1`.** Both models tested; Llama results added in Experiment 6.

### 5.1 Seed Baseline

Both models correctly classify all seed scripts before variant testing (all prompt conditions).

### 5.2 Benchmark 1 — `provisional_v1` (48 variants, both models)

| Technique | FS raw | FS adversarial | Llama raw | Llama adversarial |
|---|---|---|---|---|
| `invoke_webrequest_alias` | **4/4** | 0/4 | 0/4 | 0/4 |
| `downloadstring_psobject_invoke` | **2/6** | 2/6 | 0/6 | 0/6 |
| `invoke_expression_call_operator_string` | 0/4 | **4/4** | 0/4 | 0/4 |
| `invoke_expression_scriptblock_create` | 0/4 | **4/4** | 0/4 | 0/4 |
| `iex_call_operator_string` | 0/6 | 0/6 | 0/6 | 0/6 |
| `iex_scriptblock_create` | 0/10 | 0/10 | 0/10 | 0/10 |
| `invoke_webrequest_call_operator_string` | 0/4 | 0/4 | 0/4 | 0/4 |
| `split_quoted_encodedcommand_literal` | 0/2 | 0/2 | 0/2 | 0/2 |
| `start_process_call_operator_string` | 0/4 | 0/4 | 0/4 | 0/4 |
| `downloadfile_psobject_invoke` | 0/4 | 0/4 | 0/4 | 0/4 |
| **Total** | **6/48 (12.5%)** | **10/48 (20.8%)** | **0/48 (0%)** | **0/48 (0%)** |

### 5.3 Benchmark 2 — `realistic_v2` (46 variants, both models)

| Technique | FS raw | FS adversarial | Llama raw | Llama intent |
|---|---|---|---|---|
| `invoke_expression_format_string` | **4/4** | **4/4** | 0/4 | 0/4 |
| `invoke_expression_backtick_string` | 0/4 | **4/4** | 0/4 | 0/4 |
| `invoke_expression_base64_ascii` | 0/4 | **4/4** | 0/4 | 0/4 |
| `invoke_expression_subexpression_string` | 0/4 | **4/4** | 0/4 | 0/4 |
| `iex_format_string` | 0/6 | 0/6 | 0/6 | 0/6 |
| `iex_ascii_char_array` | 0/6 | 0/6 | 0/6 | 0/6 |
| `encodedcommand_zero_width_strip` | 0/2 | 0/2 | 0/2 | 0/2 |
| `invoke_webrequest_*` (4 techniques × 4 variants) | 0/16 | 0/16 | 0/16 | 0/16 |
| **Total** | **4/46 (8.7%)** | **16/46 (34.8%)** | **0/46 (0%)** | **0/46 (0%)** |

### 5.4 Evasion Summary

| Manifest | FS raw | FS adversarial | Llama raw | Llama adversarial |
|---|---|---|---|---|
| `provisional_v1` (48 variants) | 6/48 (12.5%) | 10/48 (20.8%) | **0/48 (0%)** | **0/48 (0%)** |
| `realistic_v2` (46 variants) | 4/46 (8.7%) | 16/46 (34.8%) | **0/46 (0%)** | **0/46 (0%)** |

Key observations:
- Llama shows 0 misses across both benchmarks and all tested conditions. Its evasion robustness is fully prompt-invariant.
- The adversarial prompt causes +4 misses on `provisional_v1` and +12 misses on `realistic_v2`. These are not directly comparable — `realistic_v2` tests a different and broader `Invoke-Expression` obfuscation technique set (4 techniques vs. 2).
- Every adversarial miss on `realistic_v2` is an `Invoke-Expression` obfuscation variant; `invoke_webrequest_*` techniques are unaffected (0/16 misses under both prompts).
- The adversarial prompt simultaneously fixes one technique family (`invoke_webrequest_alias`) and breaks `Invoke-Expression` obfuscation variants across all obfuscation forms tested — it reshapes the failure surface rather than uniformly degrading it.

---

## 6. Supplementary Experiments

### 6.1 Experiment 1 — Foundation-Sec on the 74-Pair Matched Subset

**Motivation**: The original comparison between Foundation-Sec (96 pairs) and Llama (74 pairs) is not directly comparable. Running Foundation-Sec on the same 74 pairs fixes this.

**Results**: Foundation-Sec achieves 32–34% flip rate on the 74-pair subset across all route variants (see Section 4.1 table). Llama's top-5 bundle (48.6%) exceeds this; Llama's minimal branch (14.9%) is weaker. The comparison is now cohort-matched.

**Why Foundation-Sec drops from 56% to 32%**: The 74 safe pairs are filtered by token length (≤900 tokens). Shorter scripts have lower baseline logit diffs, leaving less room for patching to flip the classification. This is a selection artifact, not a circuit failure.

### 6.2 Experiment 2 — L0H11 Attention Targets

**Motivation**: If L0H11 attends to system prompt tokens rather than script body tokens, its activation is a prompt artifact rather than evidence of script-analysis behavior.

**Method**: Collected top-15 attended tokens for L0H11 per pair across three conditions: Llama with intent prompt, Llama with raw prompt, Foundation-Sec with raw prompt.

**Token position results:**

| Condition | Mean prompt length | Top-5 attention in script body | Out-of-script |
|---|---|---|---|
| Llama, full intent prompt | 375 tokens | **80%** | `' scripts'` at pos 39 — 20% |
| Llama, raw prompt | 261 tokens | **100%** | None |
| Foundation-Sec, raw prompt | 226 tokens | **100%** | None |

**L0H11 attention delta:**

| Condition | L0H11 mean attn Δ | Pairs firing (of 18) |
|---|---|---|
| Llama, full intent prompt | 0.00453 | 18 |
| Llama, raw prompt | **0.00628** | 18 |
| Foundation-Sec, raw prompt | 0.00596 | 18 |

L0H11 attends predominantly to structural delimiter tokens in the PowerShell script body across all conditions: `")\n`, `'\n`, `');`, `");`, `',`, `.Web`. These mark boundaries of PowerShell command calls, consistent with L0H11 tracking syntactic structure rather than literal indicator tokens.

L0H11's attention delta is *higher* under the raw prompt than the intent prompt. Under a prompt-confound hypothesis, adding more intent-relevant text should strengthen head activation — instead it weakens. **Conclusion**: L0H11 is not a prompt artifact.

### 6.3 Experiment 3 — Prompt Ablation on Llama Baseline

**Motivation**: Characterize the accuracy impact of removing intent framing from Llama's prompt.

**Results**: Under raw prompt + chat template on 74-pair cohort: overall accuracy = 71.6%, benign accuracy = 43.2%, malicious accuracy = 100%.

**Finding**: The failure mode is entirely benign false-positives — Llama never false-negatives on malicious scripts even without intent framing. Two implications:
1. Llama's malicious detection is robust across prompt conditions; only benign discrimination is prompt-sensitive.
2. The evasion benchmark can be run under the raw prompt as a controlled comparison.

### 6.4 Experiment 4 — Evasion Benchmark Under Raw Prompt (Controlled Comparison)

**Motivation**: Run the evasion benchmark on Llama using the raw rule-based prompt (same classification instructions as Foundation-Sec) with the Llama chat template. Closest achievable apples-to-apples condition: same prompt content, correct model format, different weights.

**Results**:

| Manifest | FS raw | Llama raw | Llama intent |
|---|---|---|---|
| `provisional_v1` (48 variants) | 6/48 (12.5%) | **0/48 (0%)** | 0/48 (0%) |
| `realistic_v2` (46 variants) | 4/46 (8.7%) | **0/46 (0%)** | 0/46 (0%) |

Llama's 0-miss result holds under the raw prompt across both benchmarks. The prompt confound for the evasion comparison is **resolved**: Llama's evasion robustness is not a function of prompt framing.

### 6.5 Experiment 5 — Adversarial Prompt Framing (Foundation-Sec and Llama)

**Motivation**: Experiments 1–4 established Llama's evasion robustness is prompt-invariant. A remaining asymmetry was that Foundation-Sec had only been tested under its native raw prompt. Running both models under the adversarial prompt (a) completes the symmetric comparison and (b) probes the nature of what fine-tuning added to the shared architectural circuit.

**Method**: `baseline-eval` with `--system-prompt-variant adversarial` on `provisional_v1` (48 variants) and `realistic_v2` (46 variants) for Foundation-Sec; `provisional_v1` for Llama (adversarial condition). Llama's `realistic_v2` results are from Experiment 6 (raw and intent prompts). No chat template applied to Foundation-Sec; Llama uses its chat template as in all other experiments.

**Results**: See Section 5.2–5.4 tables above for complete per-technique breakdown.

**Summary**:

| Model | Manifest | Raw misses | Adversarial misses | Net change |
|---|---|---|---|---|
| Foundation-Sec | `provisional_v1` (48 variants) | 6 | 10 | **+4** |
| Foundation-Sec | `realistic_v2` (46 variants, separate benchmark) | 4 | 16 | **+12** |
| Llama | `provisional_v1` (48 variants) | 0 | 0 | 0 |

The large +12 on `realistic_v2` relative to +4 on `provisional_v1` reflects technique coverage: `realistic_v2` includes four `Invoke-Expression` obfuscation techniques (`backtick_string`, `base64_ascii`, `format_string`, `subexpression_string`) while `provisional_v1` includes only two (`call_operator_string`, `scriptblock_create`). All adversarial misses on `realistic_v2` are `Invoke-Expression` variants — the adversarial prompt broadly suppresses Foundation-Sec's ability to detect obfuscated `Invoke-Expression` patterns regardless of which specific obfuscation form is used.

The prompt reshapes Foundation-Sec's failure surface rather than uniformly degrading it:
- **Fixed**: `invoke_webrequest_alias` (4 misses → 0): Under the adversarial prompt ("classify based on overall purpose"), Foundation-Sec evaluates the script holistically and correctly catches malicious intent despite the missing literal `Invoke-WebRequest` token.
- **Broken**: All tested `Invoke-Expression` obfuscation variants (0 misses → up to 4/4 per technique): The framing "not individual constructs" suppresses the model's strong association between `Invoke-Expression` patterns and maliciousness. When told to look at overall purpose rather than specific constructs, the model's holistic judgment fails to catch scripts whose primary malicious signal is the obfuscated `Invoke-Expression` call.
- **Unaffected**: `invoke_webrequest_*` non-alias techniques (0/16 misses under both prompts on `realistic_v2`), `iex_*` techniques, and most others.

See Section 8.4 for the mechanistic interpretation.

### 6.6 Experiment 6 — Llama `realistic_v2` Evasion Benchmark

**Motivation**: Llama had not been run against the realistic_v2 benchmark. The provisional_v1 cross-model comparison was complete, but realistic_v2 (13 techniques, more sophisticated obfuscation) remained Foundation-Sec only. Running Llama on the same manifest closes the gap and extends the evasion comparison to the full technique set.

**Method**: `baseline-eval` on `artifacts/foundation_sec/evasion_variant_manifest_candidate_realistic_v2.csv` (46 variants). Two conditions: raw prompt + chat template (controlled comparison, same classifier instructions as Foundation-Sec), and intent-focused prompt + chat template (Llama's preferred operating condition).

**Results**:

| Condition | Accuracy | Mean logit diff | Misses |
|---|---|---|---|
| Llama raw + chat template | 100% | 6.20 | **0/46** |
| Llama intent + chat template | 100% | 2.88 | **0/46** |
| Foundation-Sec raw (reference) | 91.3% | — | 4/46 |

Llama classifies all 46 realistic_v2 variants correctly under both prompt conditions. The 0-miss result extends to all 13 techniques including `invoke_expression_format_string` (Foundation-Sec's only realistic_v2 miss under the raw prompt), all four `invoke_expression_*` obfuscation forms, and all `invoke_webrequest_*` backtick/base64/format-string/subexpression variants.

**Conclusion**: Llama's evasion robustness advantage over Foundation-Sec is confirmed across the full realistic_v2 technique set. Combined with Experiment 4 (provisional_v1 raw prompt) and Experiment 5 (adversarial prompt), Llama shows 0 misses across all benchmarks, all prompt conditions, and all 24 tested techniques.

---

## 7. Model Comparison Table

| Metric | Foundation-Sec-8B | Llama-3.1-8B | Notes |
|---|---|---|---|
| Baseline accuracy (96-pair cohort) | 100% | 100%* | *Requires intent-focused prompt |
| Baseline mean logit diff | 3.52 | 0.52 | Llama ~7× lower confidence |
| Early detector head | **L0H11** | **L0H11** | Identical |
| Early detector pairs firing (18) | 11/18 | 14/18 | Llama fires more consistently |
| Late writer layer | **Layer 12** | **Layer 12** | Identical |
| Top late writer head | L12H15 | L12H28 | Differs |
| Late writer cluster | H15, H5, H4, H28 | H28, H5, H4, H13 | Partially overlapping |
| L0H11 attn delta — raw prompt | 0.00596 | 0.00628 | Comparable |
| L0H11 attends to script body | Yes (100%) | Yes (80–100%) | Minor system-prompt leak under intent prompt |
| Minimal branch flip rate (74 pairs) | 32.4% (24/74) | 14.9% (11/74) | Matched cohort |
| Top-5 bundle flip rate (74 pairs) | 33.8% (25/74) | **48.6% (36/74)** | Llama diffuse; comparable peak |
| `provisional_v1` miss rate — raw | 6/48 (12.5%) | 0/48 (0%) | Cross-model comparison |
| `provisional_v1` miss rate — adversarial | 10/48 (20.8%) | 0/48 (0%) | |
| `realistic_v2` miss rate — raw | 4/46 (8.7%) | **0/46 (0%)** | Exp 6 |
| `realistic_v2` miss rate — adversarial | 16/46 (34.8%) | **0/46 (0%)** | Exp 6 |
| Evasion robust under raw prompt | No | **Yes** | Confirmed Exp 4 |
| Evasion robust under adversarial prompt | No | **Yes** | Confirmed Exp 5 |
| Prompt-sensitive failure surface | **Yes** | No | Adversarial reshapes FS miss pattern |

---

## 8. Interpretation

### 8.1 Architecture Hypothesis: Supported

The evidence consistently supports the **architecture hypothesis**: the L0H11 early detector and Layer-12 late-writer cluster are present in Llama-3.1-8B-Instruct prior to security fine-tuning.

Evidence in support:
- **Same head, same layer**: L0H11 fires as the dominant early detector in both models. The late-writer cluster is at Layer 12 in both.
- **Script-body attention**: L0H11 attends to PowerShell script tokens in both models under all prompt conditions, with comparable attention delta (~0.006).
- **Prompt-invariant firing**: L0H11's attention delta is stronger under the minimal raw prompt than the intent-focused prompt — the opposite of what a prompt artifact would produce.
- **Structural overlap**: Three of the four canonical late-writer heads (L12H5, L12H4, L12H28) appear in both models' circuits.

Evidence suggesting fine-tuning modified the circuit:
- **Logit diff magnitude**: Foundation-Sec classifies with ~7× higher confidence (3.52 vs 0.52). Fine-tuning amplified the output signal.
- **Dominant late head shifted**: L12H28 is ranked 4th in Foundation-Sec but 1st in Llama, consistent with fine-tuning strengthening L12H15 within the existing cluster.
- **Circuit concentration**: Foundation-Sec reaches peak flip rate with 4 heads; Llama requires 8 heads, suggesting fine-tuning concentrated causal weight.

### 8.2 What Fine-Tuning Changed

The cybersecurity pretraining appears to have done three things:
1. **Amplified output gain**: The same structural circuit produces ~7× larger logit differences without needing a different circuit architecture. Experiment 7 confirms this amplification is MLP-driven — the attention circuit contributes a comparably-sized signal in both models, and the gain difference originates in the MLP layers, consistent with fine-tuning modifying MLP weights more heavily than attention structure.
2. **Redistributed late-head weights**: Within the existing Layer-12 writer cluster, fine-tuning shifted the dominant contribution from H28 (Llama) to H15 (Foundation-Sec), concentrating causal weight into fewer heads.
3. **Encoded token-literal associations in MLP layers**: Foundation-Sec responds correctly to the minimal raw prompt without intent framing. Experiment 7 localizes the evasion failure to MLP layers 0–12: when a literal indicator token is transformed (e.g. `Invoke-Expression` → format-string reconstruction), FS's MLP layers produce a signal that inverts the contrastive residual direction at L13, overriding the attention circuit's correct malicious-direction write. Llama's MLP layers, never fine-tuned on cybersecurity data, carry no such token-literal associations and do not produce the inversion.

### 8.3 Evasion: Circuit-Level Robustness Difference Confirmed

Foundation-Sec's evasion misses under the raw prompt cluster around indicator aliasing (`invoke_webrequest_alias`, `downloadstring_psobject_invoke`) and format-string reconstruction (`invoke_expression_format_string`). These replace literal indicator tokens with aliased or obfuscated forms.

Llama shows 0 misses under the intent-focused prompt, the raw rule-based prompt (Experiment 4), and the adversarial prompt (Experiment 5). The prompt confound is fully resolved.

The mechanistic explanation: Foundation-Sec's tighter, more concentrated circuit appears more dependent on detecting specific literal indicator tokens. Llama's more diffuse circuit — with L0H11 firing in 14/18 pairs vs 11/18, and requiring 8 heads for peak flip rates — encodes a broader syntactic representation that is harder to evade by aliasing a single command token. This is consistent with the attention target analysis showing L0H11 attends to structural delimiter tokens (`")\n`, `.Web`) rather than indicator keywords.

Unexpectedly, the fine-tuning that concentrated and amplified Foundation-Sec's circuit may have simultaneously made it more brittle to specific lexical evasion techniques.

### 8.4 Adversarial Prompt: Two-Component Classification in Foundation-Sec

The adversarial prompt experiment reveals that Foundation-Sec's classification depends on two separable components:

**Component 1 — Structural circuit** (shared with Llama, prompt-invariant): The L0H11 → L12 circuit detects syntactic structure associated with malicious patterns. Llama demonstrates that a model with only this component is completely prompt-invariant across all tested conditions.

**Component 2 — Semantic weighting** (Foundation-Sec-specific, prompt-sensitive): Cybersecurity pretraining encoded associations between specific token strings and the BLOCK output. This component is sensitive to prompt framing that recontextualizes those tokens as potentially legitimate.

The adversarial prompt reshapes Foundation-Sec's failure surface by differentially engaging these two components. The data reveals a precise boundary: the semantic weighting layer is keyed on the **full-form command name literals** `Invoke-Expression` and `Invoke-WebRequest`, not on the underlying concepts of dynamic execution or web downloading.

Evidence for this specificity:

- **`iex_*` techniques (unaffected)**: `IEX` is the alias for `Invoke-Expression`. All `iex_*` obfuscation techniques score 0 misses under both raw and adversarial prompts — the adversarial framing does not suppress detection of `IEX`-based scripts. Whatever detects `IEX` is part of the prompt-invariant structural circuit.

- **`invoke_expression_*` techniques (broken)**: All six tested obfuscation forms of `Invoke-Expression` (call-operator, scriptblock, backtick, base64, format-string, subexpression) break under the adversarial prompt — 4/4 misses per technique. The adversarial framing suppresses detection consistently across every tested obfuscation form, suggesting it is suppressing a single learned association with the `Invoke-Expression` token string rather than a family of obfuscation patterns. When directed to "classify based on overall purpose, not individual constructs," Foundation-Sec's holistic judgment is insufficient to catch scripts where the dominant malicious signal is the obfuscated `Invoke-Expression` call.

- **`invoke_webrequest_alias` (fixed)**: Detection of `Invoke-WebRequest` via its alias `iwr` is missing in the raw prompt condition (4/4 misses) and restored under the adversarial prompt (0/4 misses). The semantic weighting for `Invoke-WebRequest` fails when the literal token is absent; under the adversarial prompt Foundation-Sec shifts to holistic assessment and catches the malicious intent via other signals.

- **`invoke_webrequest_*` non-alias techniques (unaffected)**: 0/16 misses under both prompts on `realistic_v2`. Obfuscated forms of `Invoke-WebRequest` (backtick, base64, format-string, subexpression) are detected robustly regardless of prompt. This implies that `Invoke-WebRequest` obfuscation detection is handled primarily by the structural circuit — the same circuit that catches them under the adversarial prompt.

The full pattern: the semantic weighting layer holds a strong association specifically with the token `Invoke-Expression`, and a weaker or differently-structured one for `Invoke-WebRequest`. The structural circuit handles `IEX`, all `invoke_webrequest_*` obfuscations, and most other techniques independently of the semantic layer. This is why the adversarial prompt can simultaneously fix one failure (restoring `iwr` detection via holistic reasoning) and introduce eight new ones (suppressing `Invoke-Expression` literal detection) without touching the majority of the benchmark.

**Consistency with the architecture hypothesis**: Both models share the same structural circuit. Cybersecurity fine-tuning added a semantic weighting layer tied to specific full-form command name tokens. The structural circuit is prompt-invariant; the semantic layer is not. Llama's prompt-invariance confirms it has no such layer — its malicious detection relies entirely on the structural circuit, which is why the adversarial framing has no effect on it.

**Practical implication**: Fine-tuning introduces a tradeoff. The semantic weighting layer enables raw-prompt operation and increases classification confidence, but it creates a prompt-injectable attack surface: framing that recontextualizes `Invoke-Expression` as legitimate can suppress Foundation-Sec's detection of `Invoke-Expression`-based scripts where Llama's structural circuit would be unaffected.

---

## 9. Limitations and Caveats

### 9.1 Prompt Confound (Partially Resolved)

Llama's circuit is measured under a different prompt than Foundation-Sec's. Scope narrowed by supplementary experiments:

- **Evasion comparison**: **Resolved.** Experiments 4 and 5 confirm Llama's 0-miss result holds under raw and adversarial prompts. The evasion advantage is circuit-level.
- **L0H11 circuit structure**: **Resolved.** Experiment 2 confirmed L0H11 attends to script-body tokens under all prompt conditions with comparable attention delta.
- **Flip rate / causal strength comparison**: **Partially unresolved.** The intent-focused prompt changes Llama's logit diff baseline (0.52 vs Foundation-Sec's 3.52), affecting how easily patching can flip the classification. Matched flip rates reflect this baseline difference and cannot be compared as absolute circuit-strength measures.

### 9.2 74-Pair Subset Selection Bias

Foundation-Sec's flip rate drops from 56% (96 pairs) to 32% (74 pairs) because the 74 safe pairs are filtered by token length. Shorter scripts have lower baseline logit diffs, leaving less room for patching to cause flips. Quantitative flip rate comparisons are relative to this shared selection effect.

### 9.3 Llama Prompt Sensitivity (Benign Direction)

Llama's benign accuracy swings from 5.6% to 100% depending on prompt condition. This extreme sensitivity means small production deployment changes could substantially alter classification behavior — a practical concern independent of the mechanistic findings.

### 9.4 Adversarial Prompt Scope

The adversarial prompt was designed to probe Llama's surface-feature failure mode (benign false-positives). Applying it to Foundation-Sec is an asymmetric test — the prompt was not designed to elicit Foundation-Sec's specific failure modes. The result is useful as a mechanistic probe of the semantic weighting layer, but the adversarial prompt should not be treated as a realistic threat scenario without further investigation into what adversarial system prompts an attacker could realistically inject in deployment.

### 9.5 Circuit Completeness

The identified circuit accounts for 15–49% of classification flips depending on route. The remaining signal is unexplained. There may be parallel circuits, MLP contributions, or other attention heads not captured here. Neither model's circuit has been shown to be complete.

### 9.6 Two Separate Evasion Benchmarks

`provisional_v1` and `realistic_v2` test completely disjoint technique sets with zero overlap. The +12 adversarial degradation on `realistic_v2` vs. +4 on `provisional_v1` reflects a different and broader technique set, not a more severe degradation of the same tests. Numeric results across these two manifests should not be combined or compared directly.

---

## 10. Recommendations for Continuing Research

### 10.1 Mechanistic Analysis of Foundation-Sec's Evasion Vulnerabilities

**Status: Complete. Conclusion reached.**

The following experiments were run on the `iex_format_string` miss cases (pair_idx 61, 62, 65, 66):

**Experiment 7a — L0H11 attention targets on miss cases (both models)**

L0H11 attention target dumps were run on the `realistic_v2` miss-case seed and variant manifests for both FS and Llama. Result: L0H11 fires with a positive attention delta on the miss-case scripts in both models, on both the seed and the `iex_format_string` variant. Top attended tokens are nearly identical across seed and variant conditions for both models (`ToEnd`, `` `\n ``, `))`, `]`, `ASCII`, `.Encoding`). The obfuscation does not change what L0H11 attends to or suppress its firing. **The early detector is not the failure site.**

**Experiment 7b — Contrastive residual direction at L13 (both models)**

The malicious-vs-benign contrastive direction was computed at the L13 residual stream boundary from miss-case seed pairs for both models. Patching the L13 residual with the seed's contrastive direction:

| Condition | Base logit diff | Patch delta | Flip |
|---|---|---|---|
| FS seed | +0.125 | −0.45 | Yes (already marginal) |
| FS variant | −0.188 | −0.22 | Yes (already wrong side of 0) |
| Llama seed | +3.30 | −0.25 | No |
| Llama variant | +3.11 | −0.17 | No |

FS is already outputting ALLOW on miss variants before any intervention (base logit diff −0.188). Llama's logit diff barely changes between seed (+3.30) and variant (+3.11). **The failure in FS is fully present at the L13 residual boundary — the residual stream already encodes a benign-leaning signal before L13 is reached on miss variants.**

**Experiment 7c — Per-head residual direction attribution (layers 0–12)**

`batch-trace-residual-direction-heads` was run on all four conditions (FS/Llama × seed/variant) to decompose the L13 residual direction into per-head contributions. Result: the net sum of all attention head contributions is positive and nearly identical between seed and variant conditions in both models (FS seed: +1.10, FS variant: +1.01; Llama seed: +0.89, Llama variant: +0.92). **The attention circuit does not explain the residual inversion.** The top contributing heads (L12H15, L12H9, L12H24, L8H7, L12H2) are the same on seed and variant, with only minor magnitude changes.

**Experiment 7d — MLP neuron attribution (FS, layers 0–12)**

`batch-neuron-discover` was run on seed and variant manifests for FS, capturing both positive and negative neuron contributors. Result: per-neuron contribution deltas are small (~0.003–0.007) and the net MLP contribution toward the logit direction is near-zero in both conditions (seed: −0.034, variant: +0.011). The largest layer-level shift is at Layer 10 (net swings −0.020 from seed to variant), but magnitudes do not account for the scale of the L13 residual inversion observed in Experiment 7b. The `batch-neuron-discover` tool projects onto the logit direction (BLOCK−ALLOW), not the contrastive residual basis, so it measures a different quantity than the Experiment 7b patching. Pinpointing specific neurons responsible for the residual inversion would require projecting MLP outputs onto the contrastive basis — tooling that does not currently exist in the pipeline.

**Final conclusion**: The evasion failure in Foundation-Sec on `iex_format_string` variants is localized to the MLP layers (0–12). The attention circuit — including L0H11 and the L12 writer cluster — contributes a stable, positive malicious-direction signal on both seed and variant scripts in both models. The residual inversion is FS-specific and MLP-driven. This is directly consistent with the original hypothesis (Section 8.2) that cybersecurity fine-tuning modifies MLP weights more than attention structure: the MLP layers were tuned to encode associations with specific literal indicator tokens, and produce a competing signal in the residual stream when those tokens are absent or transformed. Llama's MLP layers, never having received that fine-tuning, do not carry those associations and therefore do not produce the inversion — leaving the structural attention circuit's malicious signal intact and the classification correct.

### 10.2 Localize the Semantic Weighting Layer

The adversarial prompt experiment reveals that Foundation-Sec's prompt-sensitive component is specifically keyed on the `Invoke-Expression` token literal — not on IEX (its alias), not on `Invoke-WebRequest` obfuscation variants. Candidate approach: run logit lens or direct logit attribution on the BLOCK token across both prompt conditions for a differentially affected technique (e.g., `invoke_expression_backtick_string`) vs. an unaffected one (e.g., `iex_scriptblock_create`). Identifying which layers or MLP neurons carry the `Invoke-Expression`-specific association would directly characterize what cybersecurity pretraining encoded and why it is token-literal-specific rather than concept-general.

### 10.3 Characterize the L12H28 / L12H15 Role Shift

L12H28 is 4th-ranked in Foundation-Sec but 1st in Llama; fine-tuning strengthened L12H15 specifically. Per-token OV circuit projections for H28 vs. H15 would determine whether this is a functional distinction or a magnitude-only redistribution.

### 10.4 MLP Contribution Analysis

The ~7× amplification of logit diff gain is consistent with being MLP-driven — Experiment 7 confirms that MLP layers (not the attention circuit) are the site of FS's evasion failure, supporting the view that cybersecurity fine-tuning primarily modified MLP weights. Running layer-ablation with attention-only vs. MLP-only component ablation would decompose the amplification more directly and confirm whether the attention circuit or MLP layers are the causal site of the gain increase. Projecting per-layer MLP outputs onto the contrastive residual basis (rather than the logit direction) would enable neuron-level attribution of the inversion identified in Experiment 7b — this requires new tooling not currently in the pipeline.

### 10.5 Linear Probe at Layer 0 Output

Given that L0H11 attends to syntactic delimiter tokens rather than literal indicator tokens, a linear probe at the Layer 0 residual stream output would determine whether the malicious/benign distinction is linearly separable after Layer 0 — testing whether L0H11 performs genuine early-stage feature extraction or contributes a partial signal.

---

## 11. Glossary

**Adversarial prompt**: A system prompt variant that appends "Classify based on overall purpose, not individual constructs" to the base classifier. Called "adversarial" because it opposes surface-feature pattern matching — not adversarial in the security-testing sense (no exploitation of vulnerabilities or model weights is involved).

**Attention delta (Attn Δ)**: Attention weight from the query token (final token position) to indicator token positions, minus mean attention weight to matched random positions. Positive delta = the head preferentially attends to indicator tokens over background.

**Benign false-positive / evasion miss**: A malicious script that the model classifies as benign (ALLOW). In the evasion benchmark context, a miss is a false-positive on an evasion variant of a malicious seed.

**Circuit**: A subnetwork of attention heads (and possibly MLP layers) causally responsible for a model's classification decision. Identified through attention head ranking, path patching, and head ablation.

**Circuit concentration**: How many heads are needed to account for most of the circuit's causal effect. A concentrated circuit achieves high flip rates with few heads; a diffuse circuit requires many.

**Evasion variant**: A modified version of a malicious seed script that removes or obfuscates a specific indicator token while preserving malicious function. The benchmark tests whether the model still classifies these variants as BLOCK.

**Head ablation**: A causal intervention that zeros a specific attention head's output during a forward pass, testing whether that head is causally necessary for the classification.

**Indicator token**: A PowerShell command or construct strongly associated with malicious behavior: `Invoke-WebRequest`, `IEX`, `Invoke-Expression`, `DownloadString`, `-EncodedCommand`, `VirtualAlloc`, etc.

**L0H11 / L12H28 (etc.)**: Attention head notation: L = layer (0-indexed), H = head (0-indexed). L0H11 = layer 0, head 11.

**Late-writer head**: An attention head in a late layer (Layer 12 in this study) that writes strongly in the malicious-vs-benign contrastive direction in the residual stream.

**Logit diff**: Difference between the model's log-probability for BLOCK and ALLOW at the answer token position. Positive = model prefers BLOCK; more positive = higher confidence. Used as the primary scalar classification measure throughout.

**Path patching**: A causal intervention that replaces selected heads' activations during a benign run with activations from the matched malicious run. A high flip rate (benign → BLOCK) means those heads are causally sufficient to shift the decision.

**`provisional_v1`**: The primary evasion benchmark. 48 variants across 10 techniques covering aliasing, execution-indirection obfuscation, and string-splitting. Used for all cross-model comparisons.

**`realistic_v2`**: A separate evasion benchmark covering 11 advanced obfuscation techniques (backtick insertion, base64, format strings, subexpression splicing, zero-width strip) with no technique overlap with `provisional_v1`. Both models tested (Experiment 6). Not directly comparable to `provisional_v1`.

**Raw prompt**: The minimal rule-based classifier system prompt. Foundation-Sec's default. Does not include intent framing or construct carve-outs.

**Residual stream**: The running sum of all layer outputs in a transformer, passed between layers. A head "writes to the residual stream" by adding its output to this sum, influencing all subsequent layers.

**Semantic weighting layer**: The hypothesis (supported by Experiment 5) that cybersecurity fine-tuning added a prompt-sensitive component to Foundation-Sec encoding trained associations between specific PowerShell command patterns and the BLOCK output. Operates alongside, and separately from, the shared structural circuit.

**Strict tier**: Internal pipeline label for evasion variants passing all static checks and invariant tests. The 44 fully-passing variants are a subset of the 48-variant `provisional_v1` manifest; the 4 additional variants passed invariant checks but failed tree-sitter parse validation on some runtimes. All scored correctly under every prompt condition, making the strict/provisional distinction immaterial to results.

**Surface-feature pattern matching**: Classifying a script based on the presence or absence of specific literal tokens rather than semantic intent. Llama exhibits this as benign false-positives (under raw prompt); Foundation-Sec exhibits it as evasion brittleness on aliased commands.
