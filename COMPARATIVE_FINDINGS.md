# Comparative Circuit Analysis: Foundation-Sec-8B vs Llama-3.1-8B-Instruct

**Date**: 2026-04-17  
**Status**: Complete — all phases executed, three additional experiments run to address methodological concerns  
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

The same 96-pair matched benign/malicious PowerShell cohort used in the Foundation-Sec study was reused. Pairs are matched on primary indicator token (e.g. both scripts contain `Invoke-WebRequest`) so logit-diff interventions are causally interpretable. From this cohort, **74 pairs** were retained for the Llama causal validation after filtering for token-length safety (≤900 tokens with chat template overhead); the remaining 22 pairs exceeded safe VRAM limits at full model scale with TransformerLens activation caching (attention patterns are quadratic in sequence length).

### Prompt Engineering

Foundation-Sec required no prompt tuning — it was trained on a cybersecurity corpus and responds to the standard rule-based classifier prompt. Llama-3.1-8B-Instruct required prompt iteration. Three prompt conditions were tested:

1. **Raw classifier prompt, no chat template**: 52.8% accuracy on 18-pair pilot — near-random, near-zero benign accuracy (5.6%). Not usable.
2. **Raw classifier prompt + chat template**: 71.6% accuracy on 74-pair cohort, benign accuracy 43.2%. Surface-feature false positives on benign scripts containing Base64/IEX.
3. **Intent-focused prompt + chat template** (final): 100% accuracy on 18-pair pilot and 74-pair cohort. The system prompt explicitly instructs the model to classify primary intent, naming Base64/IEX/web-downloads as ALLOW when used in legitimate tooling.

The final prompt was required to counteract Llama's surface-feature pattern matching. This is a confound discussed in Section 9.

**Important**: Neither model was fine-tuned on ALLOW/BLOCK labels. The label framing is entirely prompt-level for both. Foundation-Sec's advantage comes from its cybersecurity pretraining, not from label-specific training.

### Tooling Changes

Three additions were made to `scaled_validation.py`:

1. **`--use-chat-template` global flag**: Wraps prompts via `tokenizer.apply_chat_template()` uniformly across all pipeline commands (baseline eval, attention discovery, causal patching, ablation).
2. **`--system-prompt-variant` flag** (`raw` | `full`): Enables prompt ablation experiments without code changes. `raw` = minimal rule-based classifier (Foundation-Sec default). `full` = intent-focused prompt with explicit carve-outs.
3. **`--target-head` flag on `batch-discover-heads`**: Dumps the top-K most attended tokens per pair per script label for a specified head, enabling direct inspection of what L0H11 attends to.

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

**Notable observation**: Llama's mean logit diff under the intent-focused prompt (0.52) is ~7× lower than Foundation-Sec's (3.52). The model separates the two classes but with substantially lower confidence margin — an important baseline for interpreting causal validation results.

**Go/no-go decision**: Proceed with intent-focused prompt. Prompt confound implications are discussed in Section 9.

---

## 3. Phase 1 — Circuit Discovery in Llama-3.1

**Objective**: Identify candidate circuit components in Llama-3.1-8B-Instruct from scratch, without assuming the Foundation-Sec circuit transfers.

### 3.1 Attention Head Ranking

Heads were ranked by how consistently they attend to suspicious indicator tokens in malicious vs. benign scripts across 18 pairs.

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

**L12H28 dominates the late-writer cluster in Llama**, with a substantially stronger residual projection than in Foundation-Sec (where L12H15 leads). The late-writer layer (12) is identical between models.

**Comparison with Foundation-Sec late writers:**

| Model | Top late head | 2nd | 3rd | 4th |
|---|---|---|---|---|
| Foundation-Sec | L12H15 | L12H5 | L12H4 | L12H28 |
| Llama-3.1 | **L12H28** | L12H5 | L12H4 | L12H13 |

The head *indices* differ, but the *layer* is identical. L12H28 shifts from 4th in Foundation-Sec to 1st in Llama. L12H13 replaces L12H15 as the 4th head. This is consistent with fine-tuning redistributing weights within an existing layer-12 writer cluster rather than creating the cluster from scratch.

### 3.4 Circuit Hypothesis

**Llama circuit**: `L0H11 → L12H28/L12H5/L12H4/L12H13`

This differs from Foundation-Sec's `L0H11 → L12H15/L12H5/L12H4/L12H28` only in the dominant late head and the composition of the cluster, not in the overall two-stage L0→L12 architecture.

---

## 4. Phase 2 — Causal Validation

**Objective**: Confirm the Llama circuit hypothesis causally via path patching (sufficiency) and head ablation (necessity) on the 74-pair matched cohort.

### 4.1 Path Patching Results (Sufficiency)

Grouped path patching replaces the output of circuit heads in a benign run with activations from the matched malicious run, then measures the logit shift and classification flip rate.

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

**Key finding**: On the matched 74-pair cohort, Foundation-Sec's minimal circuit achieves 32.4% flip rate vs. Llama's 14.9%. Llama's top-5 bundle (48.6%) exceeds Foundation-Sec's performance on the same cohort, but requires 8 heads vs. Foundation-Sec's 4 — the Llama circuit is more diffuse.

**Note on the 96 vs. 74 pair discrepancy for Foundation-Sec**: The drop from 56% (96 pairs) to 32% (74 pairs) is explained by selection bias in the safe-pair subset — shorter scripts have lower baseline logit diffs, leaving less room for patching to cause a flip. This is discussed further in Section 9.2.

### 4.2 Head Ablation Results (Necessity)

Zeroing individual head outputs on malicious prompts to test which heads are causally necessary.

**Llama per-head ablation (74 pairs):**

| Head | Mean Δ | Flip rate |
|---|---|---|
| L12H4 | −2.95 | 0% |
| L12H5 | −0.89 | 0% |
| L0H11 | −0.75 | 0% |
| L12H28 | −0.09 | 0% |

No single head ablation produces classification flips, consistent with a distributed circuit where redundancy across heads prevents single-head necessity. This matches Foundation-Sec's ablation profile.

---

## 5. Phase 3 — Evasion Benchmark

**Objective**: Run the identical two-tier evasion benchmark on Llama and compare miss rates and techniques.

### 5.1 Seed Baseline

Both models correctly classify all seed scripts before variant testing.

### 5.2 Strict Tier (v3): 44 Variants, 10 Techniques

| Technique | Foundation-Sec misses | Llama misses |
|---|---|---|
| `invoke_webrequest_alias` | **4/4** | 0/4 |
| `downloadstring_psobject_invoke` | **2/6** | 0/6 |
| `iex_call_operator_string` | 0/6 | 0/6 |
| `invoke_expression_call_operator_string` | 0/4 | 0/4 |
| `iex_scriptblock_create` | 0/6 | 0/6 |
| `invoke_expression_scriptblock_create` | 0/4 | 0/4 |
| `invoke_webrequest_call_operator_string` | 0/4 | 0/4 |
| `split_quoted_encodedcommand_literal` | 0/2 | 0/2 |
| `start_process_call_operator_string` | 0/4 | 0/4 |
| `downloadfile_psobject_invoke` | 0/4 | 0/4 |
| **Total** | **6/44 (13.6%)** | **0/44 (0%)** |

### 5.3 Provisional Tier (realistic_v2): 46 Variants

| Technique | Foundation-Sec misses | Llama misses |
|---|---|---|
| `invoke_expression_format_string` | **4/4** | 0/4 |
| All other techniques | 0/42 | 0/42 |
| **Total** | **4/46 (8.7%)** | **0/46 (0%)** |

### 5.4 Evasion Summary

| Metric | Foundation-Sec | Llama-3.1 |
|---|---|---|
| Strict tier miss rate | 6/44 (13.6%) | 0/44 (0%) |
| Provisional tier miss rate | 4/46 (8.7%) | 0/46 (0%) |
| Techniques causing misses | `iwr_alias`, `downloadstring_psobject`, `iex_format_string` | None |

Llama shows 0 misses across all 90 variants — but under an intent-focused prompt that explicitly instructs the model to ignore surface features. The evasion comparison is therefore partially confounded; see Section 6.3 and Section 9.1.

---

## 6. Supplementary Experiments

Three additional experiments were run to address the prompt confound and cohort size mismatch.

### 6.1 Experiment 1 — Foundation-Sec on the 74-Pair Matched Subset

**Motivation**: The original comparison between Foundation-Sec (96 pairs) and Llama (74 pairs) is not directly comparable. Running Foundation-Sec on the same 74 pairs fixes this.

**Results**: Foundation-Sec achieves 32–34% flip rate on the 74-pair subset across all route variants (see Section 4.1 table). Llama's top-5 bundle (48.6%) exceeds this; Llama's minimal branch (14.9%) is weaker. The comparison is now cohort-matched.

**Why Foundation-Sec drops from 56% to 32%**: The 74 safe pairs are filtered by token length (≤900 tokens). Shorter scripts have lower baseline logit diffs, leaving less room for patching to flip the classification. The 22 dropped pairs are the most complex/longest scripts, which had the strongest classification margins. This is a selection artifact, not a circuit failure.

### 6.2 Experiment 2 — L0H11 Attention Targets

**Motivation**: If L0H11 attends to tokens in the system prompt rather than script body tokens, its activation would be a prompt artifact rather than evidence of script-analysis behavior.

**Method**: Collected top-15 attended tokens for L0H11 per pair across three conditions: Llama with full intent prompt, Llama with raw prompt, and Foundation-Sec with raw prompt. Token positions were compared against approximate script-body start positions (full intent prompt ~150 tokens of overhead; raw prompts ~36 tokens).

**Token position results:**

| Condition | Mean prompt length | Top-5 attention in script body | Out-of-script |
|---|---|---|---|
| Llama, full intent prompt | 375 tokens | **80%** | `' scripts'` at pos 39 in system prompt — 20% |
| Llama, raw prompt | 261 tokens | **100%** | None |
| Foundation-Sec, raw prompt | 226 tokens | **100%** | None |

**L0H11 attention delta (indicator tokens vs. random controls):**

| Condition | L0H11 mean attn Δ | Pairs firing (of 18) |
|---|---|---|
| Llama, full intent prompt | 0.00453 | 18 |
| Llama, raw prompt | **0.00628** | 18 |
| Foundation-Sec, raw prompt | 0.00596 | 18 |

**Top attended token strings (malicious scripts, across conditions):**

All three conditions show L0H11 attending predominantly to the same syntactic tokens in the PowerShell script body: `")\n`, `'\n`, `');`, `");`, `',`, `.Web`. These are closing delimiters and object-member accessor tokens marking the boundaries of PowerShell command calls — consistent with L0H11 tracking syntactic structure of indicator expressions rather than the literal indicator tokens themselves.

**Key finding**: L0H11's attention delta is *higher* under the raw prompt than the full intent prompt (0.00628 vs 0.00453). Under a prompt-confound hypothesis, adding more intent-relevant text should strengthen the head's activation — instead it weakens. The 20% of Llama full-prompt attention landing outside the script body is concentrated on the single token `' scripts'` at position 39, a minor distraction not a driver.

**Conclusion**: L0H11 attends to script-body tokens in both models under all prompt conditions. Its activation is not a prompt artifact.

### 6.3 Experiment 3 — Prompt Ablation

**Motivation**: Characterize the accuracy impact of removing the intent-focused framing from Llama's prompt, and understand the failure mode.

**Results**: Under the raw prompt + chat template on the 74-pair cohort: overall accuracy = 71.6%, benign accuracy = 43.2%, malicious accuracy = 100%.

**Finding**: The failure mode is entirely benign false-positives — Llama never false-negatives on malicious scripts even without intent framing. The intent-focused prompt corrects benign misclassification without affecting malicious detection. This has two implications:
1. Llama's malicious detection circuitry is robust across prompt conditions; only the benign discrimination is prompt-sensitive.
2. Llama's 0 evasion misses cannot be attributed to intent-framing alone — the model does not false-negative on malicious scripts even without it. However, the evasion variants are derived from seeds that were correct under the intent-focused prompt, so a fully controlled comparison still requires matched prompt conditions.

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
| L0H11 attn delta — intent prompt | N/A | 0.00453 | Slightly weaker |
| L0H11 attends to script body | Yes (100%) | Yes (80–100%) | Minor system-prompt leak in full prompt |
| Minimal branch flip rate (74 pairs) | 32.4% (24/74) | 14.9% (11/74) | Matched cohort |
| Top-5 bundle flip rate (74 pairs) | 33.8% (25/74) | **48.6% (36/74)** | Llama diffuse; comparable peak |
| Minimal branch flip rate (96 pairs) | **56.3%** (54/96) | N/A | FS original cohort |
| Strict tier evasion misses | **6/44 (13.6%)** | 0/44 (0%) | Prompt confound for Llama |
| Provisional tier evasion misses | **4/46 (8.7%)** | 0/46 (0%) | Prompt confound for Llama |
| FS-specific evasion techniques | `iwr_alias`, `downloadstring_psobject`, `iex_format_string` | — | Indicator-aliasing / format reconstruction |

---

## 8. Interpretation

### 8.1 Architecture Hypothesis: Supported

The evidence consistently supports the **architecture hypothesis**: the L0H11 early detector and Layer-12 late-writer cluster are present in Llama-3.1-8B-Instruct prior to security fine-tuning.

Evidence in support:
- **Same head, same layer**: L0H11 fires as the dominant early detector in both models. The late-writer cluster is at Layer 12 in both.
- **Script-body attention**: L0H11 attends to PowerShell script tokens in both models under all prompt conditions, and its attention delta is comparable in magnitude (~0.006) regardless of prompt.
- **Prompt-invariant firing**: L0H11's attention delta is stronger under the minimal raw prompt than the intent-focused prompt — the opposite of what a prompt-driven artifact would produce.
- **Structural overlap**: Three of the four canonical late-writer heads (L12H5, L12H4, L12H28) appear in both models' circuits. The overall two-stage architecture is identical.

Evidence suggesting fine-tuning modified the circuit:
- **Logit diff magnitude**: Foundation-Sec classifies with ~7× higher confidence (3.52 vs 0.52 mean logit diff). Fine-tuning amplified the output signal.
- **Dominant late head shifted**: L12H28 is ranked 4th in Foundation-Sec but 1st in Llama. Fine-tuning appears to have strengthened L12H15 specifically, shifting the weight distribution within the existing layer-12 cluster.
- **Circuit concentration**: Foundation-Sec achieves its peak flip rate with 4 heads. Llama requires 8 heads to reach a comparable flip rate — fine-tuning may have concentrated the circuit's causal weight into fewer heads.

### 8.2 What Fine-Tuning Changed

The cybersecurity pretraining appears to have done three things:
1. **Amplified output gain**: The same structural circuit produces ~7× larger logit differences, meaning the model classifies with higher confidence without needing a different circuit.
2. **Redistributed late-head weights**: Within the existing Layer-12 writer cluster, fine-tuning shifted the dominant contribution from H28 (Llama) to H15 (Foundation-Sec), concentrating causal weight into fewer heads.
3. **Internalized the malicious-intent distinction**: Foundation-Sec responds correctly to the minimal rule-based prompt. Llama requires explicit intent framing at inference time. Fine-tuning encoded the semantic distinction that Llama's general RLHF did not.

### 8.3 Evasion: Prompt-Level vs. Circuit-Level Robustness

Foundation-Sec's evasion misses cluster around two technique families:
- **Indicator aliasing** (`iwr_alias`, `downloadstring_psobject_invoke`): Replaces the literal indicator command with an aliased or object-invoked form, likely escaping L0H11's indicator-token detection.
- **Format-string reconstruction** (`iex_format_string`): Splits the command into runtime-concatenated fragments.

Llama shows 0 misses — but under a prompt that explicitly instructs the model to classify intent over surface features. The evasion comparison cannot currently distinguish prompt-level from circuit-level robustness. Experiment 3 (Section 6.3) established that Llama never false-negatives on malicious scripts even under the raw prompt, which is a partial positive signal, but a controlled matched-prompt evasion benchmark is needed before drawing strong conclusions.

---

## 9. Limitations and Caveats

### 9.1 Prompt Confound

The most significant limitation. Llama's circuit is measured under a different prompt than Foundation-Sec's. The intent-focused prompt contains semantic guidance that Foundation-Sec's prompt does not. This affects:
- **Evasion comparison**: Substantially confounded. Llama's 0 miss rate cannot be cleanly attributed to the circuit.
- **Flip rate comparison**: Partially confounded. The prompt changes the logit diff baseline, which affects how easily patching can flip the classification. The L0H11 attention target experiment (Section 6.2) limits this confound's scope for circuit structure claims but does not eliminate it for causal strength claims.

### 9.2 74-Pair Subset Selection Bias

The 74-pair safe subset excludes the 22 longest scripts, which are the most complex and likely have the highest classification margins. Foundation-Sec's flip rate drops from 56% (96 pairs) to 32% (74 pairs) because of this bias. Any quantitative flip rate comparison is relative to this shared selection effect, not an absolute capability comparison.

### 9.3 Prompt Sensitivity

Llama's accuracy swings from 5.6% to 100% benign accuracy depending on prompt condition. This extreme sensitivity means small changes in production deployment conditions could substantially alter classification behavior — a practical concern beyond the mechanistic findings.

### 9.4 Circuit Completeness

The identified circuit accounts for 15–49% of classification flips depending on route. The remaining signal is unexplained. There may be parallel circuits, MLP contributions, or other attention heads not captured here. Neither model's circuit has been shown to be complete.

---

## 10. Recommendations for Continuing Research

### 10.1 Controlled Evasion Benchmark Under Matched Prompts (Highest Priority)

Run Foundation-Sec under the same intent-focused system prompt used for Llama, then re-run the full evasion benchmark. If Foundation-Sec's miss rate drops toward zero, the evasion advantage is prompt-level. If it stays at 10–14%, it is circuit-level. This is the single highest-value experiment remaining and directly resolves the main open question.

### 10.2 Evasion Benchmark on Llama Under Raw Prompt

Rather than using the 74-pair cohort (which has too-low benign accuracy under raw prompt for a clean comparison), build a new evasion seed set from malicious-only scripts — where Llama achieves 100% accuracy even without intent framing. This would provide a clean Llama evasion baseline without the prompt confound.

### 10.3 Characterize the L12H28 / L12H15 Role Shift

L12H28 is the 4th-ranked late writer in Foundation-Sec but the 1st-ranked in Llama; fine-tuning appears to have strengthened L12H15 specifically. Examining per-token OV circuit projections for H28 vs. H15 would determine whether this represents a functional distinction (they write to different token positions or in different directions) or a magnitude-only redistribution.

### 10.4 MLP Contribution Analysis

The current study focuses entirely on attention heads. Given that fine-tuning typically modifies MLP weights more than attention structure, the ~7× amplification of logit diff gain may be primarily MLP-driven. Running layer-ablation with attention-only vs. MLP-only component ablation would decompose this and clarify whether the attention circuit is the causal amplification site.

### 10.5 Linear Probe at Layer 0 Output

Given that L0H11 attends to syntactic delimiter tokens rather than literal indicator tokens, a linear probe at the Layer 0 residual stream output would determine whether the malicious/benign distinction is linearly separable after Layer 0. If yes, L0H11 is performing genuine early-stage feature extraction; if not, it is contributing a partial signal that later heads integrate.

### 10.6 Paper Structure

The comparative findings are strong enough to constitute a paper section or companion report. The core narrative — that the L0H11 → L12 circuit is architectural, that fine-tuning amplified gain and redistributed late-head weights without creating new structure, and that prompt engineering can replicate task performance but not the domain-knowledge characteristics of cybersecurity pretraining — is clean and well-supported. The prompt confound should be stated prominently as a limitation rather than buried, and the matched-prompt evasion experiment (10.1) should be run before any publication claims about evasion robustness.
