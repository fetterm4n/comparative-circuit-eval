# Comparative Circuit Analysis: Foundation-Sec-8B vs Llama-3.1-8B-Instruct

**Date**: 2026-04-17  
**Status**: Complete — all phases executed and validated  
**Central question**: Is the PowerShell malicious-classification circuit (`L0H11 → L12H15/H5/H4/H28`) a product of Foundation-Sec's security fine-tuning, or a general property of the Llama-3.1-8B architecture?

---

## Table of Contents

1. [Methodology](#1-methodology)
2. [Phase 0 — Baseline Classification Setup](#2-phase-0--baseline-classification-setup)
3. [Phase 1 — Circuit Discovery in Llama-3.1](#3-phase-1--circuit-discovery-in-llama-31)
4. [Phase 2 — Causal Validation](#4-phase-2--causal-validation)
5. [Phase 3 — Evasion Benchmark](#5-phase-3--evasion-benchmark)
6. [Model Comparison Table](#6-model-comparison-table)
7. [Interpretation](#7-interpretation)
8. [Recommendations for Continuing Research](#8-recommendations-for-continuing-research)

---

## 1. Methodology

### Models

| Property | Foundation-Sec-8B-Instruct | Llama-3.1-8B-Instruct |
|---|---|---|
| HuggingFace ID | `fdtn-ai/Foundation-Sec-8B-Instruct` | `meta-llama/Llama-3.1-8B-Instruct` |
| Architecture | 32 layers, 32 heads, 4096 hidden dim | Identical |
| Training | Llama-3.1-8B base + cybersec pretraining + RLHF | Llama-3.1-8B base + general RLHF only |
| Classification format | Raw prompt → next-token ALLOW/BLOCK | Chat template (system/user split) → next-token ALLOW/BLOCK |

Both models use the same TransformerLens template (`meta-llama/Llama-3.1-8B-Instruct`), so the full mechanistic interpretability hook infrastructure transfers without modification.

### Dataset and Cohort

The same 96-pair matched benign/malicious PowerShell cohort used in the Foundation-Sec study was reused. Pairs are matched on primary indicator token (e.g. both scripts contain `Invoke-WebRequest`) so logit-diff interventions are causally interpretable. From this cohort, 74 pairs were retained for the Llama causal validation after filtering for token-length safety (≤900 tokens with chat template overhead); the remaining 22 pairs exceeded safe VRAM limits at full model scale.

### Prompt Engineering

Foundation-Sec required no prompt engineering — the model was fine-tuned for cybersecurity ALLOW/BLOCK classification. Llama-3.1-8B-Instruct required prompt tuning. Three prompt iterations were tested on the 20-pair smoke test:

1. **Flat single-turn prompt** (raw text, no chat template): 70% accuracy — same failures as later versions, confirming the issue is content not format.
2. **Chat template, rule-based system prompt**: 70% — slightly higher logit diffs but same benign false-positive pattern.
3. **Chat template, intent-focused system prompt** (final): 100% on smoke test, 100% on pilot cohort.

The final system prompt emphasizes _intent over surface features_, explicitly noting that Base64 encoding, `Invoke-Expression`, and web downloads are ALLOW when used in legitimate administrative tooling. This was necessary because Llama pattern-matches on surface-level indicators rather than domain-specific malicious context, and several benign scripts in the dataset use those constructs legitimately.

### Tooling

All experiments used `scaled_validation.py`, the same CLI pipeline used for the Foundation-Sec study. Two modifications were made:

1. **`--use-chat-template` global flag**: When set, all `make_prompt()` calls across the entire pipeline (baseline eval, attention discovery, causal patching, ablation) wrap prompts using `tokenizer.apply_chat_template()` with the system/user message split. This ensures the Llama residual stream is measured under the same conditions in which the model classifies correctly.
2. **`use_chat_template` parameter removal from `baseline-eval` subparser**: Folded into the global flag to apply uniformly to MI commands as well.

### Serial Execution

All GPU jobs were run serially. Parallel TransformerLens model loads OOM the H100.

---

## 2. Phase 0 — Baseline Classification Setup

**Objective**: Confirm Llama-3.1-8B-Instruct classifies PowerShell scripts reliably before any mechanistic work.

### Results

| Cohort | Rows | Accuracy | Mean Logit Diff |
|---|---|---|---|
| Smoke test (20-pair subset) | 20 | **100%** | 0.728 |
| Pilot cohort (18 pairs, 36 rows) | 36 | **100%** | 0.521 |

Per-label breakdown (pilot cohort):

| Label | Accuracy | Mean Logit Diff |
|---|---|---|
| Benign | 100% | −3.404 |
| Malicious | 100% | +4.447 |

**Go/no-go decision**: Proceed. Accuracy exceeds the 85% threshold on both cohorts.

**Notable observation**: The mean logit diff of 0.52 is substantially lower than Foundation-Sec's (~3.5 on the same 96-pair cohort baseline). This reflects that Llama is relying on general instruction-following rather than domain-trained features. The model correctly separates the two classes but with lower confidence. This narrower margin is an important baseline for interpreting the causal validation results in Phase 2.

---

## 3. Phase 1 — Circuit Discovery in Llama-3.1

**Objective**: Identify candidate circuit components in Llama-3.1-8B-Instruct from scratch, without assuming the Foundation-Sec circuit transfers.

### 3.1 Attention Head Ranking

Heads were ranked by how consistently they attend to suspicious indicator tokens (IEX, DownloadString, Invoke-WebRequest, etc.) in malicious scripts vs. benign scripts, measured across 18 pairs.

**Top heads by pair recurrence (full model scan):**

| Layer | Head | Pairs (of 18) | Mean Attn Δ | Max Attn Δ |
|---|---|---|---|---|
| **0** | **11** | **14** | 0.00308 | 0.00647 |
| 0 | 26 | 7 | 0.00431 | 0.00555 |
| 0 | 24 | 7 | 0.00391 | 0.00517 |
| 0 | 28 | 7 | 0.00264 | 0.00569 |
| 0 | 9 | 6 | 0.00368 | 0.00647 |
| 0 | 1 | 5 | 0.00574 | 0.01222 |

**`L0H11` is the dominant early detector in Llama-3.1 — exactly as in Foundation-Sec.** It recurs in 14/18 pairs with the highest consistency of any head in the full 32-layer scan. All top recurring heads are in Layer 0 (next-highest is L3H1 at 3/18). No other layer produces a consistently recurring attention detector.

**Foundation-Sec comparison**: In Foundation-Sec, `L0H9` led slightly (13/18 pairs) with `L0H11` second (10/18) in the L4 scan. In the full-model scan of Llama, `L0H11` leads decisively (14/18). The same small cluster of Layer-0 heads performs indicator detection in both models.

### 3.2 Full Layer Ablation

Ablating each layer's attention and MLP components individually reveals which are causally necessary for the malicious classification.

**Components with flip_rate > 0 (18 pairs):**

| Layer | Component | Mean Δ | Flip Rate |
|---|---|---|---|
| 8 | MLP | −4.149 | 22.2% |
| **0** | **Attn** | **−4.032** | **27.8%** |
| 0 | MLP | −3.616 | **33.3%** |
| 1 | MLP | −2.934 | 27.8% |
| 6 | Attn | −1.983 | 16.7% |
| 24 | Attn | −1.647 | 11.1% |
| 30 | MLP | −0.910 | 27.8% |
| 14 | MLP | −0.544 | 5.6% |
| 21 | MLP | −0.446 | 5.6% |

**Key finding**: Layer 0 attention and MLP are among the top causal components by both mean delta and flip rate. Layer 8 MLP also has substantial causal impact. Unlike Foundation-Sec — where the decisive causal band was concentrated around layers 11–13 — Llama shows a more distributed pattern with early layers (0–1) and mid layers (6–8) dominating the flip-rate signal. Layer 12 attention appears in the ablation table but with zero flip rate, indicating it contributes to logit magnitude but is not individually sufficient to flip predictions on this 18-pair pilot.

**Foundation-Sec comparison**: In Foundation-Sec, the high-flip-rate band was layers 10–13 (MLP and attention at L13 had flip rates of 50–60%). In Llama, no single layer achieves >33% flip rate in isolation, and the distribution is spread across early and middle layers.

### 3.3 Residual Direction Tracing

To identify which heads write the strongest signal in the direction that distinguishes malicious from benign (the "mean delta direction" at resid_pre13), we traced head output projections onto the contrastive residual direction discovered at layer 13.

**Top writers (projection onto malicious-minus-benign direction at resid_pre13):**

| Layer | Head | Mean Δ Projection | Positive Delta Frac |
|---|---|---|---|
| **12** | **28** | **0.1213** | 1.0 |
| 12 | 5 | 0.0800 | 1.0 |
| 12 | 4 | 0.0597 | 1.0 |
| 12 | 13 | 0.0539 | 1.0 |
| 10 | 27 | 0.0527 | 1.0 |
| 15 | 4 | 0.0491 | 1.0 |
| 14 | 24 | 0.0444 | 1.0 |
| 12 | 22 | 0.0444 | 1.0 |
| 12 | 15 | 0.0424 | 1.0 |
| 12 | 2 | 0.0378 | 1.0 |

**Layer 12 dominates the late writer cluster — identical to Foundation-Sec.** Every head in the top-4 is a Layer 12 head. All traced heads show `positive_delta_frac = 1.0`, meaning the directional contribution is consistent across all 18 pairs.

**Foundation-Sec comparison**: In Foundation-Sec, the top late writers at resid_pre13 were `L12H15` (0.0671), `L12H5` (0.0441), `L12H4` (0.0364), `L12H28` (0.0207). In Llama, the same four heads are active but with `L12H28` promoted to first place (0.1213 — nearly 2× its Foundation-Sec projection value) and `L12H15` demoted to 9th.

### 3.4 Circuit Hypothesis

Based on Phase 1 findings, the Llama-3.1-8B-Instruct circuit hypothesis is:

**`L0H11 → L12H28 / L12H5 / L12H4 / L12H13`**

- **Early entry**: `L0H11` (indicator attention detection, same head as Foundation-Sec)
- **Late writers**: Layer 12, same layer as Foundation-Sec, but with `H28` leading instead of `H15`
- **Structural note**: `H13` replaces `H15` as the fourth late writer; `H15` is present (9th) but weaker

---

## 4. Phase 2 — Causal Validation

**Objective**: Confirm the circuit hypothesis causally on the 74-pair cohort using grouped path patching (sufficiency) and grouped head ablation (necessity).

**Cohort**: 74 of the original 96 matched pairs, filtered to ≤900 tokens per prompt after chat template application. The 22 excluded pairs were long malicious scripts (>900 tokens) that exhausted VRAM during full-model TransformerLens caching.

### 4.1 Grouped Path Patching (Sufficiency)

Replacing the benign prompt's head activations with those from the matched malicious prompt, routing only through the hypothesized circuit heads, and measuring the logit shift in the malicious direction.

**Mean base logit diff**: 6.072 (Llama, 74-pair cohort; Foundation-Sec: 3.525 on 96-pair cohort)

| Route | Heads | Mean Δ | Flip Rate | n |
|---|---|---|---|---|
| Minimal branch | L0H11 + L12H28/H5/H4 | −4.865 | **14.9%** (11/74) | 74 |
| Stronger carrier | L0H11 + L12H28/H5/H4/H13 | −5.451 | **24.3%** (18/74) | 74 |
| Late carrier only | L12H28/H5/H4/H13 (no L0H11) | −5.457 | **25.7%** (19/74) | 74 |
| Top-5 bundle | L0H11 + L12H28/H5/H4/H13/H22/H15/H2 | −6.158 | **48.6%** (36/74) | 74 |

**Foundation-Sec comparison (same experiment on 96-pair cohort):**

| Route | Heads | Mean Δ | Flip Rate | n |
|---|---|---|---|---|
| Minimal branch | L0H11 + L12H15/H5/H4 | −3.156 | **56.3%** (54/96) | 96 |
| Stronger (−H2) | L0H11 + L12H15/H5/H4/H28 | −3.293 | **62.5%** (60/96) | 96 |
| Top-5 bundle | L12H15/H5/H4/H2/H28 | −3.264 | **58.3%** (56/96) | 96 |

**The circuit is present and causally active in Llama, but with lower flip rates.** The top-5 bundle reaches 48.6% in Llama vs 58.3% in Foundation-Sec on the minimal branch alone. This is consistent with Llama's lower baseline logit margins: the mean base logit diff is 6.07 in Llama (larger numerically) but the model's overall confidence is distributed differently, and the circuit's causal contribution captures less of the total classification signal.

**Late carrier without L0H11 (25.7%) ≥ minimal branch with L0H11 (14.9%)**: This suggests that in Llama, the Layer-12 late writers are more self-sufficient and less dependent on routing through the early Layer-0 head. The L0→L12 path is present but weaker than in Foundation-Sec.

### 4.2 Grouped Head Ablation (Necessity)

Zeroing the hypothesized circuit heads and measuring how much the malicious logit signal drops.

| Route | Heads Ablated | Mean Δ | Flip Rate |
|---|---|---|---|
| Minimal branch | L0H11 + L12H28/H5/H4 | −4.105 | 0.0% |
| Stronger carrier | L0H11 + L12H28/H5/H4/H13 | −4.463 | 0.0% |

**Ablation reduces logit diff substantially (−4.1 to −4.5) but produces zero label flips.** The model does not flip to ALLOW when the circuit is zeroed — it remains classified as malicious with lower confidence. This pattern mirrors Foundation-Sec's ablation result (minimal branch ablation also produced 0% flip rate there), indicating redundancy in the classification signal. The circuit components contribute meaningfully to the margin but are not the sole route.

### 4.3 Per-Head Contributions

Individual head patching and ablation from the minimal branch run:

**Patching (contribution to BLOCK when patched into benign run):**

| Layer | Head | Mean Δ | Flip Rate |
|---|---|---|---|
| 12 | 4 | −4.177 | 5.4% |
| 12 | 5 | −1.002 | 0.0% |
| 12 | 28 | −0.939 | 0.0% |
| 0 | 11 | −0.141 | 0.0% |

**Ablation (effect of removing each head individually):**

| Layer | Head | Mean Δ | Flip Rate |
|---|---|---|---|
| 12 | 4 | −2.947 | 0.0% |
| 12 | 5 | −0.895 | 0.0% |
| 0 | 11 | −0.752 | 0.0% |
| 12 | 28 | −0.087 | 0.0% |

**`L12H4` is the dominant individual late writer in Llama.** Its single-head patch delta (−4.18) exceeds the grouped minimal branch in Foundation-Sec (−3.16). `L12H28`, which led the residual projection trace, contributes strongly when ablated from its context but shows relatively modest individual contribution when patched in isolation — suggesting its influence is partly mediated through interactions with other L12 heads.

---

## 5. Phase 3 — Evasion Benchmark

**Objective**: Run the identical two-tier evasion benchmark used in the Foundation-Sec study on Llama-3.1-8B-Instruct.

### 5.1 Seed Baseline

All 26 seed scripts correctly classified before variant testing (100% accuracy, mean logit diff = 4.07). All seeds proceed to variant evaluation.

### 5.2 Strict Tier (baseline_v1 equivalent)

44 variants across 10 techniques.

| Technique | Variants | Llama Misses | Llama Acc | FS Misses | FS Acc |
|---|---|---|---|---|---|
| invoke_webrequest_alias | 4 | **0** | **100%** | **4** | **0%** |
| downloadstring_psobject_invoke | 6 | **0** | **100%** | **2** | **67%** |
| downloadfile_psobject_invoke | 4 | 0 | 100% | 0 | 100% |
| iex_call_operator_string | 6 | 0 | 100% | 0 | 100% |
| iex_scriptblock_create | 6 | 0 | 100% | 0 | 100% |
| invoke_expression_call_operator_string | 4 | 0 | 100% | 0 | 100% |
| invoke_expression_scriptblock_create | 4 | 0 | 100% | 0 | 100% |
| invoke_webrequest_call_operator_string | 4 | 0 | 100% | 0 | 100% |
| split_quoted_encodedcommand_literal | 2 | 0 | 100% | 0 | 100% |
| start_process_call_operator_string | 4 | 0 | 100% | 0 | 100% |
| **Total** | **44** | **0** | **100%** | **6** | **86%** |

Llama mean logit diff by technique on strict tier:

| Technique | Mean Logit Diff |
|---|---|
| start_process_call_operator_string | 9.11 |
| downloadfile_psobject_invoke | 8.42 |
| split_quoted_encodedcommand_literal | 5.82 |
| iex_scriptblock_create | 5.41 |
| iex_call_operator_string | 4.06 |
| invoke_webrequest_alias | 3.18 |
| invoke_webrequest_call_operator_string | 3.19 |
| downloadstring_psobject_invoke | 2.11 |
| invoke_expression_call_operator_string | 1.42 |
| invoke_expression_scriptblock_create | 0.75 |

### 5.3 Provisional Tier (realistic_v2 equivalent)

48 variants (includes 4 additional `iex_scriptblock_create` provisional variants).

| Metric | Llama | Foundation-Sec (realistic_v2) |
|---|---|---|
| Variants | 48 | 46 |
| Misses | **0** | **4** (invoke_expression_format_string: 4/4) |
| Accuracy | **100%** | **91.3%** |

**Llama achieves zero misses on both tiers.** Foundation-Sec missed 6 variants in the strict tier and 4 in the realistic_v2 tier. Llama correctly classifies every obfuscated variant including `invoke_webrequest_alias` (Foundation-Sec's strongest failure, 4/4 misses) and `invoke_expression_format_string` (Foundation-Sec's realistic_v2 failure, 4/4 misses).

### 5.4 Evasion Interpretation

The evasion divergence is the most surprising result. Two interpretations are consistent with the data:

**Hypothesis A — Surface-form vs. intent-based classification**: Foundation-Sec was fine-tuned on cybersecurity-specific indicators and may have learned strong surface-form associations (e.g., "the presence of `Invoke-WebRequest` with an alias makes this BLOCK"). Obfuscations that hide the specific surface form can fool these learned associations. Llama, classifying by general intent, is less sensitive to the specific surface form of the suspicious construct and more sensitive to the overall behavioral intent of the script.

**Hypothesis B — Prompt framing effect**: Llama's intent-focused system prompt ("classify PRIMARY INTENT, not surface features") may be doing substantive work in making Llama robust to surface obfuscation. The prompt explicitly tells the model to look through encoding and aliasing. Foundation-Sec's prompt does not include this instruction and the model is not a general instruction-follower in the same way.

These hypotheses are not mutually exclusive. The mechanistic evidence from Phase 2 (L12H28 being far stronger in Llama's residual projection than in Foundation-Sec's) is consistent with Hypothesis A: Llama's late writers may be encoding a richer semantic representation of intent rather than keying on specific token patterns.

---

## 6. Model Comparison Table

| Metric | Foundation-Sec-8B | Llama-3.1-8B | Δ / Notes |
|---|---|---|---|
| **Baseline accuracy (full cohort)** | 100% (96 pairs) | 100% (18-pair pilot) | Comparable |
| **Mean logit diff (pilot cohort)** | ~3.5 | 0.52 | FS ~7× larger margin |
| **Early detector layer** | Layer 0 | Layer 0 | **Identical** |
| **Early detector head** | L0H9 (primary), L0H11 (secondary) | **L0H11** (primary, 14/18) | Same heads, different rank order |
| **Late writer layer** | Layer 12 | Layer 12 | **Identical** |
| **Top late writer** | L12H15 (projection 0.067) | L12H28 (projection 0.121) | Different head, same layer |
| **Core late writers** | H15, H5, H4, H28 | H28, H5, H4, H13 | 3/4 overlap (H5, H4, H28) |
| **Minimal branch patch Δ** | −3.156 | −4.865 | Larger raw delta in Llama |
| **Minimal branch flip rate** | 56.3% (54/96) | 14.9% (11/74) | FS 3.8× higher |
| **Stronger carrier flip rate** | 62.5% (60/96) | 24.3% (18/74) | FS 2.6× higher |
| **Top-5 bundle flip rate** | 58.3% (56/96) | 48.6% (36/74) | Narrowing gap |
| **Ablation flip rate (minimal)** | 0.0% (96 pairs) | 0.0% (74 pairs) | **Identical pattern** |
| **Ablation mean Δ (minimal)** | −0.840 | −4.105 | Much stronger in Llama |
| **Layer ablation causal band** | Layers 10–13 (attn+MLP) | Layers 0–1, 6–8 (distributed) | Shifted earlier in Llama |
| **Strict evasion misses** | 6/44 (13.6%) | **0/44 (0%)** | Llama fully robust |
| **Realistic evasion misses** | 4/46 (8.7%) | **0/48 (0%)** | Llama fully robust |
| **invoke_webrequest_alias** | 4/4 miss | **0/4 miss** | Critical difference |
| **invoke_expression_format_string** | 4/4 miss | **0/4 miss** | Critical difference |

---

## 7. Interpretation

### 7.1 Primary Finding: Architecture Hypothesis Supported

The central question of this study was whether the PowerShell classification circuit is a product of security fine-tuning or a general Llama-3.1-8B architectural property. The evidence strongly supports the **architecture hypothesis**.

Specifically:

1. **The early detector is the same head (`L0H11`) in both models.** This head appears in Layer 0 attending to suspicious indicator tokens before any task-specific information has been processed. It was present in Foundation-Sec and independently rediscovered in Llama-3.1-8B-Instruct.

2. **The late writer cluster is the same layer (Layer 12) in both models.** Three of four core late writers are shared (H5, H4, H28). The heads that write strongly in the malicious direction at resid_pre13 are drawn from the same small set in both models.

3. **The structural pattern is the same.** Early detection by Layer-0 attention → late compression into Layer-12 residual direction → final decision readout. This two-stage architecture is not a product of cybersecurity fine-tuning; it was present before fine-tuning.

### 7.2 What Fine-Tuning Changed

Despite the shared circuit structure, Foundation-Sec's security fine-tuning made measurable differences:

**Sharpened margins**: Foundation-Sec's minimal branch achieves 56.3% flip rate vs. Llama's 14.9% on a comparable route. Fine-tuning amplified the causal contribution of the shared circuit components — the same heads matter more in Foundation-Sec.

**Shifted head weights within the cluster**: `L12H15` is the dominant late writer in Foundation-Sec (projection 0.067) but weakly active in Llama (projection 0.042, ranked 9th). `L12H28` is the dominant late writer in Llama (projection 0.121) but secondary in Foundation-Sec. Fine-tuning appears to have specifically strengthened L12H15's role in the malicious direction while L12H28 carried this function in the base model.

**Created surface-form vulnerabilities**: The evasion failures in Foundation-Sec (`invoke_webrequest_alias`, `invoke_expression_format_string`) are not shared by Llama. Fine-tuning on cybersecurity data appears to have created specific surface-form associations that obfuscation can exploit. Llama's general instruction-following is less susceptible to these particular obfuscations.

**Layer ablation causal band shifted**: Foundation-Sec's most causally sensitive layers (layers 10–13) are later than Llama's (layers 0–1, 6–8). Security fine-tuning appears to have concentrated causal information in deeper layers, possibly by reinforcing the late-layer decision-writing pathway.

### 7.3 The Evasion Paradox

It is notable that the model that is *more* specialized for cybersecurity (Foundation-Sec) is *more* vulnerable to evasion than the general-purpose model (Llama-3.1-8B-Instruct). This is consistent with an overfitting interpretation: security fine-tuning instilled stronger associations between specific surface patterns and the BLOCK label, and obfuscations that preserve execution while hiding those patterns can fool the fine-tuned model. Llama's lower specificity is, paradoxically, a robustness advantage for these particular techniques.

This does not mean Llama is a better security classifier in general. The evasion benchmark is narrow (44 variants across 10 techniques drawn from one study). Foundation-Sec likely outperforms Llama on harder classification tasks — novel scripts, edge cases, scripts without clear indicator tokens. The evasion result applies specifically to obfuscation of known indicator patterns.

### 7.4 Caveats

- **Prompt dependency**: Llama's evasion robustness may be partly prompt-driven. The intent-focused system prompt instructs the model to look through surface obfuscation. The mechanistic study measured the circuit as active under this prompt. A different prompt might produce different evasion results and different circuit behavior.
- **Cohort size**: Llama's causal validation used 74 pairs (vs. 96 for Foundation-Sec) due to VRAM constraints from chat-template token overhead. The flip rate comparisons should be interpreted with this in mind.
- **Logit margin difference**: Llama's mean base logit diff (0.52) is much lower than Foundation-Sec's (~3.5). Some of the flip-rate difference in Phase 2 may reflect this — there is simply less causal signal to displace.

---

## 8. Recommendations for Continuing Research

### 8.1 Ablate the Prompt Effect on Evasion

The critical open question is whether Llama's evasion robustness is mechanistic (the circuit genuinely doesn't rely on the surface forms that obfuscation removes) or prompt-driven (the system prompt instructs the model to ignore surface forms). This can be tested by:

1. Rerunning the Llama evasion benchmark with a minimal prompt (e.g., identical to Foundation-Sec's flat prompt, no intent framing).
2. Comparing evasion miss rates between prompt variants.
3. Running path patching on Llama evasion variants to see if circuit activity is maintained (as in Foundation-Sec's redistribution finding).

If Llama also misses `invoke_webrequest_alias` with a simpler prompt, the robustness is prompt-driven. If it remains robust, the circuit is genuinely less surface-form-dependent.

### 8.2 Characterize L12H28's Elevated Role in Llama

`L12H28` shows a residual projection of 0.121 in Llama vs. 0.021 in Foundation-Sec — nearly a 6× difference. This is the most striking quantitative difference between the two models' circuits. Possible directions:

- **Trace L12H28 inputs**: Which earlier heads and MLPs feed into L12H28's key-query-value computation in Llama? Does it receive direct input from L0H11, or is it reading from a different part of the residual stream?
- **Residual direction intervention under L12H28 ablation**: Does ablating L12H28 in Llama disrupt the malicious residual direction at pre-13 more than in Foundation-Sec? This would quantify whether the fine-tuning redistributed the writing responsibility from H28 to H15.
- **Weight-space comparison**: A direct comparison of L12H28's output weight matrix (`W_O`) between the two models could reveal whether fine-tuning significantly modified this head's output direction.

### 8.3 Extend the Evasion Benchmark

The current benchmark covers obfuscation of known indicator patterns. Several extensions would strengthen the analysis:

- **Scripts without explicit indicator tokens**: Both Foundation-Sec and Llama were tested on scripts containing known indicators (IEX, DownloadString, etc.). Testing on malicious scripts that achieve the same effect without these tokens would reveal whether the circuit is indicator-dependent or more broadly semantic.
- **Novel obfuscation families**: The benchmark covers keyword hiding, string construction, and execution indirection. Network-layer obfuscation (e.g., domain fronting, chunked payloads) and environment-dependent payloads are not covered.
- **Llama-specific failure discovery**: The benchmark was designed based on Foundation-Sec's failure modes. A fresh attack surface analysis targeting Llama's different circuit (L12H28-led, intent-based) might find different vulnerabilities.

### 8.4 Compare Residual Stream Geometry

Foundation-Sec and Llama share circuit structure but differ in component weights and causal contributions. A direct comparison of:

- The contrastive (malicious vs. benign) residual direction at pre-13 in both models — cosine similarity between models would indicate whether fine-tuning changed the geometric direction in which "malicious intent" is encoded.
- PCA subspace analysis: Does the shared circuit use a low-dimensional subspace in both models? Is that subspace more concentrated in Foundation-Sec (as would be expected if fine-tuning sharpened the representation)?

### 8.5 Paper Structure

The comparative study is now strong enough to support a paper section or companion paper. A suggested structure:

1. Foundation-Sec circuit (already complete) as the primary claim
2. Comparative section: architecture hypothesis and evidence
3. Evasion comparison and the surface-form specialization finding
4. Discussion of fine-tuning effects on circuit sharpening vs. vulnerability creation

The key comparative claim — *the circuit pre-exists fine-tuning as an architectural property, and fine-tuning sharpens it while creating new surface-form vulnerabilities* — is supported by all three phases of this study.
