# Research Plan: Llama-3.1-8B-Instruct Comparative Circuit Study

## Purpose

This document is the self-contained pickup guide for the comparative mechanistic interpretability study between **Foundation-Sec-8B-Instruct** (the current paper) and **meta-llama/Llama-3.1-8B-Instruct** (the base instruction model). It is written to be handed back to Claude or any researcher at a later date without needing to reconstruct context.

---

## Scientific Hypothesis

Foundation-Sec-8B was created by continued pretraining of `meta-llama/Llama-3.1-8B` on a cybersecurity corpus, then instruction-tuned. The two models share identical architecture (32 layers, 32 heads, 4096 hidden dim).

**Central question**: Is the identified circuit (`L0H11 → L12H15/L12H5/L12H4/L12H28`) a product of security-domain fine-tuning, or is it a general property of the Llama-3.1-8B architecture?

**Predicted outcomes**:
- **Fine-tuning hypothesis** (expected): Llama-3.1-8B-Instruct has no stable Layer 0 detector for PowerShell indicators. Its circuit (if it classifies at all) is distributed differently, perhaps more Layer 0-absent or later-dominated. Evasion rates are higher.
- **Architecture hypothesis** (would be surprising): Llama-3.1-8B-Instruct has a similar early detector family, suggesting the circuit reflects a general inductive bias in Llama toward early keyword detection, not cybersecurity training specifically.
- **Null outcome**: Llama-3.1-8B-Instruct cannot reliably classify PowerShell as malicious/benign, making mechanistic comparison impossible without prompt engineering.

**Secondary question**: Do the same evasion techniques that fool Foundation-Sec also fool Llama? If Llama has a different circuit, it might fail on different techniques, fail on more, or fail on fewer.

---

## Key Differences Between Models

| Property | Foundation-Sec-8B-Instruct | Llama-3.1-8B-Instruct |
|---|---|---|
| HuggingFace ID | `fdtn-ai/Foundation-Sec-8B-Instruct` | `meta-llama/Llama-3.1-8B-Instruct` |
| TransformerLens template | `meta-llama/Llama-3.1-8B-Instruct` | `meta-llama/Llama-3.1-8B-Instruct` |
| Architecture | Identical (32L, 32H) | Identical |
| Training | Llama base + cybersec pretraining + RLHF | Llama base + general RLHF only |
| Label tokens | ` ALLOW` (73360), ` BLOCK` (29777) | **Must be re-established** (see Phase 0) |
| Prompt template | Foundation-Sec chat format | Llama-3.1 chat format (same tokenizer family) |

**Important**: The TransformerLens `template_name` for both models is the same (`meta-llama/Llama-3.1-8B-Instruct`) because TL uses the template only to determine architecture/weight-loading conventions. This means the hook infrastructure works out of the box for Llama-3.1.

---

## Prerequisites

Before any experiment runs:

1. **Model access**: `meta-llama/Llama-3.1-8B-Instruct` requires a HuggingFace token and Meta license acceptance. Verify at: `huggingface.co/meta-llama/Llama-3.1-8B-Instruct`.
2. **VRAM**: Requires ~16 GB in float16. H100 (80GB), A100 (40GB), or A100 (80GB) all sufficient. A single H100 is ideal to match current study conditions.
3. **TransformerLens**: Already installed in the environment (confirmed from existing notebooks). Version should support Llama-3.1.
4. **Operational rule**: Run H100 jobs **serially, not in parallel** — parallel TransformerLens model loads OOM the GPU (noted in PLAN.md).

---

## Code Changes Required

`scaled_validation.py` is ~70–80% reusable as-is. The changes are:

### Option A — CLI args only (no code changes)
Pass `--model-name` and `--template-name` on every command invocation. No file edits needed.

```bash
# Example: add these flags to every command
--model-name meta-llama/Llama-3.1-8B-Instruct \
--template-name meta-llama/Llama-3.1-8B-Instruct
```

### Option B — Edit defaults for a dedicated Llama run session
```python
# scaled_validation.py line 69
DEFAULT_MODEL_NAME = "meta-llama/Llama-3.1-8B-Instruct"
# line 72 — update ONLY if Llama uses different label words
LABELS = {"benign": "<benign_label>", "malicious": "<malicious_label>"}
```

**Recommendation**: Use Option A. Keep `scaled_validation.py` unchanged and always pass model flags explicitly. This preserves reproducibility for the Foundation-Sec baseline.

### Output prefix convention
All Llama artifacts should use a distinct prefix to avoid overwriting Foundation-Sec artifacts:

```bash
--output-prefix artifacts/llama3_
```

---

## Phase 0: Classification Task Setup (Do This First)

**This is the gating step.** Llama-3.1-8B-Instruct was not trained for ALLOW/BLOCK classification. You must establish a working classification prompt and verify accuracy before any MI work.

### Step 0.1 — Design a classification prompt

Foundation-Sec was prompted with a specific cybersecurity instruction format. Llama needs a general instruction-following format. Design a prompt that:
- Provides the task description (classify PowerShell scripts as malicious or benign)
- Ends in a forced 2-token choice format (e.g., "Answer: ALLOW" or "Answer: BLOCK")
- Or uses a next-token-prediction framing where the model completes "Classification: " with either "ALLOW" or "BLOCK"

The simplest approach (maximizing reuse of `scaled_validation.py`) is to keep the same label words (ALLOW/BLOCK) and change only the system prompt / instruction context. The token IDs will be dynamically derived from the Llama tokenizer and will likely differ from Foundation-Sec's 73360/29777 — that's fine, the code handles this.

### Step 0.2 — Run baseline accuracy check

Run `baseline-eval` on a small subset (10–20 pairs) to confirm accuracy:

```bash
python scaled_validation.py baseline-eval \
  --manifest artifacts/circuit_val_pair_manifest_t3000_valid.csv \
  --model-name meta-llama/Llama-3.1-8B-Instruct \
  --template-name meta-llama/Llama-3.1-8B-Instruct \
  --limit 20 \
  --output artifacts/llama3_baseline_smoke.csv
```

**Go/no-go criteria**:
- **Proceed** if accuracy ≥ 85% on the 20-pair subset.
- **Prompt re-design** if accuracy is 50–85%. Try different instruction phrasings or label tokens.
- **Do not proceed with MI** if accuracy is near 50% — the model is effectively random and there is no circuit to find.

### Step 0.3 — Run full baseline on matched cohort

Once the prompt works:

```bash
python scaled_validation.py baseline-eval \
  --manifest artifacts/circuit_val_pair_manifest_t3000_valid_causal18_short.csv \
  --model-name meta-llama/Llama-3.1-8B-Instruct \
  --template-name meta-llama/Llama-3.1-8B-Instruct \
  --output artifacts/llama3_circuit_val_pair_baseline_eval.csv
```

Record the accuracy, mean logit diff, and which families have the weakest accuracy. Families with < 70% accuracy should be flagged and potentially excluded from MI work.

---

## Phase 1: Discovery

**Goal**: Identify candidate circuit components in Llama-3.1-8B-Instruct. Do not assume the Foundation-Sec circuit (`L0H11 → L12`) transfers. Treat this as a fresh discovery.

### Step 1.1 — Attention head ranking (pilot, 18 pairs)

Identify which heads most consistently attend to suspicious indicator tokens:

```bash
python scaled_validation.py batch-discover-heads \
  --manifest artifacts/circuit_val_pair_manifest_t3000_valid_causal18_short.csv \
  --model-name meta-llama/Llama-3.1-8B-Instruct \
  --template-name meta-llama/Llama-3.1-8B-Instruct \
  --num-pairs 18 \
  --output-prefix artifacts/llama3_discovery_attn_l4_n18 \
  --first-n-layers 4
```

Then run across all layers to find late heads:

```bash
python scaled_validation.py batch-discover-heads \
  --manifest artifacts/circuit_val_pair_manifest_t3000_valid_causal18_short.csv \
  --model-name meta-llama/Llama-3.1-8B-Instruct \
  --template-name meta-llama/Llama-3.1-8B-Instruct \
  --num-pairs 18 \
  --output-prefix artifacts/llama3_discovery_attn_full_n18
```

**Record**: Top-5 heads by attention-to-indicator delta. Are any Layer 0 heads in the list? What layers dominate?

### Step 1.2 — Full layer ablation scan

Identify which layers are causally necessary for the malicious decision:

```bash
python scaled_validation.py batch-layer-ablation \
  --manifest artifacts/circuit_val_pair_manifest_t3000_valid_causal18_short.csv \
  --model-name meta-llama/Llama-3.1-8B-Instruct \
  --template-name meta-llama/Llama-3.1-8B-Instruct \
  --num-pairs 18 \
  --output-prefix artifacts/llama3_layer_ablation_full_n18
```

**Record**: Which layer band shows 30–50% causal impact? Does it match the Foundation-Sec pattern (Layers 20–30) or shift earlier/later?

### Step 1.3 — Residual direction tracing

Find which Layer-12-equivalent heads write the strongest malicious direction:

```bash
python scaled_validation.py batch-trace-residual-direction-heads \
  --manifest artifacts/circuit_val_pair_manifest_t3000_valid_causal18_short.csv \
  --model-name meta-llama/Llama-3.1-8B-Instruct \
  --template-name meta-llama/Llama-3.1-8B-Instruct \
  --num-pairs 18 \
  --layer-start 10 --layer-end 16 \
  --output-prefix artifacts/llama3_trace_resid_pre13_n18
```

Adjust `--layer-start` and `--layer-end` based on what you find in Step 1.2. The goal is to find the "late writer" cluster in Llama (which may not be at Layer 12).

**Record**: Top-5 late-writer heads by residual-direction contribution. Note layers.

### Step 1.4 — Contrastive direction check

Confirm that a distinguishable malicious-vs-benign direction exists in Llama's residual stream:

```bash
python scaled_validation.py discover-contrastive-residual-directions \
  --manifest artifacts/circuit_val_pair_manifest_t3000_valid_causal18_short.csv \
  --model-name meta-llama/Llama-3.1-8B-Instruct \
  --template-name meta-llama/Llama-3.1-8B-Instruct \
  --num-pairs 18 \
  --output-prefix artifacts/llama3_contrastive_resid_n18
```

**Record**: At which layer does the contrastive direction become strong? Compare with Foundation-Sec (where Layer 15–20 is the emergence zone).

**Discovery deliverable**: A new circuit hypothesis for Llama, e.g. `LxHy → LzH{a}/LzH{b}/LzH{c}`. This will likely differ from Foundation-Sec's L0→L12 route.

---

## Phase 2: Validation

**Goal**: Confirm the Llama circuit hypothesis causally on the full 96-pair matched cohort.

Use the same procedure as Foundation-Sec but substitute the Llama circuit hypothesis from Phase 1.

### Step 2.1 — Grouped path patching (sufficiency test)

Replace the early detector head(s) output in a benign example with that from the matched malicious example, routed through the identified late heads:

```bash
python scaled_validation.py batch-causal \
  --manifest artifacts/circuit_val_pair_manifest_t3000_valid.csv \
  --model-name meta-llama/Llama-3.1-8B-Instruct \
  --template-name meta-llama/Llama-3.1-8B-Instruct \
  --heads "<LxHy>,<LzHa>,<LzHb>,<LzHc>" \
  --num-pairs 96 \
  --output-prefix artifacts/llama3_path_patching_minimal_n96
```

Substitute `<LxHy>` etc. with the Llama circuit heads identified in Phase 1.

### Step 2.2 — Grouped head ablation (necessity test)

```bash
python scaled_validation.py batch-head-group-ablation \
  --manifest artifacts/circuit_val_pair_manifest_t3000_valid.csv \
  --model-name meta-llama/Llama-3.1-8B-Instruct \
  --template-name meta-llama/Llama-3.1-8B-Instruct \
  --heads "<LxHy>,<LzHa>,<LzHb>,<LzHc>" \
  --num-pairs 96 \
  --output-prefix artifacts/llama3_head_ablation_n96
```

### Step 2.3 — Route variants (same as Foundation-Sec ladder)

Run at minimum these four route variants to enable direct comparison with Table 2 in the paper:
- Minimal branch (early entry + top-3 late heads)
- Stronger late carrier (add top-4th late head)
- H2-equivalent-free carrier (drop the suspected auxiliary head)
- Top-5 bundle (include all top-5 late heads)

**Validation deliverable**: Mean Δ and flip rate for each route on the 96-pair cohort. Record per-family results in the same format as Table 2 in `paper_draft.tex`.

---

## Phase 3: Evasion Benchmark

**Goal**: Run the identical two-tier evasion benchmark on Llama and compare miss rates and techniques.

The evasion benchmark and seed manifest are model-independent — reuse them exactly.

### Step 3.1 — Baseline eval on evasion seeds

Confirm Llama correctly classifies all seed scripts before testing variants:

```bash
python scaled_validation.py baseline-eval \
  --manifest artifacts/evasion_seed_manifest_v2.csv \
  --model-name meta-llama/Llama-3.1-8B-Instruct \
  --template-name meta-llama/Llama-3.1-8B-Instruct \
  --output artifacts/llama3_evasion_seed_baseline.csv
```

Only proceed to variant testing on seeds where Llama correctly classifies the original.

### Step 3.2 — baseline_v1 tier

```bash
python scaled_validation.py build-evasion-candidate-manifest \
  --variant-manifest artifacts/evasion_variant_manifest_reviewed_v3.csv \
  --eval-manifest artifacts/llama3_evasion_seed_baseline.csv \
  --output artifacts/llama3_evasion_candidate_v1.csv

python scaled_validation.py baseline-eval \
  --manifest artifacts/llama3_evasion_candidate_v1.csv \
  --model-name meta-llama/Llama-3.1-8B-Instruct \
  --template-name meta-llama/Llama-3.1-8B-Instruct \
  --output artifacts/llama3_evasion_eval_v1.csv
```

### Step 3.3 — realistic_v2 tier

Same as above but using the v2 variant manifest.

### Step 3.4 — Circuit probes on Llama evasion misses

For each technique that produces misses in Llama, run the circuit probes using the **Llama circuit** (not the Foundation-Sec circuit):

```bash
python scaled_validation.py batch-head-group-ablation \
  --manifest artifacts/llama3_evasion_<miss_slice>.csv \
  --model-name meta-llama/Llama-3.1-8B-Instruct \
  --template-name meta-llama/Llama-3.1-8B-Instruct \
  --heads "<llama_circuit_heads>" \
  --output-prefix artifacts/llama3_evasion_ablation_<miss_slice>
```

**Compare with Foundation-Sec**: Does Llama show the same redistribution pattern, or does evasion actually delete the Llama circuit?

---

## Comparison Framework

### Primary Comparisons (Table Format)

After all runs, build a comparison table with these rows:

| Metric | Foundation-Sec-8B | Llama-3.1-8B | Interpretation |
|---|---|---|---|
| Baseline accuracy on 96-pair cohort | 100% | TBD | |
| Early detector layer | Layer 0 | TBD | |
| Late writer layer | Layer 12 | TBD | |
| Minimal branch mean Δ | -3.156 | TBD | |
| Minimal branch flip rate | 54/96 (56.25%) | TBD | |
| Stronger carrier mean Δ | -3.293 | TBD | |
| Stronger carrier flip rate | 60/96 (62.5%) | TBD | |
| baseline_v1 evasion misses | 6/44 | TBD | |
| realistic_v2 evasion misses | 4/46 | TBD | |
| Evasion miss techniques | iwr alias, format_string | TBD | |
| Circuit survives evasion? | Yes (redistribution) | TBD | |

### Interpretation Criteria

**Fine-tuning drives the circuit (strong support)**:
- Llama has no Layer 0 detector (or it is much weaker), OR
- Llama's circuit is located at substantially different layers, OR
- Llama accuracy on the matched 96-pair cohort is significantly lower than Foundation-Sec

**Architecture drives the circuit (strong support)**:
- Llama has a Layer 0 detector with similar heads (e.g., L0H11 or nearby heads)
- Llama's late writer cluster is also around Layer 12
- Flip rates are comparable

**Mixed / partial fine-tuning effect**:
- Llama has some early detection but weaker (lower flip rates)
- The late writer cluster is present but with different head indices
- Accuracy is similar but margin is smaller

### Evasion Comparison Criteria

**Model-specific vulnerabilities**: If Foundation-Sec misses `invoke_webrequest_alias` but Llama does not (or vice versa), the vulnerability is circuit-specific, not task-specific.

**Shared vulnerabilities**: If both models miss the same techniques, the vulnerability is likely in the PowerShell surface form itself (some tokens are genuinely ambiguous even to general LLMs).

**Mechanistic divergence**: If Llama evasion cases show circuit deletion (early heads stop firing) rather than redistribution, that is a meaningful difference from Foundation-Sec's redistribution pattern.

---

## Compute Budget and Timeline

### Estimated GPU hours (H100, single GPU)

| Phase | Task | Estimated hours |
|---|---|---|
| 0 | Prompt design + baseline accuracy checks | 0.5 |
| 1.1 | Attention discovery, 4-layer scan | 0.25 |
| 1.1 | Attention discovery, full-model scan | 1.0 |
| 1.2 | Full layer ablation | 0.5 |
| 1.3 | Residual direction tracing | 0.5 |
| 1.4 | Contrastive direction check | 0.25 |
| 2.1–2.3 | 4 route variants × 96 pairs patching | 3.0 |
| 2.2 | Ablation variants × 96 pairs | 1.5 |
| 3.1–3.3 | Evasion eval (baseline + v1 + v2) | 1.5 |
| 3.4 | Circuit probes on miss slices | 0.5 |
| **Total** | | **~9–10 GPU hours** |

**Estimated cloud cost**: ~$20–40 on H100 (at $2–4/hr).

**Calendar time**: 2–3 days of active work, spread across GPU sessions. Discovery and validation can be run in separate sessions; results are checkpointed to artifacts.

---

## Deliverables

After completing this study, the following artifacts and documents should exist:

### Artifacts (in `artifacts/llama3_*`)
- `llama3_baseline_eval_96pair.csv` — Llama accuracy on matched cohort
- `llama3_discovery_attn_full_n18_*.csv` — Attention discovery results
- `llama3_layer_ablation_full_n18_*.csv` — Layer ablation scan
- `llama3_trace_resid_pre*_n18_*.csv` — Residual direction tracing
- `llama3_path_patching_*_n96_*.csv` — Grouped path patching (all route variants)
- `llama3_head_ablation_*_n96_*.csv` — Grouped ablation (all route variants)
- `llama3_evasion_eval_v1.csv` — baseline_v1 evasion results
- `llama3_evasion_eval_v2.csv` — realistic_v2 evasion results
- `llama3_evasion_ablation_*.csv` — Circuit probes on miss slices

### Documents (in `claude_review/` or as a new paper section)
- Updated `llama3_comparison_plan.md` with actual results filled into the comparison table
- A `comparison_results.md` summarizing findings and interpretation
- Optional: draft of a comparative paper section if results are strong enough to justify updating `paper_draft.tex`

---

## Notes for Claude Resuming This Work

If you are Claude picking up this plan:

1. **Read this file first**, then read `PLAN.md` and `FINDINGS.md` for current Foundation-Sec baselines.
2. **Check Phase 0 first** — if Llama doesn't classify reliably, everything else is blocked.
3. **All CLI commands are in `scaled_validation.py`** — use `python scaled_validation.py --help` or `python scaled_validation.py <subcommand> --help` for arg details.
4. **Don't assume the circuit is at L0→L12** — treat Llama as a fresh discovery. Use the discovery commands to find the actual circuit.
5. **Record actual circuit heads** from Phase 1 before running Phase 2. Phase 2 commands need specific head arguments.
6. **Serial runs only** — do not try to parallelize TransformerLens model loads. They OOM.
7. **Output prefix**: use `artifacts/llama3_` for all Llama outputs to keep them distinct from Foundation-Sec artifacts.
8. The Foundation-Sec baseline numbers to beat are in `FINDINGS.md` and summarized in the comparison table above.
