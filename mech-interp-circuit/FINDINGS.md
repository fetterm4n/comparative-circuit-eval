# Mechanistic Circuit Validation of Malicious Code Detection in LLMs

## Status
- [x] Dataset prepared for large-scale validation
- [ ] Circuit discovery complete
- [ ] Causal validation confirmed
- [ ] Generalization validated
- [ ] Evasion experiments complete
- [ ] Draft ready for submission

---

## Abstract (Draft)

Large language models are increasingly used for cybersecurity tasks such as malicious code detection, yet their internal decision-making processes remain poorly understood. In this work, we identify and causally validate internal circuits responsible for malicious PowerShell classification in a domain-specific LLM. Using activation patching and head ablation, we demonstrate that specific attention heads aggregate signals from known malicious indicators (e.g., encoded execution and remote retrieval patterns) and propagate these signals through the residual stream to influence output logits. We further evaluate the robustness of this circuit under obfuscation, revealing key failure modes. Our findings provide a foundation for interpretable and robust AI-driven security systems.

---

## 0. Dataset Preparation

- Dataset: 2,556 labeled PowerShell scripts
- Usable rows after dropping empty content: 2,555
- Class balance: 1,295 benign / 1,261 malicious
- Empty-content rows: 1
- Length profile: median 2,200 chars; p90 7,333; p99 107,253; max 1,317,002
- Long-input pressure: 234 samples exceed 8k chars; 116 exceed 16k
- Truncation pressure at 12k-char preprocessing cap: 157 rows
- Initial balanced analysis manifest: 128 rows total, 64 benign / 64 malicious

**Interpretation:**
The scale-up dataset is approximately balanced, but it contains a long-tail of very large scripts. Larger-scale circuit validation should therefore use explicit length controls and report how truncation or filtering affects the evaluation set.

---

## 1. Circuit Hypothesis

**Working Hypothesis:**
A set of attention heads in mid-to-late layers aggregate signals from malicious indicator tokens (e.g., `IEX`, `FromBase64String`, `DownloadString`) and propagate these signals through the residual stream to drive malicious classification.

**Candidate Components:**
- Layers: [TO FILL]
- Heads: [TO FILL]
- Key Tokens:
  - IEX
  - FromBase64String
  - DownloadString
  - Invoke-WebRequest
  - -EncodedCommand

---

## 2. Circuit Discovery Findings

### 2.1 Attention Localization

**Results:**
- Preliminary smoke test only: in a 4-layer probe on a short benign/malicious pair, the top early heads were Layer 0 Heads 9, 7, 20, 4, and 10.
- Preliminary recurrence test: across 5 short benign/malicious pairs in a 4-layer probe, Layer 0 Head 7 appeared in 5/5 pairs, while Layer 0 Heads 9 and 4 appeared in 4/5 pairs.
- On the full-model-validated short-pair subset (4 pairs), the same early-layer pattern persisted: Layer 0 Head 7 appeared in 4/4 pairs, while Layer 0 Heads 4 and 9 appeared in 3/4 pairs.
- After expanding the validated short-pair subset to 7 pairs, Layer 0 Head 9 became the most recurrent early head in the 4-layer probe, appearing in 6/7 pairs. Layer 0 Head 7 appeared in 4/7 pairs and Layer 0 Head 4 appeared in 3/7 pairs.
- Re-running the same validated 7-pair recurrence probe with `first_n_layers = 8` produced the same top recurring heads and counts. In that setting, every top-k hit still came from Layer 0, which argues against the current signal being a trivial artifact of using only 4 layers.
- On the new overlap-controlled validation set, we built 32 explicit benign/malicious pairs where both classes contain suspicious indicator strings, then restricted to a tractable `<=3000`-char subset with 19 pairs. The full model achieved 97.4% accuracy on that tractable overlap subset, leaving 18 fully correct pairs for MI.
- On those 18 validated overlap pairs, the original root-repo Layer 0 head set generalized strongly in recurrence: Head 9 appeared in 13 pairs, Head 8 in 13, Head 23 in 12, and Head 11 in 11. In this broader setting, the root claim that the detector is concentrated in early Layer 0 heads survives better than the older short-pair-only candidate set.
- Breaking the overlap-controlled recurrence results down by indicator family preserved the same overall picture. In `Invoke-Expression`, all four root heads (`H9`, `H11`, `H23`, `H8`) remained positive and recurrent across 4 validated pairs, with `H9` and `H11` strongest. In `FromBase64String`, `H8` and `H11` remained the clearest positive heads across 4 pairs, while `H23` weakened. In smaller families such as `DownloadFile`, `Invoke-WebRequest`, and `-EncodedCommand`, `H9` was usually the strongest positive head.
- The main exception was `DownloadString`, where all four root heads were near zero or slightly negative in the attention-delta summary. That suggests the overlap-controlled circuit is not equally active across every indicator family, even though the broader early-layer recurrence claim still holds.
- Secondary recurring heads in the same probe were Layer 0 Heads 14, 24, 20, and 10.
- These rankings are not yet treated as validated paper findings; they require batch replication on the larger manifest.
- Top heads: [TO FILL]

**Artifacts:**
- artifacts/attention_heatmap.png

---

### 2.2 Residual Stream Contributions

**Artifacts:**
- artifacts/logit_lens/

---

## 3. Causal Validation

### 3.1 Activation Patching

| Head | Δ Logit Recovery | Flip Rate |
|------|-----------------|----------|
|      |                 |          |

**Preliminary reduced-layer probe only:**
- Using a 4-layer truncated model on 3 short pairs and candidate heads `0.7`, `0.9`, `0.4`, benign-to-malicious patching produced the largest mean negative shift for Layer 0 Head 4 (`mean Δ = -0.1491`), followed by Head 7 (`-0.0853`) and Head 9 (`-0.0602`).
- This probe is exploratory rather than publication-grade causal validation because the 4-layer truncated model does not preserve stable malicious-positive logits on all short pairs.
- Re-running on the subset of short pairs that the full model classifies correctly gave a partial 3-pair aggregate with the same candidate heads: Layer 0 Head 4 had the strongest mean patching shift (`mean Δ = -0.1089`), followed by Head 9 (`-0.0745`) and Head 7 (`-0.0531`).
- Expanding the validated causal subset to 6 successful standalone pair runs preserved the same ranking: Layer 0 Head 4 had the strongest mean patching shift (`mean Δ = -0.1093`), followed by Head 7 (`-0.0584`) and Head 9 (`-0.0505`).
- The three added validated pairs were `945.ps1`, `434.ps1`, and `332.ps1`. Their reduced-layer causal runs initially required a CPU fallback on this host because the original `hook_result` intervention path triggered an MPSGraph backend error on longer short pairs.
- The 6-pair causal aggregate is now reproducible from the analysis script via the `aggregate-causal` command, with excluded-pair provenance recorded explicitly in artifact metadata.
- Extending the 4-layer validated causal set to 9 successful pairs by adding `1719.ps1`, `3703.ps1`, and `2276.ps1` kept Layer 0 Head 4 as the top patching head by the summary ranking (`flip rate = 1.0`, `mean Δ = -0.0653`), although the mean patching effect weakened because the longer added pairs were more mixed under the truncated model. Layer 0 Head 7 remained slightly more negative on average (`mean Δ = -0.0736`) but no longer flipped all included pairs.
- Switching the intervention path from `hook_result` to `hook_z` removed the MPSGraph blocker for 4-layer causal runs on this host. That change allowed both previously blocked pairs, `2752.ps1` and `624.ps1`, to run successfully on MPS.
- On the resulting full 11-pair validated 4-layer causal aggregate, Layer 0 Head 4 remained the top patching head by the current summary ranking (`flip rate = 1.0`, `mean Δ = -0.0747`), followed by Head 7 (`-0.0906`, `flip rate = 0.91`) and Head 9 (`-0.0276`, `flip rate = 0.91`).
- On the overlap-controlled validation set, a causal follow-up on the 8 shortest validated pairs using the root head set `L0H11`, `L0H8`, `L0H23`, and `L0H9` did not preserve the original patching ordering. Heads 8 and 23 had negative mean patching shifts (`-0.0595` and `-0.0508`), while Heads 11 and 9 moved positive on average. This is consistent with the benign comparison samples already containing similar indicator strings, making benign-to-malicious patch transfer harder to interpret as a pure "remove malicious evidence" intervention.
- Family-level patch summaries on the same overlap-controlled causal slice show that this instability is systematic rather than random noise. `Invoke-Expression` favored negative patch effects for `H9` and `H11`, `FromBase64String` favored `H8` and `H23`, `IEX` favored `H11` and `H8`, and `Invoke-WebRequest` favored `H23` and `H8`. In other words, patching does not identify a single uniformly dominant head family-wide once the benign controls also contain the suspicious strings.
- Expanding the same overlap-controlled causal slice from 8 shortest pairs to 12 shortest pairs did not clean up the patching story. In the 12-pair aggregate, `H23` became the most negative patching head (`mean Δ = -0.0835`, flip rate `0.83`), while `H11` and `H9` moved positive on average and `H8` stayed only weakly negative. This reinforces the interpretation that patching is a weak validator in the matched-indicator setting, because the benign source activations are not acting like a simple "malicious evidence removed" control.
- Family-level patching on the 12-pair slice remained heterogeneous. `H11` led only in `-EncodedCommand` and `IEX`, `H23` led in `DownloadString` and `FromBase64String`, and `Invoke-Expression` split between `H9` and `H23`. We therefore do not treat patching as confirming a single portable four-head circuit on the overlap-controlled dataset.
- Expanding further to the full 18-pair validated overlap-controlled cohort left the patching conclusion unchanged. `H23` remained the most negative patching head (`mean Δ = -0.0946`, flip rate `0.89`), `H8` stayed only weakly negative (`-0.0296`), and both `H11` and `H9` moved positive on average. On the dominant `Invoke-Expression` family, `H23` was again the most negative patching head, while `H11` was positive. This reinforces that matched-indicator patching is not isolating a single portable causal head in the way the original root-level hypothesis would require.
- A deeper 8-layer follow-up on a very small validated subset (3 pairs: `784.ps1`, `2115.ps1`, `119.ps1`) did not preserve malicious-positive base logits for any of the malicious examples. In that misaligned operating regime, Layer 0 Head 7 became the strongest negative patching head (`mean Δ = -0.1296`), while Heads 9 and 4 moved positive on average.

---

### 3.2 Head Ablation

| Head | Δ Logit Drop | Accuracy Drop |
|------|-------------|--------------|
|      |             |              |

**Preliminary reduced-layer probe only:**
- On the same 3 short pairs, ablation of Layer 0 Head 9 produced the strongest consistent negative shift (`mean Δ = -0.1854`), while Head 4 produced a weaker negative shift (`-0.0462`).
- Layer 0 Head 7 moved in the opposite direction under ablation (`mean Δ = +0.2694`), suggesting it may play a suppressive or compensatory role in this reduced-layer setting rather than a direct malicious-evidence role.
- On the 3-pair aggregate from the full-model-validated short subset, the same pattern remained: Layer 0 Head 9 had the strongest negative ablation shift (`mean Δ = -0.1743`), Head 4 was weaker (`-0.0716`), and Head 7 again moved in the opposite direction (`+0.3511`).
- On the expanded 6-pair validated causal aggregate, the same ordering held and strengthened: Layer 0 Head 9 had the strongest negative ablation shift (`mean Δ = -0.2001`, flip rate `1.0`), Head 4 remained weaker (`-0.0529`), and Head 7 again moved in the opposite direction (`+0.4355`).
- On the expanded 9-pair validated causal aggregate, the ablation result remained stable: Layer 0 Head 9 was still the strongest negative ablation head (`mean Δ = -0.2063`, flip rate `1.0`), Head 4 stayed much weaker (`-0.0306`), and Head 7 again moved in the opposite direction (`+0.3964`).
- On the full 11-pair validated 4-layer causal aggregate after the `hook_z` fix, the ablation result remained stable: Layer 0 Head 9 was still the strongest negative ablation head (`mean Δ = -0.1979`, flip rate `1.0`), Head 4 stayed much weaker (`-0.0319`), and Head 7 again moved in the opposite direction (`+0.3737`).
- On the overlap-controlled validation set, the root head set showed a different but still meaningful causal structure under ablation on the 8 shortest validated pairs: Head 11 had the strongest negative ablation shift (`mean Δ = -0.2834`, flip rate `0.875`), Head 9 was second (`-0.2187`, flip rate `0.875`), while Heads 23 and 8 moved positive on average. This suggests the original root-level claim is partially robust: Heads 11 and 9 still behave like genuine causal contributors on the broader indicator-overlap sample, but the full four-head story does not transfer cleanly under matched-indicator controls.
- The family-level ablation slices strengthen that conclusion. `H11` and `H9` are the only heads that remain negative across every multi-pair overlap family we measured (`FromBase64String`, `Invoke-Expression`, and `Invoke-WebRequest`), and they are also the dominant negative heads in the singleton `DownloadFile` and `IEX` families. By contrast, `H23` is consistently positive in those same ablation summaries, and `H8` is mixed to positive. The broader experiment therefore supports a refined root claim: the early layer-0 detector generalizes, but its most portable causal core is concentrated in `H11` and `H9`, not uniformly across all four original heads.
- Expanding the overlap-controlled causal slice to 12 shortest validated pairs strengthened that same ablation result rather than weakening it. In the 12-pair aggregate, `H11` remained the strongest negative ablation head (`mean Δ = -0.3584`, flip rate `0.92`) and `H9` remained second (`-0.3173`, flip rate `0.92`), while `H8` and `H23` stayed positive on average.
- The 12-pair family-level ablation slices also became more persuasive because they added `-EncodedCommand` and `DownloadString` without breaking the pattern. Across all six represented families in the 12-pair slice, `H11` and `H9` were always the most negative heads, while `H23` stayed positive in every family and `H8` was positive in five of six families. This is the strongest current evidence that the broad overlap-controlled circuit has a stable causal core in `H11/H9`.
- Expanding once more to the full 18-pair validated overlap-controlled cohort preserved the same ablation ordering. `H11` remained the strongest negative ablation head (`mean Δ = -0.3029`, flip rate `0.94`) and `H9` remained second (`-0.2826`, flip rate `0.94`), while `H23` (`+0.2572`) and `H8` (`+0.1097`) stayed positive on average.
- The 18-pair family-level ablation slices now span all seven represented overlap families and still preserve the same qualitative result. In every family, `H11` and `H9` are the most negative heads, while `H23` is positive in every family and `H8` is positive in six of seven families. This is the strongest current reduced-layer evidence for the refined claim that the portable causal core of the overlap-controlled detector is `H11/H9`.
- In the 8-layer, 3-pair follow-up where all base malicious logits were already negative, the ablation ranking also changed: Layer 0 Head 7 had the strongest negative ablation shift (`mean Δ = -0.0814`), Head 9 was weaker (`-0.0205`), and Head 4 moved positive (`+0.2122`). We therefore do not treat the 8-layer truncated causal ranking as confirming the 4-layer exploratory split.

---

## 4. Generalization

- Short-pair baseline subset: 10 samples (5 benign / 5 malicious)
- Full-model baseline accuracy on that subset: 90%
- Observed failure case in short-pair subset: `321.ps1` was misclassified as benign with logit diff `-0.0469`
- Expanded short-pair baseline subset: 16 samples (8 benign / 8 malicious)
- Full-model baseline accuracy on the expanded short-pair subset: 93.75%
- Expanded validated short-pair subset: 7 pairs (14 rows); the only baseline failure remained `321.ps1`
- Of those 7 validated pairs, all now have successful 4-layer reduced-layer causal runs on this host after replacing the MPS-failing `hook_result` intervention path.
- Further-expanded short-pair baseline subset: 24 samples (12 benign / 12 malicious)
- Full-model baseline accuracy on the 12-pair short subset: 95.83%
- Further-expanded validated short-pair subset: 11 pairs (22 rows); the only baseline failure still remained `321.ps1`
- Of those 11 validated pairs, all 11 now have successful 4-layer causal runs on this host. The previous MPSGraph failure and the long-running CPU tail were both artifacts of the old `hook_result` intervention path rather than immutable host limits.
- On the 8-layer causal follow-up subset, none of the 3 malicious examples retained a malicious-positive base logit in the truncated model, which limits the interpretability of those deeper truncated causal effects.
- For the overlap-controlled validation set, the full 32-pair manifest is broad enough for dataset construction but still too slow for interactive full-model MI on the longest samples. The tractable `<=3000` subset retained 19 complete pairs, of which 18 were fully correct under the full model and 8 shortest pairs were used for the first causal follow-up.
- Within that 18-pair validated overlap-controlled subset, all seven represented indicator families (`Invoke-Expression`, `FromBase64String`, `Invoke-WebRequest`, `DownloadFile`, `DownloadString`, `IEX`, `-EncodedCommand`) were classified correctly by the full model. The broader MI story is therefore no longer resting on a single indicator type.
- After tightening the reduced-layer batch code to run causal forwards under `torch.inference_mode()` and release per-pair tensors promptly, the overlap-controlled root-head causal pass scaled from 8 shortest pairs to 12 shortest pairs on this host without the earlier MPS memory failure.
- With the same memory-tightened batch path, the overlap-controlled root-head causal pass also scaled to the full 18-pair validated cohort at 4 layers. However, the next depth increase remains blocked locally: the same 18-pair root-head causal run at `first_n_layers = 8` still exhausted MPS memory on this host before completion.
- Implication: short-pair probes remain usable for exploratory MI if we track both full-model correctness and host/backend exclusions separately from model behavior.

---

## 5. Evasion Analysis

| Technique | Δ Logit Change | Detection Drop |
|----------|---------------|----------------|
|          |               |                |

---

## 6. Security Implications

[TO FILL]

---

## Artifacts Index

| Artifact | Description |
|---------|------------|
| artifacts/dataset_summary.json | Dataset statistics and preprocessing summary |
| artifacts/analysis_manifest.csv | Balanced subset for tractable MI experiments |
| artifacts/baseline_eval.csv | Baseline ALLOW/BLOCK evaluation outputs |
| artifacts/attention_top_heads_l4.csv | Preliminary 4-layer short-pair head ranking |
| artifacts/attention_top_heads_l4.json | Metadata for preliminary 4-layer short-pair probe |
| artifacts/batch_attention_l4_n3_summary.csv | Recurrence summary across 3 short-pair probes |
| artifacts/batch_attention_l4_n5_summary.csv | Recurrence summary across 5 short-pair probes |
| artifacts/batch_causal_l4_h794_n3_patch_summary.csv | Reduced-layer patching summary for heads 0.7, 0.9, 0.4 |
| artifacts/batch_causal_l4_h794_n3_ablation_summary.csv | Reduced-layer ablation summary for heads 0.7, 0.9, 0.4 |
| artifacts/short_pairs_manifest_n5.csv | Full-model baseline cohort for short-pair validation |
| artifacts/short_pairs_baseline_eval_n5.csv | Full-model baseline results on the short-pair cohort |
| artifacts/valid_short_pairs_manifest_n4.csv | Short-pair cohort filtered to full-model-correct pairs |
| artifacts/valid_batch_attention_l4_n4_summary.csv | Recurrence summary on the validated short-pair subset |
| artifacts/valid_partial_causal_patch_summary_n3.csv | Partial validated-subset patch summary across 3 causal-pair runs |
| artifacts/valid_partial_causal_ablation_summary_n3.csv | Partial validated-subset ablation summary across 3 causal-pair runs |
| artifacts/short_pairs_manifest_n8.csv | Expanded short-pair baseline cohort |
| artifacts/short_pairs_baseline_eval_n8.csv | Full-model baseline results on the expanded short-pair cohort |
| artifacts/valid_short_pairs_manifest_n7.csv | Expanded short-pair cohort filtered to full-model-correct pairs |
| artifacts/valid_batch_attention_l4_n7_summary.csv | Recurrence summary on the expanded validated short-pair subset |
| artifacts/valid_batch_attention_l8_n7_summary.csv | 8-layer recurrence summary on the expanded validated short-pair subset |
| artifacts/short_pairs_manifest_n12.csv | Further-expanded short-pair baseline cohort |
| artifacts/short_pairs_baseline_eval_n12.csv | Full-model baseline results on the 12-pair short cohort |
| artifacts/valid_short_pairs_manifest_n11.csv | Further-expanded short-pair cohort filtered to full-model-correct pairs |
| artifacts/expanded_valid_causal_patch_summary_n6.csv | Expanded validated-subset patch summary across 6 successful causal-pair runs |
| artifacts/expanded_valid_causal_ablation_summary_n6.csv | Expanded validated-subset ablation summary across 6 successful causal-pair runs |
| artifacts/expanded_valid_causal_metadata_n6.json | Provenance and exclusion metadata for the expanded causal aggregate |
| artifacts/expanded_valid_causal_cli_n6_patch_summary.csv | CLI-generated patch summary for the reproducible 6-pair causal aggregate |
| artifacts/expanded_valid_causal_cli_n6_ablation_summary.csv | CLI-generated ablation summary for the reproducible 6-pair causal aggregate |
| artifacts/expanded_valid_causal_cli_n6_metadata.json | CLI-generated provenance and exclusion metadata for the reproducible 6-pair causal aggregate |
| artifacts/expanded_valid_causal_cli_n9_patch_summary.csv | CLI-generated patch summary for the reproducible 9-pair 4-layer causal aggregate |
| artifacts/expanded_valid_causal_cli_n9_ablation_summary.csv | CLI-generated ablation summary for the reproducible 9-pair 4-layer causal aggregate |
| artifacts/expanded_valid_causal_cli_n9_metadata.json | CLI-generated provenance and exclusion metadata for the reproducible 9-pair 4-layer causal aggregate |
| artifacts/expanded_valid_causal_cli_n11_zfix_patch_summary.csv | CLI-generated patch summary for the full 11-pair 4-layer causal aggregate after the `hook_z` fix |
| artifacts/expanded_valid_causal_cli_n11_zfix_ablation_summary.csv | CLI-generated ablation summary for the full 11-pair 4-layer causal aggregate after the `hook_z` fix |
| artifacts/expanded_valid_causal_cli_n11_zfix_metadata.json | CLI-generated metadata for the full 11-pair 4-layer causal aggregate after the `hook_z` fix |
| artifacts/circuit_val_set_metadata.json | Metadata for the balanced indicator-overlap validation set |
| artifacts/circuit_val_pair_manifest.csv | Explicit benign/malicious indicator-paired manifest from `circuit_val_set.csv` |
| artifacts/circuit_val_pair_manifest_t3000.csv | Tractable overlap-paired subset with complete pairs at `<=3000` chars |
| artifacts/circuit_val_pair_baseline_eval_t3000.csv | Full-model baseline results on the tractable overlap-paired subset |
| artifacts/circuit_val_pair_manifest_t3000_valid.csv | Fully correct overlap-paired subset used for MI |
| artifacts/circuit_val_batch_attention_l4_n18_summary.csv | 4-layer recurrence summary on 18 validated overlap-controlled pairs |
| artifacts/circuit_val_batch_causal_root_l4_n8short_patch_summary.csv | Root-head patch summary on 8 shortest validated overlap-controlled pairs |
| artifacts/circuit_val_batch_causal_root_l4_n8short_ablation_summary.csv | Root-head ablation summary on 8 shortest validated overlap-controlled pairs |
| artifacts/circuit_val_batch_causal_root_l4_n8short_metadata.json | Metadata for the overlap-controlled root-head causal follow-up |
| artifacts/circuit_val_family_root_heads_baseline_summary.csv | Family-level baseline summary on the validated overlap-controlled subset |
| artifacts/circuit_val_family_root_heads_attention_summary.csv | Family-level recurrence summary for the root head set |
| artifacts/circuit_val_family_root_heads_patch_summary.csv | Family-level patching summary for the root head set |
| artifacts/circuit_val_family_root_heads_ablation_summary.csv | Family-level ablation summary for the root head set |
| artifacts/circuit_val_family_root_heads_metadata.json | Metadata for the family-level overlap summaries |
| artifacts/circuit_val_pair_manifest_t3000_valid_causal12_short.csv | 12-shortest-pair overlap-controlled causal manifest |
| artifacts/circuit_val_batch_causal_root_l4_n12short_patch_summary.csv | Root-head patch summary on 12 shortest validated overlap-controlled pairs |
| artifacts/circuit_val_batch_causal_root_l4_n12short_ablation_summary.csv | Root-head ablation summary on 12 shortest validated overlap-controlled pairs |
| artifacts/circuit_val_batch_causal_root_l4_n12short_metadata.json | Metadata for the 12-pair overlap-controlled root-head causal follow-up |
| artifacts/circuit_val_family_root_heads_n12short_baseline_summary.csv | Family-level baseline summary for the 12-pair overlap-controlled causal slice |
| artifacts/circuit_val_family_root_heads_n12short_attention_summary.csv | Family-level recurrence summary for the 12-pair overlap-controlled causal slice |
| artifacts/circuit_val_family_root_heads_n12short_patch_summary.csv | Family-level patching summary for the 12-pair overlap-controlled causal slice |
| artifacts/circuit_val_family_root_heads_n12short_ablation_summary.csv | Family-level ablation summary for the 12-pair overlap-controlled causal slice |
| artifacts/circuit_val_family_root_heads_n12short_metadata.json | Metadata for the 12-pair family-level overlap summaries |
| artifacts/circuit_val_pair_manifest_t3000_valid_causal18_short.csv | Full 18-pair overlap-controlled causal manifest |
| artifacts/circuit_val_batch_causal_root_l4_n18short_patch_summary.csv | Root-head patch summary on the full 18-pair validated overlap-controlled cohort |
| artifacts/circuit_val_batch_causal_root_l4_n18short_ablation_summary.csv | Root-head ablation summary on the full 18-pair validated overlap-controlled cohort |
| artifacts/circuit_val_batch_causal_root_l4_n18short_metadata.json | Metadata for the full 18-pair overlap-controlled root-head causal follow-up |
| artifacts/circuit_val_family_root_heads_n18short_baseline_summary.csv | Family-level baseline summary for the full 18-pair overlap-controlled causal slice |
| artifacts/circuit_val_family_root_heads_n18short_attention_summary.csv | Family-level recurrence summary for the full 18-pair overlap-controlled causal slice |
| artifacts/circuit_val_family_root_heads_n18short_patch_summary.csv | Family-level patching summary for the full 18-pair overlap-controlled causal slice |
| artifacts/circuit_val_family_root_heads_n18short_ablation_summary.csv | Family-level ablation summary for the full 18-pair overlap-controlled causal slice |
| artifacts/circuit_val_family_root_heads_n18short_metadata.json | Metadata for the full 18-pair family-level overlap summaries |
| artifacts/valid_l8_causal_n3_mps_patch_summary.csv | 8-layer patch summary on a 3-pair validated subset |
| artifacts/valid_l8_causal_n3_mps_ablation_summary.csv | 8-layer ablation summary on a 3-pair validated subset |
| artifacts/valid_l8_causal_n3_mps_metadata.json | Provenance metadata for the 8-layer 3-pair causal follow-up |
| artifacts/attention_heatmap.png | Attention heatmap |
| artifacts/patching_results.csv | Activation patching |
| artifacts/ablation_results.csv | Head ablation |
| artifacts/evasion_results.csv | Evasion results |
