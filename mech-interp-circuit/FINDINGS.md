# Mechanistic Circuit Validation of Malicious Code Detection in LLMs

## Status
- [x] Dataset prepared for large-scale validation
- [x] Circuit discovery complete
- [x] Causal validation confirmed on the main overlap-controlled cohort
- [ ] Independent generalization fully validated
- [x] Evasion experiments complete
- [ ] Draft ready for submission

**Current state:**
The core circuit claim is now stable enough for writeup. On the overlap-controlled 18-pair validation cohort, the full model reached 100% accuracy, attention recurrence remained concentrated in Layer 0, and causal ablation consistently identified `L0H11` and `L0H9` as the most portable early detector heads. Full-model ablation, late-layer patching, contrastive residual tracing, and grouped late-head interventions support a later decision stage centered on `Layer 12-13` attention plus a broader MLP band. The cleanest current end-to-end claim is a minimal direct branch `L0H11 -> L12H15/L12H5/L12H4`, together with a stronger sufficiency-oriented late carrier `L12H15/L12H5/L12H4/L12H28`.

The expanded 96-pair interim cohort materially improves matched-control coverage but does not constitute a fully independent holdout because scripts are reused across pairings. The evasion benchmark is now also strong enough to support a mechanistic robustness claim. Two conservative obfuscation techniques produce real misses, and the clearest one, `invoke_webrequest_alias`, shows that the validated late carrier survives the evasion at `resid_pre13` but later blocks redistribute how the final decision depends on that evidence by `resid_pre31`. The remaining gaps are therefore no longer basic circuit discovery; they are stronger independent generalization and final presentation.

---

## Abstract (Draft)

Large language models are increasingly used for cybersecurity tasks such as malicious code detection, yet their internal decision-making processes remain poorly understood. In this work, we identify and causally validate a circuit for malicious PowerShell classification in a domain-specific LLM. On an overlap-controlled 18-pair cohort where benign and malicious scripts share suspicious indicators, we localize a portable early detector core in `Layer 0`, with `L0H11` and `L0H9` as the strongest causal heads. We then localize a later decision stage centered on `Layer 12-13` attention and a broader MLP band, with the strongest sufficiency-oriented late carrier given by `L12H15/L12H5/L12H4/L12H28`. An expanded 96-pair interim cohort preserves the same late-stage picture while showing that `L12H2` behaves more like a family-sensitive auxiliary contributor than a stable core writer. Finally, we evaluate the circuit under conservative syntax-preserving obfuscation and find real evasion failures. The strongest failure mode, `invoke_webrequest_alias`, does not remove the validated late carrier. Instead, it preserves the usual late malicious-evidence write at `resid_pre13` while redistributing, in later blocks, how the final decision depends on that evidence by `resid_pre31`. These results support a concrete mechanistic robustness claim: the model’s malicious-code evidence can remain present under obfuscation even as downstream computation repurposes or discounts it before the final readout.

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
- Natural-overlap circuit-validation set: 216 rows total, 108 benign / 108 malicious
- Length-filtered natural-overlap pool at `<=3000` chars: 159 rows total, 55 benign / 104 malicious
- Original mechanistic validation cohort: 18 fully correct benign/malicious pairs, 36 total rows
- Expanded interim pair cohort from within-family matching: 100 candidate pairs, 200 total rows
- Expanded interim valid pair cohort after H100 baseline filtering: 96 valid pairs, 192 total rows, 78 unique scripts
- Important caveat: the 96-pair expanded cohort reuses scripts across multiple pairings, so it materially improves coverage but does not behave like 96 independent holdout pairs

**Interpretation:**
The scale-up dataset is approximately balanced, but it contains a long-tail of very large scripts. Larger-scale circuit validation should therefore use explicit length controls and report how truncation or filtering affects the evaluation set.

---

## 1. Circuit Hypothesis

**Working Hypothesis:**
A set of early attention heads detects suspicious PowerShell indicators (e.g., `IEX`, `FromBase64String`, `DownloadString`, `Invoke-WebRequest`, `-EncodedCommand`) and writes those signals into the residual stream, after which later layers convert that evidence into the final malicious/benign decision.

**Candidate Components:**
- Early detection layer: Layer 0
- Strongest recurrent heads on the overlap-controlled cohort: `L0H9`, `L0H11`, `L0H23`, `L0H8`
- Strongest portable causal core under reduced-layer ablation: `L0H11`, `L0H9`
- Current full-model decision-stage candidate components:
  - Attention-dominant band: layers `11-13`, with additional support at `9`, `17`, and `24`
  - MLP-dominant band: layers `6`, `10`, and `13`, with secondary support at `15`, `24`, and `31`
  - Strongest targeted late heads so far: `L12H5` and `L13H0`
  - Late-stage neuron probes: distributed, with no single neuron yet matching the layer-level effects
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
- We built an overlap-controlled validation set where benign and malicious scripts share suspicious indicator strings, then restricted to a tractable `<=3000`-char paired subset.
- On that tractable subset, the original imported baseline left 18 fully correct benign/malicious pairs for mechanistic analysis. The new local H100 baseline reproduced those 18 valid pairs with 36/36 correct predictions.
- A larger interim cohort is now available from the same natural-overlap source pool by generating many within-family length-matched pairings rather than keeping only one zip-style pair per family member. With a per-family cap of 20 combinations, this produced 100 candidate pairs at `<=3000` chars.
- A local H100 baseline on that expanded candidate cohort reached `98%` row accuracy (`200/200` rows scored, four pairs dropped by pairwise filtering), leaving 96 valid pairs and 192 valid rows.
- That expanded cohort improves script coverage from 36 unique files in the original mechanistic set to 78 unique files, including 47 unique files not present in the original 18-pair cohort.
- A local H100 recurrence run over those 18 pairs again concentrated attention in Layer 0. The top recurring heads were `L0H9` (`pair_count = 13`, `mean_delta = 0.00793`), `L0H11` (`10`, `0.00587`), `L0H23` (`7`, `0.00452`), and `L0H8` (`7`, `0.00259`).
- This reproduces the earlier non-local summary closely and supports a stable early-detector claim: indicator-focused attention is concentrated in Layer 0 rather than emerging only in deeper blocks.
- The overlap-controlled family breakdown remains heterogeneous. `Invoke-Expression` and `FromBase64String` preserve strong positive recurrence for the root head set, while `DownloadString` remains weaker and less consistent.
- The expanded cohort is useful as a stronger interim validation set, but it should be interpreted as a paired-coverage expansion rather than a clean new holdout. Several families still rely on a small benign source pool, especially `DownloadFile`, `DownloadString`, and `Invoke-WebRequest`.
- Practical interpretation: the broad detector generalizes across several indicator families, but it is better described as an early Layer 0 detector family than as a single universally dominant head.

**Current best-supported early heads:**
- `L0H9`: most recurrent overlap-controlled head
- `L0H11`: second-most recurrent and later a strong causal ablation head
- `L0H23`: recurrent, but mixed under causal interventions
- `L0H8`: recurrent, but mixed under causal interventions

**Artifacts:**
- artifacts/circuit_val_batch_attention_l4_n18_h100_summary.csv
- artifacts/circuit_val_batch_attention_l4_n18_h100_metadata.json

---

### 2.2 Residual Stream Contributions

**Current full-model layer-component localization:**
- A new full-model layer ablation sweep on the 18-pair H100 cohort finally exposes a plausible later decision stage that the truncated 4-layer probes could not measure.
- Attention ablation is most destructive in layers `13`, `11`, `12`, `9`, `17`, and `24`. The strongest cohort-level effect is `Layer 13 attention` (`mean Δ = -3.45`, `flip_rate = 0.50`).
- MLP ablation is most destructive in layers `6`, `13`, and `10`, followed by `24`, `15`, and `31`. The strongest cohort-level effects are `Layer 6 MLP` (`mean Δ = -3.59`, `flip_rate = 0.39`) and `Layer 13 MLP` (`mean Δ = -3.52`, `flip_rate = 0.61`).
- Full-model benign-to-malicious patching provides the strongest bidirectional support for the late attention band. Patching benign attention outputs into malicious prompts flips `72%` of pairs at `Layer 13` and `78%` at `Layer 12`, with very large negative mean shifts (`-4.57` and `-4.40`).
- Full-model MLP patching is weaker but still directionally supportive at `Layer 10` (`mean Δ = -1.69`) and `Layer 6` (`-1.39`). `Layer 13 MLP` patching is much weaker (`-0.15`), suggesting that the attention side of the late-stage band is currently the cleaner patching signal.
- A direct path-patching follow-up comparing early heads, residual entry, and late attention states suggests that the late attention band is the dominant transportable state in the current matched-control setup. Patching `attn12+attn13` together produced the strongest effect (`mean Δ = -5.74`, `flip_rate = 0.94`). Patching the residual stream entering that band at `resid_pre12` was also substantial (`mean Δ = -3.44`, `flip_rate = 0.44`). By contrast, patching the early detector heads `L0H11+L0H9` alone was much weaker (`mean Δ = -0.53`, `flip_rate = 0.11`).
- The combined early+late+residual patch did not become stronger than late-attention patching alone. That means the current benign-source patch setup does not yet isolate a clean additive early-to-late path; some of the patched states likely interfere or overconstrain one another when copied together from benign controls.
- A follow-up low-rank residual-subspace experiment at `resid_pre12` did not recover the strong whole-state residual effect. The top `1/2/4/8` PCA-style subspace directions explained `34.8%/51.8%/73.2%/88.6%` of benign-to-malicious residual variance, but patching them caused only tiny mean shifts (`-0.089`, `-0.011`, `+0.003`, `-0.030`) and at most `1/18` flips.
- The same negative result held one layer later at `resid_pre13`. The top `1/2/4/8` dimensions explained `32.9%/48.8%/70.8%/87.2%` of variance, but patching them again produced only tiny effects (`-0.062`, `-0.004`, `+0.025`, `-0.087`) and at most `1/18` flips.
- A follow-up contrastive-direction sweep performed materially better than PCA-style patching. At `resid_pre12`, patching the single mean benign-to-malicious residual direction caused a moderate negative shift (`mean Δ = -0.694`, `flip_rate = 0.167`), while the direct final-logit readout direction remained negligible (`mean Δ = -0.002`).
- The same contrastive test strengthened one layer later at `resid_pre13`. Patching the single mean-delta direction produced `mean Δ = -1.323` with `flip_rate = 0.222`, again far stronger than any PCA-ranked subspace patch at the same site. The direct logit-readout direction still did essentially nothing (`mean Δ = -0.002`).
- Tracing attention-head writes into that discovered `resid_pre13` mean-delta direction points primarily to `Layer 12`, which is also the only late attention layer that can write into `resid_pre13` in the strict causal sense. The strongest direct writers are `L12H15` (`mean Δproj = +0.0671`), `L12H5` (`+0.0441`), `L12H4` (`+0.0364`), `L12H2` (`+0.0254`), and `L12H28` (`+0.0207`), all positive on nearly every or every pair.
- Several `Layer 13` heads also align with the same residual-space direction when their outputs are projected onto it, especially `L13H22` (`mean Δproj = +0.0289`), `L13H21` (`+0.0233`), and `L13H30` (`+0.0215`). These should be interpreted as downstream continuations of the same late decision geometry, not direct writers into `resid_pre13`.
- Grouped causal follow-up confirms that the traced `Layer 12` writer set is not just geometrically aligned but causally meaningful. On the original 18-pair cohort, patching the top-five writer bundle `L12H15/L12H5/L12H4/L12H2/L12H28` from benign into malicious prompts gives `mean Δ = -3.702` with `flip_rate = 0.50`, while ablating the same bundle gives `mean Δ = -1.567`.
- A compactness check with only the top two traced writers, `L12H15` and `L12H5`, remains directionally negative but much weaker: grouped patching gives `mean Δ = -0.932` and grouped ablation gives `mean Δ = -0.756`, both with only `1/18` flips. That suggests the late writer stage is partially localized but still distributed across several Layer 12 heads rather than collapsing to a 2-head core.
- A direct early-to-late probe now shows that the early detector pair does affect the late transport direction. Benign patching of `L0H11/L0H9` moves the discovered `resid_pre13` mean-delta projection by `+0.0286` on average (toward the benign side) while shifting the final logit by `-0.533`. Ablating `L0H11/L0H9` moves that same projection by `-0.0349` (toward the malicious side) with `mean logit Δ = -0.632`.
- A combined grouped-causal follow-up shows only limited additivity. Patching `L0H11/L0H9` together with the top-five `Layer 12` writer bundle improves the grouped patch effect only slightly (`mean Δ = -3.913`, `flip_rate = 0.611`) relative to the late writer bundle alone (`-3.702`, `0.500`). Likewise, combined ablation is only modestly stronger than late-bundle ablation alone (`-1.807` vs `-1.567`) and does not increase flips.
- An intervention-conditioned read-path trace adds an important refinement: the early detector pair does not appear to modulate the late bundle uniformly. Under `L0H11/L0H9` patching, the strongest `Layer 12` changes along the `resid_pre13` mean-delta direction land on `H12`, `H20`, `H10`, `H6`, `H4`, and then `H5`, while `H15` moves only weakly. Under `L0H11/L0H9` ablation, the clearest changes land on `H9`, `H8`, and `H6`, with `H5` again near zero and `H28` slightly negative.
- Practical interpretation: the early detector family does influence the late decision stage, but the strongest read path from `L0H11/L0H9` into `Layer 12` is not identical to the strongest late writer bundle found by direct residual-direction tracing. The late stage therefore appears to contain at least two overlapping structures: a top-five writer bundle that most strongly drives the final late transport direction, and a partially different subset that is most sensitive to upstream early-head interventions.
- A direct grouped-causal comparison confirms that those two late subsets play very different roles. The early-sensitive `Layer 12` subset (`H9/H8/H6/H12/H20/H10`) is strongly **anti-causal** for the malicious decision: benign patching makes malicious prompts *more* malicious (`mean Δ = +1.775`) and grouped ablation also makes them more malicious (`+1.439`). So this subset looks like a competing or corrective path rather than the core late malicious-evidence carrier.
- Leave-one-out tests inside the top-five writer bundle show that `L12H15` is the single most important member. Dropping `H15` reduces grouped patching from `-3.702` to `-3.536` and grouped ablation from `-1.567` to `-0.932`. Dropping `H5` also weakens the bundle, but less strongly (`patch = -3.328`, `ablation = -1.245`).
- A compact top-three writer core `L12H15/L12H5/L12H4` remains clearly causal (`patch = -3.275`, `ablation = -1.117`), but it still underperforms the fuller late-writer bundles.
- Additional leave-one-out tests on the 18-pair cohort suggested `H2` and `H28` were supportive but not primary. A larger 96-pair H100 follow-up refines that claim materially. On that expanded cohort, the fuller top-five writer bundle still beats the clean direct route under path patching (`mean Δ = -3.265`, `flip_rate = 0.583` vs `-3.156`, `0.562` for `L0H11 + L12H15/H5/H4`), but removing `H2` does **not** weaken sufficiency: `L12H15/L12H5/L12H4/L12H28` gives `mean Δ = -3.293` with `flip_rate = 0.625`. By contrast, removing `H28` weakens the carrier clearly (`mean Δ = -2.886`, `flip_rate = 0.490`).
- The ablation-side story is different. On the same 96-pair cohort, the full top-five bundle remains more necessary than `L12H15/L12H5/L12H4/L12H28` (`mean Δ = -1.206`, `flip_rate = 0.094` vs `-1.044`, `0.000`). Family-level breakdowns show that `H2` helps most under ablation for `DownloadFile`, `DownloadString`, `Invoke-WebRequest`, and `-EncodedCommand`, while it is near-neutral or slightly anti-causal for `FromBase64String`, `Invoke-Expression`, and `IEX`.
- The current best late-stage writeup should therefore separate two claims. The cleanest sufficiency-oriented late carrier is `L12H15/L12H5/L12H4/L12H28`, while `H2` is better described as a family-sensitive auxiliary late head that improves grouped ablation more than path patching.
- The evasion benchmark now supports that late-stage claim across more than one family. In the first candidate sweep, `downloadstring_psobject_invoke` produced `2/6` misses, both inside the `FromBase64String` family. In the expanded second sweep, `invoke_webrequest_alias` produced `4/4` misses on the reviewed `Invoke-WebRequest` slice and is currently the clearest failure mode in the repo. The important mechanistic read is the same in both cases: the route does not disappear. On the obfuscated variants, the clean direct route `L0H11 -> L12H15/H5/H4` and the fuller late carrier `L12H15/L12H5/L12H4/L12H28` remain strongly sufficient under path patching, but the usual late bundle loses necessity under grouped ablation and can become anti-causal. For readers with standard mechanistic-interpretability background: the simplest interpretation is a **necessity/sufficiency split**. The obfuscation appears to reroute computation around the usual late writer bundle enough that ablating it no longer harms the malicious decision much, while patching that bundle can still reintroduce malicious evidence and recover the behavior.
- The final `Invoke-WebRequest` alias follow-up sharpens that claim materially. On that family, the early `L0H11/L0H9` pair is already anti-causal even on the unobfuscated seeds, so the alias-based miss is not well described as a broken early detector. More importantly, slice-specific residual-direction probes show that the usual late writer family is still present on the evaded variants. At `resid_pre13`, `L12H15` remains the dominant writer into the slice-specific malicious-vs-benign transport direction, with `H5`, `H2`, and `H28` still in the main positive writer set. Ablating `L12H15/L12H5/L12H4/L12H28` reduces that `resid_pre13` transport direction on both seeds and variants, even though the variants already show an anti-causal logit effect.
- The cleanest localization comes from one final downstream probe. At `resid_pre31`, the same ablation still pushes the seed cohort in the usual direction (`mean logit Δ = -0.125`, `mean projection Δ = -0.203`), but it pushes the alias variants in the opposite direction on both the logit and the slice-specific late residual (`mean logit Δ = +0.344`, `mean projection Δ = +0.344`). The best current interpretation is therefore more precise than a generic rerouting story: the validated `Layer 12 -> resid_pre13` malicious-evidence carrier survives the evasion, but later blocks between `resid_pre13` and `resid_pre31` redistribute how the final decision depends on that evidence. So the evasion is not deletion of the late carrier and not merely a final-unembed quirk; it is a downstream reuse or compensation mechanism inside the later residual stream.
- Single-head routing splits the early detector pair more clearly. Under `L0H11` patching alone, the strongest `Layer 12` changes include `H12`, `H5`, `H4`, `H20`, `H10`, and a small but visible effect on `H15`. Under `L0H9` patching alone, the strongest changes land on `H9`, `H4`, `H10`, `H6`, and only weakly on the core writer heads. Practical interpretation: `L0H11` appears more directly coupled to the late malicious-evidence carrier, while `L0H9` may contribute more through the broader early-sensitive/corrective late geometry.
- Direct grouped route tests now support that split. The `L0H11`-aligned late route `L12H15/L12H5/L12H4` is clearly causal (`patch = -3.275`, `ablation = -1.117`). By contrast, the `L0H9`-aligned late route `L12H9/L12H6/L12H10` is weak and mixed: grouped patching is slightly positive (`+0.270`) and grouped ablation is nearly neutral (`-0.019`). The cleanest currently supported end-to-end branch is therefore `L0H11 -> L12H15/H5/H4`, not a symmetric two-head early story.
- A final comparison between the clean `L0H11` branch and the fuller late carrier shows the remaining tradeoff clearly. On the 18-pair cohort, combining `L0H11` with the top-three late route gives `patch = -3.490` and `ablation = -1.402`, while combining `L0H11` with the top-five late bundle gives `patch = -3.879` and `ablation = -1.802`. On the expanded 96-pair cohort, the same distinction still holds qualitatively, but the cleaner late sufficiency bundle is now `L12H15/L12H5/L12H4/L12H28`, not the full top-five set.
- Practical interpretation: the patchable late residual signal is real at the whole-state level, but it is **not** well captured by a simple low-rank variance-ranked subspace. The later decision carrier therefore appears more distributed, more nonlinear, or misaligned with PCA-style directions than the early head detector.
- The contrastive-direction result refines that claim. Some of the late residual signal *is* concentrated along a task-aligned transport direction, especially at `resid_pre13`, but the useful direction is closer to the cohort mean malicious-vs-benign displacement than to the direct output readout axis.
- Family-level summaries preserve the same broad picture. Across `Invoke-Expression`, `FromBase64String`, `Invoke-WebRequest`, `DownloadFile`, `DownloadString`, `IEX`, and `-EncodedCommand`, the strongest negative late-stage effects repeatedly land in the `11-13` attention band and the `6/10/13` MLP band.
- A targeted full-model head search inside layers `11-13` did identify recurrent late heads, but they are materially weaker than the early Layer 0 detector heads. The clearest late-head ablations are `L12H5` (`mean Δ = -0.306`) and `L13H0` (`mean Δ = -0.240`), with the remaining discovered heads weaker or sign-mixed.
- Targeted neuron discovery and direct neuron ablation inside MLP layers `6`, `10`, and `13` did **not** reveal any single-neuron analogue of the strong layer-level effects. The top recurrent candidate neurons produced only small mean shifts (roughly `-0.026` to `+0.148`) and zero flips across the 18-pair cohort.
- Grouped ablation of the top discovered neurons in layers `6`, `10`, and `13` also failed to recover the strong negative layer-level MLP effects. The tested 3-neuron and 5-neuron groups produced small-to-moderate **positive** mean deltas instead of large negative ones, again with zero flips. That suggests the discovered neurons are not a compact malicious-evidence bundle; if anything, some may weakly suppress the final `BLOCK` preference.
- Practical interpretation: the current best end-to-end circuit hypothesis is now a two-stage story. `Layer 0` heads detect suspicious indicators early, and a later decision stage centered on `attention layers 11-13` plus `MLP layers 6/10/13` converts that evidence into the final `BLOCK` preference.
- With the new full-model patching results, the current best later-stage claim is sharper than before: `attention layers 12-13` look like the strongest transportable decision-state carriers, while `MLP layers 6 and 10` look important but more distributed.
- The new path test strengthens the same point. The most decisive patchable state is not the early head pair by itself, but the late attention state around layers `12-13` and the residual entering that band.
- The latest probing suggests that this later decision stage is at least partly **distributed**: some specific late heads matter, but the strongest MLP effects appear to come from layer-level or subnetwork-level computation rather than a single dominant neuron.
- The grouped-neuron result sharpens that interpretation: even small recurrent neuron sets do not reproduce the layer-level MLP importance, so the late MLP stage is likely implemented by a broader or differently structured subspace than simple top-k neuron bundles.

**Artifacts:**
- artifacts/circuit_val_layer_ablation_full_h100_summary.csv
- artifacts/circuit_val_layer_ablation_full_h100_family_summary.csv
- artifacts/circuit_val_layer_ablation_full_h100_metadata.json

---

## 3. Causal Validation

### 3.1 Activation Patching

| Head | Δ Logit Recovery | Flip Rate |
|------|-----------------|----------|
| `L0H23` | `-0.0945` | `0.8889` |
| `L0H8`  | `-0.0299` | `0.7778` |
| `L0H11` | `+0.0930` | `0.7778` |
| `L0H9`  | `+0.0480` | `0.7222` |

**Current interpretation:**
- Local H100 reproduction on the full 18-pair overlap-controlled cohort matches the earlier imported batch summary almost exactly.
- Patching remains directionally unstable in this matched-indicator setting. `L0H23` is the strongest negative patch head, but `L0H11` and `L0H9` move positive on average.
- This does **not** look like a clean “remove malicious evidence” intervention, because the benign source prompts often still contain the same suspicious strings.
- A new 8-layer H100 follow-up also ran successfully, but it did not fix the interpretability problem: all 18 malicious examples were already benign-leaning in the truncated 8-layer model (`positive_base_frac = 0.0`), so those deeper truncated patch effects are not valid evidence for the full circuit.
- Conclusion: patching is useful as a consistency check, but it is **not** the main evidence for the portable causal core on the overlap-controlled dataset.

---

### 3.2 Head Ablation

| Head | Δ Logit Drop | Accuracy Drop |
|------|-------------|--------------|
| `L0H11` | `-0.3006` | `flip_rate = 0.9444` |
| `L0H9`  | `-0.2826` | `flip_rate = 0.9444` |
| `L0H23` | `+0.2578` | `flip_rate = 0.6667` |
| `L0H8`  | `+0.1104` | `flip_rate = 0.6111` |

**Current interpretation:**
- This is the strongest current causal result in the repo.
- On the local H100 reproduction of the full 18-pair overlap-controlled cohort, `L0H11` and `L0H9` remain the only heads with strong, stable negative ablation effects.
- Family-level summaries preserve the same pattern across all seven represented indicator families: `H11` and `H9` are the most negative heads, while `H23` is positive in every family and `H8` is positive in six of seven.
- The refined causal claim is therefore stronger than the original four-head story: the portable early detection core is concentrated in `L0H11` and `L0H9`, while `L0H23` and `L0H8` appear recurrent but not uniformly causal in the same direction.
- The new 8-layer H100 ablation follow-up likewise does not support a deeper truncated validation story. Although `H11` remains the most negative head there, every malicious example already has a negative base logit before intervention, so the 8-layer truncated model is still misaligned with the full-model task.

---

## 4. Generalization

- The overlap-controlled tractable cohort contains 18 fully correct benign/malicious pairs spanning seven indicator families: `Invoke-Expression`, `FromBase64String`, `Invoke-WebRequest`, `DownloadFile`, `DownloadString`, `IEX`, and `-EncodedCommand`.
- The local H100 baseline reproduced 36/36 correct predictions on this cohort, improving on the older imported baseline artifact that had one error before filtering.
- A larger interim generalization cohort is now available at the same `<=3000`-char cap: 96 valid benign/malicious pairs after baseline filtering, spanning the same seven indicator families.
- That larger cohort is built from within-family natural-overlap pair expansions capped at 20 pairs per family. It materially increases coverage, but it is not a clean independent holdout because source scripts are reused across multiple pairings.
- Family composition in the expanded valid cohort is still uneven. The valid pair counts are `DownloadFile=20`, `FromBase64String=20`, `Invoke-Expression=20`, `Invoke-WebRequest=18`, `DownloadString=10`, `IEX=6`, and `-EncodedCommand=2`.
- Unique-script coverage in the expanded valid cohort is 78 scripts total: 29 benign and 49 malicious. Some families still have very few benign source scripts, so the larger pair count should be interpreted as stronger matched-control coverage rather than full-distribution generalization.
- Family-level baseline summaries show all seven families remain separable under the full model, with malicious mean logit differences positive and benign mean logit differences negative.
- The early Layer 0 detector therefore generalizes beyond a single keyword family or a tiny hand-picked short-pair set.
- The expanded interim cohort strengthens that claim, but it does not fully close the generalization gap. A stronger final validation set still needs more genuinely distinct benign scripts, held-out families or templates, and a separate evasion/obfuscation split.
- The new full-model layer ablation sweep adds a plausible later decision-stage candidate that also generalizes across the 18-pair cohort, so the repo is no longer limited to an early-detector-only story.
- What remains incomplete is finer-grained validation inside those later layers. We now have full-model layer-component localization and an initial late-head scan, but not yet a convincing head-level or path-level causal decomposition of the decision-stage band.
- The new full-model patching sweep strengthens that same later-stage story in the opposite direction: replacing malicious late-layer states with benign ones in attention layers `12-13` sharply suppresses the `BLOCK` preference across the cohort.
- The new 8-layer H100 batch causal run makes that limit explicit rather than speculative: despite running cleanly on GPU, all 18 malicious prompts remained benign-leaning in the truncated 8-layer model (`mean_base_logit_diff = -1.468`), so the deeper reduced model still cannot be treated as a faithful proxy for full-model malicious classification.
- The new neuron probing also sharpens that conclusion: the late-stage MLP signal is real at the layer level, but it does not collapse to a few individually decisive neurons under the current probe. The next likely step is structured or grouped ablation inside those layers rather than single-neuron screening alone.
- A first grouped-ablation pass also came back negative: the tested top-3 and top-5 neuron groups in layers `6`, `10`, and `13` did not behave like a compact causal circuit. The next likely step is subspace-level patching/ablation or activation clustering inside those MLPs rather than just ranking neurons by individual contribution.
- The first explicit early-to-late path patching pass also shows that the path is not yet fully decomposed. We can move the decision by patching the late attention band and its incoming residual state, but the early-head patch alone is comparatively weak and the combined patch is not additive.
- A direct follow-up using stage-conditioned residual-subspace patching did not simplify that story. At both `resid_pre12` and `resid_pre13`, low-rank PCA-like subspaces captured most variance but almost none of the whole-state causal effect, so the missing path is unlikely to be a small variance-dominant linear transport channel.
- A more task-aligned follow-up did recover a nontrivial one-direction signal. The cohort mean malicious-vs-benign residual direction at `resid_pre13` moves the decision noticeably (`mean Δ = -1.323`, `flip_rate = 0.222`), while the direct `BLOCK-ALLOW` readout direction remains negligible. This suggests the late path is not pure output-readout copying, but it is also not fully distributed noise.
- A direct head trace along that same residual direction now localizes the strongest late writer set to `Layer 12`, especially `H15`, `H5`, `H4`, `H2`, and `H28`. This is the clearest current bridge between the broad late attention band and the narrower `resid_pre13` transport direction.
- A direct grouped-causal follow-up strengthens that bridge. The traced `Layer 12` top-five writer set reproduces a large fraction of the late decision effect under both patching and ablation, while the top-two subset does not. A later 96-pair follow-up refines the presentation rather than overturning it: the stronger sufficiency-oriented late carrier is `L12H15/L12H5/L12H4/L12H28`, while `H2` acts more like a family-sensitive auxiliary contributor that matters most in grouped ablation.
- A direct early-to-late intervention probe also closes part of the remaining gap: `L0H11/L0H9` measurably move the `resid_pre13` mean-delta direction in the expected direction, which supports a real causal link from the early detector into the late writer stage. But the combined intervention remains non-additive, so the end-to-end path is still only partially decomposed.
- The new intervention-conditioned trace sharpens that recommendation. The next likely step is to test a second late candidate subset centered on the heads most modulated by `L0H11/L0H9` (`L12H9`, `L12H8`, `L12H6`, with support from `L12H12/H20/H10`) and compare it directly against the top-five writer bundle.
- That comparison is now done. The early-sensitive subset is anti-causal, while the traced top-five writer bundle remains the strongest late malicious-evidence carrier. The new single-head routing split also suggests `L0H11` and `L0H9` should not be treated as interchangeable upstream components.
- The strongest paired-route comparison is now done. `L0H11 -> L12H15/H5/H4` is a plausible direct early-to-late malicious path; `L0H9 -> L12H9/H6/H10` is not.
- That `L0H11` branch comparison is now done too. The practical writeup choice is no longer about uncertainty in the results, but about presentation:
- Use `L0H11 -> L12H15/H5/H4` if the goal is the cleanest minimal direct path.
- Use `L12H15/H5/H4/H28` as the cleanest sufficiency-oriented late carrier in the main writeup.
- Mention separately that adding `H2` improves grouped ablation on the larger cohort, especially for `DownloadFile`, `DownloadString`, `Invoke-WebRequest`, and `-EncodedCommand`.
- The next likely step is therefore to consolidate the writeup around that distinction rather than continuing to treat `H2` and `H28` symmetrically.

---

## 5. Evasion Analysis

| Technique | Cohort | Main Outcome | Mechanistic Read |
|----------|--------|--------------|------------------|
| `downloadstring_psobject_invoke` | `6` reviewed seed/variant pairs | `2/6` misses | Late bundle stays sufficient under patching but loses necessity under ablation on the misses |
| `invoke_webrequest_alias` | `4` reviewed seed/variant pairs | `4/4` misses | Strongest current failure mode; usual late carrier survives early in the late stage but downstream dependence is redistributed |

**Status:** now replaced by a completed artifact-backed runnable evasion benchmark.

The codebase still contains the older conservative `generate_obfuscations` helper and `augment-pair-manifest` command for formatting-preserving rewrites, but that is no longer the main robustness result. The meaningful benchmark is now the runnable variant-manifest pipeline in `scaled_validation.py`, which generates conservative syntax-preserving obfuscations, reviews them with syntax and invariant checks, evaluates them on the full model, and then follows the strongest misses with paired circuit probes. Current benchmark evidence shows two concrete failure modes:

- `downloadstring_psobject_invoke`, which produces a narrow `FromBase64String`-linked miss pattern
- `invoke_webrequest_alias`, which produces a cleaner `4/4` miss pattern on the reviewed `Invoke-WebRequest` slice

The mechanistic conclusion is now sharper than it was in earlier resume notes. Both failure modes show a necessity/sufficiency split: the validated route can still be reintroduced by patching, but the model no longer relies on that route in the same way under obfuscation. The strongest read comes from `invoke_webrequest_alias`. On that slice, the late `Layer 12` writer family is still present on the evaded variants, and ablating `L12H15/L12H5/L12H4/L12H28` still reduces the slice-specific `resid_pre13` malicious-evidence direction. But by `resid_pre31`, the sign split is already present in the late residual stream itself: the same ablation is supportive on seeds and anti-causal on the evaded variants. So the best current characterization is that obfuscation preserves the usual early late-stage malicious-evidence write while redistributing, in later blocks, how the final decision depends on it.

So the repo now does contain a completed artifact-backed evasion evaluation with a mechanistically specific claim. The remaining gap is breadth and generalization, not the absence of any evasion benchmark.

---

## 6. Security Implications

- The model’s early malicious-code detector is interpretable enough to localize to a small Layer 0 head family, which is useful for auditing and targeted monitoring.
- The strongest portable reduced-layer causal heads on the overlap-controlled cohort are `L0H11` and `L0H9`. Those heads are better candidates for future intervention or monitoring than the broader four-head set.
- The broader four-head recurrence pattern (`H9`, `H11`, `H23`, `H8`) should not be overclaimed as a uniformly causal circuit. `H23` and `H8` recur in attention, but under ablation they often behave in the opposite direction from `H11/H9`.
- The later decision stage is now partially localized too: full-model ablation points to an attention band around layers `11-13` and an MLP band around `6/10/13`, with layer `13` especially prominent. That is enough to guide follow-up inspection, but not enough yet to claim a fully decomposed decision circuit.
- The newest evidence favors a particularly important late attention sub-band at `12-13`: those are the only late layers where benign patching flips a majority of malicious examples.
- Within that late-stage band, the cleanest currently supported late sufficiency carrier is the `Layer 12` bundle `L12H15/L12H5/L12H4/L12H28`, while `L12H2` appears to play a narrower family-sensitive auxiliary role that shows up more clearly under grouped ablation than under path patching.
- Within that late-stage band, the strongest currently validated heads are `L12H5` and `L13H0`, but their effects are still much smaller than the broad layer ablations. On the MLP side, no single neuron yet explains the layer-level signal, which suggests redundancy or distributed computation.
- The new residual-subspace sweeps sharpen that same interpretation: even when we capture roughly `87-89%` of benign/malicious residual variance at `resid_pre12` and `resid_pre13`, low-rank subspace patching barely moves the decision. The late carrier is therefore not a compact PCA-like residual channel.
- The new contrastive residual sweeps sharpen the picture further: there is a meaningful single transport direction at `resid_pre13`, but it aligns with the cohort mean malicious-vs-benign displacement rather than with the direct output readout vector. The late carrier is therefore structured, but not trivially equivalent to the final logit axis.
- The evasion benchmark now gives two concrete robustness failure modes. `downloadstring_psobject_invoke` produces a narrower miss pattern, while `invoke_webrequest_alias` gives a stronger reviewed failure on the current slice. Across both, the circuit probes point to the same high-level explanation: obfuscation changes how the late decision stage is used rather than simply turning off a compact early detector.
- The final `invoke_webrequest_alias` follow-up makes that robustness claim mechanistically precise. The usual `Layer 12` late writer family still writes the familiar malicious-evidence direction at `resid_pre13` on the evaded variants, but by `resid_pre31` the model has already transformed the downstream dependence on that evidence enough that ablating the same late bundle becomes anti-causal in the late residual stream itself. In practical terms, the model may still contain the relevant malicious evidence internally, but later blocks can repurpose or compensate for that evidence under obfuscation before the final readout.
- The complete safety story remains incomplete. We still do not know which specific late-layer subnetworks implement the decision-stage computation, how redundant those paths are, or how broadly the observed evasion mechanism generalizes beyond the currently tested `DownloadString` and `Invoke-WebRequest` benchmark slices.

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
| artifacts/circuit_val_pair_baseline_eval_t3000_h100.csv | Local H100 full-model baseline on the 18-pair overlap-controlled cohort |
| artifacts/circuit_val_pair_manifest_t3000_valid_causal18_short_h100.csv | Local H100-refreshed valid-pair manifest for the 18-pair causal cohort |
| artifacts/circuit_val_set_t3000.csv | Length-filtered `<=3000` natural-overlap source pool used for expanded pair generation |
| artifacts/circuit_val_pair_manifest_t3000_combo_cap20.csv | Expanded within-family length-matched pair manifest capped at 20 pairs per family |
| artifacts/circuit_val_pair_manifest_t3000_combo_cap20_baseline_h100.csv | Local H100 baseline on the expanded 100-pair candidate cohort |
| artifacts/circuit_val_pair_manifest_t3000_combo_cap20_valid_h100.csv | Expanded 96-pair valid cohort after baseline pair filtering |
| artifacts/circuit_val_pair_manifest_t3000_valid_causal18_short_h100_augmented.csv | Conservative formatting-variant augmentation attempt for the original 18-pair cohort |
| artifacts/circuit_val_pair_manifest_t3000_valid_causal18_short_h100_augmented_metadata.json | Metadata for the conservative pair-preserving formatting augmentation run |
| artifacts/circuit_val_batch_attention_l4_n18_h100_summary.csv | Local H100 4-layer recurrence summary on the 18-pair overlap-controlled cohort |
| artifacts/circuit_val_batch_attention_l4_n18_h100_metadata.json | Metadata for the local H100 18-pair attention recurrence run |
| artifacts/circuit_val_batch_causal_root_l4_n18short_h100_patch_summary.csv | Local H100 root-head patch summary on the full 18-pair overlap-controlled cohort |
| artifacts/circuit_val_batch_causal_root_l4_n18short_h100_ablation_summary.csv | Local H100 root-head ablation summary on the full 18-pair overlap-controlled cohort |
| artifacts/circuit_val_batch_causal_root_l4_n18short_h100_metadata.json | Metadata for the local H100 4-layer batch causal run |
| artifacts/circuit_val_family_root_heads_n18short_h100_baseline_summary.csv | Local H100 family-level baseline summary for the full 18-pair causal cohort |
| artifacts/circuit_val_family_root_heads_n18short_h100_patch_summary.csv | Local H100 family-level patch summary for the full 18-pair causal cohort |
| artifacts/circuit_val_family_root_heads_n18short_h100_ablation_summary.csv | Local H100 family-level ablation summary for the full 18-pair causal cohort |
| artifacts/circuit_val_family_root_heads_n18short_h100_metadata.json | Metadata for the local H100 family-level summaries |
| artifacts/circuit_val_batch_causal_root_l8_n18short_h100_patch_summary.csv | Local H100 8-layer root-head patch summary on the 18-pair overlap-controlled cohort |
| artifacts/circuit_val_batch_causal_root_l8_n18short_h100_ablation_summary.csv | Local H100 8-layer root-head ablation summary on the 18-pair overlap-controlled cohort |
| artifacts/circuit_val_batch_causal_root_l8_n18short_h100_metadata.json | Metadata for the local H100 8-layer batch causal follow-up |
| artifacts/circuit_val_layer_ablation_smoke_h100_summary.csv | One-pair H100 full-model layer-component ablation smoketest |
| artifacts/circuit_val_layer_ablation_smoke_h100_metadata.json | Metadata for the one-pair full-model layer ablation smoketest |
| artifacts/circuit_val_layer_ablation_full_h100_summary.csv | Full 18-pair H100 full-model layer-component ablation summary |
| artifacts/circuit_val_layer_ablation_full_h100_per_pair.csv | Per-pair outputs for the full 18-pair H100 layer-component ablation sweep |
| artifacts/circuit_val_layer_ablation_full_h100_family_summary.csv | Family-level summary for the full 18-pair H100 layer-component ablation sweep |
| artifacts/circuit_val_layer_ablation_full_h100_metadata.json | Metadata for the full 18-pair H100 layer-component ablation sweep |
| artifacts/circuit_val_layer_patching_attn_l11_l13_n18_h100_summary.csv | Full-model benign-to-malicious patching summary for attention layers 11-13 |
| artifacts/circuit_val_layer_patching_attn_l11_l13_n18_h100_metadata.json | Metadata for the late-attention patching sweep |
| artifacts/circuit_val_layer_patching_mlp_l6_l10_l13_n18_h100_summary.csv | Full-model benign-to-malicious patching summary for MLP layers 6, 10, and 13 |
| artifacts/circuit_val_layer_patching_mlp_l6_l10_l13_n18_h100_metadata.json | Metadata for the late-MLP patching sweep |
| artifacts/circuit_val_path_patching_early_to_late_n18_h100_summary.csv | Path-patching comparison for early heads, late attention, and residual entry to the late band |
| artifacts/circuit_val_path_patching_early_to_late_n18_h100_metadata.json | Metadata for the early-to-late path patching sweep |
| artifacts/circuit_val_resid_pre12_subspace_n18_h100_metadata.json | Metadata for the `resid_pre12` low-rank residual-subspace discovery run |
| artifacts/circuit_val_resid_pre12_subspace_patch_n18_h100_summary.csv | Low-rank subspace patching summary for `resid_pre12` across ranks 1, 2, 4, and 8 |
| artifacts/circuit_val_resid_pre13_subspace_n18_h100_metadata.json | Metadata for the `resid_pre13` low-rank residual-subspace discovery run |
| artifacts/circuit_val_resid_pre13_subspace_patch_n18_h100_summary.csv | Low-rank subspace patching summary for `resid_pre13` across ranks 1, 2, 4, and 8 |
| artifacts/circuit_val_resid_pre12_contrastive_n18_h100_metadata.json | Metadata for the task-aligned contrastive residual-direction discovery run at `resid_pre12` |
| artifacts/circuit_val_resid_pre12_contrastive_patch_n18_h100_summary.csv | Contrastive residual-direction patching summary for `resid_pre12` |
| artifacts/circuit_val_resid_pre13_contrastive_n18_h100_metadata.json | Metadata for the task-aligned contrastive residual-direction discovery run at `resid_pre13` |
| artifacts/circuit_val_resid_pre13_contrastive_patch_n18_h100_summary.csv | Contrastive residual-direction patching summary for `resid_pre13` |
| artifacts/circuit_val_trace_resid_pre13_mean_delta_l12_l13_n18_h100_summary.csv | Head-level projection summary for late attention writes into the discovered `resid_pre13` mean-delta direction |
| artifacts/circuit_val_trace_resid_pre13_mean_delta_l12_l13_n18_h100_metadata.json | Metadata for the late-head directional tracing sweep |
| artifacts/circuit_val_path_patching_l12_writer_top5_n18_h100_summary.csv | Grouped patching summary for the top-five traced `Layer 12` writers into the `resid_pre13` mean-delta direction |
| artifacts/circuit_val_head_group_ablation_l12_writer_top5_n18_h100_summary.csv | Grouped ablation summary for the top-five traced `Layer 12` writers |
| artifacts/circuit_val_path_patching_l12_writer_top2_n18_h100_summary.csv | Grouped patching summary for the top-two traced `Layer 12` writers |
| artifacts/circuit_val_head_group_ablation_l12_writer_top2_n18_h100_summary.csv | Grouped ablation summary for the top-two traced `Layer 12` writers |
| artifacts/circuit_val_resid_pre13_mean_delta_early_patch_n18_h100_summary.csv | Effect of benign patching `L0H11/L0H9` on the discovered `resid_pre13` mean-delta direction and final logit |
| artifacts/circuit_val_resid_pre13_mean_delta_early_ablate_n18_h100_summary.csv | Effect of ablating `L0H11/L0H9` on the discovered `resid_pre13` mean-delta direction and final logit |
| artifacts/circuit_val_path_patching_early_plus_l12_writer_top5_n18_h100_summary.csv | Combined grouped patching summary for the early detector pair plus the top-five traced `Layer 12` writers |
| artifacts/circuit_val_head_group_ablation_early_plus_l12_writer_top5_n18_h100_summary.csv | Combined grouped ablation summary for the early detector pair plus the top-five traced `Layer 12` writers |
| artifacts/circuit_val_trace_resid_pre13_mean_delta_l12_under_early_patch_n18_h100_summary.csv | Layer 12 head-write changes along the discovered `resid_pre13` mean-delta direction under `L0H11/L0H9` patching |
| artifacts/circuit_val_trace_resid_pre13_mean_delta_l12_under_early_ablate_n18_h100_summary.csv | Layer 12 head-write changes along the discovered `resid_pre13` mean-delta direction under `L0H11/L0H9` ablation |
| artifacts/circuit_val_path_patching_l12_early_sensitive_n18_h100_summary.csv | Grouped patching summary for the early-sensitive `Layer 12` late-head subset |
| artifacts/circuit_val_head_group_ablation_l12_early_sensitive_n18_h100_summary.csv | Grouped ablation summary for the early-sensitive `Layer 12` late-head subset |
| artifacts/circuit_val_path_patching_l12_writer_minus_h15_n18_h100_summary.csv | Leave-one-out grouped patching summary for the late writer bundle without `L12H15` |
| artifacts/circuit_val_head_group_ablation_l12_writer_minus_h15_n18_h100_summary.csv | Leave-one-out grouped ablation summary for the late writer bundle without `L12H15` |
| artifacts/circuit_val_path_patching_l12_writer_minus_h5_n18_h100_summary.csv | Leave-one-out grouped patching summary for the late writer bundle without `L12H5` |
| artifacts/circuit_val_head_group_ablation_l12_writer_minus_h5_n18_h100_summary.csv | Leave-one-out grouped ablation summary for the late writer bundle without `L12H5` |
| artifacts/circuit_val_path_patching_l12_writer_minus_h2_n18_h100_summary.csv | Leave-one-out grouped patching summary for the late writer bundle without `L12H2` |
| artifacts/circuit_val_head_group_ablation_l12_writer_minus_h2_n18_h100_summary.csv | Leave-one-out grouped ablation summary for the late writer bundle without `L12H2` |
| artifacts/circuit_val_path_patching_l12_writer_minus_h28_n18_h100_summary.csv | Leave-one-out grouped patching summary for the late writer bundle without `L12H28` |
| artifacts/circuit_val_head_group_ablation_l12_writer_minus_h28_n18_h100_summary.csv | Leave-one-out grouped ablation summary for the late writer bundle without `L12H28` |
| artifacts/circuit_val_path_patching_l12_writer_top3_n18_h100_summary.csv | Grouped patching summary for the compact top-three `Layer 12` writer core |
| artifacts/circuit_val_head_group_ablation_l12_writer_top3_n18_h100_summary.csv | Grouped ablation summary for the compact top-three `Layer 12` writer core |
| artifacts/circuit_val_trace_resid_pre13_mean_delta_l12_under_h011_patch_n18_h100_summary.csv | Layer 12 head-write changes along the discovered `resid_pre13` mean-delta direction under `L0H11` patching alone |
| artifacts/circuit_val_trace_resid_pre13_mean_delta_l12_under_h09_patch_n18_h100_summary.csv | Layer 12 head-write changes along the discovered `resid_pre13` mean-delta direction under `L0H9` patching alone |
| artifacts/circuit_val_path_patching_l12_h011_route_n18_h100_summary.csv | Grouped patching summary for the `L0H11`-aligned late route `L12H15/L12H5/L12H4` |
| artifacts/circuit_val_head_group_ablation_l12_h011_route_n18_h100_summary.csv | Grouped ablation summary for the `L0H11`-aligned late route |
| artifacts/circuit_val_path_patching_l12_h09_route_n18_h100_summary.csv | Grouped patching summary for the `L0H9`-aligned late route `L12H9/L12H6/L12H10` |
| artifacts/circuit_val_head_group_ablation_l12_h09_route_n18_h100_summary.csv | Grouped ablation summary for the `L0H9`-aligned late route |
| artifacts/circuit_val_path_patching_h011_plus_l12_top3_n18_h100_summary.csv | Combined grouped patching summary for `L0H11` plus the compact top-three late route |
| artifacts/circuit_val_head_group_ablation_h011_plus_l12_top3_n18_h100_summary.csv | Combined grouped ablation summary for `L0H11` plus the compact top-three late route |
| artifacts/circuit_val_path_patching_h011_plus_l12_top5_n18_h100_summary.csv | Combined grouped patching summary for `L0H11` plus the fuller top-five late carrier |
| artifacts/circuit_val_head_group_ablation_h011_plus_l12_top5_n18_h100_summary.csv | Combined grouped ablation summary for `L0H11` plus the fuller top-five late carrier |
| artifacts/circuit_val_path_patching_h011_plus_l12_top3_combo96_h100_summary.csv | 96-pair grouped patching summary for the clean direct branch `L0H11 + L12H15/L12H5/L12H4` |
| artifacts/circuit_val_path_patching_l12_writer_top5_combo96_h100_summary.csv | 96-pair grouped patching summary for the fuller late writer bundle `L12H15/L12H5/L12H4/L12H2/L12H28` |
| artifacts/circuit_val_head_group_ablation_l12_h011_route_combo96_h100_summary.csv | 96-pair grouped ablation summary for the `L0H11`-aligned late route `L12H15/L12H5/L12H4` |
| artifacts/circuit_val_head_group_ablation_l12_writer_top5_combo96_h100_summary.csv | 96-pair grouped ablation summary for the fuller late writer bundle |
| artifacts/circuit_val_path_patching_l12_writer_minus_h2_combo96_h100_summary.csv | 96-pair grouped patching summary for the late writer bundle without `L12H2` |
| artifacts/circuit_val_path_patching_l12_writer_minus_h28_combo96_h100_summary.csv | 96-pair grouped patching summary for the late writer bundle without `L12H28` |
| artifacts/circuit_val_head_group_ablation_l12_writer_h28_combo96_h100_summary.csv | 96-pair grouped ablation summary for the cleaner sufficiency-oriented late carrier `L12H15/L12H5/L12H4/L12H28` |
| artifacts/circuit_val_batch_attention_l11_l13_n18_h100_summary.csv | Targeted full-model head discovery summary restricted to layers 11-13 |
| artifacts/circuit_val_batch_attention_l11_l13_n18_h100_metadata.json | Metadata for the targeted 11-13 full-model head discovery run |
| artifacts/circuit_val_batch_causal_l11_l13_heads_n18_h100_patch_summary.csv | Full-model patch summary for the targeted late heads in layers 11-13 |
| artifacts/circuit_val_batch_causal_l11_l13_heads_n18_h100_ablation_summary.csv | Full-model ablation summary for the targeted late heads in layers 11-13 |
| artifacts/circuit_val_batch_causal_l11_l13_heads_n18_h100_metadata.json | Metadata for the targeted late-head causal validation run |
| artifacts/circuit_val_batch_neuron_discovery_l6_l10_l13_n18_h100_summary.csv | Targeted neuron discovery summary for MLP layers 6, 10, and 13 |
| artifacts/circuit_val_batch_neuron_discovery_l6_l10_l13_n18_h100_metadata.json | Metadata for the targeted neuron discovery run |
| artifacts/circuit_val_batch_neuron_ablation_l6_l10_l13_n18_h100_summary.csv | Direct neuron ablation summary for selected neurons in MLP layers 6, 10, and 13 |
| artifacts/circuit_val_batch_neuron_ablation_l6_l10_l13_n18_h100_metadata.json | Metadata for the targeted neuron ablation run |
| artifacts/circuit_val_batch_neuron_group_ablation_l6_l10_l13_n18_h100_summary.csv | Grouped ablation summary for top discovered neuron sets in MLP layers 6, 10, and 13 |
| artifacts/circuit_val_batch_neuron_group_ablation_l6_l10_l13_n18_h100_metadata.json | Metadata for the grouped neuron ablation run |
| artifacts/valid_l8_causal_n3_mps_patch_summary.csv | 8-layer patch summary on a 3-pair validated subset |
| artifacts/valid_l8_causal_n3_mps_ablation_summary.csv | 8-layer ablation summary on a 3-pair validated subset |
| artifacts/valid_l8_causal_n3_mps_metadata.json | Provenance metadata for the 8-layer 3-pair causal follow-up |
| artifacts/evasion_seed_manifest.csv | Seed manifest for the first runnable PowerShell evasion benchmark |
| artifacts/evasion_variant_manifest.csv | Generated evasion variants before review |
| artifacts/evasion_variant_review.csv | Syntax and invariant review results for generated variants |
| artifacts/evasion_variant_manifest_reviewed.csv | Reviewed variant manifest with viability fields |
| artifacts/evasion_variant_manifest_candidate.csv | Candidate variant subset that passed the Linux-side syntax and invariant screen |
| artifacts/evasion_eval_candidate_baseline.csv | Baseline model evaluation on the candidate evasion variants |
| artifacts/evasion_eval_candidate_merged.csv | Candidate evasion results merged with seed metadata and baseline deltas |
| artifacts/evasion_candidate_benchmark_summary.csv | Technique-level summary for the first candidate evasion benchmark run |
| artifacts/evasion_head_group_ablation_early_downloadstring_seed_h100_summary.csv | Early-head grouped ablation summary for the original `DownloadString` seed cohort used in evasion follow-up |
| artifacts/evasion_head_group_ablation_early_downloadstring_variant_h100_summary.csv | Early-head grouped ablation summary for the `downloadstring_psobject_invoke` variants |
| artifacts/evasion_head_group_ablation_late_downloadstring_seed_h100_summary.csv | Late-bundle grouped ablation summary for the original `DownloadString` seed cohort |
| artifacts/evasion_head_group_ablation_late_downloadstring_variant_h100_summary.csv | Late-bundle grouped ablation summary for the `downloadstring_psobject_invoke` variants |
| artifacts/evasion_head_group_ablation_late_top3_downloadstring_seed_h100_summary.csv | Top-three late-head grouped ablation summary for the original `DownloadString` seed cohort |
| artifacts/evasion_head_group_ablation_late_top3_downloadstring_variant_h100_summary.csv | Top-three late-head grouped ablation summary for the `downloadstring_psobject_invoke` variants |
| artifacts/evasion_path_patching_minimal_downloadstring_seed_h100_summary.csv | Minimal direct-route path patching summary for the original `DownloadString` seed cohort |
| artifacts/evasion_path_patching_minimal_downloadstring_variant_h100_summary.csv | Minimal direct-route path patching summary for the `downloadstring_psobject_invoke` variants |
| artifacts/evasion_path_patching_late_downloadstring_seed_h100_summary.csv | Full late-carrier path patching summary for the original `DownloadString` seed cohort |
| artifacts/evasion_path_patching_late_downloadstring_variant_h100_summary.csv | Full late-carrier path patching summary for the `downloadstring_psobject_invoke` variants |
| artifacts/evasion_path_patching_late_top3_downloadstring_seed_h100_summary.csv | Top-three late-head path patching summary for the original `DownloadString` seed cohort |
| artifacts/evasion_path_patching_late_top3_downloadstring_variant_h100_summary.csv | Top-three late-head path patching summary for the `downloadstring_psobject_invoke` variants |
| artifacts/evasion_seed_manifest_v2.csv | Expanded evasion seed manifest for the second runnable benchmark sweep |
| artifacts/evasion_variant_manifest_v2.csv | Expanded provisional evasion variants before review |
| artifacts/evasion_variant_review_v2.csv | Syntax and invariant review results for the expanded variant sweep |
| artifacts/evasion_variant_manifest_reviewed_v2.csv | Reviewed expanded variant manifest with viability fields |
| artifacts/evasion_variant_manifest_candidate_v2.csv | Expanded candidate subset that passed the Linux-side syntax and invariant screen |
| artifacts/evasion_eval_candidate_baseline_v2.csv | Baseline model evaluation on the expanded candidate evasion set |
| artifacts/evasion_eval_candidate_merged_v2.csv | Expanded candidate evasion results merged with seed metadata and baseline deltas |
| artifacts/evasion_candidate_benchmark_summary_v2.csv | Technique-level summary for the expanded candidate evasion benchmark run |
| artifacts/evasion_head_group_ablation_early_invoke_webrequest_seed_v2_h100_summary.csv | Early-head grouped ablation summary for the original `Invoke-WebRequest` seed cohort used in evasion follow-up |
| artifacts/evasion_head_group_ablation_early_invoke_webrequest_variant_v2_h100_summary.csv | Early-head grouped ablation summary for the `invoke_webrequest_alias` variants |
| artifacts/evasion_head_group_ablation_late_invoke_webrequest_seed_v2_h100_summary.csv | Late-bundle grouped ablation summary for the original `Invoke-WebRequest` seed cohort |
| artifacts/evasion_head_group_ablation_late_invoke_webrequest_variant_v2_h100_summary.csv | Late-bundle grouped ablation summary for the `invoke_webrequest_alias` variants |
| artifacts/evasion_head_group_ablation_late_top3_invoke_webrequest_seed_v2_h100_summary.csv | Top-3 late-bundle grouped ablation summary for the original `Invoke-WebRequest` seed cohort |
| artifacts/evasion_head_group_ablation_late_top3_invoke_webrequest_variant_v2_h100_summary.csv | Top-3 late-bundle grouped ablation summary for the `invoke_webrequest_alias` variants |
| artifacts/evasion_path_patching_minimal_invoke_webrequest_seed_v2_h100_summary.csv | Minimal direct-route path patching summary for the original `Invoke-WebRequest` seed cohort |
| artifacts/evasion_path_patching_minimal_invoke_webrequest_variant_v2_h100_summary.csv | Minimal direct-route path patching summary for the `invoke_webrequest_alias` variants |
| artifacts/evasion_path_patching_late_invoke_webrequest_seed_v2_h100_summary.csv | Full late-carrier path patching summary for the original `Invoke-WebRequest` seed cohort |
| artifacts/evasion_path_patching_late_invoke_webrequest_variant_v2_h100_summary.csv | Full late-carrier path patching summary for the `invoke_webrequest_alias` variants |
| artifacts/evasion_path_patching_late_top3_invoke_webrequest_seed_v2_h100_summary.csv | Top-3 late-carrier path patching summary for the original `Invoke-WebRequest` seed cohort |
| artifacts/evasion_path_patching_late_top3_invoke_webrequest_variant_v2_h100_summary.csv | Top-3 late-carrier path patching summary for the `invoke_webrequest_alias` variants |
| artifacts/evasion_invoke_webrequest_seed_v2_resid_pre13_contrastive_h100_metadata.json | Slice-specific `resid_pre13` contrastive residual metadata for the original `Invoke-WebRequest` seed cohort |
| artifacts/evasion_invoke_webrequest_variant_v2_resid_pre13_contrastive_h100_metadata.json | Slice-specific `resid_pre13` contrastive residual metadata for the `invoke_webrequest_alias` variants |
| artifacts/evasion_trace_resid_pre13_mean_delta_l12_invoke_webrequest_seed_v2_h100_summary.csv | Layer-12 writer trace into the seed-slice `resid_pre13` mean-delta direction |
| artifacts/evasion_trace_resid_pre13_mean_delta_l12_invoke_webrequest_variant_v2_h100_summary.csv | Layer-12 writer trace into the variant-slice `resid_pre13` mean-delta direction |
| artifacts/evasion_resid_pre13_mean_delta_ablate_l12_top4_invoke_webrequest_seed_v2_h100_summary.csv | Effect of ablating `L12H15/L12H5/L12H4/L12H28` on the seed-slice `resid_pre13` mean-delta direction |
| artifacts/evasion_resid_pre13_mean_delta_ablate_l12_top4_invoke_webrequest_variant_v2_h100_summary.csv | Effect of ablating `L12H15/L12H5/L12H4/L12H28` on the variant-slice `resid_pre13` mean-delta direction |
| artifacts/evasion_invoke_webrequest_seed_v2_resid_pre31_contrastive_h100_metadata.json | Slice-specific `resid_pre31` contrastive residual metadata for the original `Invoke-WebRequest` seed cohort |
| artifacts/evasion_invoke_webrequest_variant_v2_resid_pre31_contrastive_h100_metadata.json | Slice-specific `resid_pre31` contrastive residual metadata for the `invoke_webrequest_alias` variants |
| artifacts/evasion_resid_pre31_mean_delta_ablate_l12_top4_invoke_webrequest_seed_v2_h100_summary.csv | Downstream effect of ablating `L12H15/L12H5/L12H4/L12H28` on the seed-slice `resid_pre31` mean-delta direction |
| artifacts/evasion_resid_pre31_mean_delta_ablate_l12_top4_invoke_webrequest_variant_v2_h100_summary.csv | Downstream effect of ablating `L12H15/L12H5/L12H4/L12H28` on the variant-slice `resid_pre31` mean-delta direction |
| artifacts/attention_heatmap.png | Attention heatmap |
| artifacts/patching_results.csv | Activation patching |
| artifacts/ablation_results.csv | Head ablation |
| artifacts/evasion_results.csv | Evasion results |
