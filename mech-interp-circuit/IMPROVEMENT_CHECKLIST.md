# Remaining Improvements We Can Still Do Now

This checklist covers improvements that are still feasible **without** changing the core 96-pair validation cohort.

It is intentionally scoped to items that improve the current study's strength, clarity, or coverage while preserving the current claim boundary.

## Priority Order

1. Clarify the causal claim hierarchy in the writeup
2. Improve family-level reporting for the validated routes
3. Expand evasion coverage to more indicator families
4. Refine late-stage decomposition inside the already localized band
5. Upgrade figures and paper-ready presentation

## Checklist

### 1. Writeup Clarity

- [x] Separate discovery-stage evidence from final 96-pair validation evidence
- [x] State the main validated claim around:
  - minimal direct branch `L0H11 -> L12H15/L12H5/L12H4`
  - stronger sufficiency-oriented late carrier `L12H15/L12H5/L12H4/L12H28`
  - auxiliary helper interpretation for `L12H2`
- [x] Clarify that the strongest current evasion result is `invoke_webrequest_alias`, not `downloadstring_psobject_invoke`
- [x] Add junior-reader guidance explaining `mean Δ`, `flip_rate`, patching, ablation, and the `resid_pre13`/`resid_pre31` distinction
- [x] Add one compact “claim ladder” figure/table to the paper draft

### 2. Family-Level Reporting

- [x] Add a compact per-family summary table for the 96-pair cohort
- [x] Report per-family behavior for:
  - minimal direct branch
  - top-five late bundle
  - `H2`-free late carrier
  - `H28`-free late carrier
- [x] Summarize which families benefit most from including `H2` under grouped ablation
- [x] Make clear where family imbalance limits interpretation

### 3. Evasion Breadth

- [x] Extend the runnable evasion benchmark beyond the current `DownloadString` and `Invoke-WebRequest` slices
- [~] Add benchmark slices for:
  - `DownloadFile`
  - `IEX`
  - `-EncodedCommand`
- [~] Keep the same review standard:
  - syntax-preserving
  - invariant-checked
  - paired seed/variant evaluation
- `DownloadFile` and `-EncodedCommand` now meet the strict candidate benchmark standard; pure `IEX` variants now have a separate provisional candidate tier with `0/4` misses, but they are not yet parse-validated in this environment.
- [ ] Follow up the strongest new misses with the same late-carrier intervention logic used for `invoke_webrequest_alias`

### 4. Late-Stage Decomposition

- [ ] Run more targeted grouped interventions inside the already localized late attention band
- [ ] Expand slice-specific residual-direction probing where the late carrier appears to survive but downstream use changes
- [ ] Test whether additional small grouped routes inside layers `12-13` improve necessity or sufficiency without overcomplicating the story
- [ ] Keep the writeup distinction clear between:
  - broad late-stage localization
  - validated grouped late routes
  - still-unresolved fine-grained decomposition

### 5. Figures And Paper Presentation

- [x] Replace placeholder paper figures with real repo artifacts
- [x] Build one main circuit figure showing:
  - indicator tokens
  - `L0H11`
  - `L12H15/L12H5/L12H4`
  - `L12H28`
  - late malicious-evidence write at `resid_pre13`
- [x] Build one comparison figure showing:
  - minimal direct branch
  - top-five late bundle
  - `H2`-free carrier
  - `H28`-free carrier
- [x] Build one evasion figure showing:
  - seed vs variant
  - `resid_pre13` preservation
  - `resid_pre31` redistribution

## Suggested Execution Order

If the goal is strongest improvement per unit effort:

1. Finish paper/writeup clarity and add the claim-ladder summary artifact
2. Add family-level reporting from existing artifacts
3. Upgrade figures using current outputs
4. Expand evasion coverage
5. Only then do more late-stage decomposition work if the new evasion slices reveal a concrete gap

## Out Of Scope For This Checklist

- Building a stronger independent holdout with new scripts
- Reframing the study around a different main cohort
- Claiming a fully decomposed exact circuit graph
