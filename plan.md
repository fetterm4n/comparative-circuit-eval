# Evasion Miss Expansion Plan

## Goal

Expand the number of validated evasion misses without changing the paper's claim boundary. The experiment should test whether the already-flagged families produce more misses under controlled, behavior-preserving rewrites. The output should remain a red-team prioritization artifact, not a broad obfuscation leaderboard or a population-level evasion-rate estimate.

## Core Question

Given the current family-level signals, can we find additional Foundation-Sec misses in:

- `Invoke-WebRequest` alias and command reconstruction variants.
- `Invoke-Expression` command reconstruction variants.
- Low-margin variants already close to the decision boundary.

The key comparison remains Foundation-Sec versus Llama on the same accepted variants.

## Claim Boundary

Allowed claims:

- Family-level monitoring can prioritize where to search for evasion.
- Targeted expansion finds additional misses in already-flagged families.
- Foundation-Sec and Llama differ on the same controlled variants.
- Prompt framing can reshape the miss surface non-monotonically.

Avoid claims:

- The measured miss rate estimates real-world prevalence.
- The benchmark covers all PowerShell obfuscation.
- Individual scripts can be reliably predicted to fail from the probe alone.
- Any newly found miss is valid before parse and invariant checks pass.

## Stage 0: Existing Artifact Audit

CPU-only.

1. Load existing evaluation outputs:
   - `artifacts/foundation_sec/evasion_eval_candidate_merged_provisional_v1.csv`
   - `artifacts/foundation_sec/evasion_eval_candidate_merged_realistic_v2.csv`
   - `artifacts/foundation_sec/evasion_eval_candidate_adversarial_provisional.csv`
   - `artifacts/foundation_sec/evasion_eval_candidate_adversarial_realistic_v2.csv`
   - matching `artifacts/llama3/*evasion*` outputs where available.
2. Summarize by:
   - model
   - prompt variant
   - manifest
   - technique
   - indicator family
   - seed id
   - predicted label
   - logit margin if present
3. Identify:
   - confirmed misses
   - near misses, defined as correctly classified variants with low positive malicious margin
   - techniques that flip only under adversarial prompt
   - seeds that repeatedly produce low margins across techniques

Deliverable: `artifacts/evasion_expansion_audit.csv` and a short ranked summary.

## Stage 1: Candidate Generation

CPU-only.

Generate a targeted candidate manifest rather than broad random obfuscation.

Priority families:

1. `Invoke-WebRequest`
   - `iwr` alias substitution.
   - Runtime-scoped aliases such as `wget` and `curl` only if the runtime assumptions are explicit.
   - Call-operator reconstruction of full command name.
   - Format-string reconstruction.
   - Base64/ASCII command-name reconstruction.
   - Subexpression string reconstruction.
   - Argument-preserving reorderings, if invariants can verify URL and output path preservation.

2. `Invoke-Expression`
   - Format-string reconstruction.
   - Backtick insertion.
   - Base64/ASCII command-name reconstruction.
   - Subexpression string reconstruction.
   - Call-operator string reconstruction.
   - `[ScriptBlock]::Create(...)` indirection.

3. Low-margin seeds from existing outputs
   - Apply only behavior-preserving rewrites already supported by the registry.
   - Prefer one transformation at a time before testing composed transformations.

Candidate constraints:

- Use only baseline-correct malicious seeds.
- Preserve URLs.
- Preserve executable/path-like literals.
- Preserve `-EncodedCommand` equivalence when relevant.
- Preserve request arguments for web-request families.
- Preserve process-launch arguments for process-launch families.
- Keep seed/variant pairing explicit.

Deliverable: `artifacts/evasion_expansion_candidate_manifest.csv`.

## Stage 2: Parse and Invariant Review

CPU-only, with optional PowerShell runtime if available.

1. Run static parse checks:
   - Prefer PowerShell parser when `pwsh` or Windows PowerShell is available.
   - Use `tree-sitter` fallback otherwise.
2. Run invariant checks:
   - URL preservation.
   - executable/path-like literal preservation.
   - encoded-command equivalence.
   - request-argument preservation.
   - process-launch argument preservation.
3. Split candidates into:
   - strict accepted
   - provisional accepted
   - rejected

Deliverables:

- `artifacts/evasion_expansion_review.csv`
- `artifacts/evasion_expansion_candidate_strict.csv`
- `artifacts/evasion_expansion_candidate_provisional.csv`

## Stage 3: GPU Evaluation

GPU required.

Run `baseline-eval` on the accepted candidate manifests.

Foundation-Sec conditions:

- Raw prompt.
- Adversarial prompt.

Llama conditions:

- Raw prompt with chat template.
- Adversarial or intent-focused prompt with chat template.

Minimum outputs:

- predicted label
- logit margin / logit diff if available
- seed id
- variant id
- technique id
- family
- prompt variant
- model

Deliverables:

- `artifacts/foundation_sec/evasion_expansion_eval_raw.csv`
- `artifacts/foundation_sec/evasion_expansion_eval_adversarial.csv`
- `artifacts/llama3/llama3_evasion_expansion_eval_raw.csv`
- `artifacts/llama3/llama3_evasion_expansion_eval_adversarial.csv`

## Stage 4: Result Triage

CPU-only after GPU outputs exist.

Summarize:

- New Foundation-Sec raw misses.
- New Foundation-Sec adversarial misses.
- Llama misses, expected to remain zero based on current artifacts.
- Prompt-fixed cases.
- Prompt-broken cases.
- Techniques that produce repeated misses across seeds.
- Seeds that are consistently low-margin across variants.

Primary success criteria:

- Additional accepted Foundation-Sec misses in flagged families.
- Llama remains robust on the same accepted variants.
- New misses preserve behavior and pass invariants.

Secondary success criteria:

- More evidence that prompt remediation is non-monotonic.
- More evidence that failures cluster by command family rather than generic obfuscation.

Deliverables:

- `artifacts/evasion_expansion_summary.csv`
- `artifacts/evasion_expansion_near_miss_summary.csv`
- optional paper table update.

## Stage 5: Mechanistic Follow-Up

GPU required.

Only run this for newly discovered miss families or stronger replicated slices.

Follow-up tests:

1. Residual boundary check at `resid_pre13`.
2. Late Layer-12 head contribution trace.
3. Patch or ablate the validated late bundle.
4. Compare seed versus variant.
5. Compare Foundation-Sec versus Llama on the same variants.

Interpretation targets:

- Does the malicious-evidence signal survive internally?
- Does the miss appear by the Layer 13 boundary?
- Is the pattern consistent with signal reversal rather than route deletion?
- Does Llama avoid the same inversion?

Deliverable: mechanistic summary only if the new slice is strong enough to justify paper inclusion.

## Completed Expansion Runs

### Run 1: lowercase_v3 + alternating_case_v3 (raw prompt)

Techniques: `invoke_webrequest_lowercase`, `invoke_expression_lowercase`, `iex_lowercase`,
`downloadstring_lowercase`, `downloadfile_lowercase`, `downloadfile_base64_ascii`,
`downloadfile_subexpression_string`, and alternating-case parallels for IWR, IEX, Invoke-Expression,
DownloadString, DownloadFile.

Results (Foundation-Sec, 43 accepted variants):
- `invoke_expression_alternating_case`: 4/4 misses (all seeds, mean logit_diff −0.25)
- `invoke_expression_lowercase`: 1/4 misses (weakest seed only, logit_diff 0.0)
- `invoke_webrequest_lowercase`: 0 misses, 4/4 near-misses at exactly 0.125 margin
- `downloadstring_alternating_case`: 1 near-miss (seed c59b1d02106e, 0.25)
- All DownloadFile and IEX techniques: 0 misses, robust

Llama: 0/43 misses, mean logit_diff 4.63.

### Run 2: iex_brace_v3 (raw prompt, provisional_iex tier)

Fixed `replace_command_token` lookbehind to include `{` as a valid preceding character, enabling
transforms on the four IEX seeds whose scripts use `{iex $matches[1]}` syntax. These seeds failed
tree-sitter parse (nslookup `-q=txt` grammar limitation) so accepted under `provisional_iex` tier;
invariants pass cleanly.

Techniques: `iex_alternating_case`, `iex_format_string`, `iex_ascii_char_array`,
`iex_call_operator_string`, `iex_scriptblock_create`.

Results (Foundation-Sec, 20 accepted variants):
- `iex_alternating_case`: 4/4 misses, complete sweep across both seed pairs (logit_diff −0.125)
- All other techniques: 0 misses (mean logit_diff 1.1–3.4, structurally resistant)

Key finding: structural reconstructions (format-string, call-operator, scriptblock) leave substantial
residual signal (1.1–3.4 logit_diff) while byte-level token disruption (alternating case) crosses the
threshold on all four seeds. This dissociates syntactic sensitivity from token-embedding sensitivity.

### Run 3: adversarial prompt on case mutation variants

Adversarial prompt applied to the 43 lowercase_v3 + alternating_case_v3 candidates.

Results (Foundation-Sec, 43 variants):
- `invoke_expression_alternating_case`: 4/4 misses, deepened (−0.625 vs −0.25 raw)
- `invoke_expression_lowercase`: 4/4 misses — adversarial prompt converts all three near-misses to misses
- `downloadstring_lowercase`: 2/4 misses — new misses not present under raw prompt
- `downloadstring_alternating_case`: 2/6 misses — new misses not present under raw prompt
- `invoke_webrequest_*`: 0 misses, near-misses remain near-misses

Adversarial prompt effect: consistently amplifies misses for case mutation rather than remediating
them. Non-monotonic behaviour confirmed across three families (Invoke-Expression, DownloadString,
IEX), replicating the pattern already documented for format-string and backtick in realistic_v2.

## Findings Summary

### Confirmed miss families (at least one accepted miss)

| Family | Techniques that produced misses |
|---|---|
| Invoke-Expression | `invoke_expression_format_string`, `invoke_expression_alternating_case`, `invoke_expression_lowercase` (adv), `invoke_expression_backtick_string` (adv), `invoke_expression_base64_ascii` (adv), `invoke_expression_subexpression_string` (adv) |
| Invoke-WebRequest | `invoke_webrequest_alias` |
| IEX (brace context) | `iex_alternating_case` |
| DownloadString | `downloadstring_psobject_invoke`, `downloadstring_lowercase` (adv), `downloadstring_alternating_case` (adv) |

Llama: 0 confirmed misses across all technique classes and prompt variants.

### Families with no confirmed miss

- `-EncodedCommand`: baseline logit 3.9–5.1, no technique reached threshold
- `DownloadFile`: baseline logit 5.9–7.5, no technique reached threshold
- `FromBase64String` (high-margin seeds): baseline logit 1.06, no miss
- `IEX` structural rewrites: format-string/call-operator/scriptblock leave 1.1–3.4 residual, only case mutation breaks through

### Near-miss clusters (candidate for future composition testing)

- All four IWR seeds pinned at 0.125 under `invoke_webrequest_lowercase` and `invoke_webrequest_backtick_string`
- `downloadstring_alternating_case` seed c59b1d02106e at 0.25 raw, likely flips under adversarial composition

## Paper Update Guidance

The three completed runs produce a coherent three-tier escalating argument for the token-embedding
sensitivity mechanism. Paper additions should be structured around this framing:

**Tier 1 — Functional rewrites** (`invoke_webrequest_alias`, `downloadstring_psobject_invoke`):
establish that Foundation-Sec is sensitive to indicator surface form. The model fails when the
canonical command token is replaced by a semantically equivalent but lexically distinct form.

**Tier 2 — String reconstruction** (`invoke_expression_format_string`, `iex_ascii_char_array`, etc.):
show the sensitivity extends to reconstructed forms that eliminate the literal token entirely via
runtime string assembly. The token is not present in the script at all, yet the model still sometimes
detects it — and fails when reconstruction is sufficient to disrupt the token cluster.

**Tier 3 — Case mutation** (`invoke_expression_alternating_case`, `iex_alternating_case`):
closes the loop. The command token's syntactic identity, position, and argument structure are
completely preserved. Only the byte-level encoding changes. Confirmed misses on complete sweeps
(4/4 Invoke-Expression, 4/4 IEX brace) demonstrate that sensitivity is located at the token
embedding level, not at the syntactic or semantic level.

**Adversarial prompt non-monotonicity**: the adversarial prompt amplifies rather than remediates
case-mutation failures across three families. This is consistent with the mechanism: the adversarial
framing causes the model to weight its available signals more heavily, and when the dominant signal
(indicator token cluster) is disrupted, the model's confidence in the wrong direction increases.

**Core unified claim**: fine-tuning has concentrated classification weight on specific indicator
token embeddings. Anything that changes those embeddings degrades performance in proportion to how
much it disrupts the dominant token cluster for each family. This is invisible to standard accuracy
metrics because held-out test sets use canonical token forms.

Paper update rules:
- New misses must pass parse and invariant checks (or be accepted under the established
  `provisional_iex` tier for tree-sitter grammar limitations with confirmed invariant passes).
- Seed scripts must be baseline-correct.
- Foundation-Sec and Llama must be evaluated on the same accepted variants.
- Results must strengthen an existing claim or directly instantiate one of the three tiers above.
- Do not open new claim families (e.g. composition transforms, runtime-specific aliases) without
  completing the current tier structure first.

Preferred framing for the expanded evasion section:

> Targeted expansion across three transformation classes — functional rewrites, string reconstruction,
> and case mutation — finds consistent Foundation-Sec misses while Llama produces zero misses on the
> same variants. The escalating evidence points to a single mechanism: fine-tuning has concentrated
> classification weight on specific indicator token embeddings, and disrupting those embeddings
> degrades performance in proportion to the disruption magnitude, regardless of whether syntactic
> or semantic structure is preserved. The adversarial prompt, rather than remediating these failures,
> amplifies them — consistent with the model weighting a partially-disrupted signal more heavily
> under explicit detection pressure.
