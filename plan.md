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

## Recommended First Run

Start small:

1. Audit existing artifacts and rank near misses.
2. Generate 50 to 150 targeted variants from:
   - `Invoke-WebRequest`
   - `Invoke-Expression`
   - current low-margin seeds
3. Keep only strict accepted variants.
4. Evaluate Foundation-Sec raw and adversarial first.
5. Evaluate Llama only on variants that produce Foundation-Sec misses or near misses.

This minimizes GPU time while preserving the controlled comparison.

## Paper Update Rules

Update the paper only if:

- New misses pass parse and invariant checks.
- Seed scripts are baseline-correct.
- Foundation-Sec and Llama are evaluated on the same accepted variants.
- Results strengthen an existing claim rather than opening a new unsupported one.

Preferred paper framing:

> Targeted expansion within monitored command families found additional accepted misses, confirming that the monitoring signal is useful for red-team prioritization. The expanded set remains a controlled seed/variant attribution harness, not a population-level estimate of PowerShell evasion prevalence.
