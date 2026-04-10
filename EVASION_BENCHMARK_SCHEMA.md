# Evasion Benchmark Schema

## Purpose

This schema defines the first real evasion benchmark and a second more realistic robustness benchmark for the PowerShell circuit-validation work.

The benchmark is designed to answer:

> Does the model still classify malicious PowerShell correctly when attack intent is preserved but the surface forms used by the current circuit are obscured?

The benchmark must preserve **real execution viability** for the transformed PowerShell scripts. It is not a formatting benchmark and it is not a synthetic string-perturbation benchmark.

---

## Scope

This benchmark covers:

- malicious PowerShell seeds drawn from the existing mechanistic cohorts
- semantics-preserving obfuscation variants
- static viability checks
- model classification outputs
- circuit-level measurements on original and obfuscated variants

This benchmark does **not** require executing malware in the repo environment.
Instead, variants must be viable by construction and pass explicit static/runtime-target checks.

The repo now supports two explicit technique presets:

- `baseline_v1`
  - the original conservative benchmark used for the current strict candidate artifacts
- `realistic_v2`
  - a second defensive robustness benchmark focused on more realistic command and string reconstruction patterns

---

## Core Entities

### 1. Seed Script

A source PowerShell script selected as the starting point for one or more obfuscation variants.

Required properties:

- labeled `malicious`
- baseline prediction `malicious`
- logit difference recorded on the base script
- source cohort recorded
- indicator family recorded

### 2. Obfuscation Technique

A named transform class applied to a seed script.

Required properties:

- stable `technique_id`
- higher-level `family`
- runtime target
- explicit preconditions
- explicit invariants
- explicit forbidden cases

### 3. Variant

A transformed PowerShell script derived from one seed script using one technique.

Required properties:

- full transformed script content
- exact parent seed reference
- technique metadata
- viability annotations
- indicator-presence deltas

### 4. Evaluation Row

A row capturing model and circuit behavior for one variant.

Required properties:

- classification result
- logit diff
- behavior-change flags
- optional circuit measurements

---

## Runtime Targets

Every variant must declare a runtime target because some PowerShell forms are version-specific.

Allowed values:

- `windows_powershell_5_1`
- `pwsh_7`
- `cross_runtime`

Default policy:

- Prefer `cross_runtime`
- Use runtime-specific transforms only when the seed already relies on that runtime family

Example:

- Using `iwr` alias should **not** be marked `cross_runtime` by default
- Rewriting `Invoke-Expression` into `& ([scriptblock]::Create(...))` can be `cross_runtime` if the syntax remains version-safe

---

## Obfuscation Families

These are benchmark families, not individual implementations.

### 1. `keyword_hiding`

Goal:
Hide suspicious literal tokens without changing execution.

Representative transforms:

- concatenation of command names or flags
- format-string reconstruction
- case and backtick variations that remain valid PowerShell
- quoted member or command names resolved at runtime
- invisible Unicode insertion followed by explicit normalization before use

Must preserve:

- command/function invoked
- parameter meaning
- argument values

### 2. `string_construction`

Goal:
Construct suspicious strings at runtime rather than embedding them directly.

Representative transforms:

- `-join`
- array-to-string assembly
- `[char]` code assembly
- substring stitching
- base64 decode only when the original script already decodes or consumes strings at runtime in a consistent way
- double-quoted subexpression assembly such as `"$('Invoke-')Expression"`

Must preserve:

- final resolved string value
- encoding assumptions
- quoting behavior

### 3. `execution_indirection`

Goal:
Replace direct execution with an equivalent indirect execution form.

Representative transforms:

- `IEX` to `& ([scriptblock]::Create(...))`
- direct command call to call operator with resolved command string
- helper function wrapper with same final execution

Must preserve:

- execution order
- scope expectations where relevant
- whether the payload is executed in-process vs child process

### 4. `network_object_indirection`

Goal:
Swap obvious network or object-construction surfaces for semantically equivalent alternatives.

Representative transforms:

- `New-Object System.Net.WebClient` to explicit .NET construction forms
- method invocation via reflected or indirect object references
- helper function wrapping of download calls

Must preserve:

- protocol and URL semantics
- file-write target
- downstream execution behavior

### 5. `staged_payload_flow`

Goal:
Separate retrieval, decode, allocate, and execute stages while preserving final behavior.

Representative transforms:

- move suspicious operations into helper functions
- split a single expression into sequential assignments
- stage decoded payload into intermediate variables before execution

Must preserve:

- observable execution path
- payload bytes
- side-effect ordering

---

## Technique Registry Schema

Each technique should be represented in code and metadata using the following schema:

| Field | Type | Description |
|---|---|---|
| `technique_id` | `string` | Stable identifier, e.g. `iex_scriptblock_create` |
| `family` | `string` | One of the benchmark families above |
| `description` | `string` | Human-readable description |
| `runtime_target` | `string` | `windows_powershell_5_1`, `pwsh_7`, or `cross_runtime` |
| `target_indicators` | `list[string]` | Indicators this transform is meant to obscure |
| `preconditions` | `list[string]` | Conditions that must be true before applying |
| `forbidden_if` | `list[string]` | Conditions that block use |
| `expected_indicator_delta` | `string` | `remove_literal`, `reduce_literal`, or `no_change` |
| `semantic_invariants` | `list[string]` | What must remain identical after transformation |
| `static_checks` | `list[string]` | Checks required before a variant is accepted |
| `notes` | `string` | Implementation details and caveats |

---

## Seed Manifest Schema

File:

- `artifacts/evasion_seed_manifest.csv`

One row per seed script.

| Field | Type | Description |
|---|---|---|
| `seed_id` | `string` | Stable unique id |
| `filename` | `string` | Source filename |
| `source_manifest` | `string` | Parent manifest path or name |
| `source_pair_idx` | `integer` | Parent pair id if applicable |
| `label` | `string` | Must be `malicious` for v1 |
| `primary_indicator` | `string` | Seed indicator family |
| `matched_indicators` | `string` | Pipe-delimited matched indicators |
| `runtime_target` | `string` | Declared execution target |
| `baseline_predicted_label` | `string` | Baseline model output |
| `baseline_logit_diff` | `float` | Base logit diff |
| `used_char_len` | `integer` | Length used for evaluation |
| `content` | `string` | Full script text |

Acceptance rules:

- baseline prediction must match the malicious label
- script must be within the benchmark length cap
- script must contain at least one indicator family targeted by the benchmark

---

## Variant Manifest Schema

File:

- `artifacts/evasion_variant_manifest.csv`

One row per transformed malicious variant.

| Field | Type | Description |
|---|---|---|
| `variant_id` | `string` | Stable unique id |
| `seed_id` | `string` | Parent seed id |
| `filename` | `string` | Synthetic variant filename |
| `label` | `string` | `malicious` |
| `technique_id` | `string` | Applied technique |
| `family` | `string` | Obfuscation family |
| `runtime_target` | `string` | Declared runtime target |
| `variant_rank` | `integer` | Rank within seed |
| `indicator_family_targeted` | `string` | Primary targeted indicator |
| `indicator_count_before` | `integer` | Count on seed |
| `indicator_count_after` | `integer` | Count on variant |
| `literal_indicator_removed` | `boolean` | Whether the target literal disappeared |
| `viability_status` | `string` | `accepted`, `rejected`, or `needs_review` |
| `viability_reason` | `string` | Why accepted/rejected/reviewed |
| `static_parse_ok` | `boolean` | Whether parse check succeeded |
| `static_invariants_ok` | `boolean` | Whether invariants held |
| `manual_review_required` | `boolean` | Whether a human should inspect it |
| `content` | `string` | Full transformed script text |

Recommended additional fields:

- `parent_content_hash`
- `variant_content_hash`
- `notes`

---

## Viability Review Schema

File:

- `artifacts/evasion_variant_review.csv`

One row per variant after viability review.

| Field | Type | Description |
|---|---|---|
| `variant_id` | `string` | Variant id |
| `review_status` | `string` | `accepted`, `rejected`, or `needs_revision` |
| `review_type` | `string` | `static_only` or `manual_static_review` |
| `review_reason` | `string` | Short rationale |
| `syntax_ok` | `boolean` | Parser accepted the script |
| `runtime_target_ok` | `boolean` | Compatible with declared runtime |
| `behavior_equivalent_confidence` | `string` | `high`, `medium`, or `low` |
| `review_notes` | `string` | Free text |

This file is important because “obfuscated” but non-runnable variants should not be counted as valid evasion attempts.

---

## Model Evaluation Schema

File:

- `artifacts/evasion_eval_baseline.csv`

One row per accepted variant.

| Field | Type | Description |
|---|---|---|
| `variant_id` | `string` | Variant id |
| `seed_id` | `string` | Parent seed id |
| `technique_id` | `string` | Technique |
| `family` | `string` | Obfuscation family |
| `predicted_label` | `string` | Model output |
| `logit_diff` | `float` | Variant logit diff |
| `baseline_logit_diff` | `float` | Seed logit diff |
| `logit_delta_vs_seed` | `float` | Variant minus seed |
| `classification_changed` | `boolean` | Whether prediction changed |
| `evasion_success` | `boolean` | Whether malicious becomes benign |

---

## Circuit Evaluation Schema

File:

- `artifacts/evasion_eval_circuit.csv`

One row per accepted variant and intervention bundle.

| Field | Type | Description |
|---|---|---|
| `variant_id` | `string` | Variant id |
| `seed_id` | `string` | Parent seed id |
| `probe_type` | `string` | `head_ablation`, `path_patching`, or similar |
| `probe_label` | `string` | Human-readable circuit bundle |
| `base_logit_diff` | `float` | Variant base logit diff |
| `intervened_logit_diff` | `float` | Post-intervention logit diff |
| `delta_logit_diff` | `float` | Intervention effect |
| `flip_to_benign` | `boolean` | Whether intervention flips result |
| `seed_reference_delta` | `float` | Same intervention on original seed |
| `delta_change_vs_seed` | `float` | Variant intervention effect minus seed intervention effect |

Required v1 probes:

- early head ablation for `L0H11`
- early head ablation for `L0H9`
- grouped late path patching for `L12H15/L12H5/L12H4/L12H28`
- optionally grouped late ablation for `L12H15/L12H5/L12H4/L12H2/L12H28`

---

## Summary Schema

File:

- `artifacts/evasion_candidate_benchmark_summary_v3.csv`
- `artifacts/evasion_candidate_family_summary_v3.csv`

One row per technique or family aggregate.

| Field | Type | Description |
|---|---|---|
| `group_by` | `string` | `technique_id` or `family` |
| `group_value` | `string` | Group key |
| `variant_count` | `integer` | Accepted variants |
| `evasion_success_rate` | `float` | Fraction that became benign |
| `mean_logit_delta_vs_seed` | `float` | Mean logit shift |
| `mean_h11_delta_change` | `float` | Change in `L0H11` causal effect vs seed |
| `mean_h9_delta_change` | `float` | Change in `L0H9` causal effect vs seed |
| `mean_late_carrier_delta_change` | `float` | Change in late-carrier effect vs seed |
| `notes` | `string` | Short interpretation |

---

## Viability Rules

These rules are mandatory for accepted variants.

### Rule 1: Parse Validity

The variant must parse as PowerShell for the declared runtime target.

Minimum check:

- parser acceptance via a static PowerShell parse step

### Rule 2: Execution Semantics Must Be Preserved by Construction

A transform is only eligible if its semantics are locally checkable.

Examples of acceptable transforms:

- replacing `IEX $x` with `& ([scriptblock]::Create($x))`
- constructing `"Invoke-WebRequest"` from string parts before invocation
- moving a download-and-execute sequence into a helper function without altering arguments

Examples to exclude from v1:

- transforms that depend on environment-specific aliases
- transforms that change process boundaries
- transforms that alter encoding assumptions without proof
- transforms that insert non-equivalent helper logic

### Rule 3: Runtime Target Must Be Honest

If a transform is only safe on one runtime family, mark it that way.

### Rule 4: No Broken Obfuscations Count as Evasions

If a transformed script likely would not run, it must be rejected or flagged `needs_review`.

### Rule 5: Preserve Malicious Intent, Not Necessarily Surface Form

The benchmark is valid only if the transformed script would still perform the same malicious behavior in a real environment.

---

## Static Checks

Each accepted variant should pass at least:

- `parse_ok`
- balanced quoting and string delimiters
- no undefined generated variable names introduced by the transform
- no removed argument values required for execution
- no broken method/member invocation syntax
- no target-runtime mismatch

Optional stronger checks:

- AST-shape comparison on untouched sections
- targeted invariant checks for URLs, paths, payload strings, and invoked APIs
- indicator-literal accounting before and after transform

---

## Benchmark Acceptance Policy

A variant enters the benchmark only if:

1. The seed is malicious and baseline-correct.
2. The transform passes its preconditions.
3. Static parsing succeeds.
4. Semantic invariants are satisfied.
5. The variant is marked `accepted` in viability review.

If any of these fail, the variant is not counted in evasion success metrics.

Current strict-candidate note:

- the v3 benchmark includes `DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `Invoke-Expression`, and `-EncodedCommand`
- a separate provisional tier can include pure `IEX` variants when invariants hold and the only blocker is missing runtime-side parse validation

Current preset note:

- `baseline_v1` preserves the original conservative technique set and remains the default when `--techniques` is omitted
- `realistic_v2` adds defensive-evasion categories for invisible Unicode normalization, backtick-split strings, format-string reconstruction, ASCII or Base64 recovery, and alternate quoting or subexpressions

---

## Recommended V1 Benchmark Size

Recommended first pass:

- `20-30` malicious seeds
- `3-4` accepted variants per seed
- prioritize seeds from the 96-pair cohort
- maintain coverage across the main indicator families

Target coverage:

- `DownloadFile`
- `DownloadString`
- `Invoke-WebRequest`
- `Invoke-Expression`
- `FromBase64String`
- `IEX`
- `-EncodedCommand`

---

## Initial Reporting Categories

Each accepted variant should be classified into one of these outcome buckets:

- `robust_same_circuit`
  - still blocked and the early/late circuit effects remain close to seed
- `robust_shifted_circuit`
  - still blocked but one or more current circuit probes weaken materially
- `partial_evasion`
  - still blocked but confidence drops sharply
- `successful_evasion`
  - prediction flips to benign
- `invalid_variant`
  - rejected before evaluation

---

## Recommended File Set

The benchmark should produce these files:

- `artifacts/evasion_seed_manifest_v2.csv`
- `artifacts/evasion_variant_manifest_reviewed_v3.csv`
- `artifacts/evasion_variant_review_v3.csv`
- `artifacts/evasion_variant_manifest_candidate_v3.csv`
- `artifacts/evasion_variant_manifest_candidate_provisional_v1.csv`
- `artifacts/evasion_eval_candidate_baseline_v3.csv`
- `artifacts/evasion_eval_candidate_merged_v3.csv`
- `artifacts/evasion_eval_candidate_baseline_provisional_v1.csv`
- `artifacts/evasion_eval_candidate_merged_provisional_v1.csv`
- `artifacts/evasion_eval_circuit.csv`
- `artifacts/evasion_candidate_benchmark_summary_v3.csv`
- `artifacts/evasion_candidate_family_summary_v3.csv`
- `artifacts/evasion_candidate_benchmark_summary_provisional_v1.csv`
- `artifacts/evasion_candidate_family_summary_provisional_v1.csv`
- `artifacts/evasion_benchmark_metadata.json`

---

## Current Recommendation

Implement the benchmark in this order:

1. seed-manifest builder
2. technique registry with explicit preconditions/invariants
3. variant-manifest generator
4. static viability checks
5. baseline evaluation
6. circuit evaluation
7. family- and technique-level summary aggregation

That ordering keeps the benchmark honest: viable variants first, model claims second.
