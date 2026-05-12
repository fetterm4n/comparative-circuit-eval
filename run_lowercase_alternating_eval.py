#!/usr/bin/env python3
"""Run the lowercase_v3 + alternating_case_v3 evasion evaluation pipeline.

Steps:
  1. Build variant manifest from existing seed manifest
  2. Review variants (tree-sitter static parse + invariant checks)
  3. Build candidate manifest (strict tier)
  4. Run baseline-eval on Foundation-Sec
  5. Merge candidate manifest + eval output into final merged CSV
  6. Print summary of misses and near-misses
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent
ARTIFACTS = ROOT / "artifacts"
FS_ARTIFACTS = ARTIFACTS / "foundation_sec"
SCRIPT = ROOT / "scaled_validation.py"
PYTHON = sys.executable

SEED_MANIFEST = FS_ARTIFACTS / "evasion_seed_manifest_v2.csv"
TECHNIQUES = "lowercase_v3,alternating_case_v3"
PRESET_TAG = "lowercase_alternating_v3"

VARIANT_MANIFEST = ARTIFACTS / f"evasion_variant_manifest_{PRESET_TAG}.csv"
VARIANT_MANIFEST_META = ARTIFACTS / f"evasion_variant_manifest_{PRESET_TAG}_metadata.json"
SEED_MANIFEST_OUT = ARTIFACTS / f"evasion_seed_manifest_{PRESET_TAG}.csv"
REVIEW_CSV = ARTIFACTS / f"evasion_variant_review_{PRESET_TAG}.csv"
REVIEWED_MANIFEST = ARTIFACTS / f"evasion_variant_manifest_reviewed_{PRESET_TAG}.csv"
REVIEW_META = ARTIFACTS / f"evasion_variant_review_{PRESET_TAG}_metadata.json"
CANDIDATE_MANIFEST = FS_ARTIFACTS / f"evasion_variant_manifest_candidate_{PRESET_TAG}.csv"
CANDIDATE_META = FS_ARTIFACTS / f"evasion_variant_manifest_candidate_{PRESET_TAG}_metadata.json"
EVAL_OUTPUT = FS_ARTIFACTS / f"evasion_eval_candidate_baseline_{PRESET_TAG}.csv"
MERGED_OUTPUT = FS_ARTIFACTS / f"evasion_eval_candidate_merged_{PRESET_TAG}.csv"


def run(cmd: list[str], label: str) -> None:
    print(f"\n{'='*60}")
    print(f"STEP: {label}")
    print(f"CMD:  {' '.join(str(c) for c in cmd)}")
    print("=" * 60)
    result = subprocess.run(cmd, check=True)
    if result.returncode != 0:
        print(f"FAILED: {label}")
        sys.exit(1)


def merge_eval(candidate_path: Path, eval_path: Path, seed_manifest_path: Path, output_path: Path) -> pd.DataFrame:
    cand = pd.read_csv(candidate_path)
    eval_df = pd.read_csv(eval_path)
    seed = pd.read_csv(seed_manifest_path)

    seed_lookup = seed.set_index("seed_id")[["filename", "source_pair_idx", "baseline_logit_diff"]].rename(
        columns={"filename": "seed_filename", "baseline_logit_diff": "baseline_logit_diff"}
    )

    merged = cand.merge(
        eval_df[["filename", "predicted_label", "correct", "logit_diff"]],
        on="filename",
        how="left",
    )
    merged = merged.merge(seed_lookup, on="seed_id", how="left")
    merged["evasion_success"] = merged["predicted_label"] == "benign"
    merged["logit_delta_vs_seed"] = merged["logit_diff"] - merged["baseline_logit_diff"]

    output_path.parent.mkdir(parents=True, exist_ok=True)
    merged.to_csv(output_path, index=False)
    return merged


def summarize(merged: pd.DataFrame) -> None:
    print("\n" + "=" * 60)
    print("RESULTS SUMMARY")
    print("=" * 60)

    total = len(merged)
    misses = merged[merged["evasion_success"] == True]
    near_misses = merged[(merged["evasion_success"] == False) & (merged["logit_diff"] <= 0.25)]

    print(f"\nTotal accepted variants evaluated: {total}")
    print(f"Confirmed misses (evasion_success=True): {len(misses)}")
    print(f"Near-misses (correct but logit_diff <= 0.25): {len(near_misses)}")

    if len(misses):
        print("\nMISS DETAILS:")
        print(misses[["technique_id", "seed_id", "predicted_label", "logit_diff", "baseline_logit_diff", "logit_delta_vs_seed"]].to_string(index=False))

    print("\nPER-TECHNIQUE SUMMARY:")
    summary = (
        merged.groupby("technique_id")
        .agg(
            n=("variant_id", "count"),
            misses=("evasion_success", "sum"),
            mean_logit_diff=("logit_diff", "mean"),
            mean_logit_delta=("logit_delta_vs_seed", "mean"),
        )
        .reset_index()
        .sort_values("misses", ascending=False)
    )
    print(summary.to_string(index=False))

    print("\nNEAR-MISS DETAILS (lowest logit_diff, still correct):")
    print(
        near_misses[["technique_id", "seed_id", "logit_diff", "baseline_logit_diff"]]
        .sort_values("logit_diff")
        .to_string(index=False)
    )


def main() -> None:
    # Stage 1: build variant manifest
    run(
        [
            PYTHON, str(SCRIPT),
            "build-evasion-variant-manifest",
            "--manifest", str(SEED_MANIFEST),
            "--techniques", TECHNIQUES,
            "--output", str(VARIANT_MANIFEST),
            "--seed-output", str(SEED_MANIFEST_OUT),
            "--metadata-output", str(VARIANT_MANIFEST_META),
        ],
        "Build variant manifest",
    )

    # Stage 2: review variants
    run(
        [
            PYTHON, str(SCRIPT),
            "review-evasion-variants",
            "--variant-manifest", str(VARIANT_MANIFEST),
            "--seed-manifest", str(SEED_MANIFEST),
            "--review-output", str(REVIEW_CSV),
            "--updated-manifest-output", str(REVIEWED_MANIFEST),
            "--metadata-output", str(REVIEW_META),
        ],
        "Review variants (static parse + invariants)",
    )

    # Stage 3: build candidate manifest (strict tier)
    run(
        [
            PYTHON, str(SCRIPT),
            "build-evasion-candidate-manifest",
            "--reviewed-manifest", str(REVIEWED_MANIFEST),
            "--seed-manifest", str(SEED_MANIFEST),
            "--tier", "strict",
            "--output", str(CANDIDATE_MANIFEST),
            "--metadata-output", str(CANDIDATE_META),
        ],
        "Build candidate manifest (strict)",
    )

    # Stage 4: GPU baseline-eval on Foundation-Sec
    run(
        [
            PYTHON, str(SCRIPT),
            "baseline-eval",
            "--manifest", str(CANDIDATE_MANIFEST),
            "--model-name", "fdtn-ai/Foundation-Sec-8B-Instruct",
            "--torch-dtype", "bfloat16",
            "--batch-size", "4",
            "--output", str(EVAL_OUTPUT),
        ],
        "Foundation-Sec baseline eval (GPU)",
    )

    # Stage 5: merge and summarize
    print("\n" + "=" * 60)
    print("STEP: Merge candidate manifest + eval output")
    merged = merge_eval(CANDIDATE_MANIFEST, EVAL_OUTPUT, SEED_MANIFEST, MERGED_OUTPUT)
    print(f"Merged output written to: {MERGED_OUTPUT}")

    summarize(merged)


if __name__ == "__main__":
    main()
