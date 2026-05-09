"""Linear probe evaluation at resid_pre13.

Two probes:
  1. Llama resid_pre13 → Llama head trace projections (L12H4/H5/H15/H28, delta_projection)
     Tests whether circuit activity is linearly decodable from the activation.
  2. Llama resid_pre13 → FS top-5 ablation delta_logit_diff
     Tests whether FS circuit causal importance is cross-model linearly readable.

Both use 5-fold cross-validation with Ridge regression. Reports per-target r and compares
to MLP probe values.

Usage:
  python3 linear_probe_eval.py
"""

import json
import numpy as np
import pandas as pd
import torch
from pathlib import Path
from sklearn.linear_model import Ridge
from sklearn.model_selection import KFold
from sklearn.preprocessing import StandardScaler
from scipy.stats import pearsonr

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).parent
ARTIFACTS = ROOT / "artifacts"
RP_DIR = Path("/home/ryan/introspection-adapters/rp_artifacts")

LLAMA_CACHE = RP_DIR / "rp_activations_aug293_cache.pt"
TRACE_CSV = ARTIFACTS / "llama3/llama3_trace_resid_pre13_aug293_per_pair.csv"
ABLATION_CSV = ARTIFACTS / "foundation_sec/circuit_val_head_group_ablation_l12_writer_top5_aug_orig_h100_per_pair.csv"
MANIFEST_CSV = ARTIFACTS / "foundation_sec/circuit_val_aug_orig_families_valid_h100.csv"

TARGET_HEADS = [(12, 4), (12, 5), (12, 15), (12, 28)]
N_FOLDS = 5
RIDGE_ALPHA = 1.0


def load_activations(cache_path: Path) -> dict[str, np.ndarray]:
    data = torch.load(cache_path, map_location="cpu", weights_only=False)
    return {k: v.float().numpy() for k, v in data["activations"].items()}


def cv_pearson_r(X: np.ndarray, y: np.ndarray, alpha: float = RIDGE_ALPHA, n_folds: int = N_FOLDS) -> tuple[float, float]:
    """5-fold cross-validated Pearson r between Ridge predictions and true y."""
    kf = KFold(n_splits=n_folds, shuffle=True, random_state=42)
    preds = np.zeros_like(y)
    for train_idx, val_idx in kf.split(X):
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X[train_idx])
        X_val = scaler.transform(X[val_idx])
        clf = Ridge(alpha=alpha)
        clf.fit(X_train, y[train_idx])
        preds[val_idx] = clf.predict(X_val)
    r, p = pearsonr(preds, y)
    return float(r), float(p)


def main():
    acts = load_activations(LLAMA_CACHE)
    trace_df = pd.read_csv(TRACE_CSV)
    abl_df = pd.read_csv(ABLATION_CSV)
    manifest = pd.read_csv(MANIFEST_CSV)

    malicious = manifest[manifest.label == "malicious"][["filename", "pair_idx", "pair_indicator"]].drop_duplicates("filename")

    # Build activation matrix aligned to malicious filenames
    filenames = [f for f in malicious.filename if f in acts]
    X = np.stack([acts[f] for f in filenames])  # [N, 4096]
    meta = malicious[malicious.filename.isin(filenames)].set_index("filename").loc[filenames].reset_index()
    print(f"Activation matrix: {X.shape}")

    results = {}

    # ------------------------------------------------------------------
    # Probe 1: Llama resid_pre13 → head trace delta_projection per head
    # ------------------------------------------------------------------
    print("\n=== Probe 1: Llama resid_pre13 → Llama head trace delta_projection ===")
    head_results = {}
    fname_to_idx = {f: i for i, f in enumerate(meta.filename)}
    for layer, head in TARGET_HEADS:
        subset = trace_df[(trace_df["layer"] == layer) & (trace_df["head"] == head)]
        joined = meta.merge(
            subset[["malicious_filename", "delta_projection"]],
            left_on="filename", right_on="malicious_filename",
            how="inner",
        )
        if len(joined) < 20:
            print(f"  L{layer}H{head}: too few samples ({len(joined)}), skipping")
            continue
        idx = [fname_to_idx[f] for f in joined.filename]
        X_sub = X[idx]
        y = joined.delta_projection.values.astype(float)
        r, p = cv_pearson_r(X_sub, y)
        print(f"  L{layer}H{head}: r={r:+.4f}  p={p:.2e}  n={len(joined)}")
        head_results[f"L{layer}H{head}"] = {"r": r, "p": p, "n": len(joined)}

    results["head_trace"] = head_results

    # ------------------------------------------------------------------
    # Probe 2: Llama resid_pre13 → FS ablation delta_logit_diff
    # ------------------------------------------------------------------
    print("\n=== Probe 2: Llama resid_pre13 → FS top-5 ablation delta_logit_diff ===")
    joined_abl = meta.merge(
        abl_df[["malicious_filename", "delta_logit_diff"]],
        left_on="filename", right_on="malicious_filename",
        how="inner",
    )
    idx_abl = [list(meta.filename).index(f) for f in joined_abl.filename]
    X_abl = X[idx_abl]
    y_abl = joined_abl.delta_logit_diff.values.astype(float)
    r_abl, p_abl = cv_pearson_r(X_abl, y_abl)
    print(f"  CV r={r_abl:+.4f}  p={p_abl:.2e}  n={len(joined_abl)}")
    results["fs_ablation_delta"] = {"r": r_abl, "p": p_abl, "n": len(joined_abl)}

    # ------------------------------------------------------------------
    # Probe 3: Llama resid_pre13 → FS indicator token logit_diff_delta
    # ------------------------------------------------------------------
    print("\n=== Probe 3: Llama resid_pre13 → FS indicator-token logit_diff_delta ===")
    sens_fs = pd.read_csv(ARTIFACTS / "foundation_sec/indicator_sensitivity_fs_aug293_per_pair.csv")
    joined_sens = meta.merge(
        sens_fs[["malicious_filename", "logit_diff_delta", "resid_l2_sensitivity"]],
        left_on="filename", right_on="malicious_filename",
        how="inner",
    )
    idx_sens = [list(meta.filename).index(f) for f in joined_sens.filename]
    X_sens = X[idx_sens]

    y_delta = joined_sens.logit_diff_delta.values.astype(float)
    y_l2 = joined_sens.resid_l2_sensitivity.values.astype(float)

    r_delta, p_delta = cv_pearson_r(X_sens, y_delta)
    r_l2, p_l2 = cv_pearson_r(X_sens, y_l2)
    print(f"  token logit_diff_delta: r={r_delta:+.4f}  p={p_delta:.2e}  n={len(joined_sens)}")
    print(f"  token l2_sensitivity:   r={r_l2:+.4f}  p={p_l2:.2e}  n={len(joined_sens)}")
    results["fs_token_sensitivity"] = {
        "logit_diff_delta": {"r": r_delta, "p": p_delta, "n": len(joined_sens)},
        "l2_sensitivity": {"r": r_l2, "p": p_l2, "n": len(joined_sens)},
    }

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n=== Summary ===")
    print("MLP probe circuit_proxy_score vs FS ablation delta: r≈0.34 (for comparison)")
    print(f"Linear probe Llama → FS ablation delta (CV):        r={r_abl:+.4f}")
    print()
    for label, vals in head_results.items():
        print(f"Linear probe Llama → {label} trace delta (CV):  r={vals['r']:+.4f}")

    out_path = ROOT / "artifacts/linear_probe_eval_results.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved → {out_path}")


if __name__ == "__main__":
    main()
