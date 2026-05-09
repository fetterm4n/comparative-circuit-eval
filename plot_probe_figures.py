"""Generate three figures for the paper:
  1. Bar chart: indicator-token ablation delta per family, Llama vs. Foundation-Sec
  2. Bar chart: linear probe r values by head (head trace + cross-model transfers)
  3. 4-panel scatter: probe predicted vs. actual head contribution (one per head)
"""

import json
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from pathlib import Path
from sklearn.linear_model import Ridge
from sklearn.model_selection import KFold
from sklearn.preprocessing import StandardScaler
from scipy.stats import pearsonr
import torch

ROOT = Path(__file__).parent
ARTIFACTS = ROOT / "artifacts"
RP_DIR = Path("/home/ryan/introspection-adapters/rp_artifacts")
LLAMA_CACHE = RP_DIR / "rp_activations_aug293_cache.pt"
TRACE_CSV = ARTIFACTS / "llama3/llama3_trace_resid_pre13_aug293_per_pair.csv"
MANIFEST_CSV = ARTIFACTS / "foundation_sec/circuit_val_aug_orig_families_valid_h100.csv"

TARGET_HEADS = [(12, 4), (12, 5), (12, 15), (12, 28)]
FAMILY_ORDER = [
    "DownloadFile", "DownloadString", "IEX",
    "Invoke-WebRequest", "Invoke-Expression",
    "-EncodedCommand", "FromBase64String",
]
FAMILY_LABELS = {
    "DownloadFile": "DownloadFile",
    "DownloadString": "DownloadString",
    "IEX": "IEX",
    "Invoke-WebRequest": "Invoke-\nWebRequest",
    "Invoke-Expression": "Invoke-\nExpression",
    "-EncodedCommand": "-Encoded\nCommand",
    "FromBase64String": "FromBase64\nString",
}

FS_COLOR = "#E07B39"
LLAMA_COLOR = "#4C8BB5"

# ---------------------------------------------------------------------------
# Figure 1: ablation delta bar chart
# ---------------------------------------------------------------------------
def fig_ablation_delta():
    fs = pd.read_csv(ARTIFACTS / "foundation_sec/indicator_sensitivity_fs_aug293_family.csv")
    llama = pd.read_csv(ARTIFACTS / "llama3/indicator_sensitivity_llama_aug293_family.csv")

    fs = fs.set_index("pair_indicator")
    llama = llama.set_index("pair_indicator")

    families = FAMILY_ORDER
    x = np.arange(len(families))
    width = 0.38

    # Cap y-axis so small-delta families are readable; annotate clipped bars
    Y_MIN = -5.5
    llama_vals = [llama.loc[f, "mean_logit_diff_delta"] for f in families]
    fs_vals = [fs.loc[f, "mean_logit_diff_delta"] for f in families]

    fig, ax = plt.subplots(figsize=(8.5, 4.5))

    ax.bar(x - width / 2, llama_vals, width, label="Llama-3.1-8B-Instruct", color=LLAMA_COLOR, alpha=0.88)
    ax.bar(x + width / 2, fs_vals, width, label="Foundation-Sec-8B-Instruct", color=FS_COLOR, alpha=0.88)

    # Annotate any Llama bar clipped by the y-axis cap
    for i, (xi, v) in enumerate(zip(x, llama_vals)):
        if v < Y_MIN:
            ax.text(xi - width / 2, Y_MIN + 0.15, f"{v:.1f}", ha="center", va="bottom",
                    fontsize=7.5, color=LLAMA_COLOR, fontstyle="italic")

    ax.axhline(0, color="black", linewidth=0.8, linestyle="--", alpha=0.6)
    ax.set_ylim(Y_MIN, 1.6)
    ax.set_xticks(x)
    ax.set_xticklabels([FAMILY_LABELS[f] for f in families], fontsize=9)
    ax.set_ylabel("Mean logit-diff delta\n(ablating indicator tokens)", fontsize=10)
    ax.set_title(
        "Indicator-Token Ablation Delta by Family\n"
        "Sign inversion in Invoke-WebRequest predicts aliasing brittleness",
        fontsize=10.5, pad=8,
    )
    ax.legend(fontsize=9, loc="lower left")

    # Annotate the IWR sign-inversion bar
    iwr_idx = families.index("Invoke-WebRequest")
    fs_iwr = fs.loc["Invoke-WebRequest", "mean_logit_diff_delta"]
    ax.annotate(
        "Sign inversion",
        xy=(iwr_idx + width / 2, fs_iwr),
        xytext=(iwr_idx + width / 2 + 0.7, fs_iwr + 0.4),
        fontsize=8, color=FS_COLOR,
        arrowprops=dict(arrowstyle="->", color=FS_COLOR, lw=1.2),
    )

    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    fig.tight_layout()
    out = ARTIFACTS / "figure_ablation_delta_by_family.png"
    fig.savefig(out, dpi=180, bbox_inches="tight")
    print(f"Saved {out}")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Figure 2: linear probe r-value summary bar chart
# ---------------------------------------------------------------------------
def fig_probe_r_values():
    with open(ARTIFACTS / "linear_probe_eval_results.json") as f:
        res = json.load(f)

    labels = ["L12H4", "L12H5", "L12H15", "L12H28", "FS ablation\ndelta (xfer)", "FS token\nl2-sens (xfer)"]
    r_vals = [
        res["head_trace"]["L12H4"]["r"],
        res["head_trace"]["L12H5"]["r"],
        res["head_trace"]["L12H15"]["r"],
        res["head_trace"]["L12H28"]["r"],
        res["fs_ablation_delta"]["r"],
        res["fs_token_sensitivity"]["l2_sensitivity"]["r"],
    ]
    colors = [LLAMA_COLOR] * 4 + [FS_COLOR] * 2

    fig, ax = plt.subplots(figsize=(7.5, 3.8))
    bars = ax.bar(range(len(labels)), r_vals, color=colors, alpha=0.88, width=0.6)

    for bar, r in zip(bars, r_vals):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.012,
            f"r={r:.2f}",
            ha="center", va="bottom", fontsize=8.5,
        )

    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, fontsize=9)
    ax.set_ylim(0, 1.12)
    ax.set_ylabel("Cross-validated Pearson r", fontsize=10)
    ax.set_title(
        "Linear Probe Performance (Ridge, 5-fold CV)\n"
        "Llama resid_pre13 → head contributions (blue) and cross-model transfer (orange)",
        fontsize=10.5, pad=8,
    )
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor=LLAMA_COLOR, alpha=0.88, label="Llama head trace (n=206)"),
        Patch(facecolor=FS_COLOR, alpha=0.88, label="Cross-model transfer to FS (n=293)"),
    ]
    # Place legend below the title, inside the axes at top-left to avoid bar overlap
    ax.legend(handles=legend_elements, fontsize=9, loc="upper left", bbox_to_anchor=(0.01, 0.99))

    fig.tight_layout()
    out = ARTIFACTS / "figure_linear_probe_r_values.png"
    fig.savefig(out, dpi=180, bbox_inches="tight")
    print(f"Saved {out}")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Figure 3: 4-panel scatter — predicted vs. actual head contribution
# ---------------------------------------------------------------------------
def cv_predictions(X, y, alpha=1.0, n_folds=5):
    kf = KFold(n_splits=n_folds, shuffle=True, random_state=42)
    preds = np.zeros_like(y)
    for train_idx, val_idx in kf.split(X):
        scaler = StandardScaler()
        X_train = scaler.fit_transform(X[train_idx])
        X_val = scaler.transform(X[val_idx])
        clf = Ridge(alpha=alpha)
        clf.fit(X_train, y[train_idx])
        preds[val_idx] = clf.predict(X_val)
    return preds


def fig_probe_scatter():
    data = torch.load(LLAMA_CACHE, map_location="cpu", weights_only=False)
    acts = {k: v.float().numpy() for k, v in data["activations"].items()}

    trace_df = pd.read_csv(TRACE_CSV)
    manifest = pd.read_csv(MANIFEST_CSV)
    malicious = manifest[manifest.label == "malicious"][["filename", "pair_idx", "pair_indicator"]].drop_duplicates("filename")

    filenames = [f for f in malicious.filename if f in acts]
    X = np.stack([acts[f] for f in filenames])
    meta = malicious[malicious.filename.isin(filenames)].set_index("filename").loc[filenames].reset_index()
    fname_to_idx = {f: i for i, f in enumerate(meta.filename)}

    family_colors = {
        "DownloadFile": "#4C8BB5",
        "DownloadString": "#E07B39",
        "IEX": "#5BAD72",
        "Invoke-WebRequest": "#C94040",
        "Invoke-Expression": "#9B59B6",
        "-EncodedCommand": "#8B7355",
        "FromBase64String": "#E8A838",
    }

    fig, axes = plt.subplots(2, 2, figsize=(9, 8.5))
    axes = axes.flatten()

    for ax, (layer, head) in zip(axes, TARGET_HEADS):
        subset = trace_df[(trace_df["layer"] == layer) & (trace_df["head"] == head)]
        joined = meta.merge(
            subset[["malicious_filename", "delta_projection"]],
            left_on="filename", right_on="malicious_filename",
            how="inner",
        )
        idx = [fname_to_idx[f] for f in joined.filename]
        X_sub = X[idx]
        y = joined.delta_projection.values.astype(float)
        preds = cv_predictions(X_sub, y)
        r, _ = pearsonr(preds, y)

        for family in joined.pair_indicator.unique():
            mask = joined.pair_indicator.values == family
            ax.scatter(
                y[mask], preds[mask],
                color=family_colors.get(family, "gray"),
                alpha=0.65, s=28, label=family,
            )

        lim = max(abs(y.min()), abs(y.max()), abs(preds.min()), abs(preds.max())) * 1.12
        ax.plot([-lim, lim], [-lim, lim], color="black", linewidth=0.9, linestyle="--", alpha=0.45)
        ax.set_xlim(-lim, lim)
        ax.set_ylim(-lim, lim)
        ax.set_xlabel("Actual delta projection", fontsize=9)
        ax.set_ylabel("Predicted (CV)", fontsize=9)
        ax.set_title(f"L{layer}H{head}  (r = {r:.3f}, n = {len(joined)})", fontsize=10)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

    # Legend inside the figure with reserved bottom space
    handles = [
        plt.scatter([], [], color=family_colors.get(f, "gray"), s=36, alpha=0.85, label=f)
        for f in FAMILY_ORDER if f in family_colors
    ]
    fig.legend(
        handles=handles, loc="lower center", ncol=4, fontsize=9,
        bbox_to_anchor=(0.5, 0.01), frameon=True, framealpha=0.9,
        edgecolor="lightgray",
    )
    fig.suptitle(
        "Linear Probe: Llama resid_pre13 → Layer-12 Head Contributions\n"
        "5-fold cross-validated Ridge regression, colored by indicator family",
        fontsize=11, y=1.00,
    )
    fig.tight_layout(rect=[0, 0.09, 1, 1])
    out = ARTIFACTS / "figure_probe_scatter_heads.png"
    fig.savefig(out, dpi=180, bbox_inches="tight")
    print(f"Saved {out}")
    plt.close(fig)


if __name__ == "__main__":
    print("Generating Figure 1: ablation delta by family...")
    fig_ablation_delta()
    print("Generating Figure 2: linear probe r values...")
    fig_probe_r_values()
    print("Generating Figure 3: probe scatter plots...")
    fig_probe_scatter()
    print("Done.")
