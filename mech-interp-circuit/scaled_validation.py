#!/usr/bin/env python3
"""Scaled validation pipeline for PowerShell circuit analysis.

This module is the new analysis entrypoint for the larger-scale validation work
under ``mech-interp-circuit``. It keeps all new code local to this directory and
separates:

1. Dataset preparation and summarization
2. Prompt construction and baseline classification utilities
3. Mechanistic interpretability helpers that require TransformerLens

The current environment can run dataset preparation immediately. The MI helpers
are implemented behind an optional dependency gate so the pipeline remains
importable even when ``transformer_lens`` is not installed locally.
"""

from __future__ import annotations

import argparse
import csv
import gc
import json
import random
import re
import sys
from collections import deque
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Pattern, Sequence, Tuple, Union

import numpy as np
import pandas as pd
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

try:
    from transformer_lens import HookedTransformer

    HAS_TRANSFORMER_LENS = True
except ImportError:
    HookedTransformer = None
    HAS_TRANSFORMER_LENS = False


SEED = 42
random.seed(SEED)
np.random.seed(SEED)
torch.manual_seed(SEED)

ROOT = Path(__file__).resolve().parent
DEFAULT_CSV_PATH = ROOT / "ps_test_data.csv"
DEFAULT_ARTIFACT_DIR = ROOT / "artifacts"
DEFAULT_MODEL_NAME = "fdtn-ai/Foundation-Sec-8B-Instruct"
HF_CACHE_DIR = Path.home() / ".cache" / "huggingface" / "hub"

LABELS = {"benign": "ALLOW", "malicious": "BLOCK"}
SUSPICIOUS_PATTERNS: List[str] = [
    r"\bIEX\b",
    r"Invoke-Expression",
    r"FromBase64String",
    r"DownloadString",
    r"DownloadFile",
    r"Invoke-WebRequest",
    r"Net\.WebClient",
    r"-EncodedCommand",
    r"Start-Process",
    r"CreateThread",
    r"VirtualAlloc",
]
PATTERN_DISPLAY_NAMES: Dict[str, str] = {
    r"\bIEX\b": "IEX",
    r"Invoke-Expression": "Invoke-Expression",
    r"FromBase64String": "FromBase64String",
    r"DownloadString": "DownloadString",
    r"DownloadFile": "DownloadFile",
    r"Invoke-WebRequest": "Invoke-WebRequest",
    r"Net\.WebClient": "Net.WebClient",
    r"-EncodedCommand": "-EncodedCommand",
    r"Start-Process": "Start-Process",
    r"CreateThread": "CreateThread",
    r"VirtualAlloc": "VirtualAlloc",
}


@dataclass
class DatasetSummary:
    rows_total: int
    rows_used: int
    benign_total: int
    malicious_total: int
    empty_content_rows: int
    truncated_rows: int
    max_chars_applied: Optional[int]
    min_chars_applied: int
    content_len_min: int
    content_len_p50: int
    content_len_p90: int
    content_len_p99: int
    content_len_max: int
    gt_8k_chars: int
    gt_16k_chars: int


def percentile(values: Sequence[int], q: float) -> int:
    if not values:
        return 0
    idx = min(len(values) - 1, int((len(values) - 1) * q))
    return int(values[idx])


def normalize_label(raw_label: str) -> str:
    value = (raw_label or "").strip().lower()
    if value not in LABELS:
        raise ValueError(f"Unsupported label: {raw_label!r}")
    return value


def clean_script_text(text: str) -> str:
    return (text or "").replace("\r\n", "\n").strip("\n")


def truncate_script(text: str, max_chars: Optional[int]) -> Tuple[str, bool]:
    if max_chars is None or len(text) <= max_chars:
        return text, False
    return text[:max_chars], True


def load_dataset(
    csv_path: Union[str, Path] = DEFAULT_CSV_PATH,
    *,
    max_chars: Optional[int] = 12000,
    min_chars: int = 1,
) -> Tuple[pd.DataFrame, DatasetSummary]:
    csv.field_size_limit(sys.maxsize)

    csv_path = Path(csv_path)
    rows: List[Dict[str, object]] = []
    label_counts = {"benign": 0, "malicious": 0}
    lengths: List[int] = []
    empty_content_rows = 0
    truncated_rows = 0
    gt_8k_chars = 0
    gt_16k_chars = 0

    with csv_path.open(newline="", encoding="utf-8", errors="replace") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            label = normalize_label(row.get("label", ""))
            label_counts[label] += 1

            raw_content = clean_script_text(row.get("Content", "") or "")
            raw_length = len(raw_content)
            lengths.append(raw_length)

            if raw_length == 0:
                empty_content_rows += 1
            if raw_length > 8000:
                gt_8k_chars += 1
            if raw_length > 16000:
                gt_16k_chars += 1

            if raw_length < min_chars:
                continue

            content, was_truncated = truncate_script(raw_content, max_chars)
            if was_truncated:
                truncated_rows += 1

            rows.append(
                {
                    "filename": row.get("Filename", ""),
                    "label": label,
                    "target_token": LABELS[label],
                    "content": content,
                    "raw_char_len": raw_length,
                    "used_char_len": len(content),
                    "was_truncated": was_truncated,
                }
            )

    if not lengths:
        raise ValueError(f"No rows found in {csv_path}")

    lengths.sort()
    summary = DatasetSummary(
        rows_total=int(sum(label_counts.values())),
        rows_used=len(rows),
        benign_total=label_counts["benign"],
        malicious_total=label_counts["malicious"],
        empty_content_rows=empty_content_rows,
        truncated_rows=truncated_rows,
        max_chars_applied=max_chars,
        min_chars_applied=min_chars,
        content_len_min=int(lengths[0]),
        content_len_p50=percentile(lengths, 0.50),
        content_len_p90=percentile(lengths, 0.90),
        content_len_p99=percentile(lengths, 0.99),
        content_len_max=int(lengths[-1]),
        gt_8k_chars=gt_8k_chars,
        gt_16k_chars=gt_16k_chars,
    )
    return pd.DataFrame(rows), summary


def make_prompt(ps_script: str) -> str:
    return (
        "You are a security classifier. Label the given PowerShell as:\n"
        "ALLOW = benign / administrative / normal usage\n"
        "BLOCK = malicious (downloading, execution, evasion, credential theft, etc.)\n\n"
        "Return ONLY one word: ALLOW or BLOCK.\n\n"
        "PowerShell:\n"
        "```powershell\n"
        f"{ps_script}\n"
        "```\n"
        "Answer:"
    )


def attach_prompts(df: pd.DataFrame) -> pd.DataFrame:
    updated = df.copy()
    updated["prompt"] = updated["content"].map(make_prompt)
    return updated


def get_indicator_tokens(
    prompt: str,
    tokenizer,
    patterns: Optional[Sequence[Union[str, Pattern[str]]]] = None,
) -> List[int]:
    """Return token positions overlapping suspicious regex matches."""
    patterns = list(patterns or SUSPICIOUS_PATTERNS)
    encoded = tokenizer(prompt, add_special_tokens=False, return_offsets_mapping=True)
    offsets = encoded["offset_mapping"]

    spans: List[Tuple[int, int]] = []
    for pattern in patterns:
        regex = re.compile(pattern, flags=re.IGNORECASE) if isinstance(pattern, str) else pattern
        spans.extend((match.start(), match.end()) for match in regex.finditer(prompt))

    if not spans:
        return []

    hits: List[int] = []
    for token_idx, (start, end) in enumerate(offsets):
        if start == end:
            continue
        if any(not (end <= span_start or start >= span_end) for span_start, span_end in spans):
            hits.append(token_idx)
    return hits


def compute_attention_scores(
    cache,
    *,
    n_layers: int,
    n_heads: int,
    indicator_positions: Sequence[int],
    layer_filter: Optional[Sequence[int]] = None,
    query_pos: int = -1,
    topk: int = 15,
    n_control_sets: int = 30,
    seed: int = SEED,
) -> pd.DataFrame:
    """Rank heads by attention to indicator positions versus random controls."""
    if not indicator_positions:
        return pd.DataFrame(columns=["layer", "head", "attention_delta"])

    pattern_zero = cache["blocks.0.attn.hook_pattern"][0]
    seq_len = pattern_zero.shape[-1]
    indicator_positions = sorted({pos for pos in indicator_positions if 0 <= pos < seq_len})
    indicator_tensor = torch.tensor(indicator_positions, dtype=torch.long)

    indicator_attn = torch.zeros((n_layers, n_heads), device="cpu")
    for layer in range(n_layers):
        pattern = cache[f"blocks.{layer}.attn.hook_pattern"][0]
        query_attention = pattern[:, query_pos, :]
        indicator_attn[layer] = query_attention[:, indicator_tensor].mean(dim=-1).detach().cpu()

    excluded = set(indicator_positions)
    pool = [idx for idx in range(seq_len) if idx not in excluded]
    if len(pool) < len(indicator_positions):
        pool = list(range(seq_len))

    rng = np.random.default_rng(seed)
    control_attn = torch.zeros_like(indicator_attn)
    for _ in range(n_control_sets):
        control_positions = rng.choice(pool, size=len(indicator_positions), replace=False).tolist()
        control_tensor = torch.tensor(control_positions, dtype=torch.long)
        for layer in range(n_layers):
            pattern = cache[f"blocks.{layer}.attn.hook_pattern"][0]
            query_attention = pattern[:, query_pos, :]
            control_attn[layer] += query_attention[:, control_tensor].mean(dim=-1).detach().cpu()

    control_attn /= float(n_control_sets)
    delta = indicator_attn - control_attn

    allowed_layers = set(layer_filter) if layer_filter is not None else None

    rows = []
    for layer in range(n_layers):
        if allowed_layers is not None and layer not in allowed_layers:
            continue
        for head in range(n_heads):
            rows.append(
                {
                    "layer": layer,
                    "head": head,
                    "attention_delta": float(delta[layer, head].item()),
                }
            )
    if not rows:
        return pd.DataFrame(columns=["layer", "head", "attention_delta"])

    result = pd.DataFrame(rows)
    return result.sort_values("attention_delta", ascending=False).head(topk).reset_index(drop=True)


def require_transformer_lens() -> None:
    if not HAS_TRANSFORMER_LENS:
        raise RuntimeError(
            "TransformerLens is required for mechanistic interpretability steps. "
            "Install `transformer_lens` before running attention, patching, or ablation experiments."
        )


def logit_diff_from_logits(logits: torch.Tensor, allow_token_id: int, block_token_id: int) -> float:
    next_token_logits = logits[0, -1]
    return float((next_token_logits[block_token_id] - next_token_logits[allow_token_id]).item())


def run_activation_patching(
    model,
    *,
    corrupted_tokens: torch.Tensor,
    clean_cache,
    candidate_heads: Iterable[Tuple[int, int]],
    base_logit_diff: float,
    allow_token_id: int,
    block_token_id: int,
) -> pd.DataFrame:
    """Patch clean head outputs into a corrupted forward pass.

    We patch at ``hook_z`` rather than ``hook_result``. For a single head this is
    equivalent up to the head-specific linear projection ``W_O``, but it avoids
    TransformerLens materializing the large per-head attention result tensor that
    triggers MPSGraph failures on this host.
    """
    require_transformer_lens()

    rows = []
    for layer, head in candidate_heads:
        hook_name = f"blocks.{layer}.attn.hook_z"
        clean_value = clean_cache[hook_name]

        def patch_fn(result, hook, *, patch_head=head, patch_value=clean_value):
            patched = result.clone()
            # Benign and malicious prompts can have different token lengths.
            # Align from the end so the answer suffix stays positionally matched.
            clean_seq = patch_value.shape[1]
            corrupt_seq = patched.shape[1]
            shared_seq = min(clean_seq, corrupt_seq)
            patched[:, -shared_seq:, patch_head, :] = patch_value[:, -shared_seq:, patch_head, :]
            return patched

        with torch.inference_mode():
            patched_logits = model.run_with_hooks(
                corrupted_tokens,
                return_type="logits",
                fwd_hooks=[(hook_name, patch_fn)],
            )
        patched_logit_diff = logit_diff_from_logits(patched_logits, allow_token_id, block_token_id)
        delta = patched_logit_diff - base_logit_diff
        rows.append(
            {
                "layer": layer,
                "head": head,
                "base_logit_diff": base_logit_diff,
                "patched_logit_diff": patched_logit_diff,
                "delta_logit_diff": delta,
                "effect_pct": (delta / abs(base_logit_diff)) * 100 if base_logit_diff else 0.0,
            }
        )
        del patched_logits
    return pd.DataFrame(rows).sort_values("delta_logit_diff")


def run_head_ablation(
    model,
    *,
    tokens: torch.Tensor,
    candidate_heads: Iterable[Tuple[int, int]],
    base_logit_diff: float,
    allow_token_id: int,
    block_token_id: int,
) -> pd.DataFrame:
    """Zero out selected attention head outputs and measure logit change.

    As with activation patching, we intervene at ``hook_z`` to avoid forcing
    TransformerLens to build ``hook_result`` tensors on MPS.
    """
    require_transformer_lens()

    rows = []
    for layer, head in candidate_heads:
        hook_name = f"blocks.{layer}.attn.hook_z"

        def ablate_fn(result, hook, *, ablate_head=head):
            patched = result.clone()
            patched[:, :, ablate_head, :] = 0.0
            return patched

        with torch.inference_mode():
            ablated_logits = model.run_with_hooks(
                tokens,
                return_type="logits",
                fwd_hooks=[(hook_name, ablate_fn)],
            )
        ablated_logit_diff = logit_diff_from_logits(ablated_logits, allow_token_id, block_token_id)
        delta = ablated_logit_diff - base_logit_diff
        rows.append(
            {
                "layer": layer,
                "head": head,
                "base_logit_diff": base_logit_diff,
                "ablated_logit_diff": ablated_logit_diff,
                "delta_logit_diff": delta,
                "effect_pct": (delta / abs(base_logit_diff)) * 100 if base_logit_diff else 0.0,
            }
        )
        del ablated_logits
    return pd.DataFrame(rows).sort_values("delta_logit_diff")


def run_layer_component_ablation(
    model,
    *,
    tokens: torch.Tensor,
    base_logit_diff: float,
    allow_token_id: int,
    block_token_id: int,
    components: Sequence[str] = ("attn", "mlp"),
) -> pd.DataFrame:
    """Zero a whole layer component and measure the logit change."""
    require_transformer_lens()

    component_to_hook = {
        "attn": "hook_attn_out",
        "mlp": "hook_mlp_out",
    }
    invalid = [component for component in components if component not in component_to_hook]
    if invalid:
        raise ValueError(f"Unsupported layer components: {invalid!r}")

    rows = []
    for layer in range(model.cfg.n_layers):
        for component in components:
            hook_name = f"blocks.{layer}.{component_to_hook[component]}"

            def ablate_fn(result, hook):
                return torch.zeros_like(result)

            with torch.inference_mode():
                ablated_logits = model.run_with_hooks(
                    tokens,
                    return_type="logits",
                    fwd_hooks=[(hook_name, ablate_fn)],
                )
            ablated_logit_diff = logit_diff_from_logits(ablated_logits, allow_token_id, block_token_id)
            delta = ablated_logit_diff - base_logit_diff
            rows.append(
                {
                    "layer": layer,
                    "component": component,
                    "base_logit_diff": base_logit_diff,
                    "ablated_logit_diff": ablated_logit_diff,
                    "delta_logit_diff": delta,
                    "effect_pct": (delta / abs(base_logit_diff)) * 100 if base_logit_diff else 0.0,
                }
            )
            del ablated_logits
    return pd.DataFrame(rows).sort_values("delta_logit_diff")


def run_layer_component_patching(
    model,
    *,
    corrupted_tokens: torch.Tensor,
    clean_cache,
    layers: Sequence[int],
    components: Sequence[str],
    base_logit_diff: float,
    allow_token_id: int,
    block_token_id: int,
) -> pd.DataFrame:
    """Patch clean layer components into a corrupted forward pass."""
    require_transformer_lens()

    component_to_hook = {
        "attn": "hook_attn_out",
        "mlp": "hook_mlp_out",
    }
    invalid = [component for component in components if component not in component_to_hook]
    if invalid:
        raise ValueError(f"Unsupported layer components: {invalid!r}")

    rows = []
    for layer in layers:
        for component in components:
            hook_name = f"blocks.{layer}.{component_to_hook[component]}"
            clean_value = clean_cache[hook_name]

            def patch_fn(result, hook, *, patch_value=clean_value):
                patched = result.clone()
                clean_seq = patch_value.shape[1]
                corrupt_seq = patched.shape[1]
                shared_seq = min(clean_seq, corrupt_seq)
                patched[:, -shared_seq:, :] = patch_value[:, -shared_seq:, :]
                return patched

            with torch.inference_mode():
                patched_logits = model.run_with_hooks(
                    corrupted_tokens,
                    return_type="logits",
                    fwd_hooks=[(hook_name, patch_fn)],
                )
            patched_logit_diff = logit_diff_from_logits(patched_logits, allow_token_id, block_token_id)
            delta = patched_logit_diff - base_logit_diff
            rows.append(
                {
                    "layer": layer,
                    "component": component,
                    "base_logit_diff": base_logit_diff,
                    "patched_logit_diff": patched_logit_diff,
                    "delta_logit_diff": delta,
                    "effect_pct": (delta / abs(base_logit_diff)) * 100 if base_logit_diff else 0.0,
                }
            )
            del patched_logits
    return pd.DataFrame(rows).sort_values("delta_logit_diff")


def parse_layer_component_list(raw_text: str) -> List[Tuple[int, str]]:
    items: List[Tuple[int, str]] = []
    for item in raw_text.split(","):
        value = item.strip()
        if not value:
            continue
        if "." not in value:
            raise ValueError(f"Layer component specification must be layer.component, got {value!r}")
        layer_text, component = value.split(".", 1)
        items.append((int(layer_text), component.strip()))
    if not items:
        raise ValueError("At least one layer.component must be specified.")
    return items


def build_residual_hook_name(layer: int, resid_kind: str) -> str:
    resid_kind = resid_kind.strip().lower()
    kind_to_hook = {
        "pre": "hook_resid_pre",
        "mid": "hook_resid_mid",
        "post": "hook_resid_post",
    }
    if resid_kind not in kind_to_hook:
        raise ValueError(f"Unsupported residual kind: {resid_kind!r}")
    return f"blocks.{layer}.{kind_to_hook[resid_kind]}"


def run_multi_path_patching(
    model,
    *,
    corrupted_tokens: torch.Tensor,
    clean_cache,
    base_logit_diff: float,
    allow_token_id: int,
    block_token_id: int,
    head_specs: Optional[Sequence[Tuple[int, int]]] = None,
    component_specs: Optional[Sequence[Tuple[int, str]]] = None,
    residual_specs: Optional[Sequence[Tuple[int, str]]] = None,
) -> Dict[str, object]:
    """Patch multiple hooks together from a clean cache into a corrupted run."""
    require_transformer_lens()

    fwd_hooks = []
    label_parts: List[str] = []

    for layer, head in head_specs or []:
        hook_name = f"blocks.{layer}.attn.hook_z"
        clean_value = clean_cache[hook_name]

        def patch_head_fn(result, hook, *, patch_head=head, patch_value=clean_value):
            patched = result.clone()
            clean_seq = patch_value.shape[1]
            corrupt_seq = patched.shape[1]
            shared_seq = min(clean_seq, corrupt_seq)
            patched[:, -shared_seq:, patch_head, :] = patch_value[:, -shared_seq:, patch_head, :]
            return patched

        fwd_hooks.append((hook_name, patch_head_fn))
        label_parts.append(f"h{layer}.{head}")

    component_to_hook = {
        "attn": "hook_attn_out",
        "mlp": "hook_mlp_out",
    }
    for layer, component in component_specs or []:
        component = component.strip()
        if component not in component_to_hook:
            raise ValueError(f"Unsupported component: {component!r}")
        hook_name = f"blocks.{layer}.{component_to_hook[component]}"
        clean_value = clean_cache[hook_name]

        def patch_component_fn(result, hook, *, patch_value=clean_value):
            patched = result.clone()
            clean_seq = patch_value.shape[1]
            corrupt_seq = patched.shape[1]
            shared_seq = min(clean_seq, corrupt_seq)
            patched[:, -shared_seq:, :] = patch_value[:, -shared_seq:, :]
            return patched

        fwd_hooks.append((hook_name, patch_component_fn))
        label_parts.append(f"{component}{layer}")

    for layer, resid_kind in residual_specs or []:
        hook_name = build_residual_hook_name(layer, resid_kind)
        clean_value = clean_cache[hook_name]

        def patch_resid_fn(result, hook, *, patch_value=clean_value):
            patched = result.clone()
            clean_seq = patch_value.shape[1]
            corrupt_seq = patched.shape[1]
            shared_seq = min(clean_seq, corrupt_seq)
            patched[:, -shared_seq:, :] = patch_value[:, -shared_seq:, :]
            return patched

        fwd_hooks.append((hook_name, patch_resid_fn))
        label_parts.append(f"resid_{resid_kind}{layer}")

    if not fwd_hooks:
        raise ValueError("At least one patch specification is required.")

    with torch.inference_mode():
        patched_logits = model.run_with_hooks(
            corrupted_tokens,
            return_type="logits",
            fwd_hooks=fwd_hooks,
        )
    patched_logit_diff = logit_diff_from_logits(patched_logits, allow_token_id, block_token_id)
    delta = patched_logit_diff - base_logit_diff
    del patched_logits
    return {
        "patch_label": "+".join(label_parts),
        "base_logit_diff": base_logit_diff,
        "patched_logit_diff": patched_logit_diff,
        "delta_logit_diff": delta,
        "effect_pct": (delta / abs(base_logit_diff)) * 100 if base_logit_diff else 0.0,
    }


def run_multi_head_ablation(
    model,
    *,
    tokens: torch.Tensor,
    head_specs: Sequence[Tuple[int, int]],
    base_logit_diff: float,
    allow_token_id: int,
    block_token_id: int,
) -> Dict[str, object]:
    """Zero multiple attention heads together and measure logit change."""
    require_transformer_lens()
    if not head_specs:
        raise ValueError("At least one head must be provided for grouped head ablation.")

    hooks_by_name: Dict[str, List[int]] = {}
    label_parts: List[str] = []
    for layer, head in head_specs:
        hook_name = f"blocks.{layer}.attn.hook_z"
        hooks_by_name.setdefault(hook_name, []).append(head)
        label_parts.append(f"h{layer}.{head}")

    fwd_hooks = []
    for hook_name, heads in hooks_by_name.items():
        unique_heads = tuple(sorted(set(heads)))

        def ablate_fn(result, hook, *, ablate_heads=unique_heads):
            patched = result.clone()
            for ablate_head in ablate_heads:
                patched[:, :, ablate_head, :] = 0.0
            return patched

        fwd_hooks.append((hook_name, ablate_fn))

    with torch.inference_mode():
        ablated_logits = model.run_with_hooks(
            tokens,
            return_type="logits",
            fwd_hooks=fwd_hooks,
        )
    ablated_logit_diff = logit_diff_from_logits(ablated_logits, allow_token_id, block_token_id)
    delta = ablated_logit_diff - base_logit_diff
    del ablated_logits
    return {
        "ablation_label": "+".join(label_parts),
        "base_logit_diff": base_logit_diff,
        "ablated_logit_diff": ablated_logit_diff,
        "delta_logit_diff": delta,
        "effect_pct": (delta / abs(base_logit_diff)) * 100 if base_logit_diff else 0.0,
    }


def compute_residual_subspace(
    deltas: torch.Tensor,
    *,
    max_rank: int,
) -> Tuple[torch.Tensor, List[float]]:
    """Compute a low-rank basis from stacked residual-delta vectors."""
    if deltas.ndim != 2:
        raise ValueError("Residual delta tensor must be [n_samples, d_model].")
    deltas = deltas.to(dtype=torch.float32)
    n_samples, d_model = deltas.shape
    rank = max(1, min(max_rank, n_samples, d_model))
    centered = deltas - deltas.mean(dim=0, keepdim=True)
    _, singular_values, vh = torch.linalg.svd(centered, full_matrices=False)
    basis = vh[:rank].T.contiguous()
    singular_energy = singular_values.square()
    total_energy = float(singular_energy.sum().item()) if len(singular_energy) else 0.0
    explained = []
    running = 0.0
    for value in singular_energy[:rank]:
        running += float(value.item())
        explained.append((running / total_energy) if total_energy else 0.0)
    return basis, explained


def orthonormalize_named_vectors(
    named_vectors: Sequence[Tuple[str, torch.Tensor]],
    *,
    min_norm: float = 1e-8,
) -> Tuple[torch.Tensor, List[str]]:
    columns: List[torch.Tensor] = []
    labels: List[str] = []
    for label, raw_vector in named_vectors:
        vector = raw_vector.detach().to(dtype=torch.float32, device="cpu").clone()
        for existing in columns:
            vector = vector - torch.dot(vector, existing) * existing
        norm = float(vector.norm().item())
        if norm <= min_norm:
            continue
        columns.append(vector / norm)
        labels.append(label)

    if not columns:
        raise ValueError("No non-degenerate residual directions were available.")
    basis = torch.stack(columns, dim=1).contiguous()
    return basis, labels


def compute_contrastive_residual_basis(
    deltas: torch.Tensor,
    *,
    logit_dir: torch.Tensor,
) -> Tuple[torch.Tensor, List[str], Dict[str, float]]:
    """Build a small orthonormal basis from task-relevant residual directions."""
    if deltas.ndim != 2:
        raise ValueError("Residual delta tensor must be [n_samples, d_model].")
    deltas = deltas.to(dtype=torch.float32, device="cpu")
    mean_delta = deltas.mean(dim=0)
    logit_dir = logit_dir.detach().to(dtype=torch.float32, device="cpu")
    basis, labels = orthonormalize_named_vectors(
        [
            ("mean_delta", mean_delta),
            ("logit_readout", logit_dir),
        ]
    )

    mean_norm = float(mean_delta.norm().item())
    logit_norm = float(logit_dir.norm().item())
    if mean_norm > 0.0 and logit_norm > 0.0:
        cosine = float(torch.dot(mean_delta / mean_norm, logit_dir / logit_norm).item())
    else:
        cosine = 0.0

    diagnostics = {
        "mean_delta_norm": mean_norm,
        "logit_dir_norm": logit_norm,
        "mean_delta_logit_dir_cosine": cosine,
    }
    return basis, labels, diagnostics


def run_named_residual_basis_patching(
    model,
    *,
    corrupted_tokens: torch.Tensor,
    clean_cache,
    layer: int,
    resid_kind: str,
    basis: torch.Tensor,
    patch_label: str,
    base_logit_diff: float,
    allow_token_id: int,
    block_token_id: int,
) -> Dict[str, object]:
    """Patch only the clean projection inside a specified residual basis."""
    require_transformer_lens()

    hook_name = build_residual_hook_name(layer, resid_kind)
    clean_value = clean_cache[hook_name]

    def patch_fn(result, hook, *, patch_value=clean_value, patch_basis=basis):
        patched = result.clone()
        clean_last = patch_value[:, -1, :]
        corrupt_last = patched[:, -1, :]
        clean_proj = (clean_last @ patch_basis) @ patch_basis.T
        corrupt_proj = (corrupt_last @ patch_basis) @ patch_basis.T
        patched[:, -1, :] = corrupt_last - corrupt_proj + clean_proj
        return patched

    with torch.inference_mode():
        patched_logits = model.run_with_hooks(
            corrupted_tokens,
            return_type="logits",
            fwd_hooks=[(hook_name, patch_fn)],
        )
    patched_logit_diff = logit_diff_from_logits(patched_logits, allow_token_id, block_token_id)
    delta = patched_logit_diff - base_logit_diff
    del patched_logits
    return {
        "patch_label": patch_label,
        "layer": layer,
        "resid_kind": resid_kind,
        "subspace_dim": int(basis.shape[1]),
        "base_logit_diff": base_logit_diff,
        "patched_logit_diff": patched_logit_diff,
        "delta_logit_diff": delta,
        "effect_pct": (delta / abs(base_logit_diff)) * 100 if base_logit_diff else 0.0,
    }


def run_residual_subspace_patching(
    model,
    *,
    corrupted_tokens: torch.Tensor,
    clean_cache,
    layer: int,
    resid_kind: str,
    basis: torch.Tensor,
    subspace_dim: int,
    base_logit_diff: float,
    allow_token_id: int,
    block_token_id: int,
) -> Dict[str, object]:
    """Patch only the benign projection inside a learned residual subspace."""
    return run_named_residual_basis_patching(
        model,
        corrupted_tokens=corrupted_tokens,
        clean_cache=clean_cache,
        layer=layer,
        resid_kind=resid_kind,
        basis=basis[:, :subspace_dim],
        patch_label=f"subspace_{resid_kind}{layer}_k{subspace_dim}",
        base_logit_diff=base_logit_diff,
        allow_token_id=allow_token_id,
        block_token_id=block_token_id,
    )


def run_neuron_ablation(
    model,
    *,
    tokens: torch.Tensor,
    layer: int,
    neurons: Sequence[int],
    base_logit_diff: float,
    allow_token_id: int,
    block_token_id: int,
) -> pd.DataFrame:
    """Zero selected MLP neurons at hook_post and measure logit change."""
    require_transformer_lens()

    hook_name = f"blocks.{layer}.mlp.hook_post"
    rows = []
    for neuron in neurons:
        def ablate_fn(result, hook, *, ablate_neuron=neuron):
            patched = result.clone()
            patched[:, :, ablate_neuron] = 0.0
            return patched

        with torch.inference_mode():
            ablated_logits = model.run_with_hooks(
                tokens,
                return_type="logits",
                fwd_hooks=[(hook_name, ablate_fn)],
            )
        ablated_logit_diff = logit_diff_from_logits(ablated_logits, allow_token_id, block_token_id)
        delta = ablated_logit_diff - base_logit_diff
        rows.append(
            {
                "layer": layer,
                "neuron": neuron,
                "base_logit_diff": base_logit_diff,
                "ablated_logit_diff": ablated_logit_diff,
                "delta_logit_diff": delta,
                "effect_pct": (delta / abs(base_logit_diff)) * 100 if base_logit_diff else 0.0,
            }
        )
        del ablated_logits
    return pd.DataFrame(rows).sort_values("delta_logit_diff")


def run_neuron_group_ablation(
    model,
    *,
    tokens: torch.Tensor,
    layer: int,
    neurons: Sequence[int],
    base_logit_diff: float,
    allow_token_id: int,
    block_token_id: int,
) -> Dict[str, object]:
    """Zero a group of MLP neurons at hook_post and measure the logit change."""
    require_transformer_lens()

    hook_name = f"blocks.{layer}.mlp.hook_post"
    neuron_list = sorted({int(neuron) for neuron in neurons})

    def ablate_fn(result, hook, *, ablate_neurons=neuron_list):
        patched = result.clone()
        patched[:, :, ablate_neurons] = 0.0
        return patched

    with torch.inference_mode():
        ablated_logits = model.run_with_hooks(
            tokens,
            return_type="logits",
            fwd_hooks=[(hook_name, ablate_fn)],
        )
    ablated_logit_diff = logit_diff_from_logits(ablated_logits, allow_token_id, block_token_id)
    delta = ablated_logit_diff - base_logit_diff
    del ablated_logits
    return {
        "layer": layer,
        "group_size": len(neuron_list),
        "neurons": ",".join(str(neuron) for neuron in neuron_list),
        "base_logit_diff": base_logit_diff,
        "ablated_logit_diff": ablated_logit_diff,
        "delta_logit_diff": delta,
        "effect_pct": (delta / abs(base_logit_diff)) * 100 if base_logit_diff else 0.0,
    }


def generate_obfuscations(script: str) -> List[Dict[str, str]]:
    """Return conservative formatting variants for robustness bookkeeping.

    This intentionally excludes token-splitting, encoding, or string
    reconstruction transforms that would meaningfully facilitate malware evasion.
    """
    stripped = script.strip()
    collapsed_blank_lines = re.sub(r"\n{3,}", "\n\n", stripped)
    normalized_whitespace = re.sub(r"[ \t]+", " ", collapsed_blank_lines)
    single_line = re.sub(r"\s*\n\s*", " ", collapsed_blank_lines)

    seen = set()
    outputs = []
    for technique, text in [
        ("identity", stripped),
        ("collapse_blank_lines", collapsed_blank_lines),
        ("normalize_inline_whitespace", normalized_whitespace),
        ("single_line_layout", single_line),
    ]:
        if text and text not in seen:
            outputs.append({"technique": technique, "content": text})
            seen.add(text)
    return outputs


def build_augmented_pair_manifest(
    manifest: pd.DataFrame,
    *,
    include_original: bool = True,
    techniques: Optional[Sequence[str]] = None,
    max_augmented_variants_per_pair: Optional[int] = None,
) -> Tuple[pd.DataFrame, Dict[str, object]]:
    if not {"pair_idx", "pair_role", "content"}.issubset(manifest.columns):
        raise ValueError("Manifest must contain pair_idx, pair_role, and content columns.")

    allowed_techniques = set(techniques) if techniques else None
    rows: List[Dict[str, object]] = []
    technique_counts: Dict[str, int] = {}
    seen_pair_payloads: set[Tuple[str, str]] = set()
    next_pair_idx = 1
    source_pairs = select_explicit_pairs(manifest)

    def make_variant_filename(filename: str, technique: str) -> str:
        stem = Path(str(filename or "sample")).stem
        suffix = Path(str(filename or "sample")).suffix or ".ps1"
        safe_technique = re.sub(r"[^A-Za-z0-9]+", "_", technique).strip("_") or "variant"
        return f"{stem}__{safe_technique}{suffix}"

    def add_pair(
        benign_row: pd.Series,
        malicious_row: pd.Series,
        *,
        benign_content: str,
        malicious_content: str,
        technique: str,
        variant_rank: int,
    ) -> None:
        nonlocal next_pair_idx
        payload_key = (benign_content, malicious_content)
        if payload_key in seen_pair_payloads:
            return
        seen_pair_payloads.add(payload_key)

        benign_entry = dict(benign_row)
        malicious_entry = dict(malicious_row)
        benign_entry["content"] = benign_content
        malicious_entry["content"] = malicious_content
        benign_entry["raw_char_len"] = len(benign_content)
        benign_entry["used_char_len"] = len(benign_content)
        malicious_entry["raw_char_len"] = len(malicious_content)
        malicious_entry["used_char_len"] = len(malicious_content)
        benign_entry["was_truncated"] = False
        malicious_entry["was_truncated"] = False
        benign_entry["pair_idx"] = next_pair_idx
        malicious_entry["pair_idx"] = next_pair_idx
        benign_entry["pair_role"] = "benign"
        malicious_entry["pair_role"] = "malicious"
        benign_entry["parent_pair_idx"] = int(benign_row["pair_idx"])
        malicious_entry["parent_pair_idx"] = int(malicious_row["pair_idx"])
        benign_entry["augmentation_technique"] = technique
        malicious_entry["augmentation_technique"] = technique
        benign_entry["augmentation_rank"] = variant_rank
        malicious_entry["augmentation_rank"] = variant_rank
        benign_entry["parent_filename"] = str(benign_row.get("filename", ""))
        malicious_entry["parent_filename"] = str(malicious_row.get("filename", ""))
        benign_entry["filename"] = make_variant_filename(benign_row.get("filename", ""), technique)
        malicious_entry["filename"] = make_variant_filename(malicious_row.get("filename", ""), technique)
        benign_entry["source"] = "generated_obfuscation" if technique != "identity" else benign_entry.get("source", "natural_overlap")
        malicious_entry["source"] = "generated_obfuscation" if technique != "identity" else malicious_entry.get("source", "natural_overlap")
        rows.extend([benign_entry, malicious_entry])
        technique_counts[technique] = technique_counts.get(technique, 0) + 1
        next_pair_idx += 1

    for benign_row, malicious_row in source_pairs:
        benign_variants = {item["technique"]: item["content"] for item in generate_obfuscations(str(benign_row["content"]))}
        malicious_variants = {
            item["technique"]: item["content"] for item in generate_obfuscations(str(malicious_row["content"]))
        }
        common_techniques = [technique for technique in benign_variants if technique in malicious_variants]
        if allowed_techniques is not None:
            common_techniques = [technique for technique in common_techniques if technique in allowed_techniques]

        if include_original and "identity" in benign_variants and "identity" in malicious_variants:
            add_pair(
                benign_row,
                malicious_row,
                benign_content=benign_variants["identity"],
                malicious_content=malicious_variants["identity"],
                technique="identity",
                variant_rank=0,
            )

        variant_count = 0
        for technique in common_techniques:
            if technique == "identity":
                continue
            if technique != "identity" and max_augmented_variants_per_pair is not None:
                if variant_count >= max_augmented_variants_per_pair:
                    break
                variant_count += 1
            add_pair(
                benign_row,
                malicious_row,
                benign_content=benign_variants[technique],
                malicious_content=malicious_variants[technique],
                technique=technique,
                variant_rank=0 if technique == "identity" else variant_count,
            )

    augmented_df = pd.DataFrame(rows)
    if augmented_df.empty:
        raise RuntimeError("No augmented pairs were generated from the input manifest.")

    metadata = {
        "source_pairs": int(len(source_pairs)),
        "rows_total": int(len(augmented_df)),
        "num_pairs": int(augmented_df["pair_idx"].nunique()),
        "include_original": bool(include_original),
        "technique_counts": technique_counts,
        "generated_pairs": int(sum(count for tech, count in technique_counts.items() if tech != "identity")),
    }
    return augmented_df, metadata


def summarize_indicator_matches(df: pd.DataFrame, patterns: Optional[Sequence[str]] = None) -> Dict[str, int]:
    patterns = list(patterns or SUSPICIOUS_PATTERNS)
    compiled = [re.compile(pattern, flags=re.IGNORECASE) for pattern in patterns]
    counts = {pattern: 0 for pattern in patterns}

    for content in df["content"]:
        for pattern, regex in zip(patterns, compiled):
            if regex.search(content):
                counts[pattern] += 1
    return counts


def count_indicator_occurrences(text: str, patterns: Optional[Sequence[str]] = None) -> int:
    patterns = list(patterns or SUSPICIOUS_PATTERNS)
    return sum(len(re.findall(pattern, text, flags=re.IGNORECASE)) for pattern in patterns)


def add_analysis_features(df: pd.DataFrame) -> pd.DataFrame:
    enriched = df.copy()
    enriched["indicator_count"] = enriched["content"].map(count_indicator_occurrences)
    enriched["has_indicator"] = enriched["indicator_count"] > 0
    enriched["length_bucket"] = pd.cut(
        enriched["used_char_len"],
        bins=[0, 256, 1024, 4096, 12000, np.inf],
        labels=["xs", "s", "m", "l", "xl"],
        include_lowest=True,
        right=False,
    ).astype(str)
    enriched["indicator_bucket"] = np.where(
        enriched["indicator_count"] == 0,
        "zero",
        np.where(enriched["indicator_count"] == 1, "one", "multi"),
    )
    return enriched


def get_matching_patterns(text: str, patterns: Optional[Sequence[str]] = None) -> List[str]:
    matches: List[str] = []
    for pattern in patterns or SUSPICIOUS_PATTERNS:
        if re.search(pattern, text or "", flags=re.IGNORECASE):
            matches.append(pattern)
    return matches


def display_indicator_names(patterns: Sequence[str]) -> List[str]:
    return [PATTERN_DISPLAY_NAMES.get(pattern, pattern) for pattern in patterns]


def choose_primary_indicator(patterns: Sequence[str], counts_by_pattern: Dict[str, int]) -> str:
    if not patterns:
        return ""
    chosen = min(patterns, key=lambda pattern: (counts_by_pattern.get(pattern, 0), pattern))
    return PATTERN_DISPLAY_NAMES.get(chosen, chosen)


def select_malicious_match_pool(
    malicious_df: pd.DataFrame,
    *,
    target_size: int,
    target_pattern_counts: Dict[str, int],
    malicious_pattern_counts: Dict[str, int],
) -> pd.DataFrame:
    if target_size <= 0:
        return malicious_df.iloc[0:0].copy()

    remaining = {pattern: int(count) for pattern, count in target_pattern_counts.items()}
    pool = malicious_df.to_dict(orient="records")
    selected_rows: List[Dict[str, object]] = []

    while pool and len(selected_rows) < target_size:
        best_idx = None
        best_key = None

        for idx, row in enumerate(pool):
            patterns = row["matched_patterns_list"]
            weighted_coverage = sum(
                remaining.get(pattern, 0) / max(malicious_pattern_counts.get(pattern, 1), 1)
                for pattern in patterns
                if remaining.get(pattern, 0) > 0
            )
            raw_coverage = sum(remaining.get(pattern, 0) for pattern in patterns)
            key = (
                weighted_coverage,
                raw_coverage,
                -int(row["used_char_len"]),
            )
            if best_key is None or key > best_key:
                best_idx = idx
                best_key = key

        assert best_idx is not None
        chosen = pool.pop(best_idx)
        selected_rows.append(chosen)
        for pattern in chosen["matched_patterns_list"]:
            if pattern in remaining and remaining[pattern] > 0:
                remaining[pattern] -= 1

    return pd.DataFrame(selected_rows)


def build_circuit_val_set(
    df: pd.DataFrame,
    *,
    target_total: int = 300,
    patterns: Optional[Sequence[str]] = None,
) -> Tuple[pd.DataFrame, Dict[str, object]]:
    pattern_order = list(patterns or SUSPICIOUS_PATTERNS)

    eligible_patterns: List[str] = []
    overlap_counts: Dict[str, Dict[str, int]] = {}
    for pattern in pattern_order:
        mask = df["content"].str.contains(pattern, case=False, regex=True, na=False)
        counts = df[mask]["label"].value_counts().to_dict()
        if counts.get("benign", 0) > 0 and counts.get("malicious", 0) > 0:
            eligible_patterns.append(pattern)
            overlap_counts[PATTERN_DISPLAY_NAMES.get(pattern, pattern)] = {
                "benign": int(counts.get("benign", 0)),
                "malicious": int(counts.get("malicious", 0)),
            }

    if not eligible_patterns:
        raise RuntimeError("No indicator families appear in both benign and malicious classes.")

    enriched = df.copy()
    enriched["matched_patterns_list"] = enriched["content"].map(
        lambda text: get_matching_patterns(text, patterns=eligible_patterns)
    )
    enriched = enriched[enriched["matched_patterns_list"].map(bool)].copy()
    if enriched.empty:
        raise RuntimeError("No rows matched the eligible cross-class indicator families.")

    global_pattern_counts = {
        pattern: int(
            enriched["matched_patterns_list"].map(lambda items, p=pattern: p in items).sum()
        )
        for pattern in eligible_patterns
    }
    malicious_pattern_counts = {
        pattern: int(
            enriched[enriched["label"] == "malicious"]["matched_patterns_list"]
            .map(lambda items, p=pattern: p in items)
            .sum()
        )
        for pattern in eligible_patterns
    }

    benign_candidates = enriched[enriched["label"] == "benign"].copy()
    malicious_candidates = enriched[enriched["label"] == "malicious"].copy()
    target_per_class = min(target_total // 2, len(benign_candidates), len(malicious_candidates))
    if target_per_class == 0:
        raise RuntimeError("Not enough cross-class indicator-bearing samples to build a balanced set.")

    if len(benign_candidates) <= target_per_class:
        benign_selected = benign_candidates.copy()
    else:
        benign_selected = (
            benign_candidates.sort_values(["used_char_len", "filename"]).head(target_per_class).copy()
        )

    target_pattern_counts: Dict[str, int] = {}
    for pattern in eligible_patterns:
        target_pattern_counts[pattern] = int(
            benign_selected["matched_patterns_list"].map(lambda items, p=pattern: p in items).sum()
        )

    malicious_selected = select_malicious_match_pool(
        malicious_candidates,
        target_size=len(benign_selected),
        target_pattern_counts=target_pattern_counts,
        malicious_pattern_counts=malicious_pattern_counts,
    )

    selected = pd.concat([benign_selected, malicious_selected], ignore_index=True)
    selected["matched_indicators"] = selected["matched_patterns_list"].map(
        lambda items: "|".join(display_indicator_names(items))
    )
    selected["primary_indicator"] = selected["matched_patterns_list"].map(
        lambda items: choose_primary_indicator(items, global_pattern_counts)
    )
    selected["source"] = "natural_overlap"
    selected["circuit_val_version"] = "v1"

    output_columns = [
        "filename",
        "label",
        "source",
        "primary_indicator",
        "matched_indicators",
        "indicator_count",
        "has_indicator",
        "raw_char_len",
        "used_char_len",
        "was_truncated",
        "content",
    ]
    selected = add_analysis_features(selected)
    selected = selected.sort_values(["label", "primary_indicator", "used_char_len", "filename"]).reset_index(drop=True)
    output_df = selected[output_columns].copy()

    benign_pattern_coverage = {
        PATTERN_DISPLAY_NAMES.get(pattern, pattern): int(
            benign_selected["matched_patterns_list"].map(lambda items, p=pattern: p in items).sum()
        )
        for pattern in eligible_patterns
    }
    malicious_pattern_coverage = {
        PATTERN_DISPLAY_NAMES.get(pattern, pattern): int(
            malicious_selected["matched_patterns_list"].map(lambda items, p=pattern: p in items).sum()
        )
        for pattern in eligible_patterns
    }

    metadata = {
        "target_total_requested": int(target_total),
        "rows_total": int(len(output_df)),
        "per_class": output_df["label"].value_counts().sort_index().to_dict(),
        "eligible_indicator_overlap_counts": overlap_counts,
        "selected_benign_indicator_coverage": benign_pattern_coverage,
        "selected_malicious_indicator_coverage": malicious_pattern_coverage,
        "generation_needed": bool(len(output_df) < min(target_total, 200)),
        "selection_strategy": "all available benign overlap rows plus greedy malicious coverage matching",
    }
    return output_df, metadata


def build_indicator_pair_manifest(
    df: pd.DataFrame,
    *,
    indicator_column: str = "primary_indicator",
    max_pairs: Optional[int] = None,
    per_indicator_cap: Optional[int] = None,
    pairing_mode: str = "zip",
) -> pd.DataFrame:
    if indicator_column not in df.columns:
        raise ValueError(f"Missing indicator column {indicator_column!r} in input dataframe.")
    if pairing_mode not in {"zip", "all-combinations"}:
        raise ValueError(f"Unsupported pairing_mode: {pairing_mode!r}")

    pair_rows: List[Dict[str, object]] = []
    pair_idx = 1
    for indicator_value, group in df.groupby(indicator_column, sort=True):
        benign_rows = (
            group[group["label"] == "benign"]
            .sort_values(["used_char_len", "filename"])
            .reset_index(drop=True)
        )
        malicious_rows = (
            group[group["label"] == "malicious"]
            .sort_values(["used_char_len", "filename"])
            .reset_index(drop=True)
        )

        candidate_pairs: List[Tuple[pd.Series, pd.Series]] = []
        if pairing_mode == "zip":
            pair_count = min(len(benign_rows), len(malicious_rows))
            if per_indicator_cap is not None:
                pair_count = min(pair_count, per_indicator_cap)
            candidate_pairs = [
                (benign_rows.iloc[idx], malicious_rows.iloc[idx])
                for idx in range(pair_count)
            ]
        else:
            for benign_idx in range(len(benign_rows)):
                for malicious_idx in range(len(malicious_rows)):
                    candidate_pairs.append((benign_rows.iloc[benign_idx], malicious_rows.iloc[malicious_idx]))
            candidate_pairs.sort(
                key=lambda pair: (
                    abs(int(pair[0]["used_char_len"]) - int(pair[1]["used_char_len"])),
                    int(pair[0]["used_char_len"]) + int(pair[1]["used_char_len"]),
                    str(pair[0]["filename"]),
                    str(pair[1]["filename"]),
                )
            )
            if per_indicator_cap is not None:
                candidate_pairs = candidate_pairs[:per_indicator_cap]

        for benign_source, malicious_source in candidate_pairs:
            benign_entry = dict(benign_source)
            benign_entry["pair_idx"] = pair_idx
            benign_entry["pair_role"] = "benign"
            benign_entry["pair_indicator"] = indicator_value

            malicious_entry = dict(malicious_source)
            malicious_entry["pair_idx"] = pair_idx
            malicious_entry["pair_role"] = "malicious"
            malicious_entry["pair_indicator"] = indicator_value

            pair_rows.extend([benign_entry, malicious_entry])
            pair_idx += 1

            if max_pairs is not None and (pair_idx - 1) >= max_pairs:
                return pd.DataFrame(pair_rows)

    return pd.DataFrame(pair_rows)


def build_balanced_manifest(df: pd.DataFrame, *, per_label: int, seed: int = SEED) -> pd.DataFrame:
    """Sample a diverse, balanced manifest for tractable MI experiments."""
    rng = random.Random(seed)
    enriched = add_analysis_features(df)
    selected_frames: List[pd.DataFrame] = []

    for label in ["benign", "malicious"]:
        label_df = enriched[enriched["label"] == label].copy()
        groups: List[deque] = []

        for _, group in label_df.groupby(["length_bucket", "indicator_bucket"], sort=True, dropna=False):
            rows = group.sample(frac=1.0, random_state=seed).to_dict(orient="records")
            if rows:
                groups.append(deque(rows))

        rng.shuffle(groups)
        chosen: List[Dict[str, object]] = []
        while groups and len(chosen) < per_label:
            next_groups: List[deque] = []
            for group_queue in groups:
                if group_queue and len(chosen) < per_label:
                    chosen.append(group_queue.popleft())
                if group_queue:
                    next_groups.append(group_queue)
            groups = next_groups
            rng.shuffle(groups)

        selected_frames.append(pd.DataFrame(chosen))

    manifest = pd.concat(selected_frames, ignore_index=True)
    manifest["manifest_seed"] = seed
    manifest["manifest_rank"] = manifest.groupby("label").cumcount() + 1
    return manifest.sort_values(["label", "manifest_rank"]).reset_index(drop=True)


def resolve_model_source(model_name: str) -> Tuple[str, bool]:
    """Prefer a cached Hugging Face snapshot when available."""
    if "/" not in model_name:
        return model_name, False

    org, repo = model_name.split("/", 1)
    cache_dir = HF_CACHE_DIR / f"models--{org}--{repo}"
    ref_file = cache_dir / "refs" / "main"
    if ref_file.exists():
        revision = ref_file.read_text(encoding="utf-8").strip()
        snapshot_dir = cache_dir / "snapshots" / revision
        if snapshot_dir.exists():
            return str(snapshot_dir), True
    return model_name, False


def resolve_torch_dtype(torch_dtype: Optional[str]):
    dtype_map = {
        None: None,
        "float16": torch.float16,
        "bfloat16": torch.bfloat16,
        "float32": torch.float32,
    }
    return dtype_map[torch_dtype]


def load_hf_model_and_tokenizer(
    model_name: str = DEFAULT_MODEL_NAME,
    *,
    device: Optional[str] = None,
    torch_dtype: Optional[str] = None,
):
    model_source, local_files_only = resolve_model_source(model_name)
    tokenizer = AutoTokenizer.from_pretrained(
        model_source,
        use_fast=True,
        trust_remote_code=True,
        local_files_only=local_files_only,
    )
    tokenizer.padding_side = "left"
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    resolved_device = device or ("mps" if torch.backends.mps.is_available() else "cpu")
    resolved_dtype = resolve_torch_dtype(torch_dtype)
    model = AutoModelForCausalLM.from_pretrained(
        model_source,
        torch_dtype=resolved_dtype,
        trust_remote_code=True,
        local_files_only=local_files_only,
    )
    model.to(resolved_device)
    model.eval()
    return model, tokenizer, resolved_device


def build_hooked_transformer(
    hf_model,
    tokenizer,
    *,
    device: str,
    torch_dtype: Optional[str],
    template_name: str,
    first_n_layers: Optional[int] = None,
    use_attn_result: bool = False,
):
    require_transformer_lens()
    model = HookedTransformer.from_pretrained(
        template_name,
        hf_model=hf_model,
        tokenizer=tokenizer,
        device=device,
        dtype=resolve_torch_dtype(torch_dtype) or torch.float32,
        fold_ln=False,
        center_unembed=False,
        center_writing_weights=False,
        first_n_layers=first_n_layers,
    )
    model.set_use_attn_result(use_attn_result)
    return model


def select_manifest_pair(manifest: pd.DataFrame, benign_rank: int, malicious_rank: int) -> Tuple[pd.Series, pd.Series]:
    benign_rows = manifest[manifest["label"] == "benign"].sort_values("manifest_rank").reset_index(drop=True)
    malicious_rows = manifest[manifest["label"] == "malicious"].sort_values("manifest_rank").reset_index(drop=True)
    if benign_rank >= len(benign_rows) or malicious_rank >= len(malicious_rows):
        raise IndexError("Requested manifest rank is out of bounds.")
    return benign_rows.iloc[benign_rank], malicious_rows.iloc[malicious_rank]


def select_explicit_pairs(manifest: pd.DataFrame) -> List[Tuple[pd.Series, pd.Series]]:
    if not {"pair_idx", "pair_role"}.issubset(manifest.columns):
        return []

    pairs: List[Tuple[pd.Series, pd.Series]] = []
    for _, group in manifest.groupby("pair_idx", sort=True):
        if {"benign", "malicious"} - set(group["pair_role"].tolist()):
            continue
        benign_row = group[group["pair_role"] == "benign"].iloc[0]
        malicious_row = group[group["pair_role"] == "malicious"].iloc[0]
        pairs.append((benign_row, malicious_row))
    return pairs


def select_explicit_pair_by_id(manifest: pd.DataFrame, pair_idx: int) -> Tuple[pd.Series, pd.Series]:
    if not {"pair_idx", "pair_role"}.issubset(manifest.columns):
        raise ValueError("Manifest must contain pair_idx and pair_role columns.")

    group = manifest[manifest["pair_idx"] == pair_idx]
    if group.empty:
        raise IndexError(f"Requested pair_idx {pair_idx} is out of bounds.")

    roles = set(group["pair_role"].tolist())
    if {"benign", "malicious"} - roles:
        raise RuntimeError(f"pair_idx {pair_idx} does not contain both benign and malicious rows.")

    benign_row = group[group["pair_role"] == "benign"].iloc[0]
    malicious_row = group[group["pair_role"] == "malicious"].iloc[0]
    return benign_row, malicious_row


def resolve_pair_idx(
    benign_row: pd.Series,
    malicious_row: pd.Series,
    *,
    fallback_idx: int,
) -> int:
    for row in (benign_row, malicious_row):
        pair_idx = optional_int_field(row, "pair_idx")
        if pair_idx is not None:
            return pair_idx
    return fallback_idx


def select_short_pairs(
    manifest: pd.DataFrame,
    *,
    num_pairs: int,
    malicious_requires_indicator: bool = True,
) -> List[Tuple[pd.Series, pd.Series]]:
    explicit_pairs = select_explicit_pairs(manifest)
    if explicit_pairs:
        if malicious_requires_indicator and "indicator_count" in manifest.columns:
            explicit_pairs = [
                (benign_row, malicious_row)
                for benign_row, malicious_row in explicit_pairs
                if int(malicious_row.get("indicator_count", 0)) > 0
            ]
        return explicit_pairs[:num_pairs]

    benign_rows = (
        manifest[manifest["label"] == "benign"]
        .sort_values(["used_char_len", "manifest_rank"])
        .reset_index(drop=True)
    )
    malicious_df = manifest[manifest["label"] == "malicious"]
    if malicious_requires_indicator and "indicator_count" in malicious_df.columns:
        malicious_df = malicious_df[malicious_df["indicator_count"] > 0]
    malicious_rows = malicious_df.sort_values(["used_char_len", "manifest_rank"]).reset_index(drop=True)

    pair_count = min(num_pairs, len(benign_rows), len(malicious_rows))
    pairs = []
    for idx in range(pair_count):
        pairs.append((benign_rows.iloc[idx], malicious_rows.iloc[idx]))
    return pairs


def maybe_clear_device_cache(device: str) -> None:
    gc.collect()
    if device == "cuda" and torch.cuda.is_available():
        torch.cuda.empty_cache()
    if device == "mps" and hasattr(torch, "mps") and hasattr(torch.mps, "empty_cache"):
        torch.mps.empty_cache()


def parse_head_list(heads_text: str) -> List[Tuple[int, int]]:
    heads: List[Tuple[int, int]] = []
    for item in heads_text.split(","):
        value = item.strip()
        if not value:
            continue
        if "." not in value:
            raise ValueError(f"Head specification must be layer.head, got {value!r}")
        layer_text, head_text = value.split(".", 1)
        heads.append((int(layer_text), int(head_text)))
    if not heads:
        raise ValueError("At least one head must be specified.")
    return heads


def parse_int_list(raw_text: str) -> List[int]:
    values = []
    for item in raw_text.split(","):
        item = item.strip()
        if item:
            values.append(int(item))
    if not values:
        raise ValueError("Expected at least one integer value.")
    return values


def optional_layer_filter(layer_start: Optional[int], layer_end: Optional[int]) -> Optional[List[int]]:
    if layer_start is None and layer_end is None:
        return None
    if layer_start is None or layer_end is None:
        raise ValueError("Provide both layer_start and layer_end when filtering layers.")
    if layer_end < layer_start:
        raise ValueError("layer_end must be >= layer_start.")
    return list(range(layer_start, layer_end + 1))


def parse_neuron_list(neurons_text: str) -> List[Tuple[int, int]]:
    neurons: List[Tuple[int, int]] = []
    for item in neurons_text.split(","):
        value = item.strip()
        if not value:
            continue
        if "." not in value:
            raise ValueError(f"Neuron specification must be layer.neuron, got {value!r}")
        layer_text, neuron_text = value.split(".", 1)
        neurons.append((int(layer_text), int(neuron_text)))
    if not neurons:
        raise ValueError("At least one neuron must be specified.")
    return neurons


def evaluate_prompts(
    model,
    tokenizer,
    df: pd.DataFrame,
    *,
    device: str,
    batch_size: int = 1,
) -> pd.DataFrame:
    prompts = attach_prompts(df)
    allow_token_id = tokenizer.encode(" ALLOW", add_special_tokens=False)[0]
    block_token_id = tokenizer.encode(" BLOCK", add_special_tokens=False)[0]
    rows = []

    for start in range(0, len(prompts), batch_size):
        batch = prompts.iloc[start : start + batch_size].copy()
        encoded = tokenizer(
            batch["prompt"].tolist(),
            return_tensors="pt",
            padding=True,
            truncation=False,
        )
        encoded = {key: value.to(device) for key, value in encoded.items()}

        with torch.no_grad():
            outputs = model(**encoded)
            logits = outputs.logits[:, -1, :]

        for row_idx, (_, sample) in enumerate(batch.iterrows()):
            logit_diff = float((logits[row_idx, block_token_id] - logits[row_idx, allow_token_id]).item())
            predicted_label = "malicious" if logit_diff > 0 else "benign"
            target_token = sample["target_token"] if "target_token" in sample.index else LABELS[str(sample["label"]).strip().lower()]
            rows.append(
                {
                    "filename": sample["filename"],
                    "label": sample["label"],
                    "predicted_label": predicted_label,
                    "target_token": target_token,
                    "predicted_token": "BLOCK" if predicted_label == "malicious" else "ALLOW",
                    "logit_diff": logit_diff,
                    "correct": predicted_label == sample["label"],
                    "used_char_len": int(sample["used_char_len"]),
                    "was_truncated": bool(sample["was_truncated"]),
                }
            )
    return pd.DataFrame(rows)


def write_json(path: Union[str, Path], payload: Dict[str, object]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def optional_int_field(row: pd.Series, field_name: str) -> Optional[int]:
    if field_name not in row.index:
        return None
    value = row[field_name]
    if pd.isna(value):
        return None
    return int(value)


def cmd_dataset_summary(args: argparse.Namespace) -> int:
    df, summary = load_dataset(args.csv, max_chars=args.max_chars, min_chars=args.min_chars)
    indicator_counts = summarize_indicator_matches(df)

    payload = {
        "dataset_summary": asdict(summary),
        "indicator_match_counts": indicator_counts,
        "example_rows": df.head(args.preview_rows).to_dict(orient="records"),
    }

    output_path = Path(args.output or (DEFAULT_ARTIFACT_DIR / "dataset_summary.json"))
    write_json(output_path, payload)

    print(json.dumps({"output": str(output_path), **payload["dataset_summary"]}, indent=2, sort_keys=True))
    return 0


def cmd_build_manifest(args: argparse.Namespace) -> int:
    df, summary = load_dataset(args.csv, max_chars=args.max_chars, min_chars=args.min_chars)
    manifest = build_balanced_manifest(df, per_label=args.per_label, seed=args.seed)

    output_path = Path(args.output or (DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    manifest.to_csv(output_path, index=False)

    payload = {
        "output": str(output_path),
        "rows_total": int(len(manifest)),
        "per_label": args.per_label,
        "seed": args.seed,
        "source_rows_used": summary.rows_used,
        "label_counts": manifest["label"].value_counts().sort_index().to_dict(),
        "length_bucket_counts": manifest["length_bucket"].value_counts().sort_index().to_dict(),
        "indicator_bucket_counts": manifest["indicator_bucket"].value_counts().sort_index().to_dict(),
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_build_circuit_val_set(args: argparse.Namespace) -> int:
    df, _ = load_dataset(args.csv, max_chars=args.max_chars, min_chars=args.min_chars)
    output_df, metadata = build_circuit_val_set(
        df,
        target_total=args.target_total,
    )

    output_path = Path(args.output or (ROOT / "circuit_val_set.csv"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_df.to_csv(output_path, index=False)

    metadata_path = Path(args.metadata_output or (DEFAULT_ARTIFACT_DIR / "circuit_val_set_metadata.json"))
    write_json(
        metadata_path,
        {
            "output_csv": str(output_path),
            **metadata,
        },
    )

    print(
        json.dumps(
            {
                "output": str(output_path),
                "metadata": str(metadata_path),
                **metadata,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_build_indicator_pair_manifest(args: argparse.Namespace) -> int:
    df = pd.read_csv(args.input_csv)
    pair_df = build_indicator_pair_manifest(
        df,
        indicator_column=args.indicator_column,
        max_pairs=args.max_pairs,
        per_indicator_cap=args.per_indicator_cap,
        pairing_mode=args.pairing_mode,
    )
    if pair_df.empty:
        raise RuntimeError("No benign/malicious pairs could be built from the input CSV.")

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pair_df.to_csv(output_path, index=False)

    summary = (
        pair_df.groupby(["pair_indicator", "label"]).size().unstack(fill_value=0).to_dict(orient="index")
        if "pair_indicator" in pair_df.columns
        else {}
    )
    print(
        json.dumps(
            {
                "output": str(output_path),
                "rows": int(len(pair_df)),
                "num_pairs": int(pair_df["pair_idx"].nunique()),
                "pairing_mode": args.pairing_mode,
                "pair_indicator_counts": summary,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_augment_pair_manifest(args: argparse.Namespace) -> int:
    manifest = pd.read_csv(args.manifest)
    techniques = [item.strip() for item in args.techniques.split(",") if item.strip()] if args.techniques else None
    augmented_df, metadata = build_augmented_pair_manifest(
        manifest,
        include_original=args.include_original,
        techniques=techniques,
        max_augmented_variants_per_pair=args.max_augmented_variants_per_pair,
    )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    augmented_df.to_csv(output_path, index=False)

    metadata_path = Path(args.metadata_output)
    write_json(
        metadata_path,
        {
            "output_csv": str(output_path),
            "source_manifest": str(args.manifest),
            "techniques": techniques,
            **metadata,
        },
    )
    print(
        json.dumps(
            {
                "output": str(output_path),
                "metadata": str(metadata_path),
                **metadata,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def enrich_with_pair_indicator(df: pd.DataFrame, manifest: pd.DataFrame) -> pd.DataFrame:
    if "pair_indicator" in df.columns:
        return df

    enriched = df.copy()
    indicator_by_file: Dict[str, str] = {}
    if {"filename", "pair_indicator"}.issubset(manifest.columns):
        indicator_by_file = (
            manifest[["filename", "pair_indicator"]]
            .drop_duplicates()
            .set_index("filename")["pair_indicator"]
            .to_dict()
        )

    if "malicious_filename" in enriched.columns:
        enriched["pair_indicator"] = enriched["malicious_filename"].map(indicator_by_file)
    elif "filename" in enriched.columns:
        enriched["pair_indicator"] = enriched["filename"].map(indicator_by_file)
    else:
        enriched["pair_indicator"] = None
    return enriched


def filter_to_manifest(df: pd.DataFrame, manifest: pd.DataFrame) -> pd.DataFrame:
    filtered = df.copy()

    if "filename" in filtered.columns and "filename" in manifest.columns:
        allowed_filenames = set(manifest["filename"].dropna().astype(str))
        filtered = filtered[filtered["filename"].astype(str).isin(allowed_filenames)].copy()
        return filtered

    if "malicious_filename" in filtered.columns and "filename" in manifest.columns:
        allowed_filenames = set(manifest["filename"].dropna().astype(str))
        filtered = filtered[filtered["malicious_filename"].astype(str).isin(allowed_filenames)].copy()
        return filtered

    if "pair_idx" in filtered.columns and "pair_idx" in manifest.columns:
        allowed_pair_idxs = set(manifest["pair_idx"].dropna().astype(int))
        filtered = filtered[filtered["pair_idx"].astype(int).isin(allowed_pair_idxs)].copy()

    return filtered


def summarize_family_accuracy(baseline_df: pd.DataFrame) -> pd.DataFrame:
    rows: List[Dict[str, object]] = []
    for indicator, group in baseline_df.groupby("pair_indicator", dropna=False):
        overall_accuracy = float(group["correct"].mean()) if len(group) else 0.0
        benign_group = group[group["label"] == "benign"]
        malicious_group = group[group["label"] == "malicious"]
        rows.append(
            {
                "pair_indicator": indicator,
                "rows": int(len(group)),
                "pairs": int(group["filename"].nunique() // 2) if "filename" in group.columns else None,
                "accuracy": overall_accuracy,
                "benign_rows": int(len(benign_group)),
                "benign_accuracy": float(benign_group["correct"].mean()) if len(benign_group) else None,
                "malicious_rows": int(len(malicious_group)),
                "malicious_accuracy": float(malicious_group["correct"].mean()) if len(malicious_group) else None,
                "mean_logit_diff": float(group["logit_diff"].mean()) if "logit_diff" in group.columns else None,
                "mean_malicious_logit_diff": float(malicious_group["logit_diff"].mean()) if len(malicious_group) else None,
                "mean_benign_logit_diff": float(benign_group["logit_diff"].mean()) if len(benign_group) else None,
            }
        )
    return pd.DataFrame(rows).sort_values("pair_indicator").reset_index(drop=True)


def summarize_family_attention(attention_df: pd.DataFrame) -> pd.DataFrame:
    summary = (
        attention_df.groupby(["pair_indicator", "layer", "head"], as_index=False)
        .agg(
            pair_count=("malicious_filename", "nunique"),
            mean_attention_delta=("attention_delta", "mean"),
            max_attention_delta=("attention_delta", "max"),
        )
        .sort_values(["pair_indicator", "pair_count", "mean_attention_delta"], ascending=[True, False, False])
        .reset_index(drop=True)
    )
    return summary


def summarize_family_causal(df: pd.DataFrame, *, delta_column: str, score_column: str) -> pd.DataFrame:
    summary = (
        df.groupby(["pair_indicator", "layer", "head"], as_index=False)
        .agg(
            pair_count=("malicious_filename", "nunique"),
            mean_delta=(delta_column, "mean"),
            min_delta=(delta_column, "min"),
            max_delta=(delta_column, "max"),
            flip_rate=("flip_to_benign", "mean"),
            mean_score=(score_column, "mean"),
            mean_base_logit_diff=("base_logit_diff", "mean"),
        )
        .sort_values(["pair_indicator", "mean_delta"], ascending=[True, True])
        .reset_index(drop=True)
    )
    return summary


def cmd_summarize_family_overlap(args: argparse.Namespace) -> int:
    manifest = pd.read_csv(args.manifest)
    if "pair_indicator" not in manifest.columns:
        raise ValueError("Manifest must contain a pair_indicator column.")

    head_filter = None
    if args.heads:
        head_filter = set(parse_head_list(args.heads))

    output_prefix = Path(args.output_prefix or (DEFAULT_ARTIFACT_DIR / "family_overlap"))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)

    outputs: Dict[str, str] = {}
    metadata: Dict[str, object] = {
        "manifest": str(args.manifest),
        "heads_filter": [{"layer": layer, "head": head} for layer, head in sorted(head_filter)] if head_filter else None,
    }

    if args.baseline_eval:
        baseline_df = filter_to_manifest(enrich_with_pair_indicator(pd.read_csv(args.baseline_eval), manifest), manifest)
        baseline_summary = summarize_family_accuracy(baseline_df)
        baseline_path = output_prefix.with_name(output_prefix.name + "_baseline_summary.csv")
        baseline_summary.to_csv(baseline_path, index=False)
        outputs["baseline_summary_csv"] = str(baseline_path)

    if args.attention_per_pair:
        attention_df = filter_to_manifest(enrich_with_pair_indicator(pd.read_csv(args.attention_per_pair), manifest), manifest)
        if head_filter is not None:
            attention_df = attention_df[
                attention_df.apply(lambda row: (int(row["layer"]), int(row["head"])) in head_filter, axis=1)
            ].copy()
        attention_summary = summarize_family_attention(attention_df)
        attention_path = output_prefix.with_name(output_prefix.name + "_attention_summary.csv")
        attention_summary.to_csv(attention_path, index=False)
        outputs["attention_summary_csv"] = str(attention_path)

    if args.patch_per_pair:
        patch_df = filter_to_manifest(enrich_with_pair_indicator(pd.read_csv(args.patch_per_pair), manifest), manifest)
        if head_filter is not None:
            patch_df = patch_df[
                patch_df.apply(lambda row: (int(row["layer"]), int(row["head"])) in head_filter, axis=1)
            ].copy()
        patch_summary = summarize_family_causal(
            patch_df,
            delta_column="delta_logit_diff",
            score_column="patched_logit_diff",
        )
        patch_path = output_prefix.with_name(output_prefix.name + "_patch_summary.csv")
        patch_summary.to_csv(patch_path, index=False)
        outputs["patch_summary_csv"] = str(patch_path)

    if args.ablation_per_pair:
        ablation_df = filter_to_manifest(enrich_with_pair_indicator(pd.read_csv(args.ablation_per_pair), manifest), manifest)
        if head_filter is not None:
            ablation_df = ablation_df[
                ablation_df.apply(lambda row: (int(row["layer"]), int(row["head"])) in head_filter, axis=1)
            ].copy()
        ablation_summary = summarize_family_causal(
            ablation_df,
            delta_column="delta_logit_diff",
            score_column="ablated_logit_diff",
        )
        ablation_path = output_prefix.with_name(output_prefix.name + "_ablation_summary.csv")
        ablation_summary.to_csv(ablation_path, index=False)
        outputs["ablation_summary_csv"] = str(ablation_path)

    metadata_path = output_prefix.with_name(output_prefix.name + "_metadata.json")
    write_json(metadata_path, {**metadata, **outputs})
    print(json.dumps({"metadata": str(metadata_path), **outputs}, indent=2, sort_keys=True))
    return 0


def cmd_export_short_pairs(args: argparse.Namespace) -> int:
    manifest = pd.read_csv(args.manifest)
    pairs = select_short_pairs(
        manifest,
        num_pairs=args.num_pairs,
        malicious_requires_indicator=not args.allow_zero_indicator_malicious,
    )
    rows: List[Dict[str, object]] = []
    for pair_idx, (benign_row, malicious_row) in enumerate(pairs, start=1):
        benign_entry = dict(benign_row)
        benign_entry["pair_idx"] = pair_idx
        benign_entry["pair_role"] = "benign"
        malicious_entry = dict(malicious_row)
        malicious_entry["pair_idx"] = pair_idx
        malicious_entry["pair_role"] = "malicious"
        rows.extend([benign_entry, malicious_entry])

    output_path = Path(args.output or (DEFAULT_ARTIFACT_DIR / "short_pairs_manifest.csv"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(output_path, index=False)

    print(
        json.dumps(
            {
                "output": str(output_path),
                "num_pairs": len(pairs),
                "rows": len(rows),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_filter_valid_pairs(args: argparse.Namespace) -> int:
    manifest = pd.read_csv(args.manifest)
    baseline = pd.read_csv(args.baseline_eval)
    eval_columns = ["correct", "predicted_label", "logit_diff"]

    # Some manifests are already enriched with prior baseline outputs.
    # Drop stale evaluation columns so the fresh merge keeps canonical names.
    manifest = manifest.drop(columns=[column for column in eval_columns if column in manifest.columns])
    baseline = baseline.drop_duplicates(subset=["filename", "label"], keep="first")

    merged = manifest.merge(
        baseline[["filename", "label", *eval_columns]],
        on=["filename", "label"],
        how="left",
        validate="many_to_one",
    )
    if merged["correct"].isna().any():
        missing = merged[merged["correct"].isna()][["filename", "label"]]
        raise RuntimeError(f"Baseline eval missing rows for manifest entries: {missing.to_dict(orient='records')[:5]}")

    pair_quality = (
        merged.groupby("pair_idx", as_index=False)
        .agg(
            pair_rows=("filename", "count"),
            all_correct=("correct", "all"),
        )
    )
    valid_pair_ids = pair_quality.loc[
        (pair_quality["pair_rows"] == 2) & (pair_quality["all_correct"]),
        "pair_idx",
    ].tolist()

    filtered = merged[merged["pair_idx"].isin(valid_pair_ids)].copy()
    output_path = Path(args.output or (DEFAULT_ARTIFACT_DIR / "valid_short_pairs_manifest.csv"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    filtered.to_csv(output_path, index=False)

    print(
        json.dumps(
            {
                "output": str(output_path),
                "pairs_in": int(pair_quality.shape[0]),
                "pairs_out": int(len(valid_pair_ids)),
                "rows_out": int(filtered.shape[0]),
                "valid_pair_ids": valid_pair_ids,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_baseline_eval(args: argparse.Namespace) -> int:
    manifest = pd.read_csv(args.manifest)
    if args.limit is not None:
        manifest = manifest.head(args.limit).copy()

    model, tokenizer, device = load_hf_model_and_tokenizer(
        args.model_name,
        device=args.device,
        torch_dtype=args.torch_dtype,
    )
    results = evaluate_prompts(
        model,
        tokenizer,
        manifest,
        device=device,
        batch_size=args.batch_size,
    )

    output_path = Path(args.output or (DEFAULT_ARTIFACT_DIR / "baseline_eval.csv"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    results.to_csv(output_path, index=False)

    accuracy = float(results["correct"].mean()) if len(results) else 0.0
    payload = {
        "output": str(output_path),
        "rows_evaluated": int(len(results)),
        "accuracy": accuracy,
        "mean_logit_diff": float(results["logit_diff"].mean()) if len(results) else 0.0,
        "device": device,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def cmd_discover_heads(args: argparse.Namespace) -> int:
    require_transformer_lens()

    manifest = pd.read_csv(args.manifest)
    benign_row, malicious_row = select_manifest_pair(
        manifest,
        benign_rank=args.benign_rank,
        malicious_rank=args.malicious_rank,
    )

    hf_model, tokenizer, device = load_hf_model_and_tokenizer(
        args.model_name,
        device=args.device,
        torch_dtype=args.torch_dtype,
    )
    model = build_hooked_transformer(
        hf_model,
        tokenizer,
        device=device,
        torch_dtype=args.torch_dtype,
        template_name=args.template_name,
        first_n_layers=args.first_n_layers,
        use_attn_result=False,
    )
    model.eval()

    benign_prompt = make_prompt(benign_row["content"])
    malicious_prompt = make_prompt(malicious_row["content"])
    benign_tokens = model.to_tokens(benign_prompt)
    malicious_tokens = model.to_tokens(malicious_prompt)

    _, benign_cache = model.run_with_cache(benign_tokens, return_type="logits")
    _, malicious_cache = model.run_with_cache(malicious_tokens, return_type="logits")
    indicator_positions = get_indicator_tokens(malicious_prompt, tokenizer)
    layer_filter = optional_layer_filter(args.layer_start, args.layer_end)
    head_scores = compute_attention_scores(
        malicious_cache,
        n_layers=model.cfg.n_layers,
        n_heads=model.cfg.n_heads,
        indicator_positions=indicator_positions,
        layer_filter=layer_filter,
        topk=args.topk,
    )

    output_path = Path(args.output or (DEFAULT_ARTIFACT_DIR / "attention_top_heads.csv"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    head_scores.to_csv(output_path, index=False)

    metadata_path = output_path.with_suffix(".json")
    write_json(
        metadata_path,
        {
            "output_csv": str(output_path),
            "benign_filename": benign_row["filename"],
            "malicious_filename": malicious_row["filename"],
            "benign_manifest_rank": optional_int_field(benign_row, "manifest_rank"),
            "malicious_manifest_rank": optional_int_field(malicious_row, "manifest_rank"),
            "indicator_positions": indicator_positions,
            "device": device,
            "first_n_layers": args.first_n_layers,
            "layer_filter": layer_filter,
            "template_name": args.template_name,
            "topk": args.topk,
        },
    )

    print(
        json.dumps(
            {
                "output": str(output_path),
                "metadata": str(metadata_path),
                "benign_filename": benign_row["filename"],
                "malicious_filename": malicious_row["filename"],
                "top_head": head_scores.iloc[0].to_dict() if len(head_scores) else None,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_causal_pair(args: argparse.Namespace) -> int:
    require_transformer_lens()

    manifest = pd.read_csv(args.manifest)
    if args.pair_idx is not None:
        benign_row, malicious_row = select_explicit_pair_by_id(manifest, args.pair_idx)
    elif args.short_pair_index is not None:
        pairs = select_short_pairs(
            manifest,
            num_pairs=args.short_pair_index + 1,
            malicious_requires_indicator=not args.allow_zero_indicator_malicious,
        )
        if args.short_pair_index >= len(pairs):
            raise IndexError("Requested short_pair_index is out of bounds.")
        benign_row, malicious_row = pairs[args.short_pair_index]
    else:
        if args.benign_rank is None or args.malicious_rank is None:
            raise ValueError("Provide --short-pair-index or both --benign-rank and --malicious-rank.")
        benign_row, malicious_row = select_manifest_pair(
            manifest,
            benign_rank=args.benign_rank,
            malicious_rank=args.malicious_rank,
        )
    candidate_heads = parse_head_list(args.heads)

    hf_model, tokenizer, device = load_hf_model_and_tokenizer(
        args.model_name,
        device=args.device,
        torch_dtype=args.torch_dtype,
    )
    model = build_hooked_transformer(
        hf_model,
        tokenizer,
        device=device,
        torch_dtype=args.torch_dtype,
        template_name=args.template_name,
        first_n_layers=args.first_n_layers,
        use_attn_result=False,
    )
    model.eval()

    allow_token_id = tokenizer.encode(" ALLOW", add_special_tokens=False)[0]
    block_token_id = tokenizer.encode(" BLOCK", add_special_tokens=False)[0]
    benign_prompt = make_prompt(benign_row["content"])
    malicious_prompt = make_prompt(malicious_row["content"])
    benign_tokens = model.to_tokens(benign_prompt)
    malicious_tokens = model.to_tokens(malicious_prompt)
    benign_logits, benign_cache = model.run_with_cache(benign_tokens, return_type="logits")
    malicious_logits, malicious_cache = model.run_with_cache(malicious_tokens, return_type="logits")

    base_benign_diff = logit_diff_from_logits(benign_logits, allow_token_id, block_token_id)
    base_malicious_diff = logit_diff_from_logits(malicious_logits, allow_token_id, block_token_id)

    patch_df = run_activation_patching(
        model,
        corrupted_tokens=malicious_tokens,
        clean_cache=benign_cache,
        candidate_heads=candidate_heads,
        base_logit_diff=base_malicious_diff,
        allow_token_id=allow_token_id,
        block_token_id=block_token_id,
    )
    patch_df["pair_idx"] = int(args.pair_idx) if args.pair_idx is not None else None
    patch_df["benign_filename"] = benign_row["filename"]
    patch_df["malicious_filename"] = malicious_row["filename"]
    patch_df["base_benign_logit_diff"] = base_benign_diff
    patch_df["flip_to_benign"] = patch_df["patched_logit_diff"] <= 0

    ablation_df = run_head_ablation(
        model,
        tokens=malicious_tokens,
        candidate_heads=candidate_heads,
        base_logit_diff=base_malicious_diff,
        allow_token_id=allow_token_id,
        block_token_id=block_token_id,
    )
    ablation_df["pair_idx"] = int(args.pair_idx) if args.pair_idx is not None else None
    ablation_df["benign_filename"] = benign_row["filename"]
    ablation_df["malicious_filename"] = malicious_row["filename"]
    ablation_df["base_benign_logit_diff"] = base_benign_diff
    ablation_df["flip_to_benign"] = ablation_df["ablated_logit_diff"] <= 0

    output_prefix = Path(args.output_prefix or (DEFAULT_ARTIFACT_DIR / "causal_pair"))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    patch_path = output_prefix.with_name(output_prefix.name + "_patch.csv")
    ablation_path = output_prefix.with_name(output_prefix.name + "_ablation.csv")
    metadata_path = output_prefix.with_name(output_prefix.name + "_metadata.json")
    patch_df.to_csv(patch_path, index=False)
    ablation_df.to_csv(ablation_path, index=False)
    write_json(
        metadata_path,
        {
            "pair_idx": int(args.pair_idx) if args.pair_idx is not None else None,
            "benign_filename": benign_row["filename"],
            "malicious_filename": malicious_row["filename"],
            "benign_manifest_rank": optional_int_field(benign_row, "manifest_rank"),
            "malicious_manifest_rank": optional_int_field(malicious_row, "manifest_rank"),
            "first_n_layers": args.first_n_layers,
            "heads": [{"layer": layer, "head": head} for layer, head in candidate_heads],
            "device": device,
            "patch_csv": str(patch_path),
            "ablation_csv": str(ablation_path),
        },
    )

    print(
        json.dumps(
            {
                "metadata": str(metadata_path),
                "patch_csv": str(patch_path),
                "ablation_csv": str(ablation_path),
                "base_benign_logit_diff": base_benign_diff,
                "base_malicious_logit_diff": base_malicious_diff,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_batch_discover_heads(args: argparse.Namespace) -> int:
    require_transformer_lens()

    manifest = pd.read_csv(args.manifest)
    pairs = select_short_pairs(
        manifest,
        num_pairs=args.num_pairs,
        malicious_requires_indicator=not args.allow_zero_indicator_malicious,
    )
    if not pairs:
        raise RuntimeError("No eligible benign/malicious pairs found for batch discovery.")

    hf_model, tokenizer, device = load_hf_model_and_tokenizer(
        args.model_name,
        device=args.device,
        torch_dtype=args.torch_dtype,
    )
    model = build_hooked_transformer(
        hf_model,
        tokenizer,
        device=device,
        torch_dtype=args.torch_dtype,
        template_name=args.template_name,
        first_n_layers=args.first_n_layers,
        use_attn_result=False,
    )
    model.eval()
    layer_filter = optional_layer_filter(args.layer_start, args.layer_end)

    pair_rows: List[Dict[str, object]] = []
    head_rows: List[Dict[str, object]] = []

    for fallback_idx, (benign_row, malicious_row) in enumerate(pairs, start=1):
        pair_idx = resolve_pair_idx(benign_row, malicious_row, fallback_idx=fallback_idx)
        benign_prompt = make_prompt(benign_row["content"])
        malicious_prompt = make_prompt(malicious_row["content"])
        malicious_indicator_positions = get_indicator_tokens(malicious_prompt, tokenizer)

        benign_tokens = model.to_tokens(benign_prompt)
        malicious_tokens = model.to_tokens(malicious_prompt)
        _, benign_cache = model.run_with_cache(benign_tokens, return_type="logits")
        _, malicious_cache = model.run_with_cache(malicious_tokens, return_type="logits")

        head_scores = compute_attention_scores(
            malicious_cache,
            n_layers=model.cfg.n_layers,
            n_heads=model.cfg.n_heads,
            indicator_positions=malicious_indicator_positions,
            layer_filter=layer_filter,
            topk=args.topk,
        )
        head_scores["pair_idx"] = pair_idx
        head_scores["benign_filename"] = benign_row["filename"]
        head_scores["malicious_filename"] = malicious_row["filename"]
        head_scores["pair_indicator"] = benign_row.get("pair_indicator", malicious_row.get("pair_indicator"))
        head_rows.extend(head_scores.to_dict(orient="records"))

        pair_rows.append(
            {
                "pair_idx": pair_idx,
                "pair_indicator": benign_row.get("pair_indicator", malicious_row.get("pair_indicator")),
                "benign_filename": benign_row["filename"],
                "benign_manifest_rank": optional_int_field(benign_row, "manifest_rank"),
                "benign_used_char_len": int(benign_row["used_char_len"]),
                "malicious_filename": malicious_row["filename"],
                "malicious_manifest_rank": optional_int_field(malicious_row, "manifest_rank"),
                "malicious_used_char_len": int(malicious_row["used_char_len"]),
                "indicator_positions": malicious_indicator_positions,
                "indicator_count": int(malicious_row.get("indicator_count", 0)),
            }
        )

        del benign_cache
        del malicious_cache
        maybe_clear_device_cache(device)

    pair_df = pd.DataFrame(pair_rows)
    head_df = pd.DataFrame(head_rows)
    agg_df = (
        head_df.groupby(["layer", "head"], as_index=False)
        .agg(
            pair_count=("pair_idx", "nunique"),
            mean_attention_delta=("attention_delta", "mean"),
            max_attention_delta=("attention_delta", "max"),
        )
        .sort_values(["pair_count", "mean_attention_delta"], ascending=[False, False])
        .reset_index(drop=True)
    )

    output_prefix = Path(args.output_prefix or (DEFAULT_ARTIFACT_DIR / "batch_attention_l4"))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    pairs_path = output_prefix.with_name(output_prefix.name + "_pairs.csv")
    per_pair_path = output_prefix.with_name(output_prefix.name + "_per_pair.csv")
    summary_path = output_prefix.with_name(output_prefix.name + "_summary.csv")
    metadata_path = output_prefix.with_name(output_prefix.name + "_metadata.json")

    pair_df.to_csv(pairs_path, index=False)
    head_df.to_csv(per_pair_path, index=False)
    agg_df.to_csv(summary_path, index=False)
    write_json(
        metadata_path,
        {
            "pairs_csv": str(pairs_path),
            "per_pair_csv": str(per_pair_path),
            "summary_csv": str(summary_path),
            "num_pairs": len(pairs),
            "first_n_layers": args.first_n_layers,
            "layer_filter": layer_filter,
            "topk": args.topk,
            "device": device,
            "template_name": args.template_name,
        },
    )

    print(
        json.dumps(
            {
                "pairs_csv": str(pairs_path),
                "per_pair_csv": str(per_pair_path),
                "summary_csv": str(summary_path),
                "metadata": str(metadata_path),
                "top_recurring_head": agg_df.iloc[0].to_dict() if len(agg_df) else None,
                "num_pairs": len(pairs),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def summarize_causal_effects(df: pd.DataFrame, *, delta_column: str, flip_column: str) -> pd.DataFrame:
    working = df.copy()
    pair_key = "__pair_key"
    working[pair_key] = pd.Series(pd.NA, index=working.index, dtype="object")
    if "pair_idx" in working.columns:
        pair_idx_series = working["pair_idx"].where(pd.notna(working["pair_idx"]), pd.NA)
        working[pair_key] = pair_idx_series.astype("string").astype("object")

    if {"benign_filename", "malicious_filename"}.issubset(working.columns):
        missing_mask = working[pair_key].isna()
        working.loc[missing_mask, pair_key] = (
            working.loc[missing_mask, "benign_filename"].astype(str)
            + "::"
            + working.loc[missing_mask, "malicious_filename"].astype(str)
        )

    summary = (
        working.groupby(["layer", "head"], as_index=False)
        .agg(
            pair_count=(pair_key, "nunique"),
            mean_delta=(delta_column, "mean"),
            max_delta=(delta_column, "max"),
            min_delta=(delta_column, "min"),
            flip_rate=(flip_column, "mean"),
        )
        .sort_values(["flip_rate", "mean_delta"], ascending=[False, True])
        .reset_index(drop=True)
    )
    return summary


def summarize_layer_component_effects(df: pd.DataFrame) -> pd.DataFrame:
    working = df.copy()
    pair_key = "__pair_key"
    working[pair_key] = pd.Series(pd.NA, index=working.index, dtype="object")
    if "pair_idx" in working.columns:
        pair_idx_series = working["pair_idx"].where(pd.notna(working["pair_idx"]), pd.NA)
        working[pair_key] = pair_idx_series.astype("string").astype("object")

    if {"benign_filename", "malicious_filename"}.issubset(working.columns):
        missing_mask = working[pair_key].isna()
        working.loc[missing_mask, pair_key] = (
            working.loc[missing_mask, "benign_filename"].astype(str)
            + "::"
            + working.loc[missing_mask, "malicious_filename"].astype(str)
        )

    summary = (
        working.groupby(["layer", "component"], as_index=False)
        .agg(
            pair_count=(pair_key, "nunique"),
            mean_delta=("delta_logit_diff", "mean"),
            max_delta=("delta_logit_diff", "max"),
            min_delta=("delta_logit_diff", "min"),
            flip_rate=("flip_to_benign", "mean"),
            mean_base_logit_diff=("base_logit_diff", "mean"),
        )
        .sort_values(["component", "mean_delta"], ascending=[True, True])
        .reset_index(drop=True)
    )
    return summary


def summarize_layer_component_patch_effects(df: pd.DataFrame) -> pd.DataFrame:
    working = df.copy()
    pair_key = "__pair_key"
    working[pair_key] = pd.Series(pd.NA, index=working.index, dtype="object")
    if "pair_idx" in working.columns:
        pair_idx_series = working["pair_idx"].where(pd.notna(working["pair_idx"]), pd.NA)
        working[pair_key] = pair_idx_series.astype("string").astype("object")

    if {"benign_filename", "malicious_filename"}.issubset(working.columns):
        missing_mask = working[pair_key].isna()
        working.loc[missing_mask, pair_key] = (
            working.loc[missing_mask, "benign_filename"].astype(str)
            + "::"
            + working.loc[missing_mask, "malicious_filename"].astype(str)
        )

    summary = (
        working.groupby(["layer", "component"], as_index=False)
        .agg(
            pair_count=(pair_key, "nunique"),
            mean_delta=("delta_logit_diff", "mean"),
            max_delta=("delta_logit_diff", "max"),
            min_delta=("delta_logit_diff", "min"),
            flip_rate=("flip_to_benign", "mean"),
            mean_base_logit_diff=("base_logit_diff", "mean"),
        )
        .sort_values(["component", "mean_delta"], ascending=[True, True])
        .reset_index(drop=True)
    )
    return summary


def summarize_neuron_effects(df: pd.DataFrame) -> pd.DataFrame:
    working = df.copy()
    pair_key = "__pair_key"
    working[pair_key] = pd.Series(pd.NA, index=working.index, dtype="object")
    if "pair_idx" in working.columns:
        pair_idx_series = working["pair_idx"].where(pd.notna(working["pair_idx"]), pd.NA)
        working[pair_key] = pair_idx_series.astype("string").astype("object")

    if {"benign_filename", "malicious_filename"}.issubset(working.columns):
        missing_mask = working[pair_key].isna()
        working.loc[missing_mask, pair_key] = (
            working.loc[missing_mask, "benign_filename"].astype(str)
            + "::"
            + working.loc[missing_mask, "malicious_filename"].astype(str)
        )

    summary = (
        working.groupby(["layer", "neuron"], as_index=False)
        .agg(
            pair_count=(pair_key, "nunique"),
            mean_delta=("delta_logit_diff", "mean"),
            max_delta=("delta_logit_diff", "max"),
            min_delta=("delta_logit_diff", "min"),
            flip_rate=("flip_to_benign", "mean"),
            mean_base_logit_diff=("base_logit_diff", "mean"),
        )
        .sort_values(["layer", "mean_delta"], ascending=[True, True])
        .reset_index(drop=True)
    )
    return summary


def summarize_neuron_group_effects(df: pd.DataFrame) -> pd.DataFrame:
    working = df.copy()
    pair_key = "__pair_key"
    working[pair_key] = pd.Series(pd.NA, index=working.index, dtype="object")
    if "pair_idx" in working.columns:
        pair_idx_series = working["pair_idx"].where(pd.notna(working["pair_idx"]), pd.NA)
        working[pair_key] = pair_idx_series.astype("string").astype("object")

    if {"benign_filename", "malicious_filename"}.issubset(working.columns):
        missing_mask = working[pair_key].isna()
        working.loc[missing_mask, pair_key] = (
            working.loc[missing_mask, "benign_filename"].astype(str)
            + "::"
            + working.loc[missing_mask, "malicious_filename"].astype(str)
        )

    summary = (
        working.groupby(["layer", "group_size", "neurons"], as_index=False)
        .agg(
            pair_count=(pair_key, "nunique"),
            mean_delta=("delta_logit_diff", "mean"),
            max_delta=("delta_logit_diff", "max"),
            min_delta=("delta_logit_diff", "min"),
            flip_rate=("flip_to_benign", "mean"),
            mean_base_logit_diff=("base_logit_diff", "mean"),
        )
        .sort_values(["layer", "group_size"], ascending=[True, True])
        .reset_index(drop=True)
    )
    return summary


def summarize_path_patch_effects(df: pd.DataFrame) -> pd.DataFrame:
    working = df.copy()
    pair_key = "__pair_key"
    working[pair_key] = pd.Series(pd.NA, index=working.index, dtype="object")
    if "pair_idx" in working.columns:
        pair_idx_series = working["pair_idx"].where(pd.notna(working["pair_idx"]), pd.NA)
        working[pair_key] = pair_idx_series.astype("string").astype("object")

    if {"benign_filename", "malicious_filename"}.issubset(working.columns):
        missing_mask = working[pair_key].isna()
        working.loc[missing_mask, pair_key] = (
            working.loc[missing_mask, "benign_filename"].astype(str)
            + "::"
            + working.loc[missing_mask, "malicious_filename"].astype(str)
        )

    summary = (
        working.groupby("patch_label", as_index=False)
        .agg(
            pair_count=(pair_key, "nunique"),
            mean_delta=("delta_logit_diff", "mean"),
            max_delta=("delta_logit_diff", "max"),
            min_delta=("delta_logit_diff", "min"),
            flip_rate=("flip_to_benign", "mean"),
            mean_base_logit_diff=("base_logit_diff", "mean"),
        )
        .sort_values("mean_delta")
        .reset_index(drop=True)
    )
    return summary


def summarize_residual_subspace_patch_effects(df: pd.DataFrame) -> pd.DataFrame:
    working = df.copy()
    pair_key = "__pair_key"
    working[pair_key] = pd.Series(pd.NA, index=working.index, dtype="object")
    if "pair_idx" in working.columns:
        pair_idx_series = working["pair_idx"].where(pd.notna(working["pair_idx"]), pd.NA)
        working[pair_key] = pair_idx_series.astype("string").astype("object")

    if {"benign_filename", "malicious_filename"}.issubset(working.columns):
        missing_mask = working[pair_key].isna()
        working.loc[missing_mask, pair_key] = (
            working.loc[missing_mask, "benign_filename"].astype(str)
            + "::"
            + working.loc[missing_mask, "malicious_filename"].astype(str)
        )

    summary = (
        working.groupby(["layer", "resid_kind", "subspace_dim"], as_index=False)
        .agg(
            pair_count=(pair_key, "nunique"),
            mean_delta=("delta_logit_diff", "mean"),
            max_delta=("delta_logit_diff", "max"),
            min_delta=("delta_logit_diff", "min"),
            flip_rate=("flip_to_benign", "mean"),
            mean_base_logit_diff=("base_logit_diff", "mean"),
        )
        .sort_values("subspace_dim")
        .reset_index(drop=True)
    )
    return summary


def summarize_directional_head_writes(df: pd.DataFrame) -> pd.DataFrame:
    working = df.copy()
    pair_key = "__pair_key"
    working[pair_key] = pd.Series(pd.NA, index=working.index, dtype="object")
    if "pair_idx" in working.columns:
        pair_idx_series = working["pair_idx"].where(pd.notna(working["pair_idx"]), pd.NA)
        working[pair_key] = pair_idx_series.astype("string").astype("object")

    if {"benign_filename", "malicious_filename"}.issubset(working.columns):
        missing_mask = working[pair_key].isna()
        working.loc[missing_mask, pair_key] = (
            working.loc[missing_mask, "benign_filename"].astype(str)
            + "::"
            + working.loc[missing_mask, "malicious_filename"].astype(str)
        )

    summary = (
        working.groupby(["layer", "head"], as_index=False)
        .agg(
            pair_count=(pair_key, "nunique"),
            mean_benign_projection=("benign_projection", "mean"),
            mean_malicious_projection=("malicious_projection", "mean"),
            mean_delta_projection=("delta_projection", "mean"),
            max_delta_projection=("delta_projection", "max"),
            min_delta_projection=("delta_projection", "min"),
            positive_delta_frac=("delta_projection", lambda series: float((series > 0).mean())),
        )
        .sort_values("mean_delta_projection", ascending=False)
        .reset_index(drop=True)
    )
    return summary


def summarize_directional_head_intervention_effects(df: pd.DataFrame) -> pd.DataFrame:
    working = df.copy()
    pair_key = "__pair_key"
    working[pair_key] = pd.Series(pd.NA, index=working.index, dtype="object")
    if "pair_idx" in working.columns:
        pair_idx_series = working["pair_idx"].where(pd.notna(working["pair_idx"]), pd.NA)
        working[pair_key] = pair_idx_series.astype("string").astype("object")

    if {"benign_filename", "malicious_filename"}.issubset(working.columns):
        missing_mask = working[pair_key].isna()
        working.loc[missing_mask, pair_key] = (
            working.loc[missing_mask, "benign_filename"].astype(str)
            + "::"
            + working.loc[missing_mask, "malicious_filename"].astype(str)
        )

    summary = (
        working.groupby(["layer", "head"], as_index=False)
        .agg(
            pair_count=(pair_key, "nunique"),
            mean_base_projection=("base_projection", "mean"),
            mean_intervened_projection=("intervened_projection", "mean"),
            mean_projection_delta=("projection_delta", "mean"),
            max_projection_delta=("projection_delta", "max"),
            min_projection_delta=("projection_delta", "min"),
            positive_projection_delta_frac=("projection_delta", lambda series: float((series > 0).mean())),
        )
        .sort_values("mean_projection_delta", ascending=False)
        .reset_index(drop=True)
    )
    return summary


def summarize_residual_direction_interventions(df: pd.DataFrame) -> pd.DataFrame:
    working = df.copy()
    pair_key = "__pair_key"
    working[pair_key] = pd.Series(pd.NA, index=working.index, dtype="object")
    if "pair_idx" in working.columns:
        pair_idx_series = working["pair_idx"].where(pd.notna(working["pair_idx"]), pd.NA)
        working[pair_key] = pair_idx_series.astype("string").astype("object")

    if {"benign_filename", "malicious_filename"}.issubset(working.columns):
        missing_mask = working[pair_key].isna()
        working.loc[missing_mask, pair_key] = (
            working.loc[missing_mask, "benign_filename"].astype(str)
            + "::"
            + working.loc[missing_mask, "malicious_filename"].astype(str)
        )

    summary = (
        working.groupby("intervention_label", as_index=False)
        .agg(
            pair_count=(pair_key, "nunique"),
            mean_base_logit_diff=("base_logit_diff", "mean"),
            mean_intervened_logit_diff=("intervened_logit_diff", "mean"),
            mean_logit_delta=("logit_delta", "mean"),
            flip_rate=("flip_to_benign", "mean"),
            mean_base_projection=("base_projection", "mean"),
            mean_intervened_projection=("intervened_projection", "mean"),
            mean_projection_delta=("projection_delta", "mean"),
            positive_projection_delta_frac=("projection_delta", lambda series: float((series > 0).mean())),
        )
        .sort_values("mean_logit_delta")
        .reset_index(drop=True)
    )
    return summary


def parse_excluded_pair(raw_value: str) -> Dict[str, str]:
    parts = [part.strip() for part in raw_value.split("|", maxsplit=2)]
    if len(parts) != 3 or not all(parts):
        raise ValueError(
            "Excluded pair entries must use 'benign_filename|malicious_filename|reason'."
        )
    benign_filename, malicious_filename, reason = parts
    return {
        "benign_filename": benign_filename,
        "malicious_filename": malicious_filename,
        "reason": reason,
    }


def cmd_aggregate_causal(args: argparse.Namespace) -> int:
    patch_paths: List[Path] = [Path(path) for path in (args.patch_csv or [])]
    ablation_paths: List[Path] = [Path(path) for path in (args.ablation_csv or [])]

    for prefix in args.input_prefix or []:
        prefix_path = Path(prefix)
        patch_paths.append(prefix_path.with_name(prefix_path.name + "_patch.csv"))
        ablation_paths.append(prefix_path.with_name(prefix_path.name + "_ablation.csv"))

    if not patch_paths or not ablation_paths:
        raise ValueError("Provide at least one causal source via --input-prefix or explicit CSV paths.")

    missing_paths = [path for path in patch_paths + ablation_paths if not path.exists()]
    if missing_paths:
        missing_repr = ", ".join(str(path) for path in missing_paths)
        raise FileNotFoundError(f"Missing causal CSV inputs: {missing_repr}")

    patch_frames: List[pd.DataFrame] = []
    ablation_frames: List[pd.DataFrame] = []
    for path in patch_paths:
        df = pd.read_csv(path)
        df["source_file"] = path.name
        patch_frames.append(df)
    for path in ablation_paths:
        df = pd.read_csv(path)
        df["source_file"] = path.name
        ablation_frames.append(df)

    patch_df = pd.concat(patch_frames, ignore_index=True)
    ablation_df = pd.concat(ablation_frames, ignore_index=True)
    patch_summary_df = summarize_causal_effects(
        patch_df,
        delta_column="delta_logit_diff",
        flip_column="flip_to_benign",
    )
    ablation_summary_df = summarize_causal_effects(
        ablation_df,
        delta_column="delta_logit_diff",
        flip_column="flip_to_benign",
    )

    output_prefix = Path(args.output_prefix or (DEFAULT_ARTIFACT_DIR / "aggregated_causal"))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    patch_per_pair_path = output_prefix.with_name(output_prefix.name + "_patch_per_pair.csv")
    patch_summary_path = output_prefix.with_name(output_prefix.name + "_patch_summary.csv")
    ablation_per_pair_path = output_prefix.with_name(output_prefix.name + "_ablation_per_pair.csv")
    ablation_summary_path = output_prefix.with_name(output_prefix.name + "_ablation_summary.csv")
    metadata_path = output_prefix.with_name(output_prefix.name + "_metadata.json")

    patch_df.to_csv(patch_per_pair_path, index=False)
    patch_summary_df.to_csv(patch_summary_path, index=False)
    ablation_df.to_csv(ablation_per_pair_path, index=False)
    ablation_summary_df.to_csv(ablation_summary_path, index=False)

    excluded_pairs = [parse_excluded_pair(value) for value in (args.exclude_pair or [])]
    patch_pair_count = int(
        summarize_causal_effects(
            patch_df,
            delta_column="delta_logit_diff",
            flip_column="flip_to_benign",
        )["pair_count"].max()
    ) if len(patch_summary_df) else 0
    ablation_pair_count = int(
        summarize_causal_effects(
            ablation_df,
            delta_column="delta_logit_diff",
            flip_column="flip_to_benign",
        )["pair_count"].max()
    ) if len(ablation_summary_df) else 0

    write_json(
        metadata_path,
        {
            "patch_csv_inputs": [str(path) for path in patch_paths],
            "ablation_csv_inputs": [str(path) for path in ablation_paths],
            "excluded_pairs": excluded_pairs,
            "patch_per_pair_csv": str(patch_per_pair_path),
            "patch_summary_csv": str(patch_summary_path),
            "ablation_per_pair_csv": str(ablation_per_pair_path),
            "ablation_summary_csv": str(ablation_summary_path),
            "num_pairs_patch": patch_pair_count,
            "num_pairs_ablation": ablation_pair_count,
        },
    )

    print(
        json.dumps(
            {
                "metadata": str(metadata_path),
                "patch_summary_csv": str(patch_summary_path),
                "ablation_summary_csv": str(ablation_summary_path),
                "top_patch_head": patch_summary_df.iloc[0].to_dict() if len(patch_summary_df) else None,
                "top_ablation_head": ablation_summary_df.iloc[0].to_dict() if len(ablation_summary_df) else None,
                "num_pairs_patch": patch_pair_count,
                "num_pairs_ablation": ablation_pair_count,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_batch_causal(args: argparse.Namespace) -> int:
    require_transformer_lens()

    manifest = pd.read_csv(args.manifest)
    pairs = select_short_pairs(
        manifest,
        num_pairs=args.num_pairs,
        malicious_requires_indicator=not args.allow_zero_indicator_malicious,
    )
    if not pairs:
        raise RuntimeError("No eligible benign/malicious pairs found for batch causal validation.")

    candidate_heads = parse_head_list(args.heads)
    device = args.device or ("mps" if torch.backends.mps.is_available() else "cpu")
    hf_model = None
    tokenizer = None
    model = None

    if not args.reload_model_per_pair:
        hf_model, tokenizer, device = load_hf_model_and_tokenizer(
            args.model_name,
            device=args.device,
            torch_dtype=args.torch_dtype,
        )
        model = build_hooked_transformer(
            hf_model,
            tokenizer,
            device=device,
            torch_dtype=args.torch_dtype,
            template_name=args.template_name,
            first_n_layers=args.first_n_layers,
            use_attn_result=False,
        )
        model.eval()

    patch_rows: List[Dict[str, object]] = []
    ablation_rows: List[Dict[str, object]] = []

    for fallback_idx, (benign_row, malicious_row) in enumerate(pairs, start=1):
        pair_idx = resolve_pair_idx(benign_row, malicious_row, fallback_idx=fallback_idx)
        pair_hf_model = hf_model
        pair_tokenizer = tokenizer
        pair_model = model

        if args.reload_model_per_pair:
            pair_hf_model, pair_tokenizer, device = load_hf_model_and_tokenizer(
                args.model_name,
                device=args.device,
                torch_dtype=args.torch_dtype,
            )
            pair_model = build_hooked_transformer(
                pair_hf_model,
                pair_tokenizer,
                device=device,
                torch_dtype=args.torch_dtype,
                template_name=args.template_name,
                first_n_layers=args.first_n_layers,
                use_attn_result=False,
            )
            pair_model.eval()

        allow_token_id = pair_tokenizer.encode(" ALLOW", add_special_tokens=False)[0]
        block_token_id = pair_tokenizer.encode(" BLOCK", add_special_tokens=False)[0]
        benign_prompt = make_prompt(benign_row["content"])
        malicious_prompt = make_prompt(malicious_row["content"])

        benign_tokens = pair_model.to_tokens(benign_prompt)
        malicious_tokens = pair_model.to_tokens(malicious_prompt)
        with torch.inference_mode():
            benign_logits, benign_cache = pair_model.run_with_cache(benign_tokens, return_type="logits")
            malicious_logits, malicious_cache = pair_model.run_with_cache(malicious_tokens, return_type="logits")

        base_benign_diff = logit_diff_from_logits(benign_logits, allow_token_id, block_token_id)
        base_malicious_diff = logit_diff_from_logits(malicious_logits, allow_token_id, block_token_id)

        pair_patch_df = run_activation_patching(
            pair_model,
            corrupted_tokens=malicious_tokens,
            clean_cache=benign_cache,
            candidate_heads=candidate_heads,
            base_logit_diff=base_malicious_diff,
            allow_token_id=allow_token_id,
            block_token_id=block_token_id,
        )
        pair_patch_df["pair_idx"] = pair_idx
        pair_patch_df["pair_indicator"] = benign_row.get("pair_indicator", malicious_row.get("pair_indicator"))
        pair_patch_df["benign_filename"] = benign_row["filename"]
        pair_patch_df["malicious_filename"] = malicious_row["filename"]
        pair_patch_df["base_benign_logit_diff"] = base_benign_diff
        pair_patch_df["flip_to_benign"] = pair_patch_df["patched_logit_diff"] <= 0
        patch_rows.extend(pair_patch_df.to_dict(orient="records"))

        pair_ablation_df = run_head_ablation(
            pair_model,
            tokens=malicious_tokens,
            candidate_heads=candidate_heads,
            base_logit_diff=base_malicious_diff,
            allow_token_id=allow_token_id,
            block_token_id=block_token_id,
        )
        pair_ablation_df["pair_idx"] = pair_idx
        pair_ablation_df["pair_indicator"] = benign_row.get("pair_indicator", malicious_row.get("pair_indicator"))
        pair_ablation_df["benign_filename"] = benign_row["filename"]
        pair_ablation_df["malicious_filename"] = malicious_row["filename"]
        pair_ablation_df["base_benign_logit_diff"] = base_benign_diff
        pair_ablation_df["flip_to_benign"] = pair_ablation_df["ablated_logit_diff"] <= 0
        ablation_rows.extend(pair_ablation_df.to_dict(orient="records"))

        del benign_logits
        del malicious_logits
        del benign_tokens
        del malicious_tokens
        del benign_cache
        del malicious_cache
        if args.reload_model_per_pair:
            del pair_model
            del pair_hf_model
        maybe_clear_device_cache(device)

    patch_df = pd.DataFrame(patch_rows)
    ablation_df = pd.DataFrame(ablation_rows)
    patch_summary_df = summarize_causal_effects(
        patch_df,
        delta_column="delta_logit_diff",
        flip_column="flip_to_benign",
    )
    ablation_summary_df = summarize_causal_effects(
        ablation_df,
        delta_column="delta_logit_diff",
        flip_column="flip_to_benign",
    )

    output_prefix = Path(args.output_prefix or (DEFAULT_ARTIFACT_DIR / "batch_causal_l4"))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    patch_per_pair_path = output_prefix.with_name(output_prefix.name + "_patch_per_pair.csv")
    patch_summary_path = output_prefix.with_name(output_prefix.name + "_patch_summary.csv")
    ablation_per_pair_path = output_prefix.with_name(output_prefix.name + "_ablation_per_pair.csv")
    ablation_summary_path = output_prefix.with_name(output_prefix.name + "_ablation_summary.csv")
    metadata_path = output_prefix.with_name(output_prefix.name + "_metadata.json")

    patch_df.to_csv(patch_per_pair_path, index=False)
    patch_summary_df.to_csv(patch_summary_path, index=False)
    ablation_df.to_csv(ablation_per_pair_path, index=False)
    ablation_summary_df.to_csv(ablation_summary_path, index=False)
    write_json(
        metadata_path,
        {
            "heads": [{"layer": layer, "head": head} for layer, head in candidate_heads],
            "num_pairs": len(pairs),
            "first_n_layers": args.first_n_layers,
            "device": device,
            "reload_model_per_pair": bool(args.reload_model_per_pair),
            "template_name": args.template_name,
            "patch_per_pair_csv": str(patch_per_pair_path),
            "patch_summary_csv": str(patch_summary_path),
            "ablation_per_pair_csv": str(ablation_per_pair_path),
            "ablation_summary_csv": str(ablation_summary_path),
        },
    )

    print(
        json.dumps(
            {
                "metadata": str(metadata_path),
                "patch_summary_csv": str(patch_summary_path),
                "ablation_summary_csv": str(ablation_summary_path),
                "top_patch_head": patch_summary_df.iloc[0].to_dict() if len(patch_summary_df) else None,
                "top_ablation_head": ablation_summary_df.iloc[0].to_dict() if len(ablation_summary_df) else None,
                "num_pairs": len(pairs),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_batch_layer_ablation(args: argparse.Namespace) -> int:
    require_transformer_lens()

    manifest = pd.read_csv(args.manifest)
    pairs = select_short_pairs(
        manifest,
        num_pairs=args.num_pairs,
        malicious_requires_indicator=not args.allow_zero_indicator_malicious,
    )
    if not pairs:
        raise RuntimeError("No eligible benign/malicious pairs found for batch layer ablation.")

    hf_model, tokenizer, device = load_hf_model_and_tokenizer(
        args.model_name,
        device=args.device,
        torch_dtype=args.torch_dtype,
    )
    model = build_hooked_transformer(
        hf_model,
        tokenizer,
        device=device,
        torch_dtype=args.torch_dtype,
        template_name=args.template_name,
        first_n_layers=args.first_n_layers,
        use_attn_result=False,
    )
    model.eval()

    allow_token_id = tokenizer.encode(" ALLOW", add_special_tokens=False)[0]
    block_token_id = tokenizer.encode(" BLOCK", add_special_tokens=False)[0]
    components = tuple(component.strip() for component in args.components.split(",") if component.strip())

    layer_rows: List[Dict[str, object]] = []
    for fallback_idx, (benign_row, malicious_row) in enumerate(pairs, start=1):
        pair_idx = resolve_pair_idx(benign_row, malicious_row, fallback_idx=fallback_idx)
        malicious_prompt = make_prompt(malicious_row["content"])
        malicious_tokens = model.to_tokens(malicious_prompt)

        with torch.inference_mode():
            malicious_logits = model(malicious_tokens, return_type="logits")
        base_malicious_diff = logit_diff_from_logits(malicious_logits, allow_token_id, block_token_id)

        pair_df = run_layer_component_ablation(
            model,
            tokens=malicious_tokens,
            base_logit_diff=base_malicious_diff,
            allow_token_id=allow_token_id,
            block_token_id=block_token_id,
            components=components,
        )
        pair_df["pair_idx"] = pair_idx
        pair_df["pair_indicator"] = benign_row.get("pair_indicator", malicious_row.get("pair_indicator"))
        pair_df["benign_filename"] = benign_row["filename"]
        pair_df["malicious_filename"] = malicious_row["filename"]
        pair_df["flip_to_benign"] = pair_df["ablated_logit_diff"] <= 0
        layer_rows.extend(pair_df.to_dict(orient="records"))

        del malicious_logits
        del malicious_tokens
        maybe_clear_device_cache(device)

    layer_df = pd.DataFrame(layer_rows)
    summary_df = summarize_layer_component_effects(layer_df)

    output_prefix = Path(args.output_prefix or (DEFAULT_ARTIFACT_DIR / "batch_layer_ablation"))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    per_pair_path = output_prefix.with_name(output_prefix.name + "_per_pair.csv")
    summary_path = output_prefix.with_name(output_prefix.name + "_summary.csv")
    metadata_path = output_prefix.with_name(output_prefix.name + "_metadata.json")

    layer_df.to_csv(per_pair_path, index=False)
    summary_df.to_csv(summary_path, index=False)
    write_json(
        metadata_path,
        {
            "components": list(components),
            "num_pairs": len(pairs),
            "first_n_layers": args.first_n_layers,
            "device": device,
            "template_name": args.template_name,
            "per_pair_csv": str(per_pair_path),
            "summary_csv": str(summary_path),
        },
    )

    print(
        json.dumps(
            {
                "metadata": str(metadata_path),
                "summary_csv": str(summary_path),
                "top_effect": summary_df.iloc[0].to_dict() if len(summary_df) else None,
                "num_pairs": len(pairs),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_batch_neuron_discover(args: argparse.Namespace) -> int:
    require_transformer_lens()

    manifest = pd.read_csv(args.manifest)
    pairs = select_short_pairs(
        manifest,
        num_pairs=args.num_pairs,
        malicious_requires_indicator=not args.allow_zero_indicator_malicious,
    )
    if not pairs:
        raise RuntimeError("No eligible benign/malicious pairs found for batch neuron discovery.")

    target_layers = parse_int_list(args.layers)
    hf_model, tokenizer, device = load_hf_model_and_tokenizer(
        args.model_name,
        device=args.device,
        torch_dtype=args.torch_dtype,
    )
    model = build_hooked_transformer(
        hf_model,
        tokenizer,
        device=device,
        torch_dtype=args.torch_dtype,
        template_name=args.template_name,
        first_n_layers=args.first_n_layers,
        use_attn_result=False,
    )
    model.eval()

    allow_token_id = tokenizer.encode(" ALLOW", add_special_tokens=False)[0]
    block_token_id = tokenizer.encode(" BLOCK", add_special_tokens=False)[0]
    logit_dir = (model.W_U[:, block_token_id] - model.W_U[:, allow_token_id]).detach()

    rows: List[Dict[str, object]] = []
    for fallback_idx, (benign_row, malicious_row) in enumerate(pairs, start=1):
        pair_idx = resolve_pair_idx(benign_row, malicious_row, fallback_idx=fallback_idx)
        benign_prompt = make_prompt(benign_row["content"])
        malicious_prompt = make_prompt(malicious_row["content"])
        benign_tokens = model.to_tokens(benign_prompt)
        malicious_tokens = model.to_tokens(malicious_prompt)

        with torch.inference_mode():
            _, benign_cache = model.run_with_cache(benign_tokens, return_type="logits")
            _, malicious_cache = model.run_with_cache(malicious_tokens, return_type="logits")

        for layer in target_layers:
            benign_post = benign_cache[f"blocks.{layer}.mlp.hook_post"][0, -1].detach().clone()
            malicious_post = malicious_cache[f"blocks.{layer}.mlp.hook_post"][0, -1].detach().clone()
            delta_post = malicious_post - benign_post
            neuron_logit_weights = torch.matmul(model.blocks[layer].mlp.W_out, logit_dir).detach().clone()
            contribution_delta = delta_post * neuron_logit_weights
            malicious_contribution = malicious_post * neuron_logit_weights

            topk = min(args.topk_per_layer, int(contribution_delta.shape[0]))
            top_values, top_indices = torch.topk(contribution_delta, k=topk)
            for score, neuron in zip(top_values.tolist(), top_indices.tolist()):
                rows.append(
                    {
                        "pair_idx": pair_idx,
                        "pair_indicator": benign_row.get("pair_indicator", malicious_row.get("pair_indicator")),
                        "layer": layer,
                        "neuron": int(neuron),
                        "contribution_delta": float(score),
                        "malicious_contribution": float(malicious_contribution[neuron].item()),
                        "activation_delta": float(delta_post[neuron].item()),
                        "benign_filename": benign_row["filename"],
                        "malicious_filename": malicious_row["filename"],
                    }
                )

        del benign_cache
        del malicious_cache
        del benign_tokens
        del malicious_tokens
        maybe_clear_device_cache(device)

    per_pair_df = pd.DataFrame(rows)
    summary_df = (
        per_pair_df.groupby(["layer", "neuron"], as_index=False)
        .agg(
            pair_count=("pair_idx", "nunique"),
            mean_contribution_delta=("contribution_delta", "mean"),
            max_contribution_delta=("contribution_delta", "max"),
            mean_malicious_contribution=("malicious_contribution", "mean"),
            mean_activation_delta=("activation_delta", "mean"),
        )
        .sort_values(["layer", "mean_contribution_delta"], ascending=[True, False])
        .reset_index(drop=True)
    )

    output_prefix = Path(args.output_prefix or (DEFAULT_ARTIFACT_DIR / "batch_neuron_discovery"))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    per_pair_path = output_prefix.with_name(output_prefix.name + "_per_pair.csv")
    summary_path = output_prefix.with_name(output_prefix.name + "_summary.csv")
    metadata_path = output_prefix.with_name(output_prefix.name + "_metadata.json")
    per_pair_df.to_csv(per_pair_path, index=False)
    summary_df.to_csv(summary_path, index=False)
    write_json(
        metadata_path,
        {
            "layers": target_layers,
            "num_pairs": len(pairs),
            "topk_per_layer": args.topk_per_layer,
            "first_n_layers": args.first_n_layers,
            "device": device,
            "template_name": args.template_name,
            "per_pair_csv": str(per_pair_path),
            "summary_csv": str(summary_path),
        },
    )

    print(
        json.dumps(
            {
                "metadata": str(metadata_path),
                "summary_csv": str(summary_path),
                "top_rows": summary_df.groupby("layer").head(min(args.topk_per_layer, 5)).to_dict(orient="records"),
                "num_pairs": len(pairs),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_batch_neuron_ablation(args: argparse.Namespace) -> int:
    require_transformer_lens()

    manifest = pd.read_csv(args.manifest)
    pairs = select_short_pairs(
        manifest,
        num_pairs=args.num_pairs,
        malicious_requires_indicator=not args.allow_zero_indicator_malicious,
    )
    if not pairs:
        raise RuntimeError("No eligible benign/malicious pairs found for batch neuron ablation.")

    if args.neurons:
        neuron_specs = parse_neuron_list(args.neurons)
    elif args.neuron_summary:
        summary_df = pd.read_csv(args.neuron_summary)
        neuron_specs = []
        for layer in sorted(summary_df["layer"].unique().tolist()):
            layer_df = summary_df[summary_df["layer"] == layer].sort_values(
                "mean_contribution_delta", ascending=False
            )
            for _, row in layer_df.head(args.top_k_per_layer).iterrows():
                neuron_specs.append((int(row["layer"]), int(row["neuron"])))
    else:
        raise ValueError("Provide either --neurons or --neuron-summary.")

    grouped_neurons: Dict[int, List[int]] = {}
    for layer, neuron in neuron_specs:
        grouped_neurons.setdefault(layer, []).append(neuron)

    hf_model, tokenizer, device = load_hf_model_and_tokenizer(
        args.model_name,
        device=args.device,
        torch_dtype=args.torch_dtype,
    )
    model = build_hooked_transformer(
        hf_model,
        tokenizer,
        device=device,
        torch_dtype=args.torch_dtype,
        template_name=args.template_name,
        first_n_layers=args.first_n_layers,
        use_attn_result=False,
    )
    model.eval()

    allow_token_id = tokenizer.encode(" ALLOW", add_special_tokens=False)[0]
    block_token_id = tokenizer.encode(" BLOCK", add_special_tokens=False)[0]

    rows: List[Dict[str, object]] = []
    for fallback_idx, (benign_row, malicious_row) in enumerate(pairs, start=1):
        pair_idx = resolve_pair_idx(benign_row, malicious_row, fallback_idx=fallback_idx)
        malicious_prompt = make_prompt(malicious_row["content"])
        malicious_tokens = model.to_tokens(malicious_prompt)

        with torch.inference_mode():
            malicious_logits = model(malicious_tokens, return_type="logits")
        base_malicious_diff = logit_diff_from_logits(malicious_logits, allow_token_id, block_token_id)

        for layer, neurons in grouped_neurons.items():
            pair_df = run_neuron_ablation(
                model,
                tokens=malicious_tokens,
                layer=layer,
                neurons=neurons,
                base_logit_diff=base_malicious_diff,
                allow_token_id=allow_token_id,
                block_token_id=block_token_id,
            )
            pair_df["pair_idx"] = pair_idx
            pair_df["pair_indicator"] = benign_row.get("pair_indicator", malicious_row.get("pair_indicator"))
            pair_df["benign_filename"] = benign_row["filename"]
            pair_df["malicious_filename"] = malicious_row["filename"]
            pair_df["flip_to_benign"] = pair_df["ablated_logit_diff"] <= 0
            rows.extend(pair_df.to_dict(orient="records"))

        del malicious_logits
        del malicious_tokens
        maybe_clear_device_cache(device)

    per_pair_df = pd.DataFrame(rows)
    summary_df = summarize_neuron_effects(per_pair_df)

    output_prefix = Path(args.output_prefix or (DEFAULT_ARTIFACT_DIR / "batch_neuron_ablation"))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    per_pair_path = output_prefix.with_name(output_prefix.name + "_per_pair.csv")
    summary_path = output_prefix.with_name(output_prefix.name + "_summary.csv")
    metadata_path = output_prefix.with_name(output_prefix.name + "_metadata.json")
    per_pair_df.to_csv(per_pair_path, index=False)
    summary_df.to_csv(summary_path, index=False)
    write_json(
        metadata_path,
        {
            "neurons": [{"layer": layer, "neuron": neuron} for layer, neuron in neuron_specs],
            "num_pairs": len(pairs),
            "first_n_layers": args.first_n_layers,
            "device": device,
            "template_name": args.template_name,
            "per_pair_csv": str(per_pair_path),
            "summary_csv": str(summary_path),
        },
    )

    print(
        json.dumps(
            {
                "metadata": str(metadata_path),
                "summary_csv": str(summary_path),
                "top_rows": summary_df.groupby("layer").head(min(args.top_k_per_layer, 5)).to_dict(orient="records"),
                "num_pairs": len(pairs),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_batch_neuron_group_ablation(args: argparse.Namespace) -> int:
    require_transformer_lens()

    manifest = pd.read_csv(args.manifest)
    pairs = select_short_pairs(
        manifest,
        num_pairs=args.num_pairs,
        malicious_requires_indicator=not args.allow_zero_indicator_malicious,
    )
    if not pairs:
        raise RuntimeError("No eligible benign/malicious pairs found for grouped neuron ablation.")

    neuron_summary = pd.read_csv(args.neuron_summary)
    target_layers = parse_int_list(args.layers)
    group_sizes = parse_int_list(args.group_sizes)

    neurons_by_layer: Dict[int, Dict[int, List[int]]] = {}
    for layer in target_layers:
        layer_df = neuron_summary[neuron_summary["layer"] == layer].sort_values(
            ["pair_count", "mean_contribution_delta"], ascending=[False, False]
        )
        if layer_df.empty:
            raise ValueError(f"No neuron discovery rows found for layer {layer}.")
        neurons_by_layer[layer] = {}
        ordered = layer_df["neuron"].astype(int).tolist()
        for group_size in group_sizes:
            if len(ordered) < group_size:
                raise ValueError(f"Layer {layer} has only {len(ordered)} discovered neurons, need {group_size}.")
            neurons_by_layer[layer][group_size] = ordered[:group_size]

    hf_model, tokenizer, device = load_hf_model_and_tokenizer(
        args.model_name,
        device=args.device,
        torch_dtype=args.torch_dtype,
    )
    model = build_hooked_transformer(
        hf_model,
        tokenizer,
        device=device,
        torch_dtype=args.torch_dtype,
        template_name=args.template_name,
        first_n_layers=args.first_n_layers,
        use_attn_result=False,
    )
    model.eval()

    allow_token_id = tokenizer.encode(" ALLOW", add_special_tokens=False)[0]
    block_token_id = tokenizer.encode(" BLOCK", add_special_tokens=False)[0]

    rows: List[Dict[str, object]] = []
    for fallback_idx, (benign_row, malicious_row) in enumerate(pairs, start=1):
        pair_idx = resolve_pair_idx(benign_row, malicious_row, fallback_idx=fallback_idx)
        malicious_prompt = make_prompt(malicious_row["content"])
        malicious_tokens = model.to_tokens(malicious_prompt)

        with torch.inference_mode():
            malicious_logits = model(malicious_tokens, return_type="logits")
        base_malicious_diff = logit_diff_from_logits(malicious_logits, allow_token_id, block_token_id)

        for layer in target_layers:
            for group_size in group_sizes:
                result = run_neuron_group_ablation(
                    model,
                    tokens=malicious_tokens,
                    layer=layer,
                    neurons=neurons_by_layer[layer][group_size],
                    base_logit_diff=base_malicious_diff,
                    allow_token_id=allow_token_id,
                    block_token_id=block_token_id,
                )
                result["pair_idx"] = pair_idx
                result["pair_indicator"] = benign_row.get("pair_indicator", malicious_row.get("pair_indicator"))
                result["benign_filename"] = benign_row["filename"]
                result["malicious_filename"] = malicious_row["filename"]
                result["flip_to_benign"] = result["ablated_logit_diff"] <= 0
                rows.append(result)

        del malicious_logits
        del malicious_tokens
        maybe_clear_device_cache(device)

    per_pair_df = pd.DataFrame(rows)
    summary_df = summarize_neuron_group_effects(per_pair_df)

    output_prefix = Path(args.output_prefix or (DEFAULT_ARTIFACT_DIR / "batch_neuron_group_ablation"))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    per_pair_path = output_prefix.with_name(output_prefix.name + "_per_pair.csv")
    summary_path = output_prefix.with_name(output_prefix.name + "_summary.csv")
    metadata_path = output_prefix.with_name(output_prefix.name + "_metadata.json")
    per_pair_df.to_csv(per_pair_path, index=False)
    summary_df.to_csv(summary_path, index=False)
    write_json(
        metadata_path,
        {
            "layers": target_layers,
            "group_sizes": group_sizes,
            "num_pairs": len(pairs),
            "first_n_layers": args.first_n_layers,
            "device": device,
            "template_name": args.template_name,
            "per_pair_csv": str(per_pair_path),
            "summary_csv": str(summary_path),
        },
    )

    print(
        json.dumps(
            {
                "metadata": str(metadata_path),
                "summary_csv": str(summary_path),
                "rows": summary_df.to_dict(orient="records"),
                "num_pairs": len(pairs),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_batch_layer_patching(args: argparse.Namespace) -> int:
    require_transformer_lens()

    manifest = pd.read_csv(args.manifest)
    pairs = select_short_pairs(
        manifest,
        num_pairs=args.num_pairs,
        malicious_requires_indicator=not args.allow_zero_indicator_malicious,
    )
    if not pairs:
        raise RuntimeError("No eligible benign/malicious pairs found for layer patching.")

    target_layers = parse_int_list(args.layers)
    components = tuple(component.strip() for component in args.components.split(",") if component.strip())
    hf_model, tokenizer, device = load_hf_model_and_tokenizer(
        args.model_name,
        device=args.device,
        torch_dtype=args.torch_dtype,
    )
    model = build_hooked_transformer(
        hf_model,
        tokenizer,
        device=device,
        torch_dtype=args.torch_dtype,
        template_name=args.template_name,
        first_n_layers=args.first_n_layers,
        use_attn_result=False,
    )
    model.eval()

    allow_token_id = tokenizer.encode(" ALLOW", add_special_tokens=False)[0]
    block_token_id = tokenizer.encode(" BLOCK", add_special_tokens=False)[0]

    rows: List[Dict[str, object]] = []
    for fallback_idx, (benign_row, malicious_row) in enumerate(pairs, start=1):
        pair_idx = resolve_pair_idx(benign_row, malicious_row, fallback_idx=fallback_idx)
        benign_prompt = make_prompt(benign_row["content"])
        malicious_prompt = make_prompt(malicious_row["content"])
        benign_tokens = model.to_tokens(benign_prompt)
        malicious_tokens = model.to_tokens(malicious_prompt)

        with torch.inference_mode():
            _, benign_cache = model.run_with_cache(benign_tokens, return_type="logits")
            malicious_logits = model(malicious_tokens, return_type="logits")
        base_malicious_diff = logit_diff_from_logits(malicious_logits, allow_token_id, block_token_id)

        pair_df = run_layer_component_patching(
            model,
            corrupted_tokens=malicious_tokens,
            clean_cache=benign_cache,
            layers=target_layers,
            components=components,
            base_logit_diff=base_malicious_diff,
            allow_token_id=allow_token_id,
            block_token_id=block_token_id,
        )
        pair_df["pair_idx"] = pair_idx
        pair_df["pair_indicator"] = benign_row.get("pair_indicator", malicious_row.get("pair_indicator"))
        pair_df["benign_filename"] = benign_row["filename"]
        pair_df["malicious_filename"] = malicious_row["filename"]
        pair_df["flip_to_benign"] = pair_df["patched_logit_diff"] <= 0
        rows.extend(pair_df.to_dict(orient="records"))

        del benign_cache
        del malicious_logits
        del benign_tokens
        del malicious_tokens
        maybe_clear_device_cache(device)

    per_pair_df = pd.DataFrame(rows)
    summary_df = summarize_layer_component_patch_effects(per_pair_df)

    output_prefix = Path(args.output_prefix or (DEFAULT_ARTIFACT_DIR / "batch_layer_patching"))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    per_pair_path = output_prefix.with_name(output_prefix.name + "_per_pair.csv")
    summary_path = output_prefix.with_name(output_prefix.name + "_summary.csv")
    metadata_path = output_prefix.with_name(output_prefix.name + "_metadata.json")
    per_pair_df.to_csv(per_pair_path, index=False)
    summary_df.to_csv(summary_path, index=False)
    write_json(
        metadata_path,
        {
            "layers": target_layers,
            "components": list(components),
            "num_pairs": len(pairs),
            "first_n_layers": args.first_n_layers,
            "device": device,
            "template_name": args.template_name,
            "per_pair_csv": str(per_pair_path),
            "summary_csv": str(summary_path),
        },
    )

    print(
        json.dumps(
            {
                "metadata": str(metadata_path),
                "summary_csv": str(summary_path),
                "rows": summary_df.to_dict(orient="records"),
                "num_pairs": len(pairs),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_batch_path_patching(args: argparse.Namespace) -> int:
    require_transformer_lens()

    manifest = pd.read_csv(args.manifest)
    pairs = select_short_pairs(
        manifest,
        num_pairs=args.num_pairs,
        malicious_requires_indicator=not args.allow_zero_indicator_malicious,
    )
    if not pairs:
        raise RuntimeError("No eligible benign/malicious pairs found for path patching.")

    patch_variants: List[Dict[str, object]] = []
    if args.heads:
        patch_variants.append({"heads": parse_head_list(args.heads), "components": [], "residuals": []})
    if args.components:
        patch_variants.append({"heads": [], "components": parse_layer_component_list(args.components), "residuals": []})
    if args.residuals:
        residual_specs = [(layer, args.resid_kind) for layer in parse_int_list(args.residuals)]
        patch_variants.append({"heads": [], "components": [], "residuals": residual_specs})
    if args.combined:
        patch_variants.append(
            {
                "heads": parse_head_list(args.heads) if args.heads else [],
                "components": parse_layer_component_list(args.components) if args.components else [],
                "residuals": [(layer, args.resid_kind) for layer in parse_int_list(args.residuals)] if args.residuals else [],
            }
        )

    if not patch_variants:
        raise ValueError("Provide at least one of --heads, --components, --residuals, or --combined.")

    hf_model, tokenizer, device = load_hf_model_and_tokenizer(
        args.model_name,
        device=args.device,
        torch_dtype=args.torch_dtype,
    )
    model = build_hooked_transformer(
        hf_model,
        tokenizer,
        device=device,
        torch_dtype=args.torch_dtype,
        template_name=args.template_name,
        first_n_layers=args.first_n_layers,
        use_attn_result=False,
    )
    model.eval()

    allow_token_id = tokenizer.encode(" ALLOW", add_special_tokens=False)[0]
    block_token_id = tokenizer.encode(" BLOCK", add_special_tokens=False)[0]

    rows: List[Dict[str, object]] = []
    for fallback_idx, (benign_row, malicious_row) in enumerate(pairs, start=1):
        pair_idx = resolve_pair_idx(benign_row, malicious_row, fallback_idx=fallback_idx)
        benign_prompt = make_prompt(benign_row["content"])
        malicious_prompt = make_prompt(malicious_row["content"])
        benign_tokens = model.to_tokens(benign_prompt)
        malicious_tokens = model.to_tokens(malicious_prompt)

        with torch.inference_mode():
            _, benign_cache = model.run_with_cache(benign_tokens, return_type="logits")
            malicious_logits = model(malicious_tokens, return_type="logits")
        base_malicious_diff = logit_diff_from_logits(malicious_logits, allow_token_id, block_token_id)

        for variant in patch_variants:
            result = run_multi_path_patching(
                model,
                corrupted_tokens=malicious_tokens,
                clean_cache=benign_cache,
                base_logit_diff=base_malicious_diff,
                allow_token_id=allow_token_id,
                block_token_id=block_token_id,
                head_specs=variant["heads"],
                component_specs=variant["components"],
                residual_specs=variant["residuals"],
            )
            result["pair_idx"] = pair_idx
            result["pair_indicator"] = benign_row.get("pair_indicator", malicious_row.get("pair_indicator"))
            result["benign_filename"] = benign_row["filename"]
            result["malicious_filename"] = malicious_row["filename"]
            result["flip_to_benign"] = result["patched_logit_diff"] <= 0
            rows.append(result)

        del benign_cache
        del malicious_logits
        del benign_tokens
        del malicious_tokens
        maybe_clear_device_cache(device)

    per_pair_df = pd.DataFrame(rows)
    summary_df = summarize_path_patch_effects(per_pair_df)

    output_prefix = Path(args.output_prefix or (DEFAULT_ARTIFACT_DIR / "batch_path_patching"))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    per_pair_path = output_prefix.with_name(output_prefix.name + "_per_pair.csv")
    summary_path = output_prefix.with_name(output_prefix.name + "_summary.csv")
    metadata_path = output_prefix.with_name(output_prefix.name + "_metadata.json")
    per_pair_df.to_csv(per_pair_path, index=False)
    summary_df.to_csv(summary_path, index=False)
    write_json(
        metadata_path,
        {
            "heads": args.heads,
            "components": args.components,
            "residuals": args.residuals,
            "resid_kind": args.resid_kind,
            "combined": bool(args.combined),
            "num_pairs": len(pairs),
            "first_n_layers": args.first_n_layers,
            "device": device,
            "template_name": args.template_name,
            "per_pair_csv": str(per_pair_path),
            "summary_csv": str(summary_path),
        },
    )

    print(
        json.dumps(
            {
                "metadata": str(metadata_path),
                "summary_csv": str(summary_path),
                "rows": summary_df.to_dict(orient="records"),
                "num_pairs": len(pairs),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_discover_residual_subspace(args: argparse.Namespace) -> int:
    require_transformer_lens()

    manifest = pd.read_csv(args.manifest)
    pairs = select_short_pairs(
        manifest,
        num_pairs=args.num_pairs,
        malicious_requires_indicator=not args.allow_zero_indicator_malicious,
    )
    if not pairs:
        raise RuntimeError("No eligible benign/malicious pairs found for residual subspace discovery.")

    hf_model, tokenizer, device = load_hf_model_and_tokenizer(
        args.model_name,
        device=args.device,
        torch_dtype=args.torch_dtype,
    )
    model = build_hooked_transformer(
        hf_model,
        tokenizer,
        device=device,
        torch_dtype=args.torch_dtype,
        template_name=args.template_name,
        first_n_layers=args.first_n_layers,
        use_attn_result=False,
    )
    model.eval()

    hook_name = build_residual_hook_name(args.layer, args.resid_kind)
    delta_rows: List[torch.Tensor] = []
    pair_rows: List[Dict[str, object]] = []
    for fallback_idx, (benign_row, malicious_row) in enumerate(pairs, start=1):
        pair_idx = resolve_pair_idx(benign_row, malicious_row, fallback_idx=fallback_idx)
        benign_tokens = model.to_tokens(make_prompt(benign_row["content"]))
        malicious_tokens = model.to_tokens(make_prompt(malicious_row["content"]))

        with torch.inference_mode():
            _, benign_cache = model.run_with_cache(benign_tokens, return_type="logits")
            _, malicious_cache = model.run_with_cache(malicious_tokens, return_type="logits")

        benign_vec = benign_cache[hook_name][0, -1, :].detach().clone().cpu()
        malicious_vec = malicious_cache[hook_name][0, -1, :].detach().clone().cpu()
        delta_vec = malicious_vec - benign_vec
        delta_rows.append(delta_vec)
        pair_rows.append(
            {
                "pair_idx": pair_idx,
                "pair_indicator": benign_row.get("pair_indicator", malicious_row.get("pair_indicator")),
                "benign_filename": benign_row["filename"],
                "malicious_filename": malicious_row["filename"],
                "delta_norm": float(delta_vec.norm().item()),
            }
        )

        del benign_cache
        del malicious_cache
        del benign_tokens
        del malicious_tokens
        maybe_clear_device_cache(device)

    delta_tensor = torch.stack(delta_rows, dim=0)
    basis, explained = compute_residual_subspace(delta_tensor, max_rank=args.max_rank)

    output_prefix = Path(args.output_prefix or (DEFAULT_ARTIFACT_DIR / "residual_subspace"))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    basis_path = output_prefix.with_name(output_prefix.name + "_basis.pt")
    pairs_path = output_prefix.with_name(output_prefix.name + "_pairs.csv")
    metadata_path = output_prefix.with_name(output_prefix.name + "_metadata.json")
    torch.save(
        {
            "basis": basis,
            "layer": args.layer,
            "resid_kind": args.resid_kind,
            "explained_cumulative": explained,
        },
        basis_path,
    )
    pd.DataFrame(pair_rows).to_csv(pairs_path, index=False)
    write_json(
        metadata_path,
        {
            "layer": args.layer,
            "resid_kind": args.resid_kind,
            "num_pairs": len(pairs),
            "max_rank": args.max_rank,
            "explained_cumulative": explained,
            "basis_path": str(basis_path),
            "pairs_csv": str(pairs_path),
            "device": device,
            "template_name": args.template_name,
        },
    )

    print(
        json.dumps(
            {
                "metadata": str(metadata_path),
                "basis_path": str(basis_path),
                "pairs_csv": str(pairs_path),
                "explained_cumulative": explained,
                "num_pairs": len(pairs),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_batch_residual_subspace_patching(args: argparse.Namespace) -> int:
    require_transformer_lens()

    manifest = pd.read_csv(args.manifest)
    pairs = select_short_pairs(
        manifest,
        num_pairs=args.num_pairs,
        malicious_requires_indicator=not args.allow_zero_indicator_malicious,
    )
    if not pairs:
        raise RuntimeError("No eligible benign/malicious pairs found for residual subspace patching.")

    bundle = torch.load(args.basis_path, map_location="cpu")
    basis = bundle["basis"].detach().cpu()
    layer = int(bundle["layer"])
    resid_kind = str(bundle["resid_kind"])
    subspace_dims = parse_int_list(args.subspace_dims)
    max_dim = basis.shape[1]
    for subspace_dim in subspace_dims:
        if subspace_dim > max_dim:
            raise ValueError(f"Requested subspace dim {subspace_dim} exceeds basis rank {max_dim}.")

    hf_model, tokenizer, device = load_hf_model_and_tokenizer(
        args.model_name,
        device=args.device,
        torch_dtype=args.torch_dtype,
    )
    model = build_hooked_transformer(
        hf_model,
        tokenizer,
        device=device,
        torch_dtype=args.torch_dtype,
        template_name=args.template_name,
        first_n_layers=args.first_n_layers,
        use_attn_result=False,
    )
    model.eval()

    allow_token_id = tokenizer.encode(" ALLOW", add_special_tokens=False)[0]
    block_token_id = tokenizer.encode(" BLOCK", add_special_tokens=False)[0]
    basis = basis.to(device=device, dtype=model.cfg.dtype)

    rows: List[Dict[str, object]] = []
    for fallback_idx, (benign_row, malicious_row) in enumerate(pairs, start=1):
        pair_idx = resolve_pair_idx(benign_row, malicious_row, fallback_idx=fallback_idx)
        benign_tokens = model.to_tokens(make_prompt(benign_row["content"]))
        malicious_tokens = model.to_tokens(make_prompt(malicious_row["content"]))

        with torch.inference_mode():
            _, benign_cache = model.run_with_cache(benign_tokens, return_type="logits")
            malicious_logits = model(malicious_tokens, return_type="logits")
        base_malicious_diff = logit_diff_from_logits(malicious_logits, allow_token_id, block_token_id)

        for subspace_dim in subspace_dims:
            result = run_residual_subspace_patching(
                model,
                corrupted_tokens=malicious_tokens,
                clean_cache=benign_cache,
                layer=layer,
                resid_kind=resid_kind,
                basis=basis,
                subspace_dim=subspace_dim,
                base_logit_diff=base_malicious_diff,
                allow_token_id=allow_token_id,
                block_token_id=block_token_id,
            )
            result["pair_idx"] = pair_idx
            result["pair_indicator"] = benign_row.get("pair_indicator", malicious_row.get("pair_indicator"))
            result["benign_filename"] = benign_row["filename"]
            result["malicious_filename"] = malicious_row["filename"]
            result["flip_to_benign"] = result["patched_logit_diff"] <= 0
            rows.append(result)

        del benign_cache
        del malicious_logits
        del benign_tokens
        del malicious_tokens
        maybe_clear_device_cache(device)

    per_pair_df = pd.DataFrame(rows)
    summary_df = summarize_residual_subspace_patch_effects(per_pair_df)

    output_prefix = Path(args.output_prefix or (DEFAULT_ARTIFACT_DIR / "residual_subspace_patching"))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    per_pair_path = output_prefix.with_name(output_prefix.name + "_per_pair.csv")
    summary_path = output_prefix.with_name(output_prefix.name + "_summary.csv")
    metadata_path = output_prefix.with_name(output_prefix.name + "_metadata.json")
    per_pair_df.to_csv(per_pair_path, index=False)
    summary_df.to_csv(summary_path, index=False)
    write_json(
        metadata_path,
        {
            "basis_path": str(args.basis_path),
            "layer": layer,
            "resid_kind": resid_kind,
            "subspace_dims": subspace_dims,
            "num_pairs": len(pairs),
            "device": device,
            "template_name": args.template_name,
            "per_pair_csv": str(per_pair_path),
            "summary_csv": str(summary_path),
        },
    )

    print(
        json.dumps(
            {
                "metadata": str(metadata_path),
                "summary_csv": str(summary_path),
                "rows": summary_df.to_dict(orient="records"),
                "num_pairs": len(pairs),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_discover_contrastive_residual_directions(args: argparse.Namespace) -> int:
    require_transformer_lens()

    manifest = pd.read_csv(args.manifest)
    pairs = select_short_pairs(
        manifest,
        num_pairs=args.num_pairs,
        malicious_requires_indicator=not args.allow_zero_indicator_malicious,
    )
    if not pairs:
        raise RuntimeError("No eligible benign/malicious pairs found for contrastive residual discovery.")

    hf_model, tokenizer, device = load_hf_model_and_tokenizer(
        args.model_name,
        device=args.device,
        torch_dtype=args.torch_dtype,
    )
    model = build_hooked_transformer(
        hf_model,
        tokenizer,
        device=device,
        torch_dtype=args.torch_dtype,
        template_name=args.template_name,
        first_n_layers=args.first_n_layers,
        use_attn_result=False,
    )
    model.eval()

    allow_token_id = tokenizer.encode(" ALLOW", add_special_tokens=False)[0]
    block_token_id = tokenizer.encode(" BLOCK", add_special_tokens=False)[0]
    logit_dir = (model.W_U[:, block_token_id] - model.W_U[:, allow_token_id]).detach().cpu()

    hook_name = build_residual_hook_name(args.layer, args.resid_kind)
    delta_rows: List[torch.Tensor] = []
    pair_rows: List[Dict[str, object]] = []
    for fallback_idx, (benign_row, malicious_row) in enumerate(pairs, start=1):
        pair_idx = resolve_pair_idx(benign_row, malicious_row, fallback_idx=fallback_idx)
        benign_tokens = model.to_tokens(make_prompt(benign_row["content"]))
        malicious_tokens = model.to_tokens(make_prompt(malicious_row["content"]))

        with torch.inference_mode():
            _, benign_cache = model.run_with_cache(benign_tokens, return_type="logits")
            _, malicious_cache = model.run_with_cache(malicious_tokens, return_type="logits")

        benign_vec = benign_cache[hook_name][0, -1, :].detach().clone().cpu()
        malicious_vec = malicious_cache[hook_name][0, -1, :].detach().clone().cpu()
        delta_vec = malicious_vec - benign_vec
        delta_rows.append(delta_vec)
        pair_rows.append(
            {
                "pair_idx": pair_idx,
                "pair_indicator": benign_row.get("pair_indicator", malicious_row.get("pair_indicator")),
                "benign_filename": benign_row["filename"],
                "malicious_filename": malicious_row["filename"],
                "delta_norm": float(delta_vec.norm().item()),
            }
        )

        del benign_cache
        del malicious_cache
        del benign_tokens
        del malicious_tokens
        maybe_clear_device_cache(device)

    delta_tensor = torch.stack(delta_rows, dim=0)
    basis, labels, diagnostics = compute_contrastive_residual_basis(delta_tensor, logit_dir=logit_dir)

    output_prefix = Path(args.output_prefix or (DEFAULT_ARTIFACT_DIR / "contrastive_residual_directions"))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    basis_path = output_prefix.with_name(output_prefix.name + "_basis.pt")
    pairs_path = output_prefix.with_name(output_prefix.name + "_pairs.csv")
    metadata_path = output_prefix.with_name(output_prefix.name + "_metadata.json")
    torch.save(
        {
            "basis": basis,
            "basis_labels": labels,
            "layer": args.layer,
            "resid_kind": args.resid_kind,
            "diagnostics": diagnostics,
        },
        basis_path,
    )
    pd.DataFrame(pair_rows).to_csv(pairs_path, index=False)
    write_json(
        metadata_path,
        {
            "layer": args.layer,
            "resid_kind": args.resid_kind,
            "num_pairs": len(pairs),
            "basis_labels": labels,
            "diagnostics": diagnostics,
            "basis_path": str(basis_path),
            "pairs_csv": str(pairs_path),
            "device": device,
            "template_name": args.template_name,
        },
    )

    print(
        json.dumps(
            {
                "metadata": str(metadata_path),
                "basis_path": str(basis_path),
                "pairs_csv": str(pairs_path),
                "basis_labels": labels,
                "diagnostics": diagnostics,
                "num_pairs": len(pairs),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_batch_contrastive_residual_patching(args: argparse.Namespace) -> int:
    require_transformer_lens()

    manifest = pd.read_csv(args.manifest)
    pairs = select_short_pairs(
        manifest,
        num_pairs=args.num_pairs,
        malicious_requires_indicator=not args.allow_zero_indicator_malicious,
    )
    if not pairs:
        raise RuntimeError("No eligible benign/malicious pairs found for contrastive residual patching.")

    bundle = torch.load(args.basis_path, map_location="cpu")
    basis = bundle["basis"].detach().cpu()
    labels = list(bundle.get("basis_labels", [f"dir_{index}" for index in range(basis.shape[1])]))
    layer = int(bundle["layer"])
    resid_kind = str(bundle["resid_kind"])
    if basis.shape[1] != len(labels):
        raise ValueError("Contrastive basis labels do not match basis rank.")

    hf_model, tokenizer, device = load_hf_model_and_tokenizer(
        args.model_name,
        device=args.device,
        torch_dtype=args.torch_dtype,
    )
    model = build_hooked_transformer(
        hf_model,
        tokenizer,
        device=device,
        torch_dtype=args.torch_dtype,
        template_name=args.template_name,
        first_n_layers=args.first_n_layers,
        use_attn_result=False,
    )
    model.eval()

    allow_token_id = tokenizer.encode(" ALLOW", add_special_tokens=False)[0]
    block_token_id = tokenizer.encode(" BLOCK", add_special_tokens=False)[0]
    basis = basis.to(device=device, dtype=model.cfg.dtype)

    rows: List[Dict[str, object]] = []
    for fallback_idx, (benign_row, malicious_row) in enumerate(pairs, start=1):
        pair_idx = resolve_pair_idx(benign_row, malicious_row, fallback_idx=fallback_idx)
        benign_tokens = model.to_tokens(make_prompt(benign_row["content"]))
        malicious_tokens = model.to_tokens(make_prompt(malicious_row["content"]))

        with torch.inference_mode():
            _, benign_cache = model.run_with_cache(benign_tokens, return_type="logits")
            malicious_logits = model(malicious_tokens, return_type="logits")
        base_malicious_diff = logit_diff_from_logits(malicious_logits, allow_token_id, block_token_id)

        for index, label in enumerate(labels):
            result = run_named_residual_basis_patching(
                model,
                corrupted_tokens=malicious_tokens,
                clean_cache=benign_cache,
                layer=layer,
                resid_kind=resid_kind,
                basis=basis[:, index : index + 1],
                patch_label=f"contrastive_{resid_kind}{layer}_{label}",
                base_logit_diff=base_malicious_diff,
                allow_token_id=allow_token_id,
                block_token_id=block_token_id,
            )
            result["basis_label"] = label
            result["basis_mode"] = "single"
            result["pair_idx"] = pair_idx
            result["pair_indicator"] = benign_row.get("pair_indicator", malicious_row.get("pair_indicator"))
            result["benign_filename"] = benign_row["filename"]
            result["malicious_filename"] = malicious_row["filename"]
            result["flip_to_benign"] = result["patched_logit_diff"] <= 0
            rows.append(result)

        if len(labels) > 1:
            result = run_named_residual_basis_patching(
                model,
                corrupted_tokens=malicious_tokens,
                clean_cache=benign_cache,
                layer=layer,
                resid_kind=resid_kind,
                basis=basis,
                patch_label=f"contrastive_{resid_kind}{layer}_all",
                base_logit_diff=base_malicious_diff,
                allow_token_id=allow_token_id,
                block_token_id=block_token_id,
            )
            result["basis_label"] = "+".join(labels)
            result["basis_mode"] = "all"
            result["pair_idx"] = pair_idx
            result["pair_indicator"] = benign_row.get("pair_indicator", malicious_row.get("pair_indicator"))
            result["benign_filename"] = benign_row["filename"]
            result["malicious_filename"] = malicious_row["filename"]
            result["flip_to_benign"] = result["patched_logit_diff"] <= 0
            rows.append(result)

        del benign_cache
        del malicious_logits
        del benign_tokens
        del malicious_tokens
        maybe_clear_device_cache(device)

    per_pair_df = pd.DataFrame(rows)
    summary_df = summarize_path_patch_effects(per_pair_df)

    output_prefix = Path(args.output_prefix or (DEFAULT_ARTIFACT_DIR / "contrastive_residual_patching"))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    per_pair_path = output_prefix.with_name(output_prefix.name + "_per_pair.csv")
    summary_path = output_prefix.with_name(output_prefix.name + "_summary.csv")
    metadata_path = output_prefix.with_name(output_prefix.name + "_metadata.json")
    per_pair_df.to_csv(per_pair_path, index=False)
    summary_df.to_csv(summary_path, index=False)
    write_json(
        metadata_path,
        {
            "basis_path": str(args.basis_path),
            "basis_labels": labels,
            "layer": layer,
            "resid_kind": resid_kind,
            "num_pairs": len(pairs),
            "device": device,
            "template_name": args.template_name,
            "per_pair_csv": str(per_pair_path),
            "summary_csv": str(summary_path),
        },
    )

    print(
        json.dumps(
            {
                "metadata": str(metadata_path),
                "summary_csv": str(summary_path),
                "rows": summary_df.to_dict(orient="records"),
                "num_pairs": len(pairs),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_batch_trace_residual_direction_heads(args: argparse.Namespace) -> int:
    require_transformer_lens()

    manifest = pd.read_csv(args.manifest)
    pairs = select_short_pairs(
        manifest,
        num_pairs=args.num_pairs,
        malicious_requires_indicator=not args.allow_zero_indicator_malicious,
    )
    if not pairs:
        raise RuntimeError("No eligible benign/malicious pairs found for residual-direction head tracing.")

    bundle = torch.load(args.basis_path, map_location="cpu")
    basis = bundle["basis"].detach().cpu()
    labels = list(bundle.get("basis_labels", [f"dir_{index}" for index in range(basis.shape[1])]))
    layer = int(bundle["layer"])
    resid_kind = str(bundle["resid_kind"])
    if args.basis_label not in labels:
        raise ValueError(f"Basis label {args.basis_label!r} not found in {labels!r}.")
    basis_index = labels.index(args.basis_label)
    direction = basis[:, basis_index].detach().cpu()
    target_layers = parse_int_list(args.layers)

    hf_model, tokenizer, device = load_hf_model_and_tokenizer(
        args.model_name,
        device=args.device,
        torch_dtype=args.torch_dtype,
    )
    model = build_hooked_transformer(
        hf_model,
        tokenizer,
        device=device,
        torch_dtype=args.torch_dtype,
        template_name=args.template_name,
        first_n_layers=args.first_n_layers,
        use_attn_result=False,
    )
    model.eval()

    needed_hooks = {f"blocks.{trace_layer}.attn.hook_z" for trace_layer in target_layers}
    direction = direction.to(device=device, dtype=model.cfg.dtype)
    layer_write_directions = {
        trace_layer: torch.einsum("hdm,m->hd", model.blocks[trace_layer].attn.W_O, direction)
        for trace_layer in target_layers
    }

    rows: List[Dict[str, object]] = []
    for fallback_idx, (benign_row, malicious_row) in enumerate(pairs, start=1):
        pair_idx = resolve_pair_idx(benign_row, malicious_row, fallback_idx=fallback_idx)
        benign_tokens = model.to_tokens(make_prompt(benign_row["content"]))
        malicious_tokens = model.to_tokens(make_prompt(malicious_row["content"]))

        with torch.inference_mode():
            _, benign_cache = model.run_with_cache(
                benign_tokens,
                return_type="logits",
                names_filter=lambda name: name in needed_hooks,
            )
            _, malicious_cache = model.run_with_cache(
                malicious_tokens,
                return_type="logits",
                names_filter=lambda name: name in needed_hooks,
            )

        for trace_layer in target_layers:
            hook_name = f"blocks.{trace_layer}.attn.hook_z"
            write_direction = layer_write_directions[trace_layer]
            benign_z = benign_cache[hook_name][0, -1, :, :].detach().clone()
            malicious_z = malicious_cache[hook_name][0, -1, :, :].detach().clone()
            benign_projection = (benign_z * write_direction).sum(dim=-1).detach().float().cpu()
            malicious_projection = (malicious_z * write_direction).sum(dim=-1).detach().float().cpu()
            delta_projection = malicious_projection - benign_projection

            for head in range(model.cfg.n_heads):
                rows.append(
                    {
                        "trace_target_layer": layer,
                        "trace_target_resid_kind": resid_kind,
                        "basis_label": args.basis_label,
                        "layer": trace_layer,
                        "head": head,
                        "pair_idx": pair_idx,
                        "pair_indicator": benign_row.get("pair_indicator", malicious_row.get("pair_indicator")),
                        "benign_filename": benign_row["filename"],
                        "malicious_filename": malicious_row["filename"],
                        "benign_projection": float(benign_projection[head].item()),
                        "malicious_projection": float(malicious_projection[head].item()),
                        "delta_projection": float(delta_projection[head].item()),
                    }
                )

        del benign_cache
        del malicious_cache
        del benign_tokens
        del malicious_tokens
        maybe_clear_device_cache(device)

    per_pair_df = pd.DataFrame(rows)
    summary_df = summarize_directional_head_writes(per_pair_df)
    if args.topk is not None and args.topk > 0:
        summary_df = summary_df.head(args.topk).copy()

    output_prefix = Path(args.output_prefix or (DEFAULT_ARTIFACT_DIR / "directional_head_trace"))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    per_pair_path = output_prefix.with_name(output_prefix.name + "_per_pair.csv")
    summary_path = output_prefix.with_name(output_prefix.name + "_summary.csv")
    metadata_path = output_prefix.with_name(output_prefix.name + "_metadata.json")
    per_pair_df.to_csv(per_pair_path, index=False)
    summary_df.to_csv(summary_path, index=False)
    write_json(
        metadata_path,
        {
            "basis_path": str(args.basis_path),
            "basis_label": args.basis_label,
            "trace_target_layer": layer,
            "trace_target_resid_kind": resid_kind,
            "layers": target_layers,
            "num_pairs": len(pairs),
            "device": device,
            "template_name": args.template_name,
            "per_pair_csv": str(per_pair_path),
            "summary_csv": str(summary_path),
        },
    )

    print(
        json.dumps(
            {
                "metadata": str(metadata_path),
                "summary_csv": str(summary_path),
                "rows": summary_df.to_dict(orient="records"),
                "num_pairs": len(pairs),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_batch_head_group_ablation(args: argparse.Namespace) -> int:
    require_transformer_lens()

    manifest = pd.read_csv(args.manifest)
    pairs = select_short_pairs(
        manifest,
        num_pairs=args.num_pairs,
        malicious_requires_indicator=not args.allow_zero_indicator_malicious,
    )
    if not pairs:
        raise RuntimeError("No eligible benign/malicious pairs found for grouped head ablation.")

    head_specs = parse_head_list(args.heads)
    hf_model, tokenizer, device = load_hf_model_and_tokenizer(
        args.model_name,
        device=args.device,
        torch_dtype=args.torch_dtype,
    )
    model = build_hooked_transformer(
        hf_model,
        tokenizer,
        device=device,
        torch_dtype=args.torch_dtype,
        template_name=args.template_name,
        first_n_layers=args.first_n_layers,
        use_attn_result=False,
    )
    model.eval()

    allow_token_id = tokenizer.encode(" ALLOW", add_special_tokens=False)[0]
    block_token_id = tokenizer.encode(" BLOCK", add_special_tokens=False)[0]

    rows: List[Dict[str, object]] = []
    for fallback_idx, (benign_row, malicious_row) in enumerate(pairs, start=1):
        pair_idx = resolve_pair_idx(benign_row, malicious_row, fallback_idx=fallback_idx)
        malicious_tokens = model.to_tokens(make_prompt(malicious_row["content"]))

        with torch.inference_mode():
            malicious_logits = model(malicious_tokens, return_type="logits")
        base_malicious_diff = logit_diff_from_logits(malicious_logits, allow_token_id, block_token_id)

        result = run_multi_head_ablation(
            model,
            tokens=malicious_tokens,
            head_specs=head_specs,
            base_logit_diff=base_malicious_diff,
            allow_token_id=allow_token_id,
            block_token_id=block_token_id,
        )
        result["pair_idx"] = pair_idx
        result["pair_indicator"] = benign_row.get("pair_indicator", malicious_row.get("pair_indicator"))
        result["benign_filename"] = benign_row["filename"]
        result["malicious_filename"] = malicious_row["filename"]
        result["flip_to_benign"] = result["ablated_logit_diff"] <= 0
        rows.append(result)

        del malicious_logits
        del malicious_tokens
        maybe_clear_device_cache(device)

    per_pair_df = pd.DataFrame(rows)
    summary_df = summarize_path_patch_effects(
        per_pair_df.rename(columns={"ablation_label": "patch_label"})
    ).rename(columns={"patch_label": "ablation_label"})

    output_prefix = Path(args.output_prefix or (DEFAULT_ARTIFACT_DIR / "batch_head_group_ablation"))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    per_pair_path = output_prefix.with_name(output_prefix.name + "_per_pair.csv")
    summary_path = output_prefix.with_name(output_prefix.name + "_summary.csv")
    metadata_path = output_prefix.with_name(output_prefix.name + "_metadata.json")
    per_pair_df.to_csv(per_pair_path, index=False)
    summary_df.to_csv(summary_path, index=False)
    write_json(
        metadata_path,
        {
            "heads": [{"layer": layer, "head": head} for layer, head in head_specs],
            "num_pairs": len(pairs),
            "first_n_layers": args.first_n_layers,
            "device": device,
            "template_name": args.template_name,
            "per_pair_csv": str(per_pair_path),
            "summary_csv": str(summary_path),
        },
    )

    print(
        json.dumps(
            {
                "metadata": str(metadata_path),
                "summary_csv": str(summary_path),
                "rows": summary_df.to_dict(orient="records"),
                "num_pairs": len(pairs),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_batch_residual_direction_intervention(args: argparse.Namespace) -> int:
    require_transformer_lens()

    manifest = pd.read_csv(args.manifest)
    pairs = select_short_pairs(
        manifest,
        num_pairs=args.num_pairs,
        malicious_requires_indicator=not args.allow_zero_indicator_malicious,
    )
    if not pairs:
        raise RuntimeError("No eligible benign/malicious pairs found for residual-direction intervention testing.")

    bundle = torch.load(args.basis_path, map_location="cpu")
    basis = bundle["basis"].detach().cpu()
    labels = list(bundle.get("basis_labels", [f"dir_{index}" for index in range(basis.shape[1])]))
    target_layer = int(bundle["layer"])
    target_resid_kind = str(bundle["resid_kind"])
    if args.basis_label not in labels:
        raise ValueError(f"Basis label {args.basis_label!r} not found in {labels!r}.")
    basis_index = labels.index(args.basis_label)
    direction = basis[:, basis_index].detach().cpu()
    head_specs = parse_head_list(args.heads)
    mode = args.mode.strip().lower()
    if mode not in {"patch", "ablate"}:
        raise ValueError(f"Unsupported mode: {args.mode!r}")

    hf_model, tokenizer, device = load_hf_model_and_tokenizer(
        args.model_name,
        device=args.device,
        torch_dtype=args.torch_dtype,
    )
    model = build_hooked_transformer(
        hf_model,
        tokenizer,
        device=device,
        torch_dtype=args.torch_dtype,
        template_name=args.template_name,
        first_n_layers=args.first_n_layers,
        use_attn_result=False,
    )
    model.eval()

    allow_token_id = tokenizer.encode(" ALLOW", add_special_tokens=False)[0]
    block_token_id = tokenizer.encode(" BLOCK", add_special_tokens=False)[0]
    direction = direction.to(device=device, dtype=model.cfg.dtype)
    target_hook_name = build_residual_hook_name(target_layer, target_resid_kind)
    intervention_label = f"{mode}_" + "+".join(f"h{layer}.{head}" for layer, head in head_specs)
    head_hook_names = {f"blocks.{layer}.attn.hook_z" for layer, head in head_specs}
    cache_hook_names = set(head_hook_names)
    cache_hook_names.add(target_hook_name)

    rows: List[Dict[str, object]] = []
    for fallback_idx, (benign_row, malicious_row) in enumerate(pairs, start=1):
        pair_idx = resolve_pair_idx(benign_row, malicious_row, fallback_idx=fallback_idx)
        benign_tokens = model.to_tokens(make_prompt(benign_row["content"]))
        malicious_tokens = model.to_tokens(make_prompt(malicious_row["content"]))

        with torch.inference_mode():
            _, benign_cache = model.run_with_cache(
                benign_tokens,
                return_type="logits",
                names_filter=lambda name: name in cache_hook_names,
            )
            malicious_logits, malicious_cache = model.run_with_cache(
                malicious_tokens,
                return_type="logits",
                names_filter=lambda name: name == target_hook_name,
            )
        base_logit_diff = logit_diff_from_logits(malicious_logits, allow_token_id, block_token_id)
        base_projection = float(
            torch.dot(
                malicious_cache[target_hook_name][0, -1, :].detach().clone().to(dtype=model.cfg.dtype),
                direction,
            ).item()
        )

        if mode == "patch":
            hooks = []
            for layer, head in head_specs:
                hook_name = f"blocks.{layer}.attn.hook_z"
                clean_value = benign_cache[hook_name]

                def patch_head_fn(result, hook, *, patch_head=head, patch_value=clean_value):
                    patched = result.clone()
                    clean_seq = patch_value.shape[1]
                    corrupt_seq = patched.shape[1]
                    shared_seq = min(clean_seq, corrupt_seq)
                    patched[:, -shared_seq:, patch_head, :] = patch_value[:, -shared_seq:, patch_head, :]
                    return patched

                hooks.append((hook_name, patch_head_fn))
        else:
            hooks_by_name: Dict[str, List[int]] = {}
            for layer, head in head_specs:
                hook_name = f"blocks.{layer}.attn.hook_z"
                hooks_by_name.setdefault(hook_name, []).append(head)
            hooks = []
            for hook_name, heads in hooks_by_name.items():
                unique_heads = tuple(sorted(set(heads)))

                def ablate_fn(result, hook, *, ablate_heads=unique_heads):
                    patched = result.clone()
                    for ablate_head in ablate_heads:
                        patched[:, :, ablate_head, :] = 0.0
                    return patched

                hooks.append((hook_name, ablate_fn))

        with torch.inference_mode():
            with model.hooks(fwd_hooks=hooks):
                intervened_logits, intervened_cache = model.run_with_cache(
                    malicious_tokens,
                    return_type="logits",
                    names_filter=lambda name: name == target_hook_name,
                )
        intervened_logit_diff = logit_diff_from_logits(intervened_logits, allow_token_id, block_token_id)
        intervened_projection = float(
            torch.dot(
                intervened_cache[target_hook_name][0, -1, :].detach().clone().to(dtype=model.cfg.dtype),
                direction,
            ).item()
        )

        rows.append(
            {
                "intervention_label": intervention_label,
                "mode": mode,
                "basis_label": args.basis_label,
                "target_layer": target_layer,
                "target_resid_kind": target_resid_kind,
                "pair_idx": pair_idx,
                "pair_indicator": benign_row.get("pair_indicator", malicious_row.get("pair_indicator")),
                "benign_filename": benign_row["filename"],
                "malicious_filename": malicious_row["filename"],
                "base_logit_diff": base_logit_diff,
                "intervened_logit_diff": intervened_logit_diff,
                "logit_delta": intervened_logit_diff - base_logit_diff,
                "flip_to_benign": intervened_logit_diff <= 0,
                "base_projection": base_projection,
                "intervened_projection": intervened_projection,
                "projection_delta": intervened_projection - base_projection,
            }
        )

        del benign_cache
        del malicious_cache
        del malicious_logits
        del intervened_cache
        del intervened_logits
        del benign_tokens
        del malicious_tokens
        maybe_clear_device_cache(device)

    per_pair_df = pd.DataFrame(rows)
    summary_df = summarize_residual_direction_interventions(per_pair_df)

    output_prefix = Path(args.output_prefix or (DEFAULT_ARTIFACT_DIR / "residual_direction_intervention"))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    per_pair_path = output_prefix.with_name(output_prefix.name + "_per_pair.csv")
    summary_path = output_prefix.with_name(output_prefix.name + "_summary.csv")
    metadata_path = output_prefix.with_name(output_prefix.name + "_metadata.json")
    per_pair_df.to_csv(per_pair_path, index=False)
    summary_df.to_csv(summary_path, index=False)
    write_json(
        metadata_path,
        {
            "basis_path": str(args.basis_path),
            "basis_label": args.basis_label,
            "heads": [{"layer": layer, "head": head} for layer, head in head_specs],
            "mode": mode,
            "target_layer": target_layer,
            "target_resid_kind": target_resid_kind,
            "num_pairs": len(pairs),
            "device": device,
            "template_name": args.template_name,
            "per_pair_csv": str(per_pair_path),
            "summary_csv": str(summary_path),
        },
    )

    print(
        json.dumps(
            {
                "metadata": str(metadata_path),
                "summary_csv": str(summary_path),
                "rows": summary_df.to_dict(orient="records"),
                "num_pairs": len(pairs),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def cmd_batch_trace_direction_under_intervention(args: argparse.Namespace) -> int:
    require_transformer_lens()

    manifest = pd.read_csv(args.manifest)
    pairs = select_short_pairs(
        manifest,
        num_pairs=args.num_pairs,
        malicious_requires_indicator=not args.allow_zero_indicator_malicious,
    )
    if not pairs:
        raise RuntimeError("No eligible benign/malicious pairs found for intervention-conditioned direction tracing.")

    bundle = torch.load(args.basis_path, map_location="cpu")
    basis = bundle["basis"].detach().cpu()
    labels = list(bundle.get("basis_labels", [f"dir_{index}" for index in range(basis.shape[1])]))
    trace_target_layer = int(bundle["layer"])
    trace_target_resid_kind = str(bundle["resid_kind"])
    if args.basis_label not in labels:
        raise ValueError(f"Basis label {args.basis_label!r} not found in {labels!r}.")
    basis_index = labels.index(args.basis_label)
    direction = basis[:, basis_index].detach().cpu()
    target_layers = parse_int_list(args.layers)
    source_heads = parse_head_list(args.source_heads)
    mode = args.mode.strip().lower()
    if mode not in {"patch", "ablate"}:
        raise ValueError(f"Unsupported mode: {args.mode!r}")

    hf_model, tokenizer, device = load_hf_model_and_tokenizer(
        args.model_name,
        device=args.device,
        torch_dtype=args.torch_dtype,
    )
    model = build_hooked_transformer(
        hf_model,
        tokenizer,
        device=device,
        torch_dtype=args.torch_dtype,
        template_name=args.template_name,
        first_n_layers=args.first_n_layers,
        use_attn_result=False,
    )
    model.eval()

    source_hook_names = {f"blocks.{layer}.attn.hook_z" for layer, head in source_heads}
    target_hook_names = {f"blocks.{trace_layer}.attn.hook_z" for trace_layer in target_layers}
    benign_cache_names = source_hook_names
    malicious_cache_names = target_hook_names

    direction = direction.to(device=device, dtype=model.cfg.dtype)
    layer_write_directions = {
        trace_layer: torch.einsum("hdm,m->hd", model.blocks[trace_layer].attn.W_O, direction)
        for trace_layer in target_layers
    }
    intervention_label = f"{mode}_" + "+".join(f"h{layer}.{head}" for layer, head in source_heads)

    rows: List[Dict[str, object]] = []
    for fallback_idx, (benign_row, malicious_row) in enumerate(pairs, start=1):
        pair_idx = resolve_pair_idx(benign_row, malicious_row, fallback_idx=fallback_idx)
        benign_tokens = model.to_tokens(make_prompt(benign_row["content"]))
        malicious_tokens = model.to_tokens(make_prompt(malicious_row["content"]))

        with torch.inference_mode():
            _, benign_cache = model.run_with_cache(
                benign_tokens,
                return_type="logits",
                names_filter=lambda name: name in benign_cache_names,
            )
            _, malicious_cache = model.run_with_cache(
                malicious_tokens,
                return_type="logits",
                names_filter=lambda name: name in malicious_cache_names,
            )

        if mode == "patch":
            hooks = []
            for layer, head in source_heads:
                hook_name = f"blocks.{layer}.attn.hook_z"
                clean_value = benign_cache[hook_name]

                def patch_head_fn(result, hook, *, patch_head=head, patch_value=clean_value):
                    patched = result.clone()
                    clean_seq = patch_value.shape[1]
                    corrupt_seq = patched.shape[1]
                    shared_seq = min(clean_seq, corrupt_seq)
                    patched[:, -shared_seq:, patch_head, :] = patch_value[:, -shared_seq:, patch_head, :]
                    return patched

                hooks.append((hook_name, patch_head_fn))
        else:
            hooks_by_name: Dict[str, List[int]] = {}
            for layer, head in source_heads:
                hook_name = f"blocks.{layer}.attn.hook_z"
                hooks_by_name.setdefault(hook_name, []).append(head)
            hooks = []
            for hook_name, heads in hooks_by_name.items():
                unique_heads = tuple(sorted(set(heads)))

                def ablate_fn(result, hook, *, ablate_heads=unique_heads):
                    patched = result.clone()
                    for ablate_head in ablate_heads:
                        patched[:, :, ablate_head, :] = 0.0
                    return patched

                hooks.append((hook_name, ablate_fn))

        with torch.inference_mode():
            with model.hooks(fwd_hooks=hooks):
                _, intervened_cache = model.run_with_cache(
                    malicious_tokens,
                    return_type="logits",
                    names_filter=lambda name: name in malicious_cache_names,
                )

        for trace_layer in target_layers:
            hook_name = f"blocks.{trace_layer}.attn.hook_z"
            write_direction = layer_write_directions[trace_layer]
            base_z = malicious_cache[hook_name][0, -1, :, :].detach().clone()
            intervened_z = intervened_cache[hook_name][0, -1, :, :].detach().clone()
            base_projection = (base_z * write_direction).sum(dim=-1).detach().float().cpu()
            intervened_projection = (intervened_z * write_direction).sum(dim=-1).detach().float().cpu()
            projection_delta = intervened_projection - base_projection

            for head in range(model.cfg.n_heads):
                rows.append(
                    {
                        "intervention_label": intervention_label,
                        "mode": mode,
                        "trace_target_layer": trace_target_layer,
                        "trace_target_resid_kind": trace_target_resid_kind,
                        "basis_label": args.basis_label,
                        "layer": trace_layer,
                        "head": head,
                        "pair_idx": pair_idx,
                        "pair_indicator": benign_row.get("pair_indicator", malicious_row.get("pair_indicator")),
                        "benign_filename": benign_row["filename"],
                        "malicious_filename": malicious_row["filename"],
                        "base_projection": float(base_projection[head].item()),
                        "intervened_projection": float(intervened_projection[head].item()),
                        "projection_delta": float(projection_delta[head].item()),
                    }
                )

        del benign_cache
        del malicious_cache
        del intervened_cache
        del benign_tokens
        del malicious_tokens
        maybe_clear_device_cache(device)

    per_pair_df = pd.DataFrame(rows)
    summary_df = summarize_directional_head_intervention_effects(per_pair_df)
    if args.topk is not None and args.topk > 0:
        summary_df = summary_df.head(args.topk).copy()

    output_prefix = Path(args.output_prefix or (DEFAULT_ARTIFACT_DIR / "direction_trace_under_intervention"))
    output_prefix.parent.mkdir(parents=True, exist_ok=True)
    per_pair_path = output_prefix.with_name(output_prefix.name + "_per_pair.csv")
    summary_path = output_prefix.with_name(output_prefix.name + "_summary.csv")
    metadata_path = output_prefix.with_name(output_prefix.name + "_metadata.json")
    per_pair_df.to_csv(per_pair_path, index=False)
    summary_df.to_csv(summary_path, index=False)
    write_json(
        metadata_path,
        {
            "basis_path": str(args.basis_path),
            "basis_label": args.basis_label,
            "source_heads": [{"layer": layer, "head": head} for layer, head in source_heads],
            "mode": mode,
            "trace_target_layer": trace_target_layer,
            "trace_target_resid_kind": trace_target_resid_kind,
            "layers": target_layers,
            "num_pairs": len(pairs),
            "device": device,
            "template_name": args.template_name,
            "per_pair_csv": str(per_pair_path),
            "summary_csv": str(summary_path),
        },
    )

    print(
        json.dumps(
            {
                "metadata": str(metadata_path),
                "summary_csv": str(summary_path),
                "rows": summary_df.to_dict(orient="records"),
                "num_pairs": len(pairs),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    dataset_summary_parser = subparsers.add_parser(
        "dataset-summary",
        help="Summarize the PowerShell dataset and write an artifact JSON file.",
    )
    dataset_summary_parser.add_argument("--csv", type=Path, default=DEFAULT_CSV_PATH)
    dataset_summary_parser.add_argument("--max-chars", type=int, default=12000)
    dataset_summary_parser.add_argument("--min-chars", type=int, default=1)
    dataset_summary_parser.add_argument("--preview-rows", type=int, default=3)
    dataset_summary_parser.add_argument("--output", type=Path, default=DEFAULT_ARTIFACT_DIR / "dataset_summary.json")
    dataset_summary_parser.set_defaults(func=cmd_dataset_summary)

    manifest_parser = subparsers.add_parser(
        "build-manifest",
        help="Build a balanced, diverse manifest for tractable MI experiments.",
    )
    manifest_parser.add_argument("--csv", type=Path, default=DEFAULT_CSV_PATH)
    manifest_parser.add_argument("--max-chars", type=int, default=12000)
    manifest_parser.add_argument("--min-chars", type=int, default=1)
    manifest_parser.add_argument("--per-label", type=int, default=64)
    manifest_parser.add_argument("--seed", type=int, default=SEED)
    manifest_parser.add_argument("--output", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv")
    manifest_parser.set_defaults(func=cmd_build_manifest)

    circuit_val_parser = subparsers.add_parser(
        "build-circuit-val-set",
        help="Build a balanced circuit validation set from indicator-bearing rows present in both classes.",
    )
    circuit_val_parser.add_argument("--csv", type=Path, default=DEFAULT_CSV_PATH)
    circuit_val_parser.add_argument("--max-chars", type=int, default=12000)
    circuit_val_parser.add_argument("--min-chars", type=int, default=1)
    circuit_val_parser.add_argument("--target-total", type=int, default=300)
    circuit_val_parser.add_argument("--output", type=Path, default=ROOT / "circuit_val_set.csv")
    circuit_val_parser.add_argument(
        "--metadata-output",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "circuit_val_set_metadata.json",
    )
    circuit_val_parser.set_defaults(func=cmd_build_circuit_val_set)

    indicator_pair_parser = subparsers.add_parser(
        "build-indicator-pair-manifest",
        help="Build an explicit benign/malicious paired manifest grouped by indicator family.",
    )
    indicator_pair_parser.add_argument("--input-csv", type=Path, required=True)
    indicator_pair_parser.add_argument("--indicator-column", default="primary_indicator")
    indicator_pair_parser.add_argument("--pairing-mode", choices=["zip", "all-combinations"], default="zip")
    indicator_pair_parser.add_argument("--max-pairs", type=int, default=None)
    indicator_pair_parser.add_argument("--per-indicator-cap", type=int, default=None)
    indicator_pair_parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "indicator_pair_manifest.csv",
    )
    indicator_pair_parser.set_defaults(func=cmd_build_indicator_pair_manifest)

    augment_pair_parser = subparsers.add_parser(
        "augment-pair-manifest",
        help="Create conservative paired formatting variants from an explicit benign/malicious pair manifest.",
    )
    augment_pair_parser.add_argument("--manifest", type=Path, required=True)
    augment_pair_parser.add_argument(
        "--techniques",
        default="collapse_blank_lines,normalize_inline_whitespace,single_line_layout",
        help="Comma-separated augmentation techniques drawn from generate_obfuscations().",
    )
    augment_pair_parser.add_argument("--include-original", action="store_true")
    augment_pair_parser.add_argument("--max-augmented-variants-per-pair", type=int, default=None)
    augment_pair_parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "augmented_pair_manifest.csv",
    )
    augment_pair_parser.add_argument(
        "--metadata-output",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "augmented_pair_manifest_metadata.json",
    )
    augment_pair_parser.set_defaults(func=cmd_augment_pair_manifest)

    family_summary_parser = subparsers.add_parser(
        "summarize-family-overlap",
        help="Summarize overlap-validation results by indicator family.",
    )
    family_summary_parser.add_argument("--manifest", type=Path, required=True)
    family_summary_parser.add_argument("--baseline-eval", type=Path, default=None)
    family_summary_parser.add_argument("--attention-per-pair", type=Path, default=None)
    family_summary_parser.add_argument("--patch-per-pair", type=Path, default=None)
    family_summary_parser.add_argument("--ablation-per-pair", type=Path, default=None)
    family_summary_parser.add_argument("--heads", default=None)
    family_summary_parser.add_argument(
        "--output-prefix",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "family_overlap",
    )
    family_summary_parser.set_defaults(func=cmd_summarize_family_overlap)

    export_pairs_parser = subparsers.add_parser(
        "export-short-pairs",
        help="Export the short benign/malicious pairs used for reduced-layer probes.",
    )
    export_pairs_parser.add_argument("--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv")
    export_pairs_parser.add_argument("--num-pairs", type=int, default=5)
    export_pairs_parser.add_argument("--allow-zero-indicator-malicious", action="store_true")
    export_pairs_parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "short_pairs_manifest.csv",
    )
    export_pairs_parser.set_defaults(func=cmd_export_short_pairs)

    filter_pairs_parser = subparsers.add_parser(
        "filter-valid-pairs",
        help="Keep only pair_ids whose benign and malicious rows are both correct in baseline eval.",
    )
    filter_pairs_parser.add_argument("--manifest", type=Path, required=True)
    filter_pairs_parser.add_argument("--baseline-eval", type=Path, required=True)
    filter_pairs_parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "valid_short_pairs_manifest.csv",
    )
    filter_pairs_parser.set_defaults(func=cmd_filter_valid_pairs)

    baseline_parser = subparsers.add_parser(
        "baseline-eval",
        help="Run ALLOW/BLOCK baseline evaluation on a manifest using the HF model.",
    )
    baseline_parser.add_argument("--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv")
    baseline_parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    baseline_parser.add_argument("--device", default=None)
    baseline_parser.add_argument("--torch-dtype", choices=["float16", "bfloat16", "float32"], default="float16")
    baseline_parser.add_argument("--batch-size", type=int, default=1)
    baseline_parser.add_argument("--limit", type=int, default=None)
    baseline_parser.add_argument("--output", type=Path, default=DEFAULT_ARTIFACT_DIR / "baseline_eval.csv")
    baseline_parser.set_defaults(func=cmd_baseline_eval)

    discover_parser = subparsers.add_parser(
        "discover-heads",
        help="Run a first attention-localization pass on one benign/malicious manifest pair.",
    )
    discover_parser.add_argument("--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv")
    discover_parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    discover_parser.add_argument("--template-name", default="meta-llama/Llama-3.1-8B-Instruct")
    discover_parser.add_argument("--device", default=None)
    discover_parser.add_argument("--torch-dtype", choices=["float16", "bfloat16", "float32"], default="float16")
    discover_parser.add_argument("--benign-rank", type=int, default=0)
    discover_parser.add_argument("--malicious-rank", type=int, default=0)
    discover_parser.add_argument("--first-n-layers", type=int, default=None)
    discover_parser.add_argument("--layer-start", type=int, default=None)
    discover_parser.add_argument("--layer-end", type=int, default=None)
    discover_parser.add_argument("--topk", type=int, default=10)
    discover_parser.add_argument("--output", type=Path, default=DEFAULT_ARTIFACT_DIR / "attention_top_heads.csv")
    discover_parser.set_defaults(func=cmd_discover_heads)

    causal_pair_parser = subparsers.add_parser(
        "causal-pair",
        help="Run reduced-layer patching and ablation on one benign/malicious manifest pair.",
    )
    causal_pair_parser.add_argument("--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv")
    causal_pair_parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    causal_pair_parser.add_argument("--template-name", default="meta-llama/Llama-3.1-8B-Instruct")
    causal_pair_parser.add_argument("--device", default=None)
    causal_pair_parser.add_argument("--torch-dtype", choices=["float16", "bfloat16", "float32"], default="float16")
    causal_pair_parser.add_argument("--benign-rank", type=int, default=None)
    causal_pair_parser.add_argument("--malicious-rank", type=int, default=None)
    causal_pair_parser.add_argument("--short-pair-index", type=int, default=None)
    causal_pair_parser.add_argument("--pair-idx", type=int, default=None)
    causal_pair_parser.add_argument("--first-n-layers", type=int, default=4)
    causal_pair_parser.add_argument("--heads", default="0.7,0.9,0.4")
    causal_pair_parser.add_argument("--allow-zero-indicator-malicious", action="store_true")
    causal_pair_parser.add_argument(
        "--output-prefix",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "causal_pair",
    )
    causal_pair_parser.set_defaults(func=cmd_causal_pair)

    aggregate_causal_parser = subparsers.add_parser(
        "aggregate-causal",
        help="Aggregate standalone causal-pair CSV outputs into reproducible summaries.",
    )
    aggregate_causal_parser.add_argument("--input-prefix", type=Path, action="append", default=[])
    aggregate_causal_parser.add_argument("--patch-csv", type=Path, action="append", default=[])
    aggregate_causal_parser.add_argument("--ablation-csv", type=Path, action="append", default=[])
    aggregate_causal_parser.add_argument(
        "--exclude-pair",
        action="append",
        default=[],
        help="Record an excluded pair as benign_filename|malicious_filename|reason.",
    )
    aggregate_causal_parser.add_argument(
        "--output-prefix",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "aggregated_causal",
    )
    aggregate_causal_parser.set_defaults(func=cmd_aggregate_causal)

    batch_discover_parser = subparsers.add_parser(
        "batch-discover-heads",
        help="Aggregate early-layer head rankings across multiple short benign/malicious pairs.",
    )
    batch_discover_parser.add_argument("--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv")
    batch_discover_parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    batch_discover_parser.add_argument("--template-name", default="meta-llama/Llama-3.1-8B-Instruct")
    batch_discover_parser.add_argument("--device", default=None)
    batch_discover_parser.add_argument("--torch-dtype", choices=["float16", "bfloat16", "float32"], default="float16")
    batch_discover_parser.add_argument("--num-pairs", type=int, default=5)
    batch_discover_parser.add_argument("--first-n-layers", type=int, default=4)
    batch_discover_parser.add_argument("--layer-start", type=int, default=None)
    batch_discover_parser.add_argument("--layer-end", type=int, default=None)
    batch_discover_parser.add_argument("--topk", type=int, default=5)
    batch_discover_parser.add_argument("--allow-zero-indicator-malicious", action="store_true")
    batch_discover_parser.add_argument(
        "--output-prefix",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "batch_attention_l4",
    )
    batch_discover_parser.set_defaults(func=cmd_batch_discover_heads)

    batch_causal_parser = subparsers.add_parser(
        "batch-causal",
        help="Run reduced-layer activation patching and ablation across multiple short pairs.",
    )
    batch_causal_parser.add_argument("--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv")
    batch_causal_parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    batch_causal_parser.add_argument("--template-name", default="meta-llama/Llama-3.1-8B-Instruct")
    batch_causal_parser.add_argument("--device", default=None)
    batch_causal_parser.add_argument("--torch-dtype", choices=["float16", "bfloat16", "float32"], default="float16")
    batch_causal_parser.add_argument("--num-pairs", type=int, default=3)
    batch_causal_parser.add_argument("--first-n-layers", type=int, default=4)
    batch_causal_parser.add_argument("--heads", default="0.7,0.9,0.4")
    batch_causal_parser.add_argument("--allow-zero-indicator-malicious", action="store_true")
    batch_causal_parser.add_argument("--reload-model-per-pair", action="store_true")
    batch_causal_parser.add_argument(
        "--output-prefix",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "batch_causal_l4",
    )
    batch_causal_parser.set_defaults(func=cmd_batch_causal)

    batch_layer_ablation_parser = subparsers.add_parser(
        "batch-layer-ablation",
        help="Ablate full-layer attention/MLP components across multiple pairs.",
    )
    batch_layer_ablation_parser.add_argument("--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv")
    batch_layer_ablation_parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    batch_layer_ablation_parser.add_argument("--template-name", default="meta-llama/Llama-3.1-8B-Instruct")
    batch_layer_ablation_parser.add_argument("--device", default=None)
    batch_layer_ablation_parser.add_argument("--torch-dtype", choices=["float16", "bfloat16", "float32"], default="float16")
    batch_layer_ablation_parser.add_argument("--num-pairs", type=int, default=3)
    batch_layer_ablation_parser.add_argument("--first-n-layers", type=int, default=None)
    batch_layer_ablation_parser.add_argument("--components", default="attn,mlp")
    batch_layer_ablation_parser.add_argument("--allow-zero-indicator-malicious", action="store_true")
    batch_layer_ablation_parser.add_argument(
        "--output-prefix",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "batch_layer_ablation",
    )
    batch_layer_ablation_parser.set_defaults(func=cmd_batch_layer_ablation)

    batch_layer_patching_parser = subparsers.add_parser(
        "batch-layer-patching",
        help="Patch full-layer attention/MLP components from benign into malicious prompts.",
    )
    batch_layer_patching_parser.add_argument("--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv")
    batch_layer_patching_parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    batch_layer_patching_parser.add_argument("--template-name", default="meta-llama/Llama-3.1-8B-Instruct")
    batch_layer_patching_parser.add_argument("--device", default=None)
    batch_layer_patching_parser.add_argument("--torch-dtype", choices=["float16", "bfloat16", "float32"], default="float16")
    batch_layer_patching_parser.add_argument("--num-pairs", type=int, default=3)
    batch_layer_patching_parser.add_argument("--first-n-layers", type=int, default=None)
    batch_layer_patching_parser.add_argument("--layers", required=True)
    batch_layer_patching_parser.add_argument("--components", default="attn,mlp")
    batch_layer_patching_parser.add_argument("--allow-zero-indicator-malicious", action="store_true")
    batch_layer_patching_parser.add_argument(
        "--output-prefix",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "batch_layer_patching",
    )
    batch_layer_patching_parser.set_defaults(func=cmd_batch_layer_patching)

    batch_path_patching_parser = subparsers.add_parser(
        "batch-path-patching",
        help="Patch early heads, late components, and/or residual states together across pairs.",
    )
    batch_path_patching_parser.add_argument("--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv")
    batch_path_patching_parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    batch_path_patching_parser.add_argument("--template-name", default="meta-llama/Llama-3.1-8B-Instruct")
    batch_path_patching_parser.add_argument("--device", default=None)
    batch_path_patching_parser.add_argument("--torch-dtype", choices=["float16", "bfloat16", "float32"], default="float16")
    batch_path_patching_parser.add_argument("--num-pairs", type=int, default=3)
    batch_path_patching_parser.add_argument("--first-n-layers", type=int, default=None)
    batch_path_patching_parser.add_argument("--heads", default=None)
    batch_path_patching_parser.add_argument("--components", default=None)
    batch_path_patching_parser.add_argument("--residuals", default=None)
    batch_path_patching_parser.add_argument("--resid-kind", default="pre")
    batch_path_patching_parser.add_argument("--combined", action="store_true")
    batch_path_patching_parser.add_argument("--allow-zero-indicator-malicious", action="store_true")
    batch_path_patching_parser.add_argument(
        "--output-prefix",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "batch_path_patching",
    )
    batch_path_patching_parser.set_defaults(func=cmd_batch_path_patching)

    batch_neuron_discover_parser = subparsers.add_parser(
        "batch-neuron-discover",
        help="Discover candidate MLP neurons in selected layers via logit-aligned contribution deltas.",
    )
    batch_neuron_discover_parser.add_argument("--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv")
    batch_neuron_discover_parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    batch_neuron_discover_parser.add_argument("--template-name", default="meta-llama/Llama-3.1-8B-Instruct")
    batch_neuron_discover_parser.add_argument("--device", default=None)
    batch_neuron_discover_parser.add_argument("--torch-dtype", choices=["float16", "bfloat16", "float32"], default="float16")
    batch_neuron_discover_parser.add_argument("--num-pairs", type=int, default=3)
    batch_neuron_discover_parser.add_argument("--first-n-layers", type=int, default=None)
    batch_neuron_discover_parser.add_argument("--layers", required=True)
    batch_neuron_discover_parser.add_argument("--topk-per-layer", type=int, default=20)
    batch_neuron_discover_parser.add_argument("--allow-zero-indicator-malicious", action="store_true")
    batch_neuron_discover_parser.add_argument(
        "--output-prefix",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "batch_neuron_discovery",
    )
    batch_neuron_discover_parser.set_defaults(func=cmd_batch_neuron_discover)

    batch_neuron_ablation_parser = subparsers.add_parser(
        "batch-neuron-ablation",
        help="Ablate selected MLP neurons across multiple pairs.",
    )
    batch_neuron_ablation_parser.add_argument("--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv")
    batch_neuron_ablation_parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    batch_neuron_ablation_parser.add_argument("--template-name", default="meta-llama/Llama-3.1-8B-Instruct")
    batch_neuron_ablation_parser.add_argument("--device", default=None)
    batch_neuron_ablation_parser.add_argument("--torch-dtype", choices=["float16", "bfloat16", "float32"], default="float16")
    batch_neuron_ablation_parser.add_argument("--num-pairs", type=int, default=3)
    batch_neuron_ablation_parser.add_argument("--first-n-layers", type=int, default=None)
    batch_neuron_ablation_parser.add_argument("--neurons", default=None)
    batch_neuron_ablation_parser.add_argument("--neuron-summary", type=Path, default=None)
    batch_neuron_ablation_parser.add_argument("--top-k-per-layer", type=int, default=5)
    batch_neuron_ablation_parser.add_argument("--allow-zero-indicator-malicious", action="store_true")
    batch_neuron_ablation_parser.add_argument(
        "--output-prefix",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "batch_neuron_ablation",
    )
    batch_neuron_ablation_parser.set_defaults(func=cmd_batch_neuron_ablation)

    batch_neuron_group_ablation_parser = subparsers.add_parser(
        "batch-neuron-group-ablation",
        help="Ablate discovered neuron groups together across multiple pairs.",
    )
    batch_neuron_group_ablation_parser.add_argument("--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv")
    batch_neuron_group_ablation_parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    batch_neuron_group_ablation_parser.add_argument("--template-name", default="meta-llama/Llama-3.1-8B-Instruct")
    batch_neuron_group_ablation_parser.add_argument("--device", default=None)
    batch_neuron_group_ablation_parser.add_argument("--torch-dtype", choices=["float16", "bfloat16", "float32"], default="float16")
    batch_neuron_group_ablation_parser.add_argument("--num-pairs", type=int, default=3)
    batch_neuron_group_ablation_parser.add_argument("--first-n-layers", type=int, default=None)
    batch_neuron_group_ablation_parser.add_argument("--layers", required=True)
    batch_neuron_group_ablation_parser.add_argument("--group-sizes", default="3,5")
    batch_neuron_group_ablation_parser.add_argument("--neuron-summary", type=Path, required=True)
    batch_neuron_group_ablation_parser.add_argument("--allow-zero-indicator-malicious", action="store_true")
    batch_neuron_group_ablation_parser.add_argument(
        "--output-prefix",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "batch_neuron_group_ablation",
    )
    batch_neuron_group_ablation_parser.set_defaults(func=cmd_batch_neuron_group_ablation)

    discover_residual_subspace_parser = subparsers.add_parser(
        "discover-residual-subspace",
        help="Compute a low-rank residual-delta basis between benign and malicious prompts.",
    )
    discover_residual_subspace_parser.add_argument(
        "--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv"
    )
    discover_residual_subspace_parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    discover_residual_subspace_parser.add_argument("--template-name", default="meta-llama/Llama-3.1-8B-Instruct")
    discover_residual_subspace_parser.add_argument("--device", default=None)
    discover_residual_subspace_parser.add_argument(
        "--torch-dtype", choices=["float16", "bfloat16", "float32"], default="float16"
    )
    discover_residual_subspace_parser.add_argument("--num-pairs", type=int, default=3)
    discover_residual_subspace_parser.add_argument("--first-n-layers", type=int, default=None)
    discover_residual_subspace_parser.add_argument("--layer", type=int, required=True)
    discover_residual_subspace_parser.add_argument("--resid-kind", choices=["pre", "mid", "post"], default="pre")
    discover_residual_subspace_parser.add_argument("--max-rank", type=int, default=8)
    discover_residual_subspace_parser.add_argument("--allow-zero-indicator-malicious", action="store_true")
    discover_residual_subspace_parser.add_argument(
        "--output-prefix",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "residual_subspace",
    )
    discover_residual_subspace_parser.set_defaults(func=cmd_discover_residual_subspace)

    batch_residual_subspace_patching_parser = subparsers.add_parser(
        "batch-residual-subspace-patching",
        help="Patch low-rank residual subspaces from benign into malicious prompts across pairs.",
    )
    batch_residual_subspace_patching_parser.add_argument(
        "--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv"
    )
    batch_residual_subspace_patching_parser.add_argument("--basis-path", type=Path, required=True)
    batch_residual_subspace_patching_parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    batch_residual_subspace_patching_parser.add_argument(
        "--template-name", default="meta-llama/Llama-3.1-8B-Instruct"
    )
    batch_residual_subspace_patching_parser.add_argument("--device", default=None)
    batch_residual_subspace_patching_parser.add_argument(
        "--torch-dtype", choices=["float16", "bfloat16", "float32"], default="float16"
    )
    batch_residual_subspace_patching_parser.add_argument("--num-pairs", type=int, default=3)
    batch_residual_subspace_patching_parser.add_argument("--first-n-layers", type=int, default=None)
    batch_residual_subspace_patching_parser.add_argument("--subspace-dims", default="1,2,4,8")
    batch_residual_subspace_patching_parser.add_argument("--allow-zero-indicator-malicious", action="store_true")
    batch_residual_subspace_patching_parser.add_argument(
        "--output-prefix",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "residual_subspace_patching",
    )
    batch_residual_subspace_patching_parser.set_defaults(func=cmd_batch_residual_subspace_patching)

    discover_contrastive_residual_parser = subparsers.add_parser(
        "discover-contrastive-residual-directions",
        help="Build a task-aligned residual basis from mean delta and logit readout directions.",
    )
    discover_contrastive_residual_parser.add_argument(
        "--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv"
    )
    discover_contrastive_residual_parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    discover_contrastive_residual_parser.add_argument(
        "--template-name", default="meta-llama/Llama-3.1-8B-Instruct"
    )
    discover_contrastive_residual_parser.add_argument("--device", default=None)
    discover_contrastive_residual_parser.add_argument(
        "--torch-dtype", choices=["float16", "bfloat16", "float32"], default="float16"
    )
    discover_contrastive_residual_parser.add_argument("--num-pairs", type=int, default=3)
    discover_contrastive_residual_parser.add_argument("--first-n-layers", type=int, default=None)
    discover_contrastive_residual_parser.add_argument("--layer", type=int, required=True)
    discover_contrastive_residual_parser.add_argument("--resid-kind", choices=["pre", "mid", "post"], default="pre")
    discover_contrastive_residual_parser.add_argument("--allow-zero-indicator-malicious", action="store_true")
    discover_contrastive_residual_parser.add_argument(
        "--output-prefix",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "contrastive_residual_directions",
    )
    discover_contrastive_residual_parser.set_defaults(func=cmd_discover_contrastive_residual_directions)

    batch_contrastive_residual_patching_parser = subparsers.add_parser(
        "batch-contrastive-residual-patching",
        help="Patch task-aligned residual directions from benign into malicious prompts across pairs.",
    )
    batch_contrastive_residual_patching_parser.add_argument(
        "--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv"
    )
    batch_contrastive_residual_patching_parser.add_argument("--basis-path", type=Path, required=True)
    batch_contrastive_residual_patching_parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    batch_contrastive_residual_patching_parser.add_argument(
        "--template-name", default="meta-llama/Llama-3.1-8B-Instruct"
    )
    batch_contrastive_residual_patching_parser.add_argument("--device", default=None)
    batch_contrastive_residual_patching_parser.add_argument(
        "--torch-dtype", choices=["float16", "bfloat16", "float32"], default="float16"
    )
    batch_contrastive_residual_patching_parser.add_argument("--num-pairs", type=int, default=3)
    batch_contrastive_residual_patching_parser.add_argument("--first-n-layers", type=int, default=None)
    batch_contrastive_residual_patching_parser.add_argument("--allow-zero-indicator-malicious", action="store_true")
    batch_contrastive_residual_patching_parser.add_argument(
        "--output-prefix",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "contrastive_residual_patching",
    )
    batch_contrastive_residual_patching_parser.set_defaults(func=cmd_batch_contrastive_residual_patching)

    batch_trace_residual_direction_heads_parser = subparsers.add_parser(
        "batch-trace-residual-direction-heads",
        help="Rank late attention heads by projection onto a discovered residual direction.",
    )
    batch_trace_residual_direction_heads_parser.add_argument(
        "--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv"
    )
    batch_trace_residual_direction_heads_parser.add_argument("--basis-path", type=Path, required=True)
    batch_trace_residual_direction_heads_parser.add_argument("--basis-label", required=True)
    batch_trace_residual_direction_heads_parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    batch_trace_residual_direction_heads_parser.add_argument(
        "--template-name", default="meta-llama/Llama-3.1-8B-Instruct"
    )
    batch_trace_residual_direction_heads_parser.add_argument("--device", default=None)
    batch_trace_residual_direction_heads_parser.add_argument(
        "--torch-dtype", choices=["float16", "bfloat16", "float32"], default="float16"
    )
    batch_trace_residual_direction_heads_parser.add_argument("--num-pairs", type=int, default=3)
    batch_trace_residual_direction_heads_parser.add_argument("--first-n-layers", type=int, default=None)
    batch_trace_residual_direction_heads_parser.add_argument("--layers", required=True)
    batch_trace_residual_direction_heads_parser.add_argument("--topk", type=int, default=12)
    batch_trace_residual_direction_heads_parser.add_argument("--allow-zero-indicator-malicious", action="store_true")
    batch_trace_residual_direction_heads_parser.add_argument(
        "--output-prefix",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "directional_head_trace",
    )
    batch_trace_residual_direction_heads_parser.set_defaults(func=cmd_batch_trace_residual_direction_heads)

    batch_head_group_ablation_parser = subparsers.add_parser(
        "batch-head-group-ablation",
        help="Ablate a selected attention-head group together across multiple pairs.",
    )
    batch_head_group_ablation_parser.add_argument(
        "--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv"
    )
    batch_head_group_ablation_parser.add_argument("--heads", required=True)
    batch_head_group_ablation_parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    batch_head_group_ablation_parser.add_argument(
        "--template-name", default="meta-llama/Llama-3.1-8B-Instruct"
    )
    batch_head_group_ablation_parser.add_argument("--device", default=None)
    batch_head_group_ablation_parser.add_argument(
        "--torch-dtype", choices=["float16", "bfloat16", "float32"], default="float16"
    )
    batch_head_group_ablation_parser.add_argument("--num-pairs", type=int, default=3)
    batch_head_group_ablation_parser.add_argument("--first-n-layers", type=int, default=None)
    batch_head_group_ablation_parser.add_argument("--allow-zero-indicator-malicious", action="store_true")
    batch_head_group_ablation_parser.add_argument(
        "--output-prefix",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "batch_head_group_ablation",
    )
    batch_head_group_ablation_parser.set_defaults(func=cmd_batch_head_group_ablation)

    batch_residual_direction_intervention_parser = subparsers.add_parser(
        "batch-residual-direction-intervention",
        help="Measure how a head intervention changes a discovered residual direction and the final logit.",
    )
    batch_residual_direction_intervention_parser.add_argument(
        "--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv"
    )
    batch_residual_direction_intervention_parser.add_argument("--basis-path", type=Path, required=True)
    batch_residual_direction_intervention_parser.add_argument("--basis-label", required=True)
    batch_residual_direction_intervention_parser.add_argument("--heads", required=True)
    batch_residual_direction_intervention_parser.add_argument("--mode", choices=["patch", "ablate"], required=True)
    batch_residual_direction_intervention_parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    batch_residual_direction_intervention_parser.add_argument(
        "--template-name", default="meta-llama/Llama-3.1-8B-Instruct"
    )
    batch_residual_direction_intervention_parser.add_argument("--device", default=None)
    batch_residual_direction_intervention_parser.add_argument(
        "--torch-dtype", choices=["float16", "bfloat16", "float32"], default="float16"
    )
    batch_residual_direction_intervention_parser.add_argument("--num-pairs", type=int, default=3)
    batch_residual_direction_intervention_parser.add_argument("--first-n-layers", type=int, default=None)
    batch_residual_direction_intervention_parser.add_argument("--allow-zero-indicator-malicious", action="store_true")
    batch_residual_direction_intervention_parser.add_argument(
        "--output-prefix",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "residual_direction_intervention",
    )
    batch_residual_direction_intervention_parser.set_defaults(func=cmd_batch_residual_direction_intervention)

    batch_trace_direction_under_intervention_parser = subparsers.add_parser(
        "batch-trace-direction-under-intervention",
        help="Trace how a source-head intervention changes late head writes into a discovered residual direction.",
    )
    batch_trace_direction_under_intervention_parser.add_argument(
        "--manifest", type=Path, default=DEFAULT_ARTIFACT_DIR / "analysis_manifest.csv"
    )
    batch_trace_direction_under_intervention_parser.add_argument("--basis-path", type=Path, required=True)
    batch_trace_direction_under_intervention_parser.add_argument("--basis-label", required=True)
    batch_trace_direction_under_intervention_parser.add_argument("--source-heads", required=True)
    batch_trace_direction_under_intervention_parser.add_argument("--mode", choices=["patch", "ablate"], required=True)
    batch_trace_direction_under_intervention_parser.add_argument("--model-name", default=DEFAULT_MODEL_NAME)
    batch_trace_direction_under_intervention_parser.add_argument(
        "--template-name", default="meta-llama/Llama-3.1-8B-Instruct"
    )
    batch_trace_direction_under_intervention_parser.add_argument("--device", default=None)
    batch_trace_direction_under_intervention_parser.add_argument(
        "--torch-dtype", choices=["float16", "bfloat16", "float32"], default="float16"
    )
    batch_trace_direction_under_intervention_parser.add_argument("--num-pairs", type=int, default=3)
    batch_trace_direction_under_intervention_parser.add_argument("--first-n-layers", type=int, default=None)
    batch_trace_direction_under_intervention_parser.add_argument("--layers", required=True)
    batch_trace_direction_under_intervention_parser.add_argument("--topk", type=int, default=12)
    batch_trace_direction_under_intervention_parser.add_argument("--allow-zero-indicator-malicious", action="store_true")
    batch_trace_direction_under_intervention_parser.add_argument(
        "--output-prefix",
        type=Path,
        default=DEFAULT_ARTIFACT_DIR / "direction_trace_under_intervention",
    )
    batch_trace_direction_under_intervention_parser.set_defaults(func=cmd_batch_trace_direction_under_intervention)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
