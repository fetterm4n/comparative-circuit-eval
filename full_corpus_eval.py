"""Unselected, paired PowerShell evaluation; no activation caching required.

Preparation and reporting use only the standard library. Inference requires
the existing pipeline's PyTorch/Transformers environment. See FULL_CORPUS_EVAL.md.
"""
import argparse
import ast
import collections
import csv
import hashlib
import json
import math
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MODELS = {
    "foundation_sec": "fdtn-ai/Foundation-Sec-8B-Instruct",
    "llama3": "meta-llama/Llama-3.1-8B-Instruct",
}


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def prompts():
    # Reuse the exact established prompts without importing GPU dependencies.
    names = {"raw": "_CLASSIFIER_PROMPT_SYSTEM", "full": "_CLASSIFIER_INTENT_SYSTEM",
             "adversarial": "_CLASSIFIER_ADVERSARIAL_SYSTEM"}
    values = {}
    for node in ast.parse((ROOT / "scaled_validation.py").read_text()).body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in names.values():
                    values[target.id] = ast.literal_eval(node.value)
    return {key: values[value] for key, value in names.items()}


def prepare(args):
    csv.field_size_limit(sys.maxsize)
    unique, empty, duplicates, conflicts = {}, 0, 0, []
    with args.csv.open(newline="", encoding="utf-8-sig") as handle:
        for line, row in enumerate(csv.DictReader(handle), 2):
            label = row.get("label", "").strip().lower()
            if label not in {"benign", "malicious"}:
                raise ValueError(f"Invalid label at CSV line {line}: {label!r}")
            content = row.get("Content", row.get("content", "")).replace("\r\n", "\n").strip("\n")
            if not content.strip():
                empty += 1
                continue
            key = digest(content)
            if key in unique:
                duplicates += 1
                if unique[key]["label"] != label:
                    conflicts.append({"script_id": key, "csv_line": line})
                continue
            unique[key] = {"script_id": key, "filename": row.get("Filename", row.get("filename", "")),
                           "label": label, "content": content, "raw_char_len": len(content)}
    if conflicts:
        raise ValueError(f"Conflicting labels on duplicate contents: {conflicts}")
    if not unique:
        raise ValueError("Dataset contains no nonempty scripts")
    args.output.mkdir(parents=True, exist_ok=True)
    manifest = args.output / "manifest.jsonl"
    data = "".join(json.dumps(row) + "\n" for row in unique.values())
    if manifest.exists() and manifest.read_text() != data:
        raise ValueError("Existing manifest differs; use a fresh output directory.")
    manifest.write_text(data)
    info = {"source": str(args.csv.resolve()), "source_sha256": hashlib.sha256(args.csv.read_bytes()).hexdigest(),
            "unique_nonempty_scripts": len(unique), "empty_rows": empty, "duplicate_rows": duplicates,
            "classes": dict(collections.Counter(row["label"] for row in unique.values())),
            "manifest_sha256": digest(data)}
    (args.output / "dataset.json").write_text(json.dumps(info, indent=2) + "\n")
    print(json.dumps(info, indent=2))


def read_jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def run(args):
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    rows = read_jsonl(args.output / "manifest.jsonl")
    system_prompts = prompts()
    manifest_hash = digest((args.output / "manifest.jsonl").read_text())
    for name in args.models:
        model_id = MODELS[name]
        tokenizer = AutoTokenizer.from_pretrained(model_id, revision=args.revision)
        model = AutoModelForCausalLM.from_pretrained(model_id, revision=args.revision,
                                                    torch_dtype=torch.bfloat16 if args.device == "cuda" else torch.float32)
        model.to(args.device).eval()
        # Historical metric: compare the first tokens of space-prefixed labels.
        allow_id = tokenizer.encode(" ALLOW", add_special_tokens=False)[0]
        block_id = tokenizer.encode(" BLOCK", add_special_tokens=False)[0]
        if allow_id == block_id:
            raise ValueError("Label first tokens coincide; cannot use historical scoring.")
        context = min(args.max_tokens, int(model.config.max_position_embeddings))
        for variant in args.prompts:
            path = args.output / f"{name}_{variant}.jsonl"
            settings = {"model": model_id, "revision": args.revision,
                        "resolved_commit": getattr(model.config, "_commit_hash", None),
                        "prompt": variant, "system": system_prompts[variant], "chat_template": tokenizer.chat_template,
                        "max_tokens": context, "max_chars": args.max_chars, "manifest_sha256": manifest_hash,
                        "scoring": "first-token BLOCK minus ALLOW logits", "allow_token_id": allow_id,
                        "block_token_id": block_id, "dtype": str(model.dtype)}
            meta = path.with_suffix(".metadata.json")
            if meta.exists() and json.loads(meta.read_text()) != settings:
                raise ValueError(f"Settings changed for {path}; use a fresh output directory.")
            if path.exists() and not meta.exists():
                raise ValueError(f"Missing metadata for {path}")
            meta.write_text(json.dumps(settings, indent=2) + "\n")
            completed = {r["script_id"] for r in read_jsonl(path)} if path.exists() else set()

            def encode(content):
                messages = [{"role": "system", "content": system_prompts[variant]},
                            {"role": "user", "content": "PowerShell:\n```powershell\n" + content + "\n```\nAnswer:"}]
                return tokenizer.apply_chat_template(messages, tokenize=True, add_generation_prompt=True)

            with path.open("a") as handle:
                for index, row in enumerate(rows):
                    if row["script_id"] in completed:
                        continue
                    content = row["content"][:args.max_chars] if args.max_chars else row["content"]
                    char_capped = len(content) < len(row["content"])
                    ids = encode(content)
                    uncapped_tokens = len(ids)
                    if len(ids) > context:
                        # Trim only script text, preserving system instructions and answer suffix.
                        low, high = 0, len(content)
                        while low < high:
                            mid = (low + high + 1) // 2
                            if len(encode(content[:mid])) <= context:
                                low = mid
                            else:
                                high = mid - 1
                        content = content[:low]
                        ids = encode(content)
                    if len(ids) > context:
                        raise ValueError("Context budget is smaller than the prompt overhead")
                    with torch.inference_mode():
                        inputs = torch.tensor([ids], device=args.device)
                        logits = model(input_ids=inputs, attention_mask=torch.ones_like(inputs)).logits[0, -1]
                        diff = float((logits[block_id].float() - logits[allow_id].float()).item())
                    if not math.isfinite(diff):
                        raise ValueError(f"Nonfinite logits for {row['script_id']}")
                    result = {k: v for k, v in row.items() if k != "content"}
                    result.update(predicted_label="malicious" if diff > 0 else "benign", logit_diff=diff,
                                  prompt_tokens=len(ids), uncapped_prompt_tokens=uncapped_tokens,
                                  used_char_len=len(content), char_capped=char_capped,
                                  token_capped=len(ids) < uncapped_tokens)
                    handle.write(json.dumps(result) + "\n")
                    handle.flush()
                    if (index + 1) % 50 == 0:
                        print(f"{name}/{variant}: {index + 1}/{len(rows)}", flush=True)
        del model
        if args.device == "cuda":
            torch.cuda.empty_cache()


def metrics(rows):
    tp = sum(r["label"] == "malicious" and r["predicted_label"] == "malicious" for r in rows)
    tn = sum(r["label"] == "benign" and r["predicted_label"] == "benign" for r in rows)
    fp = sum(r["label"] == "benign" and r["predicted_label"] == "malicious" for r in rows)
    fn = sum(r["label"] == "malicious" and r["predicted_label"] == "benign" for r in rows)
    def ratio(a, b):
        return a / b if b else None
    recall, specificity = ratio(tp, tp + fn), ratio(tn, tn + fp)
    return {"n": len(rows), "accuracy": ratio(tp + tn, len(rows)), "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "precision": ratio(tp, tp + fp), "recall": recall, "f1": ratio(2 * tp, 2 * tp + fp + fn),
            "false_positive_rate": ratio(fp, fp + tn),
            "balanced_accuracy": (recall + specificity) / 2 if recall is not None and specificity is not None else None}


def report(args):
    source = read_jsonl(args.output / "manifest.jsonl")
    ids = {r["script_id"] for r in source}
    results, summaries, comparisons = {}, {}, {}
    for path in sorted(args.output.glob("*.jsonl")):
        if path.name == "manifest.jsonl":
            continue
        rows = read_jsonl(path)
        if len({r["script_id"] for r in rows}) != len(rows):
            raise ValueError(f"Duplicate predictions in {path}")
        if not {r["script_id"] for r in rows} <= ids:
            raise ValueError(f"Unknown scripts in {path}")
        results[path.stem] = {r["script_id"]: r for r in rows}
        summaries[path.stem] = {"complete": len(rows) == len(source), "overall": metrics(rows),
            "untruncated": metrics([r for r in rows if not r["char_capped"] and not r["token_capped"]]),
            "truncated": metrics([r for r in rows if r["char_capped"] or r["token_capped"]]),
            "by_length": {label: metrics([r for r in rows if lo <= r["raw_char_len"] < hi])
                          for label, lo, hi in [("under_3k", 0, 3000), ("3k_to_12k", 3000, 12000),
                                                ("12k_plus", 12000, float("inf"))]}}
        families = ["-EncodedCommand", "DownloadFile", "DownloadString", "FromBase64String",
                    "IEX", "Invoke-Expression", "Invoke-WebRequest"]
        summaries[path.stem]["by_indicator"] = {
            family: metrics([results[path.stem][s["script_id"]] for s in source
                             if s["script_id"] in results[path.stem] and family.lower() in s["content"].lower()])
            for family in families}
    for variant in prompts():
        left, right = results.get(f"foundation_sec_{variant}"), results.get(f"llama3_{variant}")
        if left is None or right is None or set(left) != ids or set(right) != ids:
            continue
        changes = [int(left[k]["label"] == left[k]["predicted_label"]) -
                   int(right[k]["label"] == right[k]["predicted_label"]) for k in sorted(ids)]
        fs_only, llama_only = changes.count(1), changes.count(-1)
        counts = [changes.count(-1), changes.count(0), changes.count(1)]
        rng = random.Random(42)
        # Paired bootstrap of per-script correctness differences.
        draws = []
        for _ in range(2000):
            sample = rng.choices([-1, 0, 1], weights=counts, k=len(changes))
            draws.append(sum(sample) / len(sample))
        draws.sort()
        discordant = fs_only + llama_only
        p = min(1.0, 2 * sum(math.comb(discordant, i) for i in range(min(fs_only, llama_only) + 1)) / 2 ** discordant) if discordant else 1.0
        comparisons[variant] = {"n": len(changes), "accuracy_difference": sum(changes) / len(changes),
                                "paired_bootstrap_95_ci": [draws[50], draws[1949]],
                                "foundation_only_correct": fs_only, "llama_only_correct": llama_only,
                                "mcnemar_exact_p": p}
    payload = {"runs": summaries, "same_prompt_comparisons": comparisons}
    (args.output / "report.json").write_text(json.dumps(payload, indent=2) + "\n")
    print(json.dumps(payload, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["prepare", "run", "report"])
    parser.add_argument("--csv", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts" / "full_corpus_eval")
    parser.add_argument("--models", nargs="+", choices=MODELS, default=list(MODELS))
    parser.add_argument("--prompts", nargs="+", choices=["raw", "adversarial", "full"], default=["raw", "adversarial", "full"])
    parser.add_argument("--device", default="cuda")
    parser.add_argument("--revision", default="main")
    parser.add_argument("--max-tokens", type=int, default=8192)
    parser.add_argument("--max-chars", type=int, default=12000, help="0 disables the historical character cap")
    args = parser.parse_args()
    if args.command == "prepare" and args.csv is None:
        parser.error("prepare requires --csv")
    if args.max_tokens < 1 or args.max_chars < 0:
        parser.error("max-tokens must be positive and max-chars nonnegative")
    {"prepare": prepare, "run": run, "report": report}[args.command](args)


if __name__ == "__main__":
    main()
