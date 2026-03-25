# Circuit Validation - Quick Start Guide

## What Is This?

A new Jupyter notebook (`circuit_validation_experiments.ipynb`) that validates the three-stage PowerShell classification circuit through **5 focused experiments**.

## Why Validate?

The initial analysis identified the circuit through **observational methods** (attention, logit lens). Validation uses **causal methods** (ablation, minimization, attribution) to prove the circuit components actually matter.

## The 5 Experiments (30-45 min total)

| # | Name | What It Does | Expected Result |
|---|------|-------------|-----------------|
| 1 | Layer 0 Ablation | Zero out Layer 0 heads | Malicious confidence ↓ |
| 2 | Critical Layer Ablation | Zero out layers 20,25,30 | Classification broken |
| 3 | Minimal Circuit | Keep only Layer 0 + 25-31 | 70-80% behavior preserved |
| 4 | Keyword Sensitivity | Replace keywords | Malicious → benign |
| 5 | Token Attribution | Mask each token | Keywords = top scores |

## How to Run

```bash
# 1. Open the notebook
jupyter notebook circuit_validation_experiments.ipynb

# 2. Run all cells in order (takes 30-45 min)
# Cell > Run All

# 3. Check results in circuit_validation_results/
# (CSV files for each experiment)
```

## What to Look For

✅ **Success** = All 5 experiments show predicted results
⚠️ **Partial** = 3-4 experiments work (refine circuit)
❌ **Fail** = <3 experiments work (re-examine analysis)

## Key Question Each Experiment Answers

1. **Layer 0 matter?** → Yes if malicious LD drops
2. **Late layers critical?** → Yes if huge LD changes
3. **Circuit minimal?** → Yes if preserves ~75%
4. **Keywords matter?** → Yes if replacing breaks it
5. **Keywords top signal?** → Yes if highest attribution

## Files Generated

```
circuit_validation_results/
├── baseline_results.csv
├── exp1_layer0_ablation.csv
├── exp2_layers_ablation.csv
├── exp3_minimal_circuit.csv
├── exp4_keyword_sensitivity.csv
└── exp5_token_attribution.csv
```

## Quick Analysis

```python
import pandas as pd

# Check each experiment
results = {}
for i in range(1, 6):
    if i == 0:
        df = pd.read_csv("circuit_validation_results/baseline_results.csv")
    else:
        df = pd.read_csv(f"circuit_validation_results/exp{i}_*.csv")
    results[i] = df

# Overall success
exp1 = results[1]  # Layer 0 ablation
mal_data = exp1[exp1["label"] == 1]
success = (mal_data["ld_change"] < 0).mean() > 0.6  # >60% reduced confidence
print(f"Experiment 1 success: {success}")
```

## Debugging Tips

**Slow?** → Normal, takes 30-45 min
**Memory error?** → Skip Exp2, use GPU if available
**No results?** → Check transformer_lens is installed
**Different numbers?** → Model uses randomness, set SEED first

## Expected Results Summary

If validation succeeds, you'll see:

✓ Layer 0 heads causally reduce confidence when removed
✓ Layers 20,25,30 are where decision actually happens
✓ 75% of behavior survives with minimal circuit
✓ Keywords are crucial (replacing them changes classification)
✓ Keywords are top-attributed tokens

This **proves the circuit structure** and shows each stage is **causally important**.

## Next Steps

- ✅ Run validation experiments
- ✅ Check all 5 experiments pass
- ✅ Save results CSVs
- ✅ Document findings
- ✅ Share/publish results

## Files

- **Notebook**: `circuit_validation_experiments.ipynb`
- **Guide**: `VALIDATION_EXPERIMENTS_README.md` (detailed)
- **This file**: `VALIDATION_QUICK_START.md` (quick reference)

## Time Estimate

- Setup: 2-3 min
- Baseline: 2 min
- Exp 1 (ablate Layer 0): 3 min
- Exp 2 (ablate layers): 10-15 min ⏱️
- Exp 3 (minimal circuit): 10-15 min ⏱️
- Exp 4 (keywords): 2 min
- Exp 5 (attribution): 5 min
- **Total: 30-45 minutes**

---

## Start Here

```bash
jupyter notebook circuit_validation_experiments.ipynb
# Run all cells
# Check results in circuit_validation_results/
```

Questions? See `VALIDATION_EXPERIMENTS_README.md` for detailed guide.
