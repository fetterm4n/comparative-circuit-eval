# Validation Experiments - File Index

## Overview

This folder now contains a **complete validation pipeline** for the PowerShell classification circuit. The new validation notebook (`circuit_validation_experiments.ipynb`) provides causal evidence through 5 focused experiments.

---

## New Validation Files (March 24, 2026)

### 1. **circuit_validation_experiments.ipynb** (29 KB)
**What**: Main Jupyter notebook with all 5 validation experiments
**Contains**:
- Setup and model loading
- Extended dataset (10 examples: 5 benign, 5 malicious)
- Experiment 1: Layer 0 ablation
- Experiment 2: Critical layer ablation (layers 20, 25, 30)
- Experiment 3: Minimal circuit test
- Experiment 4: Keyword sensitivity analysis
- Experiment 5: Token attribution analysis
- Results summary and interpretation

**How to use**: `jupyter notebook circuit_validation_experiments.ipynb` → Run all cells

**Runtime**: 30-45 minutes

**Output**: CSV files in `circuit_validation_results/`

---

### 2. **VALIDATION_QUICK_START.md** (3.9 KB)
**What**: 1-2 page quick reference guide
**Best for**: Users who want to start immediately
**Contains**:
- What is this? Why validate?
- The 5 experiments (table format)
- How to run (2 steps)
- Expected outcomes (success/partial/fail)
- Files generated
- Quick Python analysis snippet
- Debugging tips
- Time estimates

**Read time**: 5-10 minutes

---

### 3. **VALIDATION_EXPERIMENTS_README.md** (9.3 KB)
**What**: Detailed comprehensive guide
**Best for**: Users who want to understand everything
**Contains**:
- Overview and purpose
- Each experiment detailed (motivation, method, expected result)
- Running the notebook (prerequisites, setup, runtime)
- Dataset used (10 examples)
- Key results to look for (what's success vs failure)
- Output files (detailed explanation)
- Troubleshooting section
- Extending the validation (how to test more)
- Interpreting validation (strong/partial/no validation)
- Success criteria
- Next steps (if validation succeeds/fails)
- References to other files

**Read time**: 20-30 minutes

---

## Original Analysis Files (for Reference)

### From Initial Analysis (March 23, 2026)

- **00_START_HERE.md** - Project entry point with 4 reading paths
- **ANALYSIS_COMPLETE.txt** - Full summary with all findings
- **CIRCUIT_FINDINGS.md** - Key results and interpretation
- **circuit_validation_guide.md** - Original methodology (10 sections)
- **README_CIRCUIT_ANALYSIS.md** - Complete technical guide
- **INDEX.md** - Navigation guide for original analysis files
- **DELIVERABLES.txt** - Original completion checklist

### Code Files

- **foundation_sec_mi_powershell_circuit_analysis.py** - Automated analysis script
- **foundation_sec_mi_powershell_classification.ipynb** - Original interactive notebook

---

## How to Use This Validation Workflow

### Step 1: Understand What You're Validating (5 min)
Read: **00_START_HERE.md** or **CIRCUIT_FINDINGS.md**

Understand:
- The three-stage circuit structure
- Initial findings (attention, logit lens, etc.)
- Why validation is needed

### Step 2: Choose Your Path (2 min)

**Path A - Quick Start** (60 min total):
1. Read: VALIDATION_QUICK_START.md (5 min)
2. Run: circuit_validation_experiments.ipynb (40 min)
3. Analyze: Results CSV files (15 min)

**Path B - Detailed Start** (90 min total):
1. Read: VALIDATION_EXPERIMENTS_README.md (20 min)
2. Read: circuit_validation_guide.md first 5 sections (15 min)
3. Run: circuit_validation_experiments.ipynb (40 min)
4. Analyze: Results with context (15 min)

### Step 3: Run the Validation Experiments (30-45 min)
```bash
jupyter notebook circuit_validation_experiments.ipynb
# Run all cells
```

### Step 4: Check Results (5-10 min)
```bash
ls circuit_validation_results/
# 6 CSV files:
# - baseline_results.csv
# - exp1_layer0_ablation.csv
# - exp2_layers_ablation.csv
# - exp3_minimal_circuit.csv
# - exp4_keyword_sensitivity.csv
# - exp5_token_attribution.csv
```

### Step 5: Interpret Results (10-20 min)
Use VALIDATION_EXPERIMENTS_README.md section "Interpreting Circuit Validation" to determine:
- ✅ Strong validation (all experiments confirm)
- ⚠️ Partial validation (some experiments work)
- ❌ No validation (experiments contradict)

---

## The 5 Validation Experiments

| # | Name | Duration | Purpose | Success Signal |
|---|------|----------|---------|-----------------|
| 1 | Layer 0 Ablation | 3 min | Test early detection layer | Malicious LD drops |
| 2 | Critical Layer Ablation | 10-15 min | Test decision layers | Classification breaks |
| 3 | Minimal Circuit | 10-15 min | Test circuit minimality | ~75% behavior preserved |
| 4 | Keyword Sensitivity | 2 min | Test keyword dependence | Keywords matter |
| 5 | Token Attribution | 5 min | Find important tokens | Keywords top-attributed |

---

## Expected Results

### Success ✅
All 5 experiments confirm predictions:
- Layer 0 heads causally important
- Layers 20,25,30 decision-critical
- Minimal circuit preserves behavior
- Keywords drive classification
- Keywords have high attribution

→ **Conclusion**: Circuit is valid, publication-ready

### Partial ⚠️
3-4 experiments confirm:
- Refine circuit model
- Identify which components need adjustment
- Re-test with adjusted circuit

→ **Conclusion**: Circuit needs refinement

### No Validation ❌
<3 experiments confirm:
- Re-examine initial circuit identification
- Try different layer combinations
- Consider alternative architectures

→ **Conclusion**: Circuit structure needs revision

---

## Output Files Generated

After running `circuit_validation_experiments.ipynb`, you'll have:

```
circuit_validation_results/
├── baseline_results.csv          (10 rows, baseline accuracy)
├── exp1_layer0_ablation.csv      (10 rows, layer 0 removal effects)
├── exp2_layers_ablation.csv      (10 rows, layers 20,25,30 removal effects)
├── exp3_minimal_circuit.csv      (10 rows, behavior preservation metrics)
├── exp4_keyword_sensitivity.csv  (5 rows, keyword replacement effects)
└── exp5_token_attribution.csv    (~70 rows, per-token attribution scores)
```

### Quick CSV Analysis

```python
import pandas as pd

# Check each experiment
baseline = pd.read_csv("circuit_validation_results/baseline_results.csv")
exp1 = pd.read_csv("circuit_validation_results/exp1_layer0_ablation.csv")
exp3 = pd.read_csv("circuit_validation_results/exp3_minimal_circuit.csv")

# Metrics
print(f"Baseline accuracy: {baseline['correct'].mean():.1%}")
print(f"Exp 1 - Mal avg LD change: {exp1[exp1['label']==1]['ld_change'].mean():.4f}")
print(f"Exp 3 - Avg preservation: {exp3['behavior_preserved_%'].mean():.1f}%")
```

---

## Troubleshooting

### Issue: Slow Experiments 2 & 3
**Normal**: These use layer ablation (must re-run forward passes)
**Expected**: 10-15 min each
**Solution**: Patience, or use GPU

### Issue: Memory Error
**Cause**: Large model + layer ablation
**Solution**: Skip Experiment 2 initially, use GPU if available

### Issue: NaN Values in Results
**Cause**: Edge cases in tokenization or attribution
**Solution**: Safe to ignore individual NaN entries, check means

### Issue: Different Numbers Than Expected
**Cause**: Model randomness, different seeds
**Solution**: Set SEED at top of notebook for reproducibility

---

## File Locations

All files are in: `/Users/rfetterman/DEV/mech-interp/`

**Quick access commands:**
```bash
# View validation docs
cat VALIDATION_QUICK_START.md          # 2 min summary
cat VALIDATION_EXPERIMENTS_README.md   # 20 min detailed guide

# Open notebook
jupyter notebook circuit_validation_experiments.ipynb

# Check results
ls -la circuit_validation_results/
```

---

## Next Steps After Validation

### If Validation Succeeds ✅
- [ ] Document in paper/report
- [ ] Compare with other models
- [ ] Test on larger dataset
- [ ] Prepare for publication

### If Validation Partial ⚠️
- [ ] Refine circuit model
- [ ] Adjust layer combinations
- [ ] Re-test with new hypothesis

### If Validation Fails ❌
- [ ] Re-examine initial analysis
- [ ] Try different methodologies
- [ ] Consider alternative circuit structures

---

## Reference

**For original circuit identification**:
- See: `00_START_HERE.md`, `CIRCUIT_FINDINGS.md`

**For original methodology**:
- See: `circuit_validation_guide.md`, `README_CIRCUIT_ANALYSIS.md`

**For understanding this validation work**:
- Start: `VALIDATION_QUICK_START.md`
- Deep: `VALIDATION_EXPERIMENTS_README.md`

---

## Timeline

**March 23, 2026**: Initial circuit identification (completed)
- Attention analysis
- Head patching
- Layer patching
- Logit lens
- Documentation

**March 24, 2026**: Validation experiments (this work)
- Ablation studies
- Circuit minimization
- Token attribution
- Comprehensive validation pipeline
- Documentation and guides

**Next**: Run validation and report results

---

## Success Criteria

Your validation work is successful when:

✓ All 5 experiments run without errors
✓ 4+ experiments show predicted results
✓ Layer 0 shows causal impact (Experiment 1)
✓ Layers 20-31 show causal impact (Experiment 2)
✓ Minimal circuit preserves >70% (Experiment 3)
✓ Keywords matter (Experiments 4 & 5)
✓ All examples maintain >80% baseline accuracy

---

## Questions?

**Quick questions**: See VALIDATION_QUICK_START.md

**Detailed questions**: See VALIDATION_EXPERIMENTS_README.md

**Methodology questions**: See circuit_validation_guide.md

**Overview questions**: See 00_START_HERE.md

---

**Status**: Validation pipeline ready
**Created**: March 24, 2026
**Files**: 3 new files + 1 notebook
**Runtime**: 30-45 minutes to validate
