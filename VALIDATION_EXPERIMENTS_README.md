# Circuit Validation Experiments - README

## Overview

This notebook (`circuit_validation_experiments.ipynb`) contains **targeted experiments** designed to validate the three-stage PowerShell classification circuit that was identified in the main analysis.

**Purpose**: Move beyond observational evidence (attention, logit lens) to **causal validation** through ablation, minimization, and attribution studies.

---

## Experiments Overview

### Experiment 1: Ablate Layer 0 Heads
**Question**: Are Layer 0 heads really important for classification?

**Method**: Set identified important heads (0.11, 0.8, 0.23) to zero and measure classification change

**Expected Result**: Logit diff moves toward 0 (less confident in BLOCK)

**Validates**: Stage 1 (Early Detection) is causally important

---

### Experiment 2: Ablate Critical Layers (20, 25, 30)
**Question**: Are late layers really where the decision happens?

**Method**: Zero out MLPs in layers 20, 25, 30 and measure classification change

**Expected Result**: Large logit diff movement toward 0

**Validates**: Stage 3 (Decision Finalization) is causally critical

---

### Experiment 3: Minimal Circuit Test
**Question**: Can we recreate the behavior with just a subset of the circuit?

**Method**: Keep Layer 0 and layers 25-31 active, zero out layers 1-24

**Expected Result**: Preserves ~70-80% of the original behavior

**Validates**: Identified circuit components are sufficient for most behavior

---

### Experiment 4: Keyword Sensitivity
**Question**: How sensitive is the model to specific keywords?

**Method**: Replace malicious keywords (IEX, DownloadString, etc.) with innocuous alternatives

**Expected Result**: Malicious examples become less confident (logit diff → 0 or negative)

**Validates**: Model uses keyword detection (not just behavior analysis)

---

### Experiment 5: Token Attribution
**Question**: Which individual tokens drive the classification most?

**Method**: Mask each token and measure impact on logit diff

**Expected Result**: Keywords have highest attribution scores

**Validates**: Keywords are the primary signal, not context

---

## Running the Notebook

### Prerequisites
```bash
pip install transformer_lens transformers torch pandas numpy
```

### Setup
1. Open `circuit_validation_experiments.ipynb`
2. Run cells in order (they build on each other)
3. Watch for progress updates (some experiments take time)

### Expected Runtime
- Setup: ~2-3 min
- Baseline: ~2 min
- Experiment 1 (Head ablation): ~3 min
- Experiment 2 (Layer ablation): ~10-15 min (slower)
- Experiment 3 (Minimal circuit): ~10-15 min (slower)
- Experiment 4 (Keyword sensitivity): ~2 min
- Experiment 5 (Attribution): ~5 min

**Total**: ~30-45 minutes

---

## Dataset Used

The notebook expands the original dataset from 8 to 10 examples:

**Benign** (5 examples):
- List services
- Check disk space
- Read local log
- Ping host
- List processes

**Malicious** (5 examples):
- DownloadString + IEX
- Base64 + IEX
- WebRequest to temp
- EncodedCommand
- Invoke-Expression hidden

This allows better evaluation of circuit generalization across different examples.

---

## Key Results to Look For

### Experiment 1: Layer 0 Ablation
✓ **Expected**: Benign examples should be relatively unaffected (small LD change)
✓ **Expected**: Malicious examples should show reduced confidence (LD → 0)
✗ **Problem**: If no effect, Layer 0 heads might not be as important as thought

### Experiment 2: Critical Layer Ablation
✓ **Expected**: Both benign and malicious should show significant LD changes
✓ **Expected**: Ablating all three layers should show cumulative effect
✗ **Problem**: If small effect, layers might be redundant

### Experiment 3: Minimal Circuit
✓ **Expected**: Predictions should match original ~80-90% of the time
✓ **Expected**: LD change should be <50% of original magnitude
✗ **Problem**: If circuit doesn't preserve behavior, more components needed

### Experiment 4: Keyword Sensitivity
✓ **Expected**: Malicious examples become more "benign" (LD → 0/-3)
✓ **Expected**: Some should flip classification (BLOCK → ALLOW)
✗ **Problem**: If no change, model might not be keyword-based

### Experiment 5: Attribution
✓ **Expected**: Top tokens include IEX, DownloadString, WebClient, etc.
✓ **Expected**: Context words should have lower attribution
✗ **Problem**: If context words dominate, behavior-based detection active

---

## Output Files

The notebook generates CSV files in `./circuit_validation_results/`:

- `baseline_results.csv` - Classification on all 10 examples
- `exp1_layer0_ablation.csv` - Layer 0 head ablation results
- `exp2_layers_ablation.csv` - Layers 20,25,30 ablation results
- `exp3_minimal_circuit.csv` - Minimal circuit preservation metrics
- `exp4_keyword_sensitivity.csv` - Keyword replacement effects
- `exp5_token_attribution.csv` - Per-token attribution scores

### Analyzing Results

```python
import pandas as pd

# Check baseline accuracy
baseline = pd.read_csv("circuit_validation_results/baseline_results.csv")
accuracy = baseline["correct"].mean()
print(f"Baseline accuracy: {accuracy:.1%}")

# Check Layer 0 impact
exp1 = pd.read_csv("circuit_validation_results/exp1_layer0_ablation.csv")
mal_impact = exp1[exp1["label"] == 1]["ld_change"].mean()
print(f"Malicious LD change (Layer 0 ablation): {mal_impact:.4f}")

# Check minimal circuit preservation
exp3 = pd.read_csv("circuit_validation_results/exp3_minimal_circuit.csv")
preservation = exp3["behavior_preserved_%"].mean()
print(f"Behavior preserved by minimal circuit: {preservation:.1f}%")
```

---

## Troubleshooting

### Out of Memory
If you get OOM errors:
- Reduce batch size (though we already use single examples)
- Skip Experiment 2 (most memory-intensive)
- Use GPU if available

### Slow Experiments
- Experiments 2, 3 are slow because they use layer ablation (must re-run many forward passes)
- Expected: 10-15 min each
- Patience is the solution

### NaN Values
- May appear in attribution if tokens aren't well-defined
- Safe to ignore individual NaN entries
- Check means/medians instead

### Different Results Than Expected
- Model randomness: Set SEED for reproducibility
- Example sensitivity: Different examples may show different patterns
- Approximation error: Attribution is approximate, not exact

---

## Extending the Validation

### Test on More Examples
Modify the DATA dictionary to include more benign/malicious examples. The circuit should generalize to new examples.

### Test on Variant Keywords
Try other malicious patterns:
- `Invoke-RestMethod` (alternative to WebRequest)
- `$([wmiclass]...)` (obfuscation)
- `cmd.exe /c` (cmd invocation)

### Test Attention Pattern Correlation
Compare the attention patterns (from main analysis) with ablation results:
- Do heads with highest attention also show largest impact when ablated?
- Should have strong correlation if attention analysis was accurate

### Test on Different Models
Apply the same validation methodology to:
- Other Foundation models
- GPT-4
- Claude variants
- Smaller models (to see if circuit differs)

---

## Interpreting Circuit Validation

### Strong Validation ✅
All experiments confirm predictions:
- Layer 0 ablation shows clear impact
- Late layers are critical
- Minimal circuit preserves behavior
- Keywords drive classification
- Keywords are top tokens

→ **Conclusion**: Circuit is well-characterized and validated

### Partial Validation ⚠️
Some experiments confirm, others don't:
- If minimal circuit doesn't work: more layers needed
- If keywords don't matter: behavior-based detection also present
- If Layer 0 weak: pattern detection might happen elsewhere

→ **Conclusion**: Circuit is more complex than identified. Refine model.

### No Validation ❌
Experiments contradict predictions:
- Ablations show no effect: identified components might not matter
- Minimal circuit fails: circuit structure wrong
- Keywords irrelevant: completely different mechanism

→ **Conclusion**: Re-examine initial circuit identification

---

## Success Criteria

Your validation is successful if:

✓ At least 4 of 5 experiments show predicted results
✓ Layer 0 and layers 20-31 show causal impact
✓ Minimal circuit preserves >70% behavior
✓ Keywords show non-zero attribution
✓ All examples maintain >80% baseline accuracy

---

## Next Steps After Validation

### If Validation Succeeds
1. Document circuit in paper/report
2. Test on production data
3. Build applications using circuit knowledge
4. Compare with other models

### If Validation Partially Succeeds
1. Refine circuit identification
2. Include additional components
3. Re-test until all experiments pass

### If Validation Fails
1. Re-examine initial analysis
2. Test different layer combinations
3. Use different ablation methods (gradient-based, etc.)
4. Consider alternative circuit architectures

---

## References

See these files for context:
- `CIRCUIT_FINDINGS.md` - Initial circuit identification
- `circuit_validation_guide.md` - Methodology for circuit analysis
- `foundation_sec_mi_powershell_circuit_analysis.py` - Original analysis code

---

## Questions?

Refer to:
- **Methodology**: `circuit_validation_guide.md`
- **Findings**: `CIRCUIT_FINDINGS.md`
- **Original Analysis**: `foundation_sec_mi_powershell_circuit_analysis.py`
- **Overview**: `00_START_HERE.md`

---

**Status**: Ready to run
**Date**: March 24, 2026
**Estimated Runtime**: 30-45 minutes
