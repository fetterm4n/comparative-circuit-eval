# Full-corpus classification evaluation

The historical 74-pair cohort has 148 rows but only 62 unique scripts. It was
selected for mechanistic interventions, including length safety and baseline
correctness. Its accuracy difference is not a full-corpus benchmark.

Evaluate every nonempty script in the original `ps_test_data.csv`. Do not use a
matched-pair manifest or a baseline-correct filter. Exact duplicate contents count
once; conflicting labels fail preparation. Keep the original corpus separate
from augmented or generated scripts. Record source hashes and actual model commits.

```sh
python3 full_corpus_eval.py prepare --csv /path/to/ps_test_data.csv
python3 full_corpus_eval.py run --device cuda
python3 full_corpus_eval.py report
```

Inference requires PyTorch, Transformers, and access to both Hugging Face models
(including the gated Llama model). Models load serially. No TransformerLens or
activation caching is required. Predictions checkpoint after every script; rerun
the same command to resume. A crash leaving a partial JSON line requires repairing
that final line before resuming. Changed inputs/settings require a fresh output
directory. GPU errors fail visibly rather than silently dropping samples.

Both models receive each of the same three established prompts (`raw`,
`adversarial`, `full`) through their native system/user chat template. Primary
comparisons are within the same prompt condition. Report all conditions; do not
select the best prompt after observing corpus results. This separates prompt
sensitivity from a model advantage. The historical cross-prompt 4.7-point result
is a separate operating-condition comparison.

The scorer preserves the repository's historical metric: the next-token logit
of the first token of ` BLOCK` minus the first token of ` ALLOW`, with BLOCK
chosen when the difference is positive. This is constrained label scoring, not
free-form generated-answer accuracy or full multi-token label likelihood.

The default 12,000-character cap reproduces historical preprocessing. An explicit
8,192-token budget further bounds inference cost, preserving the prompt and answer
suffix while trimming only script text. Every truncation is recorded. Results on
long scripts therefore describe the observed prefix, not the entire script.
After the primary run, repeat with `--max-chars 0 --max-tokens 16384` in a fresh
output directory to measure sensitivity to truncation, subject to GPU capacity.
Prepare that new directory from the same source CSV first.

The report includes confusion counts, accuracy, balanced accuracy, malicious
precision/recall/F1, benign false-positive rate, length slices, truncation slices,
and overlapping case-insensitive indicator substring slices. Only complete
paired runs produce model comparisons: accuracy differences, deterministic
paired bootstrap intervals, and exact McNemar tests. Exact-content deduplication
does not remove near-duplicate family dependence; intervals describe this corpus
under a script-level resampling assumption. This is a broad corpus evaluation,
not evidence that the corpus was absent from either model's training data.

Current local prerequisites: the original corpus is absent from this checkout;
the nearby `expanded-ps-validation/artifacts/ps_test_data_fa2y_augmented.csv` has
600 augmented rows and is a distinct dataset. The default local Python lacks
PyTorch. Supply the original corpus location and the GPU runtime to execute the
full benchmark.
