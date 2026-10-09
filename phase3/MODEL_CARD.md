# Model card: SecureMind Phase 3 URL-only phishing candidates

**Status: EXPERIMENTAL. Not used by the application.**

The live app still uses the unchanged synthetic-data demo model.

Every number below is copied from `reports/metrics.json`, which
`python phase3/run.py evaluate` generated on 2026-10-09 with Python 3.12.10
and scikit-learn 1.8.0. Bracketed ranges are 95% bootstrap intervals that
resample whole domains.

## Models

| Artifact (in `artifacts/`, gitignored) | Experiment | Input | Model |
|---|---|---|---|
| `A_host_phiusiil__logreg_charngram` | A, the primary candidate | Hostname with a leading `www.` removed | Hashed character 3–5-grams (2^18 buckets) with logistic regression, C = 4 |
| `B_full_hannousse__logreg_charngram` | B | The URL without its scheme | Same family, C = 16 |

**How the model was chosen.** Three families were compared on validation
PR-AUC only:
- lexical logistic regression (the baseline)
- histogram gradient boosting
- character n-gram logistic regression

Character n-grams won in both experiments. The decision thresholds were also
chosen on validation data.

**Format.** Each artifact is JSON metadata plus a `.npz` file of
coefficients, loaded with `allow_pickle=False`. No code runs when an
artifact is loaded. Before writing an artifact, the pipeline reloads it and
checks that it reproduces scikit-learn's probabilities. The largest
difference was 2.2×10⁻¹⁶ on every test row.

## Intended use

**Intended:**
- Research and benchmarking of URL-string phishing signals.
- A starting point for a future, separately approved app integration.

**Out of scope:**
- Blocking, allow-listing or any automated security decision.
- Any claim that a URL is "safe".

The model sees only URL text. It never visits, resolves or looks up a site.

## Data

The datasets are covered in detail in `DATASET_REVIEW.md`.

| Dataset | Licence | Size after cleaning | Collected |
|---|---|---|---|
| PhiUSIIL (UCI #967) | CC BY 4.0 | 235,349 URLs | Unknown (donated in 2024) |
| Hannousse & Yahiouche (Mendeley, v3) | CC BY 4.0 | 11,424 URLs | May 2020 |

**PhiUSIIL shortcut.** Every legitimate PhiUSIIL URL is a bare
`https://www.<domain>` homepage. A rule with no machine learning
("legitimate iff https AND `www.` AND no path") scores **F1 0.996** on
PhiUSIIL's held-out domains. The same rule scores only 0.754 on Hannousse.
Experiment A therefore uses only the hostname, without `www.`.

**Splits.**
- 70/15/15 by registrable domain, using the Public Suffix List.
- No domain appears in more than one split.
- External test sets exclude every domain seen in training or validation.

## Results

### Experiment A: hostname model trained on PhiUSIIL

| Test set | Model | ROC-AUC | PR-AUC | Recall at the "FPR ≤ 1%" validation threshold | Realised test FPR |
|---|---|---|---|---|---|
| PhiUSIIL held-out domains (35,816 URLs, 29,522 domains) | **Candidate** | 0.919 [0.902–0.935] | 0.925 [0.897–0.949] | 0.662 [0.593–0.725] | 0.92% |
| | Lexical baseline | 0.781 | 0.827 | 0.469 | 1.11% |
| | Current app model | 0.848 | 0.840 | 0.530 | 0.72% |
| **Hannousse, external** (9,625 URLs, a different dataset and year) | **Candidate** | 0.741 [0.711–0.772] | 0.769 [0.716–0.822] | 0.356 | **6.2%** |
| | Lexical baseline | 0.664 | 0.734 | 0.384 | 10.7% |
| | Current app model | 0.717 [0.682–0.751] | 0.700 | 0.724 | 41.4% |

The current app model's behaviour at its own default threshold of 0.5:

| Test set | Recall | FPR |
|---|---|---|
| PhiUSIIL held-out domains | 0.106 | 0.01% |
| Hannousse, external | 0.382 | 13.4% |

### Experiment B: full-URL model trained on Hannousse

| Test set | Model | ROC-AUC | PR-AUC | Recall at the "FPR ≤ 1%" validation threshold | Realised test FPR |
|---|---|---|---|---|---|
| Hannousse held-out domains (1,969 URLs, 1,072 domains) | **Candidate** | 0.967 [0.940–0.985] | 0.977 [0.940–0.994] | 0.760 [0.625–0.855] | 1.17% |
| | Lexical baseline | 0.941 | 0.957 | 0.574 | 1.17% |
| | Current app model | 0.776 [0.651–0.858] | 0.822 | 0.000 (see failure modes) | 0% |

On the same Hannousse test set, the current app model at its default
threshold of 0.5 has recall 0.532 at 15.1% FPR.

## What the evidence supports

- **In-distribution ranking is clearly better.** On held-out domains of
  their training dataset, both candidates rank URLs better than the current
  app model, and the confidence intervals don't overlap: PhiUSIIL ROC-AUC
  0.919 against 0.848, and Hannousse 0.967 against 0.776.
- **Generalising to a different dataset is weak.** On external Hannousse,
  candidate A reaches ROC-AUC 0.741 against the app model's 0.717, and those
  intervals overlap. The threshold tuned for 1% FPR on validation gives
  **6.2%** FPR on the new distribution. A threshold chosen on one dataset
  does not carry over.
- **No production claim is justified.** Neither candidate is ready for a
  security decision.

## Limitations and failure modes

- **Distribution shift.** Experiment A's legitimate data is popular
  homepages, so real legitimate long-tail sites look unfamiliar to it. The
  external result shows this.
- **Results driven by a few domains.**
  - `ipfs.io` has 1,550 rows in the PhiUSIIL test set.
  - In Hannousse, `duilawyeryork.com` alone is 18% of the test set.
  - The intervals are wide for this reason, and per-domain weighting is not
    yet applied.
- **Small Hannousse test set.** About 2,000 URLs means Experiment B's
  numbers carry wide intervals. FPR ≤ 0.1% cannot be estimated reliably and
  is not reported.
- **Unpinned grid edge.** Experiment B selected C = 16, the edge of its
  grid, so a larger value might do better. That is unexplored.
- **Unusable thresholds for the current app model.** It gives a vote share
  of 1.0 to more than 1% of legitimate Hannousse validation URLs, so no
  threshold reaches 1% FPR. Its recall at that operating point is 0.
- **No time-based evaluation.** Neither dataset has timestamps, so drift
  over time is unmeasured. The data dates from 2020 to 2024 and phishing
  infrastructure changes quickly.
- **Evasion.** The model is purely lexical and character-based. It can be
  evaded with clean-looking hostnames, such as compromised legitimate
  domains or hosting on reputable platforms, and with homoglyphs the n-grams
  have not seen.
- **Label noise.** The publishers do not document where their URLs came
  from. Some "phishing" URLs may be dead or reused domains.

## Reproduce

```powershell
.\.venv\Scripts\python.exe phase3/run.py download
.\.venv\Scripts\python.exe phase3/run.py all
```

Inputs are pinned by SHA-256, splits are hash-based and seeds are fixed.
Re-running on the same platform reproduced identical metrics; see the Phase
3 report for evidence.
