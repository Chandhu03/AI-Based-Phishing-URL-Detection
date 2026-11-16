# Model card: SecureMind Phase 3 URL-only phishing candidates

**Status: EXPERIMENTAL.** Experiments A and B below are not used by any
application. The Streamlit app still uses the unchanged synthetic-data demo
model. The website's in-browser engine uses a separate model trained by the
engine experiment; see "Engine model" at the end of this card.

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

## Engine model (shipped in the website)

Numbers from `reports/engine/metrics.json` (`python phase3/run.py engine`,
scikit-learn 1.8.0). Details and all tables: `reports/engine/ENGINE_REPORT.md`.

- **Model.** HOST view (hostname, one leading `www.` removed); hashed
  character 3–5-grams, 2^16 buckets; logistic regression, C = 1; int8
  coefficients; Platt calibration. Trained on the union of PhiUSIIL and
  Hannousse training domains (170,734 rows; 0 cross-dataset label
  conflicts, 44 cross-dataset duplicates collapsed).
- **Choices.** Size and C by validation PR-AUC, preferring the smallest
  size within 0.002 of the best (2^18 scored 0.9057, 2^16 0.9054). int8
  because it moved validation ROC-AUC by 0.0003. Calibration and the two
  thresholds (validation FPR ≤ 1% "high", ≤ 5% "elevated") on validation
  only.
- **Held-out test domains** (shipped weights; baselines thresholded on the
  same validation split):

| Test set | Model | ROC-AUC | PR-AUC | recall / FPR at high | recall / FPR at elevated |
|---|---|---|---|---|---|
| PhiUSIIL (35,816) | engine | 0.916 | 0.921 | 0.642 / 0.009 | 0.742 / 0.050 |
| PhiUSIIL | candidate A | 0.919 | 0.925 | 0.654 / 0.008 | 0.749 / 0.045 |
| PhiUSIIL | demo model | 0.848 | 0.840 | 0.132 / 0.000 | 0.626 / 0.017 |
| Hannousse (1,946) | engine | 0.850 | 0.899 | 0.538 / 0.036 | 0.666 / 0.112 |
| Hannousse | candidate A | 0.832 | 0.881 | 0.525 / 0.049 | 0.651 / 0.102 |
| Hannousse | demo model | 0.780 | 0.823 | 0.575 / 0.183 | 0.859 / 0.516 |

- **What this supports.** Training on both datasets trades a small loss on
  PhiUSIIL (ROC-AUC −0.003) for a gain on Hannousse (+0.018) and a lower
  FPR at the high threshold there. The validation split is about 95%
  PhiUSIIL, so thresholds are tuned to PhiUSIIL: on Hannousse the "high"
  threshold gives 3.6% FPR, not 1%. Expect more false positives on varied
  real-world legitimate hosts.
- **Counted once per site** (`reports/engine/site_metrics.json`,
  `python phase3/run.py engine-sites`, which `engine` also runs; same
  shipped scores and thresholds). The table above counts URLs, and every URL
  on one host gets the same score; one Hannousse domain is 18% of its test
  URLs.

| Test set | Counted | items | ROC-AUC | recall / FPR at high |
|---|---|---|---|---|
| PhiUSIIL | per URL | 35,816 | 0.916 | 0.642 / 0.009 |
| PhiUSIIL | per host | 31,968 | 0.899 | 0.576 / 0.009 |
| PhiUSIIL | per domain | 29,537 | 0.887 | 0.551 / 0.009 |
| Hannousse | per URL | 1,946 | 0.850 | 0.538 / 0.036 |
| Hannousse | per host | 1,208 | 0.758 | 0.315 / 0.037 |
| Hannousse | per domain | 1,067 | 0.757 | 0.282 / 0.033 |

- **Identity.** Model id `url-host-ea3f55ce1c18faa2`: `url-host-` plus the
  first 16 hex digits of the SHA-256 of every field that decides a score
  (format, view, n-gram settings, coefficients, intercept, calibration,
  thresholds), in a canonical form shared by `engine.py` and `model.js`.
  Same id, same scores; any change gives a new id. The browser, the CLI and
  `engine-sites` refuse an artifact whose content does not match its id. The
  artifact was first published as `url-host-20261113`; only the id changed
  (weights, thresholds and every metric are unchanged).
- **Input scope.** Only host names that pass IDNA2008 are scored, as in
  training (the Python pipeline drops the rest). Browsers accept more (emoji,
  symbols, mixed-direction labels); for those the website reports
  "Characters outside the domain name standard" and does not use the model.
  On 8,660 fuzzed Unicode hosts the browser and Python now agree on 8,656
  (previously 6,093); the 4 left are characters a browser maps to `_`. IP
  addresses are not scored either.
- **Model-only false positives investigated.** On popular legitimate hosts
  the model alone pushed `shopify.com`, `protonmail.com`, `cash.app` and some
  country storefronts (`amazon.com.mx`, `google.co.in`) to Suspicious or
  Inconclusive. The fix is in the brand reference list, not the model: these
  brands and country domains are now listed, so their own sites are
  recognised and the model is set aside, while look-alikes such as
  `cashapp-support.xyz` remain High risk. `ipfs.io` and `*.myshopify.com`
  still score high: anyone can publish there and phishing is common, so they
  are labelled as shared hosting instead. These are spot checks, not a
  measured false-positive rate.
- **Transfer** (same configuration, trained on one dataset only): PhiUSIIL
  → Hannousse ROC-AUC 0.838; Hannousse → PhiUSIIL 0.802.
- **Use.** One input to an explainable, rule-based assessment in the
  browser. It sees only the hostname, and a low score is not evidence of
  safety.
