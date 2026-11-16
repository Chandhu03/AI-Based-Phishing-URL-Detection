# Phase 3: reproducible phishing-URL detector (research)

An experimental pipeline that trains and honestly evaluates URL-only
phishing detectors on real, licence-checked datasets. It does **not** change
the live app or its demo model. Everything it produces is an experimental
candidate.

| Document | Contents |
|---|---|
| `DATASET_REVIEW.md` | Sources, licences, integrity, and the PhiUSIIL shortcut |
| `MODEL_CARD.md` | Intended use, results, limitations, failure modes |
| `reports/EVALUATION_REPORT.md` | Generated results report |
| `reports/metrics.json`, `reports/data_stats.json` | Machine-readable results |

## Setup

No extra dependencies: the pipeline uses only packages already in the
project's hash-locked environment. Install it as described in the
top-level README:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: --no-deps -r requirements-dev-lock.txt
```

`phase3/requirements.txt` documents that no additional packages are
required.

## Run (from the repository root)

```powershell
$py = ".\.venv\Scripts\python.exe"
& $py phase3/run.py download      # ~19 MB, SHA-256 verified, into phase3/data/raw/
& $py phase3/run.py verify-psl    # Public Suffix List vs. official test vectors
& $py phase3/run.py prepare       # clean + split -> phase3/data/work/, reports/data_stats.json
& $py phase3/run.py evaluate      # train/select/evaluate -> reports/, artifacts/
& $py phase3/run.py engine        # browser model -> reports/engine/, website/src/engine/models/
& $py -m pytest -q -p no:cacheprovider phase3/tests
```

On Linux, use `.venv/bin/python` instead of `$py`.

- **Run time.** `evaluate` takes several minutes on a laptop CPU. Pass
  `--bootstrap 0` to skip the confidence intervals.
- **Outputs.** `phase3/data/` and `phase3/artifacts/` are gitignored.
  `phase3/reports/` is small and meant to be reviewed.

## Pipeline

| Step | Module | What it guarantees |
|------|--------|--------------------|
| Download | `download.py`, `sources.py` | HTTPS only, size-capped, SHA-256 pinned. Never runs on import. URLs *inside* the data are never fetched |
| Load and validate schema | `datasets.py` | Exact columns and label values, otherwise the run fails. One label convention: `is_phishing` (1 = phishing) |
| Canonicalise | `canonical.py` | Uses the app's own `securemind.url_validation`, unchanged. Keeps userinfo, port, IDN and IP signals |
| Clean | `cleaning.py` | Counts rejected rows, duplicates and conflicting-label URLs |
| Group | `psl.py` | Registrable domain from the pinned Public Suffix List. Passes all official vectors |
| Split | `splits.py` | 70/15/15 by salted hash of the domain. Deterministic, and no domain appears in two splits |
| Features | `features.py` | HOST view (immune to scheme, `www.` and path) and FULL view. All lexical, with no network |
| Models | `models.py` | Baseline logistic regression; candidates are gradient boosting and character n-gram logistic regression |
| Select and evaluate | `experiment.py`, `metrics.py` | Choice of model and threshold uses validation only. Test sets are scored once. CIs come from a bootstrap that resamples whole domains |
| Reference | `reference.py` | The current demo model, scored exactly as the app scores it |
| Artifacts | `serialize.py` | JSON plus `.npz` loaded with `allow_pickle=False`. The saved model must reproduce scikit-learn's predictions exactly |

## Tests

`phase3/tests` covers:
- preprocessing, labels and schema errors
- duplicate and conflict handling
- deterministic, leak-free splits
- feature-view invariance
- metrics and threshold guarantees
- artifact round-trips and tamper detection
- import-time side effects
- reference-model equivalence

The tests use synthetic in-memory fixtures. These are **not** evaluation
results. The official PSL vector test runs only after `download`.

## Engine experiment (the model the website ships)

`python phase3/run.py engine` (module `engine.py`, after `prepare`) trains
the HOST-view character 3–5-gram logistic regression on the union of both
datasets' training domains, selects size and C on validation, quantises the
coefficients, fits Platt scaling and two operating thresholds (validation
FPR ≤ 1% and ≤ 5%) on validation, and scores each test set once.

It writes:
- `reports/engine/metrics.json` and `reports/engine/ENGINE_REPORT.md`
- `website/src/engine/models/url-host-model.js`, a generated ES module with
  the int8 coefficients (base64) and metadata
- `website/src/engine/models/url-host-model.golden.json`, vectors for the
  JavaScript scorer's parity test

The export refuses to write anything unless an independent pure-Python
scorer reproduces scikit-learn's logits to 1e-9. `tests/test_engine.py`
covers hashing parity, quantisation bounds, calibration, validation-only
threshold selection and the parity refusal.

## Dependency bloat: measured, proposed, not applied

I measured the Linux x86_64 CPython 3.12 wheels in the dev lock:

| Package | Size |
|---|---|
| `nvidia-nccl-cu12` (pulled in only by `xgboost` on Linux) | 335 MB |
| `xgboost` | 126 MB |
| **Together** | **461 MB, about 71% of the 649 MB wheel set** |

- **Who uses xgboost.** The app does not import it. Only
  `step2_train_models*.py` and `step4_demo.py` use it, and Phase 3 does not
  need it at all.
- **What I tested.** In a scratch copy, I removed `xgboost==3.2.0` from
  `requirements.txt` and regenerated the runtime lock with the documented
  command and cutoff. Exactly two packages left the lock, `xgboost` and
  `nvidia-nccl-cu12`, and no other pin changed.
- **Proposed change** (reversible, but it touches Phase 2 files, so it has
  not been applied):
  1. Move `xgboost` to a new `requirements-research.txt` with its own
     hashed lock.
  2. Regenerate `requirements-lock.txt` and `requirements-dev-lock.txt`.
  3. Replace the `nvidia-nccl-cu12` assertion in `tests/test_lockfiles.py`
     with an assertion that the runtime lock contains neither package.
  4. Add the research lock to CI's lock-freshness check.

## Safety notes

- **No pickles.** The pipeline never loads a pickle. The repository's legacy
  `results/*.pkl` files are not touched.
- **No network contact with the data.** Dataset URLs are handled as text
  and never requested.
- **The Streamlit app is not part of Phase 3.** Phase 3 does not change the
  legacy app's demo model; the app's limitation text quotes the Phase 3
  measurement of that model. Phase 3 tests run in CI. The website's
  in-browser engine uses the model exported by `engine`; `engine-sites`
  re-scores the test sets with that exported file and writes per-host and
  per-domain metrics to `reports/engine/site_metrics.json`.
