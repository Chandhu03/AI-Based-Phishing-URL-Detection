# Phishing URL Detection — ECE 569A AI Project


---

## What is this project?
A program that looks at a website link (URL) and predicts:
**"Is this link trying to scam someone, or is it safe?"**

---

## Repository layout

| Path | What it is |
|------|------------|
| `app.py`, `securemind/` | The Streamlit demo app and its URL validation, features and demo model |
| `tests/` | App, security, model-parity and lock-file tests |
| `phase3/` | Reproducible evaluation pipeline, reports and model card (see `phase3/README.md`) |
| `website/` | The SecureMind Labs static website (see `website/README.md` and `website/DEPLOYMENT.md`) |
| `step*.py`, `dataset/`, `results/` | The original course-project pipeline and its artifacts |

---

## How to run 

```bash
# Step 0: Generate a practice dataset (replace with Kaggle data later)
python step0_generate_dataset.py

# Step 1: Turn URLs into numbers (feature extraction)
python step1_extract_features.py

# Step 2: Train 4 AI models and compare them
python step2_train_models.py

# Step 3: Create all charts for the report
python step3_visualize.py

# Step 4: Live demo — type any URL and get a prediction
python step4_demo.py
```

---

## Requirements and local setup

**Supported Python: 3.12** (64-bit), on Windows and Linux. CI tests both.

### Dependency files

| File | Role | Edited by |
|------|------|-----------|
| `requirements.txt` | Direct runtime dependencies (app + research scripts), exact pins | Hand |
| `requirements-dev.txt` | Direct test, audit and lock tools, exact pins | Hand |
| `requirements-lock.txt` | **Runtime install set:** every package, pinned, with SHA-256 hashes | Generated |
| `requirements-dev-lock.txt` | **Development/CI install set:** runtime lock + tools, with hashes | Generated |

The two hand-edited files are the source of truth; the two locks are
generated from them with [uv](https://docs.astral.sh/uv/) and must never be
edited by hand. The runtime lock is what a deployment installs; the dev lock
is a strict superset (identical runtime entries, enforced by
`tests/test_lockfiles.py`) that adds the tools.

The locks are **universal**: one file serves Windows, macOS and Linux.
Platform-specific packages carry environment markers. For example,
`nvidia-nccl-cu12` installs only on Linux because `xgboost` requires it
there. Each entry lists the SHA-256 of every distribution file PyPI publishes
for that version. `pip --require-hashes` rejects any file whose hash is not
listed, and `--no-deps` stops it installing anything that is not in the lock.

### Install

Windows (PowerShell):

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes --only-binary=:all: --no-deps -r requirements-dev-lock.txt
.\.venv\Scripts\python.exe -m pip check
```

Linux / macOS:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: --no-deps -r requirements-dev-lock.txt
.venv/bin/python -m pip check
```

For a runtime-only environment (for example a deployment), use
`requirements-lock.txt` instead of `requirements-dev-lock.txt`.

### Run the web app locally

Start it from the repository root so the hardened settings in
`.streamlit/config.toml` are applied:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

The app opens at http://localhost:8501.

### Run the CI checks locally

These are the checks `.github/workflows/ci.yml` runs, after installing the
dev lock as shown above.

Windows (PowerShell 5.1 or 7):

```powershell
$py = ".\.venv\Scripts\python.exe"
& $py -m compileall -q -f -x '[\\/]\.(venv|git)[\\/]' .
& $py -m pytest -q -p no:cacheprovider
& $py -m pip_audit --progress-spinner off --require-hashes --disable-pip -r requirements-lock.txt
& $py -m pip_audit --progress-spinner off
& $py -m bandit -q -ll -r app.py securemind
```

Linux / macOS (bash):

```bash
py=.venv/bin/python
"$py" -m compileall -q -f -x '[\\/]\.(venv|git)[\\/]' .
"$py" -m pytest -q -p no:cacheprovider
"$py" -m pip_audit --progress-spinner off --require-hashes --disable-pip -r requirements-lock.txt
"$py" -m pip_audit --progress-spinner off
"$py" -m bandit -q -ll -r app.py securemind
```

pip-audit prints its summary on stderr. In Windows PowerShell 5.1, redirecting
it (`2>&1`) shows a harmless red `NativeCommandError` banner; judge the result
by the exit code.

| Check | What it proves |
|-------|----------------|
| `pip install --require-hashes ...` then `pip check` | Every installed file matches a locked hash, and the dependency set is complete |
| `compileall` | Every `.py` file in the repository compiles |
| `pytest` | Unit, app-level security, model-parity and lock-integrity tests pass |
| `pip_audit -r requirements-lock.txt` | No known advisories for the runtime set as the **current platform** would install it. CI runs this on Linux |
| `pip_audit` (no arguments) | No known advisories for everything installed in the environment, tools included. CI runs this on Linux and Windows |
| `bandit -ll` | No medium- or high-severity static-analysis findings in app code. The research `step*` scripts are not scanned |

CI also runs:
- **Secret scanning** with gitleaks over every commit (see below).
- **Workflow linting** with [actionlint](https://github.com/rhysd/actionlint)
  v1.7.12. On the runner it also runs shellcheck on the workflow scripts.
- A **lock freshness check**. It regenerates both locks with the documented
  commands and fails if they differ from the committed files.

CI downloads gitleaks and actionlint from their official GitHub releases. It
refuses to run either tool unless its SHA-256 matches the value pinned in the
workflow.

**Interpreting results.** A pip-audit finding names a package, an advisory
ID and the fixed version. Check the fix is compatible, update the pin in
`requirements*.txt`, regenerate the locks and re-run every check. Do not
ignore advisories without a documented justification. A clean audit only
means *no known advisories in dependencies*. It does not mean the
application is secure.

### Secret scanning

Secret scanning uses [gitleaks](https://github.com/gitleaks/gitleaks)
v8.30.1. Before running it:
1. Download the release archive for your platform.
2. Verify it against `gitleaks_8.30.1_checksums.txt` from the same release.

Then run:

```powershell
gitleaks git --no-banner --no-color --redact --verbose .
```

**What each mode covers:**
- **`gitleaks git`** scans every commit. It does **not** see uncommitted or
  untracked files.
- **`gitleaks dir --no-banner --redact <copy>`** scans those as well. Run it
  on a copy of the working tree without `.venv/`. Create the copy from
  `git ls-files -co --exclude-standard`.

**How to judge a scan:**
- Gitleaks exits with status 1 when it finds a leak, and `--redact` keeps
  secret values out of the output.
- Gitleaks also exits **0** when git fails or no commits are visible (for
  example in a shallow clone). Always check that the log says `N commits
  scanned` with N equal to `git rev-list --all --count`, and that it contains
  no `ERR` lines. CI enforces both checks, and also fails on a shallow
  checkout.
- Gitleaks ignores low-entropy strings, so a scan that finds nothing is
  evidence, not proof.

**Handling findings:**
- Treat every finding as real until it is checked.
- Never paste a finding's value anywhere.
- Rotate a confirmed credential with its issuer.
- Do not rewrite git history without agreement.

### Updating dependencies

1. Edit `requirements.txt` and/or `requirements-dev.txt`.
2. Regenerate both locks, in this order, from the repository root. Use a
   cutoff at or after the current UTC time. It must be the same in both
   commands.

   Windows (PowerShell):

   ```powershell
   $py = ".\.venv\Scripts\python.exe"
   $env:UV_NO_CONFIG = "1"
   $cutoff = "2026-10-09T00:00:00Z"   # update when changing dependencies
   & $py -m uv pip compile requirements.txt --universal --python-version 3.12 --only-binary :all: --generate-hashes --exclude-newer $cutoff -o requirements-lock.txt
   & $py -m uv pip compile requirements.txt requirements-dev.txt -c requirements-lock.txt --universal --python-version 3.12 --only-binary :all: --generate-hashes --exclude-newer $cutoff -o requirements-dev-lock.txt
   ```

   Linux / macOS:

   ```bash
   py=.venv/bin/python
   export UV_NO_CONFIG=1
   cutoff=2026-10-09T00:00:00Z   # update when changing dependencies
   "$py" -m uv pip compile requirements.txt --universal --python-version 3.12 --only-binary :all: --generate-hashes --exclude-newer "$cutoff" -o requirements-lock.txt
   "$py" -m uv pip compile requirements.txt requirements-dev.txt -c requirements-lock.txt --universal --python-version 3.12 --only-binary :all: --generate-hashes --exclude-newer "$cutoff" -o requirements-dev-lock.txt
   ```

   Notes:
   - uv keeps existing pins where they are still valid. To move a specific
     pin, add `--upgrade-package <name>`.
   - The cutoff makes regeneration deterministic. Files that PyPI publishes
     later cannot change the lock, so CI's freshness check stays stable.
   - `UV_NO_CONFIG=1` ignores any personal uv configuration, such as an
     alternative package index.
   - Hashes come from PyPI, the default and only index used. `pip` verifies
     them against the real files at install time.
3. Re-run every check above, and review the lock diff before committing.

### Known limitations

- **xgboost on Linux** pulls in the large `nvidia-nccl-cu12` CUDA library.
  The app itself does not import xgboost, which is used only by the research
  scripts. Splitting it out of the runtime set is a future option.
- **Hash scope.** The locks list hashes for every published file, but only
  Windows x86_64 and Linux x86_64 are exercised (locally and in CI). macOS
  and ARM are untested.
- **Hashes and binary wheels.** The locks also hash source distributions.
  Every documented install uses `--only-binary=:all:`, so no package build
  code ever runs.
- **What the offline lock tests cannot catch.** `tests/test_lockfiles.py`
  cannot tell a fabricated hash from a real one. Fabricated hashes are
  caught by CI's freshness check and by pip's hash check at install time.
- **What the lock check guarantees.** It ensures the same *dependency
  resolution and installed files*. It is not a reproducible *build* of the
  application.

> **Note:** `step0_generate_dataset.py` overwrites `dataset/urls.csv`, and the
> `step2_*` scripts overwrite the files in `results/`. Back up those files
> before re-running the pipeline.

---

## Project structure
```
phishing_project/
├── step0_generate_dataset.py    ← Creates practice data
├── step1_extract_features.py    ← Turns URLs into numbers
├── step2_train_models.py        ← Trains 4 ML models
├── step3_visualize.py           ← Makes all charts
├── step4_demo.py                ← Live demo for presentation
├── dataset/
│   ├── urls.csv                 ← Raw URLs with labels
│   └── features.csv             ← URLs converted to numbers
├── results/
│   ├── metrics.json             ← Model scores
│   ├── roc_data.json            ← ROC curve data
│   ├── feature_importance.json  ← Which features matter
│   ├── best_model.pkl           ← Saved trained model
│   ├── scaler.pkl               ← Saved scaler
│   ├── model_comparison.png     ← Chart for report
│   ├── confusion_matrices.png   ← Chart for report
│   ├── roc_curves.png           ← Chart for report
│   ├── feature_importance.png   ← Chart for report
│   └── summary_table.png        ← Table for report
└── README.md                    ← This file
```

---

## IMPORTANT: Using a real Kaggle dataset
The synthetic dataset gives perfect (100%) accuracy because the
patterns are too obvious.

---

## What each team member should do

| Member | Responsibility | Files |
|--------|---------------|-------|
|Chandhu Allam | Dataset + Feature Extraction | step0, step1 |
| Member 2 | Model Training + Tuning | step2 |
| Member 3 | Visualization + Report + Demo | step3, step4 |

---
