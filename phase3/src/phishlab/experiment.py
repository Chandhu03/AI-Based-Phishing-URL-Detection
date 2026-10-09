"""Train, select (validation only) and evaluate (held-out domains) models.

Experiments
-----------
A. host_phiusiil  - HOST view, trained on PhiUSIIL train domains.
   Test: PhiUSIIL held-out test domains, plus EXTERNAL Hannousse rows whose
   domains never appear in PhiUSIIL train/val.
B. full_hannousse - FULL view, trained on Hannousse train domains.
   Test: Hannousse held-out test domains, plus EXTERNAL PhiUSIIL test rows
   whose domains never appear in Hannousse train/val.

The reference demo model is scored on every test set with the same metrics.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance

from securemind.url_validation import validate_url

from . import features as F
from .metrics import (binary_metrics, grouped_bootstrap_ci, ranking_metrics,
                      threshold_for_fpr, threshold_max_f1)
from .models import BASELINE, FAMILIES, SEED
from .reference import ReferenceModel

LOW_FPR = 0.01


@dataclass
class Prepared:
    df: pd.DataFrame
    normalized: list
    host_rows: list
    full_rows: list


def prepare_rows(df: pd.DataFrame) -> Prepared:
    normalized = [validate_url(u) for u in df["url"]]  # canonical URLs re-validate identically
    host_rows = [F.host_features(n, g) for n, g in zip(normalized, df["group"])]
    full_rows = [F.full_features(n, g) for n, g in zip(normalized, df["group"])]
    return Prepared(df.reset_index(drop=True), normalized, host_rows, full_rows)


def _inputs(p: Prepared, idx: np.ndarray, view: str, kind: str):
    if kind == "lexical":
        rows = p.host_rows if view == "host" else p.full_rows
        names = F.HOST_FEATURES if view == "host" else F.FULL_FEATURES
        return F.matrix([rows[i] for i in idx], names)
    text = F.host_text if view == "host" else F.full_text
    return [text(p.normalized[i]) for i in idx]


def _score(model, X) -> np.ndarray:
    proba = model.predict_proba(X)
    return proba[:, list(model.classes_).index(1)]


def _evaluate(y, score, groups, thresholds: dict, n_boot: int) -> dict:
    out = {"n": int(len(y)), "positives": int(y.sum()), "negatives": int(len(y) - y.sum()),
           "domains": int(len(np.unique(groups)))}
    out.update(ranking_metrics(y, score))
    for name, t in thresholds.items():
        out[f"at_{name}"] = binary_metrics(y, score, t)
    if n_boot and len(np.unique(y)) == 2:
        out["ci95_at_val_fpr_1pct"] = grouped_bootstrap_ci(y, score, groups, thresholds["val_fpr_1pct"],
                                                         n_boot=n_boot, seed=SEED)
    return out


def run_experiment(name: str, view: str, train_p: Prepared, test_sets: dict[str, tuple[Prepared, np.ndarray]],
                   reference: ReferenceModel, n_boot: int, log) -> tuple[dict, dict]:
    d = train_p.df
    tr = np.flatnonzero(d["split"].to_numpy() == "train")
    va = np.flatnonzero(d["split"].to_numpy() == "val")
    y_tr = d["is_phishing"].to_numpy()[tr]
    y_va = d["is_phishing"].to_numpy()[va]
    result: dict = {"view": view, "selection": {}, "models": {}}
    fitted = {}

    # ---- model selection on validation (test data untouched here) ----
    for fam in FAMILIES:
        X_tr, X_va = _inputs(train_p, tr, view, fam.input), _inputs(train_p, va, view, fam.input)
        trials = []
        for params in fam.grid:
            t0 = time.time()
            model = fam.build(params).fit(X_tr, y_tr)
            s_va = _score(model, X_va)
            r = ranking_metrics(y_va, s_va)
            trials.append({"params": params, "val_pr_auc": r["pr_auc"], "val_roc_auc": r["roc_auc"],
                           "fit_seconds": round(time.time() - t0, 1)})
            log(f"  [{name}] {fam.name} {params} val PR-AUC={r['pr_auc']:.4f}")
            if r["pr_auc"] == max(t["val_pr_auc"] for t in trials):
                fitted[fam.name] = (model, params, s_va)
        result["selection"][fam.name] = trials

    # ---- reference model: same validation set for its thresholds ----
    s_va_ref = reference.score([train_p.normalized[i] for i in va])
    fitted[reference.name] = (reference, {}, s_va_ref)

    best_family = max((f.name for f in FAMILIES), key=lambda k: max(t["val_pr_auc"] for t in result["selection"][k]))
    result["selected_candidate"] = best_family
    result["baseline"] = BASELINE

    # ---- final evaluation on held-out sets (once, after selection) ----
    for model_name, (model, params, s_va) in fitted.items():
        thresholds = {"val_max_f1": threshold_max_f1(y_va, s_va),
                      "val_fpr_1pct": threshold_for_fpr(y_va, s_va, LOW_FPR)}
        if model_name == reference.name:
            thresholds["app_default_0.5"] = 0.5
        entry = {"params": params, "validation": _evaluate(y_va, s_va, d["group"].to_numpy()[va], thresholds, 0),
                 "thresholds": thresholds, "test": {}}
        boot = n_boot if model_name in (best_family, BASELINE, reference.name) else 0
        for set_name, (p, idx) in test_sets.items():
            y = p.df["is_phishing"].to_numpy()[idx]
            if model_name == reference.name:
                s = reference.score([p.normalized[i] for i in idx])
            else:
                fam = next(f for f in FAMILIES if f.name == model_name)
                s = _score(model, _inputs(p, idx, view, fam.input))
            entry["test"][set_name] = _evaluate(y, s, p.df["group"].to_numpy()[idx], thresholds, boot)
        result["models"][model_name] = entry

    # ---- explainability for the lexical models ----
    expl = {}
    names = F.HOST_FEATURES if view == "host" else F.FULL_FEATURES
    lr = fitted["logreg_lexical"][0]
    coefs = lr[-1].coef_[0]
    expl["logreg_lexical_std_coefficients"] = dict(sorted(zip(names, map(float, coefs)), key=lambda kv: -abs(kv[1])))
    hgb = fitted["hgb_lexical"][0]
    X_va = _inputs(train_p, va, view, "lexical")
    pi = permutation_importance(hgb, X_va, y_va, scoring="average_precision", n_repeats=3, random_state=SEED)
    expl["hgb_lexical_permutation_importance_val_pr_auc"] = dict(
        sorted(zip(names, map(float, pi.importances_mean)), key=lambda kv: -kv[1]))
    result["explainability"] = expl
    return result, {k: v[0] for k, v in fitted.items()}


def shortcut_probe(p: Prepared, idx: np.ndarray) -> dict:
    """Rule: legitimate iff https + www + no path/query (PhiUSIIL artefact)."""
    y = p.df["is_phishing"].to_numpy()[idx]
    rule_legit = np.array([n.scheme == "https" and n.scheme_explicit and n.hostname.startswith("www.")
                           and n.path in ("", "/") and not n.query for n in (p.normalized[i] for i in idx)])
    score = (~rule_legit).astype(float)
    return {"rule": "predict legitimate iff scheme is https AND host starts with www. AND no path/query",
            **binary_metrics(y, score, 0.5)}


def dump(obj, path):
    path.write_text(json.dumps(obj, indent=2, sort_keys=False), encoding="utf-8")
