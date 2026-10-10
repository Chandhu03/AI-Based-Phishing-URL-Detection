"""Evaluation metrics. Positive class = phishing (is_phishing == 1)."""
from __future__ import annotations

import numpy as np
from sklearn.metrics import average_precision_score, confusion_matrix, roc_auc_score


def threshold_for_fpr(y: np.ndarray, score: np.ndarray, max_fpr: float) -> float:
    """Smallest threshold whose false-positive rate on (y, score) is <= max_fpr.

    Predictions are `score >= threshold`. Chosen on VALIDATION data only.
    """
    neg = np.sort(score[y == 0])[::-1]
    if len(neg) == 0:
        raise ValueError("no negatives to estimate FPR")
    k = int(np.floor(max_fpr * len(neg)))  # allowed false positives
    if k >= len(neg):
        return float(neg[-1])
    # threshold strictly above the (k+1)-th highest negative score
    return float(np.nextafter(neg[k], np.inf))


def threshold_max_f1(y: np.ndarray, score: np.ndarray) -> float:
    order = np.argsort(-score, kind="stable")
    s, t = score[order], y[order]
    tp = np.cumsum(t)
    fp = np.cumsum(1 - t)
    p_total = t.sum()
    # only evaluate at distinct score boundaries
    last = np.r_[s[1:] != s[:-1], True]
    prec = tp / np.maximum(tp + fp, 1)
    rec = tp / max(p_total, 1)
    f1 = np.where(prec + rec > 0, 2 * prec * rec / np.maximum(prec + rec, 1e-12), 0.0)
    f1 = np.where(last, f1, -1)
    return float(s[int(np.argmax(f1))])


def binary_metrics(y: np.ndarray, score: np.ndarray, threshold: float) -> dict:
    pred = (score >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "threshold": float(threshold),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(2 * precision * recall / (precision + recall)) if precision + recall else 0.0,
        "fpr": float(fp / (fp + tn)) if fp + tn else 0.0,
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def ranking_metrics(y: np.ndarray, score: np.ndarray) -> dict:
    if len(np.unique(y)) < 2:
        return {"roc_auc": None, "pr_auc": None}
    return {"roc_auc": float(roc_auc_score(y, score)),
            "pr_auc": float(average_precision_score(y, score))}


def grouped_bootstrap_ci(y, score, groups, threshold, n_boot=200, seed=0) -> dict:
    """95% percentile CIs, resampling whole domains (groups) with replacement."""
    rng = np.random.default_rng(seed)
    uniq, inv = np.unique(groups, return_inverse=True)
    idx_by_group = np.split(np.argsort(inv, kind="stable"), np.cumsum(np.bincount(inv))[:-1])
    out = {k: [] for k in ("pr_auc", "roc_auc", "recall", "fpr", "precision")}
    for _ in range(n_boot):
        pick = rng.integers(0, len(uniq), len(uniq))
        idx = np.concatenate([idx_by_group[g] for g in pick])
        yb, sb = y[idx], score[idx]
        if len(np.unique(yb)) < 2:
            continue
        r = ranking_metrics(yb, sb)
        b = binary_metrics(yb, sb, threshold)
        for k in ("pr_auc", "roc_auc"):
            out[k].append(r[k])
        for k in ("recall", "fpr", "precision"):
            out[k].append(b[k])
    return {k: [float(np.percentile(v, 2.5)), float(np.percentile(v, 97.5))] if v else None
            for k, v in out.items()}
