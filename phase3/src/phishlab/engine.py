"""Engine experiment: a browser-portable HOST-view character n-gram model.

The SecureMind Labs platform scores URLs in the visitor's browser, so the
shipped model must be small, pickle-free and exactly reproducible in
JavaScript. This module:

1. trains hashed character 3-5-gram logistic regression on the HOST view
   (hostname with one leading "www." removed) of the UNION of the PhiUSIIL
   and Hannousse training domains (domain-disjoint 70/15/15 split shared by
   both datasets, so no registrable domain is in two splits);
2. selects n_features and C on the union VALIDATION split only;
3. fits Platt scaling and the operating thresholds on validation only;
4. quantises the coefficients, and evaluates the DEQUANTISED (shipped)
   weights on each dataset's held-out test domains, plus leave-one-dataset-
   out transfer, against two baselines (phase3 experiment A's selected
   model and the current demo model);
5. exports a generated ES module and golden vectors for the JavaScript
   implementation, refusing to write anything if an independent pure-Python
   scorer disagrees with scikit-learn.

Hashing semantics (sklearn HashingVectorizer, analyzer="char",
alternate_sign=False): every n-gram is UTF-8 encoded and hashed with
MurmurHash3_x86_32 (seed 0, signed result h); bucket = abs(h) % n_features,
except h == -2**31, whose bucket is (2**31 - 1 - (n_features - 1)) % n_features.
Repeated n-grams add 1 per occurrence; the row is then L2-normalised.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import numbers
import re
import struct
import time
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.utils import murmurhash3_32

from securemind.url_validation import validate_url

from . import features as F
from .metrics import binary_metrics, ranking_metrics, threshold_for_fpr
from .models import FAMILIES, NGRAM_RANGE, SEED

N_FEATURES_GRID = (2**14, 2**16, 2**18)
C_GRID = (1.0, 4.0, 16.0)
# Validation-only tie-break: prefer the smallest n_features whose best
# validation PR-AUC is within this tolerance of the overall best (smaller
# artifact for the browser, same validation quality).
SIZE_TOLERANCE = 0.002
FPR_HIGH, FPR_ELEVATED = 0.01, 0.05
ECE_BINS = 10
FORMAT = "securemind.charngram-logreg/1"
_WS = re.compile(r"\s\s+")


class ParityError(RuntimeError):
    """The independent scorer disagrees with scikit-learn: do not ship."""


# ------------------------------------------------------------------ data
def union_frames(p_df: pd.DataFrame, h_df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Concatenate both cleaned datasets, drop cross-dataset label conflicts,
    and collapse URLs present in both datasets with the same label."""
    both = pd.concat([p_df.assign(source="phiusiil"), h_df.assign(source="hannousse")], ignore_index=True)
    labels = both.groupby("url")["is_phishing"].nunique()
    conflicts = set(labels[labels > 1].index)
    stats = {"rows_in": int(len(both)), "cross_dataset_conflicting_urls": len(conflicts),
             "cross_dataset_conflicting_rows": int(both.url.isin(conflicts).sum())}
    both = both[~both.url.isin(conflicts)]
    dup = both.duplicated(subset=["url"], keep="first")
    stats["cross_dataset_duplicate_rows_collapsed"] = int(dup.sum())
    both = both[~dup].reset_index(drop=True)
    stats["rows_out"] = int(len(both))
    split_groups = {s: set(both.loc[both.split == s, "group"]) for s in ("train", "val", "test")}
    stats["shared_groups"] = {"train_val": len(split_groups["train"] & split_groups["val"]),
                              "train_test": len(split_groups["train"] & split_groups["test"]),
                              "val_test": len(split_groups["val"] & split_groups["test"])}
    if any(stats["shared_groups"].values()):
        raise RuntimeError(f"domain leakage across splits: {stats['shared_groups']}")
    return both, stats


def host_texts(urls) -> list[str]:
    return [F.host_text(validate_url(u)) for u in urls]


# ------------------------------------------------------------------ model
def vectorizer(n_features: int) -> HashingVectorizer:
    # float64 (not phase3's float32) so the JavaScript port can match to 1e-9.
    return HashingVectorizer(analyzer="char", ngram_range=NGRAM_RANGE, n_features=n_features,
                             alternate_sign=False, norm="l2", lowercase=False, dtype=np.float64)


def fit(texts, y: np.ndarray, n_features: int, C: float) -> LogisticRegression:
    """`texts` may be a list of strings or an already-hashed sparse matrix."""
    X = vectorizer(n_features).transform(texts) if isinstance(texts, list) else texts
    return LogisticRegression(C=C, solver="liblinear", max_iter=2000, random_state=SEED).fit(X, y)


def logits(coef: np.ndarray, intercept: float, texts: list[str]) -> np.ndarray:
    return vectorizer(len(coef)).transform(texts) @ coef + intercept


def quantize(coef: np.ndarray, bits: int) -> tuple[np.ndarray, float]:
    qmax = 2 ** (bits - 1) - 1
    scale = float(np.max(np.abs(coef)) / qmax) or 1.0
    q = np.clip(np.rint(coef / scale), -qmax, qmax).astype(np.int16 if bits == 16 else np.int8)
    return q, scale


def dequantize(q: np.ndarray, scale: float) -> np.ndarray:
    return q.astype(np.float64) * scale


def fit_platt(val_logit: np.ndarray, y_val: np.ndarray) -> tuple[float, float]:
    """1-D logistic regression on the validation logits (validation only)."""
    lr = LogisticRegression(C=1e6, solver="lbfgs", max_iter=1000).fit(val_logit.reshape(-1, 1), y_val)
    return float(lr.coef_[0][0]), float(lr.intercept_[0])


def platt(logit: np.ndarray, a: float, b: float) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-(a * logit + b)))


def select_thresholds(y_val: np.ndarray, p_val: np.ndarray) -> dict:
    """Operating thresholds from VALIDATION data only."""
    return {"high": threshold_for_fpr(y_val, p_val, FPR_HIGH),
            "elevated": threshold_for_fpr(y_val, p_val, FPR_ELEVATED)}


def ece(y: np.ndarray, p: np.ndarray, bins: int = ECE_BINS) -> float:
    edges = np.linspace(0.0, 1.0, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1], right=False), 0, bins - 1)
    total = 0.0
    for b in range(bins):
        m = idx == b
        if m.any():
            total += m.mean() * abs(y[m].mean() - p[m].mean())
    return float(total)


def evaluate(y: np.ndarray, score: np.ndarray, thresholds: dict, probability: bool) -> dict:
    out = {"n": int(len(y)), "positives": int(y.sum())}
    out.update(ranking_metrics(y, score))
    for k, t in thresholds.items():
        out[f"at_{k}"] = binary_metrics(y, score, t)
    if probability:
        out["brier"] = float(np.mean((score - y) ** 2))
        out["ece_10"] = ece(y, score)
    return out


# ------------------------------------------------------------------ independent scorer
def char_ngrams(text: str) -> list[str]:
    text = _WS.sub(" ", text)
    lo, hi = NGRAM_RANGE
    return [text[i:i + n] for n in range(lo, min(hi, len(text)) + 1) for i in range(len(text) - n + 1)]


def bucket(ngram: str, n_features: int) -> int:
    h = murmurhash3_32(ngram.encode("utf-8"), seed=0, positive=False)
    if h == -(2**31):
        return (2**31 - 1 - (n_features - 1)) % n_features
    return abs(h) % n_features


def pure_logit(text: str, coef: np.ndarray, intercept: float) -> float:
    counts: dict[int, float] = {}
    for g in char_ngrams(text):
        b = bucket(g, len(coef))
        counts[b] = counts.get(b, 0.0) + 1.0
    norm = math.sqrt(sum(v * v for v in counts.values()))
    if norm == 0.0:
        return float(intercept)
    return float(intercept + sum(v / norm * coef[b] for b, v in counts.items()))


def check_parity(texts: list[str], coef: np.ndarray, intercept: float, tol: float = 1e-9) -> np.ndarray:
    """Return sklearn logits; raise ParityError if the pure scorer differs."""
    ref = logits(coef, intercept, texts)
    for t, r in zip(texts, ref):
        p = pure_logit(t, coef, intercept)
        if not abs(p - r) <= tol:
            raise ParityError(f"logit mismatch for {t!r}: pure={p!r} sklearn={r!r}")
    return ref


# ------------------------------------------------------------------ golden URLs
def golden_urls() -> list[str]:
    """Synthetic URLs covering the normaliser's and hasher's edge cases.
    None of them is taken from the datasets."""
    rng = np.random.default_rng(SEED)
    brands = ["paypal", "apple", "microsoft", "amazon", "netflix", "chase", "github", "google"]
    words = ["secure", "login", "verify", "account", "update", "support", "billing", "wallet"]
    tlds = ["com", "net", "org", "co.uk", "io", "xyz", "top", "tk", "info", "app", "de", "ru"]
    urls = [
        "https://example.com/", "http://example.org/path?q=1", "https://www.example.com",
        "https://WWW.EXAMPLE.COM/Path", "HTTPS://Sub.Example.CO.UK:8443/x", "example.com",
        "www.example.com/login", "https://example.com./", "https://user:pass@example.com/",
        "http://paypal.com@evil.example/", "http://192.168.1.1/admin", "http://3232235777/",
        "http://0xC0A80101/", "http://0300.0250.1.1/", "http://127.1/", "http://[::1]:8080/",
        "http://[2001:db8::1]/", "http://[::ffff:127.0.0.1]/", "https://xn--pple-43d.com/",
        "https://аpple.com/", "https://bücher.de/", "https://münchen.de/",
        "https://ｅｘａｍｐｌｅ.com/", "https://xn--80ak6aa92e.com/",
        "https://a.b.c.d.e.f.example.com/", "https://www.www.example.com/", "https://www.com/",
        "https://ab.io/", "https://a.co/", "https://x.y/", "https://xn--fiq228c.xn--55qx5d.cn/",
        "https://" + "a" * 63 + ".com/", "https://" + ".".join(["b" * 40] * 5) + ".net/",
        "https://123-456-789.example.com/", "https://login-secure-paypal.com.verify-account.xyz/",
        "https://my--double--hyphen.example/", "https://_dmarc.example.com/",
        "https://under_score.example.com/", "http://localhost/", "http://localhost:3000/",
        "http://a/", "http://ab/",  # fewer than 3 characters: no n-grams, logit = intercept
    ]
    for _ in range(140):
        w = rng.choice(words, size=int(rng.integers(1, 4)), replace=False)
        b = rng.choice(brands)
        tld = rng.choice(tlds)
        sep = rng.choice(["-", ".", ""])
        host = sep.join([*w, b]) if rng.random() < 0.5 else f"{b}.com.{sep.join(w)}"
        scheme = rng.choice(["http://", "https://", ""])
        urls.append(f"{scheme}{host}.{tld}/{rng.choice(words)}")
    for _ in range(80):
        n = int(rng.integers(3, 14))
        label = "".join(rng.choice(list("abcdefghijklmnopqrstuvwxyz0123456789-"), size=n))
        label = label.strip("-") or "a"
        sub = rng.choice(["", "www.", "m.", "app.", "cdn1.", "login."])
        urls.append(f"https://{sub}{label}.{rng.choice(tlds)}/")
    for _ in range(40):
        ip = ".".join(str(int(v)) for v in rng.integers(1, 255, size=4))
        urls.append(f"http://{ip}/{rng.choice(brands)}/{rng.choice(words)}")
    for b in brands:
        urls.append(f"https://www.{b}.com/")
        urls.append(f"https://{b}.com.{rng.choice(words)}.{rng.choice(tlds)}/")
    return urls


# ------------------------------------------------------------------ export
def js_module(meta: dict) -> str:
    body = json.dumps(meta, indent=2, ensure_ascii=True)
    return ("// GENERATED by phase3 engine export - do not edit.\n"
            "// Regenerate with: python phase3/run.py engine (see phase3/README.md).\n"
            f"export const MODEL = {body};\n")


# Fields that decide every score an artifact produces. The model id is the
# SHA-256 of these fields, so two artifacts with the same id score
# identically, and any change to weights, calibration or thresholds changes it.
SCORING_FIELDS = ("format", "view", "analyzer", "ngramRange", "nFeatures", "lowercase", "norm", "hash",
                  "intercept", "coefEncoding", "coefScale", "coefBase64", "calibration", "thresholds")


def canonical(value) -> str:
    """Byte-exact text shared with website/src/engine/model.js: keys sorted,
    strings JSON-escaped to ASCII, every number as its IEEE-754 binary64 bits
    (so float formatting differences between languages cannot matter)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, numbers.Real):
        return "0x" + struct.pack(">d", float(value)).hex()
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{" + ",".join(json.dumps(k, ensure_ascii=True) + ":" + canonical(value[k]) for k in sorted(value)) + "}"
    raise TypeError(f"cannot canonicalise {type(value).__name__}")


def model_identity(meta: dict) -> tuple[str, str]:
    """(model id, full SHA-256 hex digest) of an artifact's scoring fields."""
    missing = [f for f in SCORING_FIELDS if f not in meta]
    if missing:
        raise KeyError(f"model metadata lacks {', '.join(missing)}")
    digest = hashlib.sha256(canonical({k: meta[k] for k in SCORING_FIELDS}).encode("ascii")).hexdigest()
    return "url-host-" + digest[:16], digest


def export(meta: dict, coef: np.ndarray, out_js: Path, out_golden: Path) -> dict:
    """Write the ES module and golden vectors. Raises ParityError (and writes
    nothing) if the independent scorer disagrees with scikit-learn."""
    urls = golden_urls()
    texts = host_texts(urls)
    ref = check_parity(texts, coef, meta["intercept"])
    a, b = meta["calibration"]["a"], meta["calibration"]["b"]
    golden = [{"url": u, "text": t, "logit": float(l), "probability": float(platt(np.array([l]), a, b)[0])}
              for u, t, l in zip(urls, texts, ref)]
    out_js.parent.mkdir(parents=True, exist_ok=True)
    out_js.write_text(js_module(meta), encoding="utf-8", newline="\n")
    out_golden.write_text(json.dumps({"model_id": meta["id"], "vectors": golden}, indent=1,
                                     ensure_ascii=True) + "\n", encoding="utf-8", newline="\n")
    return {"golden_vectors": len(golden), "js_bytes": out_js.stat().st_size,
            "golden_bytes": out_golden.stat().st_size}


# ------------------------------------------------------------------ reporting
def _op(m: dict) -> dict:
    return {k: round(m[k], 4) for k in ("recall", "fpr", "precision")}


def _compact(e: dict) -> dict:
    out = {"n": e["n"], "positives": e["positives"], "roc_auc": round(e["roc_auc"], 4),
           "pr_auc": round(e["pr_auc"], 4), "high": _op(e["at_high"]), "elevated": _op(e["at_elevated"])}
    if "ece_10" in e:
        out["brier"], out["ece_10"] = round(e["brier"], 4), round(e["ece_10"], 4)
    return out


def compact_evaluation(metrics: dict, sources: dict) -> dict:
    t = metrics["test"]
    return {
        "generatedUtc": metrics["generated_utc"],
        "environment": {k: metrics["environment"][k] for k in ("sklearn", "numpy")},
        "datasets": {k: {"license": sources[k].license, "sha256": sources[k].sha256} for k in ("phiusiil", "hannousse")},
        "sizes": metrics["sizes"],
        "split": "domain-disjoint 70/15/15 by salted hash of the registrable domain",
        "selectionAndThresholds": "validation split only; test sets scored once",
        "test": {name: {model: _compact(t[model][name]) for model in
                        ("engine_shipped", "baseline_A_host_phiusiil", "reference_demo_model")}
                 for name in t["engine_shipped"]},
        "transfer": {k: _compact(v) for k, v in metrics["transfer"].items()},
    }


def report_markdown(m: dict) -> str:
    L = ["# Engine model: evaluation report", "",
         f"Generated {m['generated_utc']} (scikit-learn {m['environment']['sklearn']}, "
         f"numpy {m['environment']['numpy']}). Model id `{m['export']['model_id']}` "
         f"(SHA-256 of the scoring fields: `{m['export']['model_sha256']}`).", "",
         "HOST-view hashed character 3-5-gram logistic regression trained on the union of the "
         "PhiUSIIL and Hannousse training domains. Model choice, quantisation, calibration and "
         "thresholds use the union validation split only; each test set was scored once. "
         "Metrics are for the shipped (dequantised, calibrated) weights.", "",
         "## Data", "", "| Item | Value |", "|---|---|"]
    for k, v in m["union"].items():
        L.append(f"| union {k} | {v} |")
    for k, v in m["sizes"].items():
        L.append(f"| rows: {k} | {v} |")
    L += ["", "## Selection (validation PR-AUC)", "", "| n_features | C | val PR-AUC | val ROC-AUC | fit s |",
          "|---|---|---|---|---|"]
    for t in m["selection"]["trials"]:
        L.append(f"| 2^{int(math.log2(t['n_features']))} | {t['C']} | {t['val_pr_auc']:.4f} | "
                 f"{t['val_roc_auc']:.4f} | {t['fit_seconds']} |")
    sel = m["selection"]["selected"]
    q = m["quantization"]
    L += ["", f"Rule: {m['selection']['rule']}. Selected: n_features = 2^{int(math.log2(sel['n_features']))}, "
          f"C = {sel['C']}.", "",
          f"Quantisation ({q['rule']}): validation ROC-AUC float64 {q['validation_roc_auc']['float64']:.5f}, "
          f"int16 {q['validation_roc_auc']['int16']:.5f}, int8 {q['validation_roc_auc']['int8']:.5f}; "
          f"shipped `{q['chosen']}`.", "",
          f"Calibration: Platt scaling on validation logits, a = {m['calibration']['a']:.4f}, "
          f"b = {m['calibration']['b']:.4f}. Thresholds ({m['thresholds']['rule']}): "
          f"high = {m['thresholds']['engine']['high']:.4f}, elevated = {m['thresholds']['engine']['elevated']:.4f}.",
          "", "## Held-out test domains", "",
          "Baselines use thresholds chosen on the same union validation split.", "",
          "| Test set | Model | n | ROC-AUC | PR-AUC | recall@high | FPR@high | recall@elevated | FPR@elevated | Brier | ECE |",
          "|---|---|---|---|---|---|---|---|---|---|---|"]
    for model, sets in m["test"].items():
        if model == "engine_uncalibrated":
            continue
        for name, e in sets.items():
            L.append(f"| {name} | {model} | {e['n']} | {e['roc_auc']:.4f} | {e['pr_auc']:.4f} | "
                     f"{e['at_high']['recall']:.3f} | {e['at_high']['fpr']:.3f} | {e['at_elevated']['recall']:.3f} | "
                     f"{e['at_elevated']['fpr']:.3f} | {e['brier']:.4f} | {e['ece_10']:.4f} |")
    L += ["", "Calibration of the engine before Platt scaling (raw sigmoid of the logit):", "",
          "| Test set | Brier raw | ECE raw | Brier calibrated | ECE calibrated |", "|---|---|---|---|---|"]
    for name, u in m["test"]["engine_uncalibrated"].items():
        c = m["test"]["engine_shipped"][name]
        L.append(f"| {name} | {u['brier']:.4f} | {u['ece_10']:.4f} | {c['brier']:.4f} | {c['ece_10']:.4f} |")
    L += ["", "## Leave-one-dataset-out transfer (selected configuration)", "",
          "Trained on one dataset's training domains, calibrated and thresholded on its validation "
          "domains, tested on the other dataset's test domains.", "",
          "| Direction | ROC-AUC | PR-AUC | recall@high | FPR@high | recall@elevated | FPR@elevated |",
          "|---|---|---|---|---|---|---|"]
    for k, e in m["transfer"].items():
        L.append(f"| {k} | {e['roc_auc']:.4f} | {e['pr_auc']:.4f} | {e['at_high']['recall']:.3f} | "
                 f"{e['at_high']['fpr']:.3f} | {e['at_elevated']['recall']:.3f} | {e['at_elevated']['fpr']:.3f} |")
    ex = m["export"]
    L += ["", "## Export", "",
          f"`website/src/engine/models/url-host-model.js` ({ex['js_bytes']} bytes) and "
          f"`url-host-model.golden.json` ({ex['golden_vectors']} vectors). An independent pure-Python "
          "scorer matched scikit-learn to 1e-9 on every golden vector before anything was written.", "",
          "## Limitations", "",
          "- Both datasets are public and dated; performance on new campaigns is unknown.",
          "- The model sees only the hostname. Path, query and userinfo signals are handled by "
          "the separate rule layer, which is not evaluated here.",
          "- Test sets are dominated by a few large domains (see EVALUATION_REPORT.md); no "
          "bootstrap intervals are computed for this experiment.",
          "- A low score is not evidence that a URL is safe.", ""]
    return "\n".join(L)


# ------------------------------------------------------------------ experiment
@dataclass
class Split:
    texts: list[str]
    y: np.ndarray
    normalized: list


def _split(df: pd.DataFrame) -> Split:
    n = [validate_url(u) for u in df["url"]]
    return Split([F.host_text(x) for x in n], df["is_phishing"].to_numpy().astype(int), n)


def run(p_df: pd.DataFrame, h_df: pd.DataFrame, reference, baseline_a_params: dict, log) -> tuple[dict, dict]:
    """Run the full engine experiment. Returns (metrics, export_meta_without_id)."""
    union, union_stats = union_frames(p_df, h_df)
    log(f"union: {union_stats}")
    tr, va = _split(union[union.split == "train"]), _split(union[union.split == "val"])
    tests = {"phiusiil_test": _split(union[(union.split == "test") & (union.source == "phiusiil")]),
             "hannousse_test": _split(union[(union.split == "test") & (union.source == "hannousse")])}

    # ---- selection on validation only ----
    trials, best = [], None
    for nf in N_FEATURES_GRID:
        X_tr, X_va = vectorizer(nf).transform(tr.texts), vectorizer(nf).transform(va.texts)
        for C in C_GRID:
            t0 = time.time()
            m = fit(X_tr, tr.y, nf, C)
            r = ranking_metrics(va.y, X_va @ m.coef_[0] + m.intercept_[0])
            trials.append({"n_features": nf, "C": C, "val_pr_auc": r["pr_auc"], "val_roc_auc": r["roc_auc"],
                           "fit_seconds": round(time.time() - t0, 1)})
            log(f"  n_features=2**{int(math.log2(nf))} C={C} val PR-AUC={r['pr_auc']:.4f}")
            del m
        del X_tr, X_va
    top = max(t["val_pr_auc"] for t in trials)
    nf_sel = min(t["n_features"] for t in trials if t["val_pr_auc"] >= top - SIZE_TOLERANCE)
    best = max((t for t in trials if t["n_features"] == nf_sel), key=lambda t: t["val_pr_auc"])
    log(f"selected n_features={nf_sel} C={best['C']}")
    model = fit(tr.texts, tr.y, nf_sel, best["C"])
    coef_f, intercept = model.coef_[0].astype(np.float64), float(model.intercept_[0])

    # ---- quantisation (decided on validation ROC-AUC) ----
    q16, s16 = quantize(coef_f, 16)
    q8, s8 = quantize(coef_f, 8)
    roc_val = {k: ranking_metrics(va.y, logits(c, intercept, va.texts))["roc_auc"]
               for k, c in (("float64", coef_f), ("int16", dequantize(q16, s16)), ("int8", dequantize(q8, s8)))}
    use8 = abs(roc_val["int8"] - roc_val["float64"]) < 0.002
    q, scale, enc = (q8, s8, "int8") if use8 else (q16, s16, "int16")
    coef = dequantize(q, scale)

    # ---- calibration and thresholds on validation only ----
    val_logit = logits(coef, intercept, va.texts)
    a, b = fit_platt(val_logit, va.y)
    p_val = platt(val_logit, a, b)
    thr = select_thresholds(va.y, p_val)

    # ---- baselines: same validation set for their thresholds ----
    fam = next(f for f in FAMILIES if f.name == "logreg_charngram")
    p_tr = _split(p_df[p_df.split == "train"])
    base_a = fam.build(baseline_a_params).fit(p_tr.texts, p_tr.y)

    def score_a(s: Split) -> np.ndarray:
        return base_a.predict_proba(s.texts)[:, list(base_a.classes_).index(1)]

    def score_ref(s: Split) -> np.ndarray:
        return reference.score(s.normalized)

    thr_a = select_thresholds(va.y, score_a(va))
    thr_ref = select_thresholds(va.y, score_ref(va))

    results: dict = {"engine_shipped": {}, "engine_uncalibrated": {}, "baseline_A_host_phiusiil": {},
                     "reference_demo_model": {}}
    for name, s in tests.items():
        lg = logits(coef, intercept, s.texts)
        results["engine_shipped"][name] = evaluate(s.y, platt(lg, a, b), thr, probability=True)
        raw_p = 1.0 / (1.0 + np.exp(-lg))
        results["engine_uncalibrated"][name] = {"brier": float(np.mean((raw_p - s.y) ** 2)),
                                                "ece_10": ece(s.y, raw_p)}
        results["baseline_A_host_phiusiil"][name] = evaluate(s.y, score_a(s), thr_a, probability=True)
        results["reference_demo_model"][name] = evaluate(s.y, score_ref(s), thr_ref, probability=True)
        log(f"  {name}: engine ROC={results['engine_shipped'][name]['roc_auc']:.4f} "
            f"A={results['baseline_A_host_phiusiil'][name]['roc_auc']:.4f} "
            f"ref={results['reference_demo_model'][name]['roc_auc']:.4f}")

    # ---- leave-one-dataset-out transfer for the selected config ----
    transfer = {}
    for src, dst in (("phiusiil", "hannousse"), ("hannousse", "phiusiil")):
        sd = union[union.source == src]
        s_tr, s_va = _split(sd[sd.split == "train"]), _split(sd[sd.split == "val"])
        m = fit(s_tr.texts, s_tr.y, nf_sel, best["C"])
        c, i0 = m.coef_[0], float(m.intercept_[0])
        aa, bb = fit_platt(logits(c, i0, s_va.texts), s_va.y)
        t_thr = select_thresholds(s_va.y, platt(logits(c, i0, s_va.texts), aa, bb))
        dst_test = tests[f"{dst}_test"]
        transfer[f"train_{src}_test_{dst}"] = evaluate(dst_test.y, platt(logits(c, i0, dst_test.texts), aa, bb),
                                                       t_thr, probability=True)
        log(f"  transfer {src}->{dst}: ROC={transfer[f'train_{src}_test_{dst}']['roc_auc']:.4f}")

    metrics = {
        "union": union_stats,
        "sizes": {"train": len(tr.y), "val": len(va.y), **{k: len(v.y) for k, v in tests.items()}},
        "selection": {"trials": trials, "rule": f"max validation PR-AUC; smallest n_features within "
                      f"{SIZE_TOLERANCE} of the best", "selected": {"n_features": nf_sel, "C": best["C"]}},
        "quantization": {"validation_roc_auc": roc_val, "chosen": enc, "rule": "int8 if |delta val ROC-AUC| < 0.002"},
        "calibration": {"kind": "platt", "a": a, "b": b, "fit_on": "union validation"},
        "thresholds": {"engine": thr, "baseline_A_host_phiusiil": thr_a, "reference_demo_model": thr_ref,
                       "rule": f"high: validation FPR <= {FPR_HIGH}; elevated: validation FPR <= {FPR_ELEVATED}"},
        "validation_engine": evaluate(va.y, p_val, thr, probability=True),
        "test": results,
        "transfer": transfer,
        "baseline_A_params": baseline_a_params,
    }
    meta = {
        "format": FORMAT, "view": "host", "analyzer": "char", "ngramRange": list(NGRAM_RANGE),
        "nFeatures": nf_sel, "lowercase": False, "norm": "l2", "hash": "murmurhash3_32/seed0/abs-mod",
        "intercept": intercept, "coefEncoding": enc, "coefScale": scale,
        "coefBase64": base64.b64encode(q.astype("<i2" if enc == "int16" else "i1").tobytes()).decode("ascii"),
        "calibration": {"kind": "platt", "a": a, "b": b},
        "thresholds": {"high": thr["high"], "elevated": thr["elevated"]},
    }
    return metrics, {"meta": meta, "coef": coef}


# ------------------------------------------------------------------ per-site evaluation
def site_evaluation(texts: list[str], groups: list[str], y: np.ndarray, score: np.ndarray, thresholds: dict) -> dict:
    """Evaluate the same scores counted per URL, once per host and once per
    registrable domain.

    Every URL on one host gets the same host-view score, so per-URL metrics
    weight a site by how many of its URLs a dataset happens to contain. Here a
    host (or domain) counts once per label; its score is the mean of its rows
    (identical for a host; for a domain, the mean over its hosts' URLs)."""
    df = pd.DataFrame({"text": texts, "group": groups, "y": y.astype(int), "s": score})
    out = {"per_url": evaluate(df.y.to_numpy(), df.s.to_numpy(), thresholds, probability=False)}
    for name, key in (("per_host", "text"), ("per_domain", "group")):
        g = df.groupby([key, "y"], as_index=False)["s"].mean()
        out[name] = evaluate(g.y.to_numpy(), g.s.to_numpy(), thresholds, probability=False)
    top = df.groupby("group").size().sort_values(ascending=False)
    out["largest_domain_share"] = float(top.iloc[0] / len(df)) if len(df) else 0.0
    return out


def shipped_scores(model_js: Path, texts: list[str]) -> tuple[np.ndarray, dict]:
    """Calibrated scores from the exported artifact itself (not a retrain)."""
    src = model_js.read_text(encoding="utf-8")
    meta = json.loads(src[src.index("{"):src.rindex("}") + 1])
    if model_identity(meta) != (meta.get("id"), meta.get("sha256")):
        raise ValueError(f"{model_js} does not match its content-addressed id; re-export it")
    dtype = "<i2" if meta["coefEncoding"] == "int16" else "i1"
    coef = np.frombuffer(base64.b64decode(meta["coefBase64"]), dtype=dtype).astype(np.float64) * meta["coefScale"]
    lg = logits(coef, meta["intercept"], texts)
    cal = meta["calibration"]
    return platt(lg, cal["a"], cal["b"]), meta
