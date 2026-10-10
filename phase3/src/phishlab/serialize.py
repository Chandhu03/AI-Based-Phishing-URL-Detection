"""Pickle-free model artifacts.

Every candidate is saved as plain JSON metadata plus, where needed, a NumPy
`.npz` of numeric arrays, which is always loaded with `allow_pickle=False`.
Loading an artifact therefore never executes code. The loaders below
re-implement prediction from those arrays, and `save()` refuses to write an
artifact unless the reloaded model reproduces scikit-learn's probabilities
on the evaluation rows.

Formats:
* logreg_lexical   - JSON: scaler mean/scale, coefficients, intercept.
* logreg_charngram - JSON: vectoriser settings + intercept; npz: coefficients.
* hgb_lexical      - JSON: baseline + tree count; npz: every tree's node arrays.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np

from . import features as F
from .models import HASH_FEATURES, NGRAM_RANGE, hashing_vectorizer

FORMAT_VERSION = 1
_NODE_FIELDS = ("value", "feature_idx", "num_threshold", "missing_go_to_left", "left", "right", "is_leaf")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sigmoid(x: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-x))


# ------------------------------------------------------------------ export
def _export(model, family: str) -> tuple[dict, dict[str, np.ndarray]]:
    if family == "logreg_lexical":
        scaler, lr = model[0], model[-1]
        return {"mean": scaler.mean_.tolist(), "scale": scaler.scale_.tolist(),
                "coef": lr.coef_[0].tolist(), "intercept": float(lr.intercept_[0])}, {}
    if family == "logreg_charngram":
        lr = model[-1]
        return ({"intercept": float(lr.intercept_[0]), "n_features": HASH_FEATURES,
                 "ngram_range": list(NGRAM_RANGE), "analyzer": "char", "alternate_sign": False,
                 "norm": "l2", "lowercase": False},
                {"coef": lr.coef_[0].astype(np.float64)})
    if family == "hgb_lexical":
        if model.n_trees_per_iteration_ != 1:
            raise ValueError("only binary HistGradientBoosting models are supported")
        if getattr(model, "is_categorical_", None) is not None and np.any(model.is_categorical_):
            raise ValueError("categorical splits are not supported")
        arrays = {}
        for i, (pred,) in enumerate(model._predictors):
            nodes = pred.nodes
            for f in _NODE_FIELDS:
                arrays[f"t{i}_{f}"] = np.ascontiguousarray(nodes[f])
        baseline = np.asarray(model._baseline_prediction).ravel()
        return {"baseline": float(baseline[0]), "n_trees": len(model._predictors)}, arrays
    raise ValueError(family)


# ------------------------------------------------------------------ loading
class LoadedModel:
    """A model reconstructed from an artifact; exposes predict_phishing()."""

    def __init__(self, meta: dict, arrays: dict[str, np.ndarray]):
        self.meta, self.arrays = meta, arrays
        self.family = meta["family"]
        if self.family == "logreg_charngram":
            self.vectorizer = hashing_vectorizer()

    def predict_phishing(self, X) -> np.ndarray:
        p = self.meta["params"]
        if self.family == "logreg_lexical":
            z = (np.asarray(X, dtype=np.float64) - np.array(p["mean"])) / np.array(p["scale"])
            return _sigmoid(z @ np.array(p["coef"]) + p["intercept"])
        if self.family == "logreg_charngram":
            Xs = self.vectorizer.transform(X)
            return _sigmoid(np.asarray(Xs @ self.arrays["coef"]).ravel() + p["intercept"])
        if self.family == "hgb_lexical":
            X = np.asarray(X, dtype=np.float64)
            raw = np.full(len(X), p["baseline"])
            for i in range(p["n_trees"]):
                raw += self._tree(i, X)
            return _sigmoid(raw)
        raise ValueError(self.family)

    def _tree(self, i: int, X: np.ndarray) -> np.ndarray:
        a = {f: self.arrays[f"t{i}_{f}"] for f in _NODE_FIELDS}
        node = np.zeros(len(X), dtype=np.int64)
        active = ~a["is_leaf"][node].astype(bool)
        while active.any():
            n = node[active]
            x = X[np.flatnonzero(active), a["feature_idx"][n]]
            go_left = np.where(np.isnan(x), a["missing_go_to_left"][n].astype(bool), x <= a["num_threshold"][n])
            node[active] = np.where(go_left, a["left"][n], a["right"][n])
            active = ~a["is_leaf"][node].astype(bool)
        return a["value"][node]


def load(meta_path: Path) -> LoadedModel:
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    if meta.get("format_version") != FORMAT_VERSION:
        raise ValueError("unsupported artifact format")
    arrays: dict[str, np.ndarray] = {}
    if meta.get("arrays_file"):
        npz_path = meta_path.parent / meta["arrays_file"]
        if _sha256(npz_path) != meta["arrays_sha256"]:
            raise ValueError("artifact arrays do not match their recorded SHA-256")
        with np.load(npz_path, allow_pickle=False) as z:
            arrays = {k: z[k] for k in z.files}
    return LoadedModel(meta, arrays)


# ------------------------------------------------------------------ save
def save(model, family: str, result: dict, exp_key: str, prep, out_dir: Path) -> str:
    from .experiment import _inputs, _score

    view = result["view"]
    params, arrays = _export(model, family)
    stem = f"{exp_key}__{family}"
    meta = {
        "format_version": FORMAT_VERSION,
        "status": "EXPERIMENTAL CANDIDATE - not used by the application",
        "experiment": exp_key, "family": family, "view": view,
        "feature_names": list(F.HOST_FEATURES if view == "host" else F.FULL_FEATURES)
        if family != "logreg_charngram" else None,
        "text_input": None if family != "logreg_charngram" else
        ("hostname without leading www." if view == "host" else "URL without scheme"),
        "positive_class": "phishing (score >= threshold means phishing)",
        "thresholds": result["models"][family]["thresholds"],
        "hyperparameters": result["models"][family]["params"],
        "params": params,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    if arrays:
        npz_path = out_dir / f"{stem}.npz"
        np.savez_compressed(npz_path, **arrays)
        meta["arrays_file"] = npz_path.name
        meta["arrays_sha256"] = _sha256(npz_path)
    meta_path = out_dir / f"{stem}.json"
    meta_path.write_text(json.dumps(meta, indent=1), encoding="utf-8")

    # Round-trip check on every row of the training dataset's test split.
    df = prep.df
    idx = np.flatnonzero(df["split"].to_numpy() == "test")
    kind = "text" if family == "logreg_charngram" else "lexical"
    X = _inputs(prep, idx, view, kind)
    expected = _score(model, X)
    got = load(meta_path).predict_phishing(X)
    max_diff = float(np.max(np.abs(expected - got)))
    if max_diff > 1e-9:
        meta_path.unlink()
        raise RuntimeError(f"{stem}: reloaded predictions differ from sklearn (max diff {max_diff})")
    meta["roundtrip_check"] = {"rows": int(len(idx)), "max_abs_diff": max_diff}
    meta_path.write_text(json.dumps(meta, indent=1), encoding="utf-8")
    return f"{meta_path.name} (round-trip max diff {max_diff:.2e} on {len(idx)} rows)"
