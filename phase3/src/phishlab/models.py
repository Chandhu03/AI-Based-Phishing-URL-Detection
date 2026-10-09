"""Model families. All use scikit-learn already pinned in requirements.txt.

* logreg_lexical    - baseline: standardised lexical features + logistic regression
* hgb_lexical       - candidate: histogram gradient boosting on lexical features
* logreg_charngram  - candidate: hashed character 3-5-grams + logistic regression
                      (HashingVectorizer is stateless, so the model is fully
                      described by its coefficients)

Hyperparameters are chosen on the validation split only, from small grids.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import HashingVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

SEED = 20261009
HASH_FEATURES = 2**18
NGRAM_RANGE = (3, 5)


def hashing_vectorizer() -> HashingVectorizer:
    return HashingVectorizer(analyzer="char", ngram_range=NGRAM_RANGE, n_features=HASH_FEATURES,
                             alternate_sign=False, norm="l2", lowercase=False, dtype=np.float32)


@dataclass
class Family:
    name: str
    input: str                 # "lexical" (dense matrix) or "text" (strings)
    grid: list[dict] = field(default_factory=list)

    def build(self, params: dict):
        if self.name == "logreg_lexical":
            return make_pipeline(StandardScaler(),
                                 LogisticRegression(C=params["C"], max_iter=5000, random_state=SEED))
        if self.name == "hgb_lexical":
            return HistGradientBoostingClassifier(
                learning_rate=params["learning_rate"], max_leaf_nodes=params["max_leaf_nodes"],
                max_iter=params["max_iter"], l2_regularization=1.0, early_stopping=False,
                random_state=SEED)
        if self.name == "logreg_charngram":
            return make_pipeline(hashing_vectorizer(),
                                 LogisticRegression(C=params["C"], solver="liblinear", max_iter=2000,
                                                    random_state=SEED))
        raise ValueError(self.name)


FAMILIES = [
    Family("logreg_lexical", "lexical", [{"C": c} for c in (0.1, 1.0, 10.0)]),
    Family("hgb_lexical", "lexical", [
        {"learning_rate": 0.1, "max_leaf_nodes": m, "max_iter": 300} for m in (15, 31, 63)]),
    Family("logreg_charngram", "text", [{"C": c} for c in (1.0, 4.0, 16.0)]),
]
BASELINE = "logreg_lexical"
