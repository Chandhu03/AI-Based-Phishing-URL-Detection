"""Score URLs with the existing demo model, exactly as the live app does.

The demo model is trained by `securemind.demo_model.train_demo_model()`
(unchanged; bit-identical per tests/test_demo_model_parity.py). This module
only batches what `securemind.demo_model.predict` does per URL, and returns
the phishing-class probability so it can be ranked like any other model.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from securemind.demo_model import train_demo_model
from securemind.features import FEATURE_NAMES, extract_url_features
from securemind.url_validation import NormalizedURL


class ReferenceModel:
    name = "reference_demo_model"

    def __init__(self):
        self.model, self.scaler = train_demo_model()

    def score(self, normalized: list[NormalizedURL]) -> np.ndarray:
        frame = pd.DataFrame([extract_url_features(n) for n in normalized], columns=list(FEATURE_NAMES))
        proba = self.model.predict_proba(self.scaler.transform(frame))
        classes = list(self.model.classes_)
        return proba[:, classes.index(1)]
