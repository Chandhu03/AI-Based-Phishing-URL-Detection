import hashlib
import random

import numpy as np
import pytest

from securemind.demo_model import (
    build_training_matrix, generate_training_urls, train_demo_model,
)
from securemind.features import extract_url_features
from securemind.url_validation import validate_url
from tests import legacy_reference

TRAINING_MATRIX_SHA256 = "ff388bd5e68ee0ecab6c959cff3bcd70562caf174434ffcf1effed3e21b66224"
TREE_FINGERPRINT_SHA256 = "9dca794c012c198694c3f6b1f2b39317af9521e39b050c02c6e4eaeb0b693fb8"


@pytest.fixture(scope="module")
def matrix():
    return build_training_matrix()


@pytest.fixture(scope="module")
def trained():
    return train_demo_model()


def test_feature_parity_with_legacy_on_all_training_urls():
    urls = generate_training_urls()
    assert len(urls) == 10000
    for u, _ in urls:
        new = extract_url_features(validate_url(u))
        old = legacy_reference.extract_url_features(u)
        assert new == old, f"first mismatch: {u!r}\nnew={new}\nold={old}"


def test_training_matrix_hash(matrix):
    X, y = matrix
    h = hashlib.sha256()
    h.update(np.ascontiguousarray(X.to_numpy(dtype=np.int64)).tobytes())
    h.update(np.asarray(y, dtype=np.int64).tobytes())
    assert h.hexdigest() == TRAINING_MATRIX_SHA256


def test_tree_fingerprint(trained):
    import sklearn
    if sklearn.__version__ != "1.8.0":
        pytest.skip(f"tree fingerprint recorded with scikit-learn 1.8.0, found {sklearn.__version__}")
    model, _ = trained
    h = hashlib.sha256()
    for est in model.estimators_:
        t = est.tree_
        for a in (t.feature, t.threshold, t.value, t.children_left, t.children_right):
            h.update(np.ascontiguousarray(a).tobytes())
    assert h.hexdigest() == TREE_FINGERPRINT_SHA256


def test_global_random_state_unchanged():
    before = random.getstate()
    generate_training_urls()
    assert random.getstate() == before
