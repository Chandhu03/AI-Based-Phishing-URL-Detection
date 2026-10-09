"""Pickle-free artifacts round-trip exactly; imports and downloads are safe."""
import importlib
import json
import socket
import sys

import numpy as np
import pytest

from phishlab import serialize
from phishlab.models import FAMILIES


def _toy_lexical(n=400, d=6, seed=0):
    rng = np.random.default_rng(seed)
    X = rng.normal(size=(n, d))
    y = (X[:, 0] + 0.5 * X[:, 1] + rng.normal(scale=0.5, size=n) > 0).astype(int)
    return X, y


def _toy_text(n=300, seed=0):
    rng = np.random.default_rng(seed)
    good = [f"shop{i}.example.com" for i in range(n // 2)]
    bad = [f"secure-login-{i}.verify-account.tk" for i in range(n // 2)]
    X = good + bad
    y = np.array([0] * len(good) + [1] * len(bad))
    order = rng.permutation(len(X))
    return [X[i] for i in order], y[order]


@pytest.mark.parametrize("family", ["logreg_lexical", "hgb_lexical", "logreg_charngram"])
def test_artifact_roundtrip_matches_sklearn(tmp_path, family):
    fam = next(f for f in FAMILIES if f.name == family)
    X, y = _toy_text() if fam.input == "text" else _toy_lexical()
    model = fam.build(fam.grid[0]).fit(X, y)
    params, arrays = serialize._export(model, family)
    meta = {"format_version": serialize.FORMAT_VERSION, "family": family, "params": params}
    if arrays:
        np.savez_compressed(tmp_path / "a.npz", **arrays)
        meta["arrays_file"] = "a.npz"
        meta["arrays_sha256"] = serialize._sha256(tmp_path / "a.npz")
    (tmp_path / "m.json").write_text(json.dumps(meta), encoding="utf-8")
    got = serialize.load(tmp_path / "m.json").predict_phishing(X)
    expected = model.predict_proba(X)[:, 1]
    assert np.max(np.abs(got - expected)) < 1e-9


def test_tampered_artifact_is_rejected(tmp_path):
    fam = next(f for f in FAMILIES if f.name == "hgb_lexical")
    X, y = _toy_lexical()
    params, arrays = serialize._export(fam.build(fam.grid[0]).fit(X, y), "hgb_lexical")
    np.savez_compressed(tmp_path / "a.npz", **arrays)
    meta = {"format_version": 1, "family": "hgb_lexical", "params": params,
            "arrays_file": "a.npz", "arrays_sha256": "0" * 64}
    (tmp_path / "m.json").write_text(json.dumps(meta), encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256"):
        serialize.load(tmp_path / "m.json")


def test_artifact_npz_contains_no_pickled_objects(tmp_path):
    fam = next(f for f in FAMILIES if f.name == "hgb_lexical")
    X, y = _toy_lexical()
    _, arrays = serialize._export(fam.build(fam.grid[0]).fit(X, y), "hgb_lexical")
    assert all(a.dtype != object for a in arrays.values())


MODULES = ["sources", "download", "psl", "canonical", "datasets", "cleaning", "features",
           "splits", "metrics", "models", "reference", "experiment", "serialize", "report", "cli"]


def test_importing_modules_has_no_side_effects(monkeypatch, tmp_path):
    """Importing never downloads, reads datasets, or writes files."""
    def deny(*a, **k):
        raise AssertionError("network access during import")
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    from phishlab.sources import PHASE3_DIR
    before = {p for p in PHASE3_DIR.rglob("*") if "__pycache__" not in p.parts}
    for m in MODULES:
        sys.modules.pop(f"phishlab.{m}", None)
        importlib.import_module(f"phishlab.{m}")
    after = {p for p in PHASE3_DIR.rglob("*") if "__pycache__" not in p.parts}
    assert after == before


def test_ensure_without_permission_never_downloads(monkeypatch, tmp_path):
    from phishlab import download as D
    monkeypatch.setattr(D, "RAW_DIR", tmp_path)
    monkeypatch.setattr(D, "_fetch", lambda *a, **k: (_ for _ in ()).throw(AssertionError("fetched")))
    with pytest.raises(D.DownloadError, match="missing"):
        D.ensure("hannousse", allow_download=False)


def test_local_file_with_wrong_hash_is_rejected(monkeypatch, tmp_path):
    from phishlab import download as D
    monkeypatch.setattr(D, "RAW_DIR", tmp_path)
    (tmp_path / D.SOURCES["hannousse"].filename).write_text("tampered", encoding="utf-8")
    with pytest.raises(D.DownloadError, match="does not match"):
        D.ensure("hannousse", allow_download=False)


@pytest.mark.parametrize("target", ["http://example.invalid/x", "ftp://example.invalid/x",
                                    "file:///etc/passwd"])
def test_non_https_redirects_are_refused(target):
    import urllib.request

    from phishlab import download as D
    req = urllib.request.Request("https://example.invalid/start")
    with pytest.raises(D.DownloadError, match="non-https redirect"):
        D._HttpsOnlyRedirects().redirect_request(req, None, 302, "Found", {}, target)


def test_downloader_has_no_file_or_ftp_handlers():
    import urllib.request

    from phishlab import download as D
    kinds = {type(h) for h in D._OPENER.handlers}
    assert urllib.request.FileHandler not in kinds and urllib.request.FTPHandler not in kinds
    assert urllib.request.HTTPHandler not in kinds  # plain http is not even possible


def test_only_https_sources():
    from phishlab.sources import SOURCES
    assert all(s.url.startswith("https://") for s in SOURCES.values())
    assert all(len(s.sha256) == 64 for s in SOURCES.values())


def test_reference_batch_scoring_matches_app_predict():
    """Batched reference scores equal securemind.demo_model.predict per URL."""
    from phishlab.reference import ReferenceModel
    from securemind.demo_model import predict
    from securemind.url_validation import validate_url

    ref = ReferenceModel()
    urls = ["https://www.google.com/search?q=weather", "http://secure-paypal-login.xyz/verify?token=1",
            "http://192.168.1.100/chase/login", "evil.tk:443/login"]
    ns = [validate_url(u) for u in urls]
    batch = ref.score(ns)
    for n, s in zip(ns, batch):
        p = predict(n, ref.model, ref.scaler)
        assert (s >= 0.5) == p.is_phishing
        assert max(s, 1 - s) == pytest.approx(p.vote_share)
