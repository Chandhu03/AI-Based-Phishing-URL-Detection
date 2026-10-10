"""Feature views, metrics and threshold selection (synthetic fixtures)."""
import numpy as np
import pytest

from phishlab import features as F
from phishlab.metrics import binary_metrics, ranking_metrics, threshold_for_fpr, threshold_max_f1
from securemind.url_validation import validate_url


def _host(url, group):
    return F.host_features(validate_url(url), group)


# ---------------------------------------------------------------- features
@pytest.mark.parametrize("variant", [
    "http://example.com", "https://www.example.com", "https://www.example.com/a/b?c=d",
    "HTTP://WWW.EXAMPLE.COM/login.php#x",
])
def test_host_view_ignores_scheme_www_and_path(variant):
    """The PhiUSIIL artefact lives in scheme/www/path; the HOST view must not see it."""
    assert _host(variant, "example.com") == _host("https://www.example.com", "example.com")


def test_full_view_sees_scheme_www_and_path():
    a = F.full_features(validate_url("https://www.example.com"), "example.com")
    b = F.full_features(validate_url("http://example.com/login.php?x=1"), "example.com")
    assert a["is_https"] == 1 and b["is_https"] == 0
    assert a["has_www"] == 1 and b["has_www"] == 0
    assert a["path_len"] == 0 and b["path_has_ext_php_html"] == 1 and b["query_params"] == 1


def test_feature_values_for_known_phishing_shape():
    f = F.full_features(validate_url("http://user@secure-login.paypal.com.evil.tk:8080/verify"), "evil.tk")
    assert f["subdomain_labels"] == 3
    assert f["host_keyword_hits"] >= 2          # "secure", "login"
    assert f["tld_suspicious"] == 1
    assert f["has_userinfo"] == 1 and f["nonstandard_port"] == 1
    assert set(f) == set(F.FULL_FEATURES)


def test_ip_and_idn_flags():
    ip = _host("http://3232235777/x", "192.168.1.1")
    assert ip["is_ip"] == 1 and ip["ip_obfuscated"] == 1
    idn = _host("http://xn--pple-43d.com/", "xn--pple-43d.com")
    assert idn["is_idn"] == 1


def test_features_need_no_network(monkeypatch):
    import socket

    def deny(*a, **k):
        raise AssertionError("network access attempted")
    for name in ("create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, deny)
    F.full_features(validate_url("https://login.example.com/a"), "example.com")


# ---------------------------------------------------------------- metrics
def test_binary_metrics_known_values():
    y = np.array([1, 1, 1, 0, 0, 0, 0, 0])
    s = np.array([0.9, 0.8, 0.2, 0.7, 0.1, 0.1, 0.1, 0.1])
    m = binary_metrics(y, s, 0.5)
    assert m["confusion_matrix"] == {"tn": 4, "fp": 1, "fn": 1, "tp": 2}
    assert m["precision"] == pytest.approx(2 / 3) and m["recall"] == pytest.approx(2 / 3)
    assert m["fpr"] == pytest.approx(1 / 5)


@pytest.mark.parametrize("max_fpr", [0.0, 0.01, 0.05, 0.2])
def test_threshold_for_fpr_never_exceeds_target_on_its_own_data(max_fpr):
    rng = np.random.default_rng(0)
    y = rng.integers(0, 2, 3000)
    s = np.round(rng.random(3000) + y * 0.3, 2)   # rounding creates ties
    t = threshold_for_fpr(y, s, max_fpr)
    assert binary_metrics(y, s, t)["fpr"] <= max_fpr + 1e-12


def test_threshold_max_f1_finds_perfect_separation():
    y = np.array([0, 0, 1, 1])
    s = np.array([0.1, 0.2, 0.8, 0.9])
    assert binary_metrics(y, s, threshold_max_f1(y, s))["f1"] == 1.0


def test_ranking_metrics_single_class_is_none():
    assert ranking_metrics(np.array([1, 1]), np.array([0.2, 0.3])) == {"roc_auc": None, "pr_auc": None}
