import pytest

from securemind.features import FEATURE_NAMES, extract_url_features
from securemind.url_validation import validate_url
from tests import legacy_reference


def feats(u):
    return extract_url_features(validate_url(u))


@pytest.mark.parametrize("u", [
    "HTTPS://EVIL.TK/login", "evil.tk:443/login", "http://user@evil.tk/",
    "http://paypal.com@evil.tk/", "evil.tk.",
])
def test_suspicious_tld_not_evaded(u):
    assert feats(u)["suspicious_tld"] == 1


@pytest.mark.parametrize("u", [
    "http://3232235777/", "http://0xC0A80001/", "http://0300.0250.1.1/",
    "http://127.1/", "http://[::1]/", "http://192.168.1.1/",
])
def test_ip_flag(u):
    assert feats(u)["has_ip"] == 1


def test_schemeless_has_no_https():
    assert feats("example.com/login")["has_https"] == 0
    assert feats("httpsecure-login-paypal.xyz/verify")["has_https"] == 0
    assert feats("https://example.com")["has_https"] == 1


def test_keys_order():
    assert tuple(feats("https://example.com")) == FEATURE_NAMES
    assert len(FEATURE_NAMES) == 18


@pytest.mark.parametrize("u", [
    "https://www.google.com/search?q=weather",
    "http://secure-paypal-login.xyz/verify?token=456789",
    "http://192.168.1.100/chase/login",
])
def test_quick_test_urls_match_legacy(u):
    assert feats(u) == legacy_reference.extract_url_features(u)
