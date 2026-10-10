"""Regression tests for URL validation edge cases found during security review."""
import pytest

from securemind.features import extract_url_features
from securemind.url_validation import URLValidationError, validate_url


@pytest.mark.parametrize(
    "raw, canonical",
    [
        # Fullwidth digits map to ASCII under UTS #46; browsers then treat
        # the host as an IPv4 address. It must not pass as a domain name.
        ("http://１２７.０.０.１/login", "127.0.0.1"),
        ("http://１９２.１６８.１.１/", "192.168.1.1"),
        ("http://０ｘ７ｆ０００００１/", "127.0.0.1"),
    ],
    ids=["fullwidth-dotted", "fullwidth-private", "fullwidth-hex"],
)
def test_fullwidth_digit_ip_is_detected_as_obfuscated_ip(raw, canonical):
    n = validate_url(raw)
    assert n.is_ip and n.ip_version == 4
    assert n.hostname == canonical
    assert n.ip_obfuscated
    assert extract_url_features(n)["has_ip"] == 1


def test_port_zero_is_rejected():
    with pytest.raises(URLValidationError) as exc:
        validate_url("http://a.com:0/")
    assert exc.value.code == "invalid_port"


def test_unicode_domain_still_treated_as_idn_not_ip():
    n = validate_url("http://раураl.com/")
    assert not n.is_ip
    assert n.is_idn and n.non_ascii_host
    assert n.hostname.startswith("xn--")


# WHATWG parity cases confirmed in the independent security review.
@pytest.mark.parametrize(
    "raw, host",
    [
        ("https://evil.com#@good.com", "evil.com"),
        ("https://evil.com;@good.com", "good.com"),
        ("https://evil.com%2f@good.com", "good.com"),
        ("https://a@b@evil.com", "evil.com"),
        ("http://0x/", "0.0.0.0"),
        ("http://0x7f.1/", "127.0.0.1"),
        ("http://[::ffff:127.0.0.1]/", "::ffff:7f00:1"),
        ("http://127。0。0。1/", "127.0.0.1"),
        ("example.com/r?u=https://x.example", "example.com"),
        ("localhost./", "localhost"),
    ],
)
def test_host_matches_browser_interpretation(raw, host):
    assert validate_url(raw).hostname == host


@pytest.mark.parametrize(
    "raw, host",
    [
        ("http://[::ffff:127.0.0.1]/", "::ffff:7f00:1"),
        ("http://[::FFFF:C0A8:101]:8080/", "::ffff:c0a8:101"),
        ("http://[2001:db8::1]/", "2001:db8::1"),
    ],
)
def test_ipv6_text_is_independent_of_python_version(monkeypatch, raw, host):
    """Newer CPython patch releases render IPv4-mapped addresses as
    '::ffff:127.0.0.1'. Simulate that and require the browser's hex form."""
    import ipaddress

    original = ipaddress.IPv6Address.compressed

    def mixed_notation(self):
        if self.ipv4_mapped is not None:
            return f"::ffff:{self.ipv4_mapped}"
        return original.fget(self)

    monkeypatch.setattr(ipaddress.IPv6Address, "compressed", property(mixed_notation))
    assert validate_url(raw).hostname == host


@pytest.mark.parametrize(
    "raw, code",
    [
        ("http://[fe80::1%25eth0]/", "invalid_host"),
        ("http://[::1]evil.com/", "malformed"),
        ("http://evil.com[::1]/", "malformed"),
        ("http://4294967296/", "invalid_ip"),
        ("http://08.0.0.1/", "invalid_ip"),
        ("javascript://x/%0aalert(1)", "scheme_not_allowed"),
    ],
)
def test_ambiguous_hosts_rejected(raw, code):
    with pytest.raises(URLValidationError) as exc:
        validate_url(raw)
    assert exc.value.code == code
