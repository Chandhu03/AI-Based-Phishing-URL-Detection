import pytest

from securemind.url_validation import (
    ERROR_MESSAGES, MAX_URL_LENGTH, NormalizedURL, URLValidationError,
    validate_url,
)

PAD_BASE = "http://example.com/"

REJECT = [
    # (input, code or tuple of acceptable codes)
    ("", "empty"),
    ("   \t ", ("empty", "control_chars")),
    (None, "not_a_string"),
    (123, "not_a_string"),
    (b"http://a.com", "not_a_string"),
    pytest.param(PAD_BASE + "a" * (MAX_URL_LENGTH + 1 - len(PAD_BASE)), "too_long", id="2049"),
    pytest.param("a" * 10_000_000, "too_long", id="ten_mb"),
    ("http://a.com/\x00", "control_chars"),
    ("http://a.com/a\r\nb", "control_chars"),
    ("http://a.com/a\tb", "control_chars"),
    ("http://a.com/‮", "control_chars"),
    ("http://a.com/​", "control_chars"),
    ("http://exa mple.com", "whitespace"),
    ("http://a.com/a b", "whitespace"),
    ("https://evil.com\\@google.com", "backslash"),
    ("javascript:alert(1)", "scheme_not_allowed"),
    ("JaVaScRiPt:alert(1)", "scheme_not_allowed"),
    ("data:text/html,<script>", "scheme_not_allowed"),
    ("file:///etc/passwd", "scheme_not_allowed"),
    ("ftp://x.com", "scheme_not_allowed"),
    ("vbscript:x", "scheme_not_allowed"),
    ("mailto:a@b.com", "scheme_not_allowed"),
    ("http:/evil.com", "malformed"),
    ("https:evil.com", "malformed"),
    ("://x", "malformed"),
    ("http://", "missing_host"),
    ("/path/only", "missing_host"),
    ("http://evil.tk:99999/", "invalid_port"),
    ("http://evil.tk:abc/", "invalid_port"),
    ("evil.tk:abc/login", "scheme_not_allowed"),
    ("evil.tk..", "invalid_host"),
    ("http://a..b.com/", "invalid_host"),
    ("http://.a.com/", "invalid_host"),
    ("http://%65vil.com/", "invalid_host"),
    ("<img src=x onerror=alert(1)>", ("invalid_host", "missing_host", "whitespace")),
    ("<img/src=x/onerror=alert(1)>", ("invalid_host", "missing_host")),
    ("http://" + "a" * 64 + ".com/", "invalid_host"),
    ("http://" + ".".join(["a" * 60] * 5) + ".com/", "invalid_host"),
    ("http://-a.com/", "invalid_host"),
    ("1.2.3.4.5", "invalid_ip"),
    ("http://999.1.1.1/", "invalid_ip"),
    ("http://256.1.1.1/", "invalid_ip"),
    ("http://4294967296/", "invalid_ip"),
    ("http://09.1.1.1/", "invalid_ip"),
    ("http://[::1/", ("malformed", "invalid_ip")),
    ("http://[zzzz]/", ("malformed", "invalid_ip")),
    ("http://xn--zzzz-.com/", ("invalid_idn", "invalid_host")),
    ("http://xn--a.com/", ("invalid_idn", "invalid_host")),
]


@pytest.mark.parametrize("raw,code", REJECT)
def test_rejected(raw, code):
    codes = (code,) if isinstance(code, str) else code
    with pytest.raises(URLValidationError) as ei:
        validate_url(raw)
    e = ei.value
    assert e.code in codes
    assert e.code in ERROR_MESSAGES
    assert e.user_message == ERROR_MESSAGES[e.code]
    if isinstance(raw, str) and len(raw) <= 5000:
        msg = e.user_message
        for i in range(len(raw) - 3):
            assert raw[i:i + 4] not in msg, "message echoes input"


def test_exact_max_length_accepted():
    raw = PAD_BASE + "a" * (MAX_URL_LENGTH - len(PAD_BASE))
    assert len(raw) == MAX_URL_LENGTH
    assert validate_url(raw).hostname == "example.com"


def test_surrounding_whitespace_stripped():
    n = validate_url("  https://example.com/x \n")
    assert n.url == "https://example.com/x"


def test_basic_http_https():
    a = validate_url("http://example.com/a?b=1#c")
    assert (a.scheme, a.scheme_explicit, a.hostname) == ("http", True, "example.com")
    assert (a.path, a.query, a.fragment) == ("/a", "b=1", "c")
    assert a.url == "http://example.com/a?b=1#c"
    b = validate_url("https://example.com")
    assert b.scheme == "https" and b.path == "" and b.port is None
    assert not b.nonstandard_port and not b.is_ip and b.notes == ()


def test_mixed_case():
    n = validate_url("HTTPS://EVIL.TK/login")
    assert n.scheme == "https" and n.hostname == "evil.tk"
    assert n.path == "/login"


def test_userinfo_password_never_leaks():
    n = validate_url("http://user:pw@evil.tk/")
    assert n.has_userinfo and n.hostname == "evil.tk"
    for text in (n.hostname, n.hostname_display, *n.notes):
        assert "pw" not in text and "user" not in text


def test_at_confusion():
    n = validate_url("http://paypal.com@evil.tk/")
    assert n.hostname == "evil.tk" and n.has_userinfo


def test_schemeless_with_port():
    n = validate_url("evil.tk:443/login")
    assert not n.scheme_explicit and n.scheme == "http"
    assert n.hostname == "evil.tk" and n.port == 443 and n.path == "/login"
    assert any("http://" in x for x in n.notes)


def test_nonstandard_port():
    assert validate_url("http://a.com:8080/").nonstandard_port
    assert not validate_url("http://a.com:80/").nonstandard_port
    assert not validate_url("https://a.com:443/").nonstandard_port
    assert validate_url("https://a.com:80/").nonstandard_port
    assert validate_url("a.com:8080").port == 8080


def test_trailing_dot():
    assert validate_url("evil.tk.").hostname == "evil.tk"
    assert validate_url("http://evil.tk./x").hostname == "evil.tk"


@pytest.mark.parametrize("host,canon,obf", [
    ("192.168.1.100", "192.168.1.100", False),
    ("3232235777", "192.168.1.1", True),
    ("0xC0A80101", "192.168.1.1", True),
    ("0300.0250.1.1", "192.168.1.1", True),
    ("127.1", "127.0.0.1", True),
    ("0x7f.1", "127.0.0.1", True),
    ("192.168.001.1", "192.168.1.1", True),
    ("0.0.0.0", "0.0.0.0", False),
])
def test_ipv4(host, canon, obf):
    n = validate_url(f"http://{host}/x")
    assert n.is_ip and n.ip_version == 4
    assert n.hostname == canon and n.ip_obfuscated is obf
    assert n.url == f"http://{canon}/x"
    assert any("IP address" in x for x in n.notes)


def test_ipv6():
    n = validate_url("http://[::1]/")
    assert n.is_ip and n.ip_version == 6 and n.hostname == "::1"
    assert n.url == "http://[::1]/"
    m = validate_url("http://[2001:db8::1]:8080/")
    assert m.hostname == "2001:db8::1" and m.port == 8080 and m.nonstandard_port
    assert m.url == "http://[2001:db8::1]:8080/"


def test_idn_punycode():
    n = validate_url("http://xn--pypal-4ve.com/")
    assert n.is_idn and n.non_ascii_host
    assert n.hostname == "xn--pypal-4ve.com"
    assert not n.hostname_display.isascii()


def test_idn_unicode_cyrillic():
    n = validate_url("http://раураl.com/")
    assert n.is_idn and n.non_ascii_host
    assert n.hostname.startswith("xn--") and n.hostname.isascii()
    assert n.hostname_display == "раураl.com"
    assert any("international" in x for x in n.notes)


def test_fullwidth_maps_to_ascii():
    n = validate_url("ｅｘａｍｐｌｅ．ｃｏｍ")
    assert n.hostname == "example.com"
    assert n.is_idn and not n.non_ascii_host


def test_scheme_like_hostname_not_scheme():
    n = validate_url("httpsecure-login-paypal.xyz/verify")
    assert not n.scheme_explicit and n.hostname == "httpsecure-login-paypal.xyz"
    assert n.path == "/verify"


def test_percent_encoded_path_ok():
    n = validate_url("http://a.com/a%20b?x=%41")
    assert n.path == "/a%20b" and n.query == "x=%41"


def test_label_and_host_limits():
    assert validate_url("http://" + "a" * 63 + ".com/").hostname.startswith("a" * 63)
    host = ".".join(["a" * 61] * 4) + ".com"  # 61*4+3+4 = 251
    assert len(host) <= 253
    assert validate_url(f"http://{host}/").hostname == host
    assert len(host + ".abc") > 253
    with pytest.raises(URLValidationError) as ei:
        validate_url(f"http://{host}.abc/")
    assert ei.value.code == "invalid_host"


def test_underscore_label_lenient():
    assert validate_url("http://a_b.example.com").hostname == "a_b.example.com"


def test_empty_query_dropped():
    assert validate_url("http://a.com/x?").url == "http://a.com/x"


def test_notes_are_static_and_input_free():
    secret = "zzSecretPw9"
    n = validate_url(f"user{secret}@evil{secret}.tk:8080/p")
    assert isinstance(n, NormalizedURL)
    assert n.has_userinfo and n.nonstandard_port and not n.scheme_explicit
    joined = " ".join(n.notes)
    for frag in (secret, "evil", "8080", "user"):
        assert frag not in joined
    assert len(n.notes) >= 3


def test_all_codes_have_messages():
    for code in ["not_a_string", "empty", "too_long", "control_chars", "whitespace",
                 "backslash", "scheme_not_allowed", "malformed", "missing_host",
                 "invalid_port", "invalid_host", "invalid_ip", "invalid_idn"]:
        assert ERROR_MESSAGES[code]


def test_never_assumes_https():
    assert validate_url("example.com").scheme == "http"
