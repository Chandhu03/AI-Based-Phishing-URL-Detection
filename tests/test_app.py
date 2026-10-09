"""App-level regression and security tests using streamlit.testing.v1.AppTest.

AppTest runs app.py in-process, so monkeypatching modules and sockets applies.
Note: AppTest's set_value bypasses the browser-side max_chars, so the
server-side length limit is exercised directly. server.maxMessageSize only
applies to a real Streamlit server and cannot be tested here.
"""
from __future__ import annotations

import logging
import re
import socket
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

from securemind.url_validation import ERROR_MESSAGES, MAX_URL_LENGTH

APP = str(Path(__file__).resolve().parent.parent / "app.py")
TIMEOUT = 180

GENERIC_ERROR = ("The URL could not be analysed because of an internal error. "
                 "No details are shown.")
PHISH_HEAD = "Phishing indicators detected in the URL text"
BENIGN_HEAD = "No phishing indicators detected in the URL text"
NOT_CHECKED = "The website itself was not checked."
LIMITATIONS = [
    "This demo examines the characters of the URL string only.",
    "The website is not visited, fetched, or resolved.",
    "No live reputation or blocklist lookup is performed.",
    "False positives and false negatives are possible.",
    "A result is not a security guarantee.",
    "The live model is a demonstration trained on synthetic URLs and has not "
    "been evaluated on real-world data.",
]
VOTE_RE = re.compile(
    r"Model vote share: \d{1,3}% of trees agreed\. This is not a calibrated probability\.")
FORBIDDEN_WORDING = ["Appears Safe", "Safety confidence", "Threat confidence"]

EXAMPLES = {
    "Example: google.com": "benign",
    "Example: phishing-style URL": "phish",
    "Example: raw IP host": "phish",
}


# ---------------------------------------------------------------- helpers
def new_app() -> AppTest:
    return AppTest.from_file(APP, default_timeout=TIMEOUT).run()


def submit(url: str) -> AppTest:
    at = new_app()
    at.text_input(key="url_input").set_value(url)
    return at.run()


def click(label: str) -> AppTest:
    at = new_app()
    matches = [b for b in at.button if b.label == label]
    assert matches, f"button {label!r} not found"
    matches[0].click()
    return at.run()


def md_values(at):
    return [m.value for m in at.markdown]


def text_elements(at):
    """Every rendered text-bearing element as (kind, value)."""
    out = []
    for kind in ("markdown", "error", "code", "caption", "text", "info",
                 "warning", "success", "exception"):
        for el in getattr(at, kind):
            out.append((kind, str(el.value)))
    return out


def all_text(at) -> str:
    return "\n".join(v for _, v in text_elements(at))


def non_code_text(at) -> str:
    return "\n".join(v for k, v in text_elements(at) if k != "code")


def html_markdown(at):
    return [m.value for m in at.markdown if m.proto.allow_html]


def has_result(at) -> bool:
    t = all_text(at)
    return PHISH_HEAD in t or BENIGN_HEAD in t


def is_phish(at) -> bool:
    return PHISH_HEAD in "\n".join(md_values(at))


def is_benign(at) -> bool:
    return BENIGN_HEAD in "\n".join(md_values(at))


def assert_limitations(at):
    t = "\n".join(md_values(at) + [str(c.value) for c in at.caption])
    for s in LIMITATIONS:
        assert s in t, f"missing limitation sentence: {s}"
    assert "Limitations" in t


@pytest.fixture(scope="module", autouse=True)
def _warm_model():
    """Train/cache the demo model once so later tests are fast."""
    new_app()


# ------------------------------------------------------------- 1. examples
@pytest.mark.parametrize("label,kind", list(EXAMPLES.items()))
def test_quick_test_buttons(label, kind):
    at = click(label)
    assert not at.exception
    assert not at.error
    if kind == "phish":
        assert is_phish(at), "expected phishing heading"
        assert not is_benign(at)
    else:
        assert is_benign(at), "expected benign heading"
        assert not is_phish(at)
        assert NOT_CHECKED in all_text(at)
    assert_limitations(at)


# ------------------------------------------------------ 2. HTML/JS injection
INJECTION = [
    "<img src=x onerror=alert(1)>",
    '"><script>alert(1)</script>',
    "http://evil.tk/<script>alert(1)</script>",
    "http://evil.tk/?q=<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
]


@pytest.mark.parametrize("payload", INJECTION)
def test_injection_not_rendered_as_html(payload):
    at = submit(payload)
    assert not at.exception
    for v in html_markdown(at):
        assert payload not in v
        for bad in ("<script", "onerror", "javascript:"):
            assert bad not in v, f"{bad!r} in allow_html markdown"
    # user input must never be rendered through markdown at all
    for v in md_values(at):
        assert payload not in v
    for e in at.error:
        assert payload not in e.value
        for bad in ("<script", "onerror", "javascript:"):
            assert bad not in e.value
    # only st.code may hold user-derived text
    nc = non_code_text(at)
    assert payload not in nc
    for bad in ("<script", "onerror"):
        assert bad not in nc


# ------------------------------------------------------------ 3. invalid input
INVALID = [
    ("javascript:alert(1)", "scheme_not_allowed"),
    ("data:text/html,x", "scheme_not_allowed"),
    ("http://", None),  # code derived from the validator below
    ("http://exa\x00mple.com", "control_chars"),
    ("http://exa\u202emple.com", "control_chars"),
    ("https://evil.com\\@google.com", "backslash"),
]


def _expected_code(raw):
    from securemind.url_validation import URLValidationError, validate_url
    with pytest.raises(URLValidationError) as ei:
        validate_url(raw)
    return ei.value.code


@pytest.mark.parametrize("raw,code", INVALID)
def test_invalid_inputs_show_exact_message(raw, code):
    code = code or _expected_code(raw)
    at = submit(raw)
    assert not at.exception
    assert [e.value for e in at.error] == [ERROR_MESSAGES[code]]
    assert not has_result(at)
    # input is never echoed outside the input widget
    assert raw not in all_text(at)


def test_empty_input_is_neutral():
    at = submit("")
    assert not at.exception
    assert not has_result(at)
    errs = [e.value for e in at.error]
    # neutral placeholder state, or at most the exact 'empty' message
    assert errs in ([], [ERROR_MESSAGES["empty"]])


# ------------------------------------------------------------- 4. length
@pytest.mark.parametrize("n", [MAX_URL_LENGTH + 1, 10 * 1024 * 1024])
@pytest.mark.parametrize("prefix", ["", "http://example.com/"])
def test_overlong_input_rejected_not_truncated(n, prefix):
    """Streamlit 1.65 truncates widget text to max_chars server-side. The app
    sets max_chars to MAX_URL_LENGTH + 1 so that over-long input is bounded
    by the framework AND still reaches validate_url, which rejects it with
    the explicit too_long message. It must never be silently truncated to a
    valid-looking URL and analysed."""
    at = submit(prefix + "a" * n)
    assert not at.exception
    assert len(at.text_input(key="url_input").value) <= MAX_URL_LENGTH + 1
    assert [e.value for e in at.error] == [ERROR_MESSAGES["too_long"]]
    assert not has_result(at)
    assert "a" * 100 not in non_code_text(at)


def test_exactly_max_length_url_is_analysed():
    prefix = "http://example.com/"
    url = prefix + "a" * (MAX_URL_LENGTH - len(prefix))
    assert len(url) == MAX_URL_LENGTH
    at = submit(url)
    assert not at.exception
    assert not at.error
    assert has_result(at)
    assert_limitations(at)


# ------------------------------------------------------------- 5. no network
def _deny(*a, **k):
    raise AssertionError("network access attempted")


def _is_loopback(addr) -> bool:
    return isinstance(addr, tuple) and addr and addr[0] in ("127.0.0.1", "::1")


@pytest.fixture
def no_network(monkeypatch):
    """Block all outbound network access.

    Documented exception: on Windows, asyncio (used internally by AppTest /
    Streamlit when creating an event loop) builds a loopback socketpair via
    socket.connect(('127.0.0.1', port)). Loopback connects are therefore
    allowed; anything else raises. DNS and create_connection are fully denied.
    """
    real_connect = socket.socket.connect
    real_connect_ex = socket.socket.connect_ex

    def guarded_connect(self, addr):
        if not _is_loopback(addr):
            _deny()
        return real_connect(self, addr)

    def guarded_connect_ex(self, addr):
        if not _is_loopback(addr):
            _deny()
        return real_connect_ex(self, addr)

    for name in ("create_connection", "getaddrinfo", "gethostbyname"):
        monkeypatch.setattr(socket, name, _deny)
    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)


def test_no_network_during_analysis(no_network):
    # The patch spans the whole app run (AppTest needs no real socket).
    urls = ["http://secure-paypal-login.xyz/verify?token=1",
            "https://www.google.com/", "http://192.168.1.100/chase/login",
            "http://xn--pypal-4ve.com/", "evil.tk:443/login"]
    for u in urls:
        at = submit(u)
        assert not at.exception, u
        assert has_result(at), u
    for label in EXAMPLES:
        at = click(label)
        assert not at.exception, label
        assert has_result(at), label


def test_no_network_during_model_training(no_network):
    from securemind.demo_model import train_demo_model
    model, scaler = train_demo_model()
    assert model is not None and scaler is not None


# ------------------------------------------------------ 6. no logging of URL
def test_url_not_logged_or_printed(capsys, caplog):
    caplog.set_level(logging.DEBUG)
    logging.getLogger().setLevel(logging.DEBUG)
    marker_url = "http://marker-7f3a9c.example/path?token=SECRET123"
    at = submit(marker_url)
    assert not at.exception
    assert has_result(at)
    out = capsys.readouterr()
    blob = out.out + out.err + "\n".join(
        r.getMessage() + repr(r.args) + str(r.exc_text) for r in caplog.records)
    for m in ("marker-7f3a9c", "SECRET123"):
        assert m not in blob
    # the secret must not leak into non-code rendered output either
    assert "SECRET123" not in non_code_text(at)


# ------------------------------------------------- 7. internal error handling
def test_internal_error_not_disclosed(monkeypatch):
    import securemind.demo_model as dm
    import securemind.features as feat

    def boom(*a, **k):
        raise RuntimeError("C:\\secret\\path TRACE_MARKER_123")

    monkeypatch.setattr(dm, "predict", boom)
    monkeypatch.setattr(dm, "extract_url_features", boom)
    monkeypatch.setattr(feat, "extract_url_features", boom)
    at = submit("http://secure-paypal-login.xyz/verify?token=456789")
    assert [e.value for e in at.error] == [GENERIC_ERROR]
    assert not at.exception
    assert not has_result(at)
    blob = all_text(at)
    for bad in ("TRACE_MARKER_123", "Traceback", "secret", "RuntimeError"):
        assert bad not in blob


# ------------------------------------------------------- 8. honest wording
@pytest.mark.parametrize("url", [
    "https://www.google.com/search?q=weather",
    "https://github.com/python/cpython",
    "http://secure-paypal-login.xyz/verify?token=456789",
    "http://192.168.1.100/chase/login",
    "http://paypal.com.account-verify.tk/signin",
])
def test_honest_wording(url):
    at = submit(url)
    assert not at.exception and not at.error
    assert has_result(at)
    t = all_text(at)
    for bad in FORBIDDEN_WORDING:
        assert bad not in t
    assert VOTE_RE.search("\n".join(md_values(at) + [c.value for c in at.caption]))
    if is_benign(at):
        assert NOT_CHECKED in t
    assert_limitations(at)


# ----------------------------------------------------- 9. evasion normalised
@pytest.mark.parametrize("raw", [
    "HTTPS://EVIL.TK/login", "evil.tk:443/login", "http://user@evil.tk/",
])
def test_evasions_normalised_host(raw):
    at = submit(raw)
    assert not at.exception
    assert not at.error
    codes = [str(c.value) for c in at.code]
    assert "evil.tk" in codes, codes
    assert has_result(at)
    # userinfo never displayed
    assert "user@" not in all_text(at)


# ------------------------------------------------- 10. benchmark/badge wording
def test_benchmark_labelling_and_badge():
    at = new_app()
    t = "\n".join(md_values(at) + [c.value for c in at.caption])
    assert "It is not used for live URL checks" in t
    assert "Offline research benchmark (not the live model)" in t
    assert "Demo model loaded" in t
    assert not at.exception


# ------------------------------------------------- 11. render sinks (hostile)
HOSTILE = [
    "<img src=x onerror=alert(1)>",
    "<script>alert(1)</script>",
    "[click](javascript:alert(1))",
    "![](http://tracker.example/p.png)",
]


def test_hostile_strings_reach_only_code_elements(monkeypatch):
    """Validation normally makes hostile hosts impossible, so this bypasses it:
    a NormalizedURL carrying hostile text must still render only via st.code,
    never in markdown, HTML, captions or errors."""
    import dataclasses

    import securemind.url_validation as uv

    real = uv.validate_url
    hostile_display = " ".join(HOSTILE)

    def fake_validate(raw):
        n = real("http://evil.tk/login")
        return dataclasses.replace(
            n, hostname="<b>hostile-ascii</b>", hostname_display=hostile_display)

    monkeypatch.setattr(uv, "validate_url", fake_validate)
    at = submit("http://anything.example/")
    assert not at.exception
    assert has_result(at)
    codes = [str(c.value) for c in at.code]
    assert hostile_display in codes and "<b>hostile-ascii</b>" in codes
    rendered = non_code_text(at)
    for s in HOSTILE + ["hostile-ascii"]:
        assert s not in rendered
    for m in html_markdown(at):
        assert "onerror" not in m and "<script" not in m and "javascript:" not in m


def test_unexpected_validator_error_is_generic(monkeypatch):
    """An unexpected exception inside validation (whose message could contain
    the URL) must produce only the generic error, never details."""
    import securemind.url_validation as uv

    def boom(raw):
        raise RuntimeError("TRACE_MARKER_VALIDATOR " + str(raw))

    monkeypatch.setattr(uv, "validate_url", boom)
    at = submit("http://marker-validator.example/")
    assert not at.exception
    assert [e.value for e in at.error] == [GENERIC_ERROR]
    t = all_text(at)
    assert "TRACE_MARKER_VALIDATOR" not in t and "marker-validator" not in t
    assert not has_result(at)
