"""URL feature extraction over a validated NormalizedURL."""
from __future__ import annotations

from .url_validation import NormalizedURL

FEATURE_NAMES: tuple[str, ...] = (
    "url_length", "domain_length", "path_length", "num_dots", "num_hyphens",
    "num_subdomains", "has_https", "has_ip", "has_at_symbol",
    "num_special_chars", "digits_in_domain", "suspicious_tld", "has_login",
    "has_verify", "has_secure", "has_account", "has_update", "has_query",
)

# FROZEN for model parity with the trained demo model: do not add entries
# (e.g. .info, .ru, .cn) until the approved ML phase.
SUSPICIOUS_TLDS: tuple[str, ...] = (
    ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top",
    ".club", ".online", ".site", ".buzz", ".link", ".click",
)

SPECIAL_CHARS = "!#$%^&*()=+[]{}|;:',<>?"


def extract_url_features(n: NormalizedURL) -> dict[str, int]:
    """Compute the 18 model features from a validated URL.

    Reads the hostname rather than the raw netloc, so ports and userinfo
    cannot hide the TLD. On the demo training data this is provably
    identical to the legacy extractor (checked by the parity tests).
    """
    url_lower = n.url.lower()
    host = n.hostname
    return {
        "url_length": len(n.url),
        "domain_length": len(host),
        "path_length": len(n.path),
        "num_dots": n.url.count("."),
        "num_hyphens": host.count("-"),
        "num_subdomains": host.count("."),
        "has_https": int(n.scheme == "https"),
        "has_ip": int(n.is_ip),
        "has_at_symbol": int("@" in n.url),
        "num_special_chars": sum(1 for c in n.url if c in SPECIAL_CHARS),
        "digits_in_domain": sum(1 for c in host if c.isdigit()),
        "suspicious_tld": int(any(host.endswith(t) for t in SUSPICIOUS_TLDS)),
        "has_login": int("login" in url_lower),
        "has_verify": int("verify" in url_lower),
        "has_secure": int("secure" in url_lower),
        "has_account": int("account" in url_lower),
        "has_update": int("update" in url_lower),
        "has_query": int(bool(n.query)),
    }
