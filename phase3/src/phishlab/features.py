"""Explainable lexical features, computed only from the URL text.

Two views:

* HOST view: features of the hostname alone, after removing one leading
  "www." label. It cannot see the scheme, a "www." prefix, the path or the
  query. PhiUSIIL's legitimate class is 100% "https://www.<domain>" with no
  path (see DATASET_REVIEW.md), so any feature that sees those properties
  learns a dataset artefact instead of phishing behaviour.
* FULL view: HOST view plus scheme, path, query and URL-structure features.
  Only trained on data whose legitimate class has realistic URLs.

No feature performs network access (no DNS, WHOIS or page fetches).
"""
from __future__ import annotations

import math
from collections import Counter

import numpy as np

from securemind.features import SUSPICIOUS_TLDS
from securemind.url_validation import NormalizedURL

KEYWORDS = ("login", "signin", "verify", "secure", "account", "update", "confirm",
            "bank", "password", "wallet", "auth", "support", "billing", "recover")

HOST_FEATURES = (
    "host_len", "host_labels", "subdomain_labels", "reg_label_len", "reg_label_entropy",
    "reg_label_digits", "reg_label_hyphens", "host_digits", "host_digit_ratio",
    "host_hyphens", "host_max_label_len", "host_entropy", "host_vowel_ratio",
    "host_keyword_hits", "tld_len", "tld_suspicious", "is_ip", "ip_obfuscated", "is_idn",
)
FULL_ONLY_FEATURES = (
    "is_https", "has_www", "url_len", "path_len", "path_depth", "query_len",
    "query_params", "has_fragment", "path_digits", "path_special", "pct_encoded",
    "path_keyword_hits", "double_slash_in_path", "path_has_ext_php_html",
    "has_userinfo", "nonstandard_port", "has_at",
)
FULL_FEATURES = HOST_FEATURES + FULL_ONLY_FEATURES


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def strip_www(host: str) -> str:
    return host[4:] if host.startswith("www.") and host.count(".") >= 2 else host


def host_features(n: NormalizedURL, group: str) -> dict[str, float]:
    host = strip_www(n.hostname)
    if n.is_ip:
        reg_label, tld, sub = "", "", 0
    else:
        reg_label = group.split(".", 1)[0]
        tld = host.rsplit(".", 1)[-1]
        sub = max(0, host.count(".") - group.count("."))
    labels = host.split(".")
    letters = [c for c in host if c.isalpha()]
    return {
        "host_len": len(host),
        "host_labels": len(labels),
        "subdomain_labels": sub,
        "reg_label_len": len(reg_label),
        "reg_label_entropy": _entropy(reg_label),
        "reg_label_digits": sum(c.isdigit() for c in reg_label),
        "reg_label_hyphens": reg_label.count("-"),
        "host_digits": sum(c.isdigit() for c in host),
        "host_digit_ratio": sum(c.isdigit() for c in host) / max(1, len(host)),
        "host_hyphens": host.count("-"),
        "host_max_label_len": max(len(lbl) for lbl in labels),
        "host_entropy": _entropy(host),
        "host_vowel_ratio": sum(c in "aeiou" for c in letters) / max(1, len(letters)),
        "host_keyword_hits": sum(k in host for k in KEYWORDS),
        "tld_len": len(tld),
        "tld_suspicious": int(any(("." + host).endswith(t) for t in SUSPICIOUS_TLDS)),
        "is_ip": int(n.is_ip),
        "ip_obfuscated": int(n.ip_obfuscated),
        "is_idn": int(n.is_idn),
    }


def full_features(n: NormalizedURL, group: str) -> dict[str, float]:
    f = host_features(n, group)
    path, query = n.path, n.query
    path_l = path.lower()
    f.update({
        "is_https": int(n.scheme == "https" and n.scheme_explicit),
        "has_www": int(n.hostname.startswith("www.")),
        "url_len": len(n.url),
        "path_len": len(path),
        "path_depth": len([s for s in path.split("/") if s]),
        "query_len": len(query),
        "query_params": len([p for p in query.split("&") if p]) if query else 0,
        "has_fragment": int(bool(n.fragment)),
        "path_digits": sum(c.isdigit() for c in path),
        "path_special": sum(c in "-_.~!$&'()*+,;=:@" for c in path),
        "pct_encoded": n.url.count("%"),
        "path_keyword_hits": sum(k in path_l or k in query.lower() for k in KEYWORDS),
        "double_slash_in_path": int("//" in path),
        "path_has_ext_php_html": int(path_l.endswith((".php", ".html", ".htm", ".asp", ".aspx"))),
        "has_userinfo": int(n.has_userinfo),
        "nonstandard_port": int(n.nonstandard_port),
        "has_at": int("@" in n.url),
    })
    return f


def matrix(rows: list[dict[str, float]], names: tuple[str, ...]) -> np.ndarray:
    return np.array([[r[k] for k in names] for r in rows], dtype=np.float64)


def host_text(n: NormalizedURL) -> str:
    """Text used by the character n-gram model in the HOST view."""
    return strip_www(n.hostname)


def full_text(n: NormalizedURL) -> str:
    """Text used by the character n-gram model in the FULL view (no scheme)."""
    return n.url.split("://", 1)[1]
