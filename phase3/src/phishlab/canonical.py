"""URL canonicalization that preserves security-relevant signals.

Reuses the application's validator (`securemind.url_validation`) unchanged,
so the research pipeline parses URLs exactly as the live app does: lowercase
host, punycode, WHATWG IPv4 forms, userinfo and port kept as signals, and no
silent https assumption. Path, query and fragment are kept verbatim.
"""
from __future__ import annotations

from dataclasses import dataclass

from securemind.url_validation import NormalizedURL, URLValidationError, validate_url

from .psl import PublicSuffixList


@dataclass(frozen=True)
class Canonical:
    ok: bool
    reason: str | None
    url: str | None
    host: str | None
    group: str | None          # registrable domain, IP literal, or host fallback
    n: NormalizedURL | None


def canonicalize(raw: object, psl: PublicSuffixList) -> Canonical:
    try:
        n = validate_url(raw)
    except URLValidationError as exc:
        return Canonical(False, exc.code, None, None, None, None)
    if n.is_ip:
        group = n.hostname
    else:
        group = psl.registrable_domain(n.hostname) or n.hostname
    return Canonical(True, None, n.url, n.hostname, group, n)
