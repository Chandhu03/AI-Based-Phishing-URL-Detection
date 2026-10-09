"""Public Suffix List lookup (https://github.com/publicsuffix/list/wiki/Format).

Implements the documented algorithm: exception rules win, otherwise the
longest matching rule (including wildcards) prevails, with "*" as the
default rule. Both the ICANN and PRIVATE sections are used, so hosts on
shared platforms (for example `x.firebaseapp.com`) group by their owner.
Validated against the official test vectors (tests/test_psl.py).
"""
from __future__ import annotations

from pathlib import Path

import idna


def _to_ascii(label_or_name: str) -> str:
    if label_or_name.isascii():
        return label_or_name.lower()
    return idna.encode(label_or_name, uts46=True).decode("ascii")


class PublicSuffixList:
    def __init__(self, rules: list[str]):
        self.exact: set[str] = set()
        self.wildcard: set[str] = set()   # stored without the leading "*."
        self.exception: set[str] = set()  # stored without the leading "!"
        for rule in rules:
            if rule.startswith("!"):
                self.exception.add(_to_ascii(rule[1:]))
            elif rule.startswith("*."):
                self.wildcard.add(_to_ascii(rule[2:]))
            else:
                self.exact.add(_to_ascii(rule))

    @classmethod
    def from_file(cls, path: Path) -> "PublicSuffixList":
        rules = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("//"):
                rules.append(line.split()[0])
        return cls(rules)

    def public_suffix(self, host: str) -> str:
        """Public suffix of an ASCII (punycode) lowercase hostname."""
        labels = host.split(".")
        n = len(labels)
        best = 1  # implicit "*" rule matches the last label
        for i in range(n):
            name = ".".join(labels[i:])
            if name in self.exception:
                # The exception rule's suffix is one label shorter.
                return ".".join(labels[i + 1:])
            k = n - i
            if name in self.exact and k > best:
                best = k
            if i > 0 and name in self.wildcard and k + 1 > best:
                best = k + 1
        return ".".join(labels[n - best:])

    def registrable_domain(self, host: str) -> str | None:
        """eTLD+1 of a hostname, or None if the host is itself a public suffix."""
        host = host.lower().rstrip(".")
        if not host or host.startswith(".") or ".." in host:
            return None
        suffix = self.public_suffix(host)
        if host == suffix:
            return None
        rest = host[: -len(suffix) - 1]
        return rest.rsplit(".", 1)[-1] + "." + suffix


def check_official_vectors(psl: PublicSuffixList, vectors: Path) -> tuple[int, list[str]]:
    """Run the official `checkPublicSuffix(input, expected)` vectors.

    Returns (number passed, list of failure descriptions). Inputs are
    lowercased and converted to punycode first, as the test file assumes.
    """
    import re

    pattern = re.compile(r"^checkPublicSuffix\((null|'[^']*'), (null|'[^']*')\);")
    passed, failures = 0, []
    for line in vectors.read_text(encoding="utf-8").splitlines():
        m = pattern.match(line.strip())
        if not m:
            continue
        raw = None if m.group(1) == "null" else m.group(1)[1:-1]
        expected = None if m.group(2) == "null" else _to_ascii(m.group(2)[1:-1])
        try:
            got = None if raw is None else psl.registrable_domain(_to_ascii(raw))
        except idna.IDNAError:
            got = None
        if got == expected:
            passed += 1
        else:
            failures.append(f"{raw!r}: expected {expected!r}, got {got!r}")
    return passed, failures
