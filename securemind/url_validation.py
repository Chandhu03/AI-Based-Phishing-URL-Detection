"""Strict, offline URL validation and normalization.

Never touches the network (no DNS, no sockets). Error messages are fixed
sentences and never echo any part of the input.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit

import idna

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = frozenset({"http", "https"})

ERROR_MESSAGES: dict[str, str] = {
    "not_a_string": "The input must be text.",
    "empty": "Please enter a URL.",
    "too_long": "That URL is too long to analyse (limit is 2048 characters).",
    "control_chars": "The URL contains hidden or control characters, which are not allowed.",
    "whitespace": "The URL contains spaces or other whitespace, which are not allowed.",
    "backslash": "The URL contains a backslash, which is ambiguous. Use forward slashes.",
    "scheme_not_allowed": "Only http and https URLs can be analysed.",
    "malformed": "That does not look like a well-formed URL.",
    "missing_host": "The URL has no host name.",
    "invalid_port": "The URL has an invalid port number.",
    "invalid_host": "The URL has an invalid host name.",
    "invalid_ip": "The URL has an invalid IP address.",
    "invalid_idn": "The URL has an invalid internationalized domain name.",
}


class URLValidationError(ValueError):
    def __init__(self, code: str, user_message: str):
        super().__init__(code)
        self.code = code
        self.user_message = user_message


def _err(code: str) -> URLValidationError:
    return URLValidationError(code, ERROR_MESSAGES[code])


@dataclass(frozen=True)
class NormalizedURL:
    url: str
    scheme: str
    scheme_explicit: bool
    hostname: str
    hostname_display: str
    is_ip: bool
    ip_version: int | None
    ip_obfuscated: bool
    is_idn: bool
    non_ascii_host: bool
    port: int | None
    nonstandard_port: bool
    has_userinfo: bool
    path: str
    query: str
    fragment: str
    notes: tuple[str, ...]


_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*$")
_SCHEME_COLON_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")
_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$")
_DIGITS_RE = re.compile(r"^[0-9]+$")
_HEX_RE = re.compile(r"^0[xX][0-9a-fA-F]*$")
_DEFAULT_PORTS = {"http": 80, "https": 443}


def _parse_ipv4_label(label: str) -> int:
    if _HEX_RE.match(label):
        return int(label[2:], 16) if len(label) > 2 else 0
    if not _DIGITS_RE.match(label):
        raise ValueError
    if len(label) > 1 and label[0] == "0":
        return int(label, 8)  # ValueError on digits 8/9
    return int(label, 10)


def _ends_in_number(labels: list[str]) -> bool:
    last = labels[-1]
    return bool(_DIGITS_RE.match(last) or _HEX_RE.match(last))


def validate_url(raw: object) -> NormalizedURL:
    # 1. type and length (before any other processing, keeps work bounded)
    if not isinstance(raw, str):
        raise _err("not_a_string")
    if len(raw) > MAX_URL_LENGTH:
        raise _err("too_long")

    # 2. whitespace
    s = raw.strip()
    if not s:
        raise _err("empty")

    # 3. forbidden characters
    for ch in s:
        if unicodedata.category(ch) in ("Cc", "Cf"):
            raise _err("control_chars")
    if any(ch.isspace() for ch in s):
        raise _err("whitespace")
    if "\\" in s:
        raise _err("backslash")

    # 4. scheme detection (never assume https)
    scheme_explicit = True
    sep = s.find("://")
    # A "://" only marks a scheme if it comes before any path, query or
    # fragment delimiter; "example.com/r?u=https://x" is scheme-less.
    if sep != -1 and not any(c in s[:sep] for c in "/?#"):
        scheme_text = s[:sep]
        if not _SCHEME_RE.match(scheme_text):
            raise _err("malformed")
        scheme = scheme_text.lower()
        if scheme not in ALLOWED_SCHEMES:
            raise _err("scheme_not_allowed")
        to_parse = s
    else:
        m = _SCHEME_COLON_RE.match(s)
        if m and not s[m.end():m.end() + 1].isdigit():
            if m.group(0)[:-1].lower() in ALLOWED_SCHEMES:
                raise _err("malformed")
            raise _err("scheme_not_allowed")
        scheme = "http"
        scheme_explicit = False
        to_parse = "http://" + s

    # 5. parsing
    try:
        parts = urlsplit(to_parse)
        port = parts.port
    except ValueError as exc:
        # urlsplit raises for bad brackets; parts.port for bad ports.
        if "port" in str(exc).lower():
            raise _err("invalid_port") from None
        raise _err("malformed") from None
    if port == 0:
        raise _err("invalid_port")
    host = parts.hostname
    if not host:
        raise _err("missing_host")
    netloc = parts.netloc
    has_userinfo = "@" in netloc
    userinfo, _, hostport = netloc.rpartition("@")
    bracketed = hostport.startswith("[")

    # 6. hostname
    if "%" in host:
        raise _err("invalid_host")
    if host.endswith("."):
        host = host[:-1]
    if not host or host.endswith(".") or any(lbl == "" for lbl in host.split(".")):
        raise _err("invalid_host")
    if len(host) > 253:
        raise _err("invalid_host")

    is_ip = False
    ip_version: int | None = None
    ip_obfuscated = False
    is_idn = False
    non_ascii_host = False
    display = host

    if bracketed:
        # 7. IPv6
        try:
            addr6 = ipaddress.IPv6Address(host)
        except ValueError:
            raise _err("invalid_ip") from None
        host = display = addr6.compressed
        is_ip, ip_version = True, 6
    else:
        # 9a. Map non-ASCII hosts to ASCII (UTS #46) BEFORE the IPv4 check,
        # matching browser order: fullwidth digits such as "１２７.０.０.１"
        # map to "127.0.0.1" and must be classified as an IP address.
        if not host.isascii():
            try:
                host = idna.encode(host, uts46=True).decode("ascii")
            except (idna.IDNAError, UnicodeError):
                raise _err("invalid_idn") from None
            is_idn = True
            if host.endswith("."):
                host = host[:-1]
            if not host or any(lbl == "" for lbl in host.split(".")):
                raise _err("invalid_host")
            if len(host) > 253:
                raise _err("invalid_host")
        labels = host.split(".")
        if _ends_in_number(labels):
            # 8. numeric IPv4 (WHATWG "ends in a number")
            if len(labels) > 4:
                raise _err("invalid_ip")
            try:
                vals = [_parse_ipv4_label(lbl) for lbl in labels]
            except ValueError:
                raise _err("invalid_ip") from None
            if any(v > 255 for v in vals[:-1]):
                raise _err("invalid_ip")
            if vals[-1] >= 256 ** (5 - len(vals)):
                raise _err("invalid_ip")
            num = vals[-1]
            for i, v in enumerate(vals[:-1]):
                num += v * 256 ** (3 - i)
            canonical = str(ipaddress.IPv4Address(num))
            ip_obfuscated = host != canonical
            # Non-ASCII digits that mapped to an IP are also a disguise.
            ip_obfuscated = ip_obfuscated or is_idn
            host = display = canonical
            is_ip, ip_version = True, 4
            is_idn = False
        else:
            # 9b. domain names
            disp_labels = []
            for label in host.split("."):
                if not (1 <= len(label) <= 63) or not _LABEL_RE.match(label):
                    raise _err("invalid_host")
                if label.startswith("xn--"):
                    try:
                        disp_labels.append(idna.decode(label))
                    except (idna.IDNAError, UnicodeError):
                        raise _err("invalid_idn") from None
                    is_idn = True
                else:
                    disp_labels.append(label)
            display = ".".join(disp_labels)
            non_ascii_host = not display.isascii()

    # 10. normalized URL
    # Note: a bare "?" with an empty query is dropped in the normalized form.
    # userinfo is used in memory for features only and is never displayed.
    url = (
        f"{scheme}://"
        + (userinfo + "@" if has_userinfo else "")
        + (f"[{host}]" if bracketed else host)
        + (f":{port}" if port is not None else "")
        + parts.path
        + ("?" + parts.query if parts.query else "")
        + ("#" + parts.fragment if parts.fragment else "")
    )

    # 11. final field and static notes
    nonstandard_port = port is not None and port != _DEFAULT_PORTS[scheme]
    notes: list[str] = []
    if not scheme_explicit:
        notes.append("No http:// or https:// was given, so the link was analysed as plain http.")
    if has_userinfo:
        notes.append("The URL contains login details before the host; the real host is the part after the last @ sign.")
    if nonstandard_port:
        notes.append("The URL uses a non-standard port.")
    if ip_obfuscated:
        notes.append("The host is an IP address written in a disguised numeric form.")
    if is_idn or non_ascii_host:
        notes.append("The host uses international characters, which can imitate familiar domains.")
    if is_ip:
        notes.append("The host is a raw IP address rather than a domain name.")

    return NormalizedURL(
        url=url, scheme=scheme, scheme_explicit=scheme_explicit,
        hostname=host, hostname_display=display, is_ip=is_ip,
        ip_version=ip_version, ip_obfuscated=ip_obfuscated, is_idn=is_idn,
        non_ascii_host=non_ascii_host, port=port,
        nonstandard_port=nonstandard_port, has_userinfo=has_userinfo,
        path=parts.path, query=parts.query, fragment=parts.fragment,
        notes=tuple(notes),
    )
