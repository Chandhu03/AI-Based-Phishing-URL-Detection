"""Explicit, verified downloads of the pinned sources (never import-time).

Only the dataset files themselves are fetched. URLs *inside* the datasets are
treated strictly as text and are never requested, resolved or opened.
"""
from __future__ import annotations

import hashlib
import os
import tempfile
import urllib.request
from pathlib import Path

from .sources import RAW_DIR, SOURCES, Source

_CHUNK = 1 << 16


class DownloadError(RuntimeError):
    pass


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects only to https URLs (urllib would also follow http/ftp)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise DownloadError(f"refusing non-https redirect to {newurl[:80]}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


# Only HTTPS and HTTPS-only redirects; no file:, ftp: or data: handlers.
_OPENER = urllib.request.OpenerDirector()
for _h in (urllib.request.HTTPSHandler(), _HttpsOnlyRedirects(), urllib.request.HTTPErrorProcessor(),
           urllib.request.HTTPDefaultErrorHandler()):
    _OPENER.add_handler(_h)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(_CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def _fetch(src: Source, dest: Path) -> str:
    if not src.url.startswith("https://"):
        raise DownloadError(f"{src.key}: only https sources are allowed")
    req = urllib.request.Request(src.url, headers={"User-Agent": "securemind-phase3/1.0"})
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dest.parent, prefix=".part-")
    h, total = hashlib.sha256(), 0
    try:
        with _OPENER.open(req, timeout=60) as resp, os.fdopen(fd, "wb") as out:
            for block in iter(lambda: resp.read(_CHUNK), b""):
                total += len(block)
                if total > src.max_bytes:
                    raise DownloadError(f"{src.key}: exceeds size limit of {src.max_bytes} bytes")
                h.update(block)
                out.write(block)
        digest = h.hexdigest()
        if not src.sha256.startswith("__") and digest != src.sha256:
            raise DownloadError(f"{src.key}: SHA-256 mismatch (got {digest}, expected {src.sha256})")
        os.replace(tmp, dest)
        return digest
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def ensure(key: str, *, allow_download: bool) -> Path:
    """Return the verified local path of a source, downloading it if allowed."""
    src = SOURCES[key]
    path = RAW_DIR / src.filename
    if path.exists():
        digest = sha256_file(path)
        if src.sha256.startswith("__"):
            raise DownloadError(f"{key}: no pinned SHA-256 yet (local file has {digest})")
        if digest != src.sha256:
            raise DownloadError(f"{key}: local file SHA-256 {digest} does not match pin {src.sha256}")
        return path
    if not allow_download:
        raise DownloadError(f"{key}: {path} missing; run `python -m phishlab download` first")
    digest = _fetch(src, path)
    if src.sha256.startswith("__"):
        raise DownloadError(f"{key}: downloaded, SHA-256 {digest}; pin it in sources.py before use")
    return path


def download_all() -> dict[str, str]:
    results = {}
    for key in SOURCES:
        path = ensure(key, allow_download=True)
        results[key] = f"{path.name} sha256={sha256_file(path)}"
    return results
