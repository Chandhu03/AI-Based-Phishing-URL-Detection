"""Structural integrity checks for the dependency files.

These run offline on every platform. They do not prove the locks are
current (CI regenerates them with uv for that); they prove the locks are
well-formed, fully hash-pinned, consistent with the declared direct
dependencies, and that no file switches package index.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RUNTIME_REQS = ROOT / "requirements.txt"
DEV_REQS = ROOT / "requirements-dev.txt"
RUNTIME_LOCK = ROOT / "requirements-lock.txt"
DEV_LOCK = ROOT / "requirements-dev-lock.txt"
ALL_FILES = (RUNTIME_REQS, DEV_REQS, RUNTIME_LOCK, DEV_LOCK)

_ENTRY = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)==(\S+?)(?:\s*;\s*(.+?))?\s*\\?$")
_HASH = re.compile(r"^\s*--hash=sha256:([0-9a-f]{64})\s*\\?$")
_INDEX_OPTIONS = ("--index-url", "--extra-index-url", "-i ", "--find-links",
                  "-f ", "--trusted-host", "--no-index")


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_lock(path: Path) -> dict[str, dict]:
    """Return {name: {"version", "marker", "hashes"}} for a uv/pip hashed lock."""
    entries: dict[str, dict] = {}
    current = None
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _ENTRY.match(line)
        if m:
            name = _norm(m.group(1))
            assert name not in entries, f"{path.name}:{lineno} duplicate entry {name}"
            current = entries[name] = {
                "version": m.group(2), "marker": m.group(3), "hashes": set()}
            continue
        h = _HASH.match(line)
        assert h and current is not None, (
            f"{path.name}:{lineno} unexpected line (not a pinned entry or sha256 hash)")
        current["hashes"].add(h.group(1))
    return entries


def parse_direct(path: Path) -> dict[str, str]:
    """Return {name: version} for a hand-edited requirements file."""
    out = {}
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)==([^\s;]+)$", line)
        assert m, f"{path.name}:{lineno} direct dependencies must be exact '==' pins"
        out[_norm(m.group(1))] = m.group(2)
    return out


@pytest.fixture(scope="module")
def runtime_lock():
    return parse_lock(RUNTIME_LOCK)


@pytest.fixture(scope="module")
def dev_lock():
    return parse_lock(DEV_LOCK)


@pytest.mark.parametrize("path", [RUNTIME_LOCK, DEV_LOCK], ids=lambda p: p.name)
def test_every_lock_entry_is_pinned_and_hashed(path):
    entries = parse_lock(path)
    assert entries, f"{path.name} has no entries"
    unhashed = [n for n, e in entries.items() if not e["hashes"]]
    assert not unhashed, f"{path.name}: entries without hashes: {unhashed}"


@pytest.mark.parametrize("path", ALL_FILES, ids=lambda p: p.name)
def test_no_package_index_overrides(path):
    text = path.read_text(encoding="utf-8")
    for line in text.splitlines():
        stripped = line.strip()
        for opt in _INDEX_OPTIONS:
            assert not stripped.startswith(opt), (
                f"{path.name} must not change the package index: {stripped[:40]}")


@pytest.mark.parametrize(
    "reqs, lock_fixture",
    [(RUNTIME_REQS, "runtime_lock"), (DEV_REQS, "dev_lock"), (RUNTIME_REQS, "dev_lock")],
    ids=["runtime-in-runtime-lock", "dev-in-dev-lock", "runtime-in-dev-lock"],
)
def test_direct_dependencies_locked_at_declared_version(reqs, lock_fixture, request):
    lock = request.getfixturevalue(lock_fixture)
    for name, version in parse_direct(reqs).items():
        assert name in lock, f"{name} from {reqs.name} is missing from the lock"
        assert lock[name]["version"] == version, (
            f"{name}: {reqs.name} pins {version}, lock has {lock[name]['version']}")


def test_dev_lock_contains_runtime_lock_exactly(runtime_lock, dev_lock):
    """CI installs the dev lock; it must install the same runtime packages,
    versions, markers and allowed files as production would."""
    for name, entry in runtime_lock.items():
        assert name in dev_lock, f"{name} missing from dev lock"
        assert dev_lock[name] == entry, f"{name} differs between runtime and dev locks"


_CUTOFF = r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"
_EXPECTED_COMMANDS = {
    RUNTIME_LOCK: (
        "uv pip compile requirements.txt --universal --python-version 3.12 "
        "--only-binary :all: --generate-hashes --exclude-newer {cutoff} "
        "-o requirements-lock.txt"),
    DEV_LOCK: (
        "uv pip compile requirements.txt requirements-dev.txt -c requirements-lock.txt "
        "--universal --python-version 3.12 --only-binary :all: --generate-hashes "
        "--exclude-newer {cutoff} -o requirements-dev-lock.txt"),
}


def test_lock_headers_record_exact_documented_command():
    """The header must be exactly the documented command (README and CI use
    the same one), with the same --exclude-newer cutoff in both locks."""
    cutoffs = set()
    for path, template in _EXPECTED_COMMANDS.items():
        head = path.read_text(encoding="utf-8").splitlines()[:2]
        assert head[0] == "# This file was autogenerated by uv via the following command:", path.name
        pattern = "^#    " + re.escape(template).replace(re.escape("{cutoff}"), _CUTOFF) + "$"
        m = re.match(pattern, head[1])
        assert m, f"{path.name} header is not the documented command: {head[1]}"
        cutoffs.add(m.group(1))
    assert len(cutoffs) == 1, f"locks use different --exclude-newer cutoffs: {cutoffs}"


@pytest.mark.parametrize(
    "reqs, lock_fixture",
    [(RUNTIME_REQS, "runtime_lock"), (DEV_REQS, "dev_lock")],
    ids=["runtime", "dev"],
)
def test_direct_dependencies_are_unconditional(reqs, lock_fixture, request):
    """A direct dependency must install on every platform; an environment
    marker on it would silently drop it somewhere."""
    lock = request.getfixturevalue(lock_fixture)
    for name in parse_direct(reqs):
        assert lock[name]["marker"] is None, f"{name} has marker {lock[name]['marker']!r}"


def test_lock_is_dependency_complete_for_installed_environment(dev_lock):
    """For every locked package installed at its locked version, each of its
    declared requirements that applies to this platform must also be locked.
    Strict in CI (which installs exactly the dev lock); skipped in an
    environment that was not installed from the lock."""
    from importlib import metadata

    from packaging.markers import default_environment
    from packaging.requirements import Requirement

    env = default_environment()
    applicable = {n: e for n, e in dev_lock.items()
                  if e["marker"] is None or Requirement(f"x; {e['marker']}").marker.evaluate(env)}
    checked, missing = 0, []
    for name, entry in applicable.items():
        try:
            if metadata.version(name) != entry["version"]:
                continue
            requires = metadata.requires(name) or []
        except metadata.PackageNotFoundError:
            continue
        checked += 1
        for spec in requires:
            req = Requirement(spec)
            if req.marker is not None and not req.marker.evaluate({**env, "extra": ""}):
                continue
            if _norm(req.name) not in dev_lock:
                missing.append(f"{name} -> {req.name}")
    if checked < len(applicable) * 0.9:
        pytest.skip(f"environment not installed from the dev lock ({checked}/{len(applicable)} entries match)")
    assert not missing, f"requirements missing from the lock: {missing}"


def test_linux_only_xgboost_dependency_is_locked(runtime_lock):
    """xgboost requires nvidia-nccl-cu12 on Linux only; a lock generated on
    one platform without --universal would silently omit it."""
    entry = runtime_lock.get("nvidia-nccl-cu12")
    assert entry is not None, "nvidia-nccl-cu12 missing: lock is not universal"
    assert entry["marker"] and "linux" in entry["marker"]
