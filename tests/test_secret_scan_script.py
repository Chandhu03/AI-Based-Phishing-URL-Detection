"""Regression tests for .github/scripts/secret-scan.sh (the CI secret-scan guard).

A stub stands in for gitleaks and reproduces its observed behaviour
(gitleaks 8.30.1): `gitleaks git` counts merge commits only when git log
receives "-m". A pull_request checkout is a synthetic merge commit, which is
the case that failed on PR #2 ("scanned '31' commits; the repository has 32").
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / ".github" / "scripts" / "secret-scan.sh"

STUB = r"""#!/usr/bin/env bash
# Fake gitleaks: records its arguments, then reports like gitleaks 8.30.1.
printf '%s\n' "$@" > "$STUB_ARGS"
opts=""
for a in "$@"; do case "$a" in --log-opts=*) opts="${a#--log-opts=}";; esac; done
if [[ " $opts " == *" -m "* && -z "${STUB_IGNORE_M:-}" ]]; then
  n=$(git rev-list --all --count)
else
  n=$(git rev-list --all --no-merges --count)
fi
echo "1:00AM INF $n commits scanned."
[ -n "${STUB_ERR:-}" ] && echo "1:00AM ERR [git] fatal: simulated failure"
if [ -n "${STUB_LEAK:-}" ]; then echo "1:00AM WRN leaks found: 1"; exit 1; fi
echo "1:00AM INF no leaks found"
"""


def _bash() -> str | None:
    if os.name == "nt":
        exec_path = subprocess.run(["git", "--exec-path"], capture_output=True, text=True).stdout.strip()
        if exec_path:
            candidate = Path(exec_path).parents[2] / "bin" / "bash.exe"
            if candidate.exists():
                return str(candidate)
        return None
    return shutil.which("bash")


BASH = _bash()
pytestmark = pytest.mark.skipif(BASH is None, reason="bash (Git Bash on Windows) is required")


def git(repo: Path, *args: str) -> str:
    cmd = ["git", "-c", "user.email=t@example.invalid", "-c", "user.name=t",
           "-c", "commit.gpgsign=false", "-c", "core.autocrlf=false", *args]
    return subprocess.run(cmd, cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def commit(repo: Path, name: str) -> str:
    (repo / name).write_text(name + "\n", encoding="utf-8")
    git(repo, "add", name)
    git(repo, "commit", "-q", "-m", name)
    return git(repo, "rev-parse", "HEAD")


@pytest.fixture
def stub(tmp_path):
    path = tmp_path / "gitleaks"
    path.write_text(STUB, encoding="utf-8", newline="\n")
    path.chmod(0o755)
    return path


def run(repo: Path, stub: Path, tmp_path: Path, **env) -> subprocess.CompletedProcess:
    # Start from a clean environment for the PR variables so a CI runner's
    # own values can never leak into a test.
    full_env = {k: v for k, v in os.environ.items() if k not in ("PR_BASE_SHA", "PR_HEAD_SHA")}
    full_env.update({"STUB_ARGS": (tmp_path / "stub-args.txt").as_posix(), **env})
    return run_script(SCRIPT, repo, stub, tmp_path, full_env)


def run_script(script: Path, repo: Path, stub: Path, tmp_path: Path, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run([BASH, script.as_posix(), stub.as_posix(), (tmp_path / "gl.log").as_posix()],
                          cwd=repo, env=env, capture_output=True, text=True)


@pytest.fixture
def linear_repo(tmp_path):
    repo = tmp_path / "linear"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    for name in ("a", "b", "c"):
        commit(repo, name)
    return repo


@pytest.fixture
def pr_checkout(tmp_path):
    """A repository checked out like actions/checkout does for pull_request:
    HEAD is a synthetic merge of the PR head into the base branch."""
    repo = tmp_path / "pr"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    commit(repo, "base1")
    base = commit(repo, "base2")
    git(repo, "checkout", "-q", "-b", "feature")
    commit(repo, "feat1")
    head = commit(repo, "feat2")
    git(repo, "checkout", "-q", "--detach", base)
    git(repo, "merge", "-q", "--no-ff", "--no-edit", "feature")
    assert len(git(repo, "log", "-1", "--format=%P").split()) == 2
    return repo, base, head


def test_linear_history_passes(linear_repo, stub, tmp_path):
    r = run(linear_repo, stub, tmp_path)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "scanned all 3 reachable commits" in r.stdout


def test_pull_request_merge_checkout_passes(pr_checkout, stub, tmp_path):
    """Regression for PR #2: the synthetic merge commit must be scanned and counted."""
    repo, base, head = pr_checkout
    r = run(repo, stub, tmp_path, PR_BASE_SHA=base, PR_HEAD_SHA=head)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "scanned all 5 reachable commits (1 merge commit(s) included)" in r.stdout
    assert "2 commit(s), all inside the scanned history" in r.stdout


def test_gitleaks_is_asked_to_scan_merge_commits(pr_checkout, stub, tmp_path):
    repo, base, head = pr_checkout
    run(repo, stub, tmp_path, PR_BASE_SHA=base, PR_HEAD_SHA=head)
    args = (tmp_path / "stub-args.txt").read_text(encoding="utf-8").split("\n")
    assert args[0] == "git"
    assert "--log-opts=--all -m" in args
    assert "--redact" in args


def test_scan_that_skips_merge_commits_is_rejected(pr_checkout, stub, tmp_path):
    """The original failure mode: merges not scanned -> count one short -> must fail."""
    repo, base, head = pr_checkout
    r = run(repo, stub, tmp_path, PR_BASE_SHA=base, PR_HEAD_SHA=head, STUB_IGNORE_M="1")
    assert r.returncode != 0
    assert "scanned '4' commits; 5 are reachable (1 merge commit(s))" in r.stdout


def test_pr_head_outside_scanned_history_fails(pr_checkout, stub, tmp_path):
    repo, base, _ = pr_checkout
    r = run(repo, stub, tmp_path, PR_BASE_SHA=base, PR_HEAD_SHA="0" * 40)
    assert r.returncode != 0
    assert "is not in the checked-out history" in r.stdout


def test_missing_pr_base_fails(pr_checkout, stub, tmp_path):
    repo, _, head = pr_checkout
    r = run(repo, stub, tmp_path, PR_BASE_SHA="", PR_HEAD_SHA=head)
    assert r.returncode != 0
    assert "base or head SHA is missing" in r.stdout


@pytest.mark.parametrize("env, message", [
    ({"STUB_LEAK": "1"}, "exited with status 1"),
    ({"STUB_ERR": "1"}, "logged an error"),
])
def test_leaks_and_scanner_errors_fail(linear_repo, stub, tmp_path, env, message):
    r = run(linear_repo, stub, tmp_path, **env)
    assert r.returncode != 0
    assert message in r.stdout


def test_shallow_clone_fails(linear_repo, stub, tmp_path):
    shallow = tmp_path / "shallow"
    subprocess.run(["git", "clone", "-q", "--depth", "1", linear_repo.as_uri(), str(shallow)],
                   check=True, capture_output=True)
    r = run(shallow, stub, tmp_path)
    assert r.returncode != 0
    assert "Shallow clone" in r.stdout
