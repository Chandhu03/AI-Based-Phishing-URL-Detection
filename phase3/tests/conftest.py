"""Make `phishlab` (phase3/src) and `securemind` (repo root) importable.

All Phase 3 tests use small in-memory fixtures (synthetic URLs) and never
touch the network or the downloaded datasets, except the official PSL
vector test, which is skipped unless `python phase3/run.py download` ran.
"""
import sys
from pathlib import Path

PHASE3 = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(PHASE3 / "src"), str(PHASE3.parent)]
