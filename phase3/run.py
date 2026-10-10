"""Run the Phase 3 pipeline: python phase3/run.py <command> (see --help).

Adds phase3/src (the `phishlab` package) and the repository root (the
existing `securemind` package, used unchanged) to the import path.
"""
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE / "src"), str(HERE.parent)]

from phishlab.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
