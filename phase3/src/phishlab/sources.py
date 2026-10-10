"""Pinned external inputs. See phase3/DATASET_REVIEW.md for licensing evidence.

Each source is downloaded only by `python -m phishlab download` and is
verified against `sha256` before use. A `sha256_origin` of "publisher" means
the publisher lists the hash; "first-download" means the hash was recorded
from our first download (trust on first use) because the publisher does not
publish one; "git-blob-verified" means the file's git blob id matched the
GitHub API listing at the pinned commit before the SHA-256 was recorded.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

PHASE3_DIR = Path(__file__).resolve().parents[2]
RAW_DIR = PHASE3_DIR / "data" / "raw"
WORK_DIR = PHASE3_DIR / "data" / "work"
REPORTS_DIR = PHASE3_DIR / "reports"
ARTIFACTS_DIR = PHASE3_DIR / "artifacts"

PSL_COMMIT = "3929462652695bad04f0a27afb600974014a3c8b"


@dataclass(frozen=True)
class Source:
    key: str
    url: str
    filename: str
    sha256: str
    sha256_origin: str
    max_bytes: int
    license: str
    citation: str


SOURCES: dict[str, Source] = {
    "phiusiil": Source(
        key="phiusiil",
        url="https://archive.ics.uci.edu/static/public/967/phiusiil+phishing+url+dataset.zip",
        filename="phiusiil.zip",
        sha256="0a639fd03aea6308c5b1c10c92aa23c2ce1505447a9137271865cd0badc9a59a",
        sha256_origin="first-download",
        max_bytes=40 * 1024 * 1024,
        license="CC BY 4.0",
        citation=("Prasad, A. & Chandra, S. (2024). PhiUSIIL Phishing URL (Website) "
                  "[Dataset]. UCI Machine Learning Repository. "
                  "https://doi.org/10.1016/j.cose.2023.103545"),
    ),
    "hannousse": Source(
        key="hannousse",
        url=("https://data.mendeley.com/public-files/datasets/c2gw7fy2j4/files/"
             "575316f4-ee1d-453e-a04f-7b950915b61b/file_downloaded"),
        filename="hannousse_dataset_B_05_2020.csv",
        sha256="21093e2902e5441c86a6daf95e86e7c332046e477fdf109a579d7bd81e586d6c",
        sha256_origin="publisher",
        max_bytes=10 * 1024 * 1024,
        license="CC BY 4.0",
        citation=("Hannousse, A. & Yahiouche, S. (2021). Web page phishing detection "
                  "(Version 3) [Dataset]. Mendeley Data. https://doi.org/10.17632/c2gw7fy2j4.3"),
    ),
    "psl": Source(
        key="psl",
        url=f"https://raw.githubusercontent.com/publicsuffix/list/{PSL_COMMIT}/public_suffix_list.dat",
        filename="public_suffix_list.dat",
        sha256="2919eb9803c91a3f73a507cc6fedc934de005543c22c4016f72e3343de5dd6e7",
        sha256_origin="git-blob-verified",
        max_bytes=2 * 1024 * 1024,
        license="MPL-2.0",
        citation=f"Public Suffix List, github.com/publicsuffix/list @ {PSL_COMMIT}",
    ),
    "psl_tests": Source(
        key="psl_tests",
        url=f"https://raw.githubusercontent.com/publicsuffix/list/{PSL_COMMIT}/tests/test_psl.txt",
        filename="test_psl.txt",
        sha256="8f50ad958916d6a8f79fba2363501475571acce752757f9126fe9d2f17dd920d",
        sha256_origin="git-blob-verified",
        max_bytes=256 * 1024,
        license="CC0 / public domain (PSL test vectors)",
        citation=f"Public Suffix List test vectors @ {PSL_COMMIT}",
    ),
}
