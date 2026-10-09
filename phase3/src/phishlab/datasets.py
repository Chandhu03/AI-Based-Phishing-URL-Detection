"""Dataset loaders with explicit schema validation and label normalisation.

Every loader returns a DataFrame with exactly these columns:
    source       dataset key ("phiusiil" or "hannousse")
    url_raw      the URL text exactly as published (never fetched)
    is_phishing  1 = phishing, 0 = legitimate (the ONLY label convention used
                 anywhere in phase3; the publishers' conventions differ)

Only the URL and label columns are read. Publisher-supplied features are
deliberately ignored: several are computed from page content or from
similarity scores that can leak the label, and none are available to a
URL-only detector at inference time.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

import pandas as pd

COLUMNS = ["source", "url_raw", "is_phishing"]


class SchemaError(ValueError):
    pass


def _require(df: pd.DataFrame, cols: list[str], name: str) -> None:
    missing = [c for c in cols if c not in df.columns]
    if missing:
        raise SchemaError(f"{name}: missing columns {missing}; found {list(df.columns)[:10]}")


def normalise_phiusiil(df: pd.DataFrame) -> pd.DataFrame:
    """PhiUSIIL (UCI #967): "Label 1 corresponds to a legitimate URL, label 0
    to a phishing URL" -> is_phishing = (label == 0)."""
    _require(df, ["URL", "label"], "phiusiil")
    labels = set(pd.unique(df["label"]))
    if not labels <= {0, 1}:
        raise SchemaError(f"phiusiil: unexpected label values {sorted(labels)}")
    if df["URL"].isna().any():
        raise SchemaError("phiusiil: null URLs present")
    return pd.DataFrame({"source": "phiusiil", "url_raw": df["URL"].astype(str),
                         "is_phishing": (df["label"] == 0).astype("int8")})


def normalise_hannousse(df: pd.DataFrame) -> pd.DataFrame:
    """Hannousse & Yahiouche (Mendeley c2gw7fy2j4 v3): status is the string
    'phishing' or 'legitimate' -> is_phishing = (status == 'phishing')."""
    _require(df, ["url", "status"], "hannousse")
    labels = set(pd.unique(df["status"]))
    if not labels <= {"phishing", "legitimate"}:
        raise SchemaError(f"hannousse: unexpected status values {sorted(labels)}")
    if df["url"].isna().any():
        raise SchemaError("hannousse: null URLs present")
    return pd.DataFrame({"source": "hannousse", "url_raw": df["url"].astype(str),
                         "is_phishing": (df["status"] == "phishing").astype("int8")})


def load_phiusiil(zip_path: Path) -> pd.DataFrame:
    with zipfile.ZipFile(zip_path) as z:
        names = [n for n in z.namelist() if n.lower().endswith(".csv")]
        if names != ["PhiUSIIL_Phishing_URL_Dataset.csv"]:
            raise SchemaError(f"phiusiil: unexpected archive contents {z.namelist()}")
        with z.open(names[0]) as f:
            df = pd.read_csv(f, encoding="utf-8-sig", usecols=["URL", "label"], dtype={"URL": str})
    return normalise_phiusiil(df)


def load_hannousse(csv_path: Path) -> pd.DataFrame:
    df = pd.read_csv(csv_path, usecols=["url", "status"], dtype={"url": str, "status": str})
    return normalise_hannousse(df)
