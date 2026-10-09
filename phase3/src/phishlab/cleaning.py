"""Canonicalisation, duplicate and conflicting-label handling.

Order of operations (each step's counts are reported):
1. Canonicalise every URL with the app's validator; rows it rejects are
   dropped and counted by reason and class (the live app would reject them
   too, so they cannot be scored at inference time).
2. Exact duplicates of (canonical URL, label) collapse to one row.
3. Canonical URLs that appear with BOTH labels are conflicting and are
   removed entirely (no reliable ground truth).
"""
from __future__ import annotations

from collections import Counter

import pandas as pd

from .canonical import canonicalize
from .psl import PublicSuffixList


def clean(df: pd.DataFrame, psl: PublicSuffixList) -> tuple[pd.DataFrame, dict]:
    stats: dict = {"rows_in": int(len(df)),
                   "class_in": {int(k): int(v) for k, v in df["is_phishing"].value_counts().items()}}
    canon = [canonicalize(u, psl) for u in df["url_raw"]]
    ok = pd.Series([c.ok for c in canon], index=df.index)
    reasons = Counter((c.reason, int(lab)) for c, lab in zip(canon, df["is_phishing"]) if not c.ok)
    stats["rejected_by_validator"] = int((~ok).sum())
    stats["rejected_reasons"] = {f"{r}|is_phishing={lab}": n for (r, lab), n in sorted(reasons.items())}

    out = df.loc[ok].copy()
    kept = [c for c in canon if c.ok]
    out["url"] = [c.url for c in kept]
    out["host"] = [c.host for c in kept]
    out["group"] = [c.group for c in kept]

    before = len(out)
    out = out.drop_duplicates(subset=["url", "is_phishing"], keep="first")
    stats["exact_duplicates_removed"] = int(before - len(out))

    label_counts = out.groupby("url")["is_phishing"].nunique()
    conflicting = set(label_counts[label_counts > 1].index)
    stats["conflicting_urls"] = len(conflicting)
    stats["conflicting_rows_removed"] = int(out["url"].isin(conflicting).sum())
    out = out[~out["url"].isin(conflicting)]

    group_labels = out.groupby("group")["is_phishing"].nunique()
    stats["groups_with_both_labels"] = int((group_labels > 1).sum())
    stats["rows_out"] = int(len(out))
    stats["class_out"] = {int(k): int(v) for k, v in out["is_phishing"].value_counts().items()}
    stats["unique_groups"] = int(out["group"].nunique())
    stats["unique_hosts"] = int(out["host"].nunique())
    return out.reset_index(drop=True), stats
