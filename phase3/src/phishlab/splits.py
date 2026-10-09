"""Deterministic, domain-separated splits.

Each group (registrable domain) is assigned to train/validation/test by a
salted SHA-256 of the group name, so the assignment:
* never puts one domain in two splits (no domain leakage),
* does not depend on row order, dataset size or random state,
* is stable when rows are added or removed.
"""
from __future__ import annotations

import hashlib

import pandas as pd

DEFAULT_SALT = "securemind-phase3-v1"
DEFAULT_FRACTIONS = (0.70, 0.15, 0.15)


def bucket(group: str, salt: str = DEFAULT_SALT) -> float:
    digest = hashlib.sha256(f"{salt}\0{group}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def assign(groups: pd.Series, fractions=DEFAULT_FRACTIONS, salt: str = DEFAULT_SALT) -> pd.Series:
    train, val, _ = fractions
    if abs(sum(fractions) - 1.0) > 1e-9:
        raise ValueError("fractions must sum to 1")
    b = groups.map(lambda g: bucket(g, salt))
    return pd.Series(pd.cut(b, [0.0, train, train + val, 1.0], right=False,
                            labels=["train", "val", "test"]).astype(str), index=groups.index)


def leakage_report(df: pd.DataFrame, split_col: str = "split", group_col: str = "group") -> dict:
    sets = {s: set(df.loc[df[split_col] == s, group_col]) for s in ("train", "val", "test")}
    return {
        "train_val_shared_groups": len(sets["train"] & sets["val"]),
        "train_test_shared_groups": len(sets["train"] & sets["test"]),
        "val_test_shared_groups": len(sets["val"] & sets["test"]),
    }
