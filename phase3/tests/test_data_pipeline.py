"""Labels, schema validation, cleaning, duplicates and splits (synthetic fixtures)."""
import pandas as pd
import pytest

from phishlab.cleaning import clean
from phishlab.datasets import SchemaError, normalise_hannousse, normalise_phiusiil
from phishlab.psl import PublicSuffixList
from phishlab.splits import assign, bucket, leakage_report

PSL = PublicSuffixList(["com", "org", "uk", "co.uk", "tk", "github.io"])


# ---------------------------------------------------------------- labels
def test_phiusiil_label_zero_means_phishing():
    out = normalise_phiusiil(pd.DataFrame({"URL": ["https://a.com", "https://b.com"], "label": [0, 1]}))
    assert out["is_phishing"].tolist() == [1, 0]
    assert list(out.columns) == ["source", "url_raw", "is_phishing"]


def test_hannousse_status_strings():
    out = normalise_hannousse(pd.DataFrame({"url": ["http://a.com", "http://b.com"],
                                            "status": ["phishing", "legitimate"]}))
    assert out["is_phishing"].tolist() == [1, 0]


@pytest.mark.parametrize("frame, fn", [
    (pd.DataFrame({"URL": ["x"], "label": [2]}), normalise_phiusiil),
    (pd.DataFrame({"url": ["x"]}), normalise_phiusiil),
    (pd.DataFrame({"url": ["x"], "status": ["malicious"]}), normalise_hannousse),
    (pd.DataFrame({"url": [None], "status": ["phishing"]}), normalise_hannousse),
])
def test_schema_violations_rejected(frame, fn):
    with pytest.raises(SchemaError):
        fn(frame)


# ---------------------------------------------------------------- cleaning
def _frame(rows):
    return pd.DataFrame(rows, columns=["source", "url_raw", "is_phishing"])


def test_duplicates_conflicts_and_rejections_are_counted():
    df = _frame([
        ("t", "https://www.example.com", 0),
        ("t", "HTTPS://WWW.EXAMPLE.COM", 0),      # same canonical URL -> duplicate
        ("t", "http://login.evil.tk/x", 1),
        ("t", "http://login.evil.tk/x", 0),       # conflicting label -> both removed
        ("t", "javascript:alert(1)", 1),          # rejected by the app validator
        ("t", "http://other.evil.tk/y", 1),
    ])
    out, s = clean(df, PSL)
    assert s["rows_in"] == 6
    assert s["rejected_by_validator"] == 1
    assert s["rejected_reasons"] == {"scheme_not_allowed|is_phishing=1": 1}
    assert s["exact_duplicates_removed"] == 1
    assert s["conflicting_urls"] == 1 and s["conflicting_rows_removed"] == 2
    assert s["rows_out"] == 2
    assert set(out["group"]) == {"example.com", "evil.tk"}


def test_cleaning_preserves_security_signals_in_canonical_url():
    df = _frame([("t", "HTTP://User@PayPal.com.Evil.TK:8080/Login?Next=/A", 1)])
    out, _ = clean(df, PSL)
    url = out.loc[0, "url"]
    assert "paypal.com.evil.tk" in url            # host lowercased
    assert "user@" in url.lower() and ":8080" in url  # userinfo and port kept
    assert url.endswith("/Login?Next=/A")         # path/query case kept
    assert out.loc[0, "group"] == "evil.tk"


def test_cleaning_does_not_mutate_input():
    df = _frame([("t", "https://a.com", 0)])
    before = df.copy()
    clean(df, PSL)
    pd.testing.assert_frame_equal(df, before)


# ---------------------------------------------------------------- splits
def test_split_is_deterministic_and_order_independent():
    groups = pd.Series([f"d{i}.com" for i in range(2000)])
    a = assign(groups)
    b = assign(groups.sample(frac=1, random_state=3)).sort_index()
    assert a.equals(b)


def test_no_group_in_two_splits_and_fractions_reasonable():
    groups = pd.Series([f"d{i % 700}.com" for i in range(5000)])
    df = pd.DataFrame({"group": groups, "split": assign(groups)})
    assert leakage_report(df) == {"train_val_shared_groups": 0, "train_test_shared_groups": 0,
                                  "val_test_shared_groups": 0}
    frac = df.drop_duplicates("group")["split"].value_counts(normalize=True)
    assert 0.62 < frac["train"] < 0.78 and 0.09 < frac["val"] < 0.21 and 0.09 < frac["test"] < 0.21


def test_salt_changes_assignment_and_bucket_range():
    assert bucket("a.com") != bucket("a.com", salt="other")
    assert all(0 <= bucket(f"x{i}.com") < 1 for i in range(500))


def test_leakage_report_detects_shared_group():
    df = pd.DataFrame({"group": ["a.com", "a.com", "b.com"], "split": ["train", "test", "val"]})
    assert leakage_report(df)["train_test_shared_groups"] == 1
