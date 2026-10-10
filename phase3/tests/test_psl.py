import pytest

from phishlab.psl import PublicSuffixList, check_official_vectors
from phishlab.sources import RAW_DIR

RULES = ["com", "uk", "co.uk", "jp", "*.kawasaki.jp", "!city.kawasaki.jp",
         "github.io", "*.ck", "!www.ck"]


@pytest.fixture(scope="module")
def psl():
    return PublicSuffixList(RULES)


@pytest.mark.parametrize("host, expected", [
    ("example.com", "example.com"),
    ("a.b.example.com", "example.com"),
    ("www.bbc.co.uk", "bbc.co.uk"),
    ("co.uk", None),                       # host is itself a public suffix
    ("com", None),
    ("x.y.kawasaki.jp", "x.y.kawasaki.jp"),  # wildcard: y.kawasaki.jp is a suffix
    ("city.kawasaki.jp", "city.kawasaki.jp"),  # exception rule
    ("a.city.kawasaki.jp", "city.kawasaki.jp"),
    ("user.github.io", "user.github.io"),  # private-section rule groups by owner
    ("a.user.github.io", "user.github.io"),
    ("www.ck", "www.ck"),
    ("example.unlistedtld", "example.unlistedtld"),  # default "*" rule
    ("login.paypal.com.evil.com", "evil.com"),  # brand in subdomain does not fool grouping
])
def test_registrable_domain(psl, host, expected):
    assert psl.registrable_domain(host) == expected


@pytest.mark.parametrize("bad", ["", ".example.com", "a..b.com"])
def test_malformed_hosts_have_no_registrable_domain(psl, bad):
    assert psl.registrable_domain(bad) is None


def test_official_vectors_if_downloaded():
    lst, vec = RAW_DIR / "public_suffix_list.dat", RAW_DIR / "test_psl.txt"
    if not (lst.exists() and vec.exists()):
        pytest.skip("PSL not downloaded; run `python phase3/run.py download`")
    passed, failures = check_official_vectors(PublicSuffixList.from_file(lst), vec)
    assert passed >= 70 and failures == []
