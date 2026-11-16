"""Shared URL cases: the validator must give the outcome recorded in
tests/fixtures/url_cases.json, which the website's JavaScript dissector is
tested against as well (website/src/engine/url-anatomy.test.js)."""
import json
from pathlib import Path

import pytest

from securemind.url_validation import URLValidationError, validate_url

CASES = json.loads((Path(__file__).parent / "fixtures" / "url_cases.json").read_text(encoding="utf-8"))["cases"]


@pytest.mark.parametrize("case", CASES, ids=[c["url"].encode("unicode_escape").decode("ascii")[:60] for c in CASES])
def test_shared_url_case(case):
    if "error" in case:
        with pytest.raises(URLValidationError) as exc:
            validate_url(case["url"])
        assert exc.value.code == case["error"]
        return
    n = validate_url(case["url"])
    assert n.hostname == case["host"]
    if "ip_obfuscated" in case:
        assert n.ip_obfuscated is case["ip_obfuscated"]


def test_every_intentional_difference_is_explained():
    for case in CASES:
        if "js" in case:
            assert case.get("why"), case["url"]
