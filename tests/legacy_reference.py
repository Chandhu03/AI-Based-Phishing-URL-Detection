# FROZEN verbatim copy of the original extract_url_features from app.py at
# commit 4a912ac. Used ONLY for parity tests. Do not modify.
import re
from urllib.parse import urlparse


def extract_url_features(url):
    """Extract features from a raw URL string for the demo."""
    features = {}
    try:
        parsed = urlparse(url)
    except Exception:
        parsed = urlparse("http://error.com")

    domain = parsed.netloc
    path = parsed.path
    query = parsed.query

    features["url_length"] = len(url)
    features["domain_length"] = len(domain)
    features["path_length"] = len(path)
    features["num_dots"] = url.count(".")
    features["num_hyphens"] = domain.count("-")
    features["num_subdomains"] = domain.count(".")
    features["has_https"] = 1 if parsed.scheme == "https" else 0
    features["has_ip"] = 1 if re.search(
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain) else 0
    features["has_at_symbol"] = 1 if "@" in url else 0
    features["num_special_chars"] = sum(
        1 for c in url if c in "!#$%^&*()=+[]{}|;:',<>?")
    features["digits_in_domain"] = sum(1 for c in domain if c.isdigit())

    suspicious_tlds = [
        ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top",
        ".club", ".online", ".site", ".buzz", ".link", ".click"]
    features["suspicious_tld"] = 1 if any(
        domain.endswith(tld) for tld in suspicious_tlds) else 0

    url_lower = url.lower()
    features["has_login"] = 1 if "login" in url_lower else 0
    features["has_verify"] = 1 if "verify" in url_lower else 0
    features["has_secure"] = 1 if "secure" in url_lower else 0
    features["has_account"] = 1 if "account" in url_lower else 0
    features["has_update"] = 1 if "update" in url_lower else 0
    features["has_query"] = 1 if query else 0

    return features
