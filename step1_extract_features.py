"""
STEP 1: Feature Extraction
============================
This is the MOST IMPORTANT file in the project.

WHAT DOES "FEATURE EXTRACTION" MEAN?
    A machine learning model can't read text. It only understands numbers.
    So we need to turn each URL into a list of numbers (features).
    
    Think of it like a detective examining a URL:
    - How long is it? (Phishing URLs tend to be longer)
    - Does it use HTTPS? (Legit sites usually do)
    - How many dots? (Phishing URLs often have lots of subdomains)
    - Does it contain suspicious words like "login" or "verify"?
    
    Each of these questions becomes a NUMBER, and together they form
    a "fingerprint" of the URL that the model can analyze.

WHAT THIS FILE DOES:
    1. Reads the CSV file with URLs and labels
    2. For each URL, calculates ~18 features (numbers)
    3. Saves the result as a new CSV where each row has:
       [feature1, feature2, ..., feature18, label]
"""

import pandas as pd
import re
from urllib.parse import urlparse
import os


def extract_features(url):
    """
    Take a URL string and return a dictionary of numeric features.
    
    Example:
        Input:  "http://secure-paypal-login.xyz/verify?token=123"
        Output: {"url_length": 48, "num_dots": 2, "has_https": 0, ...}
    """
    features = {}
    
    # Parse the URL into its parts
    # urlparse("http://www.example.com/path?q=1") gives us:
    #   scheme = "http"
    #   netloc = "www.example.com"  (the domain part)
    #   path   = "/path"
    #   query  = "q=1"
    try:
        parsed = urlparse(url)
    except Exception:
        parsed = urlparse("http://error.com")
    
    domain = parsed.netloc    # e.g., "www.example.com"
    path = parsed.path        # e.g., "/login/verify"
    query = parsed.query      # e.g., "token=123&redirect=true"
    
    # =====================================================
    # FEATURE 1: URL Length
    # WHY: Phishing URLs tend to be LONGER than legit ones
    #       because they stuff in extra words to look real.
    # =====================================================
    features["url_length"] = len(url)
    
    # =====================================================
    # FEATURE 2: Domain Length
    # WHY: Legit domains are short (google.com = 10).
    #       Phishing domains are long (secure-paypal-login.xyz = 24).
    # =====================================================
    features["domain_length"] = len(domain)
    
    # =====================================================
    # FEATURE 3: Path Length
    # WHY: Phishing URLs often have long paths like
    #       /verify-account/secure-login/confirm
    # =====================================================
    features["path_length"] = len(path)
    
    # =====================================================
    # FEATURE 4: Number of dots in URL
    # WHY: Phishing URLs use lots of subdomains:
    #       paypal.com.secure.verify.evil.xyz (5 dots!)
    #       vs google.com (1 dot)
    # =====================================================
    features["num_dots"] = url.count(".")
    
    # =====================================================
    # FEATURE 5: Number of hyphens in domain
    # WHY: Phishing domains love hyphens:
    #       secure-paypal-login.xyz (2 hyphens)
    #       vs paypal.com (0 hyphens)
    # =====================================================
    features["num_hyphens"] = domain.count("-")
    
    # =====================================================
    # FEATURE 6: Number of subdomains
    # WHY: More subdomains = more suspicious.
    #       "www.google.com" has 1 subdomain (www)
    #       "paypal.com.secure.evil.xyz" has 3 subdomains
    # =====================================================
    # Count dots in domain = number of separators
    # "www.google.com" has 2 dots, so 2 subdomains
    features["num_subdomains"] = domain.count(".")
    
    # =====================================================
    # FEATURE 7: Has HTTPS?
    # WHY: Legitimate sites almost always use HTTPS.
    #       Phishing sites often don't bother.
    #       1 = yes (good), 0 = no (suspicious)
    # =====================================================
    features["has_https"] = 1 if parsed.scheme == "https" else 0
    
    # =====================================================
    # FEATURE 8: Has IP address instead of domain name?
    # WHY: Normal sites use names: google.com
    #       Phishing sites sometimes use raw IPs: 192.168.1.1
    #       1 = has IP (suspicious), 0 = normal domain
    # =====================================================
    ip_pattern = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    features["has_ip"] = 1 if re.search(ip_pattern, domain) else 0
    
    # =====================================================
    # FEATURE 9: Has @ symbol?
    # WHY: The @ in a URL can trick browsers:
    #       http://google.com@evil.com actually goes to evil.com!
    #       1 = has @ (very suspicious), 0 = normal
    # =====================================================
    features["has_at_symbol"] = 1 if "@" in url else 0
    
    # =====================================================
    # FEATURE 10: Number of special characters
    # WHY: Phishing URLs use more special chars to confuse people
    # =====================================================
    special_chars = sum(1 for c in url if c in "!#$%^&*()=+[]{}|;:',<>?")
    features["num_special_chars"] = special_chars
    
    # =====================================================
    # FEATURE 11: Number of digits in domain
    # WHY: Legit domains rarely have numbers.
    #       "google.com" vs "g00gle-secure123.xyz"
    # =====================================================
    features["digits_in_domain"] = sum(1 for c in domain if c.isdigit())
    
    # =====================================================
    # FEATURE 12: Has suspicious TLD?
    # WHY: Certain domain endings are heavily used by phishers
    #       .xyz, .tk, .ml, .ga are cheap/free domains
    # =====================================================
    suspicious_tlds = [
        ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top",
        ".club", ".online", ".site", ".buzz", ".link", ".click",
    ]
    features["suspicious_tld"] = 1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0
    
    # =====================================================
    # FEATURE 13-17: Contains suspicious keywords?
    # WHY: Phishing URLs contain words designed to create
    #       urgency or fake legitimacy
    # =====================================================
    url_lower = url.lower()
    features["has_login"] = 1 if "login" in url_lower else 0
    features["has_verify"] = 1 if "verify" in url_lower else 0
    features["has_secure"] = 1 if "secure" in url_lower else 0
    features["has_account"] = 1 if "account" in url_lower else 0
    features["has_update"] = 1 if "update" in url_lower else 0
    
    # =====================================================
    # FEATURE 18: URL has query parameters?
    # WHY: Phishing URLs often use query strings to pass
    #       tracking tokens: ?token=123456&redirect=true
    # =====================================================
    features["has_query"] = 1 if query else 0
    
    return features


def main():
    """Load URLs, extract features, save result."""
    
    # --- Load the dataset ---
    data_path = os.path.join(os.path.dirname(__file__), "dataset", "urls.csv")
    print(f"Loading URLs from {data_path}...")
    df = pd.read_csv(data_path)
    print(f"  Loaded {len(df)} URLs")
    print(f"  Legitimate: {(df['label'] == 0).sum()}")
    print(f"  Phishing:   {(df['label'] == 1).sum()}")
    
    # --- Extract features for every URL ---
    print("\nExtracting features...")
    feature_list = []
    for i, row in df.iterrows():
        features = extract_features(row["url"])
        features["label"] = row["label"]  # Keep the label
        feature_list.append(features)
        
        # Print progress every 2000 URLs
        if (i + 1) % 2000 == 0:
            print(f"  Processed {i + 1}/{len(df)} URLs...")
    
    # Convert to DataFrame
    features_df = pd.DataFrame(feature_list)
    
    # --- Save the features ---
    output_path = os.path.join(os.path.dirname(__file__), "dataset", "features.csv")
    features_df.to_csv(output_path, index=False)
    print(f"\nFeatures saved to {output_path}")
    print(f"  Shape: {features_df.shape[0]} rows × {features_df.shape[1]} columns")
    
    # --- Show what we created ---
    print("\n--- Feature names (what each column means) ---")
    for col in features_df.columns:
        if col != "label":
            print(f"  {col}")
    
    print("\n--- Sample of the features (first 3 rows) ---")
    print(features_df.head(3).to_string())
    
    print("\n--- Basic statistics ---")
    print(features_df.describe().round(2).to_string())


if __name__ == "__main__":
    main()
