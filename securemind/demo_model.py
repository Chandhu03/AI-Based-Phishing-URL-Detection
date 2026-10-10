"""DEMONSTRATION phishing model trained on synthetic URLs.

The training URLs come from a seeded generator, the model has never been
evaluated on real data, and its vote share (share of tree votes for the
predicted class) is NOT a calibrated probability.

The generator and training settings are moved verbatim from the original
app.py so the trained model is bit-identical (see parity tests).
No Streamlit imports or caching here; callers wrap train_demo_model.
"""
from __future__ import annotations

import random
from dataclasses import dataclass

import pandas as pd

from .features import FEATURE_NAMES, extract_url_features
from .url_validation import NormalizedURL, validate_url


def generate_training_urls() -> list[tuple[str, int]]:
    """Return 10,000 shuffled (url, label) pairs; label 1 = phishing.

    Uses a local Random(42); the global random state is not touched.
    """
    rng = random.Random(42)

    # --- Building blocks for training URLs ---
    legit_domains = [
        "google.com", "facebook.com", "amazon.com", "microsoft.com",
        "apple.com", "netflix.com", "github.com", "stackoverflow.com",
        "wikipedia.org", "linkedin.com", "twitter.com", "instagram.com",
        "youtube.com", "reddit.com", "ebay.com", "walmart.com",
        "bbc.co.uk", "cnn.com", "nytimes.com", "medium.com",
        "shopify.com", "dropbox.com", "zoom.us", "slack.com",
        "adobe.com", "spotify.com", "paypal.com", "chase.com",
        "bankofamerica.com", "wellsfargo.com", "td.com", "rbc.ca",
        "uvic.ca", "ubc.ca", "mit.edu", "stanford.edu", "harvard.edu",
        "gov.ca", "canada.ca", "irs.gov", "nhs.uk", "who.int",
        "arxiv.org", "nature.com", "sciencedirect.com", "ieee.org",
        "docker.com", "kubernetes.io", "python.org", "nodejs.org",
        "npmjs.com", "pypi.org", "rust-lang.org", "golang.org",
        "stripe.com", "twilio.com", "cloudflare.com", "fastly.com",
        "heroku.com", "vercel.com", "netlify.com", "railway.app",
        "notion.so", "figma.com", "canva.com", "trello.com",
        "airbnb.com", "booking.com", "expedia.com", "tripadvisor.com",
        "uber.com", "lyft.com", "doordash.com", "grubhub.com",
        "zillow.com", "realtor.com", "craigslist.org", "etsy.com",
        "target.com", "bestbuy.com", "costco.com", "homedepot.com",
    ]
    legit_paths = [
        "/", "/about", "/contact", "/products", "/services",
        "/help", "/support", "/login", "/account", "/settings",
        "/news", "/blog", "/docs", "/api", "/pricing",
        "/careers", "/team", "/faq", "/terms", "/privacy",
        "/search", "/explore", "/trending", "/popular", "/new",
        "/dp/B08N5WRWNW", "/python/cpython", "/user/repos",
        "/watch?v=dQw4w9WgXcQ", "/r/programming", "/p/12345",
    ]
    legit_subdomains = [
        "www", "blog", "docs", "help", "api", "mail",
        "app", "dev", "staging", "cdn", "static", "m",
        "store", "shop", "support", "status", "my",
    ]
    phishing_keywords = [
        "secure", "verify", "update", "confirm", "login",
        "account", "banking", "signin", "authenticate", "validate",
        "password", "credential", "alert", "suspended", "locked",
    ]
    phishing_brands = [
        "paypal", "apple", "google", "microsoft", "amazon",
        "netflix", "chase", "wellsfargo", "bankofamerica", "facebook",
    ]
    phishing_tlds = [
        ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
        ".top", ".club", ".online", ".site", ".info",
        ".ru", ".cn", ".buzz", ".link", ".click",
    ]
    phishing_paths = [
        "/verify-account", "/secure-login", "/update-info",
        "/confirm-identity", "/reset-password", "/unlock-account",
        "/validate-user", "/security-check", "/auth/login",
        "/account/verify", "/signin/confirm", "/secure/update",
    ]

    def gen_legit():
        # Mix of protocols — legit sites mostly HTTPS
        proto = rng.choice(["https://"] * 8 + ["https://www."] * 4 + ["http://"] * 1)
        dom = rng.choice(legit_domains)
        path = rng.choice(legit_paths)

        # Sometimes add a subdomain
        if rng.random() < 0.15:
            dom = rng.choice(legit_subdomains) + "." + dom

        # Various query patterns
        q = ""
        r = rng.random()
        if r < 0.15:
            q = f"?id={rng.randint(100, 9999)}"
        elif r < 0.25:
            q = f"?q={rng.choice(['weather', 'news', 'python', 'recipe', 'how+to'])}"
        elif r < 0.30:
            q = f"?page={rng.randint(1, 20)}&sort=popular"

        # Sometimes generate bare domain (common user input)
        if rng.random() < 0.15:
            return proto + dom

        return proto + dom + path + q

    def gen_phish():
        proto = rng.choice(["http://", "https://", "http://www."])
        pattern = rng.choice(["kw", "brand", "ip", "sub"])
        if pattern == "kw":
            parts = rng.sample(phishing_keywords, rng.randint(2, 3))
            brand = rng.choice(phishing_brands)
            sep = rng.choice(["-", ".", ""])
            dom = sep.join(parts + [brand]) + rng.choice(phishing_tlds)
        elif pattern == "brand":
            brand = rng.choice(phishing_brands)
            kw = rng.choice(phishing_keywords)
            ext = rng.choice([".com", ".org", ".net"])
            dom = f"{brand}-{kw}{ext}.{kw}-{rng.choice(phishing_keywords)}{rng.choice(phishing_tlds)}"
        elif pattern == "ip":
            ip = f"{rng.randint(1,255)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,255)}"
            brand = rng.choice(phishing_brands)
            return f"http://{ip}/{brand}/login"
        else:
            brand = rng.choice(phishing_brands)
            subs = rng.sample(phishing_keywords, rng.randint(2, 4))
            dom = f"{brand}.com.{'.'.join(subs)}{rng.choice(phishing_tlds)}"
        path = rng.choice(phishing_paths)
        q = f"?token={rng.randint(100000,999999)}&redirect=true" if rng.random() < 0.4 else ""
        return proto + dom + path + q

    # Generate training data
    train_data = []
    for _ in range(5000):
        train_data.append((gen_legit(), 0))   # 0 = safe
    for _ in range(5000):
        train_data.append((gen_phish(), 1))    # 1 = phishing
    rng.shuffle(train_data)
    return train_data


def build_training_matrix() -> tuple[pd.DataFrame, list[int]]:
    rows = []
    labels = []
    for url, label in generate_training_urls():
        try:
            n = validate_url(url)
        except ValueError as exc:
            raise RuntimeError(
                "Generated training URL failed validation: " + repr(url)
            ) from exc
        rows.append(extract_url_features(n))
        labels.append(label)
    return pd.DataFrame(rows, columns=list(FEATURE_NAMES)), labels


def train_demo_model():
    """Return (model, scaler), trained exactly as the legacy app did."""
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.preprocessing import StandardScaler

    X, y = build_training_matrix()
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    model = RandomForestClassifier(n_estimators=200, max_depth=None, random_state=42)
    model.fit(X_scaled, y)
    return model, scaler


@dataclass(frozen=True)
class Prediction:
    is_phishing: bool
    vote_share: float  # share of tree votes for the predicted class
    features: dict[str, int]


def predict(n: NormalizedURL, model, scaler) -> Prediction:
    feats = extract_url_features(n)
    X = pd.DataFrame([feats], columns=list(FEATURE_NAMES))
    proba = model.predict_proba(scaler.transform(X))[0]
    classes = list(model.classes_)
    idx = int(proba.argmax())
    return Prediction(
        is_phishing=bool(classes[idx] == 1),
        vote_share=float(proba[idx]),
        features=feats,
    )
