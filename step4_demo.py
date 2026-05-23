"""
STEP 4: Demo — Phishing Detection
====================================
This demo works TWO ways:
 
1. KAGGLE MODEL TEST: Tests the trained model on random samples
   from the real dataset (proves the model works)
 
2. URL MODE: Trains a quick model on URL-only features
   so you can type in any URL live and get a prediction
 
For your presentation, show BOTH:
  - First: the Kaggle model accuracy (the real scores)
  - Then: type in URLs live (the crowd-pleaser)
"""
 
import pandas as pd
import numpy as np
import pickle
import json
import os
import re
import random
from urllib.parse import urlparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
 
 
def extract_url_features(url):
    """Extract features from a raw URL string."""
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
    features["has_ip"] = 1 if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain) else 0
    features["has_at_symbol"] = 1 if "@" in url else 0
    features["num_special_chars"] = sum(1 for c in url if c in "!#$%^&*()=+[]{}|;:',<>?")
    features["digits_in_domain"] = sum(1 for c in domain if c.isdigit())
    suspicious_tlds = [".xyz",".tk",".ml",".ga",".cf",".gq",".top",".club",".online",".site",".buzz",".link",".click"]
    features["suspicious_tld"] = 1 if any(domain.endswith(t) for t in suspicious_tlds) else 0
    url_lower = url.lower()
    features["has_login"] = 1 if "login" in url_lower else 0
    features["has_verify"] = 1 if "verify" in url_lower else 0
    features["has_secure"] = 1 if "secure" in url_lower else 0
    features["has_account"] = 1 if "account" in url_lower else 0
    features["has_update"] = 1 if "update" in url_lower else 0
    features["has_query"] = 1 if query else 0
    return features
 
 
def build_url_demo_model():
    """Train a quick Random Forest on URL features for the live demo."""
    print("  Training URL-based demo model...")
    random.seed(42)
    from step0_generate_dataset import generate_legit_url, generate_phishing_url
    train_data = []
    for _ in range(2500):
        train_data.append((generate_legit_url(), 0))
    for _ in range(2500):
        train_data.append((generate_phishing_url(), 1))
    random.shuffle(train_data)
    X = pd.DataFrame([extract_url_features(url) for url, _ in train_data])
    y = [label for _, label in train_data]
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
    model.fit(X_scaled, y)
    print("  Done!\n")
    return model, scaler
 
 
def predict_url(url, model, scaler):
    """Predict whether a URL is phishing or safe."""
    features = extract_url_features(url)
    df = pd.DataFrame([features])
    scaled = scaler.transform(df)
    pred = model.predict(scaled)[0]
    probs = model.predict_proba(scaled)[0]
    prediction = "PHISHING" if pred == 1 else "SAFE"
    confidence = probs[1] if pred == 1 else probs[0]
    return prediction, confidence, features
 
 
def print_result(url, prediction, confidence, features):
    print()
    print("-" * 60)
    print(f"  URL: {url}")
    print("-" * 60)
    if prediction == "PHISHING":
        print(f"  WARNING  Prediction:  {prediction}")
    else:
        print(f"  OK       Prediction:  {prediction}")
    print(f"  Confidence:  {confidence*100:.1f}%")
    print(f"\n  Key features:")
    print(f"    URL length:        {features['url_length']}")
    print(f"    Uses HTTPS:        {'Yes' if features['has_https'] else 'No'}")
    print(f"    Dots in URL:       {features['num_dots']}")
    print(f"    Hyphens in domain: {features['num_hyphens']}")
    print(f"    Suspicious TLD:    {'Yes' if features['suspicious_tld'] else 'No'}")
    print(f"    Has IP address:    {'Yes' if features['has_ip'] else 'No'}")
    print(f"    Contains 'login':  {'Yes' if features['has_login'] else 'No'}")
    print(f"    Contains 'secure': {'Yes' if features['has_secure'] else 'No'}")
    print("-" * 60)
 
 
def main():
    print("=" * 60)
    print("  PHISHING URL DETECTOR - LIVE DEMO")
    print("  ECE 569A AI Project")
    print("=" * 60)
 
    results_dir = os.path.join(os.path.dirname(__file__), "results")
 
    # --- PART 1: Test Kaggle model on real data samples ---
    print("\n" + "=" * 60)
    print("  PART 1: KAGGLE MODEL TEST (real dataset)")
    print("=" * 60)
 
    try:
        with open(os.path.join(results_dir, "best_model.pkl"), "rb") as f:
            kaggle_model = pickle.load(f)
        with open(os.path.join(results_dir, "scaler.pkl"), "rb") as f:
            kaggle_scaler = pickle.load(f)
        with open(os.path.join(results_dir, "feature_names.json")) as f:
            kaggle_features = json.load(f)
 
        data_path = os.path.join(os.path.dirname(__file__), "dataset", "Phishing_Legitimate_full.csv")
        df = pd.read_csv(data_path)
 
        phishing_samples = df[df["CLASS_LABEL"] == 0].sample(5, random_state=99)
        legit_samples = df[df["CLASS_LABEL"] == 1].sample(5, random_state=99)
        test_samples = pd.concat([phishing_samples, legit_samples])
 
        X_test = test_samples[kaggle_features]
        y_test = test_samples["CLASS_LABEL"]
        X_scaled = kaggle_scaler.transform(X_test)
        preds = kaggle_model.predict(X_scaled)
        probs = kaggle_model.predict_proba(X_scaled)
 
        correct = 0
        print()
        for i, (idx, row) in enumerate(test_samples.iterrows()):
            actual = "Legitimate" if row["CLASS_LABEL"] == 1 else "Phishing"
            pred = "Legitimate" if preds[i] == 1 else "Phishing"
            conf = max(probs[i]) * 100
            ok = preds[i] == row["CLASS_LABEL"]
            if ok: correct += 1
            mark = "OK" if ok else "MISS"
            print(f"  [{mark:4s}] Sample #{idx:<5d} | Actual: {actual:11s} | Predicted: {pred:11s} | Conf: {conf:.1f}%")
 
        print(f"\n  Score: {correct}/{len(test_samples)} correct ({correct/len(test_samples)*100:.0f}%)")
        print(f"  Best model: XGBoost (F1 = 0.986 on full test set)")
    except FileNotFoundError:
        print("  Kaggle model not found. Run step2_train_models_kaggle.py first.")
 
    # --- PART 2: Live URL Demo ---
    print("\n" + "=" * 60)
    print("  PART 2: LIVE URL DEMO")
    print("=" * 60)
 
    demo_model, demo_scaler = build_url_demo_model()
 
    examples = [
        "https://www.google.com/search?q=weather",
        "http://secure-paypal-login.xyz/verify?token=456789",
        "https://github.com/python/cpython",
        "http://192.168.1.100/chase/login",
        "https://www.amazon.com/dp/B08N5WRWNW",
        "http://account-verify-secure.login.confirm.tk/auth",
    ]
 
    for url in examples:
        prediction, confidence, features = predict_url(url, demo_model, demo_scaler)
        print_result(url, prediction, confidence, features)
 
    # Interactive
    print("\n" + "=" * 60)
    print("  INTERACTIVE MODE - Type a URL or 'quit' to exit")
    print("=" * 60)
 
    while True:
        try:
            url = input("\nEnter URL: ").strip()
            if url.lower() in ("quit", "exit", "q"):
                print("\nGoodbye!")
                break
            if not url:
                continue
            if not url.startswith("http"):
                url = "http://" + url
            prediction, confidence, features = predict_url(url, demo_model, demo_scaler)
            print_result(url, prediction, confidence, features)
        except (KeyboardInterrupt, EOFError):
            print("\nGoodbye!")
            break
 
 
if __name__ == "__main__":
    main()
 