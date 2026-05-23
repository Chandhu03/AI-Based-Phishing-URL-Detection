import streamlit as st
import pandas as pd
import numpy as np
import pickle
import json
import os
import re
from urllib.parse import urlparse


# PAGE CONFIG

st.set_page_config(
    page_title="Phishing URL Detector",
    page_icon="🔒",
    layout="centered",
)


# FEATURE EXTRACTION (same logic as step1)

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
    features["has_ip"] = 1 if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain) else 0
    features["has_at_symbol"] = 1 if "@" in url else 0
    features["num_special_chars"] = sum(1 for c in url if c in "!#$%^&*()=+[]{}|;:',<>?")
    features["digits_in_domain"] = sum(1 for c in domain if c.isdigit())

    suspicious_tlds = [".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top",
                       ".club", ".online", ".site", ".buzz", ".link", ".click"]
    features["suspicious_tld"] = 1 if any(domain.endswith(tld) for tld in suspicious_tlds) else 0

    url_lower = url.lower()
    features["has_login"] = 1 if "login" in url_lower else 0
    features["has_verify"] = 1 if "verify" in url_lower else 0
    features["has_secure"] = 1 if "secure" in url_lower else 0
    features["has_account"] = 1 if "account" in url_lower else 0
    features["has_update"] = 1 if "update" in url_lower else 0
    features["has_query"] = 1 if query else 0

    return features



# LOAD MODEL

@st.cache_resource
def load_model():
    """Load the trained model, scaler, and feature names."""
    results_dir = os.path.join(os.path.dirname(__file__), "results")
    with open(os.path.join(results_dir, "best_model.pkl"), "rb") as f:
        model = pickle.load(f)
    with open(os.path.join(results_dir, "scaler.pkl"), "rb") as f:
        scaler = pickle.load(f)
    with open(os.path.join(results_dir, "feature_names.json")) as f:
        feature_names = json.load(f)
    return model, scaler, feature_names


@st.cache_resource
def load_metrics():
    """Load model comparison metrics."""
    results_dir = os.path.join(os.path.dirname(__file__), "results")
    with open(os.path.join(results_dir, "metrics.json")) as f:
        return json.load(f)



# MAIN APP

def main():
    # --- Header ---
    st.title("🔒 Phishing URL Detector")
    st.markdown("*ECE 569A — AI Term Project | University of Victoria*")
    st.markdown("Enter any URL below and our ML model will predict if it's **phishing** or **safe**.")
    st.divider()

    # --- Load model ---
    try:
        model, scaler, feature_names = load_model()
    except FileNotFoundError:
        st.error("Model files not found! Run `step2_train_models_kaggle.py` first.")
        return

    # --- URL Input ---
    url = st.text_input(
        "🔗 Enter a URL to check:",
        placeholder="e.g., http://secure-paypal-login.xyz/verify",
    )

    # Example buttons
    st.markdown("**Try these examples:**")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("✅ google.com", use_container_width=True):
            url = "https://www.google.com/search?q=weather"
    with col2:
        if st.button("⚠️ Phishing URL", use_container_width=True):
            url = "http://secure-paypal-login.xyz/verify?token=456789"
    with col3:
        if st.button("⚠️ IP-based URL", use_container_width=True):
            url = "http://192.168.1.100/chase/login"

    # --- Prediction ---
    if url:
        if not url.startswith("http"):
            url = "http://" + url

        # Extract features
        features = extract_url_features(url)
        feature_df = pd.DataFrame([features])

        # Align features with model's expected columns
        try:
            feature_values = feature_df[feature_names]
        except KeyError:
            # Feature mismatch — model was trained on different features
            st.warning("⚠️ This demo uses URL-based feature extraction. "
                       "For best results, use a model trained on the same features.")
            return

        # Scale and predict
        scaled = scaler.transform(feature_values)
        prediction = model.predict(scaled)[0]
        probabilities = model.predict_proba(scaled)[0]

        # Determine result
        if prediction == 1:
            phishing_prob = probabilities[1]
            label = "PHISHING"
            confidence = phishing_prob
        else:
            phishing_prob = probabilities[1]
            label = "SAFE"
            confidence = 1 - phishing_prob

        st.divider()

        # --- Display Result ---
        if label == "PHISHING":
            st.error(f"⚠️ **PHISHING DETECTED** — Confidence: {confidence*100:.1f}%")
            st.progress(confidence, text=f"Phishing probability: {confidence*100:.1f}%")
        else:
            st.success(f"✅ **URL appears SAFE** — Confidence: {confidence*100:.1f}%")
            st.progress(confidence, text=f"Safety confidence: {confidence*100:.1f}%")

        # --- Feature Breakdown ---
        with st.expander("🔍 Feature analysis — why this prediction?"):
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown("**URL characteristics:**")
                st.markdown(f"- URL length: **{features['url_length']}** chars")
                st.markdown(f"- Domain length: **{features['domain_length']}** chars")
                st.markdown(f"- Number of dots: **{features['num_dots']}**")
                st.markdown(f"- Hyphens in domain: **{features['num_hyphens']}**")
                st.markdown(f"- Subdomains: **{features['num_subdomains']}**")
            with col_b:
                st.markdown("**Security indicators:**")
                st.markdown(f"- Uses HTTPS: **{'Yes ✅' if features['has_https'] else 'No ❌'}**")
                st.markdown(f"- Has IP address: **{'Yes ⚠️' if features['has_ip'] else 'No'}**")
                st.markdown(f"- Suspicious TLD: **{'Yes ⚠️' if features['suspicious_tld'] else 'No'}**")
                st.markdown(f"- Contains 'login': **{'Yes' if features['has_login'] else 'No'}**")
                st.markdown(f"- Contains 'secure': **{'Yes' if features['has_secure'] else 'No'}**")

    # --- Model Performance Section ---
    st.divider()
    st.subheader("📊 Model performance")

    try:
        metrics = load_metrics()
        
        # Create comparison table
        rows = []
        for name, data in metrics.items():
            rows.append({
                "Model": name,
                "Accuracy": f"{data['accuracy']*100:.1f}%",
                "Precision": f"{data['precision']*100:.1f}%",
                "Recall": f"{data['recall']*100:.1f}%",
                "F1-Score": f"{data['f1_score']:.4f}",
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    except Exception:
        st.info("Run step2 and step3 to generate model metrics.")

    # --- Charts ---
    results_dir = os.path.join(os.path.dirname(__file__), "results")

    chart_files = {
        "Model comparison": "model_comparison.png",
        "ROC curves": "roc_curves.png",
        "Confusion matrices": "confusion_matrices.png",
        "Feature importance": "feature_importance.png",
    }

    tabs = st.tabs(list(chart_files.keys()))
    for tab, (title, filename) in zip(tabs, chart_files.items()):
        with tab:
            img_path = os.path.join(results_dir, filename)
            if os.path.exists(img_path):
                st.image(img_path, use_container_width=True)
            else:
                st.info(f"Run step3_visualize.py to generate {filename}")

    # --- Footer ---
    st.divider()
    st.markdown(
        "*Built for ECE 569A Artificial Intelligence — University of Victoria, Summer 2026*  \n"
        "*Dataset: Tan, Choon Lin (2018), Phishing Dataset for Machine Learning, Mendeley Data*"
    )


if __name__ == "__main__":
    main()
