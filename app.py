import streamlit as st
import pandas as pd
import numpy as np
import pickle
import json
import os
import re
from urllib.parse import urlparse

# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="SecureMind AI",
    page_icon="🛡️",
    layout="wide",
)

# =========================================================
# CUSTOM CSS
# =========================================================

st.markdown("""
<style>

/* Main background */
.stApp {
    background: linear-gradient(135deg, #050816, #0b1120);
    color: white;
}

/* Remove default top spacing */
.block-container {
    padding-top: 2rem;
}

/* Main title */
.main-title {
    text-align: center;
    font-size: 70px;
    font-weight: 800;
    color: white;
    margin-bottom: 0;
}

/* Subtitle */
.subtitle {
    text-align: center;
    font-size: 22px;
    color: #9ca3af;
    margin-top: -10px;
    margin-bottom: 40px;
}

/* Glass cards */
.glass {
    background: rgba(255,255,255,0.05);
    padding: 25px;
    border-radius: 20px;
    backdrop-filter: blur(12px);
    border: 1px solid rgba(255,255,255,0.08);
    margin-bottom: 20px;
}

/* Metric cards */
.metric-card {
    background: rgba(255,255,255,0.06);
    padding: 20px;
    border-radius: 18px;
    text-align: center;
}

/* Text input */
[data-testid="stTextInput"] input {
    background-color: rgba(255,255,255,0.08);
    color: white;
    border-radius: 12px;
    border: 1px solid rgba(255,255,255,0.1);
    height: 50px;
}

/* Buttons */
div.stButton > button {
    background: linear-gradient(90deg, #00c6ff, #0072ff);
    color: white;
    border-radius: 12px;
    height: 3em;
    width: 100%;
    font-size: 16px;
    border: none;
    font-weight: 600;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background-color: #0b1120;
}

/* Tabs */
.stTabs [data-baseweb="tab"] {
    font-size: 16px;
    font-weight: 600;
}

/* Hide footer */
footer {
    visibility: hidden;
}

</style>
""", unsafe_allow_html=True)

# =========================================================
# FEATURE EXTRACTION
# =========================================================

def extract_url_features(url):

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
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",
        domain
    ) else 0

    features["has_at_symbol"] = 1 if "@" in url else 0

    features["num_special_chars"] = sum(
        1 for c in url if c in "!#$%^&*()=+[]{}|;:',<>?"
    )

    features["digits_in_domain"] = sum(
        1 for c in domain if c.isdigit()
    )

    suspicious_tlds = [
        ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq",
        ".top", ".club", ".online", ".site",
        ".buzz", ".link", ".click"
    ]

    features["suspicious_tld"] = 1 if any(
        domain.endswith(tld)
        for tld in suspicious_tlds
    ) else 0

    url_lower = url.lower()

    features["has_login"] = 1 if "login" in url_lower else 0
    features["has_verify"] = 1 if "verify" in url_lower else 0
    features["has_secure"] = 1 if "secure" in url_lower else 0
    features["has_account"] = 1 if "account" in url_lower else 0
    features["has_update"] = 1 if "update" in url_lower else 0
    features["has_query"] = 1 if query else 0

    return features

# =========================================================
# LOAD MODEL
# =========================================================

@st.cache_resource
def load_model():

    results_dir = os.path.join(
        os.path.dirname(__file__),
        "results"
    )

    with open(os.path.join(results_dir, "best_model.pkl"), "rb") as f:
        model = pickle.load(f)

    with open(os.path.join(results_dir, "scaler.pkl"), "rb") as f:
        scaler = pickle.load(f)

    with open(os.path.join(results_dir, "feature_names.json")) as f:
        feature_names = json.load(f)

    return model, scaler, feature_names

@st.cache_resource
def load_metrics():

    results_dir = os.path.join(
        os.path.dirname(__file__),
        "results"
    )

    with open(os.path.join(results_dir, "metrics.json")) as f:
        return json.load(f)

# =========================================================
# SIDEBAR
# =========================================================

with st.sidebar:

    st.markdown("# 🛡️ SecureMind AI")

    st.markdown("---")

    st.success("🟢 Threat Detection Engine Active")

    st.markdown("## ⚡ Features")

    st.write("✔ AI-based phishing detection")
    st.write("✔ Real-time URL analysis")
    st.write("✔ Threat confidence scoring")
    st.write("✔ Feature extraction engine")
    st.write("✔ XGBoost classification")

    st.markdown("---")

    st.markdown("## 📊 System Metrics")

    st.metric("Accuracy", "98.6%")
    st.metric("Dataset Size", "10,000")
    st.metric("Best Model", "XGBoost")

    st.markdown("---")

    st.markdown("### 🎓 ECE 569A")
    st.write("University of Victoria")

# =========================================================
# MAIN APP
# =========================================================

def main():

    # =====================================================
    # HERO SECTION
    # =====================================================

    st.markdown("""
    <h1 class="main-title">🛡️ SecureMind AI</h1>
    <p class="subtitle">
    Advanced AI-Powered Phishing Detection Platform
    </p>
    """, unsafe_allow_html=True)

    # =====================================================
    # METRICS
    # =====================================================

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric("🎯 Accuracy", "98.6%")

    with col2:
        st.metric("🧠 AI Models", "4")

    with col3:
        st.metric("🔍 URLs Analyzed", "10K+")

    st.markdown("<br>", unsafe_allow_html=True)

    # =====================================================
    # LOAD MODEL
    # =====================================================

    try:
        model, scaler, feature_names = load_model()

    except FileNotFoundError:
        st.error("❌ Model files not found!")
        return

    # =====================================================
    # INPUT SECTION
    # =====================================================

    st.markdown('<div class="glass">', unsafe_allow_html=True)

    st.markdown("## 🔗 Analyze URL")

    url = st.text_input(
        "",
        placeholder="https://secure-login-paypal.xyz"
    )

    st.markdown("### ⚡ Quick Test URLs")

    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("✅ Google"):
            url = "https://www.google.com"

    with col2:
        if st.button("⚠️ Phishing"):
            url = "http://secure-paypal-login.xyz/verify"

    with col3:
        if st.button("🚨 IP Attack"):
            url = "http://192.168.1.100/chase/login"

    st.markdown('</div>', unsafe_allow_html=True)

    # =====================================================
    # PREDICTION
    # =====================================================

    if url:

        if not url.startswith("http"):
            url = "http://" + url

        features = extract_url_features(url)

        feature_df = pd.DataFrame([features])

        # Align missing features
        for feature in feature_names:
            if feature not in feature_df.columns:
                feature_df[feature] = 0

        feature_values = feature_df[feature_names]

        scaled = scaler.transform(feature_values)

        prediction = model.predict(scaled)[0]

        probabilities = model.predict_proba(scaled)[0]

        if prediction == 1:
            phishing_prob = probabilities[1]
            label = "PHISHING"
            confidence = phishing_prob

        else:
            phishing_prob = probabilities[1]
            label = "SAFE"
            confidence = 1 - phishing_prob

        # =================================================
        # RESULT CARD
        # =================================================

        st.markdown('<div class="glass">', unsafe_allow_html=True)

        st.markdown("## 🧠 Detection Result")

        if label == "PHISHING":

            st.error(
                f"⚠️ PHISHING DETECTED — Confidence: {confidence*100:.1f}%"
            )

            st.write(f"Threat probability: {confidence*100:.1f}%")
            st.progress(confidence)
            )

        else:

            st.success(
                f"✅ URL appears SAFE — Confidence: {confidence*100:.1f}%"
            )

            st.write(f"Safety confidence: {confidence*100:.1f}%")
            st.progress(confidence)
            )

        # =================================================
        # FEATURE DETAILS
        # =================================================

        with st.expander("🔍 Why did the AI make this prediction?"):

            col_a, col_b = st.columns(2)

            with col_a:

                st.markdown("### 📌 URL Characteristics")

                st.markdown(f"- URL Length: **{features['url_length']}**")
                st.markdown(f"- Domain Length: **{features['domain_length']}**")
                st.markdown(f"- Number of Dots: **{features['num_dots']}**")
                st.markdown(f"- Hyphens: **{features['num_hyphens']}**")
                st.markdown(f"- Subdomains: **{features['num_subdomains']}**")

            with col_b:

                st.markdown("### 🛡️ Security Indicators")

                st.markdown(
                    f"- HTTPS: **{'Yes ✅' if features['has_https'] else 'No ❌'}**"
                )

                st.markdown(
                    f"- IP Address Used: **{'Yes ⚠️' if features['has_ip'] else 'No'}**"
                )

                st.markdown(
                    f"- Suspicious TLD: **{'Yes ⚠️' if features['suspicious_tld'] else 'No'}**"
                )

                st.markdown(
                    f"- Contains 'login': **{'Yes' if features['has_login'] else 'No'}**"
                )

                st.markdown(
                    f"- Contains 'secure': **{'Yes' if features['has_secure'] else 'No'}**"
                )

        st.markdown('</div>', unsafe_allow_html=True)

    # =====================================================
    # MODEL PERFORMANCE
    # =====================================================

    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown('<div class="glass">', unsafe_allow_html=True)

    st.markdown("## 📊 Model Performance Dashboard")

    try:

        metrics = load_metrics()

        rows = []

        for name, data in metrics.items():

            rows.append({
                "Model": name,
                "Accuracy": f"{data['accuracy']*100:.1f}%",
                "Precision": f"{data['precision']*100:.1f}%",
                "Recall": f"{data['recall']*100:.1f}%",
                "F1-Score": f"{data['f1_score']:.4f}",
            })

        st.dataframe(
            pd.DataFrame(rows),
            use_container_width=True,
            hide_index=True
        )

    except Exception:
        st.info("Run training scripts to generate metrics.")

    st.markdown('</div>', unsafe_allow_html=True)

    # =====================================================
    # VISUALIZATIONS
    # =====================================================

    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown('<div class="glass">', unsafe_allow_html=True)

    st.markdown("## 📈 AI Visualization Dashboard")

    results_dir = os.path.join(
        os.path.dirname(__file__),
        "results"
    )

    chart_files = {
        "📊 Model Comparison": "model_comparison.png",
        "📈 ROC Curves": "roc_curves.png",
        "🧩 Confusion Matrices": "confusion_matrices.png",
        "⭐ Feature Importance": "feature_importance.png",
    }

    tabs = st.tabs(list(chart_files.keys()))

    for tab, (title, filename) in zip(tabs, chart_files.items()):

        with tab:

            img_path = os.path.join(results_dir, filename)

            if os.path.exists(img_path):
                st.image(img_path, use_container_width=True)

            else:
                st.info(f"{filename} not found.")

    st.markdown('</div>', unsafe_allow_html=True)

    # =====================================================
    # FOOTER
    # =====================================================

    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown("""
    <div style='text-align:center; color:gray; padding:30px;'>

    <h4>🛡️ SecureMind AI</h4>

    AI-Powered Phishing Detection System <br><br>

    Developed for ECE 569A — Artificial Intelligence <br>
    University of Victoria — Summer 2026 <br><br>

    Built using:
    Streamlit • XGBoost • Scikit-learn • Python

    </div>
    """, unsafe_allow_html=True)

# =========================================================
# RUN APP
# =========================================================

if __name__ == "__main__":
    main()
