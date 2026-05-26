"""
PHISHING URL DETECTOR — SecureMind AI
=======================================
ECE 569A AI Term Project | University of Victoria
 
HOW TO RUN LOCALLY:
    streamlit run app.py
 
HOW TO DEPLOY (FREE):
    1. Push to GitHub
    2. Go to https://share.streamlit.io
    3. Connect your GitHub repo
    4. Deploy — done!
"""
 
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
    page_title="SecureMind AI — Phishing Detector",
    page_icon="🛡️",
    layout="wide",
)
 
# =========================================================
# CUSTOM CSS — Cybersecurity Dashboard Theme
# =========================================================
st.markdown("""
<style>
    /* ---- Global dark theme ---- */
    .stApp {
        background: linear-gradient(160deg, #0a0e17 0%, #0d1321 40%, #0f1829 100%);
        color: #c8d6e5;
    }
 
    /* ---- Hide default Streamlit branding ---- */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
 
    /* ---- Top padding ---- */
    .block-container {
        padding-top: 2rem;
        max-width: 1100px;
    }
 
    /* ---- Hero title ---- */
    .hero-title {
        font-size: 2.6rem;
        font-weight: 800;
        background: linear-gradient(135deg, #00d2ff, #3a7bd5, #00d2ff);
        background-size: 200% auto;
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        letter-spacing: -0.5px;
        margin-bottom: 0;
        animation: shimmer 3s ease-in-out infinite;
    }
    @keyframes shimmer {
        0%, 100% { background-position: 0% center; }
        50% { background-position: 200% center; }
    }
    .hero-sub {
        color: #5e6e82;
        font-size: 0.95rem;
        margin-top: 2px;
        margin-bottom: 1.5rem;
    }
 
    /* ---- Glass card ---- */
    .glass-card {
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 16px;
        padding: 1.5rem 1.8rem;
        margin-bottom: 1.2rem;
        backdrop-filter: blur(12px);
    }
 
    /* ---- Status badge ---- */
    .status-badge {
        display: inline-block;
        padding: 4px 14px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 1px;
        text-transform: uppercase;
    }
    .badge-online {
        background: rgba(0, 210, 120, 0.15);
        color: #00d278;
        border: 1px solid rgba(0, 210, 120, 0.3);
    }
 
    /* ---- Result banners ---- */
    .result-safe {
        background: linear-gradient(135deg, rgba(0,210,120,0.12), rgba(0,180,100,0.06));
        border: 1px solid rgba(0,210,120,0.25);
        border-left: 4px solid #00d278;
        border-radius: 12px;
        padding: 1.2rem 1.5rem;
        margin: 1rem 0;
    }
    .result-safe h3 {
        color: #00d278;
        margin: 0 0 4px 0;
        font-size: 1.3rem;
    }
    .result-safe p { color: #7ecaa0; margin: 0; font-size: 0.9rem; }
 
    .result-danger {
        background: linear-gradient(135deg, rgba(255,59,48,0.12), rgba(200,40,30,0.06));
        border: 1px solid rgba(255,59,48,0.25);
        border-left: 4px solid #ff3b30;
        border-radius: 12px;
        padding: 1.2rem 1.5rem;
        margin: 1rem 0;
    }
    .result-danger h3 {
        color: #ff3b30;
        margin: 0 0 4px 0;
        font-size: 1.3rem;
    }
    .result-danger p { color: #d48a86; margin: 0; font-size: 0.9rem; }
 
    /* ---- Metric cards ---- */
    .metric-row {
        display: flex;
        gap: 12px;
        margin: 1rem 0;
    }
    .metric-card {
        flex: 1;
        background: rgba(255,255,255,0.03);
        border: 1px solid rgba(255,255,255,0.06);
        border-radius: 12px;
        padding: 1rem;
        text-align: center;
    }
    .metric-card .label {
        font-size: 0.7rem;
        color: #5e6e82;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 4px;
    }
    .metric-card .value {
        font-size: 1.6rem;
        font-weight: 700;
        color: #e8ecf1;
    }
    .metric-card .value.accent { color: #3a7bd5; }
    .metric-card .value.green { color: #00d278; }
 
    /* ---- Feature grid ---- */
    .feat-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 8px;
        margin-top: 0.8rem;
    }
    .feat-item {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 6px 12px;
        background: rgba(255,255,255,0.02);
        border-radius: 8px;
        font-size: 0.82rem;
    }
    .feat-item .fname { color: #7a8ba3; }
    .feat-item .fval { color: #c8d6e5; font-weight: 600; }
    .feat-item .fval.warn { color: #ff9500; }
    .feat-item .fval.bad { color: #ff3b30; }
    .feat-item .fval.good { color: #00d278; }
 
    /* ---- Confidence bar ---- */
    .conf-bar-wrap {
        background: rgba(255,255,255,0.05);
        border-radius: 8px;
        height: 10px;
        margin: 10px 0 6px 0;
        overflow: hidden;
    }
    .conf-bar-fill-safe {
        height: 100%;
        border-radius: 8px;
        background: linear-gradient(90deg, #00d278, #00b368);
        transition: width 0.6s ease;
    }
    .conf-bar-fill-danger {
        height: 100%;
        border-radius: 8px;
        background: linear-gradient(90deg, #ff3b30, #cc2d25);
        transition: width 0.6s ease;
    }
 
    /* ---- Section headers ---- */
    .section-head {
        font-size: 1.1rem;
        font-weight: 700;
        color: #e0e6ed;
        margin-top: 2rem;
        margin-bottom: 0.8rem;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    .section-head .dot {
        width: 8px; height: 8px;
        border-radius: 50%;
        background: #3a7bd5;
        display: inline-block;
    }
 
    /* ---- Quick test buttons ---- */
    .stButton > button {
        border-radius: 10px !important;
        font-weight: 600 !important;
        padding: 0.5rem 1rem !important;
        transition: all 0.2s ease !important;
    }
 
    /* ---- Tabs ---- */
    .stTabs [data-baseweb="tab-list"] {
        gap: 4px;
        background: rgba(255,255,255,0.02);
        border-radius: 12px;
        padding: 4px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 10px;
        color: #7a8ba3;
        font-weight: 600;
        font-size: 0.85rem;
    }
 
    /* ---- Divider ---- */
    hr {
        border-color: rgba(255,255,255,0.06) !important;
    }
 
    /* ---- Footer ---- */
    .footer-text {
        text-align: center;
        color: #3a4556;
        font-size: 0.78rem;
        margin-top: 3rem;
        padding: 1.5rem 0;
        border-top: 1px solid rgba(255,255,255,0.04);
    }
    .footer-text a { color: #3a7bd5; text-decoration: none; }
</style>
""", unsafe_allow_html=True)
 
 
# =========================================================
# FEATURE EXTRACTION (same logic as step1)
# =========================================================
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
 
 
# =========================================================
# LOAD MODEL
# =========================================================
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
 
 
# =========================================================
# MAIN APP
# =========================================================
def main():
    # ---- Hero Header ----
    st.markdown('<div class="hero-title">🛡️ SecureMind AI</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="hero-sub">'
        'AI-Powered Phishing Detection System &nbsp;·&nbsp; '
        'ECE 569A &nbsp;·&nbsp; University of Victoria'
        '</div>', unsafe_allow_html=True)
 
    # ---- Status row ----
    st.markdown(
        '<span class="status-badge badge-online">● Engine Active</span>',
        unsafe_allow_html=True)
 
    # ---- Load model ----
    try:
        model, scaler, feature_names = load_model()
    except FileNotFoundError:
        st.error("Model files not found! Run `step2_train_models_kaggle.py` first.")
        return
 
    # ---- Load metrics for sidebar stats ----
    try:
        metrics = load_metrics()
        best_name = max(metrics, key=lambda k: metrics[k]["f1_score"])
        best_acc = metrics[best_name]["accuracy"]
    except Exception:
        metrics = None
        best_name = "N/A"
        best_acc = 0
 
    # =========================================================
    # LAYOUT — two columns: left = controls, right = results
    # =========================================================
    left_col, right_col = st.columns([1, 1.4], gap="large")
 
    with left_col:
        # ---- URL Input ----
        st.markdown(
            '<div class="section-head"><span class="dot"></span>Analyze URL</div>',
            unsafe_allow_html=True)
 
        url = st.text_input(
            "Enter a URL to scan",
            placeholder="https://secure-login-paypal.xyz",
            label_visibility="collapsed",
        )
 
        # ---- Quick test buttons ----
        st.markdown(
            '<div class="section-head"><span class="dot"></span>Quick Test URLs</div>',
            unsafe_allow_html=True)
 
        qcol1, qcol2, qcol3 = st.columns(3)
        with qcol1:
            if st.button("✅ Google", use_container_width=True):
                url = "https://www.google.com/search?q=weather"
        with qcol2:
            if st.button("🔴 Phishing", use_container_width=True):
                url = "http://secure-paypal-login.xyz/verify?token=456789"
        with qcol3:
            if st.button("🔴 IP Attack", use_container_width=True):
                url = "http://192.168.1.100/chase/login"
 
        # ---- System Metrics Panel ----
        st.markdown(
            '<div class="section-head"><span class="dot"></span>System Metrics</div>',
            unsafe_allow_html=True)
 
        st.markdown(f"""
        <div class="metric-row">
            <div class="metric-card">
                <div class="label">Accuracy</div>
                <div class="value accent">{best_acc*100:.1f}%</div>
            </div>
            <div class="metric-card">
                <div class="label">Dataset</div>
                <div class="value">10K</div>
            </div>
            <div class="metric-card">
                <div class="label">Best Model</div>
                <div class="value" style="font-size:1rem;">{best_name}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
 
    with right_col:
        # ---- Prediction Results ----
        if url:
            if not url.startswith("http"):
                url = "http://" + url
 
            # Extract features
            features = extract_url_features(url)
            feature_df = pd.DataFrame([features])
 
            # Align features — fill missing Kaggle features with 0
            for feat in feature_names:
                if feat not in feature_df.columns:
                    feature_df[feat] = 0
            feature_values = feature_df[feature_names]
 
            # Scale and predict
            scaled = scaler.transform(feature_values)
            prediction = model.predict(scaled)[0]
            probabilities = model.predict_proba(scaled)[0]
 
            # =====================================================
            # DYNAMIC LABEL MAPPING
            # Works regardless of which step2 trained the model:
            #   step2_train_models.py:        label 0=legit, 1=phishing
            #   step2_train_models_kaggle.py: CLASS_LABEL 0=phishing, 1=legit
            #
            # model.classes_ tells us the actual class order.
            # We find which index corresponds to the "phishing" class.
            # =====================================================
            classes = list(model.classes_)
 
            # Determine which dataset was used based on feature count
            # Kaggle model has 48 features: CLASS_LABEL 0=phishing, 1=legit
            # Synthetic model has 18 features: label 0=legit, 1=phishing
            if len(feature_names) > 20:
                # Kaggle model: class 0 = phishing, class 1 = legitimate
                phishing_class = 0
            else:
                # Synthetic model: class 0 = legit, class 1 = phishing
                phishing_class = 1
 
            phishing_idx = classes.index(phishing_class)
            legit_idx = 1 - phishing_idx
 
            phishing_prob = probabilities[phishing_idx]
 
            if prediction == phishing_class:
                label = "PHISHING"
                confidence = phishing_prob
            else:
                label = "SAFE"
                confidence = probabilities[legit_idx]
 
            # Clamp confidence for progress bar
            conf_int = max(0, min(100, int(confidence * 100)))
 
            st.markdown(
                '<div class="section-head"><span class="dot"></span>Detection Result</div>',
                unsafe_allow_html=True)
 
            if label == "PHISHING":
                st.markdown(f"""
                <div class="result-danger">
                    <h3>⚠️ PHISHING DETECTED</h3>
                    <p>Threat confidence: {confidence*100:.1f}%</p>
                    <div class="conf-bar-wrap">
                        <div class="conf-bar-fill-danger" style="width:{conf_int}%"></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="result-safe">
                    <h3>✅ URL Appears Safe</h3>
                    <p>Safety confidence: {confidence*100:.1f}%</p>
                    <div class="conf-bar-wrap">
                        <div class="conf-bar-fill-safe" style="width:{conf_int}%"></div>
                    </div>
                </div>
                """, unsafe_allow_html=True)
 
            # ---- Feature Breakdown ----
            st.markdown(
                '<div class="section-head"><span class="dot"></span>Feature Analysis</div>',
                unsafe_allow_html=True)
 
            def val_class(val, good_val=None, bad_val=None):
                if bad_val is not None and val == bad_val:
                    return "bad"
                if good_val is not None and val == good_val:
                    return "good"
                return ""
 
            feat_items = [
                ("URL Length", str(features["url_length"]),
                 "warn" if features["url_length"] > 75 else ""),
                ("Domain Length", str(features["domain_length"]),
                 "warn" if features["domain_length"] > 30 else ""),
                ("Dots in URL", str(features["num_dots"]),
                 "warn" if features["num_dots"] > 3 else ""),
                ("Domain Hyphens", str(features["num_hyphens"]),
                 "warn" if features["num_hyphens"] > 1 else ""),
                ("HTTPS", "Yes" if features["has_https"] else "No",
                 "good" if features["has_https"] else "bad"),
                ("IP Address", "Yes" if features["has_ip"] else "No",
                 "bad" if features["has_ip"] else "good"),
                ("Suspicious TLD", "Yes" if features["suspicious_tld"] else "No",
                 "bad" if features["suspicious_tld"] else "good"),
                ("Has 'login'", "Yes" if features["has_login"] else "No",
                 "warn" if features["has_login"] else ""),
                ("Has 'secure'", "Yes" if features["has_secure"] else "No",
                 "warn" if features["has_secure"] else ""),
                ("Has 'verify'", "Yes" if features["has_verify"] else "No",
                 "warn" if features["has_verify"] else ""),
            ]
 
            grid_html = '<div class="feat-grid">'
            for fname, fval, fcls in feat_items:
                grid_html += (
                    f'<div class="feat-item">'
                    f'<span class="fname">{fname}</span>'
                    f'<span class="fval {fcls}">{fval}</span>'
                    f'</div>')
            grid_html += '</div>'
            st.markdown(grid_html, unsafe_allow_html=True)
 
        else:
            st.markdown(
                '<div class="section-head"><span class="dot"></span>'
                'Detection Result</div>',
                unsafe_allow_html=True)
            st.markdown(
                '<div class="glass-card" style="text-align:center;color:#3a4556;'
                'padding:3rem 1rem;">Enter a URL or click a quick test to start'
                '</div>', unsafe_allow_html=True)
 
    # =========================================================
    # MODEL PERFORMANCE SECTION
    # =========================================================
    st.markdown("---")
    st.markdown(
        '<div class="section-head"><span class="dot"></span>'
        'Model Performance Comparison</div>',
        unsafe_allow_html=True)
 
    if metrics:
        perf_rows = []
        for name, data in metrics.items():
            perf_rows.append({
                "Model": name,
                "Accuracy": f"{data['accuracy']*100:.1f}%",
                "Precision": f"{data['precision']*100:.1f}%",
                "Recall": f"{data['recall']*100:.1f}%",
                "F1-Score": f"{data['f1_score']:.4f}",
                "AUC-ROC": f"{data.get('auc_roc', 0)*100:.1f}%",
            })
        st.dataframe(
            pd.DataFrame(perf_rows),
            use_container_width=True,
            hide_index=True)
    else:
        st.info("Run step2 and step3 to generate model metrics.")
 
    # ---- Charts ----
    results_dir = os.path.join(os.path.dirname(__file__), "results")
    chart_files = {
        "Model Comparison": "model_comparison.png",
        "ROC Curves": "roc_curves.png",
        "Confusion Matrices": "confusion_matrices.png",
        "Feature Importance": "feature_importance.png",
    }
 
    tabs = st.tabs(list(chart_files.keys()))
    for tab, (title, filename) in zip(tabs, chart_files.items()):
        with tab:
            img_path = os.path.join(results_dir, filename)
            if os.path.exists(img_path):
                st.image(img_path, use_container_width=True)
            else:
                st.info(f"Run step3_visualize.py to generate {filename}")
 
    # ---- Footer ----
    st.markdown(
        '<div class="footer-text">'
        '🛡️ SecureMind AI &nbsp;·&nbsp; '
        'ECE 569A Artificial Intelligence &nbsp;·&nbsp; '
        'University of Victoria, Summer 2026<br>'
        'Dataset: Tan, Choon Lin (2018), '
        'Phishing Dataset for Machine Learning, Mendeley Data'
        '</div>', unsafe_allow_html=True)
 
 
if __name__ == "__main__":
    main()
