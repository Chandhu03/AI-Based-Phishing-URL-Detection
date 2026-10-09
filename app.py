"""
PHISHING URL DETECTOR - SecureMind Labs
=======================================

This app examines the characters of a URL string only. It never visits,
fetches or resolves the site. Live predictions come from a demonstration
model trained on synthetic URLs; it has not been evaluated on real-world
data. The tables at the bottom are an offline research benchmark and are
not used for live checks.

HOW TO RUN LOCALLY:
    streamlit run app.py
"""

import html
import json
import os

import pandas as pd
import streamlit as st

from securemind.demo_model import predict, train_demo_model
from securemind.url_validation import (
    MAX_URL_LENGTH,
    URLValidationError,
    validate_url,
)

# =========================================================
# PAGE CONFIG
# =========================================================
st.set_page_config(
    page_title="SecureMind Labs — Phishing Detector",
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
# LOAD OFFLINE BENCHMARK METRICS (for display only)
# =========================================================
@st.cache_resource
def load_metrics():
    """Load model comparison metrics from the offline benchmark."""
    results_dir = os.path.join(os.path.dirname(__file__), "results")
    with open(os.path.join(results_dir, "metrics.json"), encoding="utf-8") as f:
        return json.load(f)


# =========================================================
# LIVE DEMO MODEL (trained on synthetic URLs)
# =========================================================
@st.cache_resource
def load_demo_model():
    return train_demo_model()


LIMITATIONS = (
    "This demo examines the characters of the URL string only.",
    "The website is not visited, fetched, or resolved.",
    "No live reputation or blocklist lookup is performed.",
    "False positives and false negatives are possible.",
    "A result is not a security guarantee.",
    "The live model is a demonstration trained on synthetic URLs and has not "
    "been evaluated on real-world data.",
)


def section_head(title):
    """Section heading; title is always a fixed literal."""
    st.markdown(
        f'<div class="section-head"><span class="dot"></span>'
        f'{html.escape(str(title))}</div>',
        unsafe_allow_html=True)


def render_result(n, pred):
    """Render the result for a validated URL. Only fixed text or numbers."""
    pct = pred.vote_share * 100
    features = pred.features

    section_head("Detection Result")

    if pred.is_phishing:
        st.markdown(
            '<div class="result-danger">'
            '<h3>⚠️ Phishing indicators detected in the URL text</h3>'
            '</div>',
            unsafe_allow_html=True)
    else:
        st.markdown(
            '<div class="result-safe">'
            '<h3>No phishing indicators detected in the URL text</h3>'
            '<p>The website itself was not checked.</p>'
            '</div>',
            unsafe_allow_html=True)

    st.markdown(
        f"Model vote share: {pct:.0f}% of trees agreed. "
        "This is not a calibrated probability.")

    # ---- Limitations ----
    st.markdown("**Limitations**")
    st.markdown("\n".join(f"- {s}" for s in LIMITATIONS))

    # ---- Host analysed (user-derived: only via st.code) ----
    st.markdown("**Host analysed**")
    st.code(n.hostname_display, language=None)
    if n.hostname_display != n.hostname:
        st.code(n.hostname, language=None)
        st.caption("ASCII (punycode) form")
    for note in n.notes:
        st.caption(note)

    # ---- Feature Breakdown ----
    section_head("Feature Analysis")

    if not n.scheme_explicit:
        https_item = ("HTTPS", "Not given", "warn")
    elif features["has_https"]:
        https_item = ("HTTPS", "Yes", "good")
    else:
        https_item = ("HTTPS", "No", "bad")

    feat_items = [
        ("URL Length", str(features["url_length"]),
         "warn" if features["url_length"] > 75 else ""),
        ("Domain Length", str(features["domain_length"]),
         "warn" if features["domain_length"] > 30 else ""),
        ("Dots in URL", str(features["num_dots"]),
         "warn" if features["num_dots"] > 3 else ""),
        ("Domain Hyphens", str(features["num_hyphens"]),
         "warn" if features["num_hyphens"] > 1 else ""),
        https_item,
        ("IP Address", "Yes" if features["has_ip"] else "No",
         "bad" if features["has_ip"] else "good"),
        ("Suspicious TLD", "Yes" if features["suspicious_tld"] else "No",
         "bad" if features["suspicious_tld"] else "good"),
        ("Login details in URL", "Yes" if n.has_userinfo else "No",
         "bad" if n.has_userinfo else "good"),
        ("Non-standard port", "Yes" if n.nonstandard_port else "No",
         "warn" if n.nonstandard_port else ""),
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
            f'<span class="fname">{html.escape(str(fname))}</span>'
            f'<span class="fval {html.escape(str(fcls))}">'
            f'{html.escape(str(fval))}</span>'
            f'</div>')
    grid_html += '</div>'
    st.markdown(grid_html, unsafe_allow_html=True)


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

    # ---- Load demo model for live predictions ----
    demo_model, demo_scaler = load_demo_model()

    # ---- Status row (only after the model loaded) ----
    st.markdown(
        '<span class="status-badge badge-online">● Demo model loaded</span>',
        unsafe_allow_html=True)

    # ---- Load benchmark metrics for display ----
    try:
        metrics = load_metrics()
        best_name = max(metrics, key=lambda k: metrics[k]["f1_score"])
        best_acc = metrics[best_name]["accuracy"]
    except Exception:
        metrics = None
        best_name = None
        best_acc = None

    # =========================================================
    # LAYOUT - two columns: left = controls, right = results
    # =========================================================
    left_col, right_col = st.columns([1, 1.4], gap="large")

    with left_col:
        # ---- URL Input ----
        section_head("Analyze URL")

        url = st.text_input(
            "Enter a URL to scan",
            key="url_input",
            # One character above the limit: Streamlit truncates text to
            # max_chars server-side, so allowing limit + 1 lets validate_url
            # reject over-long input explicitly instead of silently
            # analysing a truncated URL. The framework still bounds the
            # work to MAX_URL_LENGTH + 1 characters.
            max_chars=MAX_URL_LENGTH + 1,
            placeholder="https://example.com/login",
            label_visibility="collapsed",
        )

        # ---- Quick test buttons ----
        section_head("Quick Test URLs")

        qcol1, qcol2, qcol3 = st.columns(3)
        with qcol1:
            if st.button("Example: google.com", width='stretch'):
                url = "https://www.google.com/search?q=weather"
        with qcol2:
            if st.button("Example: phishing-style URL", width='stretch'):
                url = "http://secure-paypal-login.xyz/verify?token=456789"
        with qcol3:
            if st.button("Example: raw IP host", width='stretch'):
                url = "http://192.168.1.100/chase/login"

        # ---- Offline benchmark panel ----
        section_head("Offline research benchmark")

        if metrics is not None:
            acc_txt = html.escape(f"{best_acc * 100:.1f}")
            name_txt = html.escape(str(best_name))
            st.markdown(f"""
            <div class="metric-row">
                <div class="metric-card">
                    <div class="label">Benchmark accuracy</div>
                    <div class="value accent">{acc_txt}%</div>
                </div>
                <div class="metric-card">
                    <div class="label">Benchmark dataset</div>
                    <div class="value">10K</div>
                </div>
                <div class="metric-card">
                    <div class="label">Benchmark model</div>
                    <div class="value" style="font-size:1rem;">{name_txt}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)
            st.caption(
                "Benchmark: model trained on 48 webpage features from Tan "
                "(2018). It is not used for live URL checks.")
        else:
            st.info("Benchmark metrics are unavailable.")

    with right_col:
        # ---- Prediction Results ----
        if url:
            n = None
            try:
                n = validate_url(url)
            except URLValidationError as e:
                st.error(e.user_message)
            except Exception:
                # Never surface (or let Streamlit log) an unexpected error
                # whose message could contain the submitted URL.
                st.error(
                    "The URL could not be analysed because of an "
                    "internal error. No details are shown.")

            if n is not None:
                pred = None
                try:
                    pred = predict(n, demo_model, demo_scaler)
                except Exception:
                    st.error(
                        "The URL could not be analysed because of an "
                        "internal error. No details are shown.")
                if pred is not None:
                    render_result(n, pred)
        else:
            section_head("Detection Result")
            st.markdown(
                '<div class="glass-card" style="text-align:center;color:#3a4556;'
                'padding:3rem 1rem;">Enter a URL or click a quick test to start'
                '</div>', unsafe_allow_html=True)

    # =========================================================
    # OFFLINE BENCHMARK SECTION
    # =========================================================
    st.markdown("---")
    section_head("Offline research benchmark (not the live model)")
    st.caption(
        "These scores come from models trained on webpage-content features "
        "(Tan, 2018). They are not used for live URL checks and say nothing "
        "about the live demo model's accuracy.")

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
            width='stretch',
            hide_index=True)
    else:
        st.info("Benchmark metrics are unavailable.")

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
                st.image(img_path, width='stretch')
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
