"""
STEP 3: Generate Visualizations
=================================
This creates all the graphs and charts for your report and presentation.

WHAT GRAPHS DO WE MAKE?
    1. Model Comparison Bar Chart   - Which model is best?
    2. Confusion Matrices           - Where did each model make mistakes?
    3. ROC Curves                   - How good is each model at ranking?
    4. Feature Importance Bar Chart  - Which URL features matter most?

WHY ARE VISUALIZATIONS IMPORTANT?
    The professor's rubric says:
    "Use graphs, charts, and/or tables to effectively display results" (25%)
    
    Good graphs = good grade. These are publication-quality charts.
"""

import json
import os
import numpy as np
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use("Agg")  # No GUI needed
import seaborn as sns

# Set a clean style
plt.style.use("seaborn-v0_8-whitegrid")
sns.set_palette("husl")


def load_results():
    """Load all results from Step 2."""
    results_dir = os.path.join(os.path.dirname(__file__), "results")
    
    with open(os.path.join(results_dir, "metrics.json")) as f:
        metrics = json.load(f)
    with open(os.path.join(results_dir, "roc_data.json")) as f:
        roc_data = json.load(f)
    with open(os.path.join(results_dir, "feature_importance.json")) as f:
        feature_importance = json.load(f)
    
    return metrics, roc_data, feature_importance


def plot_model_comparison(metrics, save_dir):
    """
    Bar chart comparing all 4 models across all metrics.
    This is the MAIN chart for your report.
    """
    print("  Creating model comparison chart...")
    
    model_names = list(metrics.keys())
    metric_names = ["accuracy", "precision", "recall", "f1_score", "auc_roc"]
    display_names = ["Accuracy", "Precision", "Recall", "F1-Score", "AUC-ROC"]
    
    x = np.arange(len(display_names))
    width = 0.18
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    colors = ["#3B8BD4", "#2EAD6D", "#E87040", "#8B5CF6"]
    
    for i, (model, color) in enumerate(zip(model_names, colors)):
        values = [metrics[model][m] for m in metric_names]
        offset = (i - 1.5) * width
        bars = ax.bar(x + offset, values, width, label=model, color=color, alpha=0.85)
        
        # Add value labels on top of each bar
        for bar, val in zip(bars, values):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.005,
                f"{val:.3f}",
                ha="center", va="bottom",
                fontsize=7, fontweight="bold"
            )
    
    ax.set_ylabel("Score", fontsize=12)
    ax.set_title("Model Performance Comparison", fontsize=14, fontweight="bold", pad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(display_names, fontsize=11)
    ax.set_ylim(0, 1.12)
    ax.legend(loc="upper right", fontsize=10)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(save_dir, "model_comparison.png"), dpi=200, bbox_inches="tight")
    plt.close()


def plot_confusion_matrices(metrics, save_dir):
    """
    Confusion matrix for each model.
    
    WHAT IS A CONFUSION MATRIX?
        It's a 2x2 grid showing:
        - Top-left:     Correctly identified as SAFE        (True Negative)
        - Top-right:    Wrongly flagged as phishing          (False Positive)
        - Bottom-left:  Missed phishing (said it was safe)   (False Negative)  ← DANGEROUS!
        - Bottom-right: Correctly caught phishing            (True Positive)
    """
    print("  Creating confusion matrices...")
    
    fig, axes = plt.subplots(1, 4, figsize=(18, 4))
    
    for ax, (name, data) in zip(axes, metrics.items()):
        cm = np.array(data["confusion_matrix"])
        
        sns.heatmap(
            cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=["Safe", "Phishing"],
            yticklabels=["Safe", "Phishing"],
            ax=ax, cbar=False,
            annot_kws={"size": 14, "fontweight": "bold"}
        )
        ax.set_title(name, fontsize=11, fontweight="bold")
        ax.set_ylabel("Actual" if ax == axes[0] else "")
        ax.set_xlabel("Predicted")
    
    plt.suptitle("Confusion Matrices", fontsize=14, fontweight="bold", y=1.02)
    plt.tight_layout()
    plt.savefig(os.path.join(save_dir, "confusion_matrices.png"), dpi=200, bbox_inches="tight")
    plt.close()


def plot_roc_curves(roc_data, save_dir):
    """
    ROC Curve for each model.
    
    WHAT IS AN ROC CURVE?
        It shows the trade-off between:
        - Catching more phishing (True Positive Rate, y-axis)
        - Accidentally flagging safe URLs (False Positive Rate, x-axis)
        
        The CLOSER the curve is to the TOP-LEFT corner, the BETTER.
        A perfect model hugs the top-left. A random guess is diagonal.
        
        AUC = Area Under the Curve. Closer to 1.0 = better.
    """
    print("  Creating ROC curves...")
    
    fig, ax = plt.subplots(figsize=(8, 6))
    
    colors = ["#3B8BD4", "#2EAD6D", "#E87040", "#8B5CF6"]
    
    for (name, data), color in zip(roc_data.items(), colors):
        ax.plot(
            data["fpr"], data["tpr"],
            label=f'{name} (AUC = {data["auc"]:.3f})',
            color=color, linewidth=2
        )
    
    # Diagonal line = random guess
    ax.plot([0, 1], [0, 1], "k--", alpha=0.3, label="Random Guess")
    
    ax.set_xlabel("False Positive Rate", fontsize=12)
    ax.set_ylabel("True Positive Rate", fontsize=12)
    ax.set_title("ROC Curves — Model Comparison", fontsize=14, fontweight="bold")
    ax.legend(loc="lower right", fontsize=10)
    ax.set_xlim([-0.02, 1.02])
    ax.set_ylim([-0.02, 1.02])
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    
    plt.tight_layout()
    plt.savefig(os.path.join(save_dir, "roc_curves.png"), dpi=200, bbox_inches="tight")
    plt.close()


def plot_feature_importance(feature_importance, save_dir):
    """
    Horizontal bar chart showing which features matter most.
    
    WHY THIS MATTERS:
        This tells you which URL characteristics are the best
        indicators of phishing. Great for the "discussion" section
        of your report.
    """
    print("  Creating feature importance chart...")
    
    # Sort by importance
    sorted_features = sorted(feature_importance.items(), key=lambda x: x[1])
    names = [f[0] for f in sorted_features]
    values = [f[1] for f in sorted_features]
    
    # Make the names more readable
    display_names = {
        "url_length": "URL length",
        "domain_length": "Domain length",
        "path_length": "Path length",
        "num_dots": "Number of dots",
        "num_hyphens": "Hyphens in domain",
        "num_subdomains": "Number of subdomains",
        "has_https": "Uses HTTPS",
        "has_ip": "Has IP address",
        "has_at_symbol": "Has @ symbol",
        "num_special_chars": "Special characters",
        "digits_in_domain": "Digits in domain",
        "suspicious_tld": "Suspicious TLD (.xyz etc)",
        "has_login": 'Contains "login"',
        "has_verify": 'Contains "verify"',
        "has_secure": 'Contains "secure"',
        "has_account": 'Contains "account"',
        "has_update": 'Contains "update"',
        "has_query": "Has query params",
    }
    names = [display_names.get(n, n) for n in names]
    
    fig, ax = plt.subplots(figsize=(10, 8))
    
    # Color bars by importance
    colors = plt.cm.YlOrRd(np.linspace(0.2, 0.8, len(values)))
    
    ax.barh(names, values, color=colors, height=0.7)
    ax.set_xlabel("Importance Score", fontsize=12)
    ax.set_title("Feature Importance (Random Forest)", fontsize=14, fontweight="bold")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    
    # Add value labels
    for i, (name, val) in enumerate(zip(names, values)):
        ax.text(val + 0.002, i, f"{val:.3f}", va="center", fontsize=9)
    
    plt.tight_layout()
    plt.savefig(os.path.join(save_dir, "feature_importance.png"), dpi=200, bbox_inches="tight")
    plt.close()


def create_summary_table(metrics, save_dir):
    """Create a clean summary table as an image (for the report)."""
    print("  Creating summary table...")
    
    fig, ax = plt.subplots(figsize=(10, 3))
    ax.axis("off")
    
    headers = ["Model", "Accuracy", "Precision", "Recall", "F1-Score", "AUC-ROC", "CV Mean ± Std"]
    rows = []
    for name, data in metrics.items():
        rows.append([
            name,
            f"{data['accuracy']:.4f}",
            f"{data['precision']:.4f}",
            f"{data['recall']:.4f}",
            f"{data['f1_score']:.4f}",
            f"{data['auc_roc']:.4f}",
            f"{data['cv_mean']:.4f} ± {data['cv_std']:.4f}",
        ])
    
    table = ax.table(
        cellText=rows,
        colLabels=headers,
        cellLoc="center",
        loc="center",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 1.8)
    
    # Style the header
    for j in range(len(headers)):
        table[0, j].set_facecolor("#3B8BD4")
        table[0, j].set_text_props(color="white", fontweight="bold")
    
    # Alternate row colors
    for i in range(1, len(rows) + 1):
        color = "#F0F4F8" if i % 2 == 0 else "white"
        for j in range(len(headers)):
            table[i, j].set_facecolor(color)
    
    # Highlight best F1 row
    best_idx = max(range(len(rows)), key=lambda i: float(rows[i][4])) + 1
    for j in range(len(headers)):
        table[best_idx, j].set_facecolor("#E6F3E6")
    
    plt.title("Model Performance Summary", fontsize=14, fontweight="bold", pad=20)
    plt.savefig(os.path.join(save_dir, "summary_table.png"), dpi=200, bbox_inches="tight")
    plt.close()


def main():
    print("=" * 60)
    print("STEP 3: GENERATING VISUALIZATIONS")
    print("=" * 60)
    
    metrics, roc_data, feature_importance = load_results()
    save_dir = os.path.join(os.path.dirname(__file__), "results")
    
    plot_model_comparison(metrics, save_dir)
    plot_confusion_matrices(metrics, save_dir)
    plot_roc_curves(roc_data, save_dir)
    plot_feature_importance(feature_importance, save_dir)
    create_summary_table(metrics, save_dir)
    
    print(f"\nAll charts saved to {save_dir}/")
    print("  - model_comparison.png")
    print("  - confusion_matrices.png")
    print("  - roc_curves.png")
    print("  - feature_importance.png")
    print("  - summary_table.png")
    print("\nThese go directly into your report and poster!")


if __name__ == "__main__":
    main()
