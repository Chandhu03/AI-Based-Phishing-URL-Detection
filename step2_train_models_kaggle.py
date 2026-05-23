"""
STEP 2 (KAGGLE VERSION): Train ML Models on Real Phishing Dataset
===================================================================
This version uses the REAL Kaggle dataset:
"Phishing Dataset for Machine Learning" by Tan, Choon Lin (2018)

THE DATASET:
    - 10,000 websites (5,000 phishing + 5,000 legitimate)
    - 48 features already extracted (URL structure, page content, etc.)
    - CLASS_LABEL: 1 = legitimate, 0 = phishing

WHAT THIS FILE DOES:
    1. Loads the Kaggle CSV (features already extracted!)
    2. Splits: 80% training, 20% testing
    3. Trains 4 ML models
    4. Compares performance
    5. Saves results for visualization
"""

import pandas as pd
import numpy as np
import os
import json
import pickle

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc,
)


def main():
    print("=" * 60)
    print("STEP 2: TRAINING ON REAL KAGGLE PHISHING DATASET")
    print("=" * 60)

    # =========================================================
    # PART 1: Load the Kaggle dataset
    # =========================================================
    data_path = os.path.join(os.path.dirname(__file__), "dataset", "Phishing_Legitimate_full.csv")
    print(f"\nLoading dataset from {data_path}...")
    df = pd.read_csv(data_path)

    print(f"  Total samples: {len(df)}")
    print(f"  Legitimate (1): {(df['CLASS_LABEL'] == 1).sum()}")
    print(f"  Phishing   (0): {(df['CLASS_LABEL'] == 0).sum()}")
    print(f"  Features:       {df.shape[1] - 2} (excluding id and label)")

    # Separate features (X) and label (y)
    # Drop 'id' (just a row number) and 'CLASS_LABEL' (the answer)
    X = df.drop(["id", "CLASS_LABEL"], axis=1)
    y = df["CLASS_LABEL"]

    feature_names = list(X.columns)

    # =========================================================
    # PART 2: Split into training and testing
    # =========================================================
    print("\nSplitting data: 80% training, 20% testing...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f"  Training set: {len(X_train)} samples")
    print(f"  Testing set:  {len(X_test)} samples")

    # =========================================================
    # PART 3: Scale features
    # =========================================================
    print("\nScaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # =========================================================
    # PART 4: Define the 4 models
    # =========================================================
    models = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Random Forest": RandomForestClassifier(n_estimators=200, max_depth=15, random_state=42),
        "SVM": SVC(kernel="rbf", probability=True, random_state=42),
        "XGBoost": XGBClassifier(
            n_estimators=200, max_depth=8, learning_rate=0.1,
            random_state=42, eval_metric="logloss", verbosity=0
        ),
    }

    # =========================================================
    # PART 5: Train and evaluate each model
    # =========================================================
    results = {}
    roc_data = {}

    for name, model in models.items():
        print(f"\n{'─' * 50}")
        print(f"Training: {name}")
        print(f"{'─' * 50}")

        model.fit(X_train_scaled, y_train)
        print(f"  ✓ Training complete")

        y_pred = model.predict(X_test_scaled)
        y_prob = model.predict_proba(X_test_scaled)[:, 1]

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        cm = confusion_matrix(y_test, y_pred)

        fpr, tpr, _ = roc_curve(y_test, y_prob)
        roc_auc = auc(fpr, tpr)

        print(f"  Accuracy:  {acc:.4f}  ({acc*100:.1f}% correct)")
        print(f"  Precision: {prec:.4f}")
        print(f"  Recall:    {rec:.4f}")
        print(f"  F1-Score:  {f1:.4f}")
        print(f"  AUC-ROC:   {roc_auc:.4f}")
        print(f"\n  Confusion Matrix:")
        print(f"    Predicted:       Phishing   Legit")
        print(f"    Actual Phishing:  {cm[0][0]:5d}    {cm[0][1]:5d}")
        print(f"    Actual Legit:     {cm[1][0]:5d}    {cm[1][1]:5d}")

        results[name] = {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "auc_roc": round(roc_auc, 4),
            "confusion_matrix": cm.tolist(),
        }
        roc_data[name] = {
            "fpr": fpr.tolist(),
            "tpr": tpr.tolist(),
            "auc": round(roc_auc, 4),
        }

    # =========================================================
    # PART 6: Cross-validation
    # =========================================================
    print(f"\n{'=' * 60}")
    print("CROSS-VALIDATION (5-fold)")
    print("=" * 60)

    for name, model in models.items():
        scores = cross_val_score(model, X_train_scaled, y_train, cv=5, scoring="accuracy")
        results[name]["cv_mean"] = round(scores.mean(), 4)
        results[name]["cv_std"] = round(scores.std(), 4)
        print(f"  {name:25s}: {scores.mean():.4f} ± {scores.std():.4f}")

    # =========================================================
    # PART 7: Feature importance
    # =========================================================
    print(f"\n{'=' * 60}")
    print("TOP 15 MOST IMPORTANT FEATURES (Random Forest)")
    print("=" * 60)

    rf_model = models["Random Forest"]
    importances = rf_model.feature_importances_
    feature_importance = sorted(
        zip(feature_names, importances), key=lambda x: x[1], reverse=True
    )

    for feat_name, imp in feature_importance[:15]:
        bar = "█" * int(imp * 100)
        print(f"  {feat_name:40s}: {imp:.4f} {bar}")

    # =========================================================
    # PART 8: Save everything
    # =========================================================
    results_dir = os.path.join(os.path.dirname(__file__), "results")
    os.makedirs(results_dir, exist_ok=True)

    with open(os.path.join(results_dir, "metrics.json"), "w") as f:
        json.dump(results, f, indent=2)

    with open(os.path.join(results_dir, "roc_data.json"), "w") as f:
        json.dump(roc_data, f, indent=2)

    fi_data = {name: float(imp) for name, imp in feature_importance}
    with open(os.path.join(results_dir, "feature_importance.json"), "w") as f:
        json.dump(fi_data, f, indent=2)

    best_model_name = max(results, key=lambda k: results[k]["f1_score"])
    print(f"\n{'=' * 60}")
    print(f"BEST MODEL: {best_model_name} (F1 = {results[best_model_name]['f1_score']})")
    print(f"{'=' * 60}")

    with open(os.path.join(results_dir, "best_model.pkl"), "wb") as f:
        pickle.dump(models[best_model_name], f)
    with open(os.path.join(results_dir, "scaler.pkl"), "wb") as f:
        pickle.dump(scaler, f)
    with open(os.path.join(results_dir, "feature_names.json"), "w") as f:
        json.dump(feature_names, f)

    print(f"\nAll results saved to {results_dir}/")
    print("Run step3_visualize.py next to generate charts!")


if __name__ == "__main__":
    main()
