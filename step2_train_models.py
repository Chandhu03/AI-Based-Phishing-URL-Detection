"""
STEP 2: Train Machine Learning Models
=======================================
This is where the "AI" part happens.

WHAT DOES "TRAINING" MEAN?
    Imagine showing a child 8,000 flashcards:
    - Front: a URL's features (numbers)
    - Back: "phishing" or "safe"
    
    After seeing 8,000 examples, the child learns patterns:
    "Oh, if the URL is long AND has no HTTPS AND has the word 'login',
     it's probably phishing!"
    
    That's exactly what training does. The algorithm finds patterns
    in the data automatically.

WHAT DOES "TESTING" MEAN?
    After training, we show the model 2,000 NEW URLs it has never
    seen before. We check: did it get them right?
    
    This tells us how well the model will work on real URLs in the future.

WHAT THIS FILE DOES:
    1. Loads the features CSV from Step 1
    2. Splits data: 80% for training, 20% for testing
    3. Trains 4 different models
    4. Tests each model
    5. Saves all results for Step 3 (visualization)
"""

import pandas as pd
import numpy as np
import os
import json
import pickle

# --- The 4 ML models we'll compare ---
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier

# --- Tools for splitting data and measuring performance ---
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_curve,
    auc,
)


def main():
    # =========================================================
    # PART 1: Load the data
    # =========================================================
    data_path = os.path.join(os.path.dirname(__file__), "dataset", "features.csv")
    print("=" * 60)
    print("STEP 2: TRAINING MACHINE LEARNING MODELS")
    print("=" * 60)
    
    print(f"\nLoading features from {data_path}...")
    df = pd.read_csv(data_path)
    
    # Separate features (X) from labels (y)
    # X = all columns EXCEPT "label" (the numbers describing each URL)
    # y = just the "label" column (0 = legit, 1 = phishing)
    X = df.drop("label", axis=1)
    y = df["label"]
    
    feature_names = list(X.columns)
    print(f"  Features: {len(feature_names)} columns")
    print(f"  Samples:  {len(X)} URLs")
    
    # =========================================================
    # PART 2: Split into training and testing sets
    # =========================================================
    # WHY 80/20?
    #   We use 80% of data to teach the model (training)
    #   and 20% to test if it actually learned (testing).
    #   The test set is like a "final exam" - the model has
    #   NEVER seen these URLs before.
    #
    # random_state=42 makes the split the same every time you run.
    # stratify=y ensures both sets have the same ratio of phishing/legit.
    
    print("\nSplitting data: 80% training, 20% testing...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,        # 20% for testing
        random_state=42,      # Reproducible results
        stratify=y            # Keep class balance
    )
    print(f"  Training set: {len(X_train)} URLs")
    print(f"  Testing set:  {len(X_test)} URLs")
    
    # =========================================================
    # PART 3: Scale the features
    # =========================================================
    # WHY SCALE?
    #   Some features have big numbers (url_length = 50-200)
    #   and some have small numbers (has_https = 0 or 1).
    #   
    #   Some algorithms (especially SVM) get confused by this.
    #   Scaling makes all features roughly the same range.
    #   
    #   Think of it like converting everything to the same unit.
    
    print("\nScaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # =========================================================
    # PART 4: Define the 4 models
    # =========================================================
    # Each model is a different "strategy" for finding patterns.
    
    models = {
        "Logistic Regression": LogisticRegression(
            max_iter=1000,        # Give it enough time to learn
            random_state=42
        ),
        
        "Random Forest": RandomForestClassifier(
            n_estimators=100,     # Use 100 decision trees
            max_depth=10,         # Don't let trees get too deep
            random_state=42
        ),
        
        "SVM": SVC(
            kernel="rbf",         # Use a curved boundary
            probability=True,     # We need probability scores for ROC
            random_state=42
        ),
        
        "XGBoost": XGBClassifier(
            n_estimators=100,     # 100 boosting rounds
            max_depth=6,          # Tree depth
            learning_rate=0.1,    # How fast it learns
            random_state=42,
            eval_metric="logloss",
            verbosity=0           # Don't print XGBoost logs
        ),
    }
    
    # =========================================================
    # PART 5: Train and test each model
    # =========================================================
    results = {}
    roc_data = {}
    
    for name, model in models.items():
        print(f"\n{'─' * 50}")
        print(f"Training: {name}")
        print(f"{'─' * 50}")
        
        # --- Train the model ---
        # This is where the model looks at all 8,000 training URLs
        # and learns the patterns.
        model.fit(X_train_scaled, y_train)
        print(f"  ✓ Training complete")
        
        # --- Test the model ---
        # Now show it the 2,000 URLs it has NEVER seen.
        y_pred = model.predict(X_test_scaled)
        y_prob = model.predict_proba(X_test_scaled)[:, 1]  # Probability of being phishing
        
        # --- Calculate metrics ---
        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred)
        rec = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        cm = confusion_matrix(y_test, y_pred)
        
        # ROC curve data (for plotting later)
        fpr, tpr, _ = roc_curve(y_test, y_prob)
        roc_auc = auc(fpr, tpr)
        
        # Print results
        print(f"  Accuracy:  {acc:.4f}  ({acc*100:.1f}% correct)")
        print(f"  Precision: {prec:.4f}  (when it says 'phishing', it's right {prec*100:.1f}% of the time)")
        print(f"  Recall:    {rec:.4f}  (catches {rec*100:.1f}% of actual phishing URLs)")
        print(f"  F1-Score:  {f1:.4f}  (overall balance of precision & recall)")
        print(f"  AUC-ROC:   {roc_auc:.4f}")
        print(f"\n  Confusion Matrix:")
        print(f"    Predicted:     Safe    Phishing")
        print(f"    Actual Safe:   {cm[0][0]:5d}    {cm[0][1]:5d}")
        print(f"    Actual Phish:  {cm[1][0]:5d}    {cm[1][1]:5d}")
        
        # Store results
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
    # PART 6: Cross-validation (more robust evaluation)
    # =========================================================
    print(f"\n{'=' * 60}")
    print("CROSS-VALIDATION (5-fold)")
    print("=" * 60)
    print("This trains each model 5 times on different data splits")
    print("to make sure results aren't just lucky.\n")
    
    for name, model in models.items():
        scores = cross_val_score(model, X_train_scaled, y_train, cv=5, scoring="accuracy")
        results[name]["cv_mean"] = round(scores.mean(), 4)
        results[name]["cv_std"] = round(scores.std(), 4)
        print(f"  {name:25s}: {scores.mean():.4f} ± {scores.std():.4f}")
    
    # =========================================================
    # PART 7: Feature importance (which features matter most?)
    # =========================================================
    print(f"\n{'=' * 60}")
    print("FEATURE IMPORTANCE (from Random Forest)")
    print("=" * 60)
    print("Which features are most useful for detecting phishing?\n")
    
    rf_model = models["Random Forest"]
    importances = rf_model.feature_importances_
    feature_importance = sorted(
        zip(feature_names, importances),
        key=lambda x: x[1],
        reverse=True
    )
    
    for feat_name, imp in feature_importance:
        bar = "█" * int(imp * 100)
        print(f"  {feat_name:20s}: {imp:.4f} {bar}")
    
    # =========================================================
    # PART 8: Save everything for Step 3 (visualization)
    # =========================================================
    results_dir = os.path.join(os.path.dirname(__file__), "results")
    
    # Save metrics
    with open(os.path.join(results_dir, "metrics.json"), "w") as f:
        json.dump(results, f, indent=2)
    
    # Save ROC data
    with open(os.path.join(results_dir, "roc_data.json"), "w") as f:
        json.dump(roc_data, f, indent=2)
    
    # Save feature importance
    fi_data = {name: float(imp) for name, imp in feature_importance}
    with open(os.path.join(results_dir, "feature_importance.json"), "w") as f:
        json.dump(fi_data, f, indent=2)
    
    # Save the best model (Random Forest) for the demo
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
    print("  - metrics.json         (accuracy, precision, etc.)")
    print("  - roc_data.json        (for ROC curves)")
    print("  - feature_importance.json")
    print("  - best_model.pkl       (saved model for demo)")
    print("  - scaler.pkl           (saved scaler for demo)")
    print("\nReady for Step 3 (visualization)!")


if __name__ == "__main__":
    main()
