# Phishing URL Detection — ECE 569A AI Project
## Complete Beginner's Guide

---

## What is this project?
A program that looks at a website link (URL) and predicts:
**"Is this link trying to scam someone, or is it safe?"**

---

## How to run (4 commands, that's it)

```bash
# Step 0: Generate a practice dataset (replace with Kaggle data later)
python step0_generate_dataset.py

# Step 1: Turn URLs into numbers (feature extraction)
python step1_extract_features.py

# Step 2: Train 4 AI models and compare them
python step2_train_models.py

# Step 3: Create all charts for the report
python step3_visualize.py

# Step 4: Live demo — type any URL and get a prediction
python step4_demo.py
```

---

## Requirements
```bash
pip install pandas scikit-learn xgboost matplotlib seaborn
```

---

## Project structure
```
phishing_project/
├── step0_generate_dataset.py    ← Creates practice data
├── step1_extract_features.py    ← Turns URLs into numbers
├── step2_train_models.py        ← Trains 4 ML models
├── step3_visualize.py           ← Makes all charts
├── step4_demo.py                ← Live demo for presentation
├── dataset/
│   ├── urls.csv                 ← Raw URLs with labels
│   └── features.csv             ← URLs converted to numbers
├── results/
│   ├── metrics.json             ← Model scores
│   ├── roc_data.json            ← ROC curve data
│   ├── feature_importance.json  ← Which features matter
│   ├── best_model.pkl           ← Saved trained model
│   ├── scaler.pkl               ← Saved scaler
│   ├── model_comparison.png     ← Chart for report
│   ├── confusion_matrices.png   ← Chart for report
│   ├── roc_curves.png           ← Chart for report
│   ├── feature_importance.png   ← Chart for report
│   └── summary_table.png        ← Table for report
└── README.md                    ← This file
```

---

## IMPORTANT: Using a real Kaggle dataset
The synthetic dataset gives perfect (100%) accuracy because the
patterns are too obvious. For your actual submission:

1. Go to https://www.kaggle.com/datasets/shashwatwork/phishing-dataset-for-machine-learning
   or search "phishing URL dataset" on Kaggle
2. Download the CSV file
3. Make sure it has columns: "url" and "label" (0=safe, 1=phishing)
4. Replace dataset/urls.csv with the downloaded file
5. Re-run steps 1-4

With real data you'll get realistic scores like 93-97% accuracy,
which is what professors expect to see.

---

## What each team member should own

| Member | Responsibility | Files |
|--------|---------------|-------|
| Member 1 | Dataset + Feature Extraction | step0, step1 |
| Member 2 | Model Training + Tuning | step2 |
| Member 3 | Visualization + Report + Demo | step3, step4 |

---

## Key terms explained (for the presentation)

- **Feature**: A measurable fact about a URL (its length, number of dots, etc.)
- **Training**: Showing the model thousands of labeled examples so it learns patterns
- **Testing**: Checking the model on URLs it has never seen before
- **Accuracy**: % of predictions that were correct
- **Precision**: When the model says "phishing", how often is it right?
- **Recall**: Out of all actual phishing URLs, how many did it catch?
- **F1-Score**: A single number balancing precision and recall
- **ROC/AUC**: How well the model ranks phishing URLs above safe ones (1.0 = perfect)
- **Cross-validation**: Training 5 times on different splits to confirm results aren't lucky
- **Feature importance**: Which URL characteristics are most useful for detection
