# Phase 3 evaluation report

Generated 2026-10-09T06:36:03Z by `python phase3/run.py evaluate`. Environment: Python 3.12.10, scikit-learn 1.8.0. Machine-readable source: `metrics.json`, `data_stats.json`.

All results below are on **real, published datasets** (not synthetic fixtures). Positive class = phishing. Thresholds were chosen on the validation split only; test sets were scored once, after model selection. Bracketed ranges are 95% bootstrap intervals that resample whole domains (only for the selected candidate, baseline and reference).

## Data

| | phiusiil | hannousse |
|---|---|---|
| Rows in | 235795 | 11430 |
| Rejected by app validator | 9 | 4 |
| Exact duplicates removed | 437 | 2 |
| Conflicting-label rows removed | 0 | 0 |
| Rows after cleaning | 235349 | 11424 |
| Registrable domains | 197297 | 7261 |
| Domains with both labels | 106 | 17 |
| Phishing / legitimate after cleaning | 100499 / 134850 | 5709 / 5715 |
| train: rows (phishing) / domains | 163229 (68807) / 138294 | 7522 (3656) / 5127 |
| val: rows (phishing) / domains | 36304 (16036) / 29481 | 1933 (936) / 1062 |
| test: rows (phishing) / domains | 35816 (15656) / 29522 | 1969 (1117) / 1072 |
| Domains shared between splits | 0 | 0 |

Domains present in both datasets: 814 (44 identical URLs). External test sets exclude them: 1799 Hannousse rows and 0 PhiUSIIL test rows removed.

Public Suffix List: 78 official test vectors passed, 0 failed (commit 392946265269).

## Shortcut probe

A one-line rule with no machine learning: *legitimate iff https AND host starts with `www.` AND no path/query*.

| Test set | Precision | Recall | FPR | F1 |
|---|---|---|---|---|
| PhiUSIIL held-out domains | 1.000 | 0.991 | 0.0000 | 0.996 |
| Hannousse held-out domains | 0.607 | 0.996 | 0.8439 | 0.754 |

If this rule scores highly, the dataset rewards the artefact rather than phishing behaviour; full-URL results on that dataset are not credible evidence.

## Experiment A: HOST view, trained on PhiUSIIL

Selected on validation PR-AUC: **logreg_charngram**. Baseline: logreg_lexical.

Validation PR-AUC by family (best hyperparameters):

- logreg_lexical: 0.8734 with {'C': 10.0}
- hgb_lexical: 0.8907 with {'learning_rate': 0.1, 'max_leaf_nodes': 31, 'max_iter': 300}
- logreg_charngram: 0.9150 with {'C': 4.0}

### PhiUSIIL held-out domains

| Model | Role | ROC-AUC | PR-AUC | Threshold (from validation) | Precision | Recall | FPR | TN / FP / FN / TP |
|---|---|---|---|---|---|---|---|---|
| logreg_lexical | baseline | 0.781 [0.689–0.849] | 0.827 [0.782–0.870] | FPR≤1% on val (0.809) | 0.971 [0.953–0.983] | 0.469 [0.381–0.555] | 0.0111 [0.007–0.017] | 19937 / 223 / 8318 / 7338 |
|  |  |  |  | max-F1 on val (0.403) | 0.879 | 0.626 | 0.0667 | 18816 / 1344 / 5855 / 9801 |
| hgb_lexical | candidate | 0.854 | 0.869 | FPR≤1% on val (0.799) | 0.976 | 0.543 | 0.0102 | 19954 / 206 / 7154 / 8502 |
|  |  |  |  | max-F1 on val (0.449) | 0.923 | 0.628 | 0.0405 | 19344 / 816 / 5831 / 9825 |
| logreg_charngram | selected candidate | 0.919 [0.902–0.935] | 0.925 [0.897–0.949] | FPR≤1% on val (0.743) | 0.982 [0.975–0.988] | 0.662 [0.593–0.725] | 0.0092 [0.008–0.011] | 19975 / 185 / 5298 / 10358 |
|  |  |  |  | max-F1 on val (0.339) | 0.833 | 0.813 | 0.1269 | 17602 / 2558 / 2922 / 12734 |
| reference_demo_model | reference (current app) | 0.848 [0.809–0.885] | 0.840 [0.786–0.890] | FPR≤1% on val (0.210) | 0.983 [0.975–0.989] | 0.530 [0.433–0.633] | 0.0072 [0.006–0.008] | 20014 / 146 / 7358 / 8298 |
|  |  |  |  | max-F1 on val (0.010) | 0.828 | 0.751 | 0.1212 | 17716 / 2444 / 3895 / 11761 |
|  |  |  |  | app default 0.5 (0.500) | 0.999 | 0.106 | 0.0001 | 20158 / 2 / 13989 / 1667 |

### Hannousse (external; PhiUSIIL train/val domains removed)

| Model | Role | ROC-AUC | PR-AUC | Threshold (from validation) | Precision | Recall | FPR | TN / FP / FN / TP |
|---|---|---|---|---|---|---|---|---|
| logreg_lexical | baseline | 0.664 [0.618–0.709] | 0.734 [0.663–0.800] | FPR≤1% on val (0.809) | 0.787 [0.706–0.858] | 0.384 [0.317–0.463] | 0.1075 [0.076–0.144] | 4228 / 509 / 3009 / 1879 |
|  |  |  |  | max-F1 on val (0.403) | 0.727 | 0.492 | 0.1908 | 3833 / 904 / 2482 / 2406 |
| hgb_lexical | candidate | 0.668 | 0.737 | FPR≤1% on val (0.799) | 0.784 | 0.424 | 0.1203 | 4167 / 570 / 2814 / 2074 |
|  |  |  |  | max-F1 on val (0.449) | 0.709 | 0.487 | 0.2065 | 3759 / 978 / 2507 / 2381 |
| logreg_charngram | selected candidate | 0.741 [0.711–0.772] | 0.769 [0.716–0.822] | FPR≤1% on val (0.743) | 0.856 [0.805–0.891] | 0.356 [0.293–0.439] | 0.0616 [0.050–0.074] | 4445 / 292 / 3148 / 1740 |
|  |  |  |  | max-F1 on val (0.339) | 0.721 | 0.604 | 0.2415 | 3593 / 1144 / 1934 / 2954 |
| reference_demo_model | reference (current app) | 0.717 [0.682–0.751] | 0.700 [0.629–0.771] | FPR≤1% on val (0.210) | 0.644 [0.598–0.692] | 0.724 [0.686–0.761] | 0.4136 [0.387–0.442] | 2778 / 1959 / 1348 / 3540 |
|  |  |  |  | max-F1 on val (0.010) | 0.592 | 0.875 | 0.6230 | 1786 / 2951 / 612 / 4276 |
|  |  |  |  | app default 0.5 (0.500) | 0.746 | 0.382 | 0.1341 | 4102 / 635 / 3022 / 1866 |

Most important lexical features (HGB permutation importance, validation PR-AUC drop): `host_len` 0.145, `host_digits` 0.076, `host_labels` 0.066, `tld_suspicious` 0.041, `tld_len` 0.030, `subdomain_labels` 0.024, `host_entropy` 0.018, `host_max_label_len` 0.017

## Experiment B: FULL view, trained on Hannousse

Selected on validation PR-AUC: **logreg_charngram**. Baseline: logreg_lexical.

Validation PR-AUC by family (best hyperparameters):

- logreg_lexical: 0.9120 with {'C': 10.0}
- hgb_lexical: 0.9360 with {'learning_rate': 0.1, 'max_leaf_nodes': 15, 'max_iter': 300}
- logreg_charngram: 0.9691 with {'C': 16.0}

### Hannousse held-out domains

| Model | Role | ROC-AUC | PR-AUC | Threshold (from validation) | Precision | Recall | FPR | TN / FP / FN / TP |
|---|---|---|---|---|---|---|---|---|
| logreg_lexical | baseline | 0.941 [0.904–0.971] | 0.957 [0.885–0.987] | FPR≤1% on val (0.935) | 0.985 [0.942–0.997] | 0.574 [0.336–0.745] | 0.0117 [0.003–0.023] | 842 / 10 / 476 / 641 |
|  |  |  |  | max-F1 on val (0.452) | 0.870 | 0.877 | 0.1714 | 706 / 146 / 137 / 980 |
| hgb_lexical | candidate | 0.964 | 0.975 | FPR≤1% on val (0.946) | 0.993 | 0.627 | 0.0059 | 847 / 5 / 417 / 700 |
|  |  |  |  | max-F1 on val (0.348) | 0.866 | 0.939 | 0.1913 | 689 / 163 / 68 / 1049 |
| logreg_charngram | selected candidate | 0.967 [0.940–0.985] | 0.977 [0.940–0.994] | FPR≤1% on val (0.858) | 0.988 [0.968–0.997] | 0.760 [0.625–0.855] | 0.0117 [0.004–0.022] | 842 / 10 / 268 / 849 |
|  |  |  |  | max-F1 on val (0.522) | 0.886 | 0.918 | 0.1549 | 720 / 132 / 92 / 1025 |
| reference_demo_model | reference (current app) | 0.776 [0.651–0.858] | 0.822 [0.582–0.931] | FPR≤1% on val (1.000) | 0.000 [0.000–0.000] | 0.000 [0.000–0.000] | 0.0000 [0.000–0.000] | 852 / 0 / 1117 / 0 |
|  |  |  |  | max-F1 on val (0.090) | 0.673 | 0.876 | 0.5587 | 376 / 476 / 138 / 979 |
|  |  |  |  | app default 0.5 (0.500) | 0.822 | 0.532 | 0.1514 | 723 / 129 / 523 / 594 |

### PhiUSIIL test (external; Hannousse train/val domains removed)

| Model | Role | ROC-AUC | PR-AUC | Threshold (from validation) | Precision | Recall | FPR | TN / FP / FN / TP |
|---|---|---|---|---|---|---|---|---|
| logreg_lexical | baseline | 0.877 [0.845–0.904] | 0.902 [0.864–0.931] | FPR≤1% on val (0.935) | 0.999 [0.998–1.000] | 0.279 [0.244–0.319] | 0.0001 [0.000–0.000] | 20157 / 3 / 11292 / 4364 |
|  |  |  |  | max-F1 on val (0.452) | 0.993 | 0.657 | 0.0037 | 20086 / 74 / 5372 / 10284 |
| hgb_lexical | candidate | 0.870 | 0.895 | FPR≤1% on val (0.946) | 0.990 | 0.300 | 0.0024 | 20111 / 49 / 10967 / 4689 |
|  |  |  |  | max-F1 on val (0.348) | 0.936 | 0.725 | 0.0385 | 19383 / 777 / 4307 / 11349 |
| logreg_charngram | selected candidate | 0.871 [0.844–0.892] | 0.889 [0.849–0.921] | FPR≤1% on val (0.858) | 1.000 [0.999–1.000] | 0.382 [0.335–0.432] | 0.0001 [0.000–0.000] | 20158 / 2 / 9674 / 5982 |
|  |  |  |  | max-F1 on val (0.522) | 0.997 | 0.602 | 0.0012 | 20136 / 24 / 6231 / 9425 |
| reference_demo_model | reference (current app) | 0.848 [0.809–0.885] | 0.840 [0.786–0.890] | FPR≤1% on val (1.000) | 0.000 [0.000–0.000] | 0.000 [0.000–0.000] | 0.0000 [0.000–0.000] | 20160 / 0 / 15656 / 0 |
|  |  |  |  | max-F1 on val (0.090) | 0.874 | 0.666 | 0.0749 | 18651 / 1509 / 5230 / 10426 |
|  |  |  |  | app default 0.5 (0.500) | 0.999 | 0.106 | 0.0001 | 20158 / 2 / 13989 / 1667 |

Most important lexical features (HGB permutation importance, validation PR-AUC drop): `has_www` 0.050, `path_depth` 0.041, `path_digits` 0.038, `path_len` 0.025, `path_special` 0.018, `query_len` 0.018, `path_keyword_hits` 0.018, `subdomain_labels` 0.014

## How to read this

- **Experiment A, external Hannousse** is the most honest generalisation number: a different dataset, collection period and URL style, with no shared domains.
- **Experiment B, Hannousse test** is small (about 2,000 URLs); see the confidence intervals.
- **Experiment B on PhiUSIIL** is distorted by PhiUSIIL's homepage-only legitimate class.
- The reference model is the current app model (synthetic training data); its `app default 0.5` row is how the live app behaves.
- Recall at FPR ≤ 1% uses a threshold chosen on validation; the realised test FPR is reported and can exceed 1%. FPR ≤ 0.1% is not reported: validation sets are too small to estimate it reliably for Hannousse.
