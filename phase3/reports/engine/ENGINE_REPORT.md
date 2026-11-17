# Engine model: evaluation report

Generated 2026-11-13T01:55:50Z (scikit-learn 1.8.0, numpy 2.4.6). Model id `url-host-ea3f55ce1c18faa2` (SHA-256 of the scoring fields: `ea3f55ce1c18faa23fc0f9ec36cca75048b15f91314bf180edecc59cf9dfa285`).

HOST-view hashed character 3-5-gram logistic regression trained on the union of the PhiUSIIL and Hannousse training domains. Model choice, quantisation, calibration and thresholds use the union validation split only; each test set was scored once. Metrics are for the shipped (dequantised, calibrated) weights.

## Data

| Item | Value |
|---|---|
| union rows_in | 246773 |
| union cross_dataset_conflicting_urls | 0 |
| union cross_dataset_conflicting_rows | 0 |
| union cross_dataset_duplicate_rows_collapsed | 44 |
| union rows_out | 246729 |
| union shared_groups | {'train_val': 0, 'train_test': 0, 'val_test': 0} |
| rows: train | 170734 |
| rows: val | 38233 |
| rows: phiusiil_test | 35816 |
| rows: hannousse_test | 1946 |

## Selection (validation PR-AUC)

| n_features | C | val PR-AUC | val ROC-AUC | fit s |
|---|---|---|---|---|
| 2^14 | 1.0 | 0.9006 | 0.8988 | 2.5 |
| 2^14 | 4.0 | 0.8973 | 0.8948 | 3.9 |
| 2^14 | 16.0 | 0.8891 | 0.8864 | 5.7 |
| 2^16 | 1.0 | 0.9054 | 0.9051 | 3.7 |
| 2^16 | 4.0 | 0.9036 | 0.9023 | 4.9 |
| 2^16 | 16.0 | 0.8902 | 0.8879 | 12.6 |
| 2^18 | 1.0 | 0.9057 | 0.9067 | 4.7 |
| 2^18 | 4.0 | 0.9053 | 0.9058 | 10.4 |
| 2^18 | 16.0 | 0.8924 | 0.8918 | 14.0 |

Rule: max validation PR-AUC; smallest n_features within 0.002 of the best. Selected: n_features = 2^16, C = 1.0.

Quantisation (int8 if |delta val ROC-AUC| < 0.002): validation ROC-AUC float64 0.90505, int16 0.90505, int8 0.90475; shipped `int8`.

Calibration: Platt scaling on validation logits, a = 1.4116, b = 0.6341. Thresholds (high: validation FPR <= 0.01; elevated: validation FPR <= 0.05): high = 0.8670, elevated = 0.6428.

## Held-out test domains

Baselines use thresholds chosen on the same union validation split.

| Test set | Model | n | ROC-AUC | PR-AUC | recall@high | FPR@high | recall@elevated | FPR@elevated | Brier | ECE |
|---|---|---|---|---|---|---|---|---|---|---|
| phiusiil_test | engine_shipped | 35816 | 0.9156 | 0.9214 | 0.642 | 0.009 | 0.742 | 0.050 | 0.1076 | 0.0338 |
| hannousse_test | engine_shipped | 1946 | 0.8497 | 0.8985 | 0.538 | 0.036 | 0.666 | 0.112 | 0.1595 | 0.0710 |
| phiusiil_test | baseline_A_host_phiusiil | 35816 | 0.9191 | 0.9253 | 0.654 | 0.008 | 0.749 | 0.045 | 0.1019 | 0.0241 |
| hannousse_test | baseline_A_host_phiusiil | 1946 | 0.8318 | 0.8813 | 0.525 | 0.049 | 0.651 | 0.102 | 0.1737 | 0.1009 |
| phiusiil_test | reference_demo_model | 35816 | 0.8478 | 0.8403 | 0.132 | 0.000 | 0.626 | 0.017 | 0.2696 | 0.3154 |
| hannousse_test | reference_demo_model | 1946 | 0.7800 | 0.8227 | 0.575 | 0.183 | 0.859 | 0.516 | 0.2252 | 0.1800 |

Calibration of the engine before Platt scaling (raw sigmoid of the logit):

| Test set | Brier raw | ECE raw | Brier calibrated | ECE calibrated |
|---|---|---|---|---|
| phiusiil_test | 0.1066 | 0.0302 | 0.1076 | 0.0338 |
| hannousse_test | 0.1612 | 0.0873 | 0.1595 | 0.0710 |

## Leave-one-dataset-out transfer (selected configuration)

Trained on one dataset's training domains, calibrated and thresholded on its validation domains, tested on the other dataset's test domains.

| Direction | ROC-AUC | PR-AUC | recall@high | FPR@high | recall@elevated | FPR@elevated |
|---|---|---|---|---|---|---|
| train_phiusiil_test_hannousse | 0.8381 | 0.8854 | 0.538 | 0.050 | 0.669 | 0.099 |
| train_hannousse_test_phiusiil | 0.8022 | 0.7929 | 0.301 | 0.018 | 0.469 | 0.058 |

## Export

`website/src/engine/models/url-host-model.js` (92521 bytes) and `url-host-model.golden.json` (318 vectors). An independent pure-Python scorer matched scikit-learn to 1e-9 on every golden vector before anything was written.

## Limitations

- Both datasets are public and dated; performance on new campaigns is unknown.
- The model sees only the hostname. Path, query and userinfo signals are handled by the separate rule layer, which is not evaluated here.
- Test sets are dominated by a few large domains (see EVALUATION_REPORT.md); no bootstrap intervals are computed for this experiment.
- A low score is not evidence that a URL is safe.
