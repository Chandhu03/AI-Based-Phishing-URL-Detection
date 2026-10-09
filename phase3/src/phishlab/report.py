"""Render reports/EVALUATION_REPORT.md from metrics.json and data_stats.json.

Every number in the report is read from those two machine-readable files;
nothing is typed in by hand.
"""
from __future__ import annotations

from pathlib import Path

LABELS = {"phiusiil_test": "PhiUSIIL held-out domains",
          "hannousse_external": "Hannousse (external; PhiUSIIL train/val domains removed)",
          "hannousse_test": "Hannousse held-out domains",
          "phiusiil_external": "PhiUSIIL test (external; Hannousse train/val domains removed)"}


def _f(x, digits=3):
    return "n/a" if x is None else f"{x:.{digits}f}"


def _ci(ci, key):
    if not ci or not ci.get(key):
        return ""
    lo, hi = ci[key]
    return f" [{lo:.3f}–{hi:.3f}]"


def _model_table(exp: dict, set_name: str) -> list[str]:
    rows = ["| Model | Role | ROC-AUC | PR-AUC | Threshold (from validation) | Precision | Recall | FPR | TN / FP / FN / TP |",
            "|---|---|---|---|---|---|---|---|---|"]
    for name, m in exp["models"].items():
        t = m["test"].get(set_name)
        if t is None:
            continue
        role = ("selected candidate" if name == exp["selected_candidate"] else
                "baseline" if name == exp["baseline"] else
                "reference (current app)" if name.startswith("reference") else "candidate")
        ci = t.get("ci95_at_val_fpr_1pct")
        keys = ["at_val_fpr_1pct", "at_val_max_f1"] + (["at_app_default_0.5"] if "at_app_default_0.5" in t else [])
        for i, k in enumerate(keys):
            b = t[k]
            cm = b["confusion_matrix"]
            label = {"at_val_fpr_1pct": "FPR≤1% on val", "at_val_max_f1": "max-F1 on val",
                     "at_app_default_0.5": "app default 0.5"}[k]
            ranking = (f"{_f(t['roc_auc'])}{_ci(ci, 'roc_auc')} | {_f(t['pr_auc'])}{_ci(ci, 'pr_auc')}"
                       if i == 0 else " | ")
            ci_b = ci if k == "at_val_fpr_1pct" else None
            rows.append(f"| {name if i == 0 else ''} | {role if i == 0 else ''} | {ranking} | "
                        f"{label} ({b['threshold']:.3f}) | {_f(b['precision'])}{_ci(ci_b, 'precision')} | "
                        f"{_f(b['recall'])}{_ci(ci_b, 'recall')} | {_f(b['fpr'], 4)}{_ci(ci_b, 'fpr')} | "
                        f"{cm['tn']} / {cm['fp']} / {cm['fn']} / {cm['tp']} |")
    return rows


def write(metrics: dict, stats: dict, out: Path) -> None:
    L = ["# Phase 3 evaluation report", "",
         f"Generated {metrics['generated_utc']} by `python phase3/run.py evaluate`. "
         f"Environment: Python {metrics['environment']['python']}, scikit-learn "
         f"{metrics['environment']['sklearn']}. Machine-readable source: `metrics.json`, `data_stats.json`.", "",
         "All results below are on **real, published datasets** (not synthetic fixtures). "
         "Positive class = phishing. Thresholds were chosen on the validation split only; "
         "test sets were scored once, after model selection. Bracketed ranges are 95% "
         "bootstrap intervals that resample whole domains (only for the selected candidate, "
         "baseline and reference).", "",
         "## Data", "",
         "| | " + " | ".join(stats["sources"]) + " |",
         "|---|" + "---|" * len(stats["sources"])]
    for key, label in (("rows_in", "Rows in"), ("rejected_by_validator", "Rejected by app validator"),
                       ("exact_duplicates_removed", "Exact duplicates removed"),
                       ("conflicting_rows_removed", "Conflicting-label rows removed"),
                       ("rows_out", "Rows after cleaning"), ("unique_groups", "Registrable domains"),
                       ("groups_with_both_labels", "Domains with both labels")):
        L.append(f"| {label} | " + " | ".join(str(s[key]) for s in stats["sources"].values()) + " |")
    L.append("| Phishing / legitimate after cleaning | " + " | ".join(
        f"{s['class_out'].get('1', 0)} / {s['class_out'].get('0', 0)}" for s in stats["sources"].values()) + " |")
    for sp in ("train", "val", "test"):
        L.append(f"| {sp}: rows (phishing) / domains | " + " | ".join(
            f"{s['splits'][sp]['rows']} ({s['splits'][sp]['phishing']}) / {s['splits'][sp]['domains']}"
            for s in stats["sources"].values()) + " |")
    L.append("| Domains shared between splits | " + " | ".join(
        str(sum(s["leakage"].values())) for s in stats["sources"].values()) + " |")
    ex = metrics["excluded_from_external_sets"]
    L += ["", f"Domains present in both datasets: {stats['cross_dataset_shared_domains']} "
          f"({stats['cross_dataset_shared_urls']} identical URLs). External test sets exclude "
          f"them: {ex['hannousse_rows_sharing_phiusiil_trainval_domains']} Hannousse rows and "
          f"{ex['phiusiil_test_rows_sharing_hannousse_trainval_domains']} PhiUSIIL test rows removed.",
          "", f"Public Suffix List: {metrics['psl_vectors']['passed']} official test vectors passed, "
          f"{metrics['psl_vectors']['failed']} failed (commit {metrics['psl_vectors']['psl_commit'][:12]}).", "",
          "## Shortcut probe", "",
          "A one-line rule with no machine learning: *legitimate iff https AND host starts with "
          "`www.` AND no path/query*.", "",
          "| Test set | Precision | Recall | FPR | F1 |", "|---|---|---|---|---|"]
    for k, v in metrics["shortcut_probe"].items():
        L.append(f"| {LABELS[k]} | {_f(v['precision'])} | {_f(v['recall'])} | {_f(v['fpr'], 4)} | {_f(v['f1'])} |")
    L += ["", "If this rule scores highly, the dataset rewards the artefact rather than phishing "
          "behaviour; full-URL results on that dataset are not credible evidence.", ""]
    titles = {"A_host_phiusiil": "Experiment A: HOST view, trained on PhiUSIIL",
              "B_full_hannousse": "Experiment B: FULL view, trained on Hannousse"}
    for exp_key, exp in metrics["experiments"].items():
        L += [f"## {titles[exp_key]}", "",
              f"Selected on validation PR-AUC: **{exp['selected_candidate']}**. Baseline: {exp['baseline']}.", "",
              "Validation PR-AUC by family (best hyperparameters):", ""]
        for fam, trials in exp["selection"].items():
            best = max(trials, key=lambda t: t["val_pr_auc"])
            L.append(f"- {fam}: {best['val_pr_auc']:.4f} with {best['params']}")
        for set_name in next(iter(exp["models"].values()))["test"]:
            L += ["", f"### {LABELS[set_name]}", ""] + _model_table(exp, set_name)
        top = list(exp["explainability"]["hgb_lexical_permutation_importance_val_pr_auc"].items())[:8]
        L += ["", "Most important lexical features (HGB permutation importance, validation PR-AUC drop): "
              + ", ".join(f"`{k}` {v:.3f}" for k, v in top), ""]
    L += ["## How to read this", "",
          "- **Experiment A, external Hannousse** is the most honest generalisation number: a "
          "different dataset, collection period and URL style, with no shared domains.",
          "- **Experiment B, Hannousse test** is small (about 2,000 URLs); see the confidence intervals.",
          "- **Experiment B on PhiUSIIL** is distorted by PhiUSIIL's homepage-only legitimate class.",
          "- The reference model is the current app model (synthetic training data); its "
          "`app default 0.5` row is how the live app behaves.",
          "- Recall at FPR ≤ 1% uses a threshold chosen on validation; the realised test FPR is "
          "reported and can exceed 1%. FPR ≤ 0.1% is not reported: validation sets are too small "
          "to estimate it reliably for Hannousse.", ""]
    out.write_text("\n".join(L), encoding="utf-8")
