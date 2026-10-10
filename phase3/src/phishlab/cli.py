"""Command-line entry point: python phase3/run.py <command>

Commands (run in order; `all` runs prepare + evaluate):
  download     fetch the pinned sources into phase3/data/raw (verified SHA-256)
  verify-psl   check the PSL implementation against the official test vectors
  prepare      load, validate, clean and split both datasets
  evaluate     train, select on validation, evaluate on held-out domains,
               write reports/ and artifacts/
  all          prepare + evaluate (requires a prior download)
"""
from __future__ import annotations

import argparse
import json
import platform
import sys
import time

import numpy as np
import pandas as pd
import sklearn

from . import download as D
from .cleaning import clean
from .datasets import load_hannousse, load_phiusiil
from .psl import PublicSuffixList, check_official_vectors
from .sources import ARTIFACTS_DIR, PSL_COMMIT, RAW_DIR, REPORTS_DIR, SOURCES, WORK_DIR
from .splits import DEFAULT_FRACTIONS, DEFAULT_SALT, assign, leakage_report


def log(msg: str) -> None:
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def load_psl() -> PublicSuffixList:
    return PublicSuffixList.from_file(D.ensure("psl", allow_download=False))


def cmd_download(_args) -> None:
    for key, info in D.download_all().items():
        log(f"{key}: {info}")


def cmd_verify_psl(_args) -> dict:
    passed, failures = check_official_vectors(load_psl(), D.ensure("psl_tests", allow_download=False))
    log(f"PSL official vectors: {passed} passed, {len(failures)} failed")
    for f in failures:
        log(f"  FAIL {f}")
    if failures:
        raise SystemExit(1)
    return {"passed": passed, "failed": 0, "psl_commit": PSL_COMMIT}


def cmd_prepare(_args) -> None:
    psl = load_psl()
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stats = {"split_salt": DEFAULT_SALT, "split_fractions": DEFAULT_FRACTIONS, "sources": {}}
    loaders = {"phiusiil": lambda: load_phiusiil(D.ensure("phiusiil", allow_download=False)),
               "hannousse": lambda: load_hannousse(D.ensure("hannousse", allow_download=False))}
    for key, loader in loaders.items():
        log(f"loading {key}")
        raw = loader()
        cleaned, s = clean(raw, psl)
        cleaned["split"] = assign(cleaned["group"])
        s["splits"] = {sp: {"rows": int((cleaned.split == sp).sum()),
                            "phishing": int(cleaned.loc[cleaned.split == sp, "is_phishing"].sum()),
                            "domains": int(cleaned.loc[cleaned.split == sp, "group"].nunique())}
                       for sp in ("train", "val", "test")}
        s["leakage"] = leakage_report(cleaned)
        s["sha256"] = SOURCES[key].sha256
        stats["sources"][key] = s
        cleaned.to_parquet(WORK_DIR / f"clean_{key}.parquet", index=False)
        log(f"{key}: {s['rows_in']} -> {s['rows_out']} rows; splits {s['splits']}")
    p = pd.read_parquet(WORK_DIR / "clean_phiusiil.parquet")
    h = pd.read_parquet(WORK_DIR / "clean_hannousse.parquet")
    stats["cross_dataset_shared_domains"] = len(set(p.group) & set(h.group))
    stats["cross_dataset_shared_urls"] = len(set(p.url) & set(h.url))
    (REPORTS_DIR / "data_stats.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")
    log(f"wrote {REPORTS_DIR / 'data_stats.json'}")


def cmd_evaluate(args) -> None:
    from . import report, serialize
    from .experiment import dump, prepare_rows, run_experiment, shortcut_probe
    from .reference import ReferenceModel

    psl_check = cmd_verify_psl(args)
    p_df = pd.read_parquet(WORK_DIR / "clean_phiusiil.parquet")
    h_df = pd.read_parquet(WORK_DIR / "clean_hannousse.parquet")
    log("re-validating canonical URLs and computing features")
    P, H = prepare_rows(p_df), prepare_rows(h_df)
    reference = ReferenceModel()

    def idx(prep, mask):
        return np.flatnonzero(mask)

    p_trainval = set(p_df.loc[p_df.split != "test", "group"])
    h_trainval = set(h_df.loc[h_df.split != "test", "group"])
    sets_a = {"phiusiil_test": (P, idx(P, p_df.split == "test")),
              "hannousse_external": (H, idx(H, ~h_df.group.isin(p_trainval)))}
    sets_b = {"hannousse_test": (H, idx(H, h_df.split == "test")),
              "phiusiil_external": (P, idx(P, (p_df.split == "test") & ~p_df.group.isin(h_trainval)))}
    n_boot = args.bootstrap
    log("experiment A: HOST view trained on PhiUSIIL")
    res_a, models_a = run_experiment("A", "host", P, sets_a, reference, n_boot, log)
    log("experiment B: FULL view trained on Hannousse")
    res_b, models_b = run_experiment("B", "full", H, sets_b, reference, n_boot, log)

    metrics = {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": {"python": platform.python_version(), "sklearn": sklearn.__version__,
                        "numpy": np.__version__, "pandas": pd.__version__},
        "psl_vectors": psl_check,
        "excluded_from_external_sets": {
            "hannousse_rows_sharing_phiusiil_trainval_domains": int(h_df.group.isin(p_trainval).sum()),
            "phiusiil_test_rows_sharing_hannousse_trainval_domains":
                int(((p_df.split == "test") & p_df.group.isin(h_trainval)).sum())},
        "shortcut_probe": {"phiusiil_test": shortcut_probe(P, sets_a["phiusiil_test"][1]),
                           "hannousse_test": shortcut_probe(H, sets_b["hannousse_test"][1])},
        "experiments": {"A_host_phiusiil": res_a, "B_full_hannousse": res_b},
    }
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    dump(metrics, REPORTS_DIR / "metrics.json")
    log(f"wrote {REPORTS_DIR / 'metrics.json'}")

    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    for exp_key, res, models, prep in (("A_host_phiusiil", res_a, models_a, P),
                                       ("B_full_hannousse", res_b, models_b, H)):
        fam = res["selected_candidate"]
        info = serialize.save(models[fam], fam, res, exp_key, prep, ARTIFACTS_DIR)
        log(f"artifact {exp_key}: {info}")
    report.write(metrics, json.loads((REPORTS_DIR / "data_stats.json").read_text(encoding="utf-8")),
                 REPORTS_DIR / "EVALUATION_REPORT.md")
    log(f"wrote {REPORTS_DIR / 'EVALUATION_REPORT.md'}")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(prog="phishlab", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["download", "verify-psl", "prepare", "evaluate", "all"])
    ap.add_argument("--bootstrap", type=int, default=200, help="domain-bootstrap resamples (0 to skip)")
    args = ap.parse_args(argv)
    if args.command == "download":
        cmd_download(args)
    elif args.command == "verify-psl":
        cmd_verify_psl(args)
    elif args.command == "prepare":
        cmd_prepare(args)
    elif args.command == "evaluate":
        cmd_evaluate(args)
    else:
        cmd_prepare(args)
        cmd_evaluate(args)


if __name__ == "__main__":
    sys.exit(main())
