"""
dataset_validator.py
======================
Validates the complete CloudShield AI dataset quality for research-grade use.
Checks: class balance, feature variance, contextual feature coverage,
escalation technique coverage, temporal sequence completeness.

Run this AFTER the full pipeline (graph_builder + feature_extractor + weak_supervision).
"""
import json, os
import pandas as pd
import numpy as np
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]

# ─── Thresholds ───────────────────────────────────────────────────────────────
TARGET_TOTAL  = 5_000          # min total policy samples
LABEL_MIN_PCT = 0.20           # each label should be ≥ 20% of total
LABEL_MAX_PCT = 0.50           # no label should dominate > 50%
CTX_MIN_PCT   = 0.10           # at least 10% of samples should have each contextual feature
VARIANCE_MIN  = 1e-4           # features with zero variance are useless
N_TECHNIQUES  = 21             # expected escalation techniques

PASS = "✅ PASS"
FAIL = "❌ FAIL"
WARN = "⚠️  WARN"

results: list = []

def _check(name: str, passed: bool, warn_only: bool = False, detail: str = "") -> str:
    status = PASS if passed else (WARN if warn_only else FAIL)
    results.append({"check": name, "status": status, "detail": detail})
    return f"{status} | {name}{(' — '+detail) if detail else ''}"


def validate_snapshot_counts():
    print("\n── 1. Dataset Snapshot Counts ──────────────────────────────────")

    # Real-world
    rw_dir  = BASE_DIR / "data" / "realworld_policies"
    rw_cnt  = len(list(rw_dir.glob("*.json"))) if rw_dir.exists() else 0
    print(f"  Real-world policies:    {rw_cnt}")

    # Synthetic
    syn_dir = BASE_DIR / "data" / "synthetic_policies"
    syn_cnt = len(list(syn_dir.glob("*.json"))) if syn_dir.exists() else 0
    print(f"  Synthetic policies:     {syn_cnt}")

    # Guideline
    gl_dir  = BASE_DIR / "data" / "guideline_policies"
    gl_cnt  = len(list(gl_dir.glob("*.json"))) if gl_dir.exists() else 0
    print(f"  Guideline policies:     {gl_cnt}")

    # Temporal
    tmp_dir = BASE_DIR / "data" / "temporal_sequences"
    tmp_cnt = len(list(tmp_dir.glob("*.json"))) if tmp_dir.exists() else 0
    print(f"  Temporal sequences:     {tmp_cnt}")

    total = rw_cnt + syn_cnt + gl_cnt
    print(f"  ── TOTAL policy files:  {total}  (target ≥ {TARGET_TOTAL})")
    print(_check("Dataset size ≥ 5,000", total >= TARGET_TOTAL,
                 detail=f"{total} / {TARGET_TOTAL}"))
    print(_check("Real-world data present", rw_cnt > 0,
                 detail=str(rw_cnt)))
    print(_check("Temporal sequences ≥ 500", tmp_cnt >= 500,
                 detail=str(tmp_cnt)))
    return total


def validate_label_distribution():
    print("\n── 2. Label Distribution ───────────────────────────────────────")

    by_label = {0: 0, 1: 0, 2: 0}

    for meta_file in ["realworld_metadata.json", "synthetic_metadata.json",
                       "guideline_metadata.json"]:
        path = BASE_DIR / "data" / meta_file
        if path.exists():
            with open(path) as f:
                for m in json.load(f):
                    lbl = m.get("risk_label", m.get("label"))
                    if lbl in by_label:
                        by_label[lbl] += 1

    total = sum(by_label.values())
    if total == 0:
        print("  No labeled metadata found — run synthetic + realworld scripts first")
        return

    for lbl, cnt in by_label.items():
        pct = cnt / total
        name = ["LOW","MEDIUM","HIGH"][lbl]
        status = PASS if LABEL_MIN_PCT <= pct <= LABEL_MAX_PCT else WARN
        print(f"  {name}({lbl}): {cnt:>5}  ({100*pct:.1f}%)  {status}")

    print(_check("No single label > 50%",
                 all(c/total < LABEL_MAX_PCT for c in by_label.values()),
                 detail=str({k: f"{100*v/total:.1f}%" for k,v in by_label.items()})))
    print(_check("All labels ≥ 20%",
                 all(c/total >= LABEL_MIN_PCT for c in by_label.values()),
                 warn_only=True,
                 detail="Some labels underrepresented — consider upsampling"))


def validate_feature_quality():
    print("\n── 3. Feature Quality ──────────────────────────────────────────")
    feat_csv = BASE_DIR / "data" / "graph_features.csv"
    if not feat_csv.exists():
        print("  graph_features.csv not found — run feature_extractor.py first")
        print(_check("Feature CSV present", False))
        return

    df = pd.read_csv(feat_csv)
    print(f"  Rows: {len(df)}  Columns: {len(df.columns)}")

    # Variance check
    numeric = df.select_dtypes(include=[np.number])
    zero_var = [c for c in numeric.columns if numeric[c].var() < VARIANCE_MIN]
    print(f"  Zero-variance features: {zero_var}")
    print(_check("No zero-variance features",
                 len(zero_var) == 0, warn_only=True,
                 detail=str(zero_var)))

    # Contextual feature coverage
    ctx_cols = ["requires_mfa","has_ip_restriction","has_time_restriction","has_org_restriction"]
    for col in ctx_cols:
        if col in df.columns:
            pct = df[col].sum() / len(df)
            ok  = pct >= CTX_MIN_PCT
            print(f"  {col}: {100*pct:.1f}%  {PASS if ok else WARN}")
            print(_check(f"{col} coverage ≥ 10%", ok, warn_only=True,
                         detail=f"{100*pct:.1f}%"))

    # attachment_count non-zero check
    if "attachment_count" in df.columns:
        nonzero = (df["attachment_count"] > 0).sum()
        pct     = nonzero / len(df)
        print(f"  attachment_count > 0: {nonzero} ({100*pct:.1f}%)")
        print(_check("attachment_count > 0 in ≥ 50% rows",
                     pct >= 0.5, warn_only=True, detail=f"{100*pct:.1f}%"))


def validate_escalation_coverage():
    print("\n── 4. Escalation Technique Coverage ────────────────────────────")
    try:
        import sys; sys.path.insert(0, str(BASE_DIR / "src"))
        from escalation_patterns import ESCALATION_TECHNIQUES
        n = len(ESCALATION_TECHNIQUES)
        print(f"  Techniques defined: {n} / {N_TECHNIQUES}")
        print(_check(f"All {N_TECHNIQUES} techniques present",
                     n >= N_TECHNIQUES, detail=f"{n}/{N_TECHNIQUES}"))
        for t in ESCALATION_TECHNIQUES:
            print(f"    {t.technique_id}: {t.name}")
    except ImportError as e:
        print(f"  Could not import escalation_patterns: {e}")
        print(_check("Escalation patterns importable", False))


def validate_temporal_data():
    print("\n── 5. Temporal Sequence Quality ────────────────────────────────")
    meta = BASE_DIR / "data" / "temporal_metadata.json"
    if not meta.exists():
        print("  temporal_metadata.json not found — run temporal_dataset_builder.py")
        print(_check("Temporal metadata present", False))
        return

    with open(meta) as f:
        seqs = json.load(f)

    patterns  = {}
    min_snaps = 9999; max_snaps = 0
    for s in seqs:
        p = s.get("pattern","?")
        patterns[p] = patterns.get(p,0) + 1
        n_s = s.get("n_snapshots", 0)
        min_snaps = min(min_snaps, n_s)
        max_snaps = max(max_snaps, n_s)

    print(f"  Total sequences: {len(seqs)}")
    print(f"  Patterns: {patterns}")
    print(f"  Snapshots per sequence: min={min_snaps}, max={max_snaps}")
    print(_check("Drift patterns ≥ 5",
                 len(patterns) >= 5, detail=str(list(patterns.keys()))))
    print(_check("Sequences ≥ 500",
                 len(seqs) >= 500, detail=str(len(seqs))))


def print_summary():
    print("\n" + "="*60)
    print("DATASET VALIDATION SUMMARY")
    print("="*60)
    passed = sum(1 for r in results if r["status"].startswith("✅"))
    warned = sum(1 for r in results if r["status"].startswith("⚠️"))
    failed = sum(1 for r in results if r["status"].startswith("❌"))
    print(f"  PASS: {passed}  WARN: {warned}  FAIL: {failed}")
    print("="*60)
    if failed > 0:
        print("\nFailed checks:")
        for r in results:
            if r["status"].startswith("❌"):
                print(f"  ❌ {r['check']}")
    if warned > 0:
        print("\nWarnings:")
        for r in results:
            if r["status"].startswith("⚠️"):
                print(f"  ⚠️  {r['check']} — {r['detail']}")

    # Save report
    report_path = BASE_DIR / "data" / "validation_report.json"
    with open(report_path, "w") as f:
        json.dump({"results": results,
                   "summary": {"passed": passed, "warned": warned, "failed": failed}},
                  f, indent=2)
    print(f"\nReport saved to: {report_path}")


if __name__ == "__main__":
    print("="*60)
    print("CloudShield AI — Dataset Validator")
    print("="*60)
    validate_snapshot_counts()
    validate_label_distribution()
    validate_feature_quality()
    validate_escalation_coverage()
    validate_temporal_data()
    print_summary()
