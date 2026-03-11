"""
temporal_dataset_builder.py
==============================
Builds time-series sequences of IAM policy versions to simulate
permission drift — the slow accumulation of excess permissions over time.
This feeds the Liquid Neural Network (LNN) component of CloudShield AI.

Strategy:
  1. Benign drift (LOW → MEDIUM) — gradual broadening over 5 snapshots
  2. Attack escalation (LOW → HIGH in 3 steps) — rapid privilege escalation
  3. Remediation (HIGH → LOW) — incident response correction
  4. Ghost permissions (stable overly-broad for 6 months) — stale MEDIUM
  5. Rollback attack (5 policy versions, attacker reverts to escalation version)

Output:
  data/temporal_sequences/  — one JSON file per sequence
  data/temporal_metadata.json — sequence-level labels
"""
import json, random, copy
from pathlib import Path
from datetime import datetime, timedelta

BASE_DIR   = Path(__file__).resolve().parents[1]
OUT_DIR    = BASE_DIR / "data" / "temporal_sequences"
OUT_DIR.mkdir(parents=True, exist_ok=True)

LOW_RISK = 0; MEDIUM_RISK = 1; HIGH_RISK = 2
rng = random.Random(999)

sequences: list = []

# ─── Action sets ──────────────────────────────────────────────────────────────
READ_ONLY   = ["s3:GetObject","s3:ListBucket","ec2:DescribeInstances"]
WRITE_BROAD = ["s3:*","ec2:*","rds:*"]
IAM_ESC     = ["iam:AttachRolePolicy","iam:CreatePolicyVersion","iam:PassRole"]
ADMIN_ALL   = ["*"]
SENSITIVE   = ["iam:CreateUser","iam:DeleteUser","iam:AttachUserPolicy"]

def _stmt(actions, resource="*", effect="Allow", condition=None):
    s = {"Effect": effect, "Action": actions, "Resource": resource}
    if condition:
        s["Condition"] = condition
    return s

def _mfa():
    return {"Bool": {"aws:MultiFactorAuthPresent": "true"}}

def _ip():
    return {"IpAddress": {"aws:SourceIp": f"10.0.0.0/8"}}

def _ts(base: datetime, days: int) -> str:
    return (base + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

def _policy(stmts: list) -> dict:
    return {"Version": "2012-10-17", "Statement": stmts}


# ─── Sequence generators ──────────────────────────────────────────────────────
def _save_seq(name: str, snapshots: list, label: int, pattern: str):
    """Save one temporal sequence."""
    path = OUT_DIR / f"{name}.json"
    with open(path, "w") as f:
        json.dump({"snapshots": snapshots,
                   "metadata": {"sequence_label": label,
                                "drift_pattern": pattern,
                                "n_snapshots": len(snapshots)}}, f, indent=2)
    sequences.append({"name": name, "label": label, "pattern": pattern,
                       "n_snapshots": len(snapshots)})


# ── Pattern 1: Benign drift LOW → MEDIUM (perm creep over 5 months) ──────────
def gen_benign_drift(n: int = 150):
    base = datetime(2024, 1, 1)
    for i in range(n):
        snaps = []
        # v1: read only with MFA
        snaps.append({"timestamp": _ts(base, 0),  "version": "v1",
                       "policy": _policy([_stmt(READ_ONLY, condition=_mfa())]),
                       "risk_label": LOW_RISK})
        # v2: add 1 write action
        snaps.append({"timestamp": _ts(base, 30), "version": "v2",
                       "policy": _policy([_stmt(READ_ONLY + ["s3:PutObject"], condition=_mfa())]),
                       "risk_label": LOW_RISK})
        # v3: remove MFA condition (bad PR merged)
        snaps.append({"timestamp": _ts(base, 70), "version": "v3",
                       "policy": _policy([_stmt(READ_ONLY + ["s3:PutObject"])]),
                       "risk_label": MEDIUM_RISK})
        # v4: add more services, no condition
        snaps.append({"timestamp": _ts(base, 110), "version": "v4",
                       "policy": _policy([_stmt(READ_ONLY + ["s3:PutObject","ec2:RunInstances"])]),
                       "risk_label": MEDIUM_RISK})
        # v5: service wildcard creep
        snaps.append({"timestamp": _ts(base, 150), "version": "v5",
                       "policy": _policy([_stmt(["s3:*","ec2:*"])]),
                       "risk_label": MEDIUM_RISK})
        _save_seq(f"seq_benign_drift_{i:04d}", snaps, MEDIUM_RISK, "benign_drift")
    print(f"  benign_drift: {n}")


# ── Pattern 2: Attack escalation LOW → HIGH ────────────────────────────────────
def gen_attack_escalation(n: int = 120):
    base = datetime(2024, 3, 1)
    for i in range(n):
        snaps = []
        snaps.append({"timestamp": _ts(base, 0),  "version": "v1",
                       "policy": _policy([_stmt(READ_ONLY, condition=_mfa())]),
                       "risk_label": LOW_RISK})
        snaps.append({"timestamp": _ts(base, 5),  "version": "v2",
                       "policy": _policy([_stmt(READ_ONLY),  # MFA removed silently
                                          _stmt(["iam:ListRoles","iam:GetRole"])]),
                       "risk_label": MEDIUM_RISK})
        # Attacker adds escalation actions
        snaps.append({"timestamp": _ts(base, 6),  "version": "v3",
                       "policy": _policy([_stmt(READ_ONLY),
                                          _stmt(IAM_ESC)]),
                       "risk_label": HIGH_RISK})
        # Full admin
        snaps.append({"timestamp": _ts(base, 8),  "version": "v4",
                       "policy": _policy([_stmt(ADMIN_ALL)]),
                       "risk_label": HIGH_RISK})
        _save_seq(f"seq_attack_esc_{i:04d}", snaps, HIGH_RISK, "attack_escalation")
    print(f"  attack_escalation: {n}")


# ── Pattern 3: Remediation HIGH → LOW ─────────────────────────────────────────
def gen_remediation(n: int = 80):
    base = datetime(2024, 5, 1)
    for i in range(n):
        snaps = []
        snaps.append({"timestamp": _ts(base, 0),   "version": "v1",
                       "policy": _policy([_stmt(ADMIN_ALL)]),
                       "risk_label": HIGH_RISK})
        snaps.append({"timestamp": _ts(base, 1),   "version": "v2",
                       "policy": _policy([_stmt(["s3:*","iam:*"])]),
                       "risk_label": HIGH_RISK})
        # Security team remediates
        snaps.append({"timestamp": _ts(base, 3),   "version": "v3",
                       "policy": _policy([_stmt(["s3:*"])]),
                       "risk_label": MEDIUM_RISK})
        snaps.append({"timestamp": _ts(base, 7),   "version": "v4",
                       "policy": _policy([_stmt(READ_ONLY + ["s3:PutObject"])]),
                       "risk_label": MEDIUM_RISK})
        snaps.append({"timestamp": _ts(base, 14),  "version": "v5",
                       "policy": _policy([_stmt(READ_ONLY, condition=_mfa())]),
                       "risk_label": LOW_RISK})
        _save_seq(f"seq_remediation_{i:04d}", snaps, LOW_RISK, "remediation")
    print(f"  remediation: {n}")


# ── Pattern 4: Ghost permissions (stale MEDIUM unchanged for 6 months) ─────────
def gen_ghost_permissions(n: int = 80):
    base = datetime(2023, 6, 1)
    for i in range(n):
        snaps = []
        policy = _policy([_stmt(["s3:*","ec2:Describe*","rds:*"])])
        for m in range(6):
            snaps.append({"timestamp": _ts(base, m*30), "version": f"v{m+1}",
                           "policy": copy.deepcopy(policy),
                           "risk_label": MEDIUM_RISK})
        _save_seq(f"seq_ghost_perm_{i:04d}", snaps, MEDIUM_RISK, "ghost_permissions")
    print(f"  ghost_permissions: {n}")


# ── Pattern 5: Rollback attack (iam:SetDefaultPolicyVersion) ──────────────────
def gen_rollback_attack(n: int = 70):
    base = datetime(2024, 2, 1)
    for i in range(n):
        snaps = []
        # v1: safe read-only
        snaps.append({"timestamp": _ts(base, 0),  "version": "v1",
                       "policy": _policy([_stmt(READ_ONLY, condition=_mfa())]),
                       "risk_label": LOW_RISK})
        # v2: escalation version (later used for rollback)
        snaps.append({"timestamp": _ts(base, -90), "version": "v2",   # older
                       "policy": _policy([_stmt(ADMIN_ALL)]),          # dangerous
                       "risk_label": HIGH_RISK})
        # Active version is v1 (safe); but v2 exists in policy history
        # v3: attacker invokes SetDefaultPolicyVersion → v2 becomes default
        snaps.append({"timestamp": _ts(base, 15),  "version": "v2-reverted",
                       "policy": _policy([_stmt(ADMIN_ALL)]),
                       "risk_label": HIGH_RISK,
                       "is_rollback_attack": True})
        _save_seq(f"seq_rollback_{i:04d}", snaps, HIGH_RISK, "rollback_attack")
    print(f"  rollback_attack: {n}")


# ─── Master runner ────────────────────────────────────────────────────────────
def run_all():
    print("="*55 + "\nTemporal Dataset Builder\n" + "="*55)
    gen_benign_drift(150)
    gen_attack_escalation(120)
    gen_remediation(80)
    gen_ghost_permissions(80)
    gen_rollback_attack(70)

    meta_path = BASE_DIR / "data" / "temporal_metadata.json"
    with open(meta_path, "w") as f:
        json.dump(sequences, f, indent=2)

    by_label = {0:0, 1:0, 2:0}
    for s in sequences:
        by_label[s["label"]] += 1

    print("="*55)
    print(f"Total sequences: {len(sequences)}")
    print(f"  LOW={by_label[0]}  MED={by_label[1]}  HIGH={by_label[2]}")
    print(f"Output: {OUT_DIR}")
    print("="*55)

if __name__ == "__main__":
    run_all()
