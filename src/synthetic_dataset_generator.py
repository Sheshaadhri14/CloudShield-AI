"""
synthetic_dataset_generator.py
================================
Generates 5,200+ synthetic IAM policy JSON files covering every realistic
threat scenario across 8 scenario families with deterministic risk labels.
Includes Scenario H: condition-rich policies for contextual feature coverage.
Output: data/synthetic_policies/ directory
"""
import json, random, string, logging
from pathlib import Path
from itertools import product

logging.basicConfig(level=logging.INFO, format='%(levelname)s | %(message)s')
log = logging.getLogger(__name__)

BASE_DIR    = Path(__file__).resolve().parents[1]
OUTPUT_DIR  = BASE_DIR / "data" / "synthetic_policies"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

LOW_RISK = 0; MEDIUM_RISK = 1; HIGH_RISK = 2
rng = random.Random(42)

# ─── Action catalogues ────────────────────────────────────────────────────────
ESCALATION_ACTION_SETS = [
    ["iam:CreatePolicyVersion"],
    ["iam:SetDefaultPolicyVersion"],
    ["iam:CreateAccessKey"],
    ["iam:CreateLoginProfile"],
    ["iam:UpdateAssumeRolePolicy","sts:AssumeRole"],
    ["iam:AttachUserPolicy"],
    ["iam:AttachRolePolicy","sts:AssumeRole"],
    ["iam:PutUserPolicy"],
    ["iam:PutRolePolicy","sts:AssumeRole"],
    ["iam:AddUserToGroup"],
    ["lambda:UpdateFunctionCode","iam:PassRole"],
    ["iam:PassRole","lambda:CreateFunction","lambda:InvokeFunction"],
    ["ec2:RunInstances","iam:PassRole"],
    ["cloudformation:CreateStack","iam:PassRole"],
    ["datapipeline:CreatePipeline","datapipeline:ActivatePipeline","iam:PassRole"],
    ["glue:CreateDevEndpoint","iam:PassRole"],
    ["sagemaker:CreateNotebookInstance","iam:PassRole"],
    ["lambda:UpdateFunctionConfiguration","iam:PassRole"],
    ["lambda:AddPermission","lambda:InvokeFunction"],
    ["codebuild:CreateProject","codebuild:StartBuild","iam:PassRole"],
    ["sts:AssumeRole"],
]

SERVICE_WILDCARDS = [
    "s3:*", "ec2:*", "lambda:*", "iam:*", "rds:*", "dynamodb:*",
    "cloudwatch:*", "logs:*", "sqs:*", "sns:*", "kms:*", "ecs:*",
]

SENSITIVE_SERVICES = ["kms", "iam", "sts", "secretsmanager", "ssm"]
READ_ACTIONS = {
    "s3": ["s3:GetObject","s3:ListBucket"],
    "ec2": ["ec2:DescribeInstances","ec2:DescribeSecurityGroups"],
    "rds": ["rds:DescribeDBInstances"],
    "cloudwatch": ["cloudwatch:GetMetricStatistics","cloudwatch:ListMetrics"],
    "dynamodb": ["dynamodb:GetItem","dynamodb:Query"],
    "logs": ["logs:DescribeLogGroups","logs:GetLogEvents"],
}
ACCOUNT_IDS     = [f"{rng.randint(100000000000, 999999999999)}" for _ in range(20)]
BUCKET_NAMES    = [f"app-bucket-{i:04d}" for i in range(50)]
TABLE_ARNS      = [f"arn:aws:dynamodb:us-east-1:{a}:table/Table{i}" for a,i in zip(ACCOUNT_IDS,range(20))]
ROLE_ARNS       = [f"arn:aws:iam::{a}:role/role-{i}" for a,i in zip(ACCOUNT_IDS,range(20))]
EXTERNAL_ACCTS  = [str(rng.randint(100000000000,999999999999)) for _ in range(10)]
ORG_ID          = "o-exampleorgid11"

# ─── Condition helpers ────────────────────────────────────────────────────────
def _mfa():
    return {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
def _ip():
    return {"IpAddress": {"aws:SourceIp": [f"10.{rng.randint(0,255)}.0.0/16"]}}
def _org():
    return {"StringEquals": {"aws:PrincipalOrgID": ORG_ID}}
def _time():
    return {"DateGreaterThan": {"aws:CurrentTime": "2024-01-01T00:00:00Z"},
            "DateLessThan":    {"aws:CurrentTime": "2026-12-31T23:59:59Z"}}

def _merge_conds(*conds):
    merged = {}
    for c in conds:
        for op, kvs in c.items():
            merged.setdefault(op, {}).update(kvs)
    return merged

# ─── Policy doc builders ──────────────────────────────────────────────────────
def _make_policy(statements: list) -> dict:
    return {"Version": "2012-10-17", "Statement": statements}

def _make_meta(scenario: str, risk: int, attached_to: list = None) -> dict:
    return {
        "source": "synthetic",
        "scenario": scenario,
        "risk_label": risk,
        "source_type": "synthetic",
        "attached_to": attached_to or []
    }

def _rand_attached(n_users=2, n_roles=2):
    users = [f"user-{rng.randint(1,999):03d}" for _ in range(n_users)]
    roles = [f"role-{rng.randint(1,999):03d}" for _ in range(n_roles)]
    return users + roles

# ─── Scenario generators ──────────────────────────────────────────────────────
generated: list = []

def _save(name: str, doc: dict, meta: dict):
    path = OUTPUT_DIR / f"{name}.json"
    with open(path, "w") as f:
        json.dump({"policy": doc, "metadata": meta}, f, indent=2)
    generated.append({"name": name, "risk_label": meta["risk_label"]})


# Scenario A — Admin wildcard (HIGH)
def gen_admin_wildcard(n: int = 300):
    for i in range(n):
        variants = [
            [{"Effect":"Allow","Action":"*","Resource":"*"}],
            [{"Effect":"Allow","Action":"*","Resource":"*"},
             {"Effect":"Allow","Action":"iam:*","Resource":"*"}],
            [{"Effect":"Allow","Action":["*","iam:*"],"Resource":"*"}],
        ]
        stmts = rng.choice(variants)
        doc = _make_policy(stmts)
        meta = _make_meta("admin_wildcard", HIGH_RISK, _rand_attached())
        _save(f"syn_admin_wildcard_{i:04d}", doc, meta)
    log.info(f"  admin_wildcard: {n}")


# Scenario B — IAM self-escalation (all 21 techniques, HIGH)
def gen_iam_self_escalation(n_per_tech: int = 20):
    count = 0
    for tech_idx, actions in enumerate(ESCALATION_ACTION_SETS):
        for variant in range(n_per_tech):
            # Optionally add a read-only preamble to make policies look more realistic
            extra = []
            if rng.random() > 0.5:
                extra = [{"Effect":"Allow","Action":["iam:Get*","iam:List*"],"Resource":"*"}]
            stmts = extra + [{"Effect":"Allow","Action":actions,"Resource":"*"}]
            doc  = _make_policy(stmts)
            meta = _make_meta(f"iam_escalation_T{tech_idx+1:02d}", HIGH_RISK, _rand_attached())
            _save(f"syn_escalation_T{tech_idx+1:02d}_{variant:03d}", doc, meta)
            count += 1
    log.info(f"  iam_self_escalation: {count}")


# Scenario C — Cross-account abuse (HIGH)
def gen_cross_account(n: int = 200):
    for i in range(n):
        external = rng.choice(EXTERNAL_ACCTS)
        has_cond = rng.random() < 0.2   # 80% have NO condition -> HIGH risk
        stmt = {
            "Effect": "Allow",
            "Action": rng.choice([["sts:AssumeRole"], ["sts:AssumeRole","iam:PassRole"]]),
            "Resource": f"arn:aws:iam::{external}:role/*"
        }
        if has_cond:
            stmt["Condition"] = _org()
        doc  = _make_policy([stmt])
        risk = MEDIUM_RISK if has_cond else HIGH_RISK
        meta = _make_meta("cross_account_abuse", risk, _rand_attached())
        _save(f"syn_cross_account_{i:04d}", doc, meta)
    log.info(f"  cross_account: {n}")


# Scenario D — Lambda + PassRole chain (HIGH)
def gen_lambda_passrole(n: int = 200):
    for i in range(n):
        role_arn = rng.choice(ROLE_ARNS)
        stmts = [
            {"Effect":"Allow","Action":["lambda:CreateFunction","lambda:InvokeFunction","lambda:UpdateFunctionCode"],
             "Resource":"*"},
            {"Effect":"Allow","Action":"iam:PassRole","Resource": role_arn if rng.random()>0.4 else "*"},
        ]
        doc  = _make_policy(stmts)
        meta = _make_meta("lambda_passrole_chain", HIGH_RISK, _rand_attached())
        _save(f"syn_lambda_passrole_{i:04d}", doc, meta)
    log.info(f"  lambda_passrole: {n}")


# Scenario E — Overly broad / service wildcard (MEDIUM)
def gen_overly_broad(n: int = 600):
    for i in range(n):
        svc_wc = rng.sample(SERVICE_WILDCARDS, k=rng.randint(1,4))
        resource = "*" if rng.random() < 0.6 else f"arn:aws:s3:::{rng.choice(BUCKET_NAMES)}/*"
        stmts = [{"Effect":"Allow","Action":svc_wc,"Resource":resource}]
        # Occasionally add a Deny for realism
        if rng.random() < 0.2:
            stmts.append({"Effect":"Deny","Action":["iam:DeleteRole","iam:DeleteUser"],"Resource":"*"})
        doc  = _make_policy(stmts)
        meta = _make_meta("overly_broad_medium", MEDIUM_RISK, _rand_attached())
        _save(f"syn_overly_broad_{i:04d}", doc, meta)
    log.info(f"  overly_broad: {n}")


# Scenario F — Stale / no condition (MEDIUM)
def gen_stale_no_condition(n: int = 500):
    for i in range(n):
        svc = rng.choice(SENSITIVE_SERVICES)
        actions = [f"{svc}:{a}" for a in ["List*","Get*"]] + [f"{svc}:Describe*"]
        stmts = [{"Effect":"Allow","Action":actions,"Resource":"*"}]
        # 30% have a partial condition (still MEDIUM)
        if rng.random() < 0.3:
            stmts[0]["Condition"] = _ip()
        doc  = _make_policy(stmts)
        meta = _make_meta("stale_no_condition", MEDIUM_RISK, _rand_attached(n_users=1, n_roles=1))
        _save(f"syn_stale_no_cond_{i:04d}", doc, meta)
    log.info(f"  stale_no_condition: {n}")


# Scenario G — Least privilege / secure (LOW)
def gen_least_privilege(n: int = 800):
    svc_keys = list(READ_ACTIONS.keys())
    for i in range(n):
        svc = rng.choice(svc_keys)
        actions = READ_ACTIONS[svc]
        # Choose a specific resource ARN
        if svc == "s3":
            bkt = rng.choice(BUCKET_NAMES)
            resource = [f"arn:aws:s3:::{bkt}", f"arn:aws:s3:::{bkt}/*"]
        elif svc == "dynamodb":
            resource = rng.choice(TABLE_ARNS)
        else:
            resource = "*"

        # Always include at least one condition
        n_conds  = rng.randint(1, 3)
        cond_fns = rng.sample([_mfa, _ip, _org, _time], k=n_conds)
        condition = _merge_conds(*[fn() for fn in cond_fns])

        stmt = {"Effect":"Allow","Action":actions,"Resource":resource,"Condition":condition}
        # Occasionally add Deny for extra specificity
        stmts = [stmt]
        if rng.random() < 0.25:
            stmts.append({"Effect":"Deny","Action":f"{svc}:Delete*","Resource":"*"})

        doc  = _make_policy(stmts)
        meta = _make_meta("least_privilege_low", LOW_RISK, _rand_attached(n_users=1, n_roles=2))
        _save(f"syn_least_priv_{i:04d}", doc, meta)
    log.info(f"  least_privilege: {n}")


# Scenario H — Condition-rich policies (mixed risk levels)
# Ensures MFA, IP, Time, Org conditions all appear in the dataset
def gen_condition_rich(n: int = 400):
    """Generate policies with various condition combinations.
    Produces LOW/MEDIUM/HIGH depending on what actions + conditions are used."""
    svc_keys = list(READ_ACTIONS.keys())
    for i in range(n):
        # Decide risk level and action scope
        risk_roll = rng.random()
        if risk_roll < 0.35:
            # LOW: read-only with strong conditions
            svc = rng.choice(svc_keys)
            actions = READ_ACTIONS[svc]
            resource = f"arn:aws:s3:::{rng.choice(BUCKET_NAMES)}/*" if svc == "s3" else "*"
            risk = LOW_RISK
            n_conds = rng.randint(2, 4)
        elif risk_roll < 0.70:
            # MEDIUM: broader actions with some conditions
            svc_wc = rng.sample(SERVICE_WILDCARDS, k=rng.randint(1, 3))
            actions = svc_wc
            resource = "*"
            risk = MEDIUM_RISK
            n_conds = rng.randint(1, 2)
        else:
            # HIGH: dangerous actions with weak/no conditions
            actions = rng.choice(ESCALATION_ACTION_SETS)
            resource = "*"
            risk = HIGH_RISK
            n_conds = rng.randint(0, 1)

        # Build condition block with selected condition types
        cond_fns = rng.sample([_mfa, _ip, _org, _time], k=min(n_conds, 4))
        stmts = [{"Effect": "Allow", "Action": actions, "Resource": resource}]
        if cond_fns:
            stmts[0]["Condition"] = _merge_conds(*[fn() for fn in cond_fns])

        # Occasionally add a deny statement for realism
        if rng.random() < 0.2:
            stmts.append({"Effect": "Deny", "Action": ["iam:Delete*"], "Resource": "*",
                          "Condition": _mfa()})

        doc  = _make_policy(stmts)
        meta = _make_meta("condition_rich", risk, _rand_attached())
        _save(f"syn_condition_rich_{i:04d}", doc, meta)
    log.info(f"  condition_rich: {n}")


# ─── Summary writer ───────────────────────────────────────────────────────────
def write_summary():
    summary_path = BASE_DIR / "data" / "synthetic_metadata.json"
    with open(summary_path, "w") as f:
        json.dump(generated, f, indent=2)
    by_label = {0:0,1:0,2:0}
    for g in generated:
        by_label[g["risk_label"]] = by_label.get(g["risk_label"],0)+1
    log.info("="*55)
    log.info(f"Synthetic total: {len(generated)}")
    log.info(f"  LOW(0)={by_label[0]}  MED(1)={by_label[1]}  HIGH(2)={by_label[2]}")
    log.info(f"Output: {OUTPUT_DIR}")
    log.info(f"Metadata: {summary_path}")
    log.info("="*55)


def run_all():
    log.info("="*55 + "\nCloudShield AI — Synthetic Dataset Generator\n" + "="*55)
    gen_admin_wildcard(400)          # was 300
    gen_iam_self_escalation(25)      # 21 techs × 25 = 525 (was 420)
    gen_cross_account(300)           # was 200
    gen_lambda_passrole(300)         # was 200
    gen_overly_broad(800)            # was 600
    gen_stale_no_condition(700)      # was 500
    gen_least_privilege(1000)        # was 800
    gen_condition_rich(500)          # NEW scenario H
    write_summary()
    # Expected total: 400+525+300+300+800+700+1000+400 = 4425 synthetic
    # + ~1,247 managed + 125 realworld + 389 guideline ≈ 6,186 total


if __name__ == "__main__":
    run_all()
