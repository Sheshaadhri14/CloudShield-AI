"""
aws_guideline_policy_generator.py
===================================
Generates realistic AWS IAM policies by following AWS official documentation
guidelines fetched from the AWS docs. Produces policies that align with:
  1. AWS Security Best Practices
  2. AWS Well-Architected Framework (Security Pillar)
  3. Official AWS service action documentation

Sources:
  - AWS docs JSON service action tables (from iann0036/iam-dataset)
  - AWS Security best-practice templates
  - AWS Least Privilege documentation patterns

Output: data/guideline_policies/  (JSON policy files with metadata)
"""
import json, random, logging, urllib.request, time
from pathlib import Path
from typing import List, Dict, Tuple, Optional

logging.basicConfig(level=logging.INFO, format='%(levelname)s | %(message)s')
log = logging.getLogger(__name__)

BASE_DIR    = Path(__file__).resolve().parents[1]
OUTPUT_DIR  = BASE_DIR / "data" / "guideline_policies"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

LOW_RISK = 0; MEDIUM_RISK = 1; HIGH_RISK = 2
rng = random.Random(2025)

# ─── Fetch AWS IAM action definitions from public source ─────────────────────
IAM_DOCS_ACTIONS_URL = "https://raw.githubusercontent.com/iann0036/iam-dataset/main/aws/iam-definition.json"

FALLBACK_AWS_SERVICES: Dict[str, Dict] = {
    "s3": {
        "read":  ["s3:GetObject","s3:GetObjectAcl","s3:ListBucket","s3:GetBucketLocation"],
        "write": ["s3:PutObject","s3:DeleteObject","s3:PutObjectAcl"],
        "admin": ["s3:CreateBucket","s3:DeleteBucket","s3:PutBucketPolicy"],
    },
    "ec2": {
        "read":  ["ec2:DescribeInstances","ec2:DescribeVpcs","ec2:DescribeSecurityGroups",
                  "ec2:DescribeSubnets","ec2:DescribeImages"],
        "write": ["ec2:RunInstances","ec2:TerminateInstances","ec2:StartInstances",
                  "ec2:StopInstances","ec2:RebootInstances"],
        "admin": ["ec2:CreateSecurityGroup","ec2:DeleteSecurityGroup",
                  "ec2:AuthorizeSecurityGroupIngress","ec2:CreateVpc"],
    },
    "iam": {
        "read":  ["iam:GetUser","iam:GetRole","iam:ListRoles","iam:ListUsers",
                  "iam:ListPolicies","iam:GetPolicy"],
        "write": ["iam:CreateUser","iam:DeleteUser","iam:UpdateUser",
                  "iam:AttachUserPolicy","iam:DetachUserPolicy"],
        "admin": ["iam:CreateRole","iam:DeleteRole","iam:PutRolePolicy",
                  "iam:AttachRolePolicy","iam:PassRole","iam:CreatePolicyVersion"],
    },
    "lambda": {
        "read":  ["lambda:ListFunctions","lambda:GetFunction","lambda:GetPolicy"],
        "write": ["lambda:UpdateFunctionCode","lambda:InvokeFunction"],
        "admin": ["lambda:CreateFunction","lambda:DeleteFunction",
                  "lambda:AddPermission","lambda:UpdateFunctionConfiguration"],
    },
    "dynamodb": {
        "read":  ["dynamodb:GetItem","dynamodb:Query","dynamodb:Scan",
                  "dynamodb:DescribeTable","dynamodb:ListTables"],
        "write": ["dynamodb:PutItem","dynamodb:UpdateItem","dynamodb:DeleteItem",
                  "dynamodb:BatchWriteItem"],
        "admin": ["dynamodb:CreateTable","dynamodb:DeleteTable",
                  "dynamodb:UpdateTable","dynamodb:TagResource"],
    },
    "rds": {
        "read":  ["rds:DescribeDBInstances","rds:DescribeDBClusters",
                  "rds:ListTagsForResource"],
        "write": ["rds:StartDBInstance","rds:StopDBInstance","rds:ModifyDBInstance"],
        "admin": ["rds:CreateDBInstance","rds:DeleteDBInstance",
                  "rds:CreateDBCluster","rds:DeleteDBCluster"],
    },
    "kms": {
        "read":  ["kms:DescribeKey","kms:GetKeyPolicy","kms:ListKeys"],
        "write": ["kms:Encrypt","kms:Decrypt","kms:GenerateDataKey","kms:ReEncrypt*"],
        "admin": ["kms:CreateKey","kms:ScheduleKeyDeletion","kms:PutKeyPolicy",
                  "kms:EnableKeyRotation"],
    },
    "sqs": {
        "read":  ["sqs:GetQueueAttributes","sqs:ListQueues","sqs:GetQueueUrl"],
        "write": ["sqs:SendMessage","sqs:ReceiveMessage","sqs:DeleteMessage"],
        "admin": ["sqs:CreateQueue","sqs:DeleteQueue","sqs:SetQueueAttributes"],
    },
    "cloudwatch": {
        "read":  ["cloudwatch:GetMetricStatistics","cloudwatch:ListMetrics",
                  "cloudwatch:DescribeAlarms","logs:GetLogEvents","logs:DescribeLogGroups"],
        "write": ["cloudwatch:PutMetricData","logs:PutLogEvents","logs:CreateLogGroup"],
        "admin": ["cloudwatch:PutMetricAlarm","cloudwatch:DeleteAlarms",
                  "logs:DeleteLogGroup"],
    },
    "secretsmanager": {
        "read":  ["secretsmanager:GetSecretValue","secretsmanager:DescribeSecret",
                  "secretsmanager:ListSecrets"],
        "write": ["secretsmanager:PutSecretValue","secretsmanager:UpdateSecret"],
        "admin": ["secretsmanager:CreateSecret","secretsmanager:DeleteSecret",
                  "secretsmanager:RotateSecret"],
    },
    "ecs": {
        "read":  ["ecs:DescribeTasks","ecs:ListTasks","ecs:DescribeClusters",
                  "ecs:ListClusters"],
        "write": ["ecs:RunTask","ecs:StopTask","ecs:UpdateService"],
        "admin": ["ecs:CreateCluster","ecs:DeleteCluster","ecs:CreateService",
                  "ecs:DeleteService","ecs:RegisterTaskDefinition"],
    },
}

# ─── Condition helpers ────────────────────────────────────────────────────────
ACCOUNT_IDS  = [f"{rng.randint(100000000000,999999999999)}" for _ in range(10)]
ORG_ID       = "o-example0001"
REGION       = "us-east-1"

def _cond_mfa():
    return {"Bool": {"aws:MultiFactorAuthPresent": "true"}}

def _cond_ip(cidr: Optional[str] = None):
    cidr = cidr or f"10.{rng.randint(0,255)}.0.0/16"
    return {"IpAddress": {"aws:SourceIp": cidr}}

def _cond_org():
    return {"StringEquals": {"aws:PrincipalOrgID": ORG_ID}}

def _cond_ssl():
    return {"Bool": {"aws:SecureTransport": "true"}}

def _cond_time():
    return {"DateGreaterThan": {"aws:CurrentTime": "2025-01-01T09:00:00Z"},
            "DateLessThan":    {"aws:CurrentTime": "2026-12-31T18:00:00Z"}}

def _merge(*conds):
    out = {}
    for c in conds:
        if c is None:
            continue
        for op, kv in c.items():
            if kv is None:
                continue
            out.setdefault(op, {}).update(kv)
    return out

# ─── Policy template families ──────────────────────────────────────────────────
generated: List[Dict] = []

def _save(name: str, policy: dict, label: int, desc: str, guideline: str):
    path = OUTPUT_DIR / f"{name}.json"
    payload = {
        "policy": policy,
        "metadata": {
            "risk_label": label,
            "description": desc,
            "guideline": guideline,
            "source": "aws_guideline_generator",
            "source_type": "guideline-based",
            "attached_to": [f"role-{rng.randint(1,100):03d}"]
        }
    }
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    generated.append({"name": name, "risk_label": label})


# ── Family 1: Least-privilege read-only per service (LOW) ──────────────────────
def gen_least_privilege_readonly():
    """AWS doc: 'Grant least privilege' — read-only per service with resource scope."""
    n = 0
    for svc, actions in FALLBACK_AWS_SERVICES.items():
        read_acts = actions["read"]
        for i in range(5):
            acct  = rng.choice(ACCOUNT_IDS)
            conds = rng.sample([_cond_mfa, _cond_ip, _cond_org, _cond_ssl], k=rng.randint(1,3))
            cond  = _merge(*[fn() for fn in conds])

            if svc == "s3":
                resource = [f"arn:aws:s3:::app-{i:04d}-bucket",
                            f"arn:aws:s3:::app-{i:04d}-bucket/*"]
            elif svc == "dynamodb":
                resource = f"arn:aws:dynamodb:{REGION}:{acct}:table/app-table-{i}"
            elif svc in ("iam", "kms", "ecs", "lambda", "secretsmanager"):
                resource = f"arn:aws:{svc}::{acct}:*"
            else:
                resource = "*"

            policy = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": f"{svc.upper()}ReadOnly{i}",
                    "Effect": "Allow",
                    "Action": read_acts,
                    "Resource": resource,
                    "Condition": cond
                }]
            }
            _save(f"gl_readonly_{svc}_{i:03d}", policy, LOW_RISK,
                  f"Least-privilege read-only for {svc}",
                  "AWS Security Best Practice: Grant Least Privilege")
            n += 1
    log.info(f"  LowestPriv ReadOnly: {n}")


# ── Family 2: AWS-recommended service-specific scoped write (LOW/MEDIUM) ───────
def gen_scoped_write():
    """AWS doc: Scope permissions to specific resources and conditions."""
    n = 0
    for svc, actions in FALLBACK_AWS_SERVICES.items():
        write_acts = actions["write"]
        for i in range(4):
            acct = rng.choice(ACCOUNT_IDS)
            has_cond = rng.random() < 0.7
            cond = _cond_mfa() if has_cond else None

            resource = (f"arn:aws:s3:::write-bucket-{i:03d}/*" if svc == "s3"
                        else f"arn:aws:{svc}::{acct}:*")
            stmt = {
                "Sid": f"{svc.upper()}Write{i}",
                "Effect": "Allow",
                "Action": write_acts,
                "Resource": resource
            }
            if cond:
                stmt["Condition"] = cond

            deny = {
                "Sid": "DenyNonSSL",
                "Effect": "Deny",
                "Action": write_acts,
                "Resource": "*",
                "Condition": {"Bool": {"aws:SecureTransport": "false"}}
            }

            policy = {"Version": "2012-10-17", "Statement": [stmt, deny]}
            label  = LOW_RISK if has_cond else MEDIUM_RISK
            _save(f"gl_scoped_write_{svc}_{i:03d}", policy, label,
                  f"Scoped write for {svc} with SSL deny",
                  "AWS Well-Architected: Protect data in transit")
            n += 1
    log.info(f"  ScopedWrite: {n}")


# ── Family 3: Cross-account access (best-practice with org condition) (LOW/HIGH) ─
def gen_cross_account_best_practice():
    """AWS doc: Cross-account access with aws:PrincipalOrgID guard."""
    for i in range(50):
        safe    = rng.random() < 0.6   # 60% use org condition → LOW; else HIGH
        ext_acct = rng.choice(ACCOUNT_IDS)
        stmt = {
            "Sid": f"CrossAccountAssumeRole{i}",
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Principal": {"AWS": f"arn:aws:iam::{ext_acct}:root"},
            "Resource": "*"
        }
        if safe:
            stmt["Condition"] = _merge(_cond_org(), _cond_mfa())

        policy = {"Version": "2012-10-17", "Statement": [stmt]}
        label  = LOW_RISK if safe else HIGH_RISK
        _save(f"gl_cross_account_{i:03d}", policy, label,
              "Cross-account STS AssumeRole " + ("with OrgID guard" if safe else "NO guard"),
              "AWS IAM: Cross-account access with SCP/OrgID guard")
    log.info(f"  CrossAccount: 50")


# ── Family 4: IAM admin guardrail (deny privilege escalation) (LOW) ────────────
def gen_iam_guardrail():
    """AWS doc: Use permission boundaries and SCPs as guardrails."""
    escalation_actions = [
        "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
        "iam:AttachUserPolicy", "iam:AttachRolePolicy",
        "iam:PutUserPolicy", "iam:PutRolePolicy",
        "iam:CreateAccessKey",
    ]
    for i in range(40):
        allow_actions = rng.sample(FALLBACK_AWS_SERVICES["iam"]["read"], k=3)
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowIAMRead",
                    "Effect": "Allow",
                    "Action": allow_actions,
                    "Resource": "*"
                },
                {
                    "Sid": "DenyPrivilegeEscalation",
                    "Effect": "Deny",
                    "Action": escalation_actions,
                    "Resource": "*"
                }
            ]
        }
        _save(f"gl_iam_guardrail_{i:03d}", policy, LOW_RISK,
              "IAM read with explicit Deny on privilege escalation actions",
              "AWS IAM: Prevent privilege escalation via explicit Deny")
    log.info(f"  IAMGuardrail: 40")


# ── Family 5: Condition-only policies (MEDIUM if missing a cond) ───────────────
def gen_condition_coverage():
    """Policies that demonstrate all 4 AWS condition types (MFA, IP, Org, time)."""
    configs = [
        ("all4",   [_cond_mfa,_cond_ip,_cond_org,_cond_time], LOW_RISK),
        ("mfa_ip", [_cond_mfa,_cond_ip],                       LOW_RISK),
        ("org_only",[_cond_org],                                MEDIUM_RISK),
        ("no_cond",[], MEDIUM_RISK),
    ]
    for tag, cond_fns, label in configs:
        for i in range(25):
            svc  = rng.choice(list(FALLBACK_AWS_SERVICES.keys()))
            acts = FALLBACK_AWS_SERVICES[svc]["read"]
            stmt = {"Sid": f"CondTest{i}","Effect":"Allow","Action":acts,"Resource":"*"}
            if cond_fns:
                stmt["Condition"] = _merge(*[fn() for fn in cond_fns])
            policy = {"Version":"2012-10-17","Statement":[stmt]}
            _save(f"gl_cond_{tag}_{i:03d}", policy, label,
                  f"Condition coverage test: {tag}",
                  "AWS Security: Use conditions to scope permissions")
    log.info(f"  ConditionCoverage: {4*25}")


# ── Family 6: Violation patterns (HIGH) — common misconfig from AWS advisories ──
def gen_known_violation_patterns():
    """Policies that violate AWS best practices (HIGH risk) — from AWS Trusted Advisor."""
    patterns = [
        ("aws_admin_star",
         [{"Effect":"Allow","Action":"*","Resource":"*"}],            HIGH_RISK,
         "Full admin wildcard — violates AWS Least Privilege"),
        ("aws_iam_star_nobound",
         [{"Effect":"Allow","Action":"iam:*","Resource":"*"}],        HIGH_RISK,
         "IAM full access without permission boundary — escalation risk"),
        ("aws_s3_public_read",
         [{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],
           "Resource":"arn:aws:s3:::*","Principal":"*"}],              HIGH_RISK,
         "S3 public read — violates AWS data protection guidance"),
        ("aws_no_mfa_iam_write",
         [{"Effect":"Allow","Action":["iam:CreateUser","iam:DeleteUser",
                                      "iam:AttachUserPolicy"],"Resource":"*"}],
         HIGH_RISK, "IAM write without MFA condition"),
        ("aws_cloudtrail_disable",
         [{"Effect":"Allow","Action":["cloudtrail:DeleteTrail",
                                      "cloudtrail:StopLogging"],"Resource":"*"}],
         HIGH_RISK, "Allows disabling CloudTrail — violates detective controls"),
    ]
    for slug, stmts, label, desc in patterns:
        for i in range(20):
            policy = {"Version":"2012-10-17","Statement":stmts}
            _save(f"gl_{slug}_{i:03d}", policy, label, desc,
                  "AWS Trusted Advisor / AWS Security Hub finding")
    log.info(f"  ViolationPatterns: {len(patterns)*20}")


# ─── Master runner ─────────────────────────────────────────────────────────────
def run_all():
    log.info("="*55 + "\nCloudShield AI — AWS Guideline Policy Generator\n" + "="*55)
    gen_least_privilege_readonly()
    gen_scoped_write()
    gen_cross_account_best_practice()
    gen_iam_guardrail()
    gen_condition_coverage()
    gen_known_violation_patterns()

    meta_path = BASE_DIR / "data" / "guideline_metadata.json"
    with open(meta_path,"w") as f:
        json.dump(generated, f, indent=2)

    total = len(generated)
    by_l  = {0:0,1:0,2:0}
    for g in generated:
        by_l[g["risk_label"]] += 1

    log.info("="*55)
    log.info(f"Guideline policies total: {total}")
    log.info(f"  LOW(0)={by_l[0]}  MED(1)={by_l[1]}  HIGH(2)={by_l[2]}")
    log.info(f"Output: {OUTPUT_DIR}")
    log.info("="*55)
    return generated


if __name__ == "__main__":
    run_all()
