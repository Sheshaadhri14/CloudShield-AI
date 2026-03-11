"""
realworld_data_fetcher.py
Fetches and standardises real-world IAM policy data from 6 public sources:
  1. CloudGoat scenarios  (already in repo - Terraform + JSON)
  2. BishopFox/iam-vulnerable  (31 escalation paths)
  3. iann0036/iam-dataset  (AWS managed policies via GitHub)
  4. Rhino Security Labs / Pacu  (21 escalation permission sets)
  5. MITRE ATT&CK Cloud  (IAM-relevant sub-techniques)
  6. UTwente academic misconfiguration catalog
Output: data/realworld_policies/ + data/realworld_metadata.json
"""
import os, re, json, time, logging, hashlib, urllib.request
from pathlib import Path
from typing import Dict, List, Optional

logging.basicConfig(level=logging.INFO, format='%(levelname)s | %(message)s')
log = logging.getLogger(__name__)

BASE_DIR      = Path(__file__).resolve().parents[1]
OUTPUT_DIR    = BASE_DIR / "data" / "realworld_policies"
CLOUDGOAT_DIR = BASE_DIR / "data" / "cloudgoat"
METADATA_FILE = BASE_DIR / "data" / "realworld_metadata.json"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

LOW_RISK = 0; MEDIUM_RISK = 1; HIGH_RISK = 2
all_metadata: List[Dict] = []

def _save(name: str, doc: dict, meta: dict):
    path = OUTPUT_DIR / f"{name}.json"
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)
    all_metadata.append({"policy_name": name, "file": str(path), **meta})

def _fetch(url: str) -> Optional[str]:
    for i in range(3):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "iam-graph-xai"})
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.read().decode()
        except Exception as e:
            log.warning(f"  Fetch attempt {i+1} failed: {e}"); time.sleep(1.5)
    return None

# ── Source 1: CloudGoat ──────────────────────────────────────────────────────
CLOUDGOAT_RISK = {
    "iam_privesc_by_rollback": HIGH_RISK, "vulnerable_lambda": HIGH_RISK,
    "cloud_breach_s3": HIGH_RISK,         "ec2_ssrf": HIGH_RISK,
    "codebuild_secrets": MEDIUM_RISK,     "detection_evasion": HIGH_RISK,
    "rce_web_app": HIGH_RISK,             "beanstalk_secrets": MEDIUM_RISK,
}
_HEREDOC = re.compile(r'<<-?(?:EOT|EOF|POLICY|JSON)(.*?)(?:EOT|EOF|POLICY|JSON)', re.DOTALL)

def _hcl_policies(hcl: str) -> List[dict]:
    docs = []
    for m in _HEREDOC.finditer(hcl):
        c = m.group(1).strip()
        if c.startswith("{"):
            try: docs.append(json.loads(c))
            except: pass
    for m in re.finditer(r'\{\s*"Version"\s*:\s*"2012-10-17"', hcl):
        s, depth, end = m.start(), 0, m.start()
        for i, ch in enumerate(hcl[s:], s):
            if ch == '{': depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0: end = i+1; break
        try: docs.append(json.loads(hcl[s:end]))
        except: pass
    return docs

def ingest_cloudgoat():
    log.info("=== Source 1: CloudGoat ==="); count = 0
    scn_dir = CLOUDGOAT_DIR / "cloudgoat" / "scenarios"
    if not scn_dir.exists(): log.warning("  Scenarios dir not found"); return
    for scn in scn_dir.glob("aws/**"):
        if not scn.is_dir(): continue
        risk = CLOUDGOAT_RISK.get(scn.name, MEDIUM_RISK)
        for jf in scn.rglob("*.json"):
            if "package" in jf.name: continue
            try:
                doc = json.load(open(jf))
                if isinstance(doc, dict) and "Statement" in doc:
                    _save(f"cg_{scn.name}_{jf.stem}", doc,
                          {"source":"cloudgoat","scenario":scn.name,"risk_label":risk,"source_type":"real-world-attack"})
                    count += 1
            except: pass
        for tf in scn.rglob("iam.tf"):
            try:
                for i, doc in enumerate(_hcl_policies(open(tf).read())):
                    _save(f"cg_{scn.name}_tf_{i}", doc,
                          {"source":"cloudgoat_terraform","scenario":scn.name,"risk_label":risk,"source_type":"real-world-attack"})
                    count += 1
            except: pass
    log.info(f"  CloudGoat: {count} policies")

# ── Source 2: BishopFox/iam-vulnerable (31 paths) ────────────────────────────
BISHOPFOX_PATHS = [
    ("bf_CreatePolicyVersion",      ["iam:CreatePolicyVersion"],                                                      HIGH_RISK),
    ("bf_SetDefaultPolicyVersion",  ["iam:SetDefaultPolicyVersion","iam:ListPolicyVersions"],                         HIGH_RISK),
    ("bf_CreateAccessKey",          ["iam:CreateAccessKey"],                                                          HIGH_RISK),
    ("bf_CreateLoginProfile",       ["iam:CreateLoginProfile"],                                                       HIGH_RISK),
    ("bf_UpdateLoginProfile",       ["iam:UpdateLoginProfile"],                                                       HIGH_RISK),
    ("bf_AttachUserPolicy",         ["iam:AttachUserPolicy"],                                                         HIGH_RISK),
    ("bf_AttachGroupPolicy",        ["iam:AttachGroupPolicy"],                                                        HIGH_RISK),
    ("bf_AttachRolePolicy",         ["iam:AttachRolePolicy","sts:AssumeRole"],                                        HIGH_RISK),
    ("bf_PutUserPolicy",            ["iam:PutUserPolicy"],                                                            HIGH_RISK),
    ("bf_PutGroupPolicy",           ["iam:PutGroupPolicy"],                                                           HIGH_RISK),
    ("bf_PutRolePolicy",            ["iam:PutRolePolicy","sts:AssumeRole"],                                           HIGH_RISK),
    ("bf_AddUserToGroup",           ["iam:AddUserToGroup"],                                                           HIGH_RISK),
    ("bf_UpdateAssumeRolePolicy",   ["iam:UpdateAssumeRolePolicy"],                                                   HIGH_RISK),
    ("bf_EC2InstanceProfile",       ["iam:CreateInstanceProfile","iam:AddRoleToInstanceProfile","ec2:RunInstances"],  HIGH_RISK),
    ("bf_PassRole_LambdaCreate",    ["iam:PassRole","lambda:CreateFunction","lambda:InvokeFunction"],                 HIGH_RISK),
    ("bf_PassRole_LambdaUpdate",    ["iam:PassRole","lambda:UpdateFunctionCode"],                                     HIGH_RISK),
    ("bf_PassRole_LambdaCfg",       ["iam:PassRole","lambda:UpdateFunctionConfiguration"],                           HIGH_RISK),
    ("bf_PassRole_EC2UserData",     ["iam:PassRole","ec2:RunInstances","ec2:ModifyInstanceAttribute"],               HIGH_RISK),
    ("bf_PassRole_CloudFormation",  ["iam:PassRole","cloudformation:CreateStack"],                                   HIGH_RISK),
    ("bf_PassRole_DataPipeline",    ["iam:PassRole","datapipeline:CreatePipeline","datapipeline:ActivatePipeline"],  HIGH_RISK),
    ("bf_PassRole_Glue",            ["iam:PassRole","glue:CreateDevEndpoint"],                                       HIGH_RISK),
    ("bf_PassRole_SageMaker",       ["iam:PassRole","sagemaker:CreateNotebookInstance"],                             HIGH_RISK),
    ("bf_PassRole_CodeBuild",       ["iam:PassRole","codebuild:CreateProject"],                                      HIGH_RISK),
    ("bf_PassRole_SageMakerTrain",  ["iam:PassRole","sagemaker:CreateTrainingJob"],                                  HIGH_RISK),
    ("bf_PassRole_SageMakerProc",   ["iam:PassRole","sagemaker:CreateProcessingJob"],                               HIGH_RISK),
    ("bf_PassRole_ECS",             ["iam:PassRole","ecs:RegisterTaskDefinition","ecs:RunTask"],                     HIGH_RISK),
    ("bf_STS_AssumeRole",           ["sts:AssumeRole"],                                                              HIGH_RISK),
    ("bf_STS_SAML",                 ["sts:AssumeRoleWithSAML"],                                                      HIGH_RISK),
    ("bf_STS_WebIdentity",          ["sts:AssumeRoleWithWebIdentity"],                                               HIGH_RISK),
    ("bf_CodeStar_Create",          ["codestar:CreateProject","iam:PassRole"],                                       HIGH_RISK),
    ("bf_CodeStar_Associate",       ["codestar:AssociateTeamMember"],                                                MEDIUM_RISK),
]

def ingest_bishopfox():
    log.info("=== Source 2: BishopFox/iam-vulnerable ===")
    for slug, actions, risk in BISHOPFOX_PATHS:
        _save(slug,
              {"Version":"2012-10-17","Statement":[{"Sid":slug,"Effect":"Allow","Action":actions,"Resource":"*"}]},
              {"source":"bishopfox_iam_vulnerable","risk_label":risk,"source_type":"real-world-attack",
               "reference":"https://github.com/BishopFox/iam-vulnerable"})
    log.info(f"  BishopFox: {len(BISHOPFOX_PATHS)} policies")

# ── Source 3: iann0036/iam-dataset ───────────────────────────────────────────
IANN_URL = "https://raw.githubusercontent.com/iann0036/iam-dataset/main/aws/managed_policies.json"

def _guess_risk(name: str, doc: dict) -> int:
    acts = []
    for s in doc.get("Statement",[]):
        a = s.get("Action",[]); acts.extend([a] if isinstance(a,str) else a)
    if "*" in acts or any(":*" in a and a.startswith("iam") for a in acts): return HIGH_RISK
    for p in ["ADMINISTRATOR","IAMFULL"]:
        if p in name.upper(): return HIGH_RISK
    for p in ["READONLY","VIEWONLY","LISTONLY"]:
        if p in name.upper(): return LOW_RISK
    return MEDIUM_RISK if len(acts) > 30 else LOW_RISK

def ingest_iann_dataset(limit: int = 500):
    log.info("=== Source 3: iann0036/iam-dataset ===")
    raw = _fetch(IANN_URL)
    if not raw: log.warning("  Could not fetch; skipping"); return
    try: data = json.loads(raw)
    except Exception as e: log.warning(f"  Parse error: {e}"); return
    if not isinstance(data, list): data = [data]
    count = 0
    for item in data[:limit]:
        name = item.get("PolicyName") or item.get("name") or f"iann_{count}"
        doc  = item.get("PolicyDocument") or item.get("document") or item
        if not isinstance(doc,dict) or "Statement" not in doc: continue
        safe = re.sub(r'[^A-Za-z0-9_\-]','_',name)[:70]
        _save(f"iann_{safe}", doc,
              {"source":"iann0036_iam_dataset","policy_name":name,
               "risk_label":_guess_risk(name,doc),"source_type":"real-world-managed"})
        count += 1
    log.info(f"  iann0036: {count} policies")

# ── Source 4: Rhino Security Labs / Pacu ─────────────────────────────────────
RHINO_SETS = [
    ("rhino_T1",  ["iam:CreatePolicyVersion"],                                                    HIGH_RISK),
    ("rhino_T2",  ["iam:SetDefaultPolicyVersion","iam:ListPolicyVersions"],                        HIGH_RISK),
    ("rhino_T3",  ["iam:CreateAccessKey"],                                                         HIGH_RISK),
    ("rhino_T4",  ["iam:CreateLoginProfile"],                                                      HIGH_RISK),
    ("rhino_T5",  ["iam:UpdateAssumeRolePolicy","sts:AssumeRole"],                                 HIGH_RISK),
    ("rhino_T6",  ["iam:AttachUserPolicy"],                                                        HIGH_RISK),
    ("rhino_T7",  ["iam:AttachRolePolicy","sts:AssumeRole"],                                       HIGH_RISK),
    ("rhino_T8",  ["iam:PutUserPolicy"],                                                           HIGH_RISK),
    ("rhino_T9",  ["iam:PutRolePolicy","sts:AssumeRole"],                                          HIGH_RISK),
    ("rhino_T10", ["iam:AddUserToGroup"],                                                          HIGH_RISK),
    ("rhino_T11", ["lambda:UpdateFunctionCode","iam:PassRole"],                                    HIGH_RISK),
    ("rhino_T12", ["iam:PassRole","lambda:CreateFunction","lambda:InvokeFunction"],                HIGH_RISK),
    ("rhino_T13", ["ec2:RunInstances","iam:PassRole"],                                             HIGH_RISK),
    ("rhino_T14", ["cloudformation:CreateStack","iam:PassRole"],                                   HIGH_RISK),
    ("rhino_T15", ["datapipeline:CreatePipeline","datapipeline:ActivatePipeline","iam:PassRole"],  HIGH_RISK),
    ("rhino_T16", ["glue:CreateDevEndpoint","iam:PassRole"],                                       HIGH_RISK),
    ("rhino_T17", ["sagemaker:CreateNotebookInstance","iam:PassRole"],                             HIGH_RISK),
    ("rhino_T18", ["lambda:UpdateFunctionConfiguration","iam:PassRole"],                          HIGH_RISK),
    ("rhino_T19", ["lambda:AddPermission","lambda:InvokeFunction"],                               HIGH_RISK),
    ("rhino_T20", ["codebuild:CreateProject","codebuild:StartBuild","iam:PassRole"],              HIGH_RISK),
    ("rhino_T21", ["sts:AssumeRole"],                                                             HIGH_RISK),
    ("rhino_recon_iam", ["iam:List*","iam:Get*"],                                                 MEDIUM_RISK),
    ("rhino_recon_sts", ["sts:GetCallerIdentity","iam:GetUser"],                                  LOW_RISK),
]

def ingest_rhino_pacu():
    log.info("=== Source 4: Rhino Security Labs / Pacu ===")
    for slug, actions, risk in RHINO_SETS:
        _save(slug,
              {"Version":"2012-10-17","Statement":[{"Sid":slug,"Effect":"Allow","Action":actions,"Resource":"*"}]},
              {"source":"rhino_security_labs","risk_label":risk,"source_type":"real-world-attack",
               "reference":"https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"})
    log.info(f"  Rhino/Pacu: {len(RHINO_SETS)} policies")

# ── Source 5: MITRE ATT&CK Cloud ─────────────────────────────────────────────
MITRE_PATTERNS = [
    ("mitre_T1098", ["iam:UpdateAccessKey","iam:CreateAccessKey","iam:UpdateLoginProfile"],      HIGH_RISK),
    ("mitre_T1087", ["iam:ListUsers","iam:ListRoles","iam:ListPolicies"],                        MEDIUM_RISK),
    ("mitre_T1136", ["iam:CreateUser","iam:CreateRole","iam:AttachUserPolicy"],                  HIGH_RISK),
    ("mitre_T1078", ["sts:AssumeRole","sts:GetSessionToken","sts:AssumeRoleWithWebIdentity"],    HIGH_RISK),
    ("mitre_T1548", ["iam:PassRole","lambda:InvokeFunction","lambda:CreateFunction"],           HIGH_RISK),
    ("mitre_T1562", ["cloudtrail:DeleteTrail","cloudtrail:StopLogging","cloudtrail:UpdateTrail"],HIGH_RISK),
    ("mitre_T1530", ["s3:GetObject","s3:ListBucket","s3:ListAllMyBuckets"],                     MEDIUM_RISK),
    ("mitre_T1552", ["ssm:GetParameter","secretsmanager:GetSecretValue","kms:Decrypt"],         HIGH_RISK),
    ("mitre_T1537", ["s3:PutBucketPolicy","s3:PutBucketAcl","s3:PutObject"],                   HIGH_RISK),
    ("mitre_T1580", ["ec2:DescribeInstances","rds:DescribeDBInstances","eks:ListClusters"],      LOW_RISK),
]

def ingest_mitre():
    log.info("=== Source 5: MITRE ATT&CK Cloud ===")
    for slug, actions, risk in MITRE_PATTERNS:
        _save(slug,
              {"Version":"2012-10-17","Statement":[{"Sid":slug,"Effect":"Allow","Action":actions,"Resource":"*"}]},
              {"source":"mitre_attack_cloud","risk_label":risk,"source_type":"real-world-attack",
               "reference":"https://attack.mitre.org/matrices/enterprise/cloud/"})
    log.info(f"  MITRE ATT&CK: {len(MITRE_PATTERNS)} policies")

# ── Source 6: UTwente academic misconfiguration catalog ───────────────────────
UTWENTE_CATALOG = [
    ("utw_admin_wildcard",
     [{"Effect":"Allow","Action":"*","Resource":"*"}], HIGH_RISK),
    ("utw_iam_star",
     [{"Effect":"Allow","Action":"iam:*","Resource":"*"}], HIGH_RISK),
    ("utw_sts_no_condition",
     [{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"*"}], HIGH_RISK),
    ("utw_passrole_star",
     [{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}], HIGH_RISK),
    ("utw_kms_star",
     [{"Effect":"Allow","Action":"kms:*","Resource":"*"}], HIGH_RISK),
    ("utw_s3_star_all_buckets",
     [{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::*"}], MEDIUM_RISK),
    ("utw_ec2_star",
     [{"Effect":"Allow","Action":"ec2:*","Resource":"*"}], MEDIUM_RISK),
    ("utw_lambda_star",
     [{"Effect":"Allow","Action":"lambda:*","Resource":"*"}], MEDIUM_RISK),
    ("utw_cloudwatch_no_mfa",
     [{"Effect":"Allow","Action":["cloudwatch:*","logs:*"],"Resource":"*"}], MEDIUM_RISK),
    ("utw_iam_list_get",
     [{"Effect":"Allow","Action":["iam:List*","iam:Get*"],"Resource":"*"}], MEDIUM_RISK),
    ("utw_s3_readonly_orgcond",
     [{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],
       "Resource":["arn:aws:s3:::app-bucket","arn:aws:s3:::app-bucket/*"],
       "Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-example111"}}}], LOW_RISK),
    ("utw_dynamo_readonly_mfa",
     [{"Effect":"Allow","Action":["dynamodb:GetItem","dynamodb:Query"],
       "Resource":"arn:aws:dynamodb:us-east-1:123456789012:table/MyTable",
       "Condition":{"Bool":{"aws:MultiFactorAuthPresent":"true"}}}], LOW_RISK),
    ("utw_ec2_describeonly",
     [{"Effect":"Allow","Action":["ec2:Describe*"],"Resource":"*"}], LOW_RISK),
    ("utw_cloudwatch_readonly",
     [{"Effect":"Allow","Action":["cloudwatch:Describe*","cloudwatch:Get*","cloudwatch:List*"],"Resource":"*"}], LOW_RISK),
    ("utw_deny_delete",
     [{"Effect":"Allow","Action":"s3:*","Resource":"*"},
      {"Effect":"Deny","Action":["s3:DeleteObject","s3:DeleteBucket"],"Resource":"*"}], MEDIUM_RISK),
]

def ingest_utwente():
    log.info("=== Source 6: UTwente academic catalog ===")
    for slug, stmts, risk in UTWENTE_CATALOG:
        _save(slug, {"Version":"2012-10-17","Statement":stmts},
              {"source":"utwente_academic","risk_label":risk,"source_type":"real-world-research",
               "reference":"https://thijsvane.de/research/"})
    log.info(f"  UTwente: {len(UTWENTE_CATALOG)} policies")

# ── Master runner ─────────────────────────────────────────────────────────────
def run_all(iann_limit: int = 500):
    log.info("="*55 + "\nCloudShield AI — Real-World Data Fetcher\n" + "="*55)
    ingest_cloudgoat()
    ingest_bishopfox()
    ingest_iann_dataset(iann_limit)
    ingest_rhino_pacu()
    ingest_mitre()
    ingest_utwente()

    with open(METADATA_FILE,"w") as f:
        json.dump(all_metadata, f, indent=2)

    total = len(all_metadata)
    by_l  = {0:0,1:0,2:0}
    for m in all_metadata:
        lbl = m.get("risk_label",1); by_l[lbl] = by_l.get(lbl,0)+1

    log.info("="*55)
    log.info(f"TOTAL real-world policies: {total}")
    log.info(f"  LOW(0)={by_l[0]}  MED(1)={by_l[1]}  HIGH(2)={by_l[2]}")
    log.info(f"Output: {OUTPUT_DIR}")
    log.info("="*55)
    return all_metadata

if __name__ == "__main__":
    run_all(iann_limit=500)
