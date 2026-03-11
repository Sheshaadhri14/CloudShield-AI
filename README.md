# 🛡️ CloudShield AI — Intelligent IAM Risk Detection & Remediation

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python)
![PyTorch](https://img.shields.io/badge/PyTorch-Geometric-EE4C2C?style=flat-square&logo=pytorch)
![TensorFlow](https://img.shields.io/badge/TensorFlow-2.x-FF6F00?style=flat-square&logo=tensorflow)
![Status](https://img.shields.io/badge/Status-Active%20Development-yellow?style=flat-square)
![Policies](https://img.shields.io/badge/Training%20Data-1%2C247%20AWS%20Policies-orange?style=flat-square)
![F1 Target](https://img.shields.io/badge/Target%20Macro%20F1-0.92-brightgreen?style=flat-square)

**A three-tier AI system combining Graph Neural Networks, Liquid Neural Networks, and LLM reasoning to detect and auto-remediate AWS IAM misconfigurations.**

</div>

---

## 🎯 The Problem

**70% of AWS security incidents are caused by IAM misconfiguration.**

Current tools fail because they rely on fixed rules and flat classifiers — they miss the *context* behind policies. They cannot see relationships between users, roles, and resources. They cannot detect slow permission drift over months. And when they flag an issue, they cannot explain it in plain language or generate a fix.

CloudShield AI solves all three gaps with a unified three-tier architecture.

---

## 🏗️ Architecture

```
AWS IAM Policies (JSON)
         │
         ▼
┌──────────────────────────────────────┐
│  TIER 1: Heterogeneous Graph         │
│  Transformer (HGT)                   │
│                                      │
│  Builds a knowledge graph:           │
│  Users ──► Roles ──► Policies        │
│                  └──► Resources      │
│                                      │
│  Detects: Privilege escalation,      │
│  overpermissioned roles, lateral     │
│  movement risks                      │
└──────────────────┬───────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│  TIER 2: Liquid Neural Network (LNN) │
│                                      │
│  Analyses how policies evolve        │
│  over time — captures slow           │
│  permission drift that static        │
│  models completely miss              │
│                                      │
│  Detects: Temporal escalation,       │
│  silent privilege creep              │
└──────────────────┬───────────────────┘
                   │
                   ▼
┌──────────────────────────────────────┐
│  TIER 3: LLM Reasoning Agent         │
│                                      │
│  • Explains risk in plain English    │
│  • Auto-generates AWS fix patches    │
│  • Accessible to non-IAM-experts     │
└──────────────────────────────────────┘
```

---

## 💡 Why This Architecture

| Tier | Model | Why Not Something Simpler |
|---|---|---|
| 1 | Heterogeneous Graph Transformer | IAM is a graph — users, roles, policies, resources are nodes with directional relationships. CNNs and RNNs cannot model this structure. |
| 2 | Liquid Neural Network | Permission drift happens slowly over months. LNNs are built for continuous-time dynamics — they model how a system *evolved*, not just its current state. |
| 3 | LLM Reasoning Agent | Raw risk scores are useless to most security teams. The LLM converts model output into plain-English explanations and generates ready-to-deploy fix patches. |

---

## 📊 Training & Targets

| Metric | Value |
|---|---|
| Dataset | 4k+ AWS managed policies |
| Target Macro F1 | **0.92** |
| Frameworks | PyTorch Geometric, TensorFlow, Python |
| Risk categories | Overpermissioned roles, privilege escalation, temporal drift, lateral movement |

---

## 📁 Repository Structure

```
CloudShield-AI/
│
├── data/
│   └── aws_policies/           # 1,247 AWS managed policy JSONs
│
├── src/
│   └── preprocessing/          # Policy parsing & graph construction scripts
│
├── notebooks/                  # Jupyter notebooks — EDA, model experiments
│
├── requirements.txt            # All dependencies
├── STATUS.md                   # Current development progress
└── README.md
```

---

## 🔍 Example System Output

**Input:** IAM policy granting `s3:*` to a developer role with no conditions

**Tier 1 (HGT) risk signal:**
```json
{
  "risk_type": "overpermissioned_role",
  "affected_node": "role/dev-team",
  "permission_path": "dev-team → s3:* → production-bucket",
  "severity_score": 0.89
}
```

**Tier 3 (LLM) output:**
```
⚠️  HIGH RISK: Developer role has unrestricted S3 access

The dev-team role grants s3:* (all S3 actions) with no resource
constraints. Any developer can read, write, or delete production data.

Auto-generated remediation patch:
{
  "Effect": "Allow",
  "Action": ["s3:GetObject", "s3:PutObject"],
  "Resource": "arn:aws:s3:::your-bucket-name/*",
  "Condition": {
    "StringEquals": {"aws:RequestedRegion": "ap-south-1"}
  }
}
```

---

## 🚀 Setup

```bash
# Clone
git clone https://github.com/Sheshaadhri14/CloudShield-AI.git
cd CloudShield-AI

# Create virtual environment
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Launch notebooks
jupyter lab
```

---

## 👥 Team

**Sri Sheshaadhri R** *(Project Lead)*
Architecture design, dataset curation, training pipeline
- 🔗 [GitHub](https://github.com/Sheshaadhri14)
- 📧 sheshaadhri14@gmail.com
- 🏫 VIT Chennai | Computer Science & Engineering

---

> *"IAM misconfiguration causes 70% of AWS breaches. CloudShield AI makes IAM risk detection accessible to every team — not just security experts."*
