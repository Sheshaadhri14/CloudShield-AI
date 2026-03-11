# 🔧 CloudShield AI — Development Status

*Last updated: March 2026*

---

## ✅ Completed

- [x] **AWS policy dataset** — 1,247 AWS managed policies collected and stored
- [x] **Preprocessing pipeline** — scripts to parse raw IAM policy JSON, extract entities (users, roles, actions, resources), and clean data
- [x] **Exploratory analysis** — Jupyter notebooks analysing policy structure, permission distributions, and risk patterns
- [x] **Requirements defined** — `requirements.txt` with full dependency list
- [x] **System architecture** — three-tier HGT + LNN + LLM pipeline fully designed and documented

---

## 🔄 In Progress

- [ ] **Tier 1 — HGT model** — building heterogeneous graph from parsed policies, implementing graph transformer layers in PyTorch Geometric
- [ ] **Tier 2 — LNN model** — continuous-time dynamics for temporal permission drift detection using TensorFlow
- [ ] **Tier 3 — LLM reasoning agent** — prompt engineering for risk explanation and AWS remediation patch generation

---

## 📅 Upcoming

- [ ] End-to-end pipeline integration — connecting all three tiers into a single inference flow
- [ ] Benchmark against existing tools (Prowler, ScoutSuite, AWS Access Analyzer)
- [ ] Evaluation on held-out policy test set — target Macro F1: 0.92
- [ ] Real-time AWS API integration via Boto3
- [ ] Web dashboard for non-technical security teams

---

*Active development — check back for updates.*
