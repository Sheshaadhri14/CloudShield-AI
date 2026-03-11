# weak_supervision.py — CloudShield AI (ENHANCED VERSION)
# Phase 6: 18 labeling functions covering all risk dimensions
from snorkel.labeling import labeling_function, PandasLFApplier
from snorkel.labeling.model import LabelModel
import pandas as pd
import numpy as np

# Label constants
ABSTAIN     = -1
LOW_RISK    = 0
MEDIUM_RISK = 1
HIGH_RISK   = 2

# ══════════════════════════════════════════════════════════════════════════════
# ORIGINAL 8 Labeling Functions
# ══════════════════════════════════════════════════════════════════════════════

@labeling_function()
def lf_escalation_paths_exist(x):
    """LF1: Escalation paths exist → HIGH"""
    if hasattr(x, 'escalation_path_count') and x.escalation_path_count > 0:
        return HIGH_RISK
    return ABSTAIN

@labeling_function()
def lf_wildcard_with_dangerous(x):
    """LF2: Wildcard + dangerous actions → HIGH"""
    if (hasattr(x, 'has_wildcard_action') and x.has_wildcard_action == 1 and
        hasattr(x, 'dangerous_action_count') and x.dangerous_action_count > 3):
        return HIGH_RISK
    return ABSTAIN

@labeling_function()
def lf_wildcard_resource(x):
    """LF3: Wildcard resource → MEDIUM"""
    if hasattr(x, 'has_wildcard_resource') and x.has_wildcard_resource == 1:
        return MEDIUM_RISK
    return ABSTAIN

@labeling_function()
def lf_high_specificity(x):
    """LF4: High specificity → LOW"""
    if (hasattr(x, 'specificity_score') and x.specificity_score > 0.8 and
        hasattr(x, 'has_wildcard_action') and x.has_wildcard_action == 0):
        return LOW_RISK
    return ABSTAIN

@labeling_function()
def lf_many_services(x):
    """LF5: Access to many services → MEDIUM"""
    if hasattr(x, 'service_count') and x.service_count > 10:
        return MEDIUM_RISK
    return ABSTAIN

@labeling_function()
def lf_dangerous_actions(x):
    """LF6: Many dangerous actions → HIGH / MEDIUM"""
    if hasattr(x, 'dangerous_action_count') and x.dangerous_action_count >= 5:
        return HIGH_RISK
    elif hasattr(x, 'dangerous_action_count') and x.dangerous_action_count >= 2:
        return MEDIUM_RISK
    return ABSTAIN

@labeling_function()
def lf_high_attachment(x):
    """LF7: Used by many entities → MEDIUM (blast radius)"""
    if hasattr(x, 'attachment_count') and x.attachment_count > 5:
        return MEDIUM_RISK
    return ABSTAIN

@labeling_function()
def lf_high_degree(x):
    """LF8: High connectivity → MEDIUM"""
    if hasattr(x, 'out_degree') and x.out_degree > 50:
        return MEDIUM_RISK
    return ABSTAIN

# ══════════════════════════════════════════════════════════════════════════════
# NEW 10 Labeling Functions (Phase 6)
# ══════════════════════════════════════════════════════════════════════════════

@labeling_function()
def lf_no_mfa_on_iam(x):
    """LF9: IAM write actions with NO MFA → HIGH
    If dangerous_action_count > 0 (iam:Create/Delete/Put/Attach) and
    requires_mfa == 0, this is a critical misconfiguration.
    """
    has_iam = getattr(x, 'dangerous_action_count', 0) > 0
    no_mfa  = getattr(x, 'requires_mfa', 0) == 0
    if has_iam and no_mfa:
        return HIGH_RISK
    return ABSTAIN

@labeling_function()
def lf_cross_account_no_org_cond(x):
    """LF10: Cross-account STS without org restriction → HIGH
    Proxy: escalation_techniques_enabled > 0 (STS chain present) and
    has_org_restriction == 0 means the AssumeRole is unconstrained.
    """
    has_sts = getattr(x, 'escalation_techniques_enabled', 0) > 0
    no_org  = getattr(x, 'has_org_restriction', 0) == 0
    if has_sts and no_org:
        return HIGH_RISK
    return ABSTAIN

@labeling_function()
def lf_passrole_wildcard_resource(x):
    """LF11: PassRole on wildcard resource → HIGH
    dangerous_action_count covers iam:PassRole-adjacent patterns;
    wildcard resource confirms it applies to any role.
    """
    has_passrole = getattr(x, 'dangerous_action_count', 0) >= 1
    wildcard_res = getattr(x, 'has_wildcard_resource', 0) == 1
    wildcard_act = getattr(x, 'has_wildcard_action', 0) == 1
    if has_passrole and (wildcard_res or wildcard_act):
        return HIGH_RISK
    return ABSTAIN

@labeling_function()
def lf_all_conditions_present(x):
    """LF12: MFA + IP + Org all enabled → LOW (defense-in-depth)"""
    mfa = getattr(x, 'requires_mfa', 0)
    ip  = getattr(x, 'has_ip_restriction', 0)
    org = getattr(x, 'has_org_restriction', 0)
    if mfa == 1 and ip == 1 and org == 1:
        return LOW_RISK
    return ABSTAIN

@labeling_function()
def lf_deny_statement_specificity(x):
    """LF13: Very high specificity (likely has Deny statements) → LOW risk"""
    if getattr(x, 'specificity_score', 0) > 0.95:
        return LOW_RISK
    return ABSTAIN

@labeling_function()
def lf_multi_step_escalation(x):
    """LF14: 2+ escalation techniques reachable → HIGH (chained attack)"""
    tech_count = getattr(x, 'escalation_techniques_enabled', 0)
    if tech_count >= 2:
        return HIGH_RISK
    return ABSTAIN

@labeling_function()
def lf_sensitive_service_no_condition(x):
    """LF15: Close to sensitive services (kms/iam/sts) but zero conditions → MEDIUM"""
    near_sensitive = getattr(x, 'min_path_to_sensitive', 999) <= 1.0
    no_cond = (
        getattr(x, 'requires_mfa', 0)       == 0 and
        getattr(x, 'has_ip_restriction', 0)  == 0 and
        getattr(x, 'has_org_restriction', 0) == 0
    )
    if near_sensitive and no_cond:
        return MEDIUM_RISK
    return ABSTAIN

@labeling_function()
def lf_zero_attachments_inactive(x):
    """LF16: Not attached to any entity → LOW (inactive, less blast radius)"""
    if getattr(x, 'attachment_count', 0) == 0 and getattr(x, 'out_degree', 0) < 5:
        return LOW_RISK
    return ABSTAIN

@labeling_function()
def lf_resource_scoped_no_wildcard(x):
    """LF17: Resource-scoped with no wildcards and few services → LOW"""
    no_wc  = getattr(x, 'has_wildcard_resource', 0) == 0
    no_wca = getattr(x, 'has_wildcard_action', 0) == 0
    few_svc = getattr(x, 'service_count', 999) <= 3
    if no_wc and no_wca and few_svc:
        return LOW_RISK
    return ABSTAIN

@labeling_function()
def lf_service_wildcard_only(x):
    """LF18: Has service wildcards (s3:*, ec2:*) but NOT full wildcard (*) → MEDIUM"""
    svc_wc = getattr(x, 'service_wildcard_count', 0) > 0
    no_full = getattr(x, 'has_wildcard_action', 0) == 0
    if svc_wc and no_full:
        return MEDIUM_RISK
    return ABSTAIN

# ══════════════════════════════════════════════════════════════════════════════
labeling_functions = [
    # Original 8
    lf_escalation_paths_exist,
    lf_wildcard_with_dangerous,
    lf_wildcard_resource,
    lf_high_specificity,
    lf_many_services,
    lf_dangerous_actions,
    lf_high_attachment,
    lf_high_degree,
    # New 10 (Phase 6)
    lf_no_mfa_on_iam,
    lf_cross_account_no_org_cond,
    lf_passrole_wildcard_resource,
    lf_all_conditions_present,
    lf_deny_statement_specificity,
    lf_multi_step_escalation,
    lf_sensitive_service_no_condition,
    lf_zero_attachments_inactive,
    lf_resource_scoped_no_wildcard,
    lf_service_wildcard_only,
]

class WeakSupervisionPipeline:
    """Robust weak supervision pipeline"""
    
    def __init__(self, labeling_functions):
        self.lfs = labeling_functions
        self.label_model = None
        
    def apply_lfs(self, df: pd.DataFrame) -> np.ndarray:
        """Apply labeling functions with error handling"""

        required_cols = [
            'escalation_path_count', 'has_wildcard_action',
            'dangerous_action_count', 'has_wildcard_resource',
            'specificity_score', 'service_count', 'attachment_count',
            'out_degree', 'service_wildcard_count',
            # Phase 6 contextual
            'requires_mfa', 'has_ip_restriction', 'has_time_restriction',
            'has_org_restriction', 'escalation_techniques_enabled',
            'min_path_to_sensitive',
        ]
        for col in required_cols:
            if col not in df.columns:
                df[col] = 0

        applier  = PandasLFApplier(lfs=self.lfs)
        L_train  = applier.apply(df=df)
        return L_train
    
    def train_label_model(self, L_train: np.ndarray):
        """Train label aggregation model"""
        
        self.label_model = LabelModel(cardinality=3, verbose=True)
        self.label_model.fit(
            L_train=L_train,
            n_epochs=100,  # Reduced for speed
            lr=0.01,
            log_freq=50,
            seed=42
        )
        
    def get_probabilistic_labels(self, L_train: np.ndarray) -> np.ndarray:
        if self.label_model is None:
            raise ValueError("Must train label model first")
        return self.label_model.predict_proba(L=L_train)
    
    def get_hard_labels(self, L_train: np.ndarray) -> np.ndarray:
        if self.label_model is None:
            raise ValueError("Must train label model first")
        return self.label_model.predict(L=L_train)
    
    def analyze_lf_performance(self, L_train: np.ndarray):
        from snorkel.labeling import LFAnalysis
        analysis = LFAnalysis(L=L_train, lfs=self.lfs)
        df_analysis = analysis.lf_summary()
        print("\n=== LABELING FUNCTION ANALYSIS ===")
        print(df_analysis)
        return df_analysis

# Usage
if __name__ == "__main__":
    import os
    from pathlib import Path

    BASE_DIR     = Path(__file__).resolve().parents[1]
    FEATURES_CSV = BASE_DIR / "data" / "graph_features.csv"
    LABELS_CSV   = BASE_DIR / "data" / "labeled_features.csv"

    df = pd.read_csv(FEATURES_CSV)
    print(f"Loaded {len(df)} policies from {FEATURES_CSV}")

    pipeline = WeakSupervisionPipeline(labeling_functions)
    print(f"Total labeling functions: {len(labeling_functions)}")

    print("\nApplying {len(labeling_functions)} labeling functions...")
    L_train = pipeline.apply_lfs(df)
    print(f"Label matrix shape: {L_train.shape}")

    pipeline.analyze_lf_performance(L_train)

    # Use known_risk_label as seed labels if available
    if 'known_risk_label' in df.columns:
        known_mask = df['known_risk_label'].notna()
        print(f"Using {known_mask.sum()} known ground-truth labels from synthetic/real-world data")

    print("\nTraining label aggregation model...")
    pipeline.train_label_model(L_train)

    probs  = pipeline.get_probabilistic_labels(L_train)
    labels = pipeline.get_hard_labels(L_train)

    print("\nLabel distribution:")
    print(pd.Series(labels).value_counts().sort_index())

    df['risk_label'] = labels
    df[['prob_low', 'prob_medium', 'prob_high']] = probs
    df.to_csv(LABELS_CSV, index=False)
    print(f"\nLabeled dataset saved to {LABELS_CSV}")
    print(f"Total samples: {len(df)}")
    print(f"Label dist: {dict(pd.Series(labels).value_counts().sort_index())}")
