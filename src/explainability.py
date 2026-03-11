# explainability.py
import shap
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import pickle
import networkx as nx

class IAMExplainer:
    """Multi-layer explainability for IAM risk predictions"""
    
    def __init__(self, model, feature_names, graph, escalation_detector):
        self.model = model
        self.feature_names = feature_names
        self.graph = graph
        self.detector = escalation_detector
        self.shap_explainer = None
        
    def initialize_shap(self, X_background):
        """Initialize SHAP explainer with background dataset"""
        
        print("Initializing SHAP explainer (this may take a few minutes)...")
        self.shap_explainer = shap.TreeExplainer(
            self.model,
            X_background
        )
        print("SHAP explainer ready!")
    
    def explain_prediction(self, policy_id: str, features: pd.Series):
        """
        Generate multi-layer explanation for a single policy
        
        Returns:
            - SHAP explanation
            - Graph path explanation
            - Counterfactual remediation
        """
        
        explanation = {}
        
        # Predict risk
        X_single = features.values.reshape(1, -1)
        prediction = self.model.predict(X_single)[0]
        probabilities = self.model.predict_proba(X_single)[0]
        
        explanation['prediction'] = prediction
        explanation['probabilities'] = probabilities
        explanation['risk_label'] = ['Low Risk', 'Medium Risk', 'High Risk'][prediction]
        
        # Layer 1: SHAP values
        explanation['shap'] = self._shap_explanation(X_single, features, prediction)
        
        # Layer 2: Graph path explanation
        explanation['graph_paths'] = self._graph_path_explanation(policy_id)
        
        # Layer 3: Counterfactual remediation
        explanation['counterfactuals'] = self._counterfactual_explanation(
            policy_id, features, prediction
        )
        
        return explanation
    
    def _shap_explanation(self, X, features, prediction):
        """Generate SHAP-based explanation"""
        
        if self.shap_explainer is None:
            return {"error": "SHAP explainer not initialized"}
        
        # Compute SHAP values
        shap_values = self.shap_explainer.shap_values(X)
        
        # For multi-class, get values for predicted class
        if isinstance(shap_values, list):
            shap_vals = shap_values[prediction][0]
        elif isinstance(shap_values, np.ndarray) and shap_values.ndim == 3:
            # Shape: (n_outputs, n_samples, n_features) or (n_samples, n_features, n_outputs)
            shap_vals = shap_values[prediction][0]
        else:
            shap_vals = shap_values[0]
        
        # Ensure shap_vals is a flat 1D array of scalars
        shap_vals = np.array(shap_vals).flatten()
        
        # Get top contributing features
        feature_contributions = list(zip(
            self.feature_names,
            shap_vals,
            features.values
        ))
        feature_contributions.sort(key=lambda x: float(abs(x[1])), reverse=True)
        
        return {
            'top_features': feature_contributions[:10],
            'base_value': self.shap_explainer.expected_value[prediction] if isinstance(self.shap_explainer.expected_value, list) else self.shap_explainer.expected_value,
            'shap_values': shap_vals
        }
    
    def _graph_path_explanation(self, policy_id):
        """Extract and explain relevant graph paths"""
        
        explanations = []
        
        # Find entities using this policy
        policy_node = policy_id if policy_id.startswith('policy:') else f'policy:{policy_id}'
        
        if policy_node not in self.graph:
            return explanations
        
        # Get attached entities
        entities = [
            n for n in self.graph.predecessors(policy_node)
            if self.graph.nodes[n].get('type') in ['user', 'role']
        ]
        
        for entity in entities[:3]:  # Limit to first 3
            # Find escalation paths
            paths = self.detector.find_escalation_paths(entity, max_depth=4)
            
            if paths:
                # Get shortest/most risky path
                risky_path = max(paths, key=lambda p: p['risk_score'])
                
                explanations.append({
                    'entity': entity,
                    'path': risky_path['path'],
                    'techniques': risky_path['techniques'],
                    'risk_score': risky_path['risk_score'],
                    'explanation': self._format_path_explanation(risky_path)
                })
        
        return explanations
    
    def _format_path_explanation(self, path_dict):
        """Convert path to human-readable explanation"""
        
        path_nodes = path_dict['path']
        techniques = path_dict['techniques']
        
        explanation = f"Entity {path_nodes[0]} can escalate privileges through:\n"
        
        for i, technique in enumerate(techniques):
            if i < len(path_nodes) - 1:
                explanation += f"  Step {i+1}: Use '{technique}' to reach {path_nodes[i+1]}\n"
        
        explanation += f"\nFinal result: Administrative access achieved in {len(path_nodes)-1} steps"
        
        return explanation
    
    def _counterfactual_explanation(self, policy_id, features, current_risk):
        """Generate counterfactual: what changes would reduce risk?"""
        
        if current_risk == 0:  # Already low risk
            return {"message": "Policy is already low risk"}
        
        counterfactuals = []
        
        # Strategy 1: Remove escalation paths
        if features['escalation_path_count'] > 0:
            counterfactuals.append({
                'change': 'Remove privilege escalation permissions',
                'specific_actions': [
                    'Remove iam:CreatePolicyVersion',
                    'Remove iam:AttachUserPolicy',
                    'Remove iam:PutUserPolicy'
                ],
                'impact': 'Risk drops to LOW or MEDIUM'
            })
        
        # Strategy 2: Remove wildcards
        if features['has_wildcard_action'] == 1:
            counterfactuals.append({
                'change': 'Replace wildcard (*) with specific actions',
                'specific_actions': [
                    'Change Action: "*" to specific actions like ["s3:GetObject", "s3:PutObject"]'
                ],
                'impact': 'Reduces risk by limiting scope'
            })
        
        # Strategy 3: Add MFA
        if features['requires_mfa'] == 0 and features['dangerous_action_count'] > 2:
            counterfactuals.append({
                'change': 'Add MFA requirement',
                'specific_actions': [
                    'Add Condition: {"Bool": {"aws:MultiFactorAuthPresent": "true"}}'
                ],
                'impact': 'Adds protection layer'
            })
        
        # Strategy 4: Restrict resources
        if features['has_wildcard_resource'] == 1:
            counterfactuals.append({
                'change': 'Specify exact resource ARNs',
                'specific_actions': [
                    'Change Resource: "*" to specific ARNs'
                ],
                'impact': 'Limits blast radius'
            })
        
        # Compute minimal change set
        if counterfactuals:
            counterfactuals = self._prioritize_counterfactuals(counterfactuals, features)
        
        return counterfactuals
    
    def _prioritize_counterfactuals(self, counterfactuals, features):
        """Rank counterfactuals by effectiveness"""
        
        # Simple heuristic: escalation removal is highest priority
        priority_order = [
            'Remove privilege escalation permissions',
            'Replace wildcard (*) with specific actions',
            'Specify exact resource ARNs',
            'Add MFA requirement'
        ]
        
        sorted_cf = []
        for priority_change in priority_order:
            for cf in counterfactuals:
                if cf['change'] == priority_change:
                    sorted_cf.append(cf)
        
        return sorted_cf
    
    def generate_report(self, explanation, policy_id):
        """Generate human-readable explanation report"""
        
        report = []
        report.append("=" * 70)
        report.append(f"IAM POLICY RISK ANALYSIS: {policy_id}")
        report.append("=" * 70)
        
        # Prediction
        report.append(f"\nRISK LEVEL: {explanation['risk_label']}")
        report.append(f"Confidence: {explanation['probabilities'][explanation['prediction']]:.2%}")
        report.append("\nProbability Distribution:")
        probs = explanation['probabilities']
        n_classes = len(probs)

        if n_classes >= 3:
            report.append(f"  Low Risk:    {probs[0]:.2%}")
            report.append(f"  Medium Risk: {probs[1]:.2%}")
            report.append(f"  High Risk:   {probs[2]:.2%}")
        else:
            report.append(f"  Low Risk:    {probs[0]:.2%}")
            if n_classes > 1:
                report.append(f"  Medium Risk: {probs[1]:.2%}")
            report.append("  High Risk:   N/A (not predicted)")

        
        # SHAP explanation
        report.append("\n" + "-" * 70)
        report.append("KEY RISK FACTORS (SHAP Analysis)")
        report.append("-" * 70)
        
        for i, (feature, shap_val, feature_val) in enumerate(explanation['shap']['top_features'][:5]):
            shap_val = float(shap_val)
            feature_val = float(feature_val)
            direction = "increases" if shap_val > 0 else "decreases"
            report.append(f"\n{i+1}. {feature} = {feature_val:.2f}")
            report.append(f"   Impact: {direction} risk by {abs(shap_val):.4f}")
        
        # Graph paths
        if explanation['graph_paths']:
            report.append("\n" + "-" * 70)
            report.append("PRIVILEGE ESCALATION PATHS")
            report.append("-" * 70)
            
            for i, path_exp in enumerate(explanation['graph_paths']):
                report.append(f"\nPath {i+1}:")
                report.append(path_exp['explanation'])
        
        # Counterfactuals
        cf_data = explanation['counterfactuals']
        if isinstance(cf_data, dict) and 'message' in cf_data:
            report.append("\n" + "-" * 70)
            report.append("REMEDIATION")
            report.append("-" * 70)
            report.append(f"\n{cf_data['message']}")
        elif isinstance(cf_data, list) and cf_data:
            report.append("\n" + "-" * 70)
            report.append("RECOMMENDED REMEDIATION")
            report.append("-" * 70)
            
            for i, cf in enumerate(cf_data):
                report.append(f"\n{i+1}. {cf['change']}")
                report.append(f"   Impact: {cf['impact']}")
                report.append("   Specific actions:")
                for action in cf['specific_actions']:
                    report.append(f"     - {action}")
        
        report.append("\n" + "=" * 70)
        
        return "\n".join(report)

# Usage
if __name__ == "__main__":
     # Load Random Forest (SHAP-compatible)
    with open('models/rf_clean.pkl', 'rb') as f:
        model = pickle.load(f)
    
    # Load data
    df = pd.read_csv('data/labeled_features.csv')
    
    # Load graph
    import os, pickle

    BASE_DIR = os.path.dirname(os.path.dirname(__file__))
    GRAPH_PATH = os.path.join(BASE_DIR, "data", "iam_graph.pkl")

    with open(GRAPH_PATH, "rb") as f:
        graph = pickle.load(f)
    
    # Load detector
    from escalation_patterns import EscalationDetector
    detector = EscalationDetector(graph)
    
    # Prepare feature names
    drop_cols = ['policy_id', 'risk_label', 'prob_low', 'prob_medium', 'prob_high']
    feature_names = [c for c in df.columns if c not in drop_cols]
    
    X = df.drop(columns=drop_cols)
    
    # Create explainer
    explainer = IAMExplainer(model, feature_names, graph, detector)
    
    # Initialize SHAP (use sample for background)
    explainer.initialize_shap(X.sample(n=min(100, len(X))))
    
    # NEW (fallback to medium-risk):
    high_risk_policies = df[df['risk_label'] == 2]

    if len(high_risk_policies) > 0:
        sample_policy = high_risk_policies.iloc[0]
        print("Analyzing HIGH RISK policy...")
    else:
        # Fallback to medium risk
        medium_risk_policies = df[df['risk_label'] == 1]
        if len(medium_risk_policies) > 0:
            sample_policy = medium_risk_policies.iloc[0]
            print("Analyzing MEDIUM RISK policy (no high-risk found)...")
        else:
            # Fallback to any policy with highest out_degree
            sample_policy = df.nlargest(1, 'out_degree').iloc[0]
            print("Analyzing highest connectivity policy...")

    policy_id = sample_policy['policy_id']
    features = pd.Series(sample_policy[feature_names].values, index=feature_names)

    print("\nGenerating explanation...")
    explanation = explainer.explain_prediction(policy_id, features)

    # Generate report
    report = explainer.generate_report(explanation, policy_id)
    print(report)

    # Save report
    import os
    os.makedirs('output', exist_ok=True)
    with open('output/example_explanation.txt', 'w') as f:
        f.write(report)

    print("\nExplanation saved to output/example_explanation.txt")