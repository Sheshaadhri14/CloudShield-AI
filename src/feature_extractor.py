# feature_extractor.py — CloudShield AI (FULL VERSION)
# Phase 3 fix: real Condition parsing, real attachment_count,
# multi-directory support for realworld + synthetic policies
import networkx as nx
import pandas as pd
import numpy as np
from typing import Dict, List
import os, json
from pathlib import Path
from tqdm import tqdm
from escalation_patterns import EscalationDetector

# ── Condition key sets used for contextual feature extraction ─────────────────
_MFA_KEYS   = {"aws:multifactorauthpresent", "aws:multifactorauthage"}
_IP_KEYS    = {"aws:sourceip", "aws:vpcsourceip", "aws:sourcevpc", "aws:sourcevpce"}
_TIME_KEYS  = {"aws:currenttime", "aws:epochtime"}
_ORG_KEYS   = {"aws:principalorgid", "aws:principalorgpaths", "aws:resourceorgid"}

class GraphFeatureExtractor:
    """Optimized feature extractor for large IAM graphs"""
    
    def __init__(self, graph, escalation_detector):
        self.graph = graph
        self.detector = escalation_detector
        
        # Precompute expensive metrics ONCE
        print("Precomputing expensive graph metrics...")
        self._precompute_global_metrics()
        
    def _precompute_global_metrics(self):
        """Compute expensive metrics once for all nodes"""
        
        # 1. Betweenness centrality (SAMPLE k=10 nodes to make it fast)
        print("Computing sampled betweenness centrality...")
        self.betweenness = nx.betweenness_centrality(
            self.graph, 
            k=100,  # Sample 100 nodes instead of all 7k
            normalized=True
        )
        
        # 2. PageRank (alpha=0.85, fast approximation)
        print("Computing PageRank...")
        self.pagerank = nx.pagerank(self.graph, alpha=0.85, max_iter=50)
        
        # 3. Sensitive services list (precompute once)
        self.sensitive_services = ['iam', 'sts', 'organizations', 'kms', 'lambda']
        
        # 4. Precompute service nodes
        self.service_nodes = {
            n for n, d in self.graph.nodes(data=True)
            if d.get('type') == 'service'
        }
        
        print("Precomputation complete!")
    
    def extract_features_for_policy(self, policy_node_id: str) -> Dict:
        """Fast feature extraction using precomputed metrics"""
        
        features = {}
        
        # === STRUCTURAL FEATURES (FAST) ===
        features.update(self._extract_structural_features(policy_node_id))
        
        # === PERMISSION SEMANTIC FEATURES (FAST) ===
        features.update(self._extract_permission_features(policy_node_id))
        
        # === ESCALATION PATH FEATURES (SKIP OR SAMPLE) ===
        features.update(self._extract_escalation_features_fast(policy_node_id))
        
        # === CONTEXTUAL FEATURES ===
        features.update(self._extract_context_features(policy_node_id))
        
        return features
    
    def _extract_structural_features(self, node_id: str) -> Dict:
        """Structural features using precomputed metrics — attachment_count now real"""
        features = {}

        # Node degrees (O(1))
        features['out_degree'] = self.graph.out_degree(node_id)
        features['in_degree']  = self.graph.in_degree(node_id)

        # Precomputed centrality (O(1))
        features['betweenness_centrality'] = self.betweenness.get(node_id, 0.0)
        features['pagerank']               = self.pagerank.get(node_id, 0.0)

        # Real attachment count — look at in-edges typed 'attached_policy'
        # and predecessors that carry type user|role|group
        attached_entities = [
            n for n in self.graph.predecessors(node_id)
            if self.graph.nodes[n].get('type') in ('user', 'role', 'group', 'entity')
        ]
        # Also check ATTACHED_POLICY edge metadata stored on the policy node itself
        node_meta = self.graph.nodes[node_id]
        stored_attached = node_meta.get('attached_to', [])
        if isinstance(stored_attached, (list, tuple)):
            features['attachment_count'] = max(len(attached_entities), len(stored_attached))
        else:
            features['attachment_count'] = len(attached_entities)

        # Service breadth
        services = [
            n for n in self.graph.successors(node_id)
            if self.graph.nodes[n].get('type') == 'service'
        ]
        features['service_count'] = len(services)

        # Lightweight sensitive-service proximity via successor check
        sensitive_svc = {'iam', 'sts', 'organizations', 'kms', 'lambda', 'secretsmanager'}
        direct_sensitive = sum(
            1 for n in self.graph.successors(node_id)
            if self.graph.nodes[n].get('name', '') in sensitive_svc
        )
        features['avg_path_to_sensitive'] = 1.0 if direct_sensitive > 0 else 2.0
        features['min_path_to_sensitive'] = 1.0 if direct_sensitive > 0 else 999.0

        return features
    
    def _extract_permission_features(self, node_id: str) -> Dict:
        """Semantic features from edges"""
        
        features = {}
        
        # Collect all actions (fast iteration)
        actions = set()
        for neighbor in self.graph.successors(node_id):
            edge_data = self.graph.get_edge_data(node_id, neighbor)
            for key, data in edge_data.items():
                if data.get('type') == 'grants_access':
                    actions.update(data.get('actions', []))
        
        # Wildcard analysis
        features['has_wildcard_action'] = 1 if ('*' in actions or '*:*' in actions) else 0
        
        service_wildcards = sum(1 for a in actions if ':*' in a)
        features['service_wildcard_count'] = service_wildcards
        
        total_actions = len(actions)
        wildcard_ratio = service_wildcards / total_actions if total_actions > 0 else 0
        features['wildcard_entropy'] = -wildcard_ratio * np.log2(wildcard_ratio + 1e-10)
        
        # Dangerous actions (fast string matching)
        dangerous_patterns = ['iam:Create', 'iam:Delete', 'iam:Put', 'iam:Attach']
        features['dangerous_action_count'] = sum(
            1 for action in actions 
            for pattern in dangerous_patterns 
            if pattern in action
        )
        
        # Resource count
        resources = [
            n for n in self.graph.successors(node_id)
            if self.graph.nodes[n].get('type') == 'resource'
        ]
        features['resource_count'] = len(resources)
        features['has_wildcard_resource'] = 1 if '*' in resources else 0
        
        features['specificity_score'] = 1.0 / (1.0 + features['wildcard_entropy'])
        
        return features
    
    def _extract_escalation_features_fast(self, node_id: str) -> Dict:
        """Fast approximation of escalation features"""
        
        features = {}
        
        # Sample only first 3 attached entities (not all)
        entities = list(self.graph.predecessors(node_id))
        entities = [n for n in entities[:3] if self.graph.nodes[n].get('type') in ['user', 'role']]
        
        if not entities:
            features['escalation_path_count'] = 0
            features['min_escalation_path_length'] = 999
            features['max_escalation_risk'] = 0.0
            return features
        
        # Fast check for escalation techniques (no path enumeration)
        entity = entities[0]
        techniques_possible = sum(
            1 for tech in list(self.detector.techniques.values())[:5]  # Sample 5 techniques
            if self.detector.check_technique_possible(entity, tech)
        )
        
        features['escalation_techniques_enabled'] = techniques_possible
        features['escalation_path_count'] = 1 if techniques_possible > 0 else 0
        features['min_escalation_path_length'] = 3 if techniques_possible > 0 else 999
        features['max_escalation_risk'] = 0.5 * techniques_possible
        
        return features
    
    def _extract_context_features(self, node_id: str) -> Dict:
        """FIXED: Parse real Condition blocks from grants_access edges.

        Reads Condition dicts stored on graph edges and checks for:
          - aws:MultiFactorAuthPresent / aws:MultiFactorAuthAge  → requires_mfa
          - aws:SourceIp / aws:VpcSourceIp                       → has_ip_restriction
          - aws:CurrentTime / aws:EpochTime                      → has_time_restriction
          - aws:PrincipalOrgID / aws:PrincipalOrgPaths           → has_org_restriction

        Also checks node-level 'conditions' attribute injected by the expanded
        policy parser for synthetic and real-world policies.
        """
        requires_mfa = 0
        has_ip       = 0
        has_time     = 0
        has_org      = 0

        def _scan_condition(cond: dict):
            nonlocal requires_mfa, has_ip, has_time, has_org
            if not cond:
                return
            for _op, kvs in cond.items():
                if not isinstance(kvs, dict):
                    continue
                for key in kvs:
                    key_lc = key.lower()
                    if key_lc in _MFA_KEYS:
                        requires_mfa = 1
                    if key_lc in _IP_KEYS:
                        has_ip = 1
                    if key_lc in _TIME_KEYS:
                        has_time = 1
                    if key_lc in _ORG_KEYS:
                        has_org = 1

        # 1. Scan all outgoing grants_access edges for Condition blocks
        for neighbor in self.graph.successors(node_id):
            edge_data = self.graph.get_edge_data(node_id, neighbor) or {}
            for _, data in edge_data.items():
                if data.get('type') == 'grants_access':
                    _scan_condition(data.get('conditions') or data.get('condition') or {})

        # 2. Check policy node attributes (synthetic policies store conditions there)
        node_data = self.graph.nodes[node_id]
        _scan_condition(node_data.get('conditions', {}))

        # 3. Check node-level 'risk_context' dict from augmented parser
        ctx = node_data.get('risk_context', {})
        if ctx.get('has_mfa'):   requires_mfa = 1
        if ctx.get('has_ip'):    has_ip       = 1
        if ctx.get('has_time'):  has_time     = 1
        if ctx.get('has_org'):   has_org      = 1

        return {
            'requires_mfa':       requires_mfa,
            'has_ip_restriction': has_ip,
            'has_time_restriction': has_time,
            'has_org_restriction':  has_org
        }
    
    def extract_dataset(self, max_policies: int = 10000) -> pd.DataFrame:
        """Extract features for all policy nodes with progress bar.
        Supports the expanded graph that includes realworld + synthetic policies.
        """
        policy_nodes = [
            n for n, d in self.graph.nodes(data=True)
            if d.get('type') == 'policy'
        ][:max_policies]

        features_list = []
        for policy_node in tqdm(policy_nodes, desc="Extracting features"):
            try:
                features = self.extract_features_for_policy(policy_node)
                features['policy_id'] = policy_node
                # Carry known ground-truth label if injected by expanded builder
                node_data = self.graph.nodes[policy_node]
                if 'risk_label' in node_data:
                    features['known_risk_label'] = node_data['risk_label']
                features_list.append(features)
            except Exception as e:
                print(f"Error extracting features for {policy_node}: {e}")

        df = pd.DataFrame(features_list)
        return df


# ── Main entry-point: builds full expanded graph + extracts features ───────────
if __name__ == "__main__":
    import pickle
    from escalation_patterns import EscalationDetector

    BASE_DIR     = Path(__file__).resolve().parents[1]
    GRAPH_PATH   = BASE_DIR / "data" / "iam_graph.pkl"
    FEATURES_OUT = BASE_DIR / "data" / "graph_features.csv"

    with open(GRAPH_PATH, "rb") as f:
        graph = pickle.load(f)

    detector  = EscalationDetector(graph)
    extractor = GraphFeatureExtractor(graph, detector)
    df        = extractor.extract_dataset(max_policies=10000)

    df.to_csv(FEATURES_OUT, index=False)
    print(f"Extracted {len(df)} policy feature vectors")
    print(f"Feature shape: {df.shape}")
    non_zero_ctx = {
        'mfa':  int((df['requires_mfa']        > 0).sum()),
        'ip':   int((df['has_ip_restriction']   > 0).sum()),
        'time': int((df['has_time_restriction'] > 0).sum()),
        'org':  int((df['has_org_restriction']  > 0).sum()),
    }
    print(f"Contextual features coverage: {non_zero_ctx}")
    print(df.describe())
