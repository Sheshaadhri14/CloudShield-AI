# graph_builder.py — CloudShield AI (EXPANDED VERSION)
# Now loads: AWS managed policies + realworld_policies + synthetic_policies
import pickle, os, json
import networkx as nx
from pathlib import Path
from typing import List
from policy_parser import IAMPolicy
from graph_schema import NodeType, EdgeType, GraphNode, GraphEdge

class IAMGraphBuilder:
    """Construct graph from parsed IAM policies"""
    
    def __init__(self):
        self.graph = nx.MultiDiGraph()  # Directed graph with multiple edges
        self.node_counter = 0
        
    def add_node(self, node_id: str, node_type: NodeType, **attributes):
        """Add node with attributes"""
        self.graph.add_node(
            node_id,
            type=node_type.value,
            **attributes
        )
        
    def add_edge(self, source: str, target: str, edge_type: EdgeType, **attributes):
        """Add directed edge"""
        self.graph.add_edge(
            source,
            target,
            type=edge_type.value,
            **attributes
        )
        
    def build_from_policies(self, policies: List[IAMPolicy]):
        """
        Main graph construction algorithm.
        Stores risk_label, conditions, and attached_to on policy nodes
        for downstream contextual feature extraction.
        """
        service_nodes = set()

        for policy in policies:
            policy_node_id = f"policy:{policy.policy_name}"

            # Collect all conditions across statements via DEEP MERGE
            # (dict.update overwrites operator dicts — must merge per operator)
            all_conditions: dict = {}
            for stmt in policy.statements:
                if stmt.conditions:
                    for operator, kvs in stmt.conditions.items():
                        if operator not in all_conditions:
                            all_conditions[operator] = {}
                        if isinstance(kvs, dict):
                            all_conditions[operator].update(kvs)

            # Derive risk_context by scanning ACTUAL condition keys inside
            # each operator dict — NOT the operator names themselves
            all_cond_keys_lc = set()
            for _op, kvs in all_conditions.items():
                if isinstance(kvs, dict):
                    for k in kvs:
                        all_cond_keys_lc.add(k.lower())

            _MFA_KEYS  = {"aws:multifactorauthpresent", "aws:multifactorauthage"}
            _IP_KEYS   = {"aws:sourceip", "aws:vpcsourceip", "aws:sourcevpc", "aws:sourcevpce"}
            _TIME_KEYS = {"aws:currenttime", "aws:epochtime"}
            _ORG_KEYS  = {"aws:principalorgid", "aws:principalorgpaths", "aws:resourceorgid"}

            risk_ctx = {
                'has_mfa':  bool(all_cond_keys_lc & _MFA_KEYS),
                'has_ip':   bool(all_cond_keys_lc & _IP_KEYS),
                'has_time': bool(all_cond_keys_lc & _TIME_KEYS),
                'has_org':  bool(all_cond_keys_lc & _ORG_KEYS),
            }

            self.add_node(
                policy_node_id,
                NodeType.POLICY,
                name=policy.policy_name,
                statement_count=len(policy.statements),
                conditions=all_conditions,
                risk_context=risk_ctx,
                attached_to=policy.attached_to,
                # known ground-truth label (set by parser for synthetic/realworld)
                risk_label=getattr(policy, 'risk_label', None),
            )
            
            # Process each statement
            for stmt in policy.statements:
                # Extract services from actions
                for action in stmt.actions:
                    if action == "*":
                        # Wildcard - add edge to special "all_services" node
                        service = "all_services"
                    else:
                        # Extract service (e.g., "iam:CreateUser" → "iam")
                        service = action.split(':')[0]
                    
                    service_node_id = f"service:{service}"
                    
                    if service_node_id not in service_nodes:
                        self.add_node(
                            service_node_id,
                            NodeType.SERVICE,
                            name=service
                        )
                        service_nodes.add(service_node_id)
                    
                    # Add edge: Policy → Service (with conditions stored)
                    self.add_edge(
                        policy_node_id,
                        service_node_id,
                        EdgeType.GRANTS_ACCESS,
                        actions=stmt.actions,
                        effect=stmt.effect,
                        conditions=stmt.conditions or {},
                        has_wildcard=(action == "*")
                    )
                    
                # Process resources
                for resource in stmt.resources:
                    resource_node_id = f"resource:{resource}"
                    self.add_node(
                        resource_node_id,
                        NodeType.RESOURCE,
                        arn=resource,
                        is_wildcard=(resource == "*")
                    )
                    
                    self.add_edge(
                        policy_node_id,
                        resource_node_id,
                        EdgeType.ACTS_ON
                    )
                    
                # Process principals (for trust policies)
                if stmt.principals:
                    principal_type = list(stmt.principals.keys())[0]
                    principal_values = stmt.principals[principal_type]
                    
                    if not isinstance(principal_values, list):
                        principal_values = [principal_values]
                    
                    for principal in principal_values:
                        # Parse principal (could be ARN, service, account ID)
                        principal_node_id = f"principal:{principal}"
                        
                        # Determine node type
                        if "role" in principal.lower():
                            node_type = NodeType.ROLE
                        elif "user" in principal.lower():
                            node_type = NodeType.USER
                        else:
                            node_type = NodeType.SERVICE
                            
                        self.add_node(
                            principal_node_id,
                            node_type,
                            identifier=principal
                        )
                        
                        # Trust relationship edge
                        self.add_edge(
                            principal_node_id,
                            policy_node_id,
                            EdgeType.TRUST_RELATIONSHIP,
                            effect=stmt.effect
                        )
            
            # Link policy to attached entities
            for entity in policy.attached_to:
                entity_node_id = f"entity:{entity}"
                
                # Infer entity type from name
                if "role" in entity.lower():
                    entity_type = NodeType.ROLE
                elif "group" in entity.lower():
                    entity_type = NodeType.GROUP
                else:
                    entity_type = NodeType.USER
                    
                self.add_node(
                    entity_node_id,
                    entity_type,
                    name=entity
                )
                
                self.add_edge(
                    entity_node_id,
                    policy_node_id,
                    EdgeType.ATTACHED_POLICY
                )
        
        return self.graph
    
    def save_graph(self, filename: str):
        # Ensure directory exists
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "wb") as f:
            pickle.dump(self.graph, f)

    def load_graph(self, filename: str):
        """Load graph from disk using pickle"""
        with open(filename, "rb") as f:
            self.graph = pickle.load(f)
        return self.graph
    
    def get_statistics(self):
        """Print graph statistics"""
        print(f"Nodes: {self.graph.number_of_nodes()}")
        print(f"Edges: {self.graph.number_of_edges()}")
        
        # Count by node type
        node_types = {}
        for node, data in self.graph.nodes(data=True):
            ntype = data.get('type', 'unknown')
            node_types[ntype] = node_types.get(ntype, 0) + 1
            
        print("Node types:")
        for ntype, count in node_types.items():
            print(f"  {ntype}: {count}")

# ── Main entry-point: build full expanded graph from all 3 directories ──────
if __name__ == "__main__":
    from policy_parser import PolicyParser

    BASE_DIR   = Path(__file__).resolve().parents[1]
    GRAPH_PATH = BASE_DIR / "data" / "iam_graph.pkl"

    parser = PolicyParser()

    # 1. AWS managed policies (original corpus)
    managed_dir = BASE_DIR / "data" / "aws-iam-managed-policies" / "data" / "json"
    if managed_dir.exists():
        parser.parse_directory(str(managed_dir))
        print(f"Managed policies loaded: {len(parser.policies)}")

    # 2. Real-world attack policies (realworld_data_fetcher output)
    rw_dir = BASE_DIR / "data" / "realworld_policies"
    if rw_dir.exists():
        parser.parse_directory(str(rw_dir), source_type="realworld")
        print(f"After realworld: {len(parser.policies)}")

    # 3. Synthetic policies (synthetic_dataset_generator output)
    syn_dir = BASE_DIR / "data" / "synthetic_policies"
    if syn_dir.exists():
        parser.parse_directory(str(syn_dir), source_type="synthetic")
        print(f"After synthetic: {len(parser.policies)}")

    builder = IAMGraphBuilder()
    graph   = builder.build_from_policies(parser.policies)
    builder.save_graph(str(GRAPH_PATH))
    builder.get_statistics()
    print(f"Graph saved to {GRAPH_PATH}")