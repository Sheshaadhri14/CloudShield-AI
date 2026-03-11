# policy_parser.py — CloudShield AI (EXPANDED VERSION)
# Handles 3 source formats:
#   1. Plain AWS managed policy JSON  {Version, Statement}
#   2. Real-world policy JSON         (flat, + realworld_metadata.json sidecar)
#   3. Synthetic policy JSON          {policy: {Version, Statement}, metadata: {...}}
import json, os, glob
from typing import List, Dict, Optional
from dataclasses import dataclass, field

@dataclass
class PolicyStatement:
    effect:     str
    actions:    List[str]
    resources:  List[str]
    conditions: Optional[Dict] = None
    principals: Optional[Dict] = None

@dataclass
class IAMPolicy:
    policy_id:   str
    policy_name: str
    statements:  List[PolicyStatement]
    policy_type: str
    attached_to: List[str]
    risk_label:  Optional[int] = None    # ground-truth label for synthetic/RW policies

class PolicyParser:
    """Parse AWS IAM policy JSON into structured format"""
    
    def __init__(self):
        self.policies = []
        
    def parse_policy_document(self, policy_json: dict, policy_metadata: dict) -> IAMPolicy:
        """
        Parse a single IAM policy document
        
        Args:
            policy_json: The policy document JSON
            policy_metadata: Metadata (name, attached entities, etc.)
        """
        statements = []
        
        # Handle both single statement and array
        stmt_list = policy_json.get('Statement', [])
        if not isinstance(stmt_list, list):
            stmt_list = [stmt_list]
            
        for stmt in stmt_list:
            # Parse actions
            actions = stmt.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
                
            # Parse resources
            resources = stmt.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]
                
            # Parse conditions
            conditions = stmt.get('Condition')
            
            # Parse principals (for trust policies)
            principals = stmt.get('Principal')
            
            statement = PolicyStatement(
                effect=stmt.get('Effect', 'Allow'),
                actions=actions,
                resources=resources,
                conditions=conditions,
                principals=principals
            )
            statements.append(statement)
            
        return IAMPolicy(
            policy_id=policy_metadata.get('policy_id'),
            policy_name=policy_metadata.get('policy_name'),
            statements=statements,
            policy_type=policy_metadata.get('policy_type', 'identity-based'),
            attached_to=policy_metadata.get('attached_to', [])
        )
    
    def parse_directory(self, directory: str,
                        source_type: str = "managed") -> List['IAMPolicy']:
        """Parse all policies in a directory.

        Args:
            directory:   Path to directory of JSON policy files.
            source_type: 'managed' | 'realworld' | 'synthetic'
        """
        # Load sidecar metadata for real-world policies (risk labels)
        rw_meta: Dict[str, dict] = {}
        if source_type == "realworld":
            meta_path = os.path.join(os.path.dirname(directory),
                                     "realworld_metadata.json")
            if os.path.exists(meta_path):
                with open(meta_path) as mf:
                    for m in json.load(mf):
                        stem = os.path.splitext(os.path.basename(m.get('file','')))[0]
                        rw_meta[stem] = m

        policy_files = glob.glob(os.path.join(directory, "**", "*.json"),
                                 recursive=True)

        for policy_file in policy_files:
            try:
                with open(policy_file, 'r', encoding='utf-8') as f:
                    raw = json.load(f)

                stem = os.path.splitext(os.path.basename(policy_file))[0]

                # ── Detect format ──────────────────────────────────────────
                if source_type == "synthetic" and isinstance(raw, dict) and "policy" in raw:
                    # Format 3: {policy: {...}, metadata: {...}}
                    policy_doc  = raw["policy"]
                    meta        = raw.get("metadata", {})
                    attached_to = meta.get("attached_to", [])
                    risk_label  = meta.get("risk_label")

                elif source_type == "realworld":
                    # Format 2: flat IAM doc; risk from sidecar
                    policy_doc  = raw
                    meta        = rw_meta.get(stem, {})
                    attached_to = meta.get("attached_to", [])
                    risk_label  = meta.get("risk_label")

                else:
                    # Format 1: plain managed policy JSON
                    policy_doc  = raw
                    attached_to = []
                    risk_label  = None

                if not isinstance(policy_doc, dict) or "Statement" not in policy_doc:
                    continue

                metadata = {
                    'policy_id':   policy_file,
                    'policy_name': stem,
                    'attached_to': attached_to,
                    'risk_label':  risk_label,
                }
                policy = self.parse_policy_document(policy_doc, metadata)
                self.policies.append(policy)

            except Exception as e:
                print(f"Error parsing {policy_file}: {e}")

        return self.policies


# ── Convenience parse for a single doc dict (used by graph_builder) ───────
if __name__ == "__main__":
    from pathlib import Path
    BASE_DIR     = Path(__file__).resolve().parents[1]
    MANAGED_DIR  = BASE_DIR / "data" / "aws-iam-managed-policies" / "data" / "json"
    RW_DIR       = BASE_DIR / "data" / "realworld_policies"
    SYN_DIR      = BASE_DIR / "data" / "synthetic_policies"

    parser = PolicyParser()
    if MANAGED_DIR.exists():
        parser.parse_directory(str(MANAGED_DIR), source_type="managed")
    if RW_DIR.exists():
        parser.parse_directory(str(RW_DIR),      source_type="realworld")
    if SYN_DIR.exists():
        parser.parse_directory(str(SYN_DIR),     source_type="synthetic")

    print(f"Total parsed: {len(parser.policies)}")
    labelled = sum(1 for p in parser.policies if p.risk_label is not None)
    print(f"  With risk label: {labelled}")
    print(f"  Without label:   {len(parser.policies)-labelled}")