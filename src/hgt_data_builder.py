# hgt_data_builder.py — CloudShield AI
# Converts the NetworkX IAM graph to PyTorch Geometric HeteroData
# for training the Heterogeneous Graph Transformer (HGT)
import pickle, os
import numpy as np
import pandas as pd
import torch
from torch_geometric.data import HeteroData
from torch_geometric.transforms import ToUndirected
from pathlib import Path
from sklearn.model_selection import StratifiedKFold

BASE_DIR = Path(__file__).resolve().parents[1]

# ── Node-type and edge-type mappings ──────────────────────────────────────────
NODE_TYPE_MAP = {
    'policy':   0,
    'service':  1,
    'resource': 2,
    'user':     3,
    'role':     4,
    'group':    5,
}

EDGE_TYPE_MAP = {
    'grants_access':     0,
    'acts_on':           1,
    'attached_policy':   2,
    'trust':             3,
    'assume_role':       4,
    'member_of':         5,
}

# Feature columns extracted from graph_features.csv
FEATURE_COLS = [
    'out_degree', 'in_degree', 'betweenness_centrality', 'pagerank',
    'attachment_count', 'service_count', 'avg_path_to_sensitive',
    'min_path_to_sensitive', 'has_wildcard_action', 'service_wildcard_count',
    'wildcard_entropy', 'dangerous_action_count', 'resource_count',
    'has_wildcard_resource', 'specificity_score', 'escalation_techniques_enabled',
    'escalation_path_count', 'min_escalation_path_length', 'max_escalation_risk',
    'requires_mfa', 'has_ip_restriction', 'has_time_restriction',
    'has_org_restriction',
]


class HGTDataBuilder:
    """Build PyTorch Geometric HeteroData from NetworkX IAM graph."""

    def __init__(self, graph, features_df: pd.DataFrame, labels_df: pd.DataFrame):
        self.nx_graph = graph
        self.features_df = features_df
        self.labels_df = labels_df

    # ── public API ────────────────────────────────────────────────────────────
    def build(self, n_folds: int = 5, seed: int = 42) -> HeteroData:
        """Convert NetworkX graph to HeteroData with train/val/test masks."""
        data = HeteroData()

        # 1. Build node features per type
        node_id_maps = {}   # {type_str: {nx_id: int_index}}
        for ntype_str in NODE_TYPE_MAP:
            nids = [n for n, d in self.nx_graph.nodes(data=True)
                    if d.get('type') == ntype_str]
            node_id_maps[ntype_str] = {nid: i for i, nid in enumerate(nids)}

            if ntype_str == 'policy':
                x = self._policy_features(nids)
            else:
                x = self._generic_features(nids, dim=len(FEATURE_COLS))

            data[ntype_str].x = x
            data[ntype_str].num_nodes = len(nids)

        # 2. Build edges per type
        for etype_str in EDGE_TYPE_MAP:
            src_idx, dst_idx, src_type, dst_type = [], [], None, None
            for u, v, edata in self.nx_graph.edges(data=True):
                if edata.get('type') != etype_str:
                    continue
                u_type = self.nx_graph.nodes[u].get('type', 'policy')
                v_type = self.nx_graph.nodes[v].get('type', 'policy')
                if u_type not in node_id_maps or v_type not in node_id_maps:
                    continue
                if u not in node_id_maps[u_type] or v not in node_id_maps[v_type]:
                    continue
                src_idx.append(node_id_maps[u_type][u])
                dst_idx.append(node_id_maps[v_type][v])
                src_type, dst_type = u_type, v_type

            if src_idx and src_type and dst_type:
                edge_index = torch.tensor([src_idx, dst_idx], dtype=torch.long)
                data[src_type, etype_str, dst_type].edge_index = edge_index

        # 3. Build labels and masks for policy nodes
        data = self._add_labels_and_masks(data, node_id_maps['policy'], n_folds, seed)

        return data

    # ── private helpers ───────────────────────────────────────────────────────
    def _policy_features(self, nids: list) -> torch.Tensor:
        """Feature vectors for policy nodes from the features CSV."""
        feat_lookup = {}
        if 'policy_id' in self.features_df.columns:
            for _, row in self.features_df.iterrows():
                pid = row['policy_id']
                # Match either direct ID or policy:name format
                feat_lookup[pid] = row
                name = pid.split('\\')[-1].split('/')[-1] if isinstance(pid, str) else ''
                feat_lookup[f"policy:{name}"] = row

        feats = []
        for nid in nids:
            name = self.nx_graph.nodes[nid].get('name', '')
            row = feat_lookup.get(nid) or feat_lookup.get(f"policy:{name}")
            if row is not None:
                vec = [float(row.get(c, 0.0)) for c in FEATURE_COLS]
            else:
                vec = [0.0] * len(FEATURE_COLS)
            feats.append(vec)

        t = torch.tensor(feats, dtype=torch.float)
        # Normalize per-feature
        mean = t.mean(dim=0, keepdim=True)
        std  = t.std(dim=0, keepdim=True).clamp(min=1e-6)
        return (t - mean) / std

    def _generic_features(self, nids: list, dim: int) -> torch.Tensor:
        """One-hot-like features for non-policy nodes, using degree info."""
        feats = []
        for nid in nids:
            vec = [0.0] * dim
            vec[0] = float(self.nx_graph.out_degree(nid))
            vec[1] = float(self.nx_graph.in_degree(nid))
            feats.append(vec)
        if not feats:
            return torch.zeros(0, dim)
        t = torch.tensor(feats, dtype=torch.float)
        mean = t.mean(dim=0, keepdim=True)
        std  = t.std(dim=0, keepdim=True).clamp(min=1e-6)
        return (t - mean) / std

    def _add_labels_and_masks(self, data: HeteroData, policy_map: dict,
                              n_folds: int, seed: int) -> HeteroData:
        """Add labels + stratified k-fold masks to policy nodes."""
        n_policies = len(policy_map)
        labels = torch.full((n_policies,), -1, dtype=torch.long)

        # Map from labeled_features to policy graph indices
        label_lookup = {}
        if 'policy_id' in self.labels_df.columns:
            for _, row in self.labels_df.iterrows():
                pid = row['policy_id']
                lab = row.get('risk_label', -1)
                if pd.notna(lab) and int(lab) >= 0:
                    label_lookup[pid] = int(lab)
                    name = pid.split('\\')[-1].split('/')[-1] if isinstance(pid, str) else ''
                    label_lookup[f"policy:{name}"] = int(lab)

        # Also try ground-truth from graph node attributes
        for nid, idx in policy_map.items():
            name = self.nx_graph.nodes[nid].get('name', '')
            lab = label_lookup.get(nid) or label_lookup.get(f"policy:{name}")
            if lab is None:
                lab = self.nx_graph.nodes[nid].get('risk_label')
            if lab is not None and int(lab) >= 0:
                labels[idx] = int(lab)

        data['policy'].y = labels

        # Build masks — only for nodes that have labels
        labeled_mask = labels >= 0
        labeled_idx  = labeled_mask.nonzero(as_tuple=True)[0].numpy()
        labeled_y    = labels[labeled_idx].numpy()

        # Stratified K-fold
        train_mask = torch.zeros(n_policies, dtype=torch.bool)
        val_mask   = torch.zeros(n_policies, dtype=torch.bool)
        test_mask  = torch.zeros(n_policies, dtype=torch.bool)

        if len(labeled_idx) > 10:
            skf = StratifiedKFold(n_splits=n_folds, shuffle=True, random_state=seed)
            splits = list(skf.split(labeled_idx, labeled_y))

            # Use fold 0 for train/val, fold 1 for test
            train_idx_fold, test_idx_fold = splits[0]
            # Split train further into train/val (80/20)
            n_train = int(len(train_idx_fold) * 0.8)
            train_idx = labeled_idx[train_idx_fold[:n_train]]
            val_idx   = labeled_idx[train_idx_fold[n_train:]]
            test_idx  = labeled_idx[test_idx_fold]

            train_mask[train_idx] = True
            val_mask[val_idx]     = True
            test_mask[test_idx]   = True

        data['policy'].train_mask = train_mask
        data['policy'].val_mask   = val_mask
        data['policy'].test_mask  = test_mask

        n_labeled = int(labeled_mask.sum())
        n_train   = int(train_mask.sum())
        n_val     = int(val_mask.sum())
        n_test    = int(test_mask.sum())
        print(f"HGT Data: {n_policies} policy nodes, {n_labeled} labeled")
        print(f"  Train: {n_train}  Val: {n_val}  Test: {n_test}")
        print(f"  Label dist: {dict(zip(*torch.unique(labels[labels>=0], return_counts=True)))}")
        return data


def build_hetero_data():
    """Main entry point — build and save HeteroData."""
    graph_path   = BASE_DIR / "data" / "iam_graph.pkl"
    features_csv = BASE_DIR / "data" / "graph_features.csv"
    labels_csv   = BASE_DIR / "data" / "labeled_features.csv"
    output_path  = BASE_DIR / "data" / "hgt_data.pt"

    print("Loading graph...")
    with open(graph_path, "rb") as f:
        graph = pickle.load(f)

    features_df = pd.read_csv(features_csv)
    labels_df   = pd.read_csv(labels_csv)

    builder = HGTDataBuilder(graph, features_df, labels_df)
    data = builder.build()

    torch.save(data, output_path)
    print(f"\nHeteroData saved to {output_path}")
    print(f"Node types: {data.node_types}")
    print(f"Edge types: {data.edge_types}")
    return data


if __name__ == "__main__":
    build_hetero_data()
