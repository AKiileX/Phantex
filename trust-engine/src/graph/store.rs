// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

use std::sync::Arc;

use dashmap::DashMap;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::edge::{EdgeType, Severity, TrustEdge};
use super::node::{NodeKey, NodeType, TrustNode};

/// Thread-safe, tenant-isolated in-memory trust graph.
///
/// Design:
/// - `DashMap<NodeKey, NodeIndex>` gives O(1) lock-free lookups from
///   `(tenant_id, entity_id)` → petgraph node index.
/// - `petgraph::DiGraph<TrustNode, TrustEdge>` stores the actual graph
///   topology behind a `RwLock` so that readers run concurrently while
///   mutations are serialised.
pub struct TrustGraphStore {
    /// Maps `NodeKey` → petgraph `NodeIndex` for O(1) lookups.
    pub(crate) index: DashMap<NodeKey, NodeIndex>,

    /// The underlying directed graph (nodes + edges).
    pub(crate) graph: RwLock<DiGraph<TrustNode, TrustEdge>>,

    /// Set of known tenant IDs (for health-check reporting).
    tenants: DashMap<Uuid, ()>,
}

impl TrustGraphStore {
    /// Create a new empty graph with the given initial capacity hint.
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            index: DashMap::with_capacity(capacity),
            graph: RwLock::new(DiGraph::with_capacity(capacity, capacity * 5)),
            tenants: DashMap::new(),
        })
    }

    // ── Node operations ─────────────────────────────────────────────

    /// Get or create a node.  Returns the petgraph `NodeIndex`.
    ///
    /// Uses double-checked locking to prevent TOCTOU races where concurrent
    /// calls could insert duplicate nodes for the same key.
    pub async fn ensure_node(
        &self,
        tenant_id: Uuid,
        entity_id: &str,
        node_type: NodeType,
    ) -> NodeIndex {
        let key = NodeKey::new(tenant_id, entity_id);

        // Fast path: node already exists (lock-free DashMap read).
        if let Some(idx) = self.index.get(&key) {
            return *idx;
        }

        // Slow path: acquire graph write lock, then re-check.
        let node = TrustNode::new(key.clone(), node_type);
        let mut g = self.graph.write().await;

        // Re-check under write lock to prevent duplicate insertion.
        if let Some(idx) = self.index.get(&key) {
            return *idx;
        }

        let idx = g.add_node(node);
        self.index.insert(key, idx);
        self.tenants.entry(tenant_id).or_insert(());
        idx
    }

    /// Retrieve a cloned copy of a node by its key.
    pub async fn get_node(&self, tenant_id: Uuid, entity_id: &str) -> Option<TrustNode> {
        let key = NodeKey::new(tenant_id, entity_id);
        let idx = *self.index.get(&key)?;
        let g = self.graph.read().await;
        g.node_weight(idx).cloned()
    }

    /// Update a node's trust score (and sub-factors) in place.
    pub async fn update_node<F>(&self, key: &NodeKey, f: F) -> bool
    where
        F: FnOnce(&mut TrustNode),
    {
        if let Some(idx) = self.index.get(key) {
            let mut g = self.graph.write().await;
            if let Some(node) = g.node_weight_mut(*idx) {
                f(node);
                return true;
            }
        }
        false
    }

    /// Iterate over all node indices for a given tenant.
    pub async fn tenant_node_indices(&self, tenant_id: Uuid) -> Vec<NodeIndex> {
        let g = self.graph.read().await;
        self.index
            .iter()
            .filter(|entry| entry.key().tenant_id == tenant_id)
            .filter_map(|entry| {
                let idx = *entry.value();
                // Verify node still exists in graph.
                g.node_weight(idx).map(|_| idx)
            })
            .collect()
    }

    /// Return all node indices in the graph (all tenants).
    pub async fn all_node_indices(&self) -> Vec<NodeIndex> {
        let g = self.graph.read().await;
        g.node_indices().collect()
    }

    // ── Edge operations ─────────────────────────────────────────────

    /// Record an event between two nodes. Creates or updates the edge.
    pub async fn record_event(
        &self,
        source: NodeIndex,
        target: NodeIndex,
        edge_type: EdgeType,
        severity: Severity,
        bytes: u64,
    ) {
        let mut g = self.graph.write().await;

        // Look for an existing edge of the same type.
        if let Some(edge_idx) = g
            .edges_connecting(source, target)
            .find(|e| e.weight().edge_type == edge_type)
            .map(|e| e.id())
        {
            if let Some(edge) = g.edge_weight_mut(edge_idx) {
                edge.record_event(severity, bytes);
            }
        } else {
            let mut edge = TrustEdge::new(edge_type, severity);
            edge.bytes_total = bytes;
            g.add_edge(source, target, edge);
        }
    }

    // ── Read-lock graph access ──────────────────────────────────────

    /// Execute a read-only closure on the underlying graph.
    pub async fn read<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&DiGraph<TrustNode, TrustEdge>) -> R,
    {
        let g = self.graph.read().await;
        f(&g)
    }

    /// Execute a write closure on the underlying graph.
    pub async fn write<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut DiGraph<TrustNode, TrustEdge>) -> R,
    {
        let mut g = self.graph.write().await;
        f(&mut g)
    }

    // ── Stats / health ──────────────────────────────────────────────

    pub async fn node_count(&self) -> usize {
        let g = self.graph.read().await;
        g.node_count()
    }

    pub async fn edge_count(&self) -> usize {
        let g = self.graph.read().await;
        g.edge_count()
    }

    pub fn tenant_count(&self) -> usize {
        self.tenants.len()
    }

    /// Serialise the whole graph (for snapshots).
    pub async fn serialise(&self) -> (Vec<TrustNode>, Vec<(usize, usize, TrustEdge)>) {
        let g = self.graph.read().await;
        let nodes: Vec<TrustNode> = g.node_indices().filter_map(|i| g.node_weight(i).cloned()).collect();
        let edges: Vec<(usize, usize, TrustEdge)> = g
            .edge_indices()
            .filter_map(|e| {
                let (s, t) = g.edge_endpoints(e)?;
                let w = g.edge_weight(e)?.clone();
                Some((s.index(), t.index(), w))
            })
            .collect();
        (nodes, edges)
    }

    /// Restore from serialised data.
    pub async fn restore(&self, nodes: Vec<TrustNode>, edges: Vec<(usize, usize, TrustEdge)>) {
        let mut g = self.graph.write().await;
        g.clear();
        self.index.clear();
        self.tenants.clear();

        let mut idx_map = Vec::with_capacity(nodes.len());
        for node in nodes {
            let key = node.key.clone();
            let tenant_id = key.tenant_id;
            let idx = g.add_node(node);
            self.index.insert(key, idx);
            self.tenants.entry(tenant_id).or_insert(());
            idx_map.push(idx);
        }

        for (s, t, edge) in edges {
            if s < idx_map.len() && t < idx_map.len() {
                g.add_edge(idx_map[s], idx_map[t], edge);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ensure_node_creates_once() {
        let store = TrustGraphStore::new(16);
        let tid = Uuid::new_v4();
        let idx1 = store.ensure_node(tid, "agent-1", NodeType::Agent).await;
        let idx2 = store.ensure_node(tid, "agent-1", NodeType::Agent).await;
        assert_eq!(idx1, idx2);
        assert_eq!(store.node_count().await, 1);
    }

    #[tokio::test]
    async fn test_get_node() {
        let store = TrustGraphStore::new(16);
        let tid = Uuid::new_v4();
        store.ensure_node(tid, "agent-1", NodeType::Agent).await;

        let node = store.get_node(tid, "agent-1").await.unwrap();
        assert_eq!(node.trust_score, 0.5);
        assert_eq!(node.node_type, NodeType::Agent);
    }

    #[tokio::test]
    async fn test_tenant_isolation() {
        let store = TrustGraphStore::new(16);
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();

        store.ensure_node(t1, "agent-1", NodeType::Agent).await;
        store.ensure_node(t2, "agent-1", NodeType::Agent).await;

        // Same entity_id but different tenants → two separate nodes.
        assert_eq!(store.node_count().await, 2);
        assert_eq!(store.tenant_count(), 2);

        // Tenant 1 cannot see tenant 2's nodes.
        let t1_nodes = store.tenant_node_indices(t1).await;
        assert_eq!(t1_nodes.len(), 1);
    }

    #[tokio::test]
    async fn test_record_event_creates_edge() {
        let store = TrustGraphStore::new(16);
        let tid = Uuid::new_v4();
        let src = store.ensure_node(tid, "agent-1", NodeType::Agent).await;
        let tgt = store.ensure_node(tid, "tool-a", NodeType::Tool).await;

        store
            .record_event(src, tgt, EdgeType::Uses, Severity::Low, 0)
            .await;

        assert_eq!(store.edge_count().await, 1);
    }

    #[tokio::test]
    async fn test_record_event_updates_existing_edge() {
        let store = TrustGraphStore::new(16);
        let tid = Uuid::new_v4();
        let src = store.ensure_node(tid, "agent-1", NodeType::Agent).await;
        let tgt = store.ensure_node(tid, "tool-a", NodeType::Tool).await;

        store
            .record_event(src, tgt, EdgeType::Uses, Severity::Low, 0)
            .await;
        store
            .record_event(src, tgt, EdgeType::Uses, Severity::Medium, 512)
            .await;

        // Still just one edge.
        assert_eq!(store.edge_count().await, 1);

        // But count should be 2.
        let edge_count = store
            .read(|g| {
                g.edge_indices()
                    .next()
                    .and_then(|e| g.edge_weight(e).map(|w| w.count))
            })
            .await;
        assert_eq!(edge_count, Some(2));
    }

    #[tokio::test]
    async fn test_update_node() {
        let store = TrustGraphStore::new(16);
        let tid = Uuid::new_v4();
        store.ensure_node(tid, "agent-1", NodeType::Agent).await;
        let key = NodeKey::new(tid, "agent-1");

        let ok = store
            .update_node(&key, |n| n.trust_score = 0.8)
            .await;
        assert!(ok);

        let node = store.get_node(tid, "agent-1").await.unwrap();
        assert!((node.trust_score - 0.8).abs() < 1e-10);
    }

    #[tokio::test]
    async fn test_serialise_restore() {
        let store = TrustGraphStore::new(16);
        let tid = Uuid::new_v4();
        let src = store.ensure_node(tid, "agent-1", NodeType::Agent).await;
        let tgt = store.ensure_node(tid, "tool-a", NodeType::Tool).await;
        store
            .record_event(src, tgt, EdgeType::Uses, Severity::Low, 0)
            .await;

        let (nodes, edges) = store.serialise().await;
        assert_eq!(nodes.len(), 2);
        assert_eq!(edges.len(), 1);

        // Restore into a fresh store.
        let store2 = TrustGraphStore::new(16);
        store2.restore(nodes, edges).await;
        assert_eq!(store2.node_count().await, 2);
        assert_eq!(store2.edge_count().await, 1);
    }
}
