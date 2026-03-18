// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

use std::sync::Arc;

use petgraph::Direction;
use uuid::Uuid;

use super::edge::TrustEdge;
use super::node::{NodeKey, TrustNode};
use super::store::TrustGraphStore;

/// Neighbourhood result returned by `get_neighbourhood`.
#[derive(Debug, Clone)]
pub struct Neighbourhood {
    pub center: TrustNode,
    pub nodes: Vec<TrustNode>,
    pub edges: Vec<(String, String, TrustEdge)>, // (source_id, target_id, edge)
}

impl TrustGraphStore {
    /// Return the trust score of an entity (or `None` if unknown).
    pub async fn trust_score(&self, tenant_id: Uuid, entity_id: &str) -> Option<f64> {
        self.get_node(tenant_id, entity_id)
            .await
            .map(|n| n.trust_score)
    }

    /// Return the local neighbourhood of an entity up to `depth` hops.
    pub async fn get_neighbourhood(
        self: &Arc<Self>,
        tenant_id: Uuid,
        entity_id: &str,
        depth: u32,
    ) -> Option<Neighbourhood> {
        let center_key = NodeKey::new(tenant_id, entity_id);
        let center_idx = *self.index.get(&center_key)?;

        let g: tokio::sync::RwLockReadGuard<'_, petgraph::graph::DiGraph<TrustNode, TrustEdge>> = self.graph.read().await;
        let center = g.node_weight(center_idx)?.clone();

        let mut visited = std::collections::HashSet::new();
        let mut frontier = vec![center_idx];
        visited.insert(center_idx);

        for _ in 0..depth.max(1) {
            let mut next_frontier = Vec::new();
            for &idx in &frontier {
                // Outgoing neighbours.
                for neighbour in g.neighbors_directed(idx, Direction::Outgoing) {
                    if let Some(n) = g.node_weight(neighbour) {
                        // Tenant isolation check.
                        if n.key.tenant_id == tenant_id && visited.insert(neighbour) {
                            next_frontier.push(neighbour);
                        }
                    }
                }
                // Incoming neighbours.
                for neighbour in g.neighbors_directed(idx, Direction::Incoming) {
                    if let Some(n) = g.node_weight(neighbour) {
                        if n.key.tenant_id == tenant_id && visited.insert(neighbour) {
                            next_frontier.push(neighbour);
                        }
                    }
                }
            }
            frontier = next_frontier;
        }

        // Collect all nodes (except center).
        let nodes: Vec<TrustNode> = visited
            .iter()
            .filter(|&&idx| idx != center_idx)
            .filter_map(|&idx| g.node_weight(idx).cloned())
            .collect();

        // Collect edges between visited nodes.
        let mut edges = Vec::new();
        for &idx in &visited {
            for edge_ref in g.edges_directed(idx, Direction::Outgoing) {
                let target = petgraph::visit::EdgeRef::target(&edge_ref);
                if visited.contains(&target) {
                    if let (Some(src_node), Some(_tgt_node)) =
                        (g.node_weight(idx), g.node_weight(target))
                    {
                        edges.push((
                            src_node.key.entity_id.clone(),
                            g.node_weight(target).unwrap().key.entity_id.clone(),
                            edge_ref.weight().clone(),
                        ));
                    }
                }
            }
        }

        Some(Neighbourhood {
            center,
            nodes,
            edges,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::edge::{EdgeType, Severity};
    use crate::graph::node::NodeType;

    #[tokio::test]
    async fn test_trust_score_unknown_entity() {
        let store = TrustGraphStore::new(16);
        let score = store.trust_score(Uuid::new_v4(), "nonexistent").await;
        assert!(score.is_none());
    }

    #[tokio::test]
    async fn test_trust_score_known_entity() {
        let store = TrustGraphStore::new(16);
        let tid = Uuid::new_v4();
        store.ensure_node(tid, "agent-1", NodeType::Agent).await;
        let score = store.trust_score(tid, "agent-1").await;
        assert_eq!(score, Some(0.5));
    }

    #[tokio::test]
    async fn test_neighbourhood() {
        let store = TrustGraphStore::new(16);
        let tid = Uuid::new_v4();
        let src = store.ensure_node(tid, "agent-1", NodeType::Agent).await;
        let tgt1 = store.ensure_node(tid, "tool-a", NodeType::Tool).await;
        let tgt2 = store.ensure_node(tid, "tool-b", NodeType::Tool).await;
        store
            .record_event(src, tgt1, EdgeType::Uses, Severity::Low, 0)
            .await;
        store
            .record_event(src, tgt2, EdgeType::Uses, Severity::Low, 0)
            .await;

        let store = TrustGraphStore::new(16);
        let src = store.ensure_node(tid, "agent-1", NodeType::Agent).await;
        let _tgt1 = store.ensure_node(tid, "tool-a", NodeType::Tool).await;
        let _tgt2 = store.ensure_node(tid, "tool-b", NodeType::Tool).await;
        store
            .record_event(src, _tgt1, EdgeType::Uses, Severity::Low, 0)
            .await;
        store
            .record_event(src, _tgt2, EdgeType::Uses, Severity::Low, 0)
            .await;

        let nh = store.get_neighbourhood(tid, "agent-1", 1).await.unwrap();
        assert_eq!(nh.center.key.entity_id, "agent-1");
        assert_eq!(nh.nodes.len(), 2);
        assert_eq!(nh.edges.len(), 2);
    }

    #[tokio::test]
    async fn test_neighbourhood_tenant_isolation() {
        let store = TrustGraphStore::new(16);
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();

        let src1 = store.ensure_node(t1, "agent-1", NodeType::Agent).await;
        let tgt1 = store.ensure_node(t1, "tool-a", NodeType::Tool).await;
        let _src2 = store.ensure_node(t2, "agent-2", NodeType::Agent).await;

        store
            .record_event(src1, tgt1, EdgeType::Uses, Severity::Low, 0)
            .await;

        let nh = store.get_neighbourhood(t1, "agent-1", 1).await.unwrap();
        // Should only see tool-a (same tenant), not agent-2.
        assert_eq!(nh.nodes.len(), 1);
        assert_eq!(nh.nodes[0].key.entity_id, "tool-a");
    }
}
