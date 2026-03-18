// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

use std::sync::Arc;

use petgraph::Direction;
use petgraph::visit::EdgeRef;
use uuid::Uuid;

use crate::config::ScoringConfig;
use crate::graph::node::NodeKey;
use crate::graph::store::TrustGraphStore;

/// PageRank-style trust propagation through the graph.
///
/// Nodes that interact with highly-trusted nodes inherit some of that trust
/// (reputation component).  Uses the standard power-iteration PageRank
/// algorithm with a configurable damping factor.
pub struct TrustPropagation {
    pub config: ScoringConfig,
}

/// Result of a propagation pass.
#[derive(Debug, Clone)]
pub struct PropagationResult {
    pub iterations: u32,
    pub max_delta: f64,
    pub converged: bool,
    pub nodes_updated: u64,
}

impl TrustPropagation {
    pub fn new(config: ScoringConfig) -> Self {
        Self { config }
    }

    /// Run PageRank-style propagation for a single tenant.
    pub async fn propagate_tenant(
        &self,
        store: &Arc<TrustGraphStore>,
        tenant_id: Uuid,
        max_iterations: Option<u32>,
        convergence_threshold: Option<f64>,
    ) -> PropagationResult {
        let max_iter = max_iterations.unwrap_or(self.config.max_iterations);
        let threshold = convergence_threshold.unwrap_or(self.config.convergence_threshold);
        let damping = self.config.damping;

        let node_indices = store.tenant_node_indices(tenant_id).await;
        let n = node_indices.len();
        if n == 0 {
            return PropagationResult {
                iterations: 0,
                max_delta: 0.0,
                converged: true,
                nodes_updated: 0,
            };
        }

        // Initialise reputation scores from current node trust scores.
        let mut scores: Vec<f64> = Vec::with_capacity(n);
        let mut keys: Vec<NodeKey> = Vec::with_capacity(n);

        {
            let _node_data = store
                .read(|g| {
                    node_indices
                        .iter()
                        .map(|&idx| {
                            let node = g.node_weight(idx).unwrap();
                            (node.key.clone(), node.trust_score)
                        })
                        .collect::<Vec<_>>()
                })
                .await;

            for (key, score) in _node_data {
                keys.push(key);
                scores.push(score);
            }
        }

        // Build adjacency (outgoing edges with weights) within the node_indices set.
        let adj: Vec<Vec<(usize, f64)>> = store
            .read(|g| {
                let idx_to_pos: std::collections::HashMap<_, _> = node_indices
                    .iter()
                    .enumerate()
                    .map(|(pos, &idx)| (idx, pos))
                    .collect();

                node_indices
                    .iter()
                    .map(|&idx| {
                        g.edges_directed(idx, Direction::Outgoing)
                            .filter_map(|e| {
                                let target = e.target();
                                idx_to_pos.get(&target).map(|&pos| (pos, e.weight().weight))
                            })
                            .collect()
                    })
                    .collect()
            })
            .await;

        // Power iteration.
        // Pre-compute incoming adjacency and out-degrees for O(n+E) per iteration
        // instead of the naive O(n²·E) scan.
        let mut in_adj: Vec<Vec<(usize, f64)>> = vec![Vec::new(); n];
        let mut out_degree: Vec<f64> = vec![0.0; n];
        for (j, edges) in adj.iter().enumerate() {
            out_degree[j] = edges.iter().map(|&(_, w)| w).sum();
            for &(target, weight) in edges {
                in_adj[target].push((j, weight));
            }
        }

        let base = (1.0 - damping) / n as f64;
        let mut iterations = 0u32;
        let mut max_delta = 0.0f64;

        for _ in 0..max_iter {
            iterations += 1;
            max_delta = 0.0;
            let old_scores = scores.clone();

            for i in 0..n {
                // Sum incoming trust contributions via pre-built index.
                let mut incoming_sum = 0.0;
                for &(j, weight) in &in_adj[i] {
                    if out_degree[j] > 0.0 {
                        incoming_sum += old_scores[j] * weight / out_degree[j];
                    }
                }
                scores[i] = base + damping * incoming_sum;
                let delta = (scores[i] - old_scores[i]).abs();
                if delta > max_delta {
                    max_delta = delta;
                }
            }

            if max_delta < threshold {
                break;
            }
        }

        // Write reputation scores back to nodes.
        let mut nodes_updated = 0u64;
        for (i, key) in keys.iter().enumerate() {
            let rep = scores[i].clamp(0.0, 1.0);
            let updated = store
                .update_node(key, |node| {
                    node.reputation_score = rep;
                })
                .await;
            if updated {
                nodes_updated += 1;
            }
        }

        PropagationResult {
            iterations,
            max_delta,
            converged: max_delta < threshold,
            nodes_updated,
        }
    }

    /// Propagate scores for all tenants (or a specific one).
    pub async fn propagate(
        &self,
        store: &Arc<TrustGraphStore>,
        tenant_id: Option<Uuid>,
        max_iterations: Option<u32>,
        convergence_threshold: Option<f64>,
    ) -> PropagationResult {
        if let Some(tid) = tenant_id {
            return self
                .propagate_tenant(store, tid, max_iterations, convergence_threshold)
                .await;
        }

        // All tenants — collect unique tenant IDs.
        let tenant_ids: Vec<Uuid> = {
            let mut ids = Vec::new();
            // We can get tenant IDs from the store.
            let all_nodes = store.all_node_indices().await;
            let mut seen = std::collections::HashSet::new();
            for idx in all_nodes {
                if let Some(node) = store.read(|g| g.node_weight(idx).cloned()).await {
                    if seen.insert(node.key.tenant_id) {
                        ids.push(node.key.tenant_id);
                    }
                }
            }
            ids
        };

        let mut total = PropagationResult {
            iterations: 0,
            max_delta: 0.0,
            converged: true,
            nodes_updated: 0,
        };

        for tid in tenant_ids {
            let r = self
                .propagate_tenant(store, tid, max_iterations, convergence_threshold)
                .await;
            total.iterations = total.iterations.max(r.iterations);
            if r.max_delta > total.max_delta {
                total.max_delta = r.max_delta;
            }
            total.converged = total.converged && r.converged;
            total.nodes_updated += r.nodes_updated;
        }

        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::edge::{EdgeType, Severity};
    use crate::graph::node::NodeType;

    fn default_propagation() -> TrustPropagation {
        TrustPropagation::new(ScoringConfig::default())
    }

    #[tokio::test]
    async fn test_propagate_empty_graph() {
        let prop = default_propagation();
        let store = TrustGraphStore::new(16);
        let tid = Uuid::new_v4();
        let result = prop.propagate_tenant(&store, tid, None, None).await;
        assert!(result.converged);
        assert_eq!(result.iterations, 0);
        assert_eq!(result.nodes_updated, 0);
    }

    #[tokio::test]
    async fn test_propagate_simple_chain() {
        let prop = default_propagation();
        let store = TrustGraphStore::new(16);
        let tid = Uuid::new_v4();

        // A → B → C
        let a = store.ensure_node(tid, "a", NodeType::Agent).await;
        let b = store.ensure_node(tid, "b", NodeType::Tool).await;
        let c = store.ensure_node(tid, "c", NodeType::Resource).await;

        store
            .record_event(a, b, EdgeType::Uses, Severity::Low, 0)
            .await;
        store
            .record_event(b, c, EdgeType::Accesses, Severity::Low, 0)
            .await;

        let result = prop.propagate_tenant(&store, tid, None, None).await;
        assert!(result.converged);
        assert_eq!(result.nodes_updated, 3);
    }

    #[tokio::test]
    async fn test_propagate_converges_quickly() {
        let prop = default_propagation();
        let store = TrustGraphStore::new(16);
        let tid = Uuid::new_v4();

        // Create a small cycle: A → B → C → A
        let a = store.ensure_node(tid, "a", NodeType::Agent).await;
        let b = store.ensure_node(tid, "b", NodeType::Agent).await;
        let c = store.ensure_node(tid, "c", NodeType::Agent).await;

        store
            .record_event(a, b, EdgeType::Delegates, Severity::Low, 0)
            .await;
        store
            .record_event(b, c, EdgeType::Delegates, Severity::Low, 0)
            .await;
        store
            .record_event(c, a, EdgeType::Delegates, Severity::Low, 0)
            .await;

        let result = prop.propagate_tenant(&store, tid, Some(100), None).await;
        assert!(result.converged);
        assert!(result.iterations <= 100);
    }
}
