// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

use std::sync::Arc;

use uuid::Uuid;

use crate::config::ScoringConfig;
use crate::graph::edge::Severity;
use crate::graph::node::{NodeKey, NodeType};
use crate::graph::store::TrustGraphStore;

/// Computes trust scores for entities in the graph.
pub struct TrustCalculator {
    pub config: ScoringConfig,
}

/// Result of computing a trust score (with factor breakdown).
#[derive(Debug, Clone)]
pub struct TrustResult {
    pub score: f64,
    pub history: f64,
    pub behavior: f64,
    pub permissions: f64,
    pub reputation: f64,
}

impl TrustCalculator {
    pub fn new(config: ScoringConfig) -> Self {
        Self { config }
    }

    /// Compute the weighted trust score from individual factors.
    ///
    /// `Trust = w_h * history + w_b * behavior + w_p * permissions + w_r * reputation`
    pub fn compute(&self, history: f64, behavior: f64, permissions: f64, reputation: f64) -> TrustResult {
        let score = self.config.weight_history * history
            + self.config.weight_behavior * behavior
            + self.config.weight_permissions * permissions
            + self.config.weight_reputation * reputation;
        let score = score.clamp(0.0, 1.0);
        TrustResult {
            score,
            history,
            behavior,
            permissions,
            reputation,
        }
    }

    /// Recompute trust for a specific entity and write it back to the store.
    pub async fn recompute_entity(
        &self,
        store: &Arc<TrustGraphStore>,
        tenant_id: Uuid,
        entity_id: &str,
    ) -> Option<TrustResult> {
        let node = store.get_node(tenant_id, entity_id).await?;

        let history = node.compute_history();
        let behavior = node.behavior_score;
        let permissions = node.compute_permissions();
        let reputation = node.reputation_score;

        let result = self.compute(history, behavior, permissions, reputation);

        let key = NodeKey::new(tenant_id, entity_id);
        store
            .update_node(&key, |n| {
                n.trust_score = result.score;
                n.history_score = result.history;
                n.permissions_score = result.permissions;
            })
            .await;

        Some(result)
    }

    /// Process a new event: update counters then recompute trust.
    #[allow(clippy::too_many_arguments)]
    pub async fn process_event(
        &self,
        store: &Arc<TrustGraphStore>,
        tenant_id: Uuid,
        source_id: &str,
        source_type: NodeType,
        target_id: &str,
        target_type: NodeType,
        severity: Severity,
    ) -> (Option<TrustResult>, Option<TrustResult>) {
        // Determine edge type before moving types into ensure_node.
        let edge_type_str = match (&source_type, &target_type) {
            (NodeType::Agent, NodeType::Tool) => "tool_call",
            (NodeType::Agent, NodeType::Resource) => "file_access",
            (NodeType::Agent, NodeType::NetworkDest) => "network_connect",
            (NodeType::Agent, NodeType::Agent) => "delegation",
            _ => "trusts",
        };
        let edge_type = crate::graph::edge::EdgeType::from_event_type(edge_type_str)
            .unwrap_or(crate::graph::edge::EdgeType::Trusts);

        // Ensure both nodes exist.
        let src_idx = store
            .ensure_node(tenant_id, source_id, source_type)
            .await;
        let tgt_idx = store
            .ensure_node(tenant_id, target_id, target_type)
            .await;

        let is_benign = severity.is_benign();
        let penalty = severity.penalty();

        // Update source node counters.
        let src_key = NodeKey::new(tenant_id, source_id);
        store
            .update_node(&src_key, |n| {
                n.total_events += 1;
                if is_benign {
                    n.benign_events += 1;
                }
                // Apply immediate penalty for non-benign events.
                if !is_benign {
                    n.behavior_score = (n.behavior_score - penalty).max(0.0);
                    // Critical events indicate scope violation.
                    if matches!(severity, Severity::Critical | Severity::High) {
                        n.within_scope = false;
                    }
                } else {
                    // Slowly recover behavior score.
                    n.behavior_score = (n.behavior_score + severity.boost()).min(1.0);
                    // Recover within_scope after sustained benign behaviour.
                    // Requires at least 10 benign events with >90% benign ratio.
                    if !n.within_scope
                        && n.benign_events >= 10
                        && n.total_events > 0
                        && (n.benign_events as f64 / n.total_events as f64) > 0.9
                    {
                        n.within_scope = true;
                    }
                }
                n.last_event_at = chrono::Utc::now();
            })
            .await;

        store
            .record_event(src_idx, tgt_idx, edge_type, severity, 0)
            .await;

        // Recompute trust for both.
        let src_result = self.recompute_entity(store, tenant_id, source_id).await;
        let tgt_result = self.recompute_entity(store, tenant_id, target_id).await;

        (src_result, tgt_result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_calc() -> TrustCalculator {
        TrustCalculator::new(ScoringConfig::default())
    }

    #[test]
    fn test_compute_all_max() {
        let calc = default_calc();
        let r = calc.compute(1.0, 1.0, 1.0, 1.0);
        assert!((r.score - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_compute_all_min() {
        let calc = default_calc();
        let r = calc.compute(0.0, 0.0, 0.0, 0.0);
        assert!((r.score - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_compute_neutral() {
        let calc = default_calc();
        let r = calc.compute(0.5, 0.5, 0.5, 0.5);
        assert!((r.score - 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_compute_clamped() {
        let calc = default_calc();
        let r = calc.compute(2.0, 2.0, 2.0, 2.0);
        assert_eq!(r.score, 1.0);
    }

    #[tokio::test]
    async fn test_process_benign_event() {
        let calc = default_calc();
        let store = TrustGraphStore::new(16);
        let tid = Uuid::new_v4();

        let (src, _tgt) = calc
            .process_event(
                &store,
                tid,
                "agent-1",
                NodeType::Agent,
                "tool-a",
                NodeType::Tool,
                Severity::Low,
            )
            .await;

        let src = src.unwrap();
        // After one benign event, trust should be at or above neutral.
        assert!(src.score >= 0.5);
    }

    #[tokio::test]
    async fn test_process_high_severity_reduces_trust() {
        let calc = default_calc();
        let store = TrustGraphStore::new(16);
        let tid = Uuid::new_v4();

        // First a benign event to establish baseline.
        calc.process_event(
            &store,
            tid,
            "agent-1",
            NodeType::Agent,
            "tool-a",
            NodeType::Tool,
            Severity::Low,
        )
        .await;

        let initial = store.trust_score(tid, "agent-1").await.unwrap();

        // Three high-severity events.
        for _ in 0..3 {
            calc.process_event(
                &store,
                tid,
                "agent-1",
                NodeType::Agent,
                "tool-a",
                NodeType::Tool,
                Severity::High,
            )
            .await;
        }

        let after = store.trust_score(tid, "agent-1").await.unwrap();
        assert!(after < initial, "Trust should decrease after high-severity events");
    }

    #[tokio::test]
    async fn test_three_critical_drops_below_03() {
        let calc = default_calc();
        let store = TrustGraphStore::new(16);
        let tid = Uuid::new_v4();

        for _ in 0..3 {
            calc.process_event(
                &store,
                tid,
                "agent-1",
                NodeType::Agent,
                "tool-a",
                NodeType::Tool,
                Severity::Critical,
            )
            .await;
        }

        let score = store.trust_score(tid, "agent-1").await.unwrap();
        assert!(
            score < 0.3,
            "Agent with 3+ critical alerts should have trust < 0.3, got {}",
            score
        );
    }
}
