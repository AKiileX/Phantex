// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

use std::sync::Arc;

use chrono::Utc;
use uuid::Uuid;

use crate::config::ScoringConfig;
use crate::graph::store::TrustGraphStore;

/// Applies trust decay: entities that have not been observed recently
/// drift toward the neutral score (default 0.5) at a configurable rate.
pub struct TrustDecay {
    pub config: ScoringConfig,
}

impl TrustDecay {
    pub fn new(config: ScoringConfig) -> Self {
        Self { config }
    }

    /// Apply decay to all nodes in a tenant.  Returns the number of nodes updated.
    pub async fn apply_tenant(&self, store: &Arc<TrustGraphStore>, tenant_id: Uuid) -> u64 {
        let now = Utc::now();
        let neutral = self.config.neutral_score;
        let rate = self.config.decay_rate;

        let indices = store.tenant_node_indices(tenant_id).await;
        let mut updated = 0u64;

        for idx in indices {
            let maybe_key = store
                .read(|g| g.node_weight(idx).map(|n| (n.key.clone(), n.last_event_at, n.last_decay_at, n.trust_score)))
                .await;

            if let Some((key, last_event_at, last_decay_at, current_score)) = maybe_key {
                // Use last_decay_at if available; otherwise fall back to last_event_at.
                // This prevents cumulative over-decay when apply_tenant runs repeatedly.
                let reference_time = last_decay_at.unwrap_or(last_event_at);
                let days_inactive = (now - reference_time).num_seconds() as f64 / 86_400.0;
                if days_inactive <= 0.0 {
                    continue;
                }

                let decay_amount = rate * days_inactive;

                // Decay toward neutral.
                let new_score = if current_score > neutral {
                    (current_score - decay_amount).max(neutral)
                } else if current_score < neutral {
                    (current_score + decay_amount).min(neutral)
                } else {
                    continue; // Already at neutral.
                };

                if (new_score - current_score).abs() > 1e-10 {
                    let decay_now = now;
                    store
                        .update_node(&key, |n| {
                            n.trust_score = new_score;
                            n.last_decay_at = Some(decay_now);
                        })
                        .await;
                    updated += 1;
                }
            }
        }

        updated
    }

    /// Apply decay across all tenants.
    pub async fn apply_all(&self, store: &Arc<TrustGraphStore>) -> u64 {
        let tenant_ids: Vec<Uuid> = {
            let all_nodes = store.all_node_indices().await;
            let mut seen = std::collections::HashSet::new();
            let mut ids = Vec::new();
            for idx in all_nodes {
                if let Some(node) = store.read(|g| g.node_weight(idx).cloned()).await {
                    if seen.insert(node.key.tenant_id) {
                        ids.push(node.key.tenant_id);
                    }
                }
            }
            ids
        };

        let mut total = 0u64;
        for tid in tenant_ids {
            total += self.apply_tenant(store, tid).await;
        }
        total
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::node::{NodeKey, NodeType};

    #[tokio::test]
    async fn test_decay_inactive_node_toward_neutral() {
        let config = ScoringConfig::default();
        let decay = TrustDecay::new(config);
        let store = TrustGraphStore::new(16);
        let tid = Uuid::new_v4();

        store.ensure_node(tid, "agent-1", NodeType::Agent).await;

        // Manually set trust high and last_event_at to 10 days ago.
        let key = NodeKey::new(tid, "agent-1");
        store
            .update_node(&key, |n| {
                n.trust_score = 0.9;
                n.last_event_at = Utc::now() - chrono::Duration::days(10);
            })
            .await;

        let updated = decay.apply_tenant(&store, tid).await;
        assert_eq!(updated, 1);

        let node = store.get_node(tid, "agent-1").await.unwrap();
        // Decay = 0.01 * 10 = 0.10, so 0.9 - 0.1 = 0.8
        assert!(
            (node.trust_score - 0.8).abs() < 0.05,
            "Expected ~0.8, got {}",
            node.trust_score,
        );
    }

    #[tokio::test]
    async fn test_decay_low_trust_toward_neutral() {
        let config = ScoringConfig::default();
        let decay = TrustDecay::new(config);
        let store = TrustGraphStore::new(16);
        let tid = Uuid::new_v4();

        store.ensure_node(tid, "agent-1", NodeType::Agent).await;

        let key = NodeKey::new(tid, "agent-1");
        store
            .update_node(&key, |n| {
                n.trust_score = 0.2;
                n.last_event_at = Utc::now() - chrono::Duration::days(10);
            })
            .await;

        decay.apply_tenant(&store, tid).await;

        let node = store.get_node(tid, "agent-1").await.unwrap();
        // Decay = 0.01 * 10 = 0.10, so 0.2 + 0.1 = 0.3
        assert!(
            (node.trust_score - 0.3).abs() < 0.05,
            "Expected ~0.3, got {}",
            node.trust_score,
        );
    }

    #[tokio::test]
    async fn test_no_decay_for_active_node() {
        let config = ScoringConfig::default();
        let decay = TrustDecay::new(config);
        let store = TrustGraphStore::new(16);
        let tid = Uuid::new_v4();

        store.ensure_node(tid, "agent-1", NodeType::Agent).await;
        // Default: last_event_at = now, trust = 0.5 (neutral) → no decay.
        let updated = decay.apply_tenant(&store, tid).await;
        assert_eq!(updated, 0);
    }
}
