// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Types of entities tracked in the trust graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeType {
    Agent,
    Tool,
    Resource,
    NetworkDest,
}

impl NodeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Tool => "tool",
            Self::Resource => "resource",
            Self::NetworkDest => "network_dest",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "agent" => Some(Self::Agent),
            "tool" => Some(Self::Tool),
            "resource" => Some(Self::Resource),
            "network_dest" | "networkdest" => Some(Self::NetworkDest),
            _ => None,
        }
    }
}

/// Sensitivity level for resource nodes.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Sensitivity {
    Low,
    Medium,
    High,
    Critical,
}

impl Sensitivity {
    pub fn weight(&self) -> f64 {
        match self {
            Self::Low => 0.25,
            Self::Medium => 0.5,
            Self::High => 0.75,
            Self::Critical => 1.0,
        }
    }
}

/// A composite key for node look-ups: `(tenant_id, entity_id)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeKey {
    pub tenant_id: Uuid,
    pub entity_id: String,
}

impl NodeKey {
    pub fn new(tenant_id: Uuid, entity_id: impl Into<String>) -> Self {
        Self {
            tenant_id,
            entity_id: entity_id.into(),
        }
    }
}

/// Trust graph node, representing an agent, tool, resource, or destination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustNode {
    pub key: NodeKey,
    pub node_type: NodeType,
    pub trust_score: f64,

    // Factor components (for explainability)
    pub history_score: f64,
    pub behavior_score: f64,
    pub permissions_score: f64,
    pub reputation_score: f64,

    // Counters for history factor
    pub total_events: u64,
    pub benign_events: u64,

    // Whether the entity is operating within declared scope
    pub within_scope: bool,

    pub metadata: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub last_event_at: DateTime<Utc>,

    /// When decay was last applied (prevents cumulative over-decay).
    /// `None` means decay has never been applied → use `last_event_at`.
    #[serde(default)]
    pub last_decay_at: Option<DateTime<Utc>>,
}

impl TrustNode {
    /// Create a new node with neutral trust (0.5).
    pub fn new(key: NodeKey, node_type: NodeType) -> Self {
        let now = Utc::now();
        Self {
            key,
            node_type,
            trust_score: 0.5,
            history_score: 0.5,
            behavior_score: 1.0,
            permissions_score: 1.0,
            reputation_score: 0.5,
            total_events: 0,
            benign_events: 0,
            within_scope: true,
            metadata: HashMap::new(),
            created_at: now,
            last_event_at: now,
            last_decay_at: None,
        }
    }

    /// History = ratio of benign events to total events (rolling 30 day).
    pub fn compute_history(&self) -> f64 {
        if self.total_events == 0 {
            return 0.5; // neutral when no data
        }
        self.benign_events as f64 / self.total_events as f64
    }

    /// Permissions factor: 1.0 if within scope, 0.5 if exceeded.
    pub fn compute_permissions(&self) -> f64 {
        if self.within_scope {
            1.0
        } else {
            0.5
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_creation_neutral_trust() {
        let key = NodeKey::new(Uuid::new_v4(), "agent-1");
        let node = TrustNode::new(key.clone(), NodeType::Agent);
        assert_eq!(node.trust_score, 0.5);
        assert_eq!(node.node_type, NodeType::Agent);
        assert_eq!(node.key.entity_id, "agent-1");
    }

    #[test]
    fn test_history_no_events() {
        let key = NodeKey::new(Uuid::new_v4(), "agent-1");
        let node = TrustNode::new(key, NodeType::Agent);
        assert_eq!(node.compute_history(), 0.5);
    }

    #[test]
    fn test_history_all_benign() {
        let key = NodeKey::new(Uuid::new_v4(), "agent-1");
        let mut node = TrustNode::new(key, NodeType::Agent);
        node.total_events = 100;
        node.benign_events = 100;
        assert_eq!(node.compute_history(), 1.0);
    }

    #[test]
    fn test_history_mixed() {
        let key = NodeKey::new(Uuid::new_v4(), "agent-1");
        let mut node = TrustNode::new(key, NodeType::Agent);
        node.total_events = 100;
        node.benign_events = 70;
        assert!((node.compute_history() - 0.7).abs() < 1e-10);
    }

    #[test]
    fn test_permissions_in_scope() {
        let key = NodeKey::new(Uuid::new_v4(), "agent-1");
        let node = TrustNode::new(key, NodeType::Agent);
        assert_eq!(node.compute_permissions(), 1.0);
    }

    #[test]
    fn test_permissions_out_of_scope() {
        let key = NodeKey::new(Uuid::new_v4(), "agent-1");
        let mut node = TrustNode::new(key, NodeType::Agent);
        node.within_scope = false;
        assert_eq!(node.compute_permissions(), 0.5);
    }

    #[test]
    fn test_node_type_from_str() {
        assert_eq!(NodeType::parse("agent"), Some(NodeType::Agent));
        assert_eq!(NodeType::parse("tool"), Some(NodeType::Tool));
        assert_eq!(NodeType::parse("resource"), Some(NodeType::Resource));
        assert_eq!(NodeType::parse("network_dest"), Some(NodeType::NetworkDest));
        assert_eq!(NodeType::parse("unknown"), None);
    }
}
