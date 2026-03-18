// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Types of relationships between nodes in the trust graph.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EdgeType {
    /// Agent → Tool: tool invocation.
    Uses,
    /// Agent → Resource: file / data access.
    Accesses,
    /// Agent → NetworkDest: outbound connection.
    ConnectsTo,
    /// Agent → Agent: delegation of authority.
    Delegates,
    /// Any → Any: computed trust relationship.
    Trusts,
}

impl EdgeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Uses => "uses",
            Self::Accesses => "accesses",
            Self::ConnectsTo => "connects_to",
            Self::Delegates => "delegates",
            Self::Trusts => "trusts",
        }
    }

    pub fn from_event_type(event_type: &str) -> Option<Self> {
        match event_type.to_lowercase().as_str() {
            "tool_call" | "uses" => Some(Self::Uses),
            "file_access" | "accesses" => Some(Self::Accesses),
            "network_connect" | "connects_to" => Some(Self::ConnectsTo),
            "delegation" | "delegates" => Some(Self::Delegates),
            "trusts" => Some(Self::Trusts),
            _ => None,
        }
    }
}

/// Severity level of an event (determines how much trust changes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Trust penalty multiplier for adverse events.
    pub fn penalty(&self) -> f64 {
        match self {
            Self::Low => 0.01,
            Self::Medium => 0.05,
            Self::High => 0.15,
            Self::Critical => 0.35,
        }
    }

    /// Trust boost for benign events (much smaller than penalties).
    pub fn boost(&self) -> f64 {
        match self {
            Self::Low => 0.005,
            Self::Medium => 0.003,
            Self::High => 0.001,
            Self::Critical => 0.0,
        }
    }

    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" => Self::Critical,
            "high" => Self::High,
            "medium" => Self::Medium,
            _ => Self::Low,
        }
    }

    pub fn is_benign(&self) -> bool {
        matches!(self, Self::Low)
    }
}

/// A directed edge in the trust graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustEdge {
    pub edge_type: EdgeType,
    pub count: u64,
    pub weight: f64,
    pub bytes_total: u64,
    pub last_severity: Severity,
    pub last_seen: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

impl TrustEdge {
    pub fn new(edge_type: EdgeType, severity: Severity) -> Self {
        let now = Utc::now();
        Self {
            edge_type,
            count: 1,
            weight: 1.0,
            bytes_total: 0,
            last_severity: severity,
            last_seen: now,
            created_at: now,
        }
    }

    /// Update edge with a new event.
    pub fn record_event(&mut self, severity: Severity, bytes: u64) {
        self.count = self.count.saturating_add(1);
        self.bytes_total = self.bytes_total.saturating_add(bytes);
        self.last_severity = severity;
        self.last_seen = Utc::now();

        // Weight accumulates based on interaction frequency −
        // high-frequency edges carry more weight in trust propagation.
        self.weight = (self.count as f64).ln().max(1.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edge_creation() {
        let edge = TrustEdge::new(EdgeType::Uses, Severity::Low);
        assert_eq!(edge.edge_type, EdgeType::Uses);
        assert_eq!(edge.count, 1);
        assert_eq!(edge.weight, 1.0);
    }

    #[test]
    fn test_edge_record_event() {
        let mut edge = TrustEdge::new(EdgeType::Uses, Severity::Low);
        edge.record_event(Severity::Medium, 1024);
        assert_eq!(edge.count, 2);
        assert_eq!(edge.bytes_total, 1024);
        assert_eq!(edge.last_severity, Severity::Medium);
    }

    #[test]
    fn test_severity_penalty_ordering() {
        assert!(Severity::Low.penalty() < Severity::Medium.penalty());
        assert!(Severity::Medium.penalty() < Severity::High.penalty());
        assert!(Severity::High.penalty() < Severity::Critical.penalty());
    }

    #[test]
    fn test_edge_type_from_event_type() {
        assert_eq!(EdgeType::from_event_type("tool_call"), Some(EdgeType::Uses));
        assert_eq!(EdgeType::from_event_type("file_access"), Some(EdgeType::Accesses));
        assert_eq!(EdgeType::from_event_type("network_connect"), Some(EdgeType::ConnectsTo));
        assert_eq!(EdgeType::from_event_type("delegation"), Some(EdgeType::Delegates));
        assert_eq!(EdgeType::from_event_type("unknown_type"), None);
    }

    #[test]
    fn test_severity_from_str() {
        assert_eq!(Severity::parse("critical"), Severity::Critical);
        assert_eq!(Severity::parse("high"), Severity::High);
        assert_eq!(Severity::parse("medium"), Severity::Medium);
        assert_eq!(Severity::parse("low"), Severity::Low);
        assert_eq!(Severity::parse("garbage"), Severity::Low);
    }
}
