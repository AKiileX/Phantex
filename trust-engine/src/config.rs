// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

use serde::Deserialize;

/// Top-level configuration for the trust engine.
#[derive(Debug, Clone, Deserialize)]
pub struct TrustEngineConfig {
    #[serde(default = "default_grpc_addr")]
    pub grpc_addr: String,

    #[serde(default)]
    pub graph: GraphConfig,

    #[serde(default)]
    pub scoring: ScoringConfig,

    #[serde(default)]
    pub snapshot: SnapshotConfig,

    #[serde(default)]
    pub auth: AuthConfig,

    #[serde(default)]
    pub tls: TlsConfig,
}

impl Default for TrustEngineConfig {
    fn default() -> Self {
        Self {
            grpc_addr: default_grpc_addr(),
            graph: GraphConfig::default(),
            scoring: ScoringConfig::default(),
            snapshot: SnapshotConfig::default(),
            auth: AuthConfig::default(),
            tls: TlsConfig::default(),
        }
    }
}

fn default_grpc_addr() -> String {
    "[::1]:50052".to_string()
}

/// Parameters that govern the underlying graph data-structure.
#[derive(Debug, Clone, Deserialize)]
pub struct GraphConfig {
    /// Initial capacity hint for node count.
    #[serde(default = "default_initial_capacity")]
    pub initial_capacity: usize,

    /// Maximum nodes per tenant (safety valve).
    #[serde(default = "default_max_nodes_per_tenant")]
    pub max_nodes_per_tenant: usize,
}

impl Default for GraphConfig {
    fn default() -> Self {
        Self {
            initial_capacity: default_initial_capacity(),
            max_nodes_per_tenant: default_max_nodes_per_tenant(),
        }
    }
}

fn default_initial_capacity() -> usize {
    10_000
}

fn default_max_nodes_per_tenant() -> usize {
    500_000
}

/// Scoring and propagation parameters.
#[derive(Debug, Clone, Deserialize)]
pub struct ScoringConfig {
    /// Weight for history factor.
    #[serde(default = "default_weight_history")]
    pub weight_history: f64,

    /// Weight for behavior factor.
    #[serde(default = "default_weight_behavior")]
    pub weight_behavior: f64,

    /// Weight for permissions factor.
    #[serde(default = "default_weight_permissions")]
    pub weight_permissions: f64,

    /// Weight for reputation (PageRank) factor.
    #[serde(default = "default_weight_reputation")]
    pub weight_reputation: f64,

    /// Decay rate toward neutral per day without events.
    #[serde(default = "default_decay_rate")]
    pub decay_rate: f64,

    /// Neutral trust score (decay target).
    #[serde(default = "default_neutral_score")]
    pub neutral_score: f64,

    /// Default damping factor for PageRank propagation.
    #[serde(default = "default_damping")]
    pub damping: f64,

    /// Default max iterations for PageRank.
    #[serde(default = "default_max_iterations")]
    pub max_iterations: u32,

    /// Convergence threshold for PageRank.
    #[serde(default = "default_convergence_threshold")]
    pub convergence_threshold: f64,
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            weight_history: default_weight_history(),
            weight_behavior: default_weight_behavior(),
            weight_permissions: default_weight_permissions(),
            weight_reputation: default_weight_reputation(),
            decay_rate: default_decay_rate(),
            neutral_score: default_neutral_score(),
            damping: default_damping(),
            max_iterations: default_max_iterations(),
            convergence_threshold: default_convergence_threshold(),
        }
    }
}

fn default_weight_history() -> f64 {
    0.3
}
fn default_weight_behavior() -> f64 {
    0.3
}
fn default_weight_permissions() -> f64 {
    0.2
}
fn default_weight_reputation() -> f64 {
    0.2
}
fn default_decay_rate() -> f64 {
    0.01
}
fn default_neutral_score() -> f64 {
    0.5
}
fn default_damping() -> f64 {
    0.85
}
fn default_max_iterations() -> u32 {
    20
}
fn default_convergence_threshold() -> f64 {
    1e-6
}

/// Snapshot persistence settings.
#[derive(Debug, Clone, Deserialize)]
pub struct SnapshotConfig {
    /// Directory for snapshot files.
    #[serde(default = "default_snapshot_dir")]
    pub dir: String,

    /// Interval in seconds between snapshots.
    #[serde(default = "default_snapshot_interval_secs")]
    pub interval_secs: u64,

    /// Whether to encrypt snapshots at rest (AES-256-GCM).
    #[serde(default = "default_encrypt")]
    pub encrypt: bool,

    /// Hex-encoded 256-bit encryption key. Required when `encrypt` is true.
    #[serde(default)]
    pub encryption_key: Option<String>,
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            dir: default_snapshot_dir(),
            interval_secs: default_snapshot_interval_secs(),
            encrypt: default_encrypt(),
            encryption_key: None,
        }
    }
}

fn default_snapshot_dir() -> String {
    "/var/lib/phantex/trust-snapshots".to_string()
}

fn default_snapshot_interval_secs() -> u64 {
    300 // 5 minutes
}

fn default_encrypt() -> bool {
    false // default off; enable in production with a configured key
}

/// Authentication / authorisation settings.
#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    /// Optional API key.  When set, all gRPC requests must include
    /// `x-api-key` metadata matching this value.  When `None`, auth is
    /// disabled (development mode).
    #[serde(default)]
    pub api_key: Option<String>,

    /// Maximum allowed entity ID length in bytes (safety valve).
    #[serde(default = "default_max_entity_id_len")]
    pub max_entity_id_len: usize,

    /// Maximum depth for neighbourhood queries.
    #[serde(default = "default_max_graph_depth")]
    pub max_graph_depth: u32,

    /// Maximum messages in a single batch_update_events stream.
    #[serde(default = "default_max_batch_size")]
    pub max_batch_size: u64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            api_key: None,
            max_entity_id_len: default_max_entity_id_len(),
            max_graph_depth: default_max_graph_depth(),
            max_batch_size: default_max_batch_size(),
        }
    }
}

fn default_max_entity_id_len() -> usize {
    256
}

fn default_max_graph_depth() -> u32 {
    5
}

fn default_max_batch_size() -> u64 {
    100_000
}

/// TLS configuration for the gRPC server.
/// When `enabled` is false (the default), the server listens in plaintext
/// — suitable for Docker-internal networking.  For bare-metal or
/// cross-network deployments, enable TLS and supply cert/key/CA paths.
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    /// Enable TLS on the gRPC listener.
    #[serde(default)]
    pub enabled: bool,

    /// Path to the PEM-encoded server certificate.
    #[serde(default)]
    pub cert_file: Option<String>,

    /// Path to the PEM-encoded server private key.
    #[serde(default)]
    pub key_file: Option<String>,

    /// Path to the PEM-encoded CA certificate for client verification (mTLS).
    /// When set, the server requires clients to present a valid certificate.
    #[serde(default)]
    pub ca_file: Option<String>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            cert_file: None,
            key_file: None,
            ca_file: None,
        }
    }
}
