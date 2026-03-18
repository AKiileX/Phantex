// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

use std::sync::Arc;
use std::time::Instant;

use prost_types::Timestamp;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::{AuthConfig, TrustEngineConfig};
use crate::graph::edge::Severity;
use crate::graph::node::NodeType;
use crate::graph::store::TrustGraphStore;
use crate::scoring::calculator::TrustCalculator;
use crate::scoring::propagation::TrustPropagation;

use super::proto;
use super::proto::trust_service_server::TrustService;

/// gRPC service implementation for TrustService.
pub struct TrustServiceImpl {
    pub store: Arc<TrustGraphStore>,
    pub calculator: Arc<TrustCalculator>,
    pub propagation: Arc<TrustPropagation>,
    pub start_time: Instant,
    auth: AuthConfig,
}

impl TrustServiceImpl {
    pub fn new(
        store: Arc<TrustGraphStore>,
        config: &TrustEngineConfig,
    ) -> Self {
        let calculator = Arc::new(TrustCalculator::new(config.scoring.clone()));
        let propagation = Arc::new(TrustPropagation::new(config.scoring.clone()));
        Self {
            store,
            calculator,
            propagation,
            start_time: Instant::now(),
            auth: config.auth.clone(),
        }
    }

    /// Validate that an entity ID is non-empty and within length limits.
    #[allow(clippy::result_large_err)]
    fn validate_id(&self, id: &str, field: &str) -> Result<(), Status> {
        if id.is_empty() {
            return Err(Status::invalid_argument(format!("{field} must not be empty")));
        }
        let max_len = self.auth.max_entity_id_len.clamp(1, 4096);
        if id.len() > max_len {
            return Err(Status::invalid_argument(format!(
                "{field} too long ({} bytes, max {max_len})",
                id.len()
            )));
        }
        Ok(())
    }
}

#[allow(clippy::result_large_err)]
fn parse_tenant_id(s: &str) -> Result<Uuid, Status> {
    Uuid::parse_str(s).map_err(|_| Status::invalid_argument(format!("Invalid tenant_id: {s}")))
}

#[allow(clippy::result_large_err)]
fn parse_node_type(s: &str) -> Result<NodeType, Status> {
    NodeType::parse(s)
        .ok_or_else(|| Status::invalid_argument(format!("Invalid entity_type: {s}")))
}

fn chrono_to_proto(dt: chrono::DateTime<chrono::Utc>) -> Option<Timestamp> {
    Some(Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    })
}

#[tonic::async_trait]
impl TrustService for TrustServiceImpl {
    async fn get_trust_score(
        &self,
        request: Request<proto::GetTrustScoreRequest>,
    ) -> Result<Response<proto::GetTrustScoreResponse>, Status> {
        let req = request.into_inner();
        let tenant_id = parse_tenant_id(&req.tenant_id)?;
        let _entity_type = parse_node_type(&req.entity_type)?;
        self.validate_id(&req.entity_id, "entity_id")?;

        let node = self
            .store
            .get_node(tenant_id, &req.entity_id)
            .await
            .ok_or_else(|| Status::not_found("Entity not found"))?;

        let factors = vec![
            proto::TrustFactor {
                name: "history".into(),
                weight: self.calculator.config.weight_history,
                value: node.history_score,
            },
            proto::TrustFactor {
                name: "behavior".into(),
                weight: self.calculator.config.weight_behavior,
                value: node.behavior_score,
            },
            proto::TrustFactor {
                name: "permissions".into(),
                weight: self.calculator.config.weight_permissions,
                value: node.permissions_score,
            },
            proto::TrustFactor {
                name: "reputation".into(),
                weight: self.calculator.config.weight_reputation,
                value: node.reputation_score,
            },
        ];

        Ok(Response::new(proto::GetTrustScoreResponse {
            trust_score: node.trust_score,
            factors,
            last_updated: chrono_to_proto(node.last_event_at),
            entity_id: req.entity_id,
            entity_type: req.entity_type,
        }))
    }

    async fn get_trust_graph(
        &self,
        request: Request<proto::GetTrustGraphRequest>,
    ) -> Result<Response<proto::GetTrustGraphResponse>, Status> {
        let req = request.into_inner();
        let tenant_id = parse_tenant_id(&req.tenant_id)?;
        let _entity_type = parse_node_type(&req.entity_type)?;
        self.validate_id(&req.entity_id, "entity_id")?;
        // Clamp depth to configured maximum to prevent DoS.
        let max_depth = self.auth.max_graph_depth.max(1);
        let depth = if req.depth == 0 { 1 } else { req.depth.min(max_depth) };

        let nh = self
            .store
            .get_neighbourhood(tenant_id, &req.entity_id, depth)
            .await
            .ok_or_else(|| Status::not_found("Entity not found"))?;

        let mut nodes = vec![proto::TrustGraphNode {
            id: nh.center.key.entity_id.clone(),
            entity_type: nh.center.node_type.as_str().to_string(),
            trust_score: nh.center.trust_score,
            metadata: nh.center.metadata.clone(),
        }];

        for n in &nh.nodes {
            nodes.push(proto::TrustGraphNode {
                id: n.key.entity_id.clone(),
                entity_type: n.node_type.as_str().to_string(),
                trust_score: n.trust_score,
                metadata: n.metadata.clone(),
            });
        }

        let edges: Vec<proto::TrustGraphEdge> = nh
            .edges
            .iter()
            .map(|(src, tgt, e)| proto::TrustGraphEdge {
                source_id: src.clone(),
                target_id: tgt.clone(),
                edge_type: e.edge_type.as_str().to_string(),
                count: e.count,
                weight: e.weight,
                last_seen: chrono_to_proto(e.last_seen),
            })
            .collect();

        Ok(Response::new(proto::GetTrustGraphResponse { nodes, edges }))
    }

    async fn update_event(
        &self,
        request: Request<proto::UpdateEventRequest>,
    ) -> Result<Response<proto::UpdateEventResponse>, Status> {
        let req = request.into_inner();
        let tenant_id = parse_tenant_id(&req.tenant_id)?;
        self.validate_id(&req.source_id, "source_id")?;
        self.validate_id(&req.target_id, "target_id")?;
        let source_type = parse_node_type(&req.source_type)?;
        let target_type = parse_node_type(&req.target_type)?;
        let severity = Severity::parse(&req.severity);

        let (src_result, tgt_result) = self
            .calculator
            .process_event(
                &self.store,
                tenant_id,
                &req.source_id,
                source_type,
                &req.target_id,
                target_type,
                severity,
            )
            .await;

        Ok(Response::new(proto::UpdateEventResponse {
            accepted: true,
            source_score: src_result.map(|r| r.score).unwrap_or(0.5),
            target_score: tgt_result.map(|r| r.score).unwrap_or(0.5),
        }))
    }

    async fn batch_update_events(
        &self,
        request: Request<Streaming<proto::UpdateEventRequest>>,
    ) -> Result<Response<proto::BatchUpdateResponse>, Status> {
        let mut stream = request.into_inner();
        let mut accepted = 0u64;
        let mut rejected = 0u64;
        let max_batch = self.auth.max_batch_size;

        while let Some(item) = stream.next().await {
            // Enforce stream size limit to prevent unbounded memory/CPU.
            if accepted + rejected >= max_batch {
                warn!(limit = max_batch, "Batch stream limit reached");
                break;
            }

            match item {
                Ok(req) => {
                    let tenant_id = match parse_tenant_id(&req.tenant_id) {
                        Ok(t) => t,
                        Err(_) => {
                            rejected += 1;
                            continue;
                        }
                    };
                    let source_type = match parse_node_type(&req.source_type) {
                        Ok(t) => t,
                        Err(_) => {
                            rejected += 1;
                            continue;
                        }
                    };
                    let target_type = match parse_node_type(&req.target_type) {
                        Ok(t) => t,
                        Err(_) => {
                            rejected += 1;
                            continue;
                        }
                    };
                    let severity = Severity::parse(&req.severity);

                    self.calculator
                        .process_event(
                            &self.store,
                            tenant_id,
                            &req.source_id,
                            source_type,
                            &req.target_id,
                            target_type,
                            severity,
                        )
                        .await;
                    accepted += 1;
                }
                Err(e) => {
                    warn!(error = %e, "Error reading batch event");
                    rejected += 1;
                }
            }
        }

        info!(accepted, rejected, "Batch update complete");

        Ok(Response::new(proto::BatchUpdateResponse {
            accepted,
            rejected,
        }))
    }

    async fn propagate_scores(
        &self,
        request: Request<proto::PropagateRequest>,
    ) -> Result<Response<proto::PropagateResponse>, Status> {
        let req = request.into_inner();
        let tenant_id = if req.tenant_id.is_empty() {
            None
        } else {
            Some(parse_tenant_id(&req.tenant_id)?)
        };
        let max_iter = if req.max_iterations == 0 {
            None
        } else {
            Some(req.max_iterations)
        };
        let threshold = if req.convergence_threshold == 0.0 {
            None
        } else {
            Some(req.convergence_threshold)
        };

        let start = Instant::now();
        let result = self
            .propagation
            .propagate(&self.store, tenant_id, max_iter, threshold)
            .await;
        let elapsed = start.elapsed();

        Ok(Response::new(proto::PropagateResponse {
            iterations: result.iterations,
            max_delta: result.max_delta,
            converged: result.converged,
            nodes_updated: result.nodes_updated,
            elapsed_ms: elapsed.as_secs_f64() * 1000.0,
        }))
    }

    async fn health_check(
        &self,
        _request: Request<proto::HealthCheckRequest>,
    ) -> Result<Response<proto::HealthCheckResponse>, Status> {
        let node_count = self.store.node_count().await as u64;
        let edge_count = self.store.edge_count().await as u64;
        let tenant_count = self.store.tenant_count() as u64;
        let uptime = self.start_time.elapsed().as_secs_f64();

        Ok(Response::new(proto::HealthCheckResponse {
            status: "SERVING".into(),
            total_nodes: node_count,
            total_edges: edge_count,
            tenants: tenant_count,
            uptime_secs: uptime,
        }))
    }
}
