// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use uuid::Uuid;

use phantex_trust_engine::config::ScoringConfig;
use phantex_trust_engine::graph::edge::{EdgeType, Severity};
use phantex_trust_engine::graph::node::NodeType;
use phantex_trust_engine::graph::store::TrustGraphStore;
use phantex_trust_engine::scoring::propagation::TrustPropagation;

fn build_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Benchmark: trust score query latency on a graph with 100K+ nodes.
fn bench_trust_score_query(c: &mut Criterion) {
    let rt = build_runtime();
    let tid = Uuid::new_v4();

    let store = rt.block_on(async {
        let store = TrustGraphStore::new(110_000);
        for i in 0..100_000u64 {
            let agent_id = format!("agent-{i}");
            store.ensure_node(tid, &agent_id, NodeType::Agent).await;
        }
        store
    });

    c.bench_function("trust_score_query_100k_nodes", |b| {
        b.iter(|| {
            rt.block_on(async {
                let score = store.trust_score(tid, black_box("agent-50000")).await;
                black_box(score);
            });
        });
    });
}

/// Benchmark: PageRank propagation on 1000 nodes.
fn bench_propagation_1k(c: &mut Criterion) {
    let rt = build_runtime();
    let tid = Uuid::new_v4();
    let config = ScoringConfig::default();
    let prop = TrustPropagation::new(config);

    let store = rt.block_on(async {
        let store = TrustGraphStore::new(1_100);
        // Chain: 0→1→2→...→999
        let mut prev = store.ensure_node(tid, "node-0", NodeType::Agent).await;
        for i in 1..1_000 {
            let next = store
                .ensure_node(tid, &format!("node-{i}"), NodeType::Agent)
                .await;
            store
                .record_event(prev, next, EdgeType::Delegates, Severity::Low, 0)
                .await;
            prev = next;
        }
        store
    });

    c.bench_function("propagation_1k_nodes", |b| {
        b.iter(|| {
            rt.block_on(async {
                let result = prop
                    .propagate_tenant(&store, tid, Some(20), None)
                    .await;
                black_box(result);
            });
        });
    });
}

criterion_group!(benches, bench_trust_score_query, bench_propagation_1k);
criterion_main!(benches);
