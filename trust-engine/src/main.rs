// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

//! Phantex Trust Graph Engine — gRPC server entrypoint.

use std::sync::Arc;
use std::time::Duration;

use tonic::transport::Server;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use phantex_trust_engine::config::TrustEngineConfig;
use phantex_trust_engine::graph::store::TrustGraphStore;
use phantex_trust_engine::grpc::auth::api_key_interceptor;
use phantex_trust_engine::grpc::proto::trust_service_server::TrustServiceServer;
use phantex_trust_engine::grpc::server::TrustServiceImpl;
use phantex_trust_engine::persistence::snapshot::{snapshot_loop, SnapshotManager};
use phantex_trust_engine::scoring::decay::TrustDecay;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialise structured logging.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    // Load configuration (env + optional config file).
    let config = load_config()?;
    info!(grpc_addr = %config.grpc_addr, "Starting Phantex Trust Engine");

    // Create the in-memory graph store.
    let store = TrustGraphStore::new(config.graph.initial_capacity);

    // Try to load latest snapshot.
    let snap_mgr = SnapshotManager::new(config.snapshot.clone());
    match snap_mgr.load(&store).await {
        Ok(()) => info!("Loaded snapshot successfully"),
        Err(e) => warn!(error = %e, "No snapshot loaded (cold start)"),
    }

    // Spawn periodic snapshot task.
    let snap_store = Arc::clone(&store);
    let snap_config = config.snapshot.clone();
    tokio::spawn(async move {
        snapshot_loop(snap_store, snap_config).await;
    });

    // Spawn periodic trust decay task (every hour).
    let decay_store = Arc::clone(&store);
    let decay_config = config.scoring.clone();
    tokio::spawn(async move {
        let decay = TrustDecay::new(decay_config);
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            let updated = decay.apply_all(&decay_store).await;
            if updated > 0 {
                info!(nodes = updated, "Trust decay applied");
            }
        }
    });

    // Build gRPC service with optional API key authentication.
    let svc = TrustServiceImpl::new(Arc::clone(&store), &config);
    let interceptor = api_key_interceptor(config.auth.api_key.clone());
    let addr = config.grpc_addr.parse()?;

    info!(%addr, auth = config.auth.api_key.is_some(), tls = config.tls.enabled, "gRPC server listening");

    let mut server = Server::builder();

    // Optionally configure TLS / mTLS.
    if config.tls.enabled {
        use tonic::transport::{Identity, ServerTlsConfig, Certificate};

        let cert_file = config.tls.cert_file.as_deref()
            .ok_or("tls.cert_file is required when tls.enabled = true")?;
        let key_file = config.tls.key_file.as_deref()
            .ok_or("tls.key_file is required when tls.enabled = true")?;

        let cert = tokio::fs::read(cert_file).await?;
        let key = tokio::fs::read(key_file).await?;
        let identity = Identity::from_pem(cert, key);

        let mut tls_config = ServerTlsConfig::new().identity(identity);

        // If a CA file is provided, require client certificates (mTLS).
        if let Some(ca_path) = &config.tls.ca_file {
            let ca = tokio::fs::read(ca_path).await?;
            tls_config = tls_config.client_ca_root(Certificate::from_pem(ca));
            info!("mTLS enabled — requiring client certificates");
        }

        server = server.tls_config(tls_config)?;
        info!("TLS configured from {} / {}", cert_file, key_file);
    }

    server
        .add_service(TrustServiceServer::with_interceptor(svc, interceptor))
        .serve(addr)
        .await?;

    Ok(())
}

fn load_config() -> Result<TrustEngineConfig, Box<dyn std::error::Error>> {
    use figment::providers::{Env, Format, Toml};
    use figment::Figment;

    let config: TrustEngineConfig = Figment::new()
        .merge(Toml::file("trust-engine.toml"))
        .merge(Env::prefixed("TRUST_ENGINE_").split("__"))
        .extract()?;

    Ok(config)
}
