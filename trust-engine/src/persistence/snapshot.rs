// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

use std::path::PathBuf;
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tracing::{error, info};

use crate::config::SnapshotConfig;
use crate::graph::edge::TrustEdge;
use crate::graph::node::TrustNode;
use crate::graph::store::TrustGraphStore;

/// Serialisable snapshot of the entire trust graph.
#[derive(Debug, Serialize, Deserialize)]
pub struct GraphSnapshot {
    pub version: u32,
    pub nodes: Vec<TrustNode>,
    pub edges: Vec<(usize, usize, TrustEdge)>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Manages periodic serialisation of the graph to disk.
pub struct SnapshotManager {
    config: SnapshotConfig,
    dir: PathBuf,
}

impl SnapshotManager {
    pub fn new(config: SnapshotConfig) -> Self {
        let dir = PathBuf::from(&config.dir);
        Self { config, dir }
    }

    /// Save the current graph to a snapshot file.
    pub async fn save(&self, store: &Arc<TrustGraphStore>) -> Result<PathBuf, String> {
        let (nodes, edges) = store.serialise().await;

        let snapshot = GraphSnapshot {
            version: 1,
            nodes,
            edges,
            created_at: chrono::Utc::now(),
        };

        let data =
            bincode::serialize(&snapshot).map_err(|e| format!("Serialisation error: {e}"))?;

        // Ensure directory exists (async I/O).
        tokio::fs::create_dir_all(&self.dir)
            .await
            .map_err(|e| format!("Cannot create snapshot dir: {e}"))?;

        let ts = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
        let filename = format!("trust-snapshot-{ts}.bin");
        let path = self.dir.join(&filename);

        let final_data = if self.config.encrypt {
            self.encrypt(&data)?
        } else {
            data
        };

        tokio::fs::write(&path, &final_data)
            .await
            .map_err(|e| format!("Cannot write snapshot: {e}"))?;

        info!(
            path = %path.display(),
            nodes = snapshot.nodes.len(),
            edges = snapshot.edges.len(),
            bytes = final_data.len(),
            "Snapshot saved",
        );

        // Clean up old snapshots (keep last 5).
        if let Err(e) = self.cleanup_old_snapshots(5).await {
            tracing::warn!(error = %e, "Failed to clean up old snapshots");
        }

        Ok(path)
    }

    /// Load the most recent snapshot from disk.
    pub async fn load(&self, store: &Arc<TrustGraphStore>) -> Result<(), String> {
        let path = self.latest_snapshot().await?;

        let raw = tokio::fs::read(&path)
            .await
            .map_err(|e| format!("Cannot read snapshot: {e}"))?;

        let data = if self.config.encrypt {
            self.decrypt(&raw)?
        } else {
            raw
        };

        let snapshot: GraphSnapshot =
            bincode::deserialize(&data).map_err(|e| format!("Deserialisation error: {e}"))?;

        info!(
            path = %path.display(),
            nodes = snapshot.nodes.len(),
            edges = snapshot.edges.len(),
            "Loading snapshot",
        );

        store.restore(snapshot.nodes, snapshot.edges).await;
        Ok(())
    }

    /// Find the most recent snapshot file in the snapshot directory.
    async fn latest_snapshot(&self) -> Result<PathBuf, String> {
        if !self.dir.exists() {
            return Err("Snapshot directory does not exist".to_string());
        }

        let mut entries: Vec<_> = Vec::new();
        let mut read_dir = tokio::fs::read_dir(&self.dir)
            .await
            .map_err(|e| format!("Cannot list snapshot dir: {e}"))?;

        while let Some(entry) = read_dir.next_entry().await.map_err(|e| format!("Dir read error: {e}"))? {
            if entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("trust-snapshot-") && n.ends_with(".bin"))
            {
                entries.push(entry);
            }
        }

        entries.sort_by_key(|e| e.file_name());

        entries
            .last()
            .map(|e| e.path())
            .ok_or_else(|| "No snapshot files found".to_string())
    }

    /// Remove old snapshot files, keeping the most recent `keep` files.
    async fn cleanup_old_snapshots(&self, keep: usize) -> Result<(), String> {
        if !self.dir.exists() {
            return Ok(());
        }

        let mut snapshots: Vec<PathBuf> = Vec::new();
        let mut read_dir = tokio::fs::read_dir(&self.dir)
            .await
            .map_err(|e| format!("Cannot list snapshot dir: {e}"))?;

        while let Some(entry) = read_dir.next_entry().await.map_err(|e| format!("Dir read error: {e}"))? {
            if entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("trust-snapshot-") && n.ends_with(".bin"))
            {
                snapshots.push(entry.path());
            }
        }

        snapshots.sort();

        if snapshots.len() > keep {
            for old_path in &snapshots[..snapshots.len() - keep] {
                if let Err(e) = tokio::fs::remove_file(old_path).await {
                    tracing::warn!(path = %old_path.display(), error = %e, "Failed to remove old snapshot");
                }
            }
        }

        Ok(())
    }

    // ── Encryption helpers ──────────────────────────────────────────

    fn derive_key(&self) -> Result<[u8; 32], String> {
        let hex_key = self
            .config
            .encryption_key
            .as_deref()
            .ok_or("Encryption key not configured")?;

        let bytes =
            hex::decode(hex_key).map_err(|e| format!("Invalid hex encryption key: {e}"))?;

        if bytes.len() != 32 {
            return Err(format!(
                "Encryption key must be 32 bytes (got {})",
                bytes.len()
            ));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    }

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.derive_key()?;
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| format!("AES init error: {e}"))?;

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| format!("Encryption error: {e}"))?;

        // Prepend nonce to ciphertext.
        let mut output = Vec::with_capacity(12 + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend(ciphertext);
        Ok(output)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        if data.len() < 12 {
            return Err("Encrypted data too short".to_string());
        }

        let key = self.derive_key()?;
        let cipher =
            Aes256Gcm::new_from_slice(&key).map_err(|e| format!("AES init error: {e}"))?;

        let nonce = Nonce::from_slice(&data[..12]);
        let plaintext = cipher
            .decrypt(nonce, &data[12..])
            .map_err(|e| format!("Decryption error: {e}"))?;

        Ok(plaintext)
    }
}

/// Run periodic snapshots in the background.
pub async fn snapshot_loop(
    store: Arc<TrustGraphStore>,
    config: SnapshotConfig,
) {
    let interval = std::time::Duration::from_secs(config.interval_secs);
    let mgr = SnapshotManager::new(config);

    loop {
        tokio::time::sleep(interval).await;
        match mgr.save(&store).await {
            Ok(path) => info!(path = %path.display(), "Periodic snapshot complete"),
            Err(e) => error!(error = %e, "Periodic snapshot failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::edge::{EdgeType, Severity};
    use crate::graph::node::NodeType;
    use std::path::Path;
    use tempfile::TempDir;

    fn test_config(dir: &Path, encrypt: bool) -> SnapshotConfig {
        let key = if encrypt {
            // 32 random bytes in hex.
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string())
        } else {
            None
        };
        SnapshotConfig {
            dir: dir.to_str().unwrap().to_string(),
            interval_secs: 60,
            encrypt,
            encryption_key: key,
        }
    }

    #[tokio::test]
    async fn test_snapshot_unencrypted_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path(), false);
        let mgr = SnapshotManager::new(config);
        let store = TrustGraphStore::new(16);
        let tid = uuid::Uuid::new_v4();

        let src = store.ensure_node(tid, "agent-1", NodeType::Agent).await;
        let tgt = store.ensure_node(tid, "tool-a", NodeType::Tool).await;
        store
            .record_event(src, tgt, EdgeType::Uses, Severity::Low, 0)
            .await;

        // Save.
        let path = mgr.save(&store).await.unwrap();
        assert!(path.exists());

        // Restore into fresh store.
        let store2 = TrustGraphStore::new(16);
        mgr.load(&store2).await.unwrap();
        assert_eq!(store2.node_count().await, 2);
        assert_eq!(store2.edge_count().await, 1);
    }

    #[tokio::test]
    async fn test_snapshot_encrypted_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let config = test_config(tmp.path(), true);
        let mgr = SnapshotManager::new(config);
        let store = TrustGraphStore::new(16);
        let tid = uuid::Uuid::new_v4();

        let src = store.ensure_node(tid, "agent-1", NodeType::Agent).await;
        let tgt = store.ensure_node(tid, "tool-a", NodeType::Tool).await;
        store
            .record_event(src, tgt, EdgeType::Uses, Severity::Low, 0)
            .await;

        mgr.save(&store).await.unwrap();

        let store2 = TrustGraphStore::new(16);
        mgr.load(&store2).await.unwrap();
        assert_eq!(store2.node_count().await, 2);
        assert_eq!(store2.edge_count().await, 1);
    }
}
