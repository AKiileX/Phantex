// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

pub mod auth;
pub mod server;

// Re-export the generated proto types.
pub mod proto {
    tonic::include_proto!("phantex.v1");
}
