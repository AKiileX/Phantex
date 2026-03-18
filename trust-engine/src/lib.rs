// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

//! Phantex Trust Graph Engine
//!
//! High-performance in-memory graph engine that computes trust scores
//! between agents, tools, and resources.  Sub-0.5 ms query latency on
//! graphs with 100 K+ nodes.

pub mod config;
pub mod graph;
pub mod grpc;
pub mod persistence;
pub mod scoring;
