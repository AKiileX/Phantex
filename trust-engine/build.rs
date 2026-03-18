// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(
            &["../proto/phantex/v1/trust.proto"],
            &["../proto"],
        )?;
    Ok(())
}
