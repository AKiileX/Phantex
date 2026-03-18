// SPDX-License-Identifier: Apache-2.0
// Copyright 2025-2026 The Phantex Authors

// Package phantex provides runtime security instrumentation for AI agent frameworks in Go.
//
// Quick start:
//
//	client := phantex.NewClient(nil) // reads PHANTEX_* env vars
//	defer client.Close()
//	client.Start()
//
// Configuration via environment variables:
//
//	PHANTEX_TOKEN          Auth token for sensor/gateway
//	PHANTEX_TENANT_ID      Tenant UUID
//	PHANTEX_AGENT_ID       Agent PAID
//	PHANTEX_TRANSPORT      auto|grpc|http|buffer (default: auto)
//	PHANTEX_GATEWAY_ADDR   Gateway address (default: localhost:50051)
//	PHANTEX_HOOKS          auto|openai,http|none (default: auto)
//	PHANTEX_BATCH_SIZE     Batch size before flush (default: 50)
//	PHANTEX_ENABLED        0|1 (default: 1)
//	PHANTEX_DEBUG          0|1 (default: 0)
package phantex

const Version = "0.1.0"
